import unittest

from user.analyzer import Analyzer, is_within, redact_text


# 构造一条符合真实 ABI 的最小事件，测试各检测分支时复用。
def event(event_type, *, object_name="", retval=0, timestamp_ns=1_000_000_000):
    return {
        "time": "2026-09-14T10:00:00.000",
        "timestamp_ns": timestamp_ns,
        "type": event_type,
        "agent_id": 1,
        "tgid": 100,
        "tid": 100,
        "ppid": 10,
        "object": object_name,
        "dirfd": -100,
        "retval": retval,
        "destination": "",
        "port": 0,
        "flags": 0,
        "uid": 1000,
        "payload": "",
    }


class AnalyzerTest(unittest.TestCase):
# 每个用例前装载一份小阈值配置，让告警门槛容易在测试里触发。
    def setUp(self):
        self.config = {
            "unexpected_shells": ["/bin/sh", "/bin/bash"],
            "sensitive_paths": ["/etc/passwd", "/tmp/protected"],
            "agents": {1: {"name": "test-agent", "workspace": "/tmp/work"}},
            "loop_detection": {
                "enabled": True,
                "window_seconds": 10,
                "minimum_signals": 2,
                "repeated_file_operations": 3,
                "repeated_network_connections": 3,
                "repeated_process_execs": 3,
                "repeated_prompts": 2,
                "cooldown_seconds": 10,
            },
            "resource_limits": {
                "window_seconds": 10,
                "max_process_events": 3,
                "max_deletions": 3,
                "cooldown_seconds": 10,
            },
            "multi_agent": {
                "enabled": True,
                "window_seconds": 5,
                "cooldown_seconds": 5,
                "collective_min_agents": 2,
                "collective_connection_threshold": 4,
                "allowed_collaborations": [],
                "shared_paths": [],
            },
            "malicious_ips": ["203.0.113.66"],
            "high_risk_ports": [4444],
        }
        self.analyzer = Analyzer(self.config)

# 路径包含关系必须按目录组件判断，不能把 /tmp/work2 当成 /tmp/work 的子路径。
    def test_path_containment_is_component_aware(self):
        self.assertTrue(is_within("/tmp/work/a", "/tmp/work"))
        self.assertFalse(is_within("/tmp/work2/a", "/tmp/work"))

# 命中 unexpected_shells 的 exec 要产生非预期 Shell 告警。
    def test_shell_launch(self):
        alerts = self.analyzer.process(event("exec", object_name="/bin/sh"))
        self.assertEqual([alert["anomaly_type"] for alert in alerts], ["unexpected_shell"])

# 敏感文件规则只对打开成功的调用生效，失败尝试不告警。
    def test_sensitive_file_requires_success(self):
        success = self.analyzer.process(event("openat", object_name="/etc/passwd", retval=3))
        failure = self.analyzer.process(event("openat", object_name="/etc/passwd", retval=-13))
        self.assertEqual(success[0]["anomaly_type"], "sensitive_file_access")
        self.assertEqual(failure, [])

# 工作区外成功删除要告警，工作区内删除不告警。
    def test_workspace_delete(self):
        inside = self.analyzer.process(event("unlinkat", object_name="/tmp/work/a", retval=0))
        outside = self.analyzer.process(event("unlinkat", object_name="/tmp/work2/a", retval=0))
        failed = self.analyzer.process(event("unlinkat", object_name="/tmp/out", retval=-2))
        self.assertEqual(inside, [])
        self.assertEqual(outside[0]["anomaly_type"], "workspace_boundary_violation")
        self.assertEqual(failed, [])

# 逻辑死循环至少需要两类重复信号同时越过阈值才判定。
    def test_loop_requires_two_repeated_signals(self):
        alerts = []
        for index in range(3):
            alerts.extend(
                self.analyzer.process(
                    event(
                        "openat",
                        object_name="/tmp/work/repeated",
                        retval=3,
                        timestamp_ns=(index + 1) * 1_000_000_000,
                    )
                )
            )
        self.assertNotIn("infinite_loop", [alert["anomaly_type"] for alert in alerts])

        for index in range(3):
            network_event = event(
                "connect", timestamp_ns=(index + 4) * 1_000_000_000, retval=-115
            )
            network_event["destination"] = "127.0.0.1"
            network_event["port"] = 9
            alerts.extend(self.analyzer.process(network_event))
        self.assertEqual(
            [alert["anomaly_type"] for alert in alerts].count("infinite_loop"), 1
        )

# TLS Prompt 里的凭据要脱敏，并且能关联到随后的 shell 行为。
    def test_tls_prompt_is_redacted_and_correlated_to_shell(self):
        body = '{"messages":[{"role":"user","content":"run a shell"}],"api_key":"secret"}'
        tls = event("tls_write", timestamp_ns=1_000_000_000)
        tls["payload"] = f"POST /v1/chat HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n{body}"
        self.assertEqual(self.analyzer.process(tls), [])

        alerts = self.analyzer.process(
            event("exec", object_name="/bin/sh", timestamp_ns=2_000_000_000)
        )
        shell = next(alert for alert in alerts if alert["anomaly_type"] == "unexpected_shell")
        self.assertEqual(shell["causal_prompt"], "run a shell")
        self.assertNotIn("secret", str(shell))
        correlations = self.analyzer.drain_correlations()
        self.assertEqual(correlations[-1]["operation"], "exec")

# 分片到达的 TLS JSON 要重组一次，不能重复上报同一条语义。
    def test_fragmented_tls_json_is_reassembled_once(self):
        first = event("tls_write", timestamp_ns=1_000_000_000)
        first["payload"] = '{"prompt":"fragmented'
        second = event("tls_write", timestamp_ns=2_000_000_000)
        second["payload"] = ' request"}'
        self.analyzer.process(first)
        self.analyzer.process(second)
        history = list(self.analyzer.correlator.history[1])
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["text"], "fragmented request")

# Authorization 头和 Bearer Token 等凭据进入日志前必须脱敏。
    def test_redacts_headers_and_bearer_tokens(self):
        redacted = redact_text("Authorization: Bearer abc.def and api_key=topsecret")
        self.assertNotIn("abc.def", redacted)
        self.assertNotIn("topsecret", redacted)
        self.assertIn("[REDACTED]", redacted)

# 恶意 IP 与高危端口规则各自命中并给出正确的告警类型。
    def test_network_risk_rules(self):
        blocked = event("connect")
        blocked["destination"] = "203.0.113.66"
        blocked["port"] = 443
        risky = event("connect", timestamp_ns=2_000_000_000)
        risky["destination"] = "127.0.0.1"
        risky["port"] = 4444
        self.assertEqual(self.analyzer.process(blocked)[0]["anomaly_type"], "malicious_destination")
        self.assertEqual(self.analyzer.process(risky)[0]["anomaly_type"], "high_risk_network_port")

# 进程风暴和批量删除两类资源滥用阈值分别生效。
    def test_process_and_deletion_resource_abuse(self):
        alerts = []
        for index in range(3):
            alerts.extend(
                self.analyzer.process(
                    event(
                        "exec",
                        object_name=f"/usr/bin/tool-{index}",
                        timestamp_ns=(index + 1) * 1_000_000_000,
                    )
                )
            )
        self.assertIn("resource_abuse", [alert["anomaly_type"] for alert in alerts])

        analyzer = Analyzer(self.config)
        deletion_alerts = []
        for index in range(3):
            deletion_alerts.extend(
                analyzer.process(
                    event(
                        "unlinkat",
                        object_name=f"/tmp/work/file-{index}",
                        timestamp_ns=(index + 1) * 1_000_000_000,
                    )
                )
            )
        self.assertIn(
            "excessive_file_deletion",
            [alert["anomaly_type"] for alert in deletion_alerts],
        )

# 两个 Agent 写同一文件触发竞争；未授权读取触发传递告警。
    def test_cross_agent_contention_and_handoff(self):
        write_one = event("openat", object_name="/tmp/shared/data", retval=3)
        write_one["flags"] = 1
        self.assertEqual(self.analyzer.process(write_one), [])

        write_two = event(
            "openat", object_name="/tmp/shared/data", retval=4, timestamp_ns=2_000_000_000
        )
        write_two["flags"] = 1
        write_two["agent_id"] = 2
        contention = self.analyzer.process(write_two)
        self.assertEqual(contention[0]["anomaly_type"], "resource_contention")

        analyzer = Analyzer(self.config)
        analyzer.process(write_one)
        read_two = event(
            "openat", object_name="/tmp/shared/data", retval=5, timestamp_ns=2_000_000_000
        )
        read_two["agent_id"] = 2
        handoff = analyzer.process(read_two)
        self.assertEqual(handoff[0]["anomaly_type"], "unauthorized_agent_handoff")

# 多个 Agent 对同一端点的连接总数越阈值触发集体 API 风暴。
    def test_collective_api_storm(self):
        alerts = []
        for index, agent_id in enumerate((1, 2, 1, 2), 1):
            network = event("connect", timestamp_ns=index * 1_000_000_000)
            network["agent_id"] = agent_id
            network["destination"] = "198.51.100.10"
            network["port"] = 443
            alerts.extend(self.analyzer.process(network))
        self.assertIn("collective_api_storm", [alert["anomaly_type"] for alert in alerts])

# 重复 Prompt 与重复网络连接两类信号组合也能判定死循环。
    def test_repeated_prompt_and_network_form_loop(self):
        alerts = []
        for index in range(2):
            prompt = event("tls_write", timestamp_ns=(index + 1) * 1_000_000_000)
            prompt["payload"] = '{"prompt":"same question"}'
            alerts.extend(self.analyzer.process(prompt))
        for index in range(3):
            network = event("connect", timestamp_ns=(index + 3) * 1_000_000_000)
            network["destination"] = "127.0.0.1"
            network["port"] = 9
            alerts.extend(self.analyzer.process(network))
        self.assertIn("infinite_loop", [alert["anomaly_type"] for alert in alerts])


if __name__ == "__main__":
    unittest.main()
