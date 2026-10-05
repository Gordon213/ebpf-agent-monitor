"""Regression checks for the live dashboard's protocol, capture and lifecycle."""
from collections import Counter
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ui.live import driver
from ui.live.protocol import encode


class WorkerProtocolTest(unittest.TestCase):
# 为 worker 协议测试准备 socket 路径与子进程清理容器。
# 为采集器生命周期测试准备路径与临时产物。
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="live-test-")
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.certificate, key = driver.generate_certificate(directory)
        port = driver.free_port()
        self.processes = []
        self.connection = None
        self.addCleanup(self.cleanup_processes)
        tls = subprocess.Popen(
            [sys.executable, "-u", str(driver.TLS_SERVER), "--port", str(port),
             "--certificate", str(self.certificate), "--private-key", str(key),
             "--connections", "1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.processes.append(tls)
        self.assertTrue(driver.startup_line(tls).startswith("TLS SERVER READY"))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            path = str(directory / "worker.sock")
            listener.bind(path)
            listener.listen(1)
            listener.settimeout(5)
            process = subprocess.Popen(
                [sys.executable, "-u", str(driver.ROOT / "ui/live/worker.py"),
                 "--agent-id", "1", "--socket", path, "--tls-port", str(port),
                 "--tls-certificate", str(self.certificate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.processes.append(process)
            peer, _ = listener.accept()
        self.worker = process
        self.connection = driver.WorkerConnection(1, process, peer)
        self.connection.wait_for("ready", timeout=5)

# 每个用例结束后终止遗留的 worker/服务进程，避免污染后续测试。
# 清理所有已被 Collector/WorkerConnection 持有的残留子进程。
    def cleanup_processes(self):
        for process in reversed(self.processes):
            driver.stop_process(process)
            driver.close_pipes(process)
        if self.connection is not None:
            self.connection.close()

# TLS 对话和文件操作要能通过 socket 返回结构化结果。
    def test_exchange_and_run_return_results_on_socket(self):
        self.connection.send({"command": "exchange", "prompt": "中文请求：检查计划 😀"})
        messages = self.connection.wait_for("done", timeout=5)
        self.assertEqual([item["kind"] for item in messages], ["operation", "done"])
        self.assertEqual(messages[-1]["command"], "exchange")
        self.assertEqual(messages[0]["detail"], "ACK:中文请求：检查计划 😀")
        self.assertLess(messages[0]["started_ns"], messages[0]["finished_ns"])
        self.connection.send(
            {"command": "run", "operations": [
                {"op": "open", "path": str(self.certificate), "write": False}
            ]}
        )
        messages = self.connection.wait_for("done", timeout=5)
        self.assertEqual([item["kind"] for item in messages], ["operation", "done"])
        self.assertEqual(messages[-1]["command"], "run")
        self.assertEqual(messages[0]["retval"], 0)
        driver.stop_process(self.worker)
        self.assertEqual(self.worker.stdout.read(), "")

# 未知指令要回错误而不是把 worker 挂死。
    def test_bad_command_reports_an_error_instead_of_hanging(self):
        self.connection.send({"command": "unknown"})
        with self.assertRaisesRegex(RuntimeError, "unknown command"):
            self.connection.wait_for("done", timeout=5)


class WorkerQueueTest(unittest.TestCase):
# 一次 wait 之后消息要保留给下一阶段读取，不能丢。
    def test_wait_keeps_messages_for_the_next_phase(self):
        parent, peer = socket.socketpair()
        connection = driver.WorkerConnection(1, None, parent)
        try:
            peer.sendall(encode({"kind": "done"}) + encode({"kind": "operation"})
                         + encode({"kind": "done"}))
            self.assertEqual([item["kind"] for item in connection.wait_for("done", 2)], ["done"])
            self.assertEqual(
                [item["kind"] for item in connection.wait_for("done", 2)], ["operation", "done"]
            )
        finally:
            peer.close()
            connection.close()

# worker 断开时要立刻失败，而不是等到超时。
    def test_eof_fails_immediately(self):
        parent, peer = socket.socketpair()
        connection = driver.WorkerConnection(1, None, parent)
        try:
            peer.close()
            with self.assertRaisesRegex(RuntimeError, "disconnected"):
                connection.wait_for("done", 2)
        finally:
            connection.close()


class TimelineTest(unittest.TestCase):
# 构造一条时间线测试用操作记录。
    def operation(self, **changes):
        item = {"agent_id": 1, "op": "open", "target": "/tmp/live-test-file",
                "retval": 0, "started_ns": 1_000_000_000, "finished_ns": 1_010_000_000}
        item.update(changes)
        return item

# 构造一条时间线测试用事件记录。
    def event(self, **changes):
        item = {"agent_id": 1, "type": "openat", "object": "/tmp/live-test-file",
                "retval": 3, "timestamp_ns": 1_005_000_000}
        item.update(changes)
        return item

# 告警时间戳落在长操作中间时也要能匹配到该操作。
    def test_matches_the_middle_of_a_long_operation(self):
        self.assertEqual(driver.match_step(self.event(), [self.operation()]), 0)

# Agent、对象或时间对不上的告警不能错误归档到其他步骤。
    def test_rejects_unrelated_agent_object_or_time(self):
        for changes in ({"agent_id": 2}, {"object": "/tmp/another-file"},
                        {"timestamp_ns": 1_020_000_000}):
            with self.subTest(changes=changes):
                self.assertIsNone(driver.match_step(self.event(**changes), [self.operation()]))

# exec 告警的对象是解析后的可执行文件路径时仍要匹配。
    def test_exec_accepts_resolved_executable_path(self):
        event = self.event(type="exec", object=os.path.realpath("/bin/sh"))
        operation = self.operation(op="exec", target="/bin/sh")
        self.assertEqual(driver.match_step(event, [operation]), 0)

# 事件计数只统计真正采集到的事件，unlinkat 与 unlink 同等对待。
    def test_counts_only_captured_events_and_accepts_unlinkat(self):
        operation = self.operation(op="delete", events=["unlink"])
        actual = [self.event(type="unlinkat", retval=0), self.event(type="openat")]
        alert = dict(actual[0], operation="unlinkat", anomaly_type="workspace_boundary_violation")
        steps, counts, _ = driver.build_steps("test", [operation], [alert], {1: "agent"}, actual)
        self.assertEqual(dict((item["type"], item["count"]) for item in counts),
                         {"openat": 1, "unlinkat": 1})
        self.assertEqual(steps[0]["type"], "unlinkat")
        self.assertIn("workspace_boundary_violation", steps[0]["triggered"])
        _, counts, _ = driver.build_steps("test", [operation], [], {1: "agent"})
        self.assertEqual(counts, [])

# 同一操作触发多条告警时都要标记在同一步骤上。
    def test_multiple_alerts_can_mark_the_same_step(self):
        first = dict(self.event(), operation="openat", anomaly_type="sensitive_file_access")
        second = dict(first, anomaly_type="resource_contention")
        steps, _, _ = driver.build_steps("test", [self.operation()], [first, second], {})
        self.assertEqual(steps[0]["triggered"], ["sensitive_file_access", "resource_contention"])
        self.assertNotIn("_step", first)

# 多个操作时间重叠时，时长要取最晚结束的那个。
    def test_duration_includes_the_longest_overlapping_operation(self):
        first = self.operation(finished_ns=1_100_000_000)
        second = self.operation(started_ns=1_010_000_000, finished_ns=1_020_000_000)
        _, _, duration = driver.build_steps("test", [first, second], [], {})
        self.assertEqual(duration, 100)


class CollectorLifecycleTest(unittest.TestCase):
# 为采集器生命周期测试准备临时目录、假采集器脚本并替换 driver 的采集器路径。
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="collector-test-")
        self.addCleanup(self.temporary.cleanup)
        self.collector_path = Path(self.temporary.name) / "collector.py"
        self.collector_path.write_text(
            "#!/usr/bin/env python3\n"
            "import json, signal, sys, time\n"
            "def event(kind, obj):\n"
            "    print(json.dumps({'type': kind, 'agent_id': 1, 'tgid': 123, 'tid': 123,\n"
            "        'timestamp_ns': time.monotonic_ns(), 'object': obj, 'retval': 0, 'destination': '127.0.0.1', 'port': 4444}), flush=True)\n"
            "def stop(*args):\n"
            "    event('connect', '127.0.0.1:4444')\n"
            "    raise SystemExit(0)\n"
            "signal.signal(signal.SIGINT, stop)\n"
            "event('openat', '/tmp/ebpf-agent-protected/test')\n"
            "print('monitoring 1 root Agent(s); Ctrl-C to stop', file=sys.stderr, flush=True)\n"
            "while True: time.sleep(1)\n"
        )
        self.collector_path.chmod(0o700)
        self.patcher = patch.object(driver, "COLLECTOR", self.collector_path)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

# 真实采集器的启动标记和尾部事件要完整到达分析器。
    def test_real_startup_marker_and_tail_events_reach_analyzer(self):
        collector = driver.Collector({1: os.getpid()})
        self.addCleanup(collector.close)
        collector.wait_started(timeout=5)
        alerts = collector.finished_alerts()
        self.assertEqual(Counter(item["type"] for item in collector.captured_events()),
                         {"openat": 1, "connect": 1})
        self.assertEqual({item["anomaly_type"] for item in alerts},
                         {"sensitive_file_access", "high_risk_network_port"})
        self.assertIsNotNone(collector.collector.poll())
        self.assertIsNotNone(collector.analyzer.poll())

# 分析器起不来时要把采集器一起收尸，不能留下孤儿进程。
    def test_analyzer_spawn_failure_reaps_the_collector(self):
        real_popen = subprocess.Popen
        spawned = []
# 替身 Popen：第一次放行真实进程，第二次抛错模拟分析器启动失败。
        def start(*args, **kwargs):
            if spawned:
                raise OSError("injected analyzer spawn failure")
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process
        with patch.object(driver.subprocess, "Popen", side_effect=start):
            with self.assertRaisesRegex(OSError, "injected"):
                driver.Collector({1: os.getpid()})
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())

# 启动或 worker 失败时 driver 要清理掉所有子进程。
    def test_driver_cleans_all_children_on_startup_or_worker_failure(self):
        real_popen = subprocess.Popen
        original_wait = driver.WorkerConnection.wait_for
        for stage in ("startup", "worker"):
            spawned = []
# 记录每次真实启动的子进程，供清理断言使用。
            def start(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                spawned.append(process)
                return process
# 拦截 worker 等待：收到 done 时抛超时，模拟 worker 执行失败。
            def wait(connection, kind, timeout=30):
                if kind == "done":
                    raise TimeoutError("injected worker failure")
                return original_wait(connection, kind, timeout)
            failure = (patch.object(driver.Collector, "wait_started",
                                    side_effect=TimeoutError("injected startup failure"))
                       if stage == "startup" else
                       patch.object(driver.WorkerConnection, "wait_for", wait))
            with self.subTest(stage=stage), failure, \
                    patch.object(driver.subprocess, "Popen", side_effect=start), \
                    patch.object(driver.os, "geteuid", return_value=0), \
                    patch.object(driver.workloads, "prepare"):
                try:
                    with self.assertRaisesRegex(TimeoutError, "injected"):
                        driver.run("sensitive_file")
                    self.assertTrue(spawned)
                    self.assertTrue(all(process.poll() is not None for process in spawned))
                finally:
                    for process in spawned:
                        driver.stop_process(process)
                        driver.close_pipes(process)

# 外部超时中断 driver 时，整个进程组都要被清理。
    def test_external_timeout_interrupts_driver_and_cleans_its_group(self):
        code = (
            "import sys,time\n"
            "from pathlib import Path\n"
            "from ui.live import driver as d\n"
            f"d.COLLECTOR = Path({str(self.collector_path)!r})\n"
            "d.workloads.prepare = lambda: None\n"
            "def hold(self, timeout=10):\n"
            "    print('TEST CAPTURE STARTED', flush=True)\n"
            "    time.sleep(60)\n"
            "d.Collector.wait_started = hold\n"
            "sys.argv = ['driver', '--scenario', 'sensitive_file']\n"
            "sys.exit(d.main())\n"
        )
        environment = dict(os.environ, AGENT_MONITOR_SKIP_ROOT_CHECK="1")
        process = subprocess.Popen(
            ["/usr/bin/timeout", "--signal=TERM", "--kill-after=2", "2",
             sys.executable, "-c", code],
            cwd=driver.ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 124, stdout + stderr)
            self.assertIn("TEST CAPTURE STARTED", stdout)
            self.assertIn("live capture interrupted", stdout)
            rows = subprocess.check_output(["ps", "-eo", "pgid=,stat=,args="], text=True)
            remaining = []
            for row in rows.splitlines():
                fields = row.strip().split(None, 2)
                if len(fields) == 3 and int(fields[0]) == process.pid \
                        and not fields[1].startswith("Z"):
                    remaining.append(fields[2])
            self.assertEqual(remaining, [])
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            driver.close_pipes(process)

# 无响应的进程会被杀掉并回收，wait 不会永久阻塞。
    def test_unresponsive_process_is_killed_and_reaped(self):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c",
             "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
             "print('ready',flush=True); time.sleep(60)"],
            stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(driver.close_pipes, process)
        self.addCleanup(driver.stop_process, process)
        self.assertEqual(process.stdout.readline().strip(), "ready")
        driver.stop_process(process, timeout=0.05)
        self.assertEqual(process.returncode, -signal.SIGKILL)


@unittest.skipUnless(os.environ.get("AGENT_MONITOR_LIVE_TESTS") == "1" and os.geteuid() == 0,
                     "set AGENT_MONITOR_LIVE_TESTS=1 and run with sudo for kernel integration")
class LiveKernelTest(unittest.TestCase):
# 真实加载 eBPF：中文 Prompt 跨事件分片后仍要完整重组。
    def test_long_chinese_prompt_survives_actual_collector_chunks(self):
        prompt = "重复检查计划😀" * 60
        code = (
            "import json\n"
            "from ui.live import driver as d\n"
            f"d.workloads.PROMPTS['infinite_loop'] = {prompt!r}\n"
            "print(json.dumps(d.run('infinite_loop'), ensure_ascii=False))\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", code], cwd=driver.ROOT,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            result = json.loads(stdout)
            alert = next(a for a in result["alerts"] if a["anomaly_type"] == "infinite_loop")
            self.assertEqual(alert["causal_prompt"], prompt)
            self.assertEqual(alert["causal_response"], "ACK:" + prompt)
            counts = {item["type"]: item["count"] for item in result["events"]}
            self.assertGreater(counts["tls_write"], 1)
            self.assertGreater(counts["tls_read"], 1)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            driver.close_pipes(process)

# 真实加载 eBPF：所有场景都要给出带因果上下文的告警且不留残留进程。
    def test_all_live_scenarios_have_causal_alerts_and_no_leftover_processes(self):
        expected = {
            "unexpected_shell": "unexpected_shell",
            "sensitive_file": "sensitive_file_access",
            "workspace_boundary": "workspace_boundary_violation",
            "infinite_loop": "infinite_loop",
            "resource_abuse": "resource_abuse",
            "excessive_deletion": "excessive_file_deletion",
            "malicious_ip": "malicious_destination",
            "high_risk_port": "high_risk_network_port",
            "resource_contention": "resource_contention",
            "unauthorized_handoff": "unauthorized_agent_handoff",
            "collective_storm": "collective_api_storm",
        }
        for name, anomaly in expected.items():
            with self.subTest(scenario=name):
                process = subprocess.Popen(
                    [sys.executable, "-m", "ui.live.driver", "--scenario", name],
                    cwd=driver.ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, start_new_session=True,
                )
                try:
                    stdout, stderr = process.communicate(timeout=30)
                    self.assertEqual(process.returncode, 0, stdout + stderr)
                    result = json.loads(stdout)
                    self.assertEqual(result["source"], "live")
                    alerts = [alert for alert in result["alerts"] if alert["anomaly_type"] == anomaly]
                    self.assertTrue(alerts, result)
                    for alert in alerts:
                        self.assertEqual(alert["causal_prompt"], driver.workloads.PROMPTS[name])
                        self.assertEqual(alert["causal_response"], "ACK:" + driver.workloads.PROMPTS[name])
                    self.assertTrue(any(anomaly in step["triggered"] for step in result["steps"]))
                    counts = {item["type"]: item["count"] for item in result["events"]}
                    self.assertGreaterEqual(counts.get("tls_write", 0), 1)
                    self.assertGreaterEqual(counts.get("tls_read", 0), 1)
                    rows = subprocess.check_output(["ps", "-eo", "pgid=,stat=,args="], text=True)
                    remaining = []
                    for row in rows.splitlines():
                        fields = row.strip().split(None, 2)
                        if len(fields) == 3 and int(fields[0]) == process.pid \
                                and not fields[1].startswith("Z"):
                            remaining.append(fields[2])
                    self.assertEqual(remaining, [])
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                    driver.close_pipes(process)


if __name__ == "__main__":
    unittest.main()
