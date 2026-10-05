#!/usr/bin/env python3
"""Run configuration-driven demonstrations for the three contest review points."""

from __future__ import annotations

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, TextIO


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "build" / "agent-monitor"
AGENT_WORKLOAD = ROOT / "demo" / "review_agent_workload.py"
TLS_SERVER = ROOT / "demo" / "review_tls_server.py"
DEFAULT_CONFIG_DIR = ROOT / "config" / "demos"

CHECK_DESCRIPTIONS = {
    "所有进程正常完成": "确认两个 Agent、本地 HTTPS 服务、eBPF 采集器和分析器均按预期结束。",
    "目标 Agent 源文件未被监控器修改": "比较运行前后的 SHA-256，验证监控过程没有修改 Agent 程序。",
    "事件管道无解析错误": "确认采集器输出的每一行 JSON 都能被正确转发和解析。",
    "Ring Buffer 无丢失且 ABI 有效": "检查内核到用户态的事件是否丢失，以及事件结构是否符合共享 ABI。",
    "采集器与分析器事件数一致": "比较采集端和运行器收到的事件总数，确认传输管道没有漏传。",
    "OpenSSL uprobe/uretprobe 真实挂载": "确认探针真实挂载到 OpenSSL 函数，而不是使用模拟的 HTTPS 数据。",
    "要求的内核事件类型全部可见": "确认进程、文件、网络和 TLS 等配置要求的事件均被实际采集。",
    "事件包含完整系统调用上下文": "检查事件是否带有时间、Agent、进程、用户和返回值等审计字段。",
    "每个 Agent 的 HTTPS Prompt 与 Response 均被截获": "确认两个 Agent 都产生了 TLS 写入和读取事件，且没有漏掉任一 Agent。",
    "fork 子进程继承根 Agent 的稳定身份": "确认子进程在 fork/exec 后仍归属于创建它的根 Agent。",
    "关键真实文件路径被精确记录": "确认共享文件、交接文件和受保护文件的完整路径均被准确观测。",
    "要求的异常类型全部命中": "将实际告警类型与配置中的预期集合比较，确认检测规则全部生效。",
    "并发 Agent 的 Prompt 因果链不串线": "确认每条告警只关联同一 Agent 的 Prompt/Response，没有跨 Agent 错配。",
    "性能评测器正常完成": "确认成对基线/监控性能实验正常执行并生成完整测量报告。",
    "代表性负载整体通过 5% 性能门槛": "综合文件、进程和网络场景，判断监控开销是否满足赛题的 5% 门槛。",
    "demo execution": "说明演示在准备、运行或收集结果阶段发生了错误。",
}

ALERT_DESCRIPTIONS = {
    "unexpected_shell": "检测到 Agent 启动了配置之外的 Shell 程序。",
    "infinite_loop": "检测到同一 Agent 在时间窗口内重复执行多类相同行为，符合复合循环特征。",
    "resource_contention": "检测到两个 Agent 在短时间内写入同一个资源。",
    "unauthorized_agent_handoff": "检测到一个 Agent 读取了另一个 Agent 刚写入、但未获授权的交接数据。",
    "sensitive_file_access": "检测到 Agent 成功访问了规则配置的敏感路径。",
    "collective_api_storm": "检测到多个 Agent 在短时间内反复连接同一个网络端点。",
}

EVENT_DESCRIPTIONS = {
    "fork": "展示根 Agent 创建子进程，以及新进程继承 Agent 身份。",
    "exec": "展示 Agent 进程树中的程序执行行为。",
    "exit": "展示 Agent 或其子进程的退出行为。",
    "openat": "展示 Agent 打开的真实文件路径和系统调用返回值。",
    "connect": "展示 Agent 发起连接的目标 IP、端口和返回值。",
    "tls_write": "展示从 OpenSSL 写函数截获的 HTTPS 请求明文元数据。",
    "tls_read": "展示从 OpenSSL 读函数截获的 HTTPS 响应明文元数据。",
}


# 把相对路径解析成相对仓库根目录的绝对路径。
def root_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


# 读取并校验评审配置（必需字段和 kind 取值）。
def load_config(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError("PyYAML is required; install requirements.txt") from error
    with path.open("r", encoding="utf-8") as stream:
        config = yaml.safe_load(stream)
    if not isinstance(config, dict):
        raise ValueError(f"{path}: configuration root must be a mapping")
    for key in ("id", "title", "kind", "report_path"):
        if not config.get(key):
            raise ValueError(f"{path}: missing required key {key!r}")
    if config["kind"] not in {"live", "performance"}:
        raise ValueError(f"{path}: kind must be 'live' or 'performance'")
    config["_path"] = str(path)
    return config


# 确保采集器已编译：跑 make 并检查产物存在。
def ensure_build() -> None:
    completed = subprocess.run(["make"], cwd=ROOT)
    if completed.returncode or not COLLECTOR.exists():
        raise RuntimeError("collector build failed")


# 保证有 sudo 凭证：非 root 时执行 sudo -v 认证一次。
def ensure_sudo() -> None:
    if os.geteuid() == 0:
        return
    if subprocess.run(["sudo", "-v"], cwd=ROOT).returncode:
        raise RuntimeError("sudo authentication failed")


# 给命令加 sudo -n 前缀（已经是 root 就不加）。
def privileged(command: list[str]) -> list[str]:
    return command if os.geteuid() == 0 else ["sudo", "-n", *command]


# 计算文件 SHA-256，用于验证演示前后源文件未被修改。
def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# 让内核分配一个空闲本地端口并返回。
def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


# 把采集器 stdout 转给分析器 stdin，同时收集事件和解析错误。
def event_forwarder(
    source: TextIO,
    destination: TextIO,
    events: list[dict[str, Any]],
    errors: list[str],
) -> None:
    try:
        for line in source:
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                errors.append(f"invalid collector JSON: {error}")
            else:
                if isinstance(item, dict):
                    events.append(item)
            try:
                destination.write(line)
                destination.flush()
            except BrokenPipeError:
                errors.append("analyzer closed its input early")
                break
    finally:
        try:
            destination.close()
        except BrokenPipeError:
            pass


# 把多行文本里的 JSON 行解析成字典列表，坏行跳过。
def parse_json_lines(text: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            items.append(item)
    return items


# 从事件里摘出报告需要的字段（并且不含 TLS 明文）。
def event_summary(event: dict[str, Any]) -> dict[str, Any]:
    summary = {
        key: event.get(key)
        for key in (
            "time",
            "type",
            "agent_id",
            "tgid",
            "tid",
            "ppid",
            "uid",
            "comm",
            "object",
            "child_pid",
            "destination",
            "port",
            "retval",
            "data_len",
            "data_size",
        )
        if key in event
    }
    summary["description"] = EVENT_DESCRIPTIONS.get(
        str(event.get("type") or ""), "展示一条真实采集到的底层事件。"
    )
    return {"description": summary.pop("description"), **summary}


# 给检查项生成人类可读的描述文本。
def check_description(name: str) -> str:
    if "精确归因到 Agent" in name:
        return "检查异常类型、Agent ID、Prompt 及所需 Response 是否同时精确匹配。"
    if "采集样本无丢失且 ABI 有效" in name:
        return "检查该类性能样本是否收到真实事件，并且零丢失、零 ABI 错误。"
    if "中位数及 95% 上界均不超过 5%" in name:
        return "同时检查配对开销中位数和其中位数单侧 95% 置信上界是否均不超过 5%。"
    return CHECK_DESCRIPTIONS.get(name, "检查该项实际证据是否满足演示配置中的预期。")


# 向检查结果列表追加一条带描述的证据记录。
def add_check(checks: list[dict[str, Any]], name: str, passed: bool, evidence: Any) -> None:
    checks.append(
        {
            "name": name,
            "description": check_description(name),
            "pass": bool(passed),
            "evidence": evidence,
        }
    )


# 给告警补充人类可读描述（按异常类型查表）。
def describe_alert(alert: dict[str, Any]) -> dict[str, Any]:
    description = ALERT_DESCRIPTIONS.get(
        str(alert.get("anomaly_type") or ""), "展示分析器根据规则生成的一条异常告警。"
    )
    return {"description": description, **alert}


# 判断一条告警是否满足配置里的期望（异常类型、Agent、Prompt、是否需要 Response）。
def alert_matches(alert: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key in ("anomaly_type", "agent_id", "causal_prompt"):
        if key in expected and alert.get(key) != expected[key]:
            return False
    if expected.get("require_response") and not alert.get("causal_response"):
        return False
    return True


# 对一次 live 演示做全部验收比对并生成检查项列表。
def evaluate_live(
    config: dict[str, Any],
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    collector_stderr: str,
    process_status: dict[str, Any],
    source_unchanged: bool,
    forwarding_errors: list[str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    expected = config.get("expected") or {}
    event_counts = Counter(str(item.get("type") or "unknown") for item in events)
    anomaly_types = Counter(str(item.get("anomaly_type") or "unknown") for item in alerts)

    add_check(
        checks,
        "所有进程正常完成",
        process_status.get("agents_ok")
        and process_status.get("server") == 0
        and process_status.get("collector") in {0, 124, 130}
        and process_status.get("analyzer") == 0,
        process_status,
    )
    add_check(
        checks,
        "目标 Agent 源文件未被监控器修改",
        source_unchanged,
        {"sha256_unchanged": source_unchanged},
    )
    add_check(
        checks,
        "事件管道无解析错误",
        not forwarding_errors,
        forwarding_errors,
    )

    stats_match = re.search(r"received=(\d+) dropped=(\d+) invalid=(\d+)", collector_stderr)
    stats = (
        {
            "received": int(stats_match.group(1)),
            "dropped": int(stats_match.group(2)),
            "invalid": int(stats_match.group(3)),
        }
        if stats_match
        else {}
    )
    add_check(
        checks,
        "Ring Buffer 无丢失且 ABI 有效",
        bool(stats) and stats["dropped"] == 0 and stats["invalid"] == 0,
        stats,
    )
    if stats:
        add_check(
            checks,
            "采集器与分析器事件数一致",
            stats["received"] == len(events),
            {"collector": stats["received"], "runner": len(events)},
        )

    if expected.get("openssl_uprobes"):
        attached = "attached OpenSSL plaintext probes" in collector_stderr
        add_check(checks, "OpenSSL uprobe/uretprobe 真实挂载", attached, {"attached": attached})

    required_types = {str(item) for item in expected.get("event_types") or []}
    observed_types = set(event_counts)
    add_check(
        checks,
        "要求的内核事件类型全部可见",
        required_types <= observed_types,
        {"required": sorted(required_types), "observed": dict(sorted(event_counts.items()))},
    )

    required_fields = [str(item) for item in expected.get("event_fields") or []]
    field_failures: list[str] = []
    for event_type in required_types:
        candidates = [item for item in events if item.get("type") == event_type]
        if candidates and not any(all(field in item for field in required_fields) for item in candidates):
            field_failures.append(event_type)
    if required_fields:
        add_check(
            checks,
            "事件包含完整系统调用上下文",
            not field_failures,
            {"fields": required_fields, "failed_types": field_failures},
        )

    tls_agents = {int(item) for item in expected.get("tls_agents") or []}
    if tls_agents:
        writes = {int(item.get("agent_id") or 0) for item in events if item.get("type") == "tls_write"}
        reads = {int(item.get("agent_id") or 0) for item in events if item.get("type") == "tls_read"}
        add_check(
            checks,
            "每个 Agent 的 HTTPS Prompt 与 Response 均被截获",
            tls_agents <= writes and tls_agents <= reads,
            {"required": sorted(tls_agents), "tls_write": sorted(writes), "tls_read": sorted(reads)},
        )

    if expected.get("process_tree_propagation"):
        propagated = False
        for fork_event in (item for item in events if item.get("type") == "fork"):
            child = fork_event.get("child_pid")
            if any(
                item.get("type") == "exec"
                and item.get("tgid") == child
                and item.get("agent_id") == fork_event.get("agent_id")
                for item in events
            ):
                propagated = True
                break
        add_check(
            checks,
            "fork 子进程继承根 Agent 的稳定身份",
            propagated,
            {"propagated": propagated},
        )

    required_paths = [str(root_path(item)) if not str(item).startswith("/tmp/") else str(item)
                      for item in expected.get("paths") or []]
    observed_paths = {str(item.get("object") or "") for item in events}
    if required_paths:
        add_check(
            checks,
            "关键真实文件路径被精确记录",
            all(path in observed_paths for path in required_paths),
            {"required": required_paths, "missing": [p for p in required_paths if p not in observed_paths]},
        )

    required_anomalies = {str(item) for item in expected.get("anomaly_types") or []}
    add_check(
        checks,
        "要求的异常类型全部命中",
        required_anomalies <= set(anomaly_types),
        {"required": sorted(required_anomalies), "observed": dict(sorted(anomaly_types.items()))},
    )

    for requirement in expected.get("alerts") or []:
        matches = [item for item in alerts if alert_matches(item, requirement)]
        label = f"{requirement.get('anomaly_type')} 精确归因到 Agent {requirement.get('agent_id')}"
        add_check(checks, label, bool(matches), {"expected": requirement, "matches": len(matches)})

    if expected.get("causal_isolation"):
        prompts = {int(item["id"]): str(item["prompt"]) for item in config.get("agents") or []}
        causal_alerts = [item for item in alerts if item.get("causal_prompt")]
        mismatches = [
            {
                "alert_id": item.get("alert_id"),
                "agent_id": item.get("agent_id"),
                "prompt": item.get("causal_prompt"),
            }
            for item in causal_alerts
            if item.get("causal_prompt") != prompts.get(int(item.get("agent_id") or 0))
        ]
        add_check(
            checks,
            "并发 Agent 的 Prompt 因果链不串线",
            bool(causal_alerts) and not mismatches,
            {"causal_alerts": len(causal_alerts), "mismatches": mismatches},
        )
    return checks


# 用 openssl 生成演示用的临时自签证书。
def generate_certificate(directory: Path) -> tuple[Path, Path]:
    certificate = directory / "certificate.pem"
    private_key = directory / "private-key.pem"
    completed = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    if completed.returncode:
        raise RuntimeError("failed to generate temporary TLS certificate")
    return certificate, private_key


def prepare_review_workspace(
    config: dict[str, Any], directory: Path
) -> tuple[dict[str, Any], Path, dict[str, str]]:
    """Keep review fixtures private to this run, regardless of previous owners."""
    import yaml

    paths = {
        "/tmp/ebpf-agent-workspace": str(directory / "workspace"),
        "/tmp/ebpf-agent-handoff": str(directory / "handoff"),
        "/tmp/ebpf-agent-protected": str(directory / "protected"),
    }

    def remap(value: str) -> str:
        for old, new in paths.items():
            if value == old or value.startswith(old + "/"):
                return new + value[len(old):]
        return value

    runtime_config = copy.deepcopy(config)
    expected = runtime_config.get("expected") or {}
    if "paths" in expected:
        expected["paths"] = [remap(str(path)) for path in expected["paths"]]
    rules_path = root_path(config.get("analyzer_config", "config/rules.yaml"))
    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    if not isinstance(rules, dict):
        raise ValueError("analyzer configuration root must be a mapping")
    for agent in (rules.get("agents") or {}).values():
        if agent.get("workspace"):
            agent["workspace"] = remap(str(agent["workspace"]))
    rules["sensitive_paths"] = [remap(str(path)) for path in rules.get("sensitive_paths") or []]
    multi_agent = rules.get("multi_agent") or {}
    if "shared_paths" in multi_agent:
        multi_agent["shared_paths"] = [remap(str(path)) for path in multi_agent["shared_paths"]]
    analyzer_config = directory / "rules.yaml"
    analyzer_config.write_text(yaml.safe_dump(rules, allow_unicode=True), encoding="utf-8")
    protected = Path(paths["/tmp/ebpf-agent-protected"]) / "review-secret.txt"
    protected.parent.mkdir(parents=True, exist_ok=True)
    protected.write_text("harmless review decoy\n", encoding="utf-8")
    paths["protected_file"] = str(protected)
    return runtime_config, analyzer_config, paths


def stop_review_process(process: subprocess.Popen, timeout: float = 3) -> None:
    """Terminate, reap and close a child on success, failure or interruption."""
    if process.poll() is None:
        try:
            process.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def read_startup(process: subprocess.Popen, timeout: float = 10) -> str:
    """Read a startup line without leaving a failed child waiting forever."""
    assert process.stdout is not None
    result: queue.Queue[str] = queue.Queue()
    threading.Thread(target=lambda: result.put(process.stdout.readline()), daemon=True).start()
    try:
        return result.get(timeout=timeout)
    except queue.Empty as error:
        raise TimeoutError("review subprocess did not report startup") from error


# 跑一次 live 演示：起 HTTPS 服务、双 Agent、采集器和分析器，收集事件与告警。
def run_live(config: dict[str, Any]) -> dict[str, Any]:
    runtime = float((config.get("runtime") or {}).get("seconds", 9))
    agents_config = config.get("agents") or []
    if len(agents_config) < 2:
        raise ValueError("live review demos require at least two configured Agents")

    source_before = file_digest(AGENT_WORKLOAD)
    processes: list[subprocess.Popen[str]] = []
    agents: list[tuple[dict[str, Any], subprocess.Popen[str], str]] = []
    events: list[dict[str, Any]] = []
    forwarding_errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="agent-monitor-review-") as temp_directory:
        config, analyzer_config, runtime_paths = prepare_review_workspace(config, Path(temp_directory))
        certificate, private_key = generate_certificate(Path(temp_directory))
        port = reserve_port()
        server = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(TLS_SERVER),
                "--port",
                str(port),
                "--certificate",
                str(certificate),
                "--private-key",
                str(private_key),
                "--connections",
                str(len(agents_config)),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        processes.append(server)
        try:
            assert server.stdout is not None
            server_ready = read_startup(server).strip()
            if not server_ready.startswith("TLS SERVER READY"):
                raise RuntimeError(f"TLS server failed to start: {server_ready}")
            for agent_config in agents_config:
                command = [
                    sys.executable,
                    "-u",
                    str(AGENT_WORKLOAD),
                    "--agent-id",
                    str(agent_config["id"]),
                    "--role",
                    str(agent_config["role"]),
                    "--prompt",
                    str(agent_config["prompt"]),
                    "--port",
                    str(port),
                    "--start-delay",
                    str(agent_config.get("start_delay", 2.0)),
                    "--loop-count",
                    str(agent_config.get("loop_count", 1)),
                    "--workspace-root",
                    runtime_paths["/tmp/ebpf-agent-workspace"],
                    "--handoff-root",
                    runtime_paths["/tmp/ebpf-agent-handoff"],
                    "--protected-file",
                    runtime_paths["protected_file"],
                ]
                process = subprocess.Popen(
                    command,
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                processes.append(process)
                assert process.stdout is not None
                ready_line = read_startup(process)
                if not ready_line.startswith("REVIEW AGENT"):
                    raise RuntimeError(f"Agent {agent_config['id']} failed to become ready")
                agents.append((agent_config, process, ready_line))

            collector_command = privileged(
                [
                    "/usr/bin/timeout",
                    "--signal=INT",
                    "--kill-after=2",
                    str(runtime),
                    str(COLLECTOR),
                ]
            )
            for agent_config, process, _ in agents:
                collector_command.extend(["--agent", f"{agent_config['id']}:{process.pid}"])
            collector_command.append("--json")
            collector = subprocess.Popen(
                collector_command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            processes.append(collector)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ROOT)
            analyzer = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "user.analyzer",
                    "--config",
                    str(analyzer_config),
                    "--no-persist",
                ],
                cwd=ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )
            processes.append(analyzer)
            assert collector.stdout is not None
            assert analyzer.stdin is not None
            forward_thread = threading.Thread(
                target=event_forwarder,
                args=(collector.stdout, analyzer.stdin, events, forwarding_errors),
                daemon=True,
            )
            forward_thread.start()

            agent_logs: dict[int, dict[str, str | int]] = {}
            agents_ok = True
            for agent_config, process, ready_line in agents:
                stdout, stderr = process.communicate(timeout=runtime + 10)
                agent_logs[int(agent_config["id"])] = {
                    "returncode": int(process.returncode or 0),
                    "stdout": (ready_line + stdout)[-2000:],
                    "stderr": stderr[-2000:],
                }
                agents_ok = agents_ok and process.returncode == 0

            server_stdout, server_stderr = server.communicate(timeout=10)
            collector.wait(timeout=runtime + 10)
            forward_thread.join(timeout=5)
            analyzer.wait(timeout=10)
            collector_stderr = collector.stderr.read() if collector.stderr else ""
            analyzer_stdout = analyzer.stdout.read() if analyzer.stdout else ""
            analyzer_stderr = analyzer.stderr.read() if analyzer.stderr else ""
            alerts = [item for item in parse_json_lines(analyzer_stdout) if item.get("anomaly_type")]
            process_status = {
                "agents_ok": agents_ok,
                "server": server.returncode,
                "collector": collector.returncode,
                "analyzer": analyzer.returncode,
            }
            checks = evaluate_live(
                config,
                events,
                alerts,
                collector_stderr,
                process_status,
                source_before == file_digest(AGENT_WORKLOAD),
                forwarding_errors,
            )
            event_counts = Counter(str(item.get("type") or "unknown") for item in events)
            samples: list[dict[str, Any]] = []
            sample_types = [str(item) for item in (config.get("presentation") or {}).get("sample_event_types", [])]
            for event_type in sample_types:
                sample = next((item for item in events if item.get("type") == event_type), None)
                if sample:
                    samples.append(event_summary(sample))
            return {
                "id": config["id"],
                "title": config["title"],
                "description": config.get("description", config.get("review_point", "")),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "config": config["_path"],
                "environment": {"kernel": os.uname().release, "machine": os.uname().machine},
                "runtime_paths": runtime_paths,
                "pass": all(item["pass"] for item in checks),
                "checks": checks,
                "event_counts_description": "汇总本次从内核和 OpenSSL 探针实际收到的各类事件数量。",
                "event_counts": dict(sorted(event_counts.items())),
                "alerts_description": "列出命中检测规则的异常，以及对应 Agent、系统行为和 Prompt/Response 因果上下文。",
                "alerts": [describe_alert(item) for item in alerts],
                "sample_events_description": "每种关键事件选取一条脱敏样例，用于展示可观测字段；这不是全部事件。",
                "sample_events": samples,
                "collector_summary_description": "采集器摘要说明探针挂载情况、Agent PID 映射及事件健康计数。",
                "collector_summary": collector_stderr[-5000:],
                "analyzer_summary_description": "分析器摘要说明处理的事件数、生成的告警数和语义关联数。",
                "analyzer_summary": analyzer_stderr[-2000:],
                "agent_logs_description": "记录两个演示 Agent 的启动、HTTPS 响应和正常结束状态。",
                "agent_logs": agent_logs,
                "server_description": "记录仅在本机运行的临时 HTTPS 服务启动和结束状态。",
                "server_stdout": (server_ready + "\n" + server_stdout)[-2000:],
                "server_stderr": server_stderr[-2000:],
            }
        finally:
            for process in reversed(processes):
                stop_review_process(process)


# 以 root 调起性能评测器，把它的结论复核成评审检查项。
def run_performance(config: dict[str, Any]) -> dict[str, Any]:
    settings = config.get("performance") or {}
    output_directory = root_path(settings.get("output_dir", "docs/review_reports/performance"))
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    command = privileged(
        [
            sys.executable,
            str(ROOT / "tools" / "performance_eval.py"),
            "--iterations",
            str(settings.get("iterations", 10)),
            "--profile",
            str(settings.get("profile", "representative")),
            "--output-dir",
            str(output_directory),
        ]
    )
    optional_arguments = {
        "file_operations": "--file-operations",
        "exec_operations": "--exec-operations",
        "network_operations": "--network-operations",
        "decision_rounds": "--decision-rounds",
    }
    for key, option in optional_arguments.items():
        if key in settings:
            command.extend([option, str(settings[key])])
    process = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        stdout, stderr = process.communicate(timeout=int(settings.get("timeout_seconds", 300)))
    finally:
        stop_review_process(process)
    raw_report_path = output_directory / "performance_report.json"
    raw_report = (
        json.loads(raw_report_path.read_text(encoding="utf-8"))
        if raw_report_path.exists()
        else {"pass": False, "scenarios": {}}
    )
    checks: list[dict[str, Any]] = []
    add_check(
        checks,
        "性能评测器正常完成",
        process.returncode == 0,
        {"returncode": process.returncode, "stderr": stderr[-2000:]},
    )
    for name, scenario in (raw_report.get("scenarios") or {}).items():
        pairs = scenario.get("pairs") or []
        healthy = bool(pairs) and all(
            int(pair.get("received", 0)) > 0
            and int(pair.get("dropped", -1)) == 0
            and int(pair.get("invalid", -1)) == 0
            for pair in pairs
        )
        add_check(
            checks,
            f"{name} 采集样本无丢失且 ABI 有效",
            healthy,
            {"pairs": len(pairs)},
        )
        add_check(
            checks,
            f"{name} 中位数及 95% 上界均不超过 5%",
            bool(scenario.get("pass")),
            {
                "median_overhead_percent": scenario.get("median_overhead_percent"),
                "median_95_percent_upper": scenario.get("median_95_percent_upper"),
            },
        )
    add_check(
        checks,
        "代表性负载整体通过 5% 性能门槛",
        bool(raw_report.get("pass")),
        {"pass": raw_report.get("pass")},
    )
    return {
        "id": config["id"],
        "title": config["title"],
        "description": config.get("description", config.get("review_point", "")),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": config["_path"],
        "environment": {"kernel": os.uname().release, "machine": os.uname().machine},
        "pass": all(item["pass"] for item in checks),
        "checks": checks,
        "performance_description": "保存文件、进程和网络三类负载的逐组基线/监控样本及统计结论。",
        "performance": raw_report,
        "stdout_description": "性能评测器的标准输出，用于复核报告生成位置和整体结论。",
        "stdout": stdout[-10000:],
        "stderr_description": "性能评测器的错误输出；正常完成时通常为空。",
        "stderr": stderr[-3000:],
    }


# 把评审报告写到配置指定的 report_path。
def write_report(config: dict[str, Any], report: dict[str, Any]) -> Path:
    path = root_path(config["report_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


# 在终端打印 PASS/FAIL、事件证据和告警摘要。
def print_report(config: dict[str, Any], report: dict[str, Any], path: Path) -> None:
    print(f"\n=== {config['title']} ===")
    print(f"评审要点：{config.get('review_point', '')}")
    print(f"演示说明：{config.get('description', config.get('review_point', ''))}")
    for check in report.get("checks") or []:
        status = "PASS" if check["pass"] else "FAIL"
        print(f"说明：{check.get('description', check_description(str(check['name'])))}")
        print(f"[{status}] {check['name']}")
    if report.get("event_counts"):
        print(f"说明：{report.get('event_counts_description')}")
        counts = " ".join(f"{name}={count}" for name, count in report["event_counts"].items())
        print(f"事件证据：{counts}")
    for alert in report.get("alerts") or []:
        print(f"说明：{alert.get('description', '展示一条规则命中的异常告警。')}")
        prompt = alert.get("causal_prompt") or "-"
        response = alert.get("causal_response") or "-"
        print(
            f"告警证据：{alert.get('anomaly_type')} Agent={alert.get('agent_id')} "
            f"PID={alert.get('pid')} op={alert.get('operation')} object={alert.get('object')} "
            f"Prompt={prompt!r} Response={response!r}"
        )
    for event in report.get("sample_events") or []:
        print(f"说明：{event.get('description', '展示一条真实采集到的底层事件。')}")
        print(
            f"观测样例：type={event.get('type')} Agent={event.get('agent_id')} "
            f"PID/TID={event.get('tgid')}/{event.get('tid')} object={event.get('object') or '-'} "
            f"destination={event.get('destination') or '-'}:{event.get('port') or 0}"
        )
    scenarios = (report.get("performance") or {}).get("scenarios") or {}
    for name, result in scenarios.items():
        print(f"说明：展示 {name} 负载的配对开销中位数、95% 置信上界和门槛结论。")
        print(
            f"性能证据：{name} median={result.get('median_overhead_percent', 0):.3f}% "
            f"95%upper={result.get('median_95_percent_upper', 0):.3f}% "
            f"result={'PASS' if result.get('pass') else 'FAIL'}"
        )
    print("说明：只有本场景的全部自动检查均通过，最终结果才会判定为 PASS。")
    print(f"结果：{'PASS' if report.get('pass') else 'FAIL'}")
    print("说明：下面的 JSON 文件保存完整检查项、原始证据和运行摘要，便于答辩复核。")
    print(f"机器可读证据：{path}")


# 入口：加载配置、确保构建与 sudo，逐个跑演示并写报告。
def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, action="append")
    parser.add_argument("--all", action="store_true", help="run every review demo config")
    args = parser.parse_args()
    paths = list(args.config or [])
    if args.all:
        paths.extend(sorted(DEFAULT_CONFIG_DIR.glob("review-*.yaml")))
    if not paths:
        parser.error("pass --config PATH or --all")

    unique_paths: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path if path.is_absolute() else ROOT / path
        resolved = resolved.resolve()
        if resolved not in seen:
            unique_paths.append(resolved)
            seen.add(resolved)

    configs = [load_config(path) for path in unique_paths]
    ensure_build()
    ensure_sudo()
    overall = True
    for config in configs:
        try:
            report = run_live(config) if config["kind"] == "live" else run_performance(config)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report = {
                "id": config["id"],
                "title": config["title"],
                "description": config.get("description", config.get("review_point", "")),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "config": config["_path"],
                "pass": False,
                "checks": [
                    {
                        "name": "demo execution",
                        "description": check_description("demo execution"),
                        "pass": False,
                        "evidence": str(error),
                    }
                ],
            }
        path = write_report(config, report)
        print_report(config, report, path)
        overall = overall and bool(report.get("pass"))
    return 0 if overall else 1


def main() -> int:
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        return _main()
    except KeyboardInterrupt:
        print("review interrupted; child processes have been cleaned up", file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
