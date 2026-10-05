"""Scripted events that the real rule engine turns into alerts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from user.analyzer import Analyzer, load_config


RULES = ROOT / "config" / "rules.yaml"
WRITE_FLAGS = 1

ScenarioBuilder = Callable[["Clock"], list[dict[str, Any]]]


class Clock:
    """Pace the offline demonstration and record actual event times."""

    # 初始化模拟时钟（记录是否已开始）。
    def __init__(self) -> None:
        self.started = False

    # 推进模拟时钟：按需真实 sleep，返回当前时间戳。
    def tick(self, delay_ms: int) -> int:
        if self.started and delay_ms > 0:
            time.sleep(delay_ms / 1000)
        self.started = True
        return time.monotonic_ns()


# 构造一条符合真实 ABI 的模拟事件。
def _event(
    clock: Clock,
    agent_id: int,
    event_type: str,
    *,
    object_name: str = "",
    retval: int = 0,
    destination: str = "",
    port: int = 0,
    flags: int = 0,
    payload: str = "",
    delay_ms: int | None = None,
) -> dict[str, Any]:
    # The response gets a readable pause; ordinary actions follow at 120 ms.
    # These are real waits, while the event content remains a scripted demo.
    if delay_ms is None:
        delay_ms = 800 if event_type == "tls_read" else 120
    timestamp_ns = clock.tick(delay_ms)
    pid = 4100 + agent_id
    return {
        "time": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "timestamp_ns": timestamp_ns,
        "type": event_type,
        "agent_id": agent_id,
        "tgid": pid,
        "tid": pid,
        "ppid": 4000,
        "uid": 1000,
        "gid": 1000,
        "comm": "planner-agent" if agent_id == 1 else "executor-agent",
        "object": object_name,
        "dirfd": -100,
        "retval": retval,
        "destination": destination,
        "port": port,
        "flags": flags,
        "payload": payload,
        "child_pid": 0,
    }


# 构造一条带 Content-Length 的 HTTP 请求或响应报文。
def _http(kind: str, document: dict[str, Any]) -> str:
    body = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    body_length = len(body.encode("utf-8"))
    if kind == "request":
        head = f"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: {body_length}\r\n\r\n"
    else:
        head = f"HTTP/1.1 200 OK\r\nContent-Length: {body_length}\r\n\r\n"
    return head + body


# 生成一次 TLS Prompt/Response 往返的两条事件。
def _talk(clock: Clock, agent_id: int, prompt: str, response: str) -> list[dict[str, Any]]:
    request = {"messages": [{"role": "user", "content": prompt}]}
    reply = {"choices": [{"message": {"role": "assistant", "content": response}}]}
    return [
        _event(clock, agent_id, "tls_write", payload=_http("request", request), retval=len(prompt)),
        _event(clock, agent_id, "tls_read", payload=_http("response", reply), retval=len(response)),
    ]


# 场景：Prompt 后启动 /bin/sh。
def _shell(clock: Clock) -> list[dict[str, Any]]:
    return [
        *_talk(clock, 1, "请在工作区执行检查脚本", "ACK:将启动 shell"),
        _event(clock, 1, "exec", object_name="/bin/sh", retval=0),
    ]


# 场景：成功打开受保护路径。
def _sensitive(clock: Clock) -> list[dict[str, Any]]:
    return [
        *_talk(clock, 2, "读取受保护的结果文件", "ACK:准备打开敏感路径"),
        _event(
            clock,
            2,
            "openat",
            object_name="/tmp/ebpf-agent-protected/review-secret.txt",
            retval=3,
        ),
    ]


# 场景：删除工作区以外的文件。
def _workspace(clock: Clock) -> list[dict[str, Any]]:
    return [
        *_talk(clock, 1, "清理工作区以外的临时文件", "ACK:将删除指定路径"),
        _event(clock, 1, "unlinkat", object_name="/tmp/outside-workspace/notes.txt", retval=0),
    ]


# 场景：同一文件反复打开并反复连接同一地址。
def _loop(clock: Clock) -> list[dict[str, Any]]:
    events = _talk(clock, 1, "重复检查同一个计划文件并回报状态", "ACK:开始重复执行")
    for _ in range(5):
        events.append(
            _event(
                clock,
                1,
                "openat",
                object_name="/tmp/ebpf-agent-workspace/agent-1/review-loop.txt",
                retval=3,
                delay_ms=150,
            )
        )
    for _ in range(5):
        events.append(
            _event(
                clock,
                1,
                "connect",
                destination="127.0.0.1",
                port=9,
                retval=-115,
                delay_ms=180,
            )
        )
    return events


# 场景：短时间内大量执行进程。
def _process_storm(clock: Clock) -> list[dict[str, Any]]:
    events = _talk(clock, 1, "并行拉起一批辅助进程", "ACK:开始创建进程")
    events.extend(
        _event(clock, 1, "exec", object_name="/usr/bin/true", retval=0, delay_ms=50)
        for _ in range(20)
    )
    return events


# 场景：短时间内批量删除工作区文件。
def _deletion_storm(clock: Clock) -> list[dict[str, Any]]:
    events = _talk(clock, 1, "清空工作区里的中间文件", "ACK:开始批量删除")
    events.extend(
        _event(
            clock,
            1,
            "unlinkat",
            object_name=f"/tmp/ebpf-agent-workspace/agent-1/part-{index}.txt",
            retval=0,
            delay_ms=80,
        )
        for index in range(10)
    )
    return events


# 场景：连接规则里的文档地址。
def _malicious_ip(clock: Clock) -> list[dict[str, Any]]:
    return [
        *_talk(clock, 2, "把结果发到外部收集点", "ACK:准备连接目标地址"),
        _event(clock, 2, "connect", destination="203.0.113.66", port=443, retval=-115),
    ]


# 场景：连接高危端口。
def _high_risk_port(clock: Clock) -> list[dict[str, Any]]:
    return [
        *_talk(clock, 2, "打开远程调试端口", "ACK:准备连接高危端口"),
        _event(clock, 2, "connect", destination="127.0.0.1", port=4444, retval=-115),
    ]


# 场景：两个 Agent 写同一个共享文件。
def _contention(clock: Clock) -> list[dict[str, Any]]:
    path = "/tmp/ebpf-agent-workspace/shared/review-contended.txt"
    return [
        *_talk(clock, 1, "把计划写到共享文件", "ACK:planner 开始写入"),
        _event(clock, 1, "openat", object_name=path, retval=3, flags=WRITE_FLAGS),
        *_talk(clock, 2, "把执行结果写到同一个共享文件", "ACK:executor 开始写入"),
        _event(clock, 2, "openat", object_name=path, retval=4, flags=WRITE_FLAGS),
    ]


# 场景：一个 Agent 读取另一个 Agent 刚写入的非共享文件。
def _handoff(clock: Clock) -> list[dict[str, Any]]:
    path = "/tmp/ebpf-agent-handoff/review-unapproved.txt"
    return [
        *_talk(clock, 1, "把私有结果放到交接文件", "ACK:planner 已写入"),
        _event(clock, 1, "openat", object_name=path, retval=3, flags=WRITE_FLAGS),
        *_talk(clock, 2, "读取另一个 Agent 刚写下的交接文件", "ACK:executor 准备读取"),
        _event(clock, 2, "openat", object_name=path, retval=3, flags=0),
    ]


# 场景：两个 Agent 反复连接同一端点。
def _storm(clock: Clock) -> list[dict[str, Any]]:
    events = [
        *_talk(clock, 1, "连续请求同一个接口", "ACK:planner 开始请求"),
        *_talk(clock, 2, "也连续请求同一个接口", "ACK:executor 开始请求"),
    ]
    for _ in range(5):
        events.append(
            _event(clock, 1, "connect", destination="127.0.0.1", port=443, retval=0, delay_ms=100)
        )
    for _ in range(5):
        events.append(
            _event(clock, 2, "connect", destination="127.0.0.1", port=443, retval=0, delay_ms=100)
        )
    return events


SCENARIOS: dict[str, dict[str, Any]] = {
    "unexpected_shell": {
        "title": "非预期 Shell",
        "summary": "planner 收到执行脚本的 Prompt 后启动 /bin/sh。",
        "build": _shell,
    },
    "sensitive_file": {
        "title": "敏感文件",
        "summary": "executor 成功打开规则里的受保护路径。",
        "build": _sensitive,
    },
    "workspace_boundary": {
        "title": "工作区外删除",
        "summary": "planner 删除自己工作区以外的文件。",
        "build": _workspace,
    },
    "infinite_loop": {
        "title": "逻辑死循环",
        "summary": "同一 Agent 反复打开同一个文件，并反复连接同一个地址。",
        "build": _loop,
    },
    "resource_abuse": {
        "title": "进程风暴",
        "summary": "短时间内连续执行大量进程。",
        "build": _process_storm,
    },
    "excessive_deletion": {
        "title": "批量删除",
        "summary": "短时间内在工作区内连续删除多个文件。",
        "build": _deletion_storm,
    },
    "malicious_ip": {
        "title": "恶意地址",
        "summary": "连接规则中的文档地址 203.0.113.66。",
        "build": _malicious_ip,
    },
    "high_risk_port": {
        "title": "高危端口",
        "summary": "连接本地的 4444 端口。",
        "build": _high_risk_port,
    },
    "resource_contention": {
        "title": "文件写竞争",
        "summary": "两个 Agent 在短时间内写入同一个共享文件。",
        "build": _contention,
    },
    "unauthorized_handoff": {
        "title": "未授权传递",
        "summary": "executor 读取 planner 刚写入、且未标记为共享的文件。",
        "build": _handoff,
    },
    "collective_storm": {
        "title": "集体请求风暴",
        "summary": "两个 Agent 一起反复连接同一个网络端点。",
        "build": _storm,
    },
}


# 返回场景目录（id、标题、摘要）供前端列按钮。
def catalog() -> list[dict[str, str]]:
    return [
        {"id": key, "title": item["title"], "summary": item["summary"]}
        for key, item in SCENARIOS.items()
    ]


RULE_EXPLAIN = {
    "unexpected_shell": "成功执行的程序路径或文件名命中 unexpected_shells，其中包含 /bin/sh、/bin/bash、/bin/zsh 和 /usr/bin/dash。",
    "sensitive_file_access": "文件操作成功，并且路径落在 sensitive_paths 里。失败的打开不会告警。",
    "workspace_boundary_violation": "删除成功，且真实路径不在该 Agent 配置的 workspace 中。",
    "infinite_loop": "15 秒窗口内，文件、网络、进程、Prompt 这四类重复信号里至少两类同时越阈值。本场景是同一文件打开 5 次，加上同一地址连接 5 次。",
    "resource_abuse": "10 秒窗口内，fork/exec 进程事件达到 20 次。",
    "excessive_file_deletion": "10 秒窗口内，成功删除达到 10 次。",
    "malicious_destination": "connect 的目标 IP 命中 malicious_ips。演示使用文档地址 203.0.113.66，不会访问外网。",
    "high_risk_network_port": "connect 的目标端口命中 high_risk_ports，其中包含 23、4444 和 5555。",
    "resource_contention": "5 秒窗口内，两个不同 Agent 都写入了同一条路径。共享目录不会免掉写竞争。",
    "unauthorized_agent_handoff": "一个 Agent 读取了另一个 Agent 刚写入的文件，而该路径不在 shared_paths，两个 Agent 也不在允许协作名单里。",
    "collective_api_storm": "5 秒窗口内，至少两个 Agent 连接同一端点，且总连接数达到 10。",
}

ACTION_NAME = {
    "tls_write": "发出 Prompt",
    "tls_read": "收到 Response",
    "exec": "执行程序",
    "openat": "打开文件",
    "unlink": "删除文件",
    "unlinkat": "删除文件",
    "rmdir": "删除目录",
    "connect": "发起连接",
    "fork": "创建进程",
}


# 按 Agent ID 返回展示用名字。
def _agent_name(agent_id: int) -> str:
    return "planner-agent" if int(agent_id) == 1 else "executor-agent"


# 从模拟 TLS 事件里提取 Prompt/Response 文本用于展示。
def _semantic_text(event: dict[str, Any]) -> str:
    payload = str(event.get("payload") or "")
    parts = payload.split("\r\n\r\n", 1)
    if len(parts) != 2:
        return ""
    try:
        document = json.loads(parts[1])
    except json.JSONDecodeError:
        return ""
    messages = document.get("messages") or []
    if messages and isinstance(messages[0], dict):
        return str(messages[0].get("content") or "")
    choices = document.get("choices") or []
    if choices and isinstance(choices[0], dict):
        message = choices[0].get("message") or {}
        return str(message.get("content") or "")
    return ""


# 返回事件的操作对象：网络事件是 IP:端口，其余是路径。
def _target(event: dict[str, Any]) -> str:
    destination = str(event.get("destination") or "")
    port = int(event.get("port") or 0)
    if destination:
        return f"{destination}:{port}"
    return str(event.get("object") or "")


# 把事件裁剪成可以安全展示的公开字段。
def _public_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": event.get("time"),
        "timestamp_ns": event.get("timestamp_ns"),
        "type": event.get("type"),
        "agent_id": event.get("agent_id"),
        "tgid": event.get("tgid"),
        "object": event.get("object") or "",
        "destination": _target(event) if event.get("destination") else "",
        "retval": event.get("retval"),
    }


# 给事件算一个分组签名，连续同类事件会被并成一步。
def _signature(event: dict[str, Any]) -> tuple[Any, ...]:
    return (
        event.get("type"),
        event.get("agent_id"),
        event.get("object"),
        event.get("destination"),
        event.get("port"),
        event.get("flags"),
        event.get("retval"),
        event.get("payload") or "",
    )


# 相对起点换算成毫秒偏移。
def _offset_ms(event: dict[str, Any], origin: int) -> int:
    return round((int(event["timestamp_ns"]) - origin) / 1_000_000)


# 把一组连续同类事件合成时间线上的一步。
def _step_copy(group: list[dict[str, Any]], origin: int, triggered: list[str]) -> dict[str, Any]:
    first = group[0]
    last = group[-1]
    start = _offset_ms(first, origin)
    end = _offset_ms(last, origin)
    agent = _agent_name(int(first.get("agent_id") or 0))
    action = ACTION_NAME.get(str(first.get("type")), str(first.get("type")))
    target = _target(first)
    text = _semantic_text(first)
    count = len(group)
    if count == 1:
        title = f"{agent} {action}"
        if text:
            detail = text
        elif target:
            detail = f"对象 {target}，返回值 {first.get('retval')}。"
        else:
            detail = f"返回值 {first.get('retval')}。"
    else:
        title = f"{agent} 连续 {count} 次{action}"
        span = f"+{start} ms 到 +{end} ms"
        if triggered:
            detail = f"{span}，对象 {target or '-'}。第 {count} 次达到规则阈值。"
        else:
            detail = f"{span}，对象 {target or '-'}。这一组本身还没有凑满告警条件。"
    return {
        "offset_ms": start,
        "end_offset_ms": end,
        "time": first.get("time"),
        "end_time": last.get("time"),
        "count": count,
        "agent_id": first.get("agent_id"),
        "agent_name": agent,
        "type": first.get("type"),
        "title": title,
        "detail": detail,
        "target": target,
        "retval": first.get("retval"),
        "triggered": triggered,
    }


# 把「事件 + 命中告警」序列压成前端需要的时间线步骤。
def _flow(paired: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    if not paired:
        return []
    origin = int(paired[0][0]["timestamp_ns"])
    steps: list[dict[str, Any]] = []
    group: list[dict[str, Any]] = []
    triggered: list[str] = []

    # 把当前分组落成一个步骤（嵌套辅助函数）。
    def flush() -> None:
        nonlocal group, triggered
        if group:
            steps.append(_step_copy(group, origin, triggered))
        group = []
        triggered = []

    for event, fired in paired:
        if group and _signature(event) != _signature(group[-1]):
            flush()
        group.append(event)
        triggered.extend(str(alert.get("anomaly_type") or "") for alert in fired)
    flush()
    return steps


# 跑一个离线场景：生成事件、喂给真实规则引擎、返回时间线和告警。
def run_scenario(name: str) -> dict[str, Any]:
    spec = SCENARIOS.get(name)
    if spec is None:
        raise KeyError(name)
    events = spec["build"](Clock())
    analyzer = Analyzer(load_config(RULES))
    paired: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    alerts: list[dict[str, Any]] = []
    for event in events:
        fired = analyzer.process(event)
        paired.append((event, fired))
        alerts.extend(fired)
    origin = int(events[0]["timestamp_ns"]) if events else 0
    finished = _offset_ms(events[-1], origin) if events else 0
    for alert in alerts:
        alert["rule"] = RULE_EXPLAIN.get(str(alert.get("anomaly_type") or ""), "")
    return {
        "id": name,
        "title": spec["title"],
        "summary": spec["summary"],
        "duration_ms": finished,
        "steps": _flow(paired),
        "events": [_public_event(event) for event in events],
        "alerts": alerts,
    }
