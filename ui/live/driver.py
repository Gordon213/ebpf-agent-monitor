#!/usr/bin/env python3
"""Privileged one-shot engine: real Agent operations, eBPF collection, analysis.

Run through sudo (for example ``sudo -n python3 -m ui.live.driver --scenario
unexpected_shell``) and print one JSON document with the real timeline.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
import json
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui.live import workloads  # noqa: E402
from ui.live.protocol import encode, lines  # noqa: E402
from ui.scenarios import RULE_EXPLAIN, catalog  # noqa: E402

COLLECTOR = ROOT / "build" / "agent-monitor"
TLS_SERVER = ROOT / "demo" / "review_tls_server.py"
CONFIG = ROOT / "config" / "rules.yaml"

TYPE_LABEL = {
    "fork": "创建进程",
    "exec": "执行程序",
    "exit": "进程退出",
    "openat": "打开文件",
    "unlink": "删除文件",
    "unlinkat": "按目录删除",
    "rmdir": "删除目录",
    "connect": "发起连接",
    "tls_read": "HTTPS 响应",
    "tls_write": "HTTPS 请求",
}

STEP_TITLE = {
    "exchange": "发出 Prompt 并收到 Response",
    "open": "打开文件",
    "delete": "删除文件",
    "connect": "发起连接",
    "exec": "执行程序",
}


def now_ns() -> int:
    return time.monotonic_ns()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def generate_certificate(directory: Path) -> tuple[Path, Path]:
    certificate = directory / "live-certificate.pem"
    private_key = directory / "live-key.pem"
    completed = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(private_key), "-out", str(certificate),
            "-days", "1", "-subj", "/CN=127.0.0.1",
        ],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    if completed.returncode:
        raise RuntimeError("failed to generate the temporary TLS certificate")
    return certificate, private_key


def stop_process(
    process: subprocess.Popen, timeout: float = 3.0, stop_signal: int = signal.SIGTERM
) -> None:
    """Stop and reap a subprocess, including one that ignores termination."""
    if process.poll() is None:
        try:
            process.send_signal(stop_signal)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def close_pipes(process: subprocess.Popen) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def startup_line(process: subprocess.Popen, timeout: float = 10.0) -> str:
    """Bound the TLS server handshake so startup failures reach cleanup."""
    assert process.stdout is not None
    result: queue.Queue[str] = queue.Queue()
    reader = threading.Thread(
        target=lambda: result.put(process.stdout.readline().strip()), daemon=True
    )
    reader.start()
    try:
        return result.get(timeout=timeout)
    except queue.Empty as error:
        raise TimeoutError("TLS server did not report startup") from error


class WorkerConnection:
    def __init__(self, agent_id: int, process: subprocess.Popen, connection: socket.socket) -> None:
        self.agent_id = agent_id
        self.process = process
        self.connection = connection
        self.stream = connection.makefile("r", encoding="utf-8", newline="\n")
        self.messages: deque[dict[str, Any]] = deque()
        self.lock = threading.Lock()
        self.disconnected = threading.Event()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        try:
            for item in lines(self.stream):
                with self.lock:
                    self.messages.append(item)
        except (OSError, ValueError):
            pass
        finally:
            self.disconnected.set()

    def send(self, message: dict[str, Any]) -> None:
        self.connection.sendall(encode(message))

    def wait_for(self, kind: str, timeout: float = 30.0) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        collected: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            with self.lock:
                item = self.messages.popleft() if self.messages else None
            if item is not None:
                collected.append(item)
                if item.get("kind") == "error":
                    raise RuntimeError(f"worker {self.agent_id}: {item.get('detail', 'failed')}")
                if item.get("kind") == kind:
                    return collected
                continue
            if self.disconnected.is_set():
                raise RuntimeError(f"worker {self.agent_id} disconnected before {kind}")
            self.disconnected.wait(0.02)
        raise TimeoutError(f"worker {self.agent_id} did not report {kind}")

    def close(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.reader.join(timeout=2)
        self.stream.close()
        self.connection.close()


class Collector:
    """Owns the collector and analyzer subprocesses of one live run."""

    def __init__(self, agent_pids: dict[int, int]) -> None:
        self.alerts: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.stderr_lines: deque[str] = deque(maxlen=40)
        self.analyzer_errors: deque[str] = deque(maxlen=40)
        self.forward_error = ""
        self._closed = False
        command = [str(COLLECTOR)]
        for agent_id, pid in sorted(agent_pids.items()):
            command.extend(["--agent", f"{agent_id}:{pid}"])
        command.append("--json")
        self.collector = subprocess.Popen(
            command, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT)
        try:
            self.analyzer = subprocess.Popen(
                [
                    sys.executable, "-m", "user.analyzer",
                    "--config", str(CONFIG), "--no-persist",
                ],
                cwd=str(ROOT), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, env=environment, bufsize=1,
            )
        except BaseException:
            stop_process(self.collector)
            close_pipes(self.collector)
            raise
        self.forwarder = threading.Thread(target=self._forward, daemon=True)
        self.error_reader = threading.Thread(
            target=self._read_errors, args=(self.collector.stderr, self.stderr_lines), daemon=True
        )
        self.analyzer_error_reader = threading.Thread(
            target=self._read_errors, args=(self.analyzer.stderr, self.analyzer_errors), daemon=True
        )
        self.alert_reader = threading.Thread(target=self._read_alerts, daemon=True)
        for reader in (
            self.forwarder, self.error_reader, self.analyzer_error_reader, self.alert_reader
        ):
            reader.start()

    def _forward(self) -> None:
        assert self.collector.stdout is not None and self.analyzer.stdin is not None
        try:
            for line in self.collector.stdout:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict) or not item.get("type"):
                    continue
                with self.lock:
                    self.events.append(item)
                self.analyzer.stdin.write(line)
                self.analyzer.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            self.forward_error = str(error)
        finally:
            # EOF is sent only after every captured event has reached the analyzer.
            try:
                self.analyzer.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass

    def _read_alerts(self) -> None:
        assert self.analyzer.stdout is not None
        for item in lines(self.analyzer.stdout):
            if item.get("anomaly_type"):
                with self.lock:
                    self.alerts.append(item)

    def _read_errors(self, stream, target: deque[str]) -> None:
        assert stream is not None
        for line in stream:
            with self.lock:
                target.append(line.rstrip())

    def wait_started(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                log = list(self.stderr_lines)
            if self.collector.poll() is not None:
                raise RuntimeError("collector exited early: " + " | ".join(log[-5:]))
            if self.analyzer.poll() is not None:
                raise RuntimeError("analyzer exited before capture started")
            if any(line.startswith("monitoring ") and "root Agent(s)" in line for line in log):
                return
            time.sleep(0.02)
        raise TimeoutError("collector did not report startup")

    def close(self, timeout: float = 8.0) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            stop_process(self.collector, timeout, signal.SIGINT)
        finally:
            self.forwarder.join(timeout=timeout)
            # A stalled analyzer must not leave a writer blocked on its stdin.
            if self.forwarder.is_alive():
                stop_process(self.analyzer)
                self.forwarder.join(timeout=3)
            try:
                self.analyzer.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_process(self.analyzer)
            for reader in (self.alert_reader, self.error_reader, self.analyzer_error_reader):
                reader.join(timeout=3)
            close_pipes(self.collector)
            close_pipes(self.analyzer)

    def finished_alerts(self, timeout: float = 8.0) -> list[dict[str, Any]]:
        self.close(timeout)
        if self.collector.returncode:
            raise RuntimeError("collector failed: " + " | ".join(self.stderr_lines))
        if self.analyzer.returncode or self.forward_error:
            raise RuntimeError(
                "analyzer failed: " + " | ".join(self.analyzer_errors) + self.forward_error
            )
        with self.lock:
            return list(self.alerts)

    def captured_events(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.events)


OPERATION_EVENTS = {
    "open": {"openat"},
    "delete": {"unlink", "unlinkat", "rmdir"},
    "connect": {"connect"},
    "exec": {"fork", "exec", "exit"},
    "exchange": {"connect", "tls_write", "tls_read"},
}


def match_step(
    event: dict[str, Any], operations: list[dict[str, Any]]
) -> int | None:
    """Match by Agent, operation family, object and the actual execution interval."""
    agent_id = int(event.get("agent_id") or 0)
    event_type = str(event.get("operation") or event.get("type") or "")
    event_object = str(event.get("normalized_object") or event.get("object") or "")
    event_ns = int(event.get("timestamp_ns") or 0)
    best: tuple[int, int] | None = None
    for index, operation in enumerate(operations):
        if int(operation.get("agent_id") or 0) != agent_id:
            continue
        op = str(operation.get("op") or "")
        if event_type not in OPERATION_EVENTS.get(op, set()):
            continue
        target = str(operation.get("target") or "")
        if op != "exchange" and event_type not in {"fork", "exit"} and event_object:
            same_object = target == event_object
            if event_type != "connect":
                same_object = same_object or os.path.realpath(target) == os.path.realpath(event_object)
            if not same_object:
                continue
        started = int(operation.get("started_ns") or 0)
        finished = int(operation.get("finished_ns") or 0)
        if not event_ns or not started <= event_ns <= finished:
            continue
        score = (event_ns - started, index)
        if best is None or score < best:
            best = score
    return best[1] if best is not None else None


def build_steps(
    name: str,
    operations: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    agent_names: dict[int, str],
    captured_events: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    ordered = sorted(operations, key=lambda item: int(item.get("started_ns") or 0))
    captured = captured_events or []
    events_by_step: dict[int, list[dict[str, Any]]] = {}
    triggers_by_step: dict[int, list[str]] = {}
    for event in captured:
        index = match_step(event, ordered)
        if index is not None:
            events_by_step.setdefault(index, []).append(event)
    for alert in alerts:
        index = match_step(alert, ordered)
        if index is not None:
            triggered = triggers_by_step.setdefault(index, [])
            anomaly = str(alert.get("anomaly_type") or "")
            if anomaly not in triggered:
                triggered.append(anomaly)

    origin = int(ordered[0]["started_ns"]) if ordered else 0
    steps: list[dict[str, Any]] = []
    for index, operation in enumerate(ordered):
        offset = max(0, (int(operation["started_ns"]) - origin) // 1_000_000)
        end = max(offset, (int(operation["finished_ns"]) - origin) // 1_000_000)
        agent_id = int(operation["agent_id"])
        op = str(operation.get("op") or "")
        target = str(operation.get("target") or "")
        detail = str(operation.get("detail") or "")
        title = STEP_TITLE.get(op, op)
        if detail and detail != "ok":
            title = f"{title}（{detail}）"
        actual = events_by_step.get(index, [])
        preferred = {"exec": "exec", "exchange": "tls_write"}.get(op)
        primary = next((event for event in actual if event["type"] == preferred), None)
        if primary is None and actual:
            primary = actual[0]
        retval = primary.get("retval") if primary is not None else operation.get("retval")
        steps.append(
            {
                "offset_ms": offset,
                "end_offset_ms": end,
                "count": 1,
                "agent_id": agent_id,
                "agent_name": agent_names.get(agent_id, f"agent-{agent_id}"),
                "type": primary["type"] if primary is not None else op,
                "title": f"{agent_names.get(agent_id, f'agent-{agent_id}')} {title}",
                "detail": target + (f"，返回值 {retval}" if op != "exchange" else ""),
                "target": target,
                "retval": retval,
                "triggered": triggers_by_step.get(index, []),
            }
        )
    duration = max(
        (max(0, (int(item["finished_ns"]) - origin) // 1_000_000) for item in ordered),
        default=0,
    )
    counts = Counter(str(event["type"]) for event in captured if event.get("type"))
    return steps, [{"type": key, "count": value} for key, value in sorted(counts.items())], duration


def run(name: str) -> dict[str, Any]:
    spec = next((item for item in catalog() if item["id"] == name), None)
    if spec is None:
        raise KeyError(name)
    if os.geteuid() != 0 and not os.environ.get("AGENT_MONITOR_SKIP_ROOT_CHECK"):
        raise RuntimeError("live capture needs root; run this driver through sudo")
    if not COLLECTOR.is_file():
        raise RuntimeError(f"collector not built: {COLLECTOR}; run make first")

    workloads.prepare()
    plan = workloads.plan(name)
    config_text = __import__("yaml").safe_load(CONFIG.read_text(encoding="utf-8")) or {}
    agent_names = {
        int(agent_id): str((entry or {}).get("name") or f"agent-{agent_id}")
        for agent_id, entry in (config_text.get("agents") or {}).items()
    }

    operations: list[dict[str, Any]] = []
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    with tempfile.TemporaryDirectory(prefix="agent-live-") as temporary:
        temp_directory = Path(temporary)
        certificate, private_key = generate_certificate(temp_directory)
        port = free_port()
        tls_server = subprocess.Popen(
            [
                sys.executable, "-u", str(TLS_SERVER),
                "--port", str(port),
                "--certificate", str(certificate),
                "--private-key", str(private_key),
                "--connections", str(len(plan["exchanges"])),
            ],
            cwd=str(ROOT),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        processes = [tls_server]
        workers: dict[int, WorkerConnection] = {}
        collector: Collector | None = None
        try:
            ready = startup_line(tls_server)
            if not ready.startswith("TLS SERVER READY"):
                raise RuntimeError(f"TLS server failed to start: {ready}")
            agent_ids = sorted(int(item) for item in plan["operations"])
            for agent_id in agent_ids:
                path = str(temp_directory / f"worker-{agent_id}.sock")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                    server.bind(path)
                    server.listen(1)
                    process = subprocess.Popen(
                        [
                            sys.executable, "-u", str(ROOT / "ui" / "live" / "worker.py"),
                            "--agent-id", str(agent_id), "--socket", path,
                            "--tls-port", str(port), "--tls-certificate", str(certificate),
                        ],
                        cwd=str(ROOT), env=environment,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                    )
                    processes.append(process)
                    server.settimeout(5)
                    connection, _ = server.accept()
                workers[agent_id] = WorkerConnection(agent_id, process, connection)
                workers[agent_id].wait_for("ready", timeout=5)

            collector = Collector({agent_id: worker.process.pid for agent_id, worker in workers.items()})
            collector.wait_started()
            for exchange in plan["exchanges"]:
                agent_id = int(exchange["agent_id"])
                workers[agent_id].send({"command": "exchange", "prompt": exchange["prompt"]})
            for agent_id in agent_ids:
                collected = workers[agent_id].wait_for("done", timeout=20)
                operations.extend(item for item in collected if item.get("kind") == "operation")

            for agent_id in agent_ids:
                workers[agent_id].send(
                    {"command": "run", "operations": plan["operations"][str(agent_id)]}
                )
                if plan.get("sequential"):
                    collected = workers[agent_id].wait_for("done", timeout=30)
                    operations.extend(item for item in collected if item.get("kind") == "operation")
            if not plan.get("sequential"):
                for agent_id in agent_ids:
                    collected = workers[agent_id].wait_for("done", timeout=30)
                    operations.extend(item for item in collected if item.get("kind") == "operation")
            alerts = collector.finished_alerts()
            captured_events = collector.captured_events()
        finally:
            try:
                if collector is not None:
                    collector.close()
            finally:
                for process in reversed(processes):
                    stop_process(process)
                    close_pipes(process)
                for worker in workers.values():
                    worker.close()

    steps, event_counts, duration = build_steps(name, operations, alerts, agent_names, captured_events)
    for alert in alerts:
        alert["rule"] = RULE_EXPLAIN.get(str(alert.get("anomaly_type") or ""), "")
    return {
        "id": name,
        "source": "live",
        "title": str(spec["title"]),
        "summary": str(spec["summary"]),
        "duration_ms": duration,
        "steps": steps,
        "events": event_counts,
        "alerts": alerts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--check", action="store_true", help="only report readiness")
    args = parser.parse_args()
    if args.check:
        print(json.dumps({"ready": True, "root": os.geteuid() == 0}, ensure_ascii=False))
        return 0

    def interrupt_run(signum, frame):
        raise InterruptedError("live capture interrupted")

    previous_handler = signal.signal(signal.SIGTERM, interrupt_run)
    try:
        result = run(args.scenario)
    except KeyError:
        print(json.dumps({"error": f"unknown scenario: {args.scenario}"}, ensure_ascii=False))
        return 2
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False))
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
