#!/usr/bin/env python3
"""Correlate collector JSONL, detect Agent anomalies, and persist evidence."""

from __future__ import annotations

import argparse
import codecs
from collections import Counter, defaultdict, deque
from datetime import datetime
import fnmatch
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Iterable, TextIO
import uuid


DELETE_EVENTS = {"unlink", "unlinkat", "rmdir"}
FILE_EVENTS = {"openat", *DELETE_EVENTS}
TLS_EVENTS = {"tls_read", "tls_write"}
O_ACCMODE = 0o3
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000

SECRET_PATTERN = re.compile(
    r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|"
    r"((?:api[-_]?key|access[-_]?token|authorization|cookie)\s*[:=]\s*)"
    r"(?:bearer\s+)?[^\s,;&\"']+"
)
SENSITIVE_JSON_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "token",
    "authorization",
    "cookie",
    "x-api-key",
}


def is_within(path: str, root: str) -> bool:
    """Return True only when path is root or a real descendant of root."""
    try:
        normalized_path = os.path.realpath(path)
        normalized_root = os.path.realpath(root)
        return os.path.commonpath([normalized_path, normalized_root]) == normalized_root
    except (ValueError, OSError):
        return False


def event_seconds(event: dict[str, Any]) -> float:
    timestamp_ns = event.get("timestamp_ns")
    if isinstance(timestamp_ns, (int, float)):
        return float(timestamp_ns) / 1_000_000_000.0
    value = str(event.get("time") or "")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.monotonic()


def redact_text(text: str) -> str:
    """Remove common credentials before semantic text reaches logs."""

    def replacement(match: re.Match[str]) -> str:
        return f"{match.group(1) or match.group(2) or ''}[REDACTED]"

    return SECRET_PATTERN.sub(replacement, text)


def _content_text(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        texts: list[str] = []
        for item in value:
            if isinstance(item, str):
                texts.append(item)
            elif isinstance(item, dict):
                for key in ("text", "content", "value"):
                    if key in item:
                        texts.extend(_content_text(item[key]))
        return texts
    if isinstance(value, dict):
        texts = []
        for key in ("text", "content", "value"):
            if key in value:
                texts.extend(_content_text(value[key]))
        return texts
    return []


def _redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_JSON_KEYS else _redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class PathResolver:
    """Resolve syscall paths using the emitting process's cwd or dirfd."""

    @staticmethod
    def resolve(event: dict[str, Any]) -> str:
        raw_path = str(event.get("object") or "")
        if not raw_path:
            return ""
        if os.path.isabs(raw_path):
            return os.path.realpath(raw_path)

        pid = int(event.get("tgid") or 0)
        dirfd = int(event.get("dirfd", -100))
        base = ""
        if pid > 0 and dirfd >= 0:
            try:
                base = os.readlink(f"/proc/{pid}/fd/{dirfd}")
            except OSError:
                base = ""
        if not base and pid > 0:
            try:
                base = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                base = ""
        if not base:
            return raw_path
        return os.path.realpath(os.path.join(base, raw_path))


class SemanticExtractor:
    """Bounded TLS plaintext reassembly and common LLM JSON extraction."""

    def __init__(self, max_buffer_bytes: int = 262_144, max_text_chars: int = 4096):
        self.max_buffer_bytes = max_buffer_bytes
        self.max_text_chars = max_text_chars
        self.buffers: dict[tuple[int, int, str], bytes] = {}

    @staticmethod
    def _json_documents(text: str) -> tuple[list[Any], str]:
        decoder = json.JSONDecoder()
        documents: list[Any] = []
        cursor = 0
        consumed_until = 0
        while cursor < len(text):
            starts = [position for position in (text.find("{", cursor), text.find("[", cursor)) if position >= 0]
            if not starts:
                break
            start = min(starts)
            try:
                document, consumed = decoder.raw_decode(text[start:])
            except json.JSONDecodeError:
                break
            documents.append(document)
            cursor = start + consumed
            consumed_until = cursor
        return documents, text[consumed_until:]

    @staticmethod
    def _semantic_texts(document: Any, direction: str) -> list[str]:
        prompt_keys = {"prompt", "input", "query", "instruction", "user_prompt"}
        response_keys = {"response", "output", "output_text", "completion", "answer"}
        texts: list[str] = []

        def walk(value: Any, parent_key: str = "") -> None:
            if isinstance(value, dict):
                role = str(value.get("role") or "").lower()
                if "content" in value and (
                    (direction == "prompt" and role == "user")
                    or (direction == "response" and role == "assistant")
                ):
                    texts.extend(_content_text(value["content"]))
                for key, item in value.items():
                    lowered = key.lower()
                    if direction == "prompt" and lowered in prompt_keys:
                        texts.extend(_content_text(item))
                    elif direction == "response" and lowered in response_keys:
                        texts.extend(_content_text(item))
                    elif lowered == "choices" and direction == "response":
                        walk(item, lowered)
                    elif lowered not in SENSITIVE_JSON_KEYS:
                        walk(item, lowered)
            elif isinstance(value, list):
                for item in value:
                    walk(item, parent_key)

        walk(_redact_json(document))
        unique: list[str] = []
        seen: set[str] = set()
        for text in texts:
            normalized = " ".join(redact_text(text).split())[:4096]
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
        return unique

    @staticmethod
    def _payload_bytes(event: dict[str, Any]) -> bytes:
        payload = str(event.get("payload") or "")
        encoding = event.get("payload_encoding")
        # Older collectors used the same byte envelope without an encoding label.
        legacy_bytes = (
            encoding is None
            and "data_size" in event
            and event.get("data_len") == len(payload)
        )
        if encoding == "latin-1" or legacy_bytes:
            try:
                return payload.encode("latin-1")
            except UnicodeEncodeError:
                pass
        # Synthetic/replayed inputs may already contain decoded Unicode text.
        return payload.encode("utf-8")

    @staticmethod
    def _is_http(buffer: bytes) -> bool:
        prefixes = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HTTP/")
        return any(buffer.startswith(prefix) or prefix.startswith(buffer) for prefix in prefixes)

    @staticmethod
    def _http_bodies(buffer: bytes) -> tuple[list[bytes], bytes]:
        bodies: list[bytes] = []
        remaining = buffer
        while True:
            header_end = remaining.find(b"\r\n\r\n")
            if header_end < 0:
                break
            first_line = remaining.split(b"\r\n", 1)[0]
            if not (
                first_line.startswith((b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE "))
                or first_line.startswith(b"HTTP/")
            ):
                remaining = remaining[header_end + 4 :]
                continue
            headers = remaining[:header_end]
            length_match = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", headers)
            if not length_match:
                break
            body_length = int(length_match.group(1))
            message_length = header_end + 4 + body_length
            if len(remaining) < message_length:
                break
            bodies.append(remaining[header_end + 4 : message_length])
            remaining = remaining[message_length:]
        return bodies, remaining

    def feed(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if event.get("type") not in TLS_EVENTS:
            return []
        payload = self._payload_bytes(event)
        if not payload:
            return []

        direction = "prompt" if event.get("type") == "tls_write" else "response"
        key = (int(event.get("agent_id") or 0), int(event.get("tgid") or 0), direction)
        buffer = (self.buffers.get(key, b"") + payload)[-self.max_buffer_bytes :]
        bodies, remaining = self._http_bodies(buffer)
        semantics: list[dict[str, Any]] = []
        seen: set[str] = set()

        if bodies:
            document_sets = [
                self._json_documents(candidate.decode("utf-8", errors="replace"))[0]
                for candidate in bodies
            ]
            self.buffers[key] = remaining
        elif self._is_http(buffer):
            # Content-Length counts bytes; do not parse a JSON prefix of an
            # incomplete HTTP body even when that prefix happens to be valid.
            document_sets = []
            self.buffers[key] = remaining
        else:
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            decoded = decoder.decode(buffer, final=False)
            pending_bytes, _ = decoder.getstate()
            documents, json_remainder = self._json_documents(decoded)
            document_sets = [documents]
            # Keep any incomplete UTF-8 code point for the next captured chunk.
            self.buffers[key] = json_remainder.encode("utf-8") + pending_bytes

        for documents in document_sets:
            for document in documents:
                for text in self._semantic_texts(document, direction):
                    text = text[: self.max_text_chars]
                    if text in seen:
                        continue
                    seen.add(text)
                    semantics.append(
                        {
                            "id": str(uuid.uuid4()),
                            "kind": direction,
                            "text": text,
                            "timestamp": event_seconds(event),
                            "time": event.get("time"),
                            "agent_id": key[0],
                            "pid": key[1],
                        }
                    )
        return semantics


class CausalCorrelator:
    """Maintain a bounded per-Agent Prompt/Response timeline."""

    def __init__(self, config: dict[str, Any]):
        settings = config.get("semantic_capture") or {}
        self.window_seconds = float(settings.get("correlation_window_seconds", 30))
        self.max_history = int(settings.get("max_history_per_agent", 128))
        self.extractor = SemanticExtractor(
            int(settings.get("max_buffer_bytes", 262_144)),
            int(settings.get("max_text_chars", 4096)),
        )
        self.history: dict[int, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self.max_history)
        )

    def observe(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        semantics = self.extractor.feed(event)
        for semantic in semantics:
            self.history[int(semantic["agent_id"])].append(semantic)
        return semantics

    def context(self, event: dict[str, Any]) -> dict[str, Any] | None:
        agent_id = int(event.get("agent_id") or 0)
        now = event_seconds(event)
        recent = [
            item
            for item in self.history.get(agent_id, ())
            if 0 <= now - float(item["timestamp"]) <= self.window_seconds
        ]
        prompts = [item for item in recent if item["kind"] == "prompt"]
        if not prompts:
            return None
        prompt = prompts[-1]
        responses = [
            item
            for item in recent
            if item["kind"] == "response" and item["timestamp"] >= prompt["timestamp"]
        ]
        response = responses[-1] if responses else None
        return {
            "causal_link_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{prompt['id']}:{event.get('timestamp_ns')}")),
            "prompt_id": prompt["id"],
            "prompt": prompt["text"],
            "response": response["text"] if response else None,
            "age_ms": round((now - float(prompt["timestamp"])) * 1000, 3),
            "evidence": "same-agent bounded temporal correlation",
        }


class Analyzer:
    """Rule-driven detector with bounded per-Agent and cross-Agent state."""

    def __init__(self, config: dict[str, Any], resolver: PathResolver | None = None):
        self.config = config
        self.resolver = resolver or PathResolver()
        self.correlator = CausalCorrelator(config)
        self.loop_state: dict[int, dict[str, deque[tuple[float, str]]]] = defaultdict(
            lambda: {signal: deque() for signal in ("file", "network", "process", "prompt")}
        )
        self.process_state: dict[int, deque[tuple[float, int, str]]] = defaultdict(deque)
        self.delete_state: dict[int, deque[tuple[float, int, str]]] = defaultdict(deque)
        self.resource_state: dict[str, deque[tuple[float, int, str, int]]] = defaultdict(deque)
        self.endpoint_state: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.last_alert: dict[tuple[str, str], float] = {}
        self.last_loop_alert: dict[int, float] = {}
        self.pending_correlations: list[dict[str, Any]] = []

    def process(self, raw_event: dict[str, Any]) -> list[dict[str, Any]]:
        event = dict(raw_event)
        event["normalized_object"] = self.resolver.resolve(event)
        semantics = self.correlator.observe(event)
        alerts: list[dict[str, Any]] = []

        for detector in (
            self._detect_shell,
            self._detect_sensitive_file,
            self._detect_workspace_delete,
            self._detect_network_risk,
            self._detect_resource_abuse,
            self._detect_multi_agent,
        ):
            alert = detector(event)
            if alert:
                alerts.append(alert)
        loop_alert = self._detect_loop(event, semantics)
        if loop_alert:
            alerts.append(loop_alert)

        context = self.correlator.context(event)
        if context and event.get("type") not in TLS_EVENTS:
            self.pending_correlations.append(
                {
                    **context,
                    "time": event.get("time"),
                    "agent_id": int(event.get("agent_id") or 0),
                    "pid": int(event.get("tgid") or 0),
                    "tid": int(event.get("tid") or 0),
                    "operation": event.get("type"),
                    "object": event.get("normalized_object") or event.get("object") or "",
                }
            )
        for alert in alerts:
            if context:
                alert["causal_link_id"] = context["causal_link_id"]
                alert["prompt_id"] = context["prompt_id"]
                alert["causal_prompt"] = context["prompt"]
                alert["causal_response"] = context["response"]
                alert["causal_age_ms"] = context["age_ms"]
                alert["details"]["causal_evidence"] = context["evidence"]
        return alerts

    def drain_correlations(self) -> list[dict[str, Any]]:
        correlations, self.pending_correlations = self.pending_correlations, []
        return correlations

    def _agent_config(self, agent_id: int) -> dict[str, Any]:
        agents = self.config.get("agents") or {}
        return agents.get(agent_id) or agents.get(str(agent_id)) or {}

    def _new_alert(
        self,
        event: dict[str, Any],
        anomaly_type: str,
        severity: str,
        title: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        agent_id = int(event.get("agent_id") or 0)
        agent_config = self._agent_config(agent_id)
        return {
            "alert_id": str(uuid.uuid4()),
            "time": event.get("time"),
            "timestamp_ns": event.get("timestamp_ns"),
            "detected_at": datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "anomaly_type": anomaly_type,
            "severity": severity,
            "title": title,
            "agent_id": agent_id,
            "agent_name": agent_config.get("name", f"agent-{agent_id}"),
            "pid": int(event.get("tgid") or 0),
            "tid": int(event.get("tid") or 0),
            "ppid": int(event.get("ppid") or 0),
            "uid": int(event.get("uid") or 0),
            "operation": event.get("type"),
            "object": event.get("normalized_object") or event.get("object") or "",
            "retval": event.get("retval"),
            "details": details or {},
        }

    def _cooldown_ready(self, kind: str, key: str, now: float, cooldown: float) -> bool:
        alert_key = (kind, key)
        if now - self.last_alert.get(alert_key, float("-inf")) < cooldown:
            return False
        self.last_alert[alert_key] = now
        return True

    def _detect_shell(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if event.get("type") != "exec":
            return None
        executable = str(event.get("normalized_object") or event.get("object") or "")
        configured = self.config.get("unexpected_shells") or []
        configured_paths = {str(item) for item in configured}
        configured_realpaths = {os.path.realpath(path) for path in configured_paths}
        configured_names = {os.path.basename(path) for path in configured_paths}
        if (
            executable not in configured_paths
            and executable not in configured_realpaths
            and os.path.basename(executable) not in configured_names
        ):
            return None
        return self._new_alert(
            event,
            "unexpected_shell",
            "high",
            f"Agent launched shell {executable}",
            {"executable": executable},
        )

    def _is_sensitive(self, path: str) -> str | None:
        for rule in self.config.get("sensitive_paths") or []:
            rule = os.path.expanduser(str(rule))
            if any(character in rule for character in "*?["):
                if fnmatch.fnmatch(path, rule):
                    return rule
            elif is_within(path, rule):
                return rule
        return None

    def _detect_sensitive_file(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if event.get("type") not in FILE_EVENTS or int(event.get("retval", -1)) < 0:
            return None
        path = str(event.get("normalized_object") or "")
        matched_rule = self._is_sensitive(path)
        if not matched_rule:
            return None
        return self._new_alert(
            event,
            "sensitive_file_access",
            "high",
            f"Agent accessed sensitive path {path}",
            {"matched_rule": matched_rule},
        )

    def _detect_workspace_delete(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if event.get("type") not in DELETE_EVENTS or int(event.get("retval", -1)) != 0:
            return None
        agent_id = int(event.get("agent_id") or 0)
        workspace = str(self._agent_config(agent_id).get("workspace") or "")
        path = str(event.get("normalized_object") or "")
        if not workspace or not path or is_within(path, workspace):
            return None
        return self._new_alert(
            event,
            "workspace_boundary_violation",
            "critical",
            f"Agent deleted an object outside its workspace: {path}",
            {"workspace": os.path.realpath(workspace)},
        )

    def _detect_network_risk(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if event.get("type") != "connect":
            return None
        destination = str(event.get("destination") or "")
        port = int(event.get("port") or 0)
        if destination in {str(item) for item in self.config.get("malicious_ips") or []}:
            return self._new_alert(
                event,
                "malicious_destination",
                "critical",
                f"Agent connected to blocked destination {destination}",
                {"destination": destination, "port": port},
            )
        if port in {int(item) for item in self.config.get("high_risk_ports") or []}:
            return self._new_alert(
                event,
                "high_risk_network_port",
                "high",
                f"Agent used high-risk destination port {port}",
                {"destination": destination, "port": port},
            )
        return None

    @staticmethod
    def _purge(queue: deque[Any], cutoff: float) -> None:
        while queue and float(queue[0][0]) < cutoff:
            queue.popleft()

    @staticmethod
    def _highest_repeat(queue: Iterable[tuple[float, str]]) -> tuple[int, str]:
        counts = Counter(key for _, key in queue if key)
        if not counts:
            return 0, ""
        key, count = counts.most_common(1)[0]
        return count, key

    def _detect_resource_abuse(self, event: dict[str, Any]) -> dict[str, Any] | None:
        settings = self.config.get("resource_limits") or {}
        now = event_seconds(event)
        agent_id = int(event.get("agent_id") or 0)
        event_type = str(event.get("type") or "")
        window = float(settings.get("window_seconds", 10))
        cooldown = float(settings.get("cooldown_seconds", window))

        if event_type in {"fork", "exec"}:
            queue = self.process_state[agent_id]
            queue.append((now, int(event.get("tgid") or 0), event_type))
            self._purge(queue, now - window)
            threshold = int(settings.get("max_process_events", 20))
            if len(queue) >= threshold and self._cooldown_ready(
                "resource_abuse", str(agent_id), now, cooldown
            ):
                return self._new_alert(
                    event,
                    "resource_abuse",
                    "high",
                    f"Agent generated {len(queue)} process events in {window:g}s",
                    {"window_seconds": window, "process_events": len(queue)},
                )
        if event_type in DELETE_EVENTS and int(event.get("retval", -1)) == 0:
            queue = self.delete_state[agent_id]
            queue.append(
                (now, int(event.get("tgid") or 0), str(event.get("normalized_object") or ""))
            )
            self._purge(queue, now - window)
            threshold = int(settings.get("max_deletions", 10))
            if len(queue) >= threshold and self._cooldown_ready(
                "excessive_file_deletion", str(agent_id), now, cooldown
            ):
                return self._new_alert(
                    event,
                    "excessive_file_deletion",
                    "critical",
                    f"Agent deleted {len(queue)} objects in {window:g}s",
                    {
                        "window_seconds": window,
                        "deletions": len(queue),
                        "pids": sorted({pid for _, pid, _ in queue}),
                        "objects": [path for _, _, path in list(queue)[-10:]],
                    },
                )
        return None

    @staticmethod
    def _file_access(event: dict[str, Any]) -> str:
        if event.get("type") in DELETE_EVENTS:
            return "write"
        flags = int(event.get("flags") or 0)
        if flags & O_ACCMODE in {O_WRONLY, O_RDWR} or flags & (O_CREAT | O_TRUNC):
            return "write"
        return "read"

    def _collaboration_allowed(self, first: int, second: int, path: str) -> bool:
        settings = self.config.get("multi_agent") or {}
        pairs = {
            frozenset(int(item) for item in pair)
            for pair in settings.get("allowed_collaborations") or []
            if isinstance(pair, list) and len(pair) == 2
        }
        if frozenset((first, second)) in pairs:
            return True
        return any(is_within(path, str(root)) for root in settings.get("shared_paths") or [])

    def _detect_multi_agent(self, event: dict[str, Any]) -> dict[str, Any] | None:
        settings = self.config.get("multi_agent") or {}
        if not settings.get("enabled", True):
            return None
        now = event_seconds(event)
        window = float(settings.get("window_seconds", 5))
        cooldown = float(settings.get("cooldown_seconds", window))
        agent_id = int(event.get("agent_id") or 0)
        event_type = str(event.get("type") or "")

        if event_type in FILE_EVENTS and int(event.get("retval", -1)) >= 0:
            path = str(event.get("normalized_object") or "")
            if not path:
                return None
            access = self._file_access(event)
            queue = self.resource_state[path]
            self._purge(queue, now - window)
            previous = list(queue)
            queue.append((now, agent_id, access, int(event.get("tgid") or 0)))
            for _, other_agent, other_access, other_pid in reversed(previous):
                if other_agent == agent_id:
                    continue
                if access == "write" and other_access == "write" and self._cooldown_ready(
                    "resource_contention", path, now, cooldown
                ):
                    return self._new_alert(
                        event,
                        "resource_contention",
                        "high",
                        f"Agents {other_agent} and {agent_id} wrote the same resource",
                        {
                            "resource": path,
                            "peer_agent_id": other_agent,
                            "peer_pid": other_pid,
                            "window_seconds": window,
                        },
                    )
                if (
                    access == "read"
                    and other_access == "write"
                    and not self._collaboration_allowed(other_agent, agent_id, path)
                    and self._cooldown_ready("unauthorized_agent_handoff", path, now, cooldown)
                ):
                    return self._new_alert(
                        event,
                        "unauthorized_agent_handoff",
                        "critical",
                        f"Agent {agent_id} read data recently written by Agent {other_agent}",
                        {
                            "resource": path,
                            "source_agent_id": other_agent,
                            "source_pid": other_pid,
                            "window_seconds": window,
                            "evidence": "shared-file temporal relation",
                        },
                    )

        if event_type == "connect":
            endpoint = f"{event.get('destination')}:{event.get('port')}"
            queue = self.endpoint_state[endpoint]
            queue.append((now, agent_id))
            self._purge(queue, now - window)
            minimum_agents = int(settings.get("collective_min_agents", 2))
            threshold = int(settings.get("collective_connection_threshold", 10))
            agents = sorted({seen_agent for _, seen_agent in queue})
            if (
                len(agents) >= minimum_agents
                and len(queue) >= threshold
                and self._cooldown_ready("collective_api_storm", endpoint, now, cooldown)
            ):
                return self._new_alert(
                    event,
                    "collective_api_storm",
                    "critical",
                    f"Multiple Agents repeatedly connected to {endpoint}",
                    {
                        "endpoint": endpoint,
                        "agents": agents,
                        "connections": len(queue),
                        "window_seconds": window,
                    },
                )
        return None

    def _detect_loop(
        self, event: dict[str, Any], semantics: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        settings = self.config.get("loop_detection") or {}
        if not settings.get("enabled", True):
            return None

        agent_id = int(event.get("agent_id") or 0)
        if not agent_id:
            return None
        now = event_seconds(event)
        state = self.loop_state[agent_id]
        event_type = str(event.get("type") or "")
        object_name = str(event.get("normalized_object") or event.get("object") or "")
        changed = False

        if event_type in FILE_EVENTS and int(event.get("retval", -1)) >= 0:
            state["file"].append((now, f"{event_type}:{object_name}"))
            changed = True
        elif event_type == "connect":
            state["network"].append((now, f"{event.get('destination')}:{event.get('port')}"))
            changed = True
        elif event_type == "exec":
            state["process"].append((now, object_name))
            changed = True
        for semantic in semantics:
            if semantic["kind"] == "prompt":
                normalized = " ".join(str(semantic["text"]).lower().split())
                state["prompt"].append((now, normalized))
                changed = True
        if not changed:
            return None

        window = float(settings.get("window_seconds", 30))
        cutoff = now - window
        for queue in state.values():
            self._purge(queue, cutoff)
        thresholds = {
            "file": int(settings.get("repeated_file_operations", 10)),
            "network": int(settings.get("repeated_network_connections", 5)),
            "process": int(settings.get("repeated_process_execs", 5)),
            "prompt": int(settings.get("repeated_prompts", 3)),
        }
        signal_counts: dict[str, int] = {}
        repeated_objects: dict[str, str] = {}
        for signal, queue in state.items():
            count, key = self._highest_repeat(queue)
            if count >= thresholds[signal]:
                signal_counts[signal] = count
                repeated_objects[signal] = key

        if len(signal_counts) < int(settings.get("minimum_signals", 2)):
            return None
        cooldown = float(settings.get("cooldown_seconds", window))
        if now - self.last_loop_alert.get(agent_id, float("-inf")) < cooldown:
            return None
        self.last_loop_alert[agent_id] = now
        return self._new_alert(
            event,
            "infinite_loop",
            "critical",
            "Agent shows a repeated multi-signal loop pattern",
            {
                "window_seconds": window,
                "signal_counts": signal_counts,
                "repeated_objects": repeated_objects,
            },
        )


class JsonlSink:
    def __init__(self, directory: Path, prefix: str, persist: bool = True):
        self.directory = directory
        self.prefix = prefix
        self.persist = persist

    def emit(self, item: dict[str, Any], *, stdout: bool = False) -> None:
        line = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if stdout:
            print(line, flush=True)
        if not self.persist:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        filename = self.directory / f"{self.prefix}_{datetime.now():%Y%m%d}.jsonl"
        with filename.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")


class AlertSink(JsonlSink):
    def __init__(self, directory: Path, persist: bool = True):
        super().__init__(directory, "alerts", persist)

    def emit(self, item: dict[str, Any], *, stdout: bool = True) -> None:
        super().emit(item, stdout=stdout)


def load_config(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError("PyYAML is required; install python3-yaml or requirements.txt") from error
    with path.open("r", encoding="utf-8") as stream:
        try:
            config = yaml.safe_load(stream) or {}
        except yaml.YAMLError as error:
            raise ValueError(f"invalid YAML: {error}") from error
    if not isinstance(config, dict):
        raise ValueError("configuration root must be a mapping")
    return config


def event_lines(stream: TextIO) -> Iterable[dict[str, Any]]:
    for line_number, line in enumerate(stream, 1):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            print(f"warning: invalid JSON on input line {line_number}: {error}", file=sys.stderr)
            continue
        if isinstance(event, dict):
            yield event


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config/rules.yaml"))
    parser.add_argument("--events-file", type=Path)
    parser.add_argument("--logs-dir", "--alerts-dir", dest="logs_dir", type=Path, default=Path("logs"))
    parser.add_argument("--no-persist", action="store_true")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"failed to load configuration: {error}", file=sys.stderr)
        return 2

    analyzer = Analyzer(config)
    alert_sink = AlertSink(args.logs_dir, persist=not args.no_persist)
    correlation_sink = JsonlSink(args.logs_dir, "correlations", persist=not args.no_persist)
    input_stream: TextIO = sys.stdin
    if args.events_file:
        try:
            input_stream = args.events_file.open("r", encoding="utf-8")
        except OSError as error:
            print(f"failed to open events file: {error}", file=sys.stderr)
            return 2

    event_count = 0
    alert_count = 0
    correlation_count = 0
    try:
        for event in event_lines(input_stream):
            event_count += 1
            for alert in analyzer.process(event):
                alert_sink.emit(alert)
                alert_count += 1
            for correlation in analyzer.drain_correlations():
                correlation_sink.emit(correlation)
                correlation_count += 1
    except KeyboardInterrupt:
        pass
    finally:
        if input_stream is not sys.stdin:
            input_stream.close()
    print(
        f"analyzer stopped; events={event_count} alerts={alert_count} correlations={correlation_count}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
