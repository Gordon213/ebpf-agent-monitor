#!/usr/bin/env python3
"""Safe configurable Agent used by the three review demonstrations."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time


ROOT = Path("/tmp/ebpf-agent-workspace")
SHARED = ROOT / "shared"
HANDOFF = Path("/tmp/ebpf-agent-handoff")
PROTECTED = Path("/tmp/ebpf-agent-protected/review-secret.txt")


def tls_exchange(port: int, prompt: str) -> str:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    body = json.dumps(
        {"messages": [{"role": "user", "content": prompt}]},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = (
        b"POST /v1/chat/completions HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )
    response = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as connection:
            connection.sendall(request)
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    _, _, response_body = bytes(response).partition(b"\r\n\r\n")
    try:
        document = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    return str(document.get("response") or "") if isinstance(document, dict) else ""


def connect_once() -> None:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(0.1)
    try:
        connection.connect(("127.0.0.1", 9))
    except OSError:
        pass
    finally:
        connection.close()


def wait_for(path: Path, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not path.exists():
        raise RuntimeError(f"timed out waiting for {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", type=int, required=True)
    parser.add_argument("--role", choices=("planner", "executor"), required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--start-delay", type=float, default=2.0)
    parser.add_argument("--loop-count", type=int, default=6)
    args = parser.parse_args()

    workspace = ROOT / f"agent-{args.agent_id}"
    workspace.mkdir(parents=True, exist_ok=True)
    SHARED.mkdir(parents=True, exist_ok=True)
    HANDOFF.mkdir(parents=True, exist_ok=True)
    print(f"REVIEW AGENT {args.agent_id} PID {os.getpid()} role={args.role}", flush=True)
    time.sleep(args.start_delay)

    response = tls_exchange(args.port, args.prompt)
    print(f"Agent {args.agent_id} received {response}", flush=True)

    contended = SHARED / "review-contended.txt"
    handoff = HANDOFF / "review-unapproved.txt"
    if args.role == "planner":
        contended.write_text("planner result\n", encoding="utf-8")
        handoff.write_text("planner private result\n", encoding="utf-8")
        subprocess.run(
            ["/bin/sh", "-c", f"printf review-shell > {workspace / 'review-shell.txt'}"],
            check=True,
        )
    else:
        wait_for(handoff)
        time.sleep(0.25)
        contended.write_text("executor result\n", encoding="utf-8")
        handoff.read_text(encoding="utf-8")
        PROTECTED.read_text(encoding="utf-8")

    for _ in range(args.loop_count):
        connect_once()
        (workspace / "review-loop.txt").write_text("repeat\n", encoding="utf-8")
    time.sleep(0.5)
    print(f"REVIEW AGENT {args.agent_id} FINISHED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
