#!/usr/bin/env python3
"""Per-Agent workload worker: executes real operations and reports them."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui.live.protocol import encode, lines  # noqa: E402

# Match EVENT_DATA_LEN: each OpenSSL call must fit the demo collector's capture.
TLS_CAPTURE_CHUNK = 256


# 取当前单调时钟纳秒，作为操作起止时间。
def now_ns() -> int:
    return time.monotonic_ns()


class Worker:
    # 初始化 worker：预加载 TLS 栈，让 libssl 进入 /proc/PID/maps 以便 uprobe 挂载。
    def __init__(
        self, agent_id: int, tls_port: int, tls_certificate: Path, connection: socket.socket
    ) -> None:
        self.agent_id = agent_id
        self.connection = connection
        self.tls_port = tls_port
        self.tls_certificate = tls_certificate
        # Touch the TLS stack before the collector snapshots /proc/PID/maps.
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    # 把一条带 Agent/PID 的消息编码后发给 driver。
    def emit(self, kind: str, message: dict) -> None:
        payload = {"kind": kind, "agent_id": self.agent_id, "pid": os.getpid(), **message}
        self.connection.sendall(encode(payload))

    # 执行一次本地 HTTPS Prompt/Response 往返。
    def tls_exchange(self, prompt: str) -> dict:
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
        with socket.create_connection(("127.0.0.1", self.tls_port), timeout=5) as raw:
            with self.context.wrap_socket(raw, server_hostname="localhost") as connection:
                for offset in range(0, len(request), TLS_CAPTURE_CHUNK):
                    connection.sendall(request[offset : offset + TLS_CAPTURE_CHUNK])
                while True:
                    chunk = connection.recv(TLS_CAPTURE_CHUNK)
                    if not chunk:
                        break
                    response.extend(chunk)
        _, _, response_body = bytes(response).partition(b"\r\n\r\n")
        try:
            document = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = {}
        reply = ""
        if isinstance(document, dict):
            reply = str(document.get("response") or "")
        return {"prompt": prompt, "response": reply}

    # 真实打开（可选写入）文件，返回系统调用返回值。
    def open_file(self, path: str, write: bool) -> tuple[int, str]:
        flag = os.O_RDWR | os.O_CREAT if write else os.O_RDONLY
        try:
            descriptor = os.open(path, flag, 0o644)
        except OSError as error:
            return -abs(error.errno or 1), error.strerror or "error"
        try:
            if write:
                os.write(descriptor, b"live\n")
        finally:
            os.close(descriptor)
        return 0, "ok"

    # 真实删除文件，返回系统调用返回值。
    def delete_file(self, path: str) -> tuple[int, str]:
        try:
            os.unlink(path)
        except OSError as error:
            return -abs(error.errno or 1), error.strerror or "error"
        return 0, "ok"

    # 真实发起 TCP 连接尝试，返回系统调用返回值。
    def connect(self, destination: str, port: int) -> tuple[int, str]:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(0.2)
        try:
            connection.connect((destination, port))
        except OSError as error:
            return -abs(error.errno or 1), error.strerror or "error"
        finally:
            connection.close()
        return 0, "ok"

    # 真实执行一个程序，返回退出码。
    def run_exec(self, argv: list[str]) -> tuple[int, str]:
        try:
            completed = subprocess.run(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return -1, str(error)
        return int(completed.returncode), "ok"

    # 执行一条操作指令并把实际结果回报给 driver。
    def run(self, operation: dict) -> None:
        kind = str(operation.get("op") or "")
        started = now_ns()
        if kind == "open":
            path = str(operation["path"])
            retval, detail = self.open_file(path, bool(operation.get("write")))
            self.emit(
                "operation",
                {
                    "op": kind,
                    "target": path,
                    "detail": detail,
                    "retval": retval,
                    "started_ns": started,
                    "finished_ns": now_ns(),
                },
            )
        elif kind == "delete":
            path = str(operation["path"])
            retval, detail = self.delete_file(path)
            self.emit(
                "operation",
                {
                    "op": kind,
                    "target": path,
                    "detail": detail,
                    "retval": retval,
                    "started_ns": started,
                    "finished_ns": now_ns(),
                },
            )
        elif kind == "connect":
            destination = str(operation["destination"])
            port = int(operation["port"])
            retval, detail = self.connect(destination, port)
            self.emit(
                "operation",
                {
                    "op": kind,
                    "target": f"{destination}:{port}",
                    "detail": detail,
                    "retval": retval,
                    "started_ns": started,
                    "finished_ns": now_ns(),
                },
            )
        elif kind == "exec":
            argv = [str(item) for item in operation["argv"]]
            retval, detail = self.run_exec(argv)
            self.emit(
                "operation",
                {
                    "op": kind,
                    "target": argv[0],
                    "detail": detail,
                    "retval": retval,
                    "started_ns": started,
                    "finished_ns": now_ns(),
                },
            )
        elif kind == "exchange":
            result = self.tls_exchange(str(operation["prompt"]))
            self.emit(
                "operation",
                {
                    "op": kind,
                    "target": result["prompt"],
                    "detail": result["response"],
                    "retval": 0,
                    "started_ns": started,
                    "finished_ns": now_ns(),
                },
            )
        else:
            self.emit(
                "operation",
                {
                    "op": kind,
                    "target": "",
                    "detail": f"unknown operation {kind}",
                    "retval": -1,
                    "started_ns": started,
                    "finished_ns": now_ns(),
                },
            )


# 入口：连上 driver 的 socket，声明就绪，然后循环处理指令。
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", type=int, required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--tls-port", type=int, required=True)
    parser.add_argument("--tls-certificate", required=True)
    args = parser.parse_args()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(args.socket)
        with connection.makefile("r", encoding="utf-8", newline="\n") as stream:
            worker = Worker(args.agent_id, args.tls_port, Path(args.tls_certificate), connection)
            worker.emit("ready", {})
            for message in lines(stream):
                command = str(message.get("command") or "")
                try:
                    if command == "exchange":
                        worker.run({"op": "exchange", "prompt": str(message.get("prompt") or "")})
                    elif command == "run":
                        for operation in message.get("operations") or []:
                            if isinstance(operation, dict):
                                worker.run(operation)
                    else:
                        raise ValueError(f"unknown command {command}")
                    worker.emit("done", {"command": command})
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    worker.emit("error", {"detail": str(error)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
