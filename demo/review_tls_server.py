#!/usr/bin/env python3
"""Small local HTTPS server for deterministic Prompt/Response demonstrations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import ssl


def receive_http_message(connection: ssl.SSLSocket) -> bytes:
    data = bytearray()
    expected = None
    while len(data) < 64 * 1024:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        header_end = data.find(b"\r\n\r\n")
        if header_end >= 0 and expected is None:
            headers = data[:header_end].decode("iso-8859-1", errors="replace")
            content_length = 0
            for line in headers.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
                    break
            expected = header_end + 4 + content_length
        if expected is not None and len(data) >= expected:
            break
    return bytes(data)


def prompt_from_request(request: bytes) -> str:
    _, _, body = request.partition(b"\r\n\r\n")
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unknown prompt"
    messages = document.get("messages") if isinstance(document, dict) else None
    if isinstance(messages, list):
        for message in reversed(messages):
            if isinstance(message, dict) and message.get("role") == "user":
                return str(message.get("content") or "unknown prompt")
    if isinstance(document, dict):
        return str(document.get("prompt") or "unknown prompt")
    return "unknown prompt"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--connections", type=int, required=True)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certificate, args.private_key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.port))
        listener.listen(args.connections)
        listener.settimeout(20)
        print(f"TLS SERVER READY {args.port}", flush=True)
        for _ in range(args.connections):
            raw_connection, _ = listener.accept()
            with raw_connection:
                with context.wrap_socket(raw_connection, server_side=True) as connection:
                    prompt = prompt_from_request(receive_http_message(connection))
                    body = json.dumps(
                        {"response": f"ACK:{prompt}"},
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode()
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
                    connection.sendall(response)
    print("TLS SERVER FINISHED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
