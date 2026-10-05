"""Line-delimited JSON over a Unix stream socket."""

from __future__ import annotations

import json
import socket
from typing import Any, Iterator


# 把一条消息编码成一行 JSON（带换行），用于 socket 发送。
def encode(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


# 逐行读取文本流并解析 JSON，跳过空行和坏行。
def lines(stream) -> Iterator[dict[str, Any]]:
    for raw in stream:
        line = raw.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            yield item


# 连接本地 Unix socket 并设置超时。
def connect(path: str, timeout: float = 5.0) -> socket.socket:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    connection.connect(path)
    return connection


# 建一个监听中的 Unix socket，供 worker 连接。
def listener(path: str) -> socket.socket:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(8)
    return server
