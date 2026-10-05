#!/usr/bin/env python3
"""Deterministic workload used by performance_eval.py."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


# 文件负载：对临时文件重复读操作。
def file_workload(operations: int) -> None:
    with tempfile.TemporaryDirectory(prefix="agent-monitor-perf-") as directory:
        path = Path(directory) / "input.txt"
        path.write_bytes(b"x" * 4096)
        for _ in range(operations):
            with path.open("rb") as stream:
                stream.read(64)


# 进程负载：重复执行 /bin/true。
def exec_workload(operations: int) -> None:
    for _ in range(operations):
        subprocess.run(["/bin/true"], check=True)


# 网络负载：重复向本地无效端口发起连接尝试。
def network_workload(operations: int) -> None:
    for _ in range(operations):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(0.05)
        try:
            connection.connect(("127.0.0.1", 9))
        except OSError:
            pass
        finally:
            connection.close()


# 固定轮数的 PBKDF2 本地计算，模拟 Agent 规划阶段的 CPU 开销。
def decision_workload(rounds: int) -> None:
    """Fixed CPU work representing local Agent planning between tool batches."""
    value = b"AgentScope-eBPF deterministic decision workload"
    for index in range(rounds):
        value = hashlib.pbkdf2_hmac(
            "sha256", value, index.to_bytes(4, "little"), 200_000
        )


# 入口：打印 READY、等启动延迟、跑对应负载。
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=("file", "exec", "network"))
    parser.add_argument("--operations", type=int, required=True)
    parser.add_argument("--decision-rounds", type=int, default=0)
    parser.add_argument("--start-delay", type=float, default=0.35)
    args = parser.parse_args()

    print(f"READY {os.getpid()}", flush=True)
    time.sleep(args.start_delay)
    started = time.perf_counter_ns()
    {"file": file_workload, "exec": exec_workload, "network": network_workload}[
        args.scenario
    ](args.operations)
    decision_workload(args.decision_rounds)
    elapsed_ns = time.perf_counter_ns() - started
    print(
        json.dumps(
            {
                "scenario": args.scenario,
                "operations": args.operations,
                "decision_rounds": args.decision_rounds,
                "elapsed_ns": elapsed_ns,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
