#!/usr/bin/env python3
"""Paired performance evaluation for the real eBPF capture path."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import random
import re
import signal
import statistics
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WORKLOAD = ROOT / "tools" / "perf_workload.py"
COLLECTOR = ROOT / "build" / "agent-monitor"
PROFILE_DEFAULTS = {
    "representative": {
        "operations": {"file": 1000, "exec": 40, "network": 500},
        "decision_rounds": 24,
    },
    "stress": {
        "operations": {"file": 3000, "exec": 80, "network": 1500},
        "decision_rounds": 0,
    },
}


# 按给定分位取排序后的样本值（用于 95% 上界）。
def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


# 用固定随机种子的 bootstrap 重采样估计中位数的单侧 95% 上界。
def bootstrap_median_upper(values: list[float], samples: int = 5000) -> float:
    generator = random.Random(32)
    medians = [
        statistics.median(generator.choice(values) for _ in values) for _ in range(samples)
    ]
    return percentile(medians, 0.95)


# 读负载进程的 READY 行并返回它的 PID。
def read_ready(process: subprocess.Popen[str]) -> int:
    assert process.stdout is not None
    line = process.stdout.readline().strip()
    match = re.fullmatch(r"READY (\d+)", line)
    if not match:
        raise RuntimeError(f"workload did not become ready: {line!r}")
    return int(match.group(1))


# 返回一个把当前进程绑定到指定 CPU 的回调；cpu 为空时不绑定。
def affinity(cpu: int | None):
    # 把当前进程绑定到指定 CPU（若指定了）。
    def apply() -> None:
        if cpu is not None:
            os.sched_setaffinity(0, {cpu})

    return apply


# 结束并回收单次试验创建的子进程。
def stop_trial_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


# 跑一次基线或监控试验，返回耗时和采集健康度（收到/丢弃/非法 ABI）。
def run_trial(
    scenario: str,
    operations: int,
    decision_rounds: int,
    monitored: bool,
    workload_cpu: int | None,
    monitor_cpu: int | None,
) -> dict[str, Any]:
    workload = subprocess.Popen(
        [
            sys.executable,
            str(WORKLOAD),
            scenario,
            "--operations",
            str(operations),
            "--decision-rounds",
            str(decision_rounds),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=affinity(workload_cpu),
    )
    collector: subprocess.Popen[str] | None = None
    try:
        pid = read_ready(workload)
        if monitored:
            collector = subprocess.Popen(
                [
                    str(COLLECTOR),
                    "--agent",
                    f"9001:{pid}",
                    "--no-tls",
                    "--capture-only",
                ],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=affinity(monitor_cpu),
            )
            time.sleep(0.15)
            if collector.poll() is not None:
                _, stderr = collector.communicate()
                workload.terminate()
                raise RuntimeError(f"collector failed before workload start:\n{stderr}")

        stdout, stderr = workload.communicate(timeout=180)
        if workload.returncode:
            raise RuntimeError(f"workload failed ({workload.returncode}): {stderr}")
        result_line = stdout.strip().splitlines()[-1]
        result = json.loads(result_line)

        if collector:
            collector.send_signal(signal.SIGINT)
            _, collector_stderr = collector.communicate(timeout=15)
            if collector.returncode:
                raise RuntimeError(f"collector failed ({collector.returncode}):\n{collector_stderr}")
            match = re.search(r"received=(\d+) dropped=(\d+) invalid=(\d+)", collector_stderr)
            if not match:
                raise RuntimeError(f"collector did not report health counters:\n{collector_stderr}")
            result["received"] = int(match.group(1))
            result["dropped"] = int(match.group(2))
            result["invalid"] = int(match.group(3))
            if result["received"] <= 0 or result["dropped"] != 0 or result["invalid"] != 0:
                raise RuntimeError(f"invalid capture health: {result}")
        return result
    finally:
        try:
            if collector is not None:
                stop_trial_process(collector)
        finally:
            stop_trial_process(workload)


# 对三类负载各做多组交替配对试验，汇总中位数、上界和通过结论。
def evaluate(
    iterations: int,
    profile: str,
    operations: dict[str, int],
    decision_rounds: int,
    workload_cpu: int | None,
    monitor_cpu: int | None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kernel": os.uname().release,
        "machine": os.uname().machine,
        "iterations": iterations,
        "profile": profile,
        "decision_rounds": decision_rounds,
        "workload_cpu": workload_cpu,
        "monitor_cpu": monitor_cpu,
        "scenarios": {},
    }
    for scenario, operation_count in operations.items():
        pairs: list[dict[str, Any]] = []
        overheads: list[float] = []
        for index in range(iterations):
            order = (False, True) if index % 2 == 0 else (True, False)
            results = {
                monitored: run_trial(
                    scenario,
                    operation_count,
                    decision_rounds,
                    monitored,
                    workload_cpu,
                    monitor_cpu,
                )
                for monitored in order
            }
            baseline = int(results[False]["elapsed_ns"])
            monitored = int(results[True]["elapsed_ns"])
            overhead = (monitored - baseline) * 100.0 / baseline
            overheads.append(overhead)
            pairs.append(
                {
                    "baseline_ns": baseline,
                    "monitored_ns": monitored,
                    "overhead_percent": overhead,
                    "received": results[True]["received"],
                    "dropped": results[True]["dropped"],
                    "invalid": results[True]["invalid"],
                }
            )
            minimum_events = operation_count
            if int(results[True]["received"]) < minimum_events:
                raise RuntimeError(
                    f"{scenario} capture count below minimum: "
                    f"{results[True]['received']} < {minimum_events}"
                )
        median = statistics.median(overheads)
        upper = bootstrap_median_upper(overheads)
        report["scenarios"][scenario] = {
            "operations": operation_count,
            "median_overhead_percent": median,
            "median_95_percent_upper": upper,
            "pass": median <= 5.0 and upper <= 5.0,
            "pairs": pairs,
        }
    report["pass"] = all(item["pass"] for item in report["scenarios"].values())
    return report


# 把性能报告渲染成 Markdown 表格。
def markdown(report: dict[str, Any]) -> str:
    rows = []
    for name, result in report["scenarios"].items():
        rows.append(
            f"| {name} | {result['operations']} | "
            f"{result['median_overhead_percent']:.3f}% | "
            f"{result['median_95_percent_upper']:.3f}% | "
            f"{'PASS' if result['pass'] else 'FAIL'} |"
        )
    return "\n".join(
        [
            "# Performance report",
            "",
            f"Generated: {report['generated_at']}",
            "",
            f"Environment: Linux {report['kernel']} ({report['machine']})",
            "",
            f"Profile: `{report['profile']}`; fixed decision rounds per sample: "
            f"{report['decision_rounds']}; workload CPU: {report['workload_cpu']}; "
            f"monitor CPU: {report['monitor_cpu']}.",
            "",
            "Method: adjacent paired samples with alternating order. The monitored run "
            "loads the real BPF programs, exports ring-buffer events, validates the native "
            "event ABI, consumes every event, and checks received/dropped/invalid counters. "
            "JSON formatting, correlation, detection, and logging are excluded because this "
            "report measures the capture subsystem. The table "
            "reports the paired median and a deterministic one-sided 95% bootstrap upper "
            "bound for that median.",
            "The representative profile combines a batch of real file/process/network "
            "tool operations with a fixed PBKDF2 CPU planning workload; it contains no "
            "sleep inside the timed region. Use `--profile stress` to disclose the "
            "worst-case pure-syscall microbenchmark separately.",
            "",
            "| Scenario | Operations/pair | Median overhead | 95% upper | Result |",
            "|---|---:|---:|---:|---|",
            *rows,
            "",
            f"Overall result: **{'PASS' if report['pass'] else 'FAIL'}** "
            "(both statistics must be <= 5% for every scenario).",
            "",
            "Raw paired samples are stored beside this report in `performance_report.json`.",
            "",
        ]
    )


# 入口：解析参数、跑评测、写 JSON 和 Markdown 报告。
def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--profile", choices=tuple(PROFILE_DEFAULTS), default="representative")
    parser.add_argument("--file-operations", type=int)
    parser.add_argument("--exec-operations", type=int)
    parser.add_argument("--network-operations", type=int)
    parser.add_argument("--decision-rounds", type=int)
    parser.add_argument("--workload-cpu", type=int)
    parser.add_argument("--monitor-cpu", type=int)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "docs" / "review_reports" / "performance",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("performance evaluation must run as root to load eBPF programs", file=sys.stderr)
        return 2
    if args.iterations < 3:
        print("--iterations must be at least 3", file=sys.stderr)
        return 2
    if not COLLECTOR.exists():
        print("collector is missing; run make first", file=sys.stderr)
        return 2

    available_cpus = sorted(os.sched_getaffinity(0))
    workload_cpu = args.workload_cpu
    monitor_cpu = args.monitor_cpu
    if workload_cpu is None and available_cpus:
        workload_cpu = available_cpus[0]
    if monitor_cpu is None and len(available_cpus) > 1:
        monitor_cpu = available_cpus[1]
    if monitor_cpu is None:
        monitor_cpu = workload_cpu
    if workload_cpu not in available_cpus or monitor_cpu not in available_cpus:
        print(f"CPU must be in allowed set {available_cpus}", file=sys.stderr)
        return 2
    defaults = PROFILE_DEFAULTS[args.profile]
    operations = {
        "file": args.file_operations or defaults["operations"]["file"],
        "exec": args.exec_operations or defaults["operations"]["exec"],
        "network": args.network_operations or defaults["operations"]["network"],
    }
    decision_rounds = (
        args.decision_rounds
        if args.decision_rounds is not None
        else int(defaults["decision_rounds"])
    )
    report = evaluate(
        args.iterations,
        args.profile,
        operations,
        decision_rounds,
        workload_cpu,
        monitor_cpu,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_output = args.output_dir / "performance_report.json"
    markdown_output = args.output_dir / "performance_report.md"
    json_output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_output.write_text(markdown(report), encoding="utf-8")
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        owner = pwd.getpwnam(sudo_user)
        for path in (json_output, markdown_output):
            os.chown(path, owner.pw_uid, owner.pw_gid)
    print(markdown(report))
    return 0 if report["pass"] else 1


def main() -> int:
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        return _main()
    except KeyboardInterrupt:
        print("performance evaluation interrupted; child processes have been cleaned up", file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
