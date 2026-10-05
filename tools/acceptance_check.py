#!/usr/bin/env python3
"""Run non-interactive engineering checks for the three review demos."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REVIEW_CONFIGS = (
    ROOT / "config/demos/review-1-functional-causality.yaml",
    ROOT / "config/demos/review-2-observability.yaml",
    ROOT / "config/demos/review-3-performance.yaml",
)


def command_check(name: str, command: list[str], timeout: int = 180) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONPYCACHEPREFIX"] = str(ROOT / "build" / "pycache")
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=environment,
    )
    return {
        "name": name,
        "pass": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def review_config_check() -> dict[str, Any]:
    problems: list[str] = []
    ids: set[str] = set()
    for path in REVIEW_CONFIGS:
        if not path.is_file():
            problems.append(f"missing {path.relative_to(ROOT)}")
            continue
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            problems.append(f"{path.name}: root must be a mapping")
            continue
        for field in ("id", "title", "review_point", "kind", "report_path"):
            if not document.get(field):
                problems.append(f"{path.name}: missing {field}")
        review_id = str(document.get("id", ""))
        if review_id in ids:
            problems.append(f"duplicate review id: {review_id}")
        ids.add(review_id)
        kind = document.get("kind")
        if kind == "live" and len(document.get("agents", [])) < 2:
            problems.append(f"{path.name}: live review needs at least two Agents")
        if kind == "performance" and not document.get("performance"):
            problems.append(f"{path.name}: missing performance settings")
        if kind not in {"live", "performance"}:
            problems.append(f"{path.name}: unsupported kind {kind!r}")
    return {
        "name": "three review configurations",
        "pass": not problems,
        "review_ids": sorted(ids),
        "problems": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="optionally save the JSON result")
    args = parser.parse_args()

    checks = [
        command_check("dependency doctor", ["make", "doctor"]),
        command_check("full build", ["make", "-B"]),
        command_check("unit tests", ["make", "test"]),
        command_check("collector CLI", [str(ROOT / "build/agent-monitor"), "--help"]),
        command_check(
            "Python syntax",
            [
                sys.executable,
                "-m",
                "py_compile",
                "user/analyzer.py",
                "demo/review_agent_workload.py",
                "demo/review_tls_server.py",
                "tools/performance_eval.py",
                "tools/perf_workload.py",
                "tools/run_review_demo.py",
                "ui/server.py",
                "ui/live/driver.py",
                "ui/live/protocol.py",
                "ui/live/worker.py",
                "ui/live/workloads.py",
            ],
        ),
        review_config_check(),
    ]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kernel": os.uname().release,
        "machine": os.uname().machine,
        "checks": checks,
        "pass": all(check["pass"] for check in checks),
    }
    if args.output:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
