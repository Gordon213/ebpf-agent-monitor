#!/usr/bin/env python3
"""Local dashboard for the eBPF agent monitor review reports."""

from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import json
from pathlib import Path
import webbrowser


ROOT = Path(__file__).resolve().parents[1]
UI_DIR = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "docs" / "review_reports"
REVIEWS = {
    "review-1": REPORT_DIR / "review-1-functional-causality.json",
    "review-2": REPORT_DIR / "review-2-observability.json",
    "review-3": REPORT_DIR / "review-3-performance.json",
}
PERFORMANCE = REPORT_DIR / "performance" / "performance_report.json"


def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    return document if isinstance(document, dict) else None


def review_view(key: str, path: Path) -> dict:
    document = load_json(path)
    if document is None:
        return {"id": key, "available": False, "path": str(path)}
    checks = document.get("checks") or []
    performance = document.get("performance") or {}
    scenarios = {}
    for name, result in (performance.get("scenarios") or {}).items():
        if not isinstance(result, dict):
            continue
        scenarios[name] = {
            "operations": result.get("operations"),
            "median_overhead_percent": result.get("median_overhead_percent"),
            "median_95_percent_upper": result.get("median_95_percent_upper"),
            "pass": bool(result.get("pass")),
        }
    return {
        "id": document.get("id") or key,
        "available": True,
        "title": document.get("title") or key,
        "description": document.get("description") or "",
        "generated_at": document.get("generated_at"),
        "pass": bool(document.get("pass")),
        "environment": document.get("environment") or {},
        "checks_passed": sum(1 for item in checks if item.get("pass")),
        "checks_total": len(checks),
        "event_counts": document.get("event_counts") or {},
        "alerts": document.get("alerts") or [],
        "sample_events": document.get("sample_events") or [],
        "scenarios": scenarios,
    }


def performance_view() -> dict:
    document = load_json(PERFORMANCE)
    if document is None:
        return {"available": False, "path": str(PERFORMANCE)}
    scenarios = {}
    for name, result in (document.get("scenarios") or {}).items():
        if not isinstance(result, dict):
            continue
        scenarios[name] = {
            "operations": result.get("operations"),
            "median_overhead_percent": result.get("median_overhead_percent"),
            "median_95_percent_upper": result.get("median_95_percent_upper"),
            "pass": bool(result.get("pass")),
        }
    return {
        "available": True,
        "generated_at": document.get("generated_at"),
        "kernel": document.get("kernel"),
        "machine": document.get("machine"),
        "profile": document.get("profile"),
        "iterations": document.get("iterations"),
        "scenarios": scenarios,
    }


def showcase_payload() -> dict:
    return {
        "reviews": [review_view(key, path) for key, path in REVIEWS.items()],
        "performance": performance_view(),
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] == "/api/showcase":
            body = json.dumps(showcase_payload(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split("?", 1)[0] == "/":
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, format: str, *args) -> None:
        print(f"[ui] {self.address_string()} {format % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    url = f"http://{args.host}:{args.port}/"
    print(f"dashboard {url}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\ndashboard stopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
