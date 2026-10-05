#!/usr/bin/env python3
"""Local dashboard for the eBPF agent monitor review reports."""

from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import json
import os
from pathlib import Path
import subprocess
import sys
import webbrowser


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui.scenarios import catalog, run_scenario
UI_DIR = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "docs" / "review_reports"
REVIEWS = {
    "review-1": REPORT_DIR / "review-1-functional-causality.json",
    "review-2": REPORT_DIR / "review-2-observability.json",
    "review-3": REPORT_DIR / "review-3-performance.json",
}
PERFORMANCE = REPORT_DIR / "performance" / "performance_report.json"
LIVE_HINT = "sudo -v && python3 ui/server.py"


class LiveError(RuntimeError):
    """A live-run failure that may carry a fix-it hint for the console."""

    # 构造异常对象：保存消息和可展示的修复提示。
    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.hint = hint


# 检查实时采集是否可用：采集器已编译且 sudo 凭证仍有效。
def live_status() -> dict:
    """Report whether a live run can start right now."""

    if not (ROOT / "build" / "agent-monitor").is_file():
        return {"available": False, "reason": "采集器还没有编译，先运行 make"}
    try:
        completed = subprocess.run(
            ["sudo", "-n", "true"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "reason": f"无法调用 sudo，请在终端执行：{LIVE_HINT}"}
    if completed.returncode:
        return {"available": False, "reason": "需要先在终端授权 sudo"}
    return {"available": True, "reason": ""}


# 以 sudo 调起 ui/live/driver.py 跑一次真实采集，并解析它输出的结果 JSON。
def run_live_scenario(name: str) -> dict:
    """Run the real eBPF capture pipeline for one trigger and return its timeline."""

    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    try:
        completed = subprocess.run(
            [
                "sudo",
                "-n",
                sys.executable,
                "-m",
                "ui.live.driver",
                "--scenario",
                name,
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("实时采集超时，请重试") from error
    if completed.returncode == 0:
        try:
            return json.loads(completed.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as error:
            raise RuntimeError("实时采集返回了无法解析的结果") from error
    message = ""
    for line in reversed(completed.stdout.strip().splitlines()):
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = str(document.get("error") or "")
        if message:
            break
    if not message and "sudo" in (completed.stderr or ""):
        raise LiveError("sudo 授权已过期", LIVE_HINT)
    raise LiveError(message or completed.stderr.strip() or "实时采集失败")


# 读一份评审报告 JSON；文件不存在时返回 None。
def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    return document if isinstance(document, dict) else None


# 把某份评审报告裁剪成前端需要的视图（结论、检查项、告警、事件样例）。
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


# 汇总性能报告的关键指标，供“性能”页使用。
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


# 组装总览接口的返回：三份评审视图 + 性能视图。
def showcase_payload() -> dict:
    return {
        "reviews": [review_view(key, path) for key, path in REVIEWS.items()],
        "performance": performance_view(),
    }


# HTTP 处理器：静态文件走 ui/ 目录，API 走 do_GET / do_POST。
class DashboardHandler(SimpleHTTPRequestHandler):
    # 把静态文件根目录固定为 ui/。
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

# 统一输出 JSON 响应，带 no-store 防止页面读到旧报告。
    def _json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

# 处理 POST：实时采集（/api/live/scenarios/）与离线场景（/api/scenarios/）。
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        path = self.path.split("?", 1)[0]
        live_prefix = "/api/live/scenarios/"
        if path.startswith(live_prefix):
            name = path[len(live_prefix) :]
            try:
                payload = run_live_scenario(name)
            except KeyError:
                self._json(404, {"error": f"unknown scenario: {name}"})
            except LiveError as error:
                self._json(500, {"error": str(error), "hint": error.hint})
            except (OSError, RuntimeError, ValueError) as error:
                self._json(500, {"error": str(error)})
            else:
                self._json(200, payload)
            return
        prefix = "/api/scenarios/"
        if not path.startswith(prefix):
            self.send_error(404)
            return
        name = path[len(prefix) :]
        try:
            payload = run_scenario(name)
        except KeyError:
            self._json(404, {"error": f"unknown scenario: {name}"})
            return
        except (OSError, RuntimeError, ValueError) as error:
            self._json(500, {"error": str(error)})
            return
        self._json(200, payload)

# 处理 GET：实时状态、场景清单、总览数据，其余按静态文件返回。
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/live/status":
            self._json(200, live_status())
            return
        if path == "/api/scenarios":
            self._json(200, {"scenarios": catalog()})
            return
        if path == "/api/showcase":
            self._json(200, showcase_payload())
            return
        if self.path.split("?", 1)[0] == "/":
            self.path = "/index.html"
        super().do_GET()

# 把访问日志缩写成带 [ui] 前缀的一行。
    def log_message(self, format: str, *args) -> None:
        print(f"[ui] {self.address_string()} {format % args}")


# 程序入口：解析监听地址/端口，启动 sudo 续期线程，然后开始服务。
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


# sudo -v && python3 ui/server.py