#!/usr/bin/env python3
"""Adversary — Live Dashboard Server

Serves the groundwork + security report as an auto-refreshing dashboard.
Uses only Python stdlib (no pip install needed).

Usage:
    python3 serve-dashboard.py
    python3 serve-dashboard.py --port 9000 --report /path/to/report.json --no-open
"""

import argparse
import json
import os
import sys
import threading
import time
import webbrowser
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DASHBOARD_HTML = SKILL_DIR / "assets" / "dashboard-live.html"

sse_clients = []
sse_clients_lock = threading.Lock()


class FileWatcher(threading.Thread):
    """Watches report JSON file for mtime changes and notifies SSE clients."""

    def __init__(self, report_path, interval=2):
        super().__init__(daemon=True)
        self.report_path = Path(report_path)
        self.interval = interval
        self.last_mtime = self._get_mtime()

    def _get_mtime(self):
        try:
            return self.report_path.stat().st_mtime
        except FileNotFoundError:
            return 0

    def run(self):
        while True:
            time.sleep(self.interval)
            current_mtime = self._get_mtime()
            if current_mtime != self.last_mtime:
                self.last_mtime = current_mtime
                self._notify_clients()

    def _notify_clients(self):
        with sse_clients_lock:
            dead = []
            for client_wfile in sse_clients:
                try:
                    client_wfile.write(b"data: reload\n\n")
                    client_wfile.flush()
                except Exception:
                    dead.append(client_wfile)
            for d in dead:
                sse_clients.remove(d)


def make_handler(report_path):

    class DashboardHandler(BaseHTTPRequestHandler):

        def log_message(self, format, *args):
            if "/api/events" not in str(args[0]):
                super().log_message(format, *args)

        def _cors_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def do_OPTIONS(self):
            self.send_response(200)
            self._cors_headers()
            self.end_headers()

        def do_GET(self):
            if self.path == "/" or self.path == "/index.html":
                self._serve_dashboard()
            elif self.path == "/api/report":
                self._serve_report()
            elif self.path == "/api/events":
                self._serve_sse()
            else:
                self.send_error(404)

        def _serve_dashboard(self):
            try:
                content = DASHBOARD_HTML.read_bytes()
            except FileNotFoundError:
                self.send_error(500, "dashboard-live.html not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(content)

        def _serve_report(self):
            rpath = Path(report_path)
            if not rpath.exists():
                payload = json.dumps({"status": "waiting", "message": "No report data yet. Run a groundwork scan to generate data."}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self._cors_headers()
                self.end_headers()
                self.wfile.write(payload)
                return

            try:
                content = rpath.read_bytes()
                json.loads(content)
            except json.JSONDecodeError:
                self.send_error(500, "Report JSON is malformed")
                return
            except Exception as e:
                self.send_error(500, str(e))
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(content)

        def _serve_sse(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self._cors_headers()
            self.end_headers()

            with sse_clients_lock:
                sse_clients.append(self.wfile)

            try:
                self.wfile.write(b"data: connected\n\n")
                self.wfile.flush()
                while True:
                    time.sleep(30)
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except Exception:
                pass
            finally:
                with sse_clients_lock:
                    if self.wfile in sse_clients:
                        sse_clients.remove(self.wfile)

    return DashboardHandler


def main():
    parser = argparse.ArgumentParser(
        description="Adversary — Live Dashboard Server"
    )
    parser.add_argument(
        "--port", type=int, default=8450,
        help="Port to serve on (default: 8450)"
    )
    parser.add_argument(
        "--report", type=str, default="/tmp/groundwork-report.json",
        help="Path to report JSON file (default: /tmp/groundwork-report.json)"
    )
    parser.add_argument(
        "--no-open", action="store_true",
        help="Don't auto-open browser"
    )
    args = parser.parse_args()

    if not DASHBOARD_HTML.exists():
        print(f"Error: Dashboard HTML not found at {DASHBOARD_HTML}", file=sys.stderr)
        sys.exit(1)

    watcher = FileWatcher(args.report)
    watcher.start()

    handler = make_handler(args.report)
    server = HTTPServer(("127.0.0.1", args.port), handler)

    url = f"http://localhost:{args.port}"
    report_status = "found" if Path(args.report).exists() else "not yet created (waiting for scan)"

    print(f"\n  Adversary — Live Dashboard")
    print(f"  {'=' * 38}")
    print(f"  URL:        {url}")
    print(f"  Report:     {args.report} ({report_status})")
    print(f"  Watching:   every 2s for changes")
    print(f"  Press Ctrl+C to stop\n")

    if not args.no_open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
