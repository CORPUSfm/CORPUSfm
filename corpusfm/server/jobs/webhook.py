"""Webhook listener subprocess for Jobs.

Listens for POST /webhook/{job_name}/{token} and fires job runs.
Also exposes GET /health for liveness checks.

Usage (run as subprocess or directly):
    python -m corpusfm.server.jobs.webhook [--port 8765] [--jobs-dir PATH]
                                   [--archive-dir PATH] [--history-dir PATH]

The listener runs blocking in the calling thread. To launch from code:

    import subprocess, sys
    proc = subprocess.Popen([sys.executable, "-m", "corpusfm.server.jobs.webhook",
                             "--port", "8765"])

Public API (for testing / embedding):
    make_handler(jobs_dir, archive_dir, history_dir)
    webhook_url(job_name, token, host, port) -> str
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

DEFAULT_PORT = 8765


def webhook_url(
    job_name: str,
    token: str,
    host: str = "localhost",
    port: int = DEFAULT_PORT,
) -> str:
    """Return the webhook URL for a job."""
    return f"http://{host}:{port}/webhook/{job_name}/{token}"


def make_handler(
    jobs_dir: Path,
    archive_dir: Path,
    history_dir: Path,
):
    """Return a BaseHTTPRequestHandler class configured for the given directories."""

    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            parts = self.path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "webhook":
                self._respond(404, {"status": "error", "message": "Not found"})
                return

            _, job_name, token = parts

            try:
                from corpusfm.server.jobs.store import load_job
                job = load_job(job_name, jobs_dir)
            except KeyError:
                self._respond(404, {"status": "error", "message": f"Job '{job_name}' not found"})
                return

            if not job.webhook_token or job.webhook_token != token:
                self._respond(403, {"status": "error", "message": "Invalid token"})
                return

            has_webhook = any(t.type == "webhook" for t in job.triggers)
            if not has_webhook:
                self._respond(400, {"status": "error", "message": "Job has no webhook trigger"})
                return

            # Fire job in background thread; respond immediately
            def _run():
                from corpusfm.server.jobs.runner import run_job
                run_job(
                    job_name,
                    jobs_dir=jobs_dir,
                    archive_dir=archive_dir,
                    history_dir=history_dir,
                    trigger="webhook",
                )

            threading.Thread(target=_run, daemon=True).start()
            self._respond(202, {"status": "accepted", "job": job_name})

        def do_GET(self):
            if self.path in ("/health", "/health/"):
                self._respond(200, {"status": "ok", "listener": "corpusfm-webhook"})
            else:
                self._respond(404, {"status": "error", "message": "Not found"})

        def _respond(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            pass  # silence default access log

    return WebhookHandler


def _main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="corpusfm webhook listener")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--jobs-dir", type=str, default=None)
    parser.add_argument("--archive-dir", type=str, default=None)
    parser.add_argument("--history-dir", type=str, default=None)
    args = parser.parse_args()

    from corpusfm.server.jobs.history import default_history_dir
    from corpusfm.server.jobs.store import default_jobs_dir
    from corpusfm.storage import get_backend

    jobs_dir = Path(args.jobs_dir) if args.jobs_dir else default_jobs_dir()
    archive_dir = get_backend(Path(args.archive_dir) if args.archive_dir else None).archive_dir
    history_dir = Path(args.history_dir) if args.history_dir else default_history_dir()

    handler_cls = make_handler(jobs_dir, archive_dir, history_dir)
    server = HTTPServer(("", args.port), handler_cls)
    print(f"corpusfm webhook listener running on port {args.port}", flush=True)
    print(f"  Jobs dir:   {jobs_dir}", flush=True)
    print(f"  Archive:    {archive_dir}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    _main()
