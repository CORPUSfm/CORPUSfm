"""Webhook listener subprocess for Jobs.

Listens for POST /webhook/{job_uuid}/{token} and fires job runs.
Also exposes GET /health for liveness checks.

Usage (run as subprocess or directly):
    python -m corpusfm.server.jobs.webhook [--port 8765]

**The custom-path flags are gone (packet 1361-01):** `--jobs-dir`, `--archive-dir` and
`--history-dir` selected a job store, an archive and a run history off disk, which is the
filesystem job model the product does not support. Jobs come from the JOB table, the run goes on
the QUEUE, and the artifact is stored internally.

The listener runs blocking in the calling thread. To launch from code:

    import subprocess, sys
    proc = subprocess.Popen([sys.executable, "-m", "corpusfm.server.jobs.webhook",
                             "--port", "8765"])

Public API (for testing / embedding):
    make_handler()
    webhook_url(job_uuid, token, host, port) -> str
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

DEFAULT_PORT = 8765


def webhook_url(
    job_uuid: str,
    token: str,
    host: str = "localhost",
    port: int = DEFAULT_PORT,
) -> str:
    """Return the webhook URL for a job."""
    return f"http://{host}:{port}/webhook/{job_uuid}/{token}"


def make_handler():
    """Return the BaseHTTPRequestHandler class for the webhook listener."""

    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            parts = self.path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "webhook":
                self._respond(404, {"status": "error", "message": "Not found"})
                return

            _, job_uuid, token = parts

            try:
                from corpusfm.server.jobs.store import load_job
                job = load_job(job_uuid)
            except KeyError:
                self._respond(404, {"status": "error", "message": f"Job '{job_uuid}' not found"})
                return

            if not job.webhook_token or job.webhook_token != token:
                self._respond(403, {"status": "error", "message": "Invalid token"})
                return

            has_webhook = any(t.type == "webhook" for t in job.triggers)
            if not has_webhook:
                self._respond(400, {"status": "error", "message": "Job has no webhook trigger"})
                return

            # ENQUEUE, never execute (packet 1361-01, ruling 10). This used to spawn a daemon
            # thread running the synchronous runner inside the standalone webhook listener — a
            # second production pull path outside the QUEUE worker's mutual exclusion, in a process
            # that is not the worker host. It now puts a Job Run on the QUEUE exactly as the
            # scheduler, the browser and MCP do, and answers 202 with the identifiers that let the
            # caller follow it.
            try:
                from corpusfm.server import queue_handlers as QH
                from corpusfm.server import queue_workers as W
                from corpusfm.storage import queue_record as Q
                from corpusfm.storage import get_backend
                backend = get_backend()
                qid, run_id = QH.enqueue_job_run(
                    backend, job_name=job.name, job_uuid=job_uuid,
                    file_name=getattr(job.source, "file_name", "") or "",
                    trigger="webhook")
                try:
                    W.poke(Q.ACQUIRE)
                except Exception:
                    pass
            except Exception as exc:  # noqa: BLE001
                self._respond(500, {"status": "error",
                                    "message": f"could not queue the run: {exc}"})
                return
            self._respond(202, {"status": "accepted", "job": job_uuid,
                                "queue_id": qid, "run_id": run_id})

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
    args = parser.parse_args()

    server = HTTPServer(("", args.port), make_handler())
    print(f"corpusfm webhook listener running on port {args.port}", flush=True)
    print("  Jobs come from the JOB table; a trigger enqueues a Job Run.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    _main()
