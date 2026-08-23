"""Global blob-encryption conversion state + single-flight launcher.

Toggling the encrypt_blobs setting re-encodes every stored container blob to the new
form. That bulk re-encode must not race concurrent storage ops, so while it runs the
deployment gate (app.py) locks the whole app to /converting. The conversion runs in a
background daemon thread — closing the browser does not stop it. decode_blob auto-detects
on read, so a half-converted store always reads correctly.
"""

from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_state: dict = {
    "running": False,
    "done": 0,
    "total": 0,
    "target": None,   # the target encrypt_blobs value of the active/last run
    "error": "",
    "started": 0.0,
}


def is_running() -> bool:
    with _lock:
        return bool(_state["running"])


def state() -> dict:
    """A snapshot of conversion state, including a computed pct (0–100)."""
    with _lock:
        done = int(_state["done"])
        total = int(_state["total"])
        error = _state["error"]
        if error:
            # NEVER 100% for a run that failed. The old expression read "not running and no total"
            # as finished, so a conversion whose record listing failed reported 100% complete with
            # an empty error — a definite claim about work nobody observed (packet 1208).
            pct = int(round(100 * done / total)) if total else 0
        elif total:
            pct = int(round(100 * done / total))
        else:
            pct = 100 if not _state["running"] else 0
        return {
            "running": bool(_state["running"]),
            "done": done,
            "total": total,
            "pct": pct,
            "target": _state["target"],
            "error": error,
            # True only when the last run finished with every blob in the target form. The status
            # page needs to tell "finished" apart from "stopped", and `running: false` cannot.
            "complete": bool(not _state["running"] and _state["started"] and not error),
            "started": _state["started"],
        }


def _progress(done: int, total: int) -> None:
    with _lock:
        _state["done"] = int(done)
        _state["total"] = int(total)


def start(backend, target_encrypt: bool) -> bool:
    """Start a bulk re-encode in a background daemon thread. Returns False if a conversion
    is already running (single-flight). The thread never lets an error crash the process —
    it records it in state and clears running."""
    with _lock:
        if _state["running"]:
            return False
        _state["running"] = True
        _state["done"] = 0
        _state["total"] = 0
        _state["target"] = bool(target_encrypt)
        _state["error"] = ""
        _state["started"] = time.time()

    def _run() -> None:
        try:
            backend.reencode_all_blobs(bool(target_encrypt), progress_cb=_progress)
        except Exception as exc:  # never crash the daemon thread
            # Includes ReencodeIncomplete, which is the point: a partial or refused conversion now
            # ARRIVES here instead of returning normally and leaving `error` empty (packet 1208).
            with _lock:
                _state["error"] = str(exc)
        finally:
            with _lock:
                _state["running"] = False

    threading.Thread(target=_run, name="blob-reencode", daemon=True).start()
    return True
