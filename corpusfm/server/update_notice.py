"""Informational post-update notice publication.

Release markers may carry one short ``whats_new`` line. They never reset an index, re-ingest an
artifact, enqueue work, or act as a generic data-migration system. A release that genuinely needs a
derived-data migration gets its own packet and recovery design.

The web startup and the stable ``corpusfm update-notice`` installer CLI can race after restart. One
box-local lock serializes publication; state reads used for mutation are strict, and state writes use a
private atomic sibling so corruption or write failure can never be flattened into successful progress.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

RELEASE_MARKERS: list = [
    # {"build": <int>, "whats_new": "<one line>"},
]

_OBSERVE_SECONDS = 2.0
_OBSERVE_POLL_SECONDS = 0.05


class UpdateNoticeStateError(RuntimeError):
    """Notice state could not be read or published truthfully."""


def current_build() -> int:
    """This build's number (the ``N`` in ``0.N``). 0 on failure."""
    try:
        import corpusfm
        return int(str(corpusfm.__version__).rsplit(".", 1)[-1])
    except Exception:
        return 0


def _state_path() -> Path:
    from corpusfm.lifecycle import app_paths

    override = app_paths.development_override(
        "CORPUSFM_UPDATE_STATE",
        lambda: os.environ.get("CORPUSFM_UPDATE_STATE"),
        what="the update notice state file",
    )
    if override:
        return Path(str(override))
    return app_paths.state_dir() / "update_state.json"


def _load_state(*, strict: bool = False) -> dict:
    path = _state_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except Exception as exc:
        if strict:
            raise UpdateNoticeStateError("update notice state could not be read") from exc
        logger.debug("update_notice: state read failed", exc_info=True)
        return {}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("notice state is not an object")
        return parsed
    except Exception as exc:
        if strict:
            raise UpdateNoticeStateError("update notice state is corrupt") from exc
        logger.debug("update_notice: state parse failed", exc_info=True)
        return {}


def _save_state(state: dict) -> None:
    """Atomically publish private JSON or raise, leaving the previous bytes intact on failure."""
    path = _state_path()
    fd = -1
    tmp = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, raw_tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
        tmp = Path(raw_tmp)
        # mkstemp is private on both platforms. POSIX additionally pins the exact mode; Windows has
        # no os.fchmod and relies on the published state directory ACL plus mkstemp exclusivity.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        payload = json.dumps(state, indent=2).encode("utf-8")
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        # Make the rename durable where directory fsync is supported.
        try:
            dirfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except OSError:
            pass
    except Exception as exc:
        raise UpdateNoticeStateError("update notice state could not be published") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def pending_actions(last_seen: int, current: int) -> dict:
    """Collect informational lines from markers in ``(last_seen, current]``."""
    whats_new = []
    for marker in RELEASE_MARKERS:
        build = int(marker.get("build", 0) or 0)
        if last_seen < build <= current and marker.get("whats_new"):
            whats_new.append(str(marker["whats_new"]))
    return {"whats_new": whats_new}


def _flow_lock_path() -> Path:
    from corpusfm.lifecycle import app_paths

    return app_paths.run_dir() / "update_flow.lock"


def _failure(reason: str, detail: str) -> dict:
    return {"ok": False, "action": "failed", "version": current_build(), "notice": "",
            "reason": reason, "error": detail}


def _state_build(state: dict, field: str, default: int) -> int:
    """Read a persisted build number without letting malformed state escape as a raw exception."""
    try:
        return int(state.get(field, default))
    except (TypeError, ValueError) as exc:
        raise UpdateNoticeStateError(f"update notice state has an invalid {field}") from exc


def _observe_winner() -> dict:
    """Boundedly observe a contending publisher; never turn an unfinished winner into a no-op."""
    current = current_build()
    deadline = time.monotonic() + _OBSERVE_SECONDS
    while time.monotonic() < deadline:
        try:
            state = _load_state(strict=True)
        except UpdateNoticeStateError as exc:
            return _failure("state_unreadable", str(exc))
        if _state_build(state, "last_seen_version", -1) >= current:
            notice = state.get("last_notice") or {}
            if not isinstance(notice, dict):
                return _failure("state_unreadable", "update notice state has an invalid last_notice")
            text = notice.get("text", "") if _state_build(notice, "version", 0) == current else ""
            return {"ok": True, "action": "none", "version": current, "notice": text}
        time.sleep(_OBSERVE_POLL_SECONDS)
    return _failure("publication_indeterminate",
                    "another process is still publishing the update notice")


def run_update_flow(_backend=None) -> dict:
    """Publish this build's informational notice once; retained name preserves the installer contract."""
    from corpusfm.core.proc_lock import ProcessLock, ACQUIRED, HELD

    lock = ProcessLock(_flow_lock_path())
    status = lock.try_acquire()
    if status == HELD:
        return _observe_winner()
    if status != ACQUIRED:
        return _failure("lock_unavailable", "the update notice lock could not be acquired")
    try:
        return _run_update_flow_locked()
    except UpdateNoticeStateError as exc:
        return _failure("state_failure", str(exc))
    finally:
        lock.release()


def _run_update_flow_locked() -> dict:
    current = current_build()
    state = _load_state(strict=True)
    last_seen = state.get("last_seen_version")
    if last_seen is None:
        state["last_seen_version"] = current
        _save_state(state)
        return {"ok": True, "action": "fresh", "version": current, "notice": ""}
    last_seen_build = _state_build(state, "last_seen_version", -1)
    if current <= last_seen_build:
        notice = state.get("last_notice") or {}
        if not isinstance(notice, dict):
            raise UpdateNoticeStateError("update notice state has an invalid last_notice")
        text = notice.get("text", "") if _state_build(notice, "version", 0) == current else ""
        return {"ok": True, "action": "none", "version": current, "notice": text}

    actions = pending_actions(last_seen_build, current)
    result = {"ok": True, "action": "update", "version": current,
              "prev_version": last_seen_build, "whats_new": actions["whats_new"]}
    result["notice"] = notice_text(result)
    state["last_seen_version"] = current
    state["last_notice"] = {"version": current, "text": result["notice"], "detail": result}
    _save_state(state)
    return result


def notice_text(result: dict) -> str:
    if result.get("action") not in ("update",):
        return ""
    text = [f"Updated to v0.{result.get('version')}."]
    lines = result.get("whats_new") or []
    if lines:
        text.append(" ".join(line.rstrip(".") + "." for line in lines))
    return " ".join(text)


def current_notice() -> dict:
    state = _load_state()
    notice = state.get("last_notice") or {}
    if not notice or not notice.get("text"):
        return {}
    if int(notice.get("version", 0)) <= int(state.get("notice_dismissed_version", 0)):
        return {}
    return {"version": notice.get("version"), "text": notice.get("text")}


def about_notice() -> dict:
    notice = _load_state().get("last_notice") or {}
    return {"version": notice.get("version"), "text": notice.get("text")} if notice.get("text") else {}


def dismiss_notice() -> None:
    """Durably dismiss under the publication lock or raise; never report an uncommitted dismissal."""
    from corpusfm.core.proc_lock import ProcessLock, ACQUIRED, HELD

    deadline = time.monotonic() + _OBSERVE_SECONDS
    lock = ProcessLock(_flow_lock_path())
    while True:
        status = lock.try_acquire()
        if status == ACQUIRED:
            break
        if status != HELD:
            raise UpdateNoticeStateError("the update notice lock could not be acquired")
        if time.monotonic() >= deadline:
            raise UpdateNoticeStateError("update notice publication is still in progress")
        time.sleep(_OBSERVE_POLL_SECONDS)
    try:
        state = _load_state(strict=True)
        state["notice_dismissed_version"] = current_build()
        _save_state(state)
    finally:
        lock.release()
