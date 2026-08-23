"""Storage build-mismatch gate — detect a DB schema older than the running code.

Packet 085 is **fresh-install-only** (no migration to the new format; no legacy
table shapes, no compatibility shims). The old *migrate-into-new-file* data engine
(export → close → swap → import → verify, carrying pre-generic named tables forward)
is RETIRED — it only ever migrated the pre-``.500`` NAMED schema into the generic
substrate, which no supported box runs, and the packet forbids carrying data across a
schema change. What survives is the **build-mismatch gate**: when the deployed code
expects a newer schema than the live DB, we lock the UI to a "fresh install required"
page rather than silently running against a stale DB.

The gate is CACHED + FAIL-OPEN (any read error → not gated; never brick a working
box) and SELF-CLEARING (a transient boot read that can't reach OData won't stick
until a manual restart — an ACTIVE gate re-evaluates on access, throttled).
"""

from __future__ import annotations

import logging
import time as _time
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Detection ────────────────────────────────────────────────────────────────

def expected_build() -> str:
    """The Build stamped in the shipped base DB — the schema the code was built for.

    Read from the committed manifest (db_schema_build.txt), kept in sync with
    db/CORPUSfm_DB at DB-update time. NOT the app's git build number.
    """
    try:
        return (Path(__file__).with_name("db_schema_build.txt")
                .read_text(encoding="utf-8").strip())
    except Exception:
        return ""


def is_pending(backend) -> bool:
    """True only when we have a CONFIDENT, non-empty live Build that DIFFERS from the
    shipped target. An empty/unreadable Build (FMS/OData not up yet, empty SETTING table,
    a swallowed read error) is INDETERMINATE — we can't prove the DB is behind, so we
    fail open (return False) rather than brick a working box."""
    target = expected_build()
    if not target or not hasattr(backend, "load_fm_build"):
        return False
    try:
        live = str(backend.load_fm_build()).strip()
    except Exception:
        logger.debug("is_pending: load_fm_build failed", exc_info=True)
        return False
    if not live:
        return False
    return live != target


# ── Build-mismatch gate ──────────────────────────────────────────────────────
# When the running code expects a newer schema than the live DB (is_pending), the
# in-app pull can't fix it (085 is fresh-install-only — there is no in-place
# migration). We lock the UI to a "fresh install required" page and pause in-app
# updates. Cached + FAIL-OPEN (any error → not gated; never brick a working box).
#
# Self-clearing: the gate is computed once at startup, but a transient boot read (FMS/
# OData not answering yet) must not stick until a manual restart. When the gate is
# ACTIVE we re-evaluate is_pending on access (throttled to at most _GATE_RECHECK_SECS),
# so once OData is healthy the gate clears WITHOUT a restart. The INACTIVE state stays
# cached/cheap — no per-request FM read when nothing is gated.

_GATE_RECHECK_SECS = 30.0
_GATE: dict = {"active": False, "backend": None, "last_check": 0.0}


def refresh_gate(backend) -> bool:
    _GATE["backend"] = backend
    _GATE["last_check"] = _time.monotonic()
    try:
        _GATE["active"] = bool(is_pending(backend))
    except Exception:
        _GATE["active"] = False
    return _GATE["active"]


def gate_active() -> bool:
    if not _GATE.get("active"):
        return False
    backend = _GATE.get("backend")
    if backend is not None and (_time.monotonic() - _GATE.get("last_check", 0.0)) >= _GATE_RECHECK_SECS:
        _GATE["last_check"] = _time.monotonic()
        try:
            _GATE["active"] = bool(is_pending(backend))
        except Exception:
            logger.debug("gate_active: re-check failed", exc_info=True)
    return bool(_GATE.get("active"))
