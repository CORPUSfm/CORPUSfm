"""Storage build-mismatch gate — detect a DB schema older than the running code.

Packet 085 is **fresh-install-only** (no migration to the new format; no legacy
table shapes, no compatibility shims). The old *migrate-into-new-file* data engine
(export → close → swap → import → verify, carrying pre-generic named tables forward)
is RETIRED — it only ever migrated the pre-``.500`` NAMED schema into the generic
substrate, which no supported box runs, and the packet forbids carrying data across a
schema change. What survives is **build-mismatch DETECTION**: when the deployed code
expects a different schema than the live DB, startup refuses.

**There is no cached UI gate any more (packet 1361-01, round 12).** `refresh_gate()`,
`gate_active()`, the `_GATE` cache, its throttled self-clearing re-check and the
`/build-mismatch` page it redirected to are all retired. They existed to lock a SERVING
box's UI, and a box with a proven mismatch is not serving: round 11 made it a
deterministic startup refusal, so the process pauses before anything is published and the
local paused supervisory page carries the guidance. Nothing could reach the cached gate
after that, which is why it is gone rather than kept "just in case".

Two detectors survive, for two different questions:

* :func:`probe_build` — the STRICT startup probe. One live-Build read, unguarded, returning
  the structured facts the startup authority needs for BOTH its classification and its
  administrator guidance.
* :func:`is_pending` — the FAIL-OPEN convenience its remaining runtime consumers use
  (`latest.latest_available`, `tags_store`) to decide whether a schema-dependent feature is
  usable. Fail-open is right there: those callers must never brick a working box.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
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


# ── The strict startup probe ─────────────────────────────────────────────────

@dataclass(frozen=True)
class BuildProbe:
    """What ONE successful live-Build read established.

    Structured rather than a bare bool because the startup authority needs the same facts twice
    (packet 1361-01, round 12): once to CLASSIFY — a proven mismatch is a deterministic refusal —
    and once to compose the direction-specific guidance the paused supervisory page shows. It used
    to get the verdict from the probe and then read the Build a SECOND time to build the sentence,
    which is two reads of one fact and two chances for them to disagree.
    """

    mismatch: bool
    live: str
    expected: str


def probe_build(backend) -> BuildProbe:
    """Read the live Build ONCE and say what it proves. RAISES on an unreadable Build.

    :func:`is_pending` fails open on every exception, which is right for a running box's feature
    check and WRONG as a startup prerequisite (packet 1361-01, round 3): "I could not read the
    Build" is not evidence the schema matches, and recording it as "no mismatch" is exactly the
    fail-open the ruling forbids. This lets the read error out so the startup authority can stop the
    attempt and retry the whole chain.

    * unreadable → raises (the caller classifies it transient);
    * successfully read EMPTY → ``mismatch False`` and stays indeterminate, because a fresh corpus
      has no stamp yet and refusing to boot on it would brick every new installation;
    * read and DIFFERENT → ``mismatch True``, which is typed, authoritative and deterministic;
    * read and equal → ``mismatch False``, and startup proceeds normally.
    """
    target = expected_build()
    if not target or not hasattr(backend, "load_fm_build"):
        return BuildProbe(False, "", target)
    live = str(backend.load_fm_build()).strip()       # ONE read, deliberately UNGUARDED
    return BuildProbe(bool(live and live != target), live, target)
