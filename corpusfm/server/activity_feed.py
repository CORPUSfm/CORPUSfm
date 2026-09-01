"""Unified activity feed — packet 1136 **Stage 1** (server-side; no UI change yet).

ONE aggregated activity conversation (docs/reactive-feedback-design.md): the durable QUEUE workspace
(``queue_handlers.workspace_view``) normalized to the activity-record contract, PLUS a snapshot of the
ephemeral in-memory generation tasks, under a per-process ``generation`` envelope. Stages 2–4 (the
client store, busy-mode cadence, self-resolving spinners) consume this ONE feed.

**Restart-loss, resolved honestly (the load-bearing requirement).** An empty post-restart in-memory
registry CANNOT enumerate the ephemeral task ids it lost — so the feed does NOT pretend to, and nothing
here is persisted. Instead the feed carries a per-process ``generation`` token. A client that was
tracking an ephemeral task and finds it ABSENT from the feed classifies the absence WITHOUT persistence
(:func:`classify_ephemeral_absence`):

  • generation CHANGED → the process restarted and wiped the registry → ``evicted``;
  • generation UNCHANGED → ``unknown_expired``. Absence is NEVER proof of success: the client may simply
    have missed the retained terminal record (a poll gap ≥ retention, or it was offline). A success/done
    outcome comes ONLY from actually OBSERVING the terminal record within the window — never from a
    disappearance. The client must not synthesize a success state or toast from ``unknown_expired``.

Durable records survive a restart by definition (they are persisted), so the ``evicted`` terminal — and
the generation token — applies ONLY to ephemeral tasks. Durable completion/cancellation is NOT
server-retained: the durable source DELETES the record, so a durable disappearance is reconciled
CLIENT-side into a NEUTRAL terminal observation (:func:`durable_absence_is_terminal`) — and only after a
SUCCESSFUL durable observation (a failed poll is not a disappearance).

**Per-source observation validity (pin #1).** The envelope reports ``sources.{durable,ephemeral}.ok`` so a
FAILED read of one source is distinguishable from a genuinely-empty successful snapshot. A client
retains last-known state for a source whose ``ok`` is False and reconciles disappearances only against a
source it actually observed. Building the feed is a pure read; it transitions nothing.
"""
from __future__ import annotations

import logging
import uuid as _uuidlib

from corpusfm.server import activity_contract as _contract

log = logging.getLogger("corpusfm.server.activity_feed")

# Per-process generation token: distinct on every process start, so a CHANGE == a restart. In-memory
# only — never persisted. That is the whole point: ephemeral state does NOT survive a restart, and this
# token lets a client PROVE that rather than guess it from a disappearance.
_PROCESS_GENERATION: str = _uuidlib.uuid4().hex


def process_generation() -> str:
    return _PROCESS_GENERATION


def classify_ephemeral_absence(*, last_seen_generation: str, current_generation: str) -> str:
    """An ephemeral task the client was tracking is ABSENT from the feed. Absence is NEVER success — a
    done/success outcome comes ONLY from actually OBSERVING the retained terminal record within the
    retention window. Defined ONCE here so the contract has a single source. Returns:

      'evicted'         — the process generation changed since last seen → a restart wiped the in-memory
                          registry; the task's outcome is LOST.
      'unknown_expired' — same generation, but the client did not observe the terminal record before it
                          aged out of retention (a polling gap ≥ retention, or the client was offline).
                          Outcome is UNKNOWN; the client must NOT synthesize a success/done state or toast.

    Only call this for a task genuinely ABSENT from a SUCCESSFULLY-observed ephemeral source — never off a
    failed ephemeral read (that is not a disappearance; retain last-known state — see the envelope's
    ``sources.ephemeral.ok``)."""
    if last_seen_generation and last_seen_generation != current_generation:
        return "evicted"
    return "unknown_expired"


def is_restart_evicted(*, last_seen_generation: str, current_generation: str,
                       present_in_feed: bool) -> bool:
    """Preserved thin predicate: True ONLY when a generation change proves ephemeral restart-eviction of
    an absent task. It NEVER asserts completion — absence under the SAME generation is ``unknown_expired``
    (see :func:`classify_ephemeral_absence`), not success."""
    if present_in_feed:
        return False
    return classify_ephemeral_absence(last_seen_generation=last_seen_generation,
                                      current_generation=current_generation) == "evicted"


def durable_absence_is_terminal(*, durable_source_ok: bool, present_in_feed: bool) -> bool:
    """A durable record the client was tracking has left the feed. This becomes a TERMINAL client
    observation — the record completed / was cancelled / was removed (INDISTINGUISHABLE server-side, so a
    NEUTRAL 'finished/removed', NEVER a synthesized success; a JobRun's real ok/error lives durably in
    HISTORY) — ONLY after a SUCCESSFUL durable observation. A FAILED durable read (503/exception) is NOT a
    disappearance: the client retains last-known active state (pin #1). Durable completion is not
    server-retained (the durable source deletes the record), so there is no retention window to wait on —
    a single successful observation of the record's absence is the terminal signal."""
    return bool(durable_source_ok) and not present_in_feed


# Durable Queue display-tag (``queue_handlers._kinds_and_target``) → activity-contract kind. Covers
# every tag the current producers emit; an unmapped scaffolding tag (git_export/verify never surface as
# a bare row today — they ride an import pipeline) falls back defensively so the feed never crashes.
_DURABLE_KIND_MAP = {
    "Import": "import", "JobRun": "job-run", "Summarize": "enrichment-summarize",
    "Index": "enrichment-index", "Deindex": "deindex", "Reingest": "reingest",
    "Deliverable": "deliverable",
}


def _durable_kind(tag: str) -> str:
    if tag in _DURABLE_KIND_MAP:
        return _DURABLE_KIND_MAP[tag]
    k = (tag or "").strip().replace(" ", "-").lower()
    return k if k in _contract.ACTIVITY_KINDS else "import"


def _normalize_durable(row: dict) -> dict:
    """One ``workspace_view`` row → an activity-contract record. Durable rows never report ``done`` (a
    completed record is DELETED from the queue — its result lives durably in the catalog/HISTORY); the
    live states are queued/running/failed, and a failure PARKS (retained until Restart/Delete). ``progress``
    is a REAL, monotonic PIPELINE position (it advances when the record moves to its next step) — a client
    detects a change and starts ITS OWN progress-silence clock from that observation. Durable rows do NOT
    persist a per-progress timestamp, so ``updated_at`` is ``None`` (NEVER fabricated to equal created_at
    — that would be a false last-progress time). ``created_at`` is the real enqueue time. A record is
    ``cancelable`` when queued (removable) or a running raw-index (stoppable mid-run) — mirroring
    ``queue_handlers.cancel_record``."""
    steps = list(row.get("steps") or [])
    current = row.get("current") or ""
    prog = steps.index(current) if current in steps else 0
    status = row.get("status", "queued")
    rid = row.get("id", "")
    cancelable = bool(row.get("cancelable")) or status == "queued"
    kinds = [_durable_kind(k) for k in (row.get("kinds") or [])] or ["import"]
    created = row.get("created_at", "") or _contract.utcnow_iso()
    return {
        "id": rid,
        "kinds": kinds,
        "status": status,
        "progress": int(prog),
        "created_at": created,
        "updated_at": None,          # durable source tracks no per-progress ts — client times silence
        "cancelable": cancelable,    # from observed `progress`-token changes (never a fabricated ts)
        "cancel_route": f"/api/queue/{rid}/cancel" if cancelable else None,
        "target": row.get("target", "") or "",
        "error": row.get("error", "") or "",
        "ephemeral": False,
        # JobRun fold (R4): the running-badge data rides the ONE feed row, so /api/jobs/running is a
        # redundant re-derivation (retired client-side in Stage 2). Empty for non-job records.
        "job_uuid": row.get("job_uuid", "") or "",   # what the running badge joins on (1372-02)
        "job_name": row.get("job_name", "") or "",
        "file_name": row.get("file_name", "") or "",
        "uuid": row.get("uuid", "") or "",
        "owner": row.get("owner", "") or "",     # the client store's stop-permission (owner-or-admin) check
        "steps": steps,
        "current": current,
    }


def build_feed(backend, *, now_monotonic: "float | None" = None) -> dict:
    """The unified activity feed:
    ``{"generation": <token>, "records": [...], "durable_rows": [...], "sources": {...}}``. Durable
    QUEUE rows are normalized to the contract (``records``); the ephemeral generation tasks are appended
    from the in-memory registry (with terminal retention). ``durable_rows`` is the RAW ``workspace_view``
    output (un-normalized), returned so the /api/queue route reuses this one read for its record-centric
    Queue view instead of reading the durable source a second time (packet 1160); it is ``[]`` exactly
    when ``sources.durable.ok`` is False.

    ``sources.{durable,ephemeral}.ok`` reports PER-SOURCE observation validity: a FAILED read of one
    source (pin #1 — a 502/exception is not evidence of completion) is DISTINGUISHABLE from a genuinely
    empty successful snapshot, and never false-finishes, drops, or mutates the other. A client retains
    last-known state for a source whose ``ok`` is False, and reconciles a disappearance (durable or
    ephemeral) ONLY against a source it actually observed (``ok`` True)."""
    records: list = []
    durable_rows: list = []
    durable_ok = False
    try:
        from corpusfm.server import queue_handlers
        # Read ONCE. The raw rows are also returned (``durable_rows``) so the /api/queue route reuses this
        # snapshot for its Queue view instead of calling workspace_view a second time (packet 1160). Commit
        # both atomically: normalize into a temp list first, so a mid-normalize failure leaves durable_rows
        # empty + durable.ok False (retain last-known) rather than a half-populated snapshot.
        rows = queue_handlers.workspace_view(backend)
        normalized = [_normalize_durable(r) for r in rows]
        durable_rows = rows
        records.extend(normalized)
        durable_ok = True
    except Exception:
        durable_rows = []
        log.debug("activity feed: durable source read failed — retain last-known (sources.durable.ok=False)",
                  exc_info=True)
    ephemeral_ok = False
    try:
        from corpusfm.app.web.routes.api import generate as _gen
        records.extend(_gen.ephemeral_activity_snapshot(now_monotonic=now_monotonic))
        ephemeral_ok = True
    except Exception:
        log.debug("activity feed: ephemeral snapshot failed — retain last-known (sources.ephemeral.ok=False)",
                  exc_info=True)
    return {"generation": process_generation(), "records": records, "durable_rows": durable_rows,
            "sources": {"durable": {"ok": durable_ok}, "ephemeral": {"ok": ephemeral_ok}}}
