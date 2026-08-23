"""Unified QUEUE-record model (packet 086 / Ruling B) — the pure logic layer.

Every background unit of work is ONE QUEUE record that walks a linear "laundry list" of steps; its
``Type`` is the cursor into that list — and also which FIFO worker owns it right now. A worker drains
its ``Type``, does that one step, then ``advance``s (the record's cursor moves to the next step's
``Type``) or the caller ``delete``s it when the list is exhausted. **Deletion is the only success.**
Any step failure stamps ``Outcome`` + ``IsFailed`` and leaves the record at its current ``Type`` for
a human **Restart** (re-run the current step) or **Delete** — *try once, move on*, no auto-retry.

This module is **backend-agnostic**: it builds and transitions the jor dict, nothing more.
Persistence (create/update/delete over the StorageEngine) lives in the repo layer. Keeping the
transitions pure makes the whole state machine unit-testable without a backend.

The control fields (``Type``/``UUIDJob``/``UUIDStorage``/``IsFailed``) are indexed slots (registry
v2); the rest (``Steps``/``Outcome``/``Payload``/``owner``/``created_at``) ride the jor un-indexed.
``IsFailed`` is the indexed projection of "``Outcome`` is populated" — it powers the red nav badge
and the drain count.

**The cursor is ``Type`` alone (packet 1004 / D2).** ``Type`` is both the position in ``Steps`` and
the FIFO worker that owns the record — so the position is derived (``Steps.index(Type)``), never
stored twice. ``build`` enforces the invariant this rests on: **no repeated step within one laundry
list** (each pipeline visits a stage once), so ``index`` is unambiguous.
"""

from __future__ import annotations

# Step / worker vocabulary — a closed set. Each value is BOTH a laundry-list step AND a FIFO worker
# identity; changing Type hands the record from one worker to the next. deindex folds into index via
# a Payload op flag (packet-075 parity), so it is not its own step.
#
# UPLOAD is the CLIENT-performed first step of an import: the browser (or an MCP deliverable save)
# POSTs source bytes into the record's SourceXML container; the server advances upload→ingest on the
# final bytes. UPLOAD has NO worker — a client supplies the bytes — it is only swept by the upload
# WATCHDOG, which fails records that overstay the deadline (a crashed/abandoned client). This
# guarantees the INGEST worker only ever sees records whose source is present (strict two-state).
UPLOAD = "upload"
# ACQUIRE is the SELF-INITIATED first step of a Job Run (packet 1142): the run IS the acquire. The
# acquire worker calls a FileMaker export script (over OData, or fmsadmin/local read) and BLOCKS until
# it returns its verdict — the script does the whole export and either completes ("ok" / "ok: path") or
# fails ("error: N"). A push's bytes arrive via /api/upload DURING the block (the record carries the
# one-time PushTokenHash); a path-return or local method's bytes are read by the same blocking call (one
# fetch — dev decision B, packet 1142) and staged here. The step's OUTCOME is the staged source; its
# CLEANUP discards any deposited bytes on failure, so a Restart re-fires the trigger cleanly (one
# artifact, never two). The type separation IS the worker discriminator — the acquire worker drains
# ACQUIRE only, so it can never claim a client-supplied UPLOAD record.
ACQUIRE = "acquire"
INGEST = "ingest"      # parse + store the staged source → a STORAGE artifact (was LAND; renamed pkt 1142)
SUMMARIZE = "summarize"
INDEX = "index"
GIT_EXPORT = "git_export"
# REINGEST (packet 1062): re-run the canonical ingest pipeline on a stored artifact's RETAINED source
# XML and replace the record IN PLACE (same UUID/identity) with fresh derived layers. Its own worker
# (heavy: parse + mine + render), and the standard way a stored artifact picks up code improvements
# (retiring lazy self-heal). Enrichment follow-ups are re-enqueued by the handler, not baked as steps.
REINGEST = "reingest"
STEP_TYPES: tuple[str, ...] = (UPLOAD, ACQUIRE, INGEST, SUMMARIZE, INDEX, GIT_EXPORT, REINGEST)

_MAX_OUTCOME = 2000


def build(steps, *, payload=None, owner: str = "", created_at: str = "",
          uuid_job: str = "", uuid_storage: str = "", push_token_hash: str = "") -> dict:
    """A fresh QUEUE-record jor for a laundry list. ``Type`` is the first step (the cursor); the
    record is not failed. Falsy steps are dropped so callers can pass optional steps inline
    (``[LAND, summarize and SUMMARIZE, index and INDEX]``). Rejects a repeated step — the single-Type
    cursor (packet 1004) requires each step appear at most once.

    ``push_token_hash`` (packet 1015) is the sha256 of a one-time fms_push bearer token — set only
    on a pending-push ``[upload, land, …]`` record so ``/api/upload`` can resolve the waiting record
    from the token FM presents. The HASH, never the raw token, is carried (a safe indexed lookup)."""
    steps = [s for s in (steps or []) if s]
    if not steps:
        raise ValueError("a queue record needs at least one step")
    for s in steps:
        if s not in STEP_TYPES:
            raise ValueError(f"unknown step type: {s!r}")
    if len(set(steps)) != len(steps):
        raise ValueError(f"a laundry list must not repeat a step: {steps!r}")
    return {
        "Type": steps[0],
        "Steps": list(steps),
        "IsFailed": False,
        "Outcome": "",
        "Payload": dict(payload or {}),
        "UUIDJob": uuid_job or "",
        "UUIDStorage": uuid_storage or "",
        "PushTokenHash": push_token_hash or "",
        "owner": owner or "unknown",
        "created_at": created_at or "",
    }


def _cursor(jor: dict) -> "tuple[list, int]":
    """(steps, index-of-Type). Fails loud if ``Type`` isn't in ``Steps`` — a corrupt/hand-built
    record must break here, not silently mis-walk. This is the whole cost of the single-Type cursor."""
    steps = list(jor.get("Steps") or [])
    cur = jor.get("Type", "")
    try:
        return steps, steps.index(cur)
    except ValueError:
        raise ValueError(f"queue record cursor Type {cur!r} not in Steps {steps!r}")


def current_step(jor: dict) -> str:
    """The step the record sits on now (== its ``Type``)."""
    return jor.get("Type", "")


def remaining_steps(jor: dict) -> list:
    """The steps from the cursor onward (inclusive) — the work still to do."""
    steps, idx = _cursor(jor)
    return steps[idx:]


def is_failed(jor: dict) -> bool:
    """True when the record has a populated outcome (awaiting a human). Reads either the indexed
    ``IsFailed`` flag or a non-empty ``Outcome`` — they move together, but tolerate a jor that only
    carries one."""
    return bool(jor.get("IsFailed")) or bool(jor.get("Outcome"))


def is_last_step(jor: dict) -> bool:
    """True when the cursor is on the final step — a success here means delete, not advance."""
    steps, idx = _cursor(jor)
    return idx >= len(steps) - 1


def advanced(jor: dict) -> "dict | None":
    """The record AFTER the current step succeeds: the cursor (``Type``) moves to the next step and
    any failure marker is cleared. Returns ``None`` when the list is exhausted — the caller deletes
    the row (deletion is the only success). Pure — returns a new dict, never mutates the input."""
    steps, idx = _cursor(jor)
    nxt_idx = idx + 1
    if nxt_idx >= len(steps):
        return None
    nxt = dict(jor)
    nxt["Type"] = steps[nxt_idx]
    nxt["IsFailed"] = False
    nxt["Outcome"] = ""
    return nxt


def failed(jor: dict, outcome: str) -> dict:
    """The record AFTER the current step fails: ``Outcome`` populated + ``IsFailed`` set, cursor
    unchanged (it rests here until a human acts). Pure."""
    nxt = dict(jor)
    nxt["Outcome"] = (outcome or "failed")[:_MAX_OUTCOME] or "failed"
    nxt["IsFailed"] = True
    return nxt


def restarted(jor: dict) -> dict:
    """Human **Restart**: clear the failure so the worker re-runs the CURRENT step. Cursor
    unchanged. Pure."""
    nxt = dict(jor)
    nxt["Outcome"] = ""
    nxt["IsFailed"] = False
    return nxt
