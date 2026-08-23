"""Activity-record contract — packet 1136 **Stage 0** (definition only).

The reactive-feedback overhaul (docs/reactive-feedback-design.md) makes the client an OBSERVER of one
aggregated *activity conversation*. Before any wiring, this module writes down the explicit contract every
source normalizes to and that Stages 1–5 bind against. **Nothing imports this yet** — it changes no
behavior; it is the shape Stage 1 will make `workspace_view` (+ the ephemeral in-memory task registries)
emit, and that Stages 2–4 (the client store, busy-mode cadence, self-resolving spinners) consume.

Why it must exist first (the core ambiguity this overhaul removes): without a stated contract, "the item
disappeared from the list" cannot distinguish **completion** vs **restart-loss** vs **observation-failure**.
The contract resolves that with an explicit `evicted` terminal status and a terminal-retention window, so a
terminal state is always *reported*, never merely *absent*.

Changing anything here later is a CONTRACT change (it ripples through Stages 1–5), not a tweak.

─────────────────────────────────────────────────────────────────────────────────────────────────────────
Reconfirmed against HEAD (the sources this unifies):
  • Durable QUEUE — `queue_handlers.workspace_view()` rows today:
      {id, kinds, target, steps, current, status∈{queued,running,failed}, cancelable, uuid, owner, error,
       created_at}. A record LEAVES the list on completion (no `done`, no retention, no `updated_at`, no
       progress token). Cancel = POST /api/queue/{id}/cancel.
  • Ephemeral in-memory tasks — `/api/generate/status/{id}` (Explorer/Diff/patch preflight+confirm, manual
      job-run): status∈{pending,done,error} and **404 `not_found`** once a server restart evicts the task.
  • `/api/jobs/running` — a scheduler marker set that DUPLICATES the durable JobRun row (Stage 1 folds it in).

Source → contract mapping (Stage 1 IMPLEMENTED; corrected 2026-07-19 to the shipped truth):
  durable  running→running · queued→queued · failed→failed (PARKED — retained until Restart/Delete, the
           only durable retention there is). completed / cancelled → the record simply DISAPPEARS from
           the feed. There is NO server-side done/retention for durable rows — the durable source DELETES
           the record. A client reconciles a durable disappearance into a NEUTRAL terminal observation
           ("finished/removed" — NEVER a synthesized success; a JobRun's real ok/error lives durably in
           HISTORY), and ONLY after a SUCCESSFUL durable observation (a failed poll is not a
           disappearance — pin #1). See ``activity_feed.durable_absence_is_terminal``.
  ephemeral pending→queued · done→done · error→failed. A terminal ephemeral record is REPORTED for
           ``TERMINAL_RETENTION_SECONDS`` (ephemeral-only, in-memory). A process GENERATION change turns
           an absent ephemeral task into ``evicted``. Absence under the SAME generation is
           UNKNOWN/EXPIRED — the client may never have observed the terminal record before it aged out
           — and is NEVER inferred as success (``not_found`` / a poll gap ≥ retention ⇒ unknown, not
           done). See ``activity_feed.classify_ephemeral_absence``.
─────────────────────────────────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from datetime import datetime, timezone

# ── Status vocabulary — the CLOSED set every source maps into ────────────────────────────────────────────
ACTIVE_STATUSES: frozenset = frozenset({"queued", "running"})          # in-flight — the busy-mode driver
TERMINAL_STATUSES: frozenset = frozenset({"done", "failed", "cancelled", "evicted"})
ACTIVITY_STATUSES: frozenset = ACTIVE_STATUSES | TERMINAL_STATUSES
# `evicted` = an ephemeral in-memory task lost to a server restart — reported EXPLICITLY so "gone from the
# list" is never the only signal (completion vs restart-loss vs observation-failure disambiguation).

# ── Kinds — the closed set of what an activity record can be about ───────────────────────────────────────
ACTIVITY_KINDS: frozenset = frozenset({
    "import", "enrichment-index", "enrichment-summarize", "deindex", "reingest", "deliverable",
    "job-run", "generate", "preview", "patch-task",
})

# ── Terminal-state retention (EPHEMERAL-ONLY) ────────────────────────────────────────────────────────────
# A terminal EPHEMERAL record (done/failed) stays REPORTED this long after finishing, so a client that
# polls just after completion still SEES the terminal state instead of a silent disappearance. This is an
# in-memory, ephemeral-only window: DURABLE rows have NO server-side retention (the durable source deletes a
# completed/cancelled record — its outcome lives in the catalog/HISTORY). Tunable (memo: cadence numbers are
# not blocking). It must sit COMFORTABLY ABOVE the client's HIDDEN cadence (kit.js CFM_CADENCE.HIDDEN =
# 60000ms): a backgrounded tab's timers are throttled well past 60s, so a retention EQUAL to HIDDEN let a
# render that finished while hidden age out before the returning poll observed it → a completed render was
# silently downgraded to UNKNOWN/EXPIRED (packet 1000 Phase 2). 180s gives a returning user margin. A client
# whose poll gap EXCEEDS this window can still miss the terminal record — that is UNKNOWN/EXPIRED, never success.
TERMINAL_RETENTION_SECONDS: int = 180

# ── Record schema — the fields every activity record MUST carry ──────────────────────────────────────────
# A source MAY add its own extras (durable rows keep steps/current/uuid/owner); the contract is the common
# denominator the client store and spinners rely on. `kinds` is a list (a durable row can be import+enrich).
REQUIRED_FIELDS: tuple = (
    "id",            # stable identifier, survives across polls
    "kinds",         # list[str], each ∈ ACTIVITY_KINDS, len ≥ 1
    "status",        # ∈ ACTIVITY_STATUSES
    "progress",      # int monotonic revision token — increments IFF the item made progress; drives the
                     # progress-SILENCE timeout (pin #1: only a SUCCESSFUL poll with an unchanged token ages
                     # an item toward the soft-timeout — a 502/503/offline interval never does).
    "created_at",    # UTC ISO-8601, server-stamped, always REAL (enqueue/creation time)
    "updated_at",    # UTC ISO-8601 last-progress time WHERE THE SOURCE TRACKS IT (ephemeral tasks do —
                     # stamped on a real transition). None when the source does not persist a per-progress
                     # timestamp (durable QUEUE rows): clients then measure progress-SILENCE from when THEY
                     # first observe a changed `progress` token. NEVER fabricated to equal created_at.
    "cancelable",    # bool — whether this item can be cancelled right now
    "cancel_route",  # str | None — POST route to cancel (e.g. "/api/queue/{id}/cancel"); None ⇔ not cancelable
    "target",        # str human label of what the work is about ("" allowed)
    "error",         # str terminal error text ("" unless status == "failed")
    "ephemeral",     # bool — in-memory task (evicted on restart → `evicted`) vs durable QUEUE record
)


def utcnow_iso() -> str:
    """Server-stamped UTC timestamp for created_at/updated_at (per the CLAUDE.md UTC rule — the tz-aware
    form below, never a naive no-arg call)."""
    return datetime.now(timezone.utc).isoformat()


def is_terminal(status: str) -> bool:
    return status in TERMINAL_STATUSES


def validate_record(rec: dict) -> list:
    """Return a list of contract violations for one activity record (empty ⇒ conforms). A pure checker
    Stage 1 can assert its emitted rows against; wires nothing."""
    errs: list = []
    for f in REQUIRED_FIELDS:
        if f not in rec:
            errs.append(f"missing field: {f}")
    if "status" in rec and rec["status"] not in ACTIVITY_STATUSES:
        errs.append(f"status not in vocabulary: {rec['status']!r}")
    if "kinds" in rec:
        kinds = rec["kinds"]
        if not isinstance(kinds, (list, tuple)) or not kinds:
            errs.append("kinds must be a non-empty list")
        else:
            bad = [k for k in kinds if k not in ACTIVITY_KINDS]
            if bad:
                errs.append(f"kinds not in vocabulary: {bad}")
    if "created_at" in rec and not (isinstance(rec["created_at"], str) and rec["created_at"]):
        errs.append("created_at must be a non-empty UTC ISO string")
    if "updated_at" in rec:
        ua = rec["updated_at"]      # None (source tracks no per-progress ts) OR a real UTC ISO string —
        if ua is not None and not (isinstance(ua, str) and ua):   # never fabricated to equal created_at
            errs.append("updated_at must be None or a non-empty UTC ISO string")
    if rec.get("cancelable") and not rec.get("cancel_route"):
        errs.append("cancelable record must carry a cancel_route")
    if not rec.get("cancelable") and rec.get("cancel_route"):
        errs.append("non-cancelable record must not carry a cancel_route")
    return errs
