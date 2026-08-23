"""Script paste-acceptance batches — the pure, storage-free core (packet 1121).

A developer asks CORPUSfm to generate a batch of isolated script clips, pastes them into ONE disposable
FileMaker file, exports that file as SaveAsXML, and uploads it back. CORPUSfm correlates the returned scripts
to the originating cases and records a CONSERVATIVE acceptance OBSERVATION per case. The only thing the human
does is the FileMaker paste + export that cannot be automated.

This module holds only the logic that has no storage or MCP dependency: the state vocabulary, the acceptance-
case record shape + validation, the FileMaker-safe naming, and the (step id, emitter-relevant shape signature)
sequence derivation + comparison. The MCP tools (create/evaluate) and the JOR persistence live elsewhere.

What an acceptance observation is NOT:
  - `returned_shape_match` proves the named script survived paste AND its per-step DDR SHAPE matches — NOT
    behavioral equivalence, formula-result correctness, or complete content fidelity.
  - `not_found_in_return` is NOT proof of paste rejection — only an explicit user report is (`paste_rejected`).
  - a successful round trip is developer evidence, NOT a committed matched (DDR, clip) pair; it never promotes
    an emitter fence.

Signatures are the emitter FENCE tokens (`clip_emit._step_signature`), which are deliberately content-free
(field/TO names, formulas, paths are CONTENT and never enter a token — see docs/clip-emit-coverage.md), so
storing/echoing them carries no private data.
"""
from __future__ import annotations

import hashlib
import re

from corpusfm.core import safe_xml as ET
from corpusfm.core.clip_emit import _step_signature

# Record format — bump when the comparison rules change, so an old case is never silently reinterpreted.
ACCEPTANCE_FORMAT = 1

# The acceptance-state vocabulary (an OBSERVATION axis, separate from emitter result state + format gaps).
AWAITING_PASTE = "awaiting_paste"           # generated + stored; no FileMaker result supplied yet
PASTE_REJECTED = "paste_rejected"           # user explicitly reports FileMaker rejected this case
RETURNED_SHAPE_MATCH = "returned_shape_match"     # named script found + ordered step shapes match
RETURNED_SHAPE_CHANGED = "returned_shape_changed"  # named script found but the shape sequence differs
NOT_FOUND_IN_RETURN = "not_found_in_return"       # returned artifact evaluated, exact case name absent
EVALUATION_INCOMPLETE = "evaluation_incomplete"   # comparator could not read/trust the returned schema

ACCEPTANCE_STATES = frozenset({AWAITING_PASTE, PASTE_REJECTED, RETURNED_SHAPE_MATCH,
                               RETURNED_SHAPE_CHANGED, NOT_FOUND_IN_RETURN, EVALUATION_INCOMPLETE})

# The computed card/facet system tag per state (packet 1121 §D1) — never persisted as a user tag.
SYSTEM_TAG = {
    AWAITING_PASTE: "acceptance:awaiting-paste",
    PASTE_REJECTED: "acceptance:paste-rejected",
    RETURNED_SHAPE_MATCH: "acceptance:shape-match",
    RETURNED_SHAPE_CHANGED: "acceptance:shape-changed",
    NOT_FOUND_IN_RETURN: "acceptance:not-found",
    EVALUATION_INCOMPLETE: "acceptance:evaluation-incomplete",
}

# The generation result states an emitter case may carry (mirrors clip_emit result_state).
GENERATION_STATES = frozenset({"generated_verified", "generated_static_valid", "generated_experimental"})

_MAX_DIFF = 40                               # a bounded structural diff — never the whole script
_MAX_NOTE = 240
_LABEL_RE = re.compile(r"^[A-Za-z0-9 _\-]{1,60}$")   # a short, safe, non-private batch label
_NAME_PREFIX = "CFM_ACCEPT_"


class AcceptanceError(ValueError):
    """A caller-facing acceptance problem (bad label, malformed case metadata, unreadable return)."""


# ── naming ──────────────────────────────────────────────────────────────────────

def valid_label(label: str) -> bool:
    """A batch label must be short, FileMaker/UI-safe, and carry no private content (it is echoed)."""
    return isinstance(label, str) and bool(_LABEL_RE.match(label))


def batch_token(source_uuid: str, label: str, case_names: "list[str]") -> str:
    """A deterministic, FileMaker-safe batch token (hex) derived from the source + label + the exact ordered
    source script names. Deterministic so the same request reproduces it; the caller still checks catalog
    uniqueness (a collision means the same batch already exists)."""
    h = hashlib.sha256(("\x00".join([source_uuid or "", label or "", *case_names])).encode("utf-8"))
    return h.hexdigest()[:10]


def case_script_name(token: str, ordinal: int) -> str:
    """The deterministic, FileMaker-safe generated script name for a case: `CFM_ACCEPT_<token>_<NNN>`."""
    return f"{_NAME_PREFIX}{token}_{ordinal:03d}"


def is_case_name(name: str) -> bool:
    return isinstance(name, str) and name.startswith(_NAME_PREFIX)


# ── step-shape sequences ─────────────────────────────────────────────────────────

def step_shapes(steps_source_xml) -> "list[list]":
    """The ordered per-step (id, signature-token-list) sequence of a script's `StepsForScripts` blob — the
    emitter-relevant SHAPE, in FileMaker execution order. Tokens are content-free fence tokens. Raises on
    unreadable XML (the caller maps that to `evaluation_incomplete`)."""
    xml = steps_source_xml.decode("utf-8", "replace") if isinstance(steps_source_xml, bytes) else steps_source_xml
    root = ET.fromstring(_strip_decl(xml))
    out = []
    for st in root.iter("Step"):
        out.append([st.get("id"), [str(t) for t in _step_signature(st)]])
    return out


def _strip_decl(xml: str) -> str:
    x = xml.lstrip()
    if x.startswith("<?xml"):
        x = x[x.find("?>") + 2:].lstrip()
    return x


def compare_shapes(expected: "list[list]", returned: "list[list]") -> "tuple[str, list]":
    """Compare a stored EXPECTED (id, tokens) sequence to a returned one. Returns (state, bounded_diff).

    Exact ordered agreement on both id and tokens at every position → `returned_shape_match` (empty diff).
    Any length/id/token difference → `returned_shape_changed` with a bounded per-position diff carrying ONLY
    positions, step ids, and signature tokens (never content). A found-but-changed script is NEVER normalized
    to success."""
    diff = []
    n = max(len(expected), len(returned))
    for i in range(n):
        e = expected[i] if i < len(expected) else None
        r = returned[i] if i < len(returned) else None
        if e == r:
            continue
        entry = {"pos": i,
                 "expected_id": (e[0] if e else None),
                 "returned_id": (r[0] if r else None)}
        e_tok = e[1] if e else None
        r_tok = r[1] if r else None
        if e_tok != r_tok:
            entry["expected_shape"] = e_tok
            entry["returned_shape"] = r_tok
        diff.append(entry)
        if len(diff) >= _MAX_DIFF:
            diff.append({"truncated": True})
            break
    return (RETURNED_SHAPE_MATCH, []) if not diff else (RETURNED_SHAPE_CHANGED, diff)


# ── the acceptance-case record ───────────────────────────────────────────────────

def new_case(*, batch_id: str, batch_label: str, case_id: int, case_name: str,
             source_artifact_uuid: str, source_script_item_id: str, source_script_name: str,
             generation_state: str, expected_shapes: "list[list]", step_count: int) -> dict:
    """Build the versioned acceptance-case record attached to one generated fmClip. All fields are
    content-free (names are the GENERATED case name + the source SCRIPT name — a schema identifier the user
    already sees, not formula/field/path content)."""
    if generation_state not in GENERATION_STATES:
        raise AcceptanceError(f"generation_state {generation_state!r} not in {sorted(GENERATION_STATES)}")
    return {
        "format": ACCEPTANCE_FORMAT,
        "batch_id": batch_id,
        "batch_label": batch_label,
        "case_id": case_id,
        "case_name": case_name,
        "source_artifact_uuid": source_artifact_uuid,
        "source_script_item_id": source_script_item_id,
        "source_script_name": source_script_name,
        "generation_state": generation_state,
        "expected_shapes": expected_shapes,
        "step_count": step_count,
        "acceptance_state": AWAITING_PASTE,
        "returned_artifact_uuid": None,
        "diff": [],
        "note": "",
        "history": [],
    }


def bounded_note(text: str) -> str:
    """Clamp a free note to a safe length; callers must pass only non-private text."""
    t = (text or "").strip()
    return t[:_MAX_NOTE]


def apply_observation(case: dict, *, state: str, returned_artifact_uuid: "str | None",
                      diff: "list | None" = None, note: str = "") -> dict:
    """Return a NEW case dict carrying an acceptance observation, keeping a bounded prior-observation history
    (never a silent rewrite). Does not touch the immutable generation fields (expected_shapes/lineage)."""
    if state not in ACCEPTANCE_STATES:
        raise AcceptanceError(f"acceptance_state {state!r} not in {sorted(ACCEPTANCE_STATES)}")
    prior = case.get("acceptance_state")
    updated = dict(case)
    if prior and prior != AWAITING_PASTE:
        hist = list(case.get("history") or [])
        hist.append({"was": prior, "returned": case.get("returned_artifact_uuid")})
        updated["history"] = hist[-10:]
    updated["acceptance_state"] = state
    updated["returned_artifact_uuid"] = returned_artifact_uuid
    updated["diff"] = (diff or [])[:_MAX_DIFF + 1]
    updated["note"] = bounded_note(note)
    return updated
