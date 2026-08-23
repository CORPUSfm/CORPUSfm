"""FMXML clip catalog + variation detector — packet 1072.

Read-only triage over the DDR→clip emitter fence. It classifies each DDR script step as COVERED /
NEW_VARIATION / UNSUPPORTED / DDR_GAP and rolls the not-covered steps into a ranked "needs-capture"
backlog — so clip-emitter coverage grows on evidence, not guesswork.

Design (the packet-999 principle: a future variation is added to the CATALOG, not the code):
  * The COVERED / experimental / unaccounted decision reads the LIVE step assessment in clip_emit
    (step_generation_assessment — VERIFIED_STEP_IDS + _VERIFIED_SIGS + the migrated capability rules) — so
    the detector can NEVER drift from what the emitter actually generates.
  * The DDR-gap + enum knowledge on top comes from the declarative catalog (clip_catalog.yaml),
    grounded in our own committed (DDR, clip) pairs.

No emission, no mutation. Ground truth stays the committed pairs; this reports what we've verified and
what we've found unreproducible, never an inference.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import yaml

from corpusfm.core import safe_xml as ET
from corpusfm.core.clip_emit import VERIFIED_STEP_IDS, step_generation_assessment
from corpusfm.ingestion.clip import _strip_xml_decl

_CATALOG_PATH = Path(__file__).parent / "clip_catalog.yaml"

# classification kinds
COVERED = "covered"              # emitter reproduces this step's shape byte-exact (verified evidence)
EXPERIMENTAL = "experimental-capable"  # a migrated id in a capability-complete but UNCAPTURED shape → emits
NEW_VARIATION = "new-variation"  # a VERIFIED id in an unaccounted option shape → capability migration/capture
UNSUPPORTED = "unsupported"      # no emitter at all → a capture unblocks a new emitter
DDR_GAP = "ddr-gap"              # the clip needs data the DDR lacks → a policy decision, NOT a capture
NEEDS_CAPTURE = frozenset({NEW_VARIATION, UNSUPPORTED})
EXPORTS = frozenset({COVERED, EXPERIMENTAL})   # kinds that would export today (packet 1091)


class ClipCatalog:
    def __init__(self, data: dict):
        self.version = data.get("version")
        self.ddr_gaps = {int(k): v for k, v in (data.get("ddr_gaps") or {}).items()}
        self.notes = {int(k): v for k, v in (data.get("notes") or {}).items()}
        # packet 1077 — the declared clip target version + the ids whose clip shape differs by FM version
        vs = data.get("version_sensitivity") or {}
        self.clip_target_version = vs.get("target")
        self.version_universal = vs.get("universal") or {}
        self.version_sensitive = {int(k): v for k, v in (vs.get("steps") or {}).items()}
        # packet 1075 — third-party RE'd skeletons for ids we CANNOT emit. A capture HINT layer, never
        # ground truth and never an emit licence; carries its own attribution (CC BY 4.0).
        es = data.get("external_skeletons") or {}
        self.external_skeletons_source = es.get("source")
        self.external_skeletons_licence = es.get("licence")
        self.external_skeletons = {int(k): v for k, v in (es.get("steps") or {}).items()}
        # packet 1079 — the incoming-clip drift oracle. NOT enum_tables inverted: that holds only the
        # REMAPPED values, so passthrough ones (Anthropic/Cohere/Google) are absent and using it flagged
        # ordinary clips as drift. These are values OBSERVED in our committed clips — not exhaustive.
        self.known_clip_values = {int(k): {tag: set(v) for tag, v in (tags or {}).items()}
                                  for k, tags in (data.get("known_clip_values") or {}).items()}
        # packet 1080 §3 — the clip fixtures we already hold, per step id. Ships as data because they
        # live in tests/fixtures/, which a shipped detector cannot read; guard-locked to the committed
        # bytes by test_clip_evidence_matches_the_committed_masters.
        self.clip_evidence_fixtures = (data.get("clip_evidence") or {}).get("fixtures") or {}

    def note(self, sid: int):
        return self.notes.get(sid)

    def clip_evidence(self, sid: int) -> dict:
        """What clip evidence we hold for one step id — the answer to "is a FileMaker Pro trip worth
        taking?". Never a verdict: id-level, because the DDR halves of the masters are not committed
        (see the yaml header). `shapes` counts the DISTINCT clip steps a fixture holds for this id, so a
        reader can see at a glance that e.g. 144 has 8 configured shapes captured, not just one.

        As of 2026-07-15 EVERY canonical step type is held, so the `held: False` branch is unreachable
        for a real FM step id. It stays because it is the honest answer for an id we've never seen (a
        future FileMaker type), and because deleting the only branch that can say "yes, go capture" would
        leave a detector that structurally cannot ask for evidence."""
        held = []
        for fname, m in self.clip_evidence_fixtures.items():
            if sid not in (m.get("ids") or []):
                continue
            held.append({"fixture": fname, "scope": m.get("scope"), "flavor": m.get("flavor"),
                         "shapes": (m.get("multi_shape") or {}).get(sid, 1)})
        if not held:
            return {"held": False, "fixtures": [], "shapes": 0, "scopes": [],
                    "capture_would_unblock": True,
                    "summary": "no clip evidence — we hold NO captured clip for this step id. A real "
                               "(DDR, clip) capture genuinely unblocks it."}
        scopes = sorted({h["scope"] for h in held})
        shapes = max(h["shapes"] for h in held)
        return {
            "held": True, "fixtures": [h["fixture"] for h in held], "shapes": shapes, "scopes": scopes,
            "capture_would_unblock": False,
            "summary": (
                f"clip evidence HELD — {shapes} captured clip shape(s) for this id across "
                f"{len(held)} committed fixture(s) ({', '.join(scopes)}). The blocker is CODE, not "
                f"evidence: do NOT spend a FileMaker Pro trip re-capturing this. "
                f"Caveat: id-level. The fence is per-shape, so YOUR shape may not be among those "
                f"captured — check the fixture before concluding a capture is needed."),
        }

    def version_note(self, sid: int):
        """The version delta for one id, or None. Every clip is FM2026-form regardless (see
        `version_universal`); this is the ADDITIONAL, per-id sensitivity."""
        return self.version_sensitive.get(sid)


def load_catalog(path=None) -> ClipCatalog:
    with open(path or _CATALOG_PATH, encoding="utf-8") as f:
        return ClipCatalog(yaml.safe_load(f))


def classify_step(ddr_step, catalog: ClipCatalog = None):
    """(kind, detail) for one DDR <Step>. Reads the LIVE step assessment (packet 1091) so the detector can
    never call a shape a capture prerequisite once the emitter can generate it.

    Five kinds. A byte-captured shape is COVERED; a migrated capability-complete-but-uncaptured shape is
    EXPERIMENTAL (it EMITS today — never a needs-capture item, packet 1091 §D); a registered source-
    incomplete shape is DDR_GAP (class-2 policy, emitted by default); a refused shape is NEW_VARIATION
    when its id is otherwise verified (its grammar is not yet migrated / captured) or UNSUPPORTED when
    there is no emitter at all.

    Order matters. A DDR-gap is a POLICY decision ('no capture will ever fix this'), so it must not be
    reported as a needs-capture item — but it must also not swallow a genuine class-1 variation of the
    same id. Hence per-shape gaps come from the assessment's `source_incomplete` (LIVE, packet 1076/1089)
    rather than an id-level catalog entry: Print Setup's EMPTY page-setup shape is fully covered, its
    POPULATED shape is class-2, and an id-level gap could not express that split without lying about one of
    them. The catalog's `ddr_gaps` stays for ids with no emitter at all (242/…) — for those, id-level IS
    the truth, which is what `test_ddr_gap_ids_have_no_emitter` pins."""
    catalog = catalog or load_catalog()
    a = step_generation_assessment(ddr_step, flavor="xmsc")   # pkt 1123: detector reports whole-script XMSC
    sid, name = a.step_id, a.name
    if a.permission == "emit":
        if a.evidence == "verified":
            return COVERED, {"id": sid, "name": name}
        if a.evidence == "experimental":       # emits today — capability-complete, uncaptured (packet 1091)
            return EXPERIMENTAL, {"id": sid, "name": name, "reason": a.detail,
                                  "shape": list(a.signature), "note": catalog.note(sid)}
        entry = a.source_incomplete or {}      # per-shape class-2 — characterized, emitted by default
        detail = {"id": sid, "name": name, "reason": a.detail, "shape": list(a.signature),
                  "note": catalog.note(sid),
                  "gap": {"name": name, "gap": entry.get("why"),
                          "absent": entry.get("source_absent_for_target", []),
                          "source_held_unimplemented": entry.get("source_held_unimplemented", []),
                          "emitted_from_source": entry.get("emitted_from_source", []),
                          "decision": "resolved — emits the schema-held minimum BY DEFAULT (packet 1089), "
                                      "labelled source-incomplete; strict callers still refuse it"}}
        return DDR_GAP, detail
    if sid is None:
        return UNSUPPORTED, {"id": None, "name": name, "reason": a.detail}
    detail = {"id": sid, "name": name, "reason": a.detail,
              "shape": list(a.signature), "note": catalog.note(sid)}
    if sid in catalog.ddr_gaps:                # whole-id class-2 — no emitter at all
        detail["gap"] = catalog.ddr_gaps[sid]
        return DDR_GAP, detail
    if sid in VERIFIED_STEP_IDS:
        return NEW_VARIATION, detail          # known id, unaccounted shape (capability not yet migrated)
    return UNSUPPORTED, detail                 # no emitter yet


def _report(steps: list, catalog: ClipCatalog) -> dict:
    counts = Counter(s["kind"] for s in steps)
    groups: dict = defaultdict(lambda: {"count": 0, "example": None})
    for s in steps:
        # EXPORTS (COVERED + EXPERIMENTAL) would emit today — neither is a backlog/needs-capture item
        # (packet 1091 §D: an experimental-capable shape is NOT a capture owed).
        if s["kind"] in EXPORTS:
            continue
        g = groups[(s["id"], s["kind"])]
        g["count"] += 1
        if g["example"] is None:
            g["example"] = {"index": s["index"], "shape": s.get("shape")}
        g.update(id=s["id"], kind=s["kind"], name=s.get("name"), note=s.get("note"))
        if "gap" in s:
            g["gap"] = s["gap"]
        # packet 1080 §3: every needs-capture row carries what we ALREADY hold, so no row can send
        # someone to FileMaker Pro for bytes sitting in the repo. DDR-gaps are excluded on purpose —
        # for those, no capture helps at all, and clip evidence would only muddy that.
        if s["kind"] in NEEDS_CAPTURE and s["id"] is not None:
            g["evidence"] = catalog.clip_evidence(s["id"])
    backlog = sorted(groups.values(), key=lambda g: (-g["count"], g["id"] if g["id"] is not None else 0))
    # "covered" = would export today = byte-verified + capability-experimental (packet 1091). The `counts`
    # dict keeps the per-kind split (COVERED vs experimental-capable) so the two never blur.
    return {"total_steps": len(steps),
            "covered": counts.get(COVERED, 0) + counts.get(EXPERIMENTAL, 0),
            "verified": counts.get(COVERED, 0), "experimental": counts.get(EXPERIMENTAL, 0),
            "counts": dict(counts), "backlog": backlog,
            "capture_really_needed": sorted({g["id"] for g in backlog
                                             if g.get("evidence", {}).get("capture_would_unblock")}),
            "code_blocked": sorted({g["id"] for g in backlog
                                    if g.get("evidence", {}).get("held")})}


def detect_variations(steps_source_xml, catalog: ClipCatalog = None) -> dict:
    """Scan a DDR blob containing <Step>s (a StepsForScripts <Script>, or any XML with steps). Returns
    {total_steps, covered, counts, backlog} — backlog is the ranked needs-capture / ddr-gap groups."""
    catalog = catalog or load_catalog()
    xml = (steps_source_xml.decode("utf-8", "replace")
           if isinstance(steps_source_xml, bytes) else steps_source_xml)
    root = ET.fromstring(_strip_xml_decl(xml))
    steps = []
    for i, st in enumerate(root.iter("Step")):
        kind, detail = classify_step(st, catalog)
        steps.append({"index": i, "kind": kind, **detail})
    return _report(steps, catalog)


def scan_artifact(artifact, catalog: ClipCatalog = None) -> dict:
    """Whole-artifact scan: every ScriptCatalog item's StepsForScripts source, classified + rolled into
    one ranked backlog. The corpus-driven 'what to capture next' view."""
    catalog = catalog or load_catalog()
    steps = []
    idx = 0
    for it in getattr(artifact, "items", {}).values():
        if getattr(it, "section", None) != "ScriptCatalog" or getattr(it, "is_folder", False):
            continue
        src = next((s for s in (getattr(it, "xml_sources", None) or [])
                    if getattr(s, "catalog", None) == "StepsForScripts"), None)
        if src is None:
            continue
        xml = src.xml.decode("utf-8", "replace") if isinstance(src.xml, bytes) else src.xml
        for st in ET.fromstring(_strip_xml_decl(xml)).iter("Step"):
            kind, detail = classify_step(st, catalog)
            steps.append({"index": idx, "kind": kind, **detail})
            idx += 1
    return _report(steps, catalog)
