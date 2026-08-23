"""Gap analyzer for INCOMING clips — the FMXML drift early-warning (packet 1079).

The clip-side mirror of the DDR `gap_analyzer`, and it exists because of a structural asymmetry rather
than a missing feature:

    DDR : <FMSaveAsXML version="2.3.0.0" Source="26.0.1" …>   ← declares its version
    clip: <fmxmlsnippet type="FMObjectList">                   ← declares NOTHING

The FM2025 and FM2026 masters have byte-identical root elements, so the DDR's two defences cannot be
ported: there is no version to fence at the door, and the DDR gap analyzer needs a full catalog (a clip
is a fragment). Clip ingestion therefore skipped analysis entirely, and a captured clip from a newer
FileMaker was stored silently.

**Why an INCOMING clip is the place drift shows up first.** The DDR is a projection we *read* — drift
arrives in the corpus and announces itself. The clip is one we *write* — drift is invisible until a paste
misbehaves. The only FMXML that ever comes *toward* us is a captured clip (`save_clip`, paste-origin
deliverables). It is a thin stream, but it is the ground-truth stream the emitter fence is built from.
This module stops us discarding its signal.

**This is the READ path, not telemetry.** `validate_clip` / `patch_clip` operate on stored clips, so a
clip carrying something we don't understand is a correctness risk the moment someone edits it.

**Read-only, and deliberately so.** It REPORTS, it never gates: an unrecognised clip is still storable
and still patchable. It does not touch `clip_emit.py`'s fence or emitters — those stay stable; the
drift detection lives here, at the boundary.

**Knowledge comes from SHIPPED data only** — `structure_catalog.yaml` (step ids) and `clip_catalog.yaml`
(`known_clip_values`, `external_skeletons`). It cannot read `tests/fixtures/`, so its element coverage is
partial BY CONSTRUCTION and says so (`elements_checked_ids`); an analyzer implying more than it checks is
the failure mode this codebase keeps rediscovering.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from corpusfm.core import safe_xml as ET
from corpusfm.ingestion.clip import _strip_xml_decl

# `<DisableStepCollapsed>` is an FM2026 clipboard addition the FM2025 clip omits entirely (packet 1068
# finding A) — the ONLY content signal that distinguishes the two, since the envelope is identical. An
# inference, never a declaration: an FM2026 clip *could* have been hand-stripped of it.
_FM2026_MARKER = "DisableStepCollapsed"
FM2026_FORM = "FM2026-form (inferred)"
FM2025_OR_EARLIER_FORM = "FM2025-or-earlier-form (inferred)"


@dataclass
class ClipGapReport:
    """What the clip analyzer did not recognise. Empty lists mean 'nothing unknown FOUND', which is only
    'clean' if `failed` is empty too (the packet-072-D rule: a crashed analyzer must never masquerade as
    an all-clear)."""
    unknown_step_ids: list = field(default_factory=list)      # id present in the clip, not in FM's catalog
    unknown_enum_values: list = field(default_factory=list)   # "id 212 <LLMType value='Perplexity'>"
    unknown_elements: list = field(default_factory=list)      # "id 243 <NewThing>"
    inferred_fm_form: str = ""
    elements_checked_ids: list = field(default_factory=list)  # the ONLY ids whose elements we can check
    # WHAT THE ANALYZER ACTUALLY LOOKED AT (added 2026-07-15). Until this existed, a FIELD or TABLE clip
    # came back perfectly "Clean" — every check iterates <Step>, and a field clip has none, so the
    # analyzer reported no gaps in a document it never examined. A silent all-clear on an unanalysed clip
    # is exactly the 072-D failure this dataclass's docstring warns about, one level up: `failed` catches
    # a crashed miner, and this catches a miner that never ran.
    kinds_seen: list = field(default_factory=list)            # Step · Field · BaseTable
    kinds_analyzed: list = field(default_factory=list)        # those we actually have checks for
    failed: list = field(default_factory=list)                # analyzer names that crashed

    @property
    def total_issues(self) -> int:
        return (len(self.unknown_step_ids) + len(self.unknown_enum_values) + len(self.unknown_elements))

    def is_clean(self) -> bool:
        """Nothing unknown AND nothing crashed AND nothing went unlooked-at. All three are required.

        The third clause is the 2026-07-15 addition: a clip whose content we have no checks for is not
        clean, it is unexamined, and reporting those the same way is how a drift detector lies."""
        return self.total_issues == 0 and not self.failed and not self.unanalyzed_kinds

    @property
    def unanalyzed_kinds(self) -> list:
        return [k for k in self.kinds_seen if k not in self.kinds_analyzed]

    def to_dict(self) -> dict:
        return {
            "unknown_step_ids": self.unknown_step_ids,
            "unknown_enum_values": self.unknown_enum_values,
            "unknown_elements": self.unknown_elements,
            "inferred_fm_form": self.inferred_fm_form,
            "elements_checked_ids": self.elements_checked_ids,
            "kinds_seen": self.kinds_seen,
            "kinds_analyzed": self.kinds_analyzed,
            "unanalyzed_kinds": self.unanalyzed_kinds,
            "analyzer_failed": self.failed,
            "total_issues": self.total_issues,
            "clean": self.is_clean(),
        }


def _known_step_ids() -> set:
    """FileMaker's own step-id catalog for our newest supported version. An id in a CLIP that isn't here
    means FILEMAKER changed — the clip is FileMaker's own output, not something a user hand-authored."""
    from corpusfm.core.schemas.registry import load_structure_catalog
    sc, _warning = load_structure_catalog("2.3.0.0")
    return {int(i) for i in sc.step_ids()}


def _known_clip_values(catalog) -> dict:
    """id -> {element tag -> observed clip values}, from the catalog's `known_clip_values`.

    NOT `enum_tables` inverted, though that was this packet's original design and it was wrong. The enum
    tables hold only the REMAPPED values (OpenAI→ChatGPT, Custom→Other); passthrough providers
    (Anthropic/Cohere/Google) never appear there because their DDR name IS their clip value. Inverting
    the table therefore flagged an ordinary Anthropic clip as drift — and a drift alarm that cries wolf
    on normal clips is worse than no alarm. Found by driving the analyzer, not by reasoning about it."""
    return catalog.known_clip_values or {}


def _enum_bearing_children(step) -> list:
    """(tag, value) for children carrying a @value — the shape every cataloged clip enum takes
    (<LLMType value=…/>, <SaveType…>, <Action value=…/>). Attribute-only; text-node enums are not
    checked, and that limit is disclosed rather than papered over."""
    return [(c.tag, c.get("value")) for c in step if c.get("value") is not None]


def _analyze_fields(fields, report) -> None:
    """The FIELD/TABLE half (XMFD + XMTB), added 2026-07-15.

    Field-definition clips reach us the same way step clips do — `save_clip`, paste-origin deliverables —
    and until now the analyzer walked straight past them and reported Clean.

    The honesty limit is DIFFERENT here and is stated rather than glossed: FileMaker publishes no catalog
    of field vocabulary (the step-id check has `structure_catalog`, which is why it alone may claim
    "FileMaker changed"). Here everything is "no evidence" — our observed set is partial by construction,
    e.g. 2 of FM's 13 summary operations. An unknown value may be drift OR merely unsampled, and a clip
    cannot tell the two apart.

    Knowledge comes from field_emit's LIVE vocabulary, derived from the fence — never a hand-kept mirror,
    which would drift from the emitter and make the drift detector itself a source of drift."""
    from corpusfm.core.field_emit import (CLIP_AUTOENTER_MODES, CLIP_DATATYPES, CLIP_FIELD_ELEMENTS,
                                          CLIP_SUMMARY_OPERATIONS)

    def note(bucket, entry):
        if entry not in bucket:
            bucket.append(entry)

    for f in fields:
        nm = f.get("name") or "?"
        dt = f.get("dataType")
        if dt and dt not in CLIP_DATATYPES:
            note(report.unknown_enum_values,
                 f"field '{nm}' dataType=\"{dt}\" — no evidence for this value; "
                 f"observed: {sorted(CLIP_DATATYPES)}")

        ae = f.find("AutoEnter")
        mode = ae.get("value") if ae is not None else None
        if mode and mode not in CLIP_AUTOENTER_MODES:
            note(report.unknown_enum_values,
                 f"field '{nm}' <AutoEnter value=\"{mode}\"> — no evidence for this auto-enter mode; "
                 f"observed: {sorted(CLIP_AUTOENTER_MODES)}")

        si = f.find("SummaryInfo")
        op = si.get("operation") if si is not None else None
        if op and op not in CLIP_SUMMARY_OPERATIONS:
            # Expected to fire often and that is CORRECT: FM has 13 summary operations and two are
            # captured. It reads as "we have never seen this", which is the truth, not as an alarm.
            note(report.unknown_enum_values,
                 f"field '{nm}' <SummaryInfo operation=\"{op}\"> — no evidence for this operation; "
                 f"observed: {sorted(CLIP_SUMMARY_OPERATIONS)} (FileMaker has 13)")

        for el in f.iter():
            if el is f:
                continue
            if el.tag not in CLIP_FIELD_ELEMENTS:
                note(report.unknown_elements, f"field '{nm}' <{el.tag}>")


def analyze_clip(clip_xml, catalog=None) -> ClipGapReport:
    """Scan an incoming clip for what we do not recognise.

    Four checks, each backed by shipped data, and each stating exactly how far it can see:
      1. unknown step ids     — vs the structure catalog. FULL coverage, and the only check where
                                "FileMaker changed" is a fair claim (the catalog holds every step type
                                FM 2026 has, and a clip is FM's own output). The primary drift signal.
      2. unknown enum values  — vs `known_clip_values` (values OBSERVED in our committed clips). NOT
                                enum_tables inverted — see _known_clip_values. Reported as "no evidence",
                                since an unseen value may be drift OR merely unsampled.
      3. unknown elements     — vs external_skeletons. PARTIAL by construction (only the cataloged ids);
                                `elements_checked_ids` discloses which, so silence can't read as
                                "all clear on all 217".
      4. inferred FM form     — from <DisableStepCollapsed> presence. A heuristic, labelled inferred.
    """
    from corpusfm.core import clip_catalog as cc
    report = ClipGapReport()
    catalog = catalog or cc.load_catalog()

    try:
        xml = clip_xml.decode("utf-8", "replace") if isinstance(clip_xml, bytes) else clip_xml
        root = ET.fromstring(_strip_xml_decl(xml))
        steps = list(root.iter("Step"))
        # A field clip's <Field>s are top-level (XMFD) or inside a <BaseTable> (XMTB); a SUMMARY field's
        # <SummaryField> also contains a bare <Field> reference, which is a pointer, not a definition —
        # scope to the two real homes so those don't get analysed as field defs.
        tables = root.findall("BaseTable")
        fields = root.findall("Field") + [f for bt in tables for f in bt.findall("Field")]
    except Exception:
        report.failed.append("clip_gap_analyze")     # 072-D: crashed ≠ clean
        return report

    report.kinds_seen = [k for k, present in
                         (("Step", steps), ("Field", fields), ("BaseTable", tables)) if present]

    try:
        known_ids = _known_step_ids()
    except Exception:
        report.failed.append("clip_gap_analyze:step_ids")
        known_ids = None

    try:
        known_vals = _known_clip_values(catalog)
        skeletons = catalog.external_skeletons or {}
        report.elements_checked_ids = sorted(skeletons)
    except Exception:
        report.failed.append("clip_gap_analyze:catalog")
        known_vals, skeletons = {}, {}

    seen_marker = False
    for st in steps:
        if st.find(_FM2026_MARKER) is not None:
            seen_marker = True
        raw = st.get("id")
        if raw is None or not str(raw).isdigit():
            continue
        sid = int(raw)
        name = st.get("name") or "?"

        if known_ids is not None and sid not in known_ids:
            entry = f"id {sid} ({name})"
            if entry not in report.unknown_step_ids:
                report.unknown_step_ids.append(entry)
            continue          # an id FileMaker invented has no known enums/elements to check against

        for tag, val in _enum_bearing_children(st):
            vals = (known_vals.get(sid) or {}).get(tag)
            if vals and val not in vals:
                # Worded as "no evidence", NOT "FileMaker changed": our observed set is partial, so this
                # could equally be a shape nobody ever captured. We cannot tell them apart from a clip
                # alone and must not imply we can. Either way it is capture-worthy and would refuse.
                entry = (f"id {sid} ({name}) <{tag} value=\"{val}\"> — no evidence for this value; "
                         f"observed: {sorted(vals)}")
                if entry not in report.unknown_enum_values:
                    report.unknown_enum_values.append(entry)

        skel = skeletons.get(sid)
        if skel:
            expected = set(skel.get("elements") or []) | {_FM2026_MARKER}
            for c in st:
                if c.tag not in expected:
                    entry = f"id {sid} ({name}) <{c.tag}>"
                    if entry not in report.unknown_elements:
                        report.unknown_elements.append(entry)

    if steps:
        report.inferred_fm_form = FM2026_FORM if seen_marker else FM2025_OR_EARLIER_FORM
        report.kinds_analyzed.append("Step")

    if fields:
        try:
            _analyze_fields(fields, report)
            report.kinds_analyzed.append("Field")
            if tables:
                # The XMTB envelope carries nothing of its own beyond @name/@comment + the fields, so
                # analysing the fields IS analysing the table. Recorded explicitly so `unanalyzed_kinds`
                # doesn't flag a BaseTable we did in fact cover.
                report.kinds_analyzed.append("BaseTable")
        except Exception:
            report.failed.append("clip_gap_analyze:fields")
    return report
