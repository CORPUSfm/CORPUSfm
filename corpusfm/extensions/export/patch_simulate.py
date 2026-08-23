"""Simulated apply — a schema-graph dry-run of an FMUpgradeToolPatch.

The coherence checker (patch_coherence.py) validates references *inside* a patch
against the base artifact. A simulated apply goes one step further: it models the
schema state the patch would PRODUCE and asks "would the result be a consistent,
hostable file?" — the cheap proxy that stands in for a real FMUpgradeTool
close→patch→swap→reopen cycle.

The capability this adds over the coherence checker:

  • DELETE-IMPACT (the headline) — when a patch deletes an object, does the
    EXISTING, unchanged schema still reference it?  The coherence checker can't
    see this (it only reads references the patch itself carries), and
    FMUpgradeTool's --validatePatch misses it entirely (it is structural-only,
    and the dangling-cross-reference probe proved the tool silently drops broken
    refs at apply).  We answer it directly from the artifact's xref graph — the
    project's real dependency engine: for each deleted object, every xref edge
    pointing AT it from an object that survives the patch is a newly-orphaned
    reference.

  • HOSTABILITY — resulting-state violations that make FM refuse to host, e.g. a
    field Replace that changes the field's type (ledger:
    field-replace-sametype-ok-typechange-unhostable).

  • RESULTING SHAPE — per-section object counts after apply, and the signed delta.

Public API:
    simulate_apply(patch_xml: str, base_artifact: Artifact) -> SimulationReport

Pure schema-graph work: no FileMaker, no FMUpgradeTool.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from corpusfm.extensions.export.patch_coherence import (
    _OBJ_TAG_SECTION,
    _PAYLOAD_CATALOGS,
    _parse,
    check_patch_coherence,
)

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact


# Finding kinds that mean FM would refuse to HOST the resulting file (vs. merely
# host it with broken logic — dangling refs host, per the ledger probe).
_UNHOSTABLE_KINDS = {"field_type_change_unhostable"}


@dataclass
class SimFinding:
    severity: str       # "error" | "warning"
    kind: str           # delete_orphans_reference | field_type_change_unhostable | ...
    message: str
    object: str = ""    # the patch object the finding is about
    via: str = ""       # the dependent / referrer, when relevant
    ledger_id: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "message": self.message,
            "object": self.object,
            "via": self.via,
            "ledger_id": self.ledger_id,
        }


@dataclass
class SimulationReport:
    coherence: dict = field(default_factory=dict)        # CoherenceReport.to_dict()
    findings: list = field(default_factory=list)         # list[SimFinding] — post-apply
    resulting_counts: dict = field(default_factory=dict) # section -> count after apply
    deltas: dict = field(default_factory=dict)           # section -> signed delta (non-zero only)

    @property
    def errors(self) -> list:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def would_host(self) -> bool:
        """FM would host the resulting file (no unhostable-class violation).

        Note a file can host yet be inconsistent — dangling references host (the
        tool silently drops them). Hostability is the narrower verdict."""
        return not any(f.kind in _UNHOSTABLE_KINDS for f in self.errors)

    @property
    def is_consistent(self) -> bool:
        """The resulting schema has no broken references — neither inside the patch
        (coherence errors) nor newly orphaned by a delete (post-apply errors)."""
        return self.coherence.get("error_count", 0) == 0 and not self.errors

    def to_dict(self) -> dict:
        return {
            "is_consistent": self.is_consistent,
            "would_host": self.would_host,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "coherence": self.coherence,
            "findings": [f.to_dict() for f in self.findings],
            "resulting_counts": self.resulting_counts,
            "deltas": self.deltas,
        }


def _field_type(item) -> str:
    for k in ("fieldtype", "fieldType"):
        v = item.attributes.get(k)
        if v:
            return v
    return ""


def simulate_apply(patch_xml: str, base_artifact: "Artifact") -> SimulationReport:
    """Dry-run a patch against the base artifact's schema graph."""
    # Intra-patch layer: reuse the coherence checker verbatim.
    coherence = check_patch_coherence(patch_xml, base_artifact)
    report = SimulationReport(coherence=coherence.to_dict())

    root = _parse(patch_xml)
    if root is None:
        return report  # coherence already recorded unparseable_patch
    structure = root.find("Structure")
    if structure is None and root.tag == "Structure":
        structure = root
    if structure is None:
        return report

    uuid_to_item = {it.fm_uuid: it for it in base_artifact.items.values() if it.fm_uuid}

    deleted_items: list = []
    replaced: list = []  # list[(item, replace_elem)]
    add_counts: Counter = Counter()
    del_counts: Counter = Counter()

    for action in structure:
        if action.tag == "DeleteAction":
            ir = action.find("ItemReference")
            uid = ir.get("UUID") if ir is not None else None
            it = uuid_to_item.get(uid) if uid else None
            if it is not None:
                deleted_items.append(it)
                del_counts[it.section] += 1
        elif action.tag == "ReplaceAction":
            rep = action.find("Replace")
            uid = rep.get("UUID") if rep is not None else None
            it = uuid_to_item.get(uid) if uid else None
            if it is not None:
                replaced.append((it, rep))
        elif action.tag == "AddAction":
            for catalog in list(action):
                if catalog.tag in _PAYLOAD_CATALOGS:
                    continue
                if catalog.tag == "FieldsForTables":
                    for fld in catalog.iter("Field"):
                        if fld.get("name"):
                            add_counts["FieldsForTables"] += 1
                    continue
                for obj in catalog.iter():
                    sec = _OBJ_TAG_SECTION.get(obj.tag)
                    if sec and obj.get("name") and obj.get("name") != "--":
                        add_counts[sec] += 1

    deleted_ids = {it.item_id for it in deleted_items}
    replaced_ids = {it.item_id for it, _ in replaced}

    # 1) Delete-impact: surviving objects that still reference a deleted object.
    for d in deleted_items:
        for rec in base_artifact.xrefs_to(d.item_id):
            if rec.from_id in deleted_ids:
                continue  # the referrer is being removed too — no orphan
            if rec.from_id in replaced_ids:
                report.findings.append(SimFinding(
                    "warning", "delete_orphans_reference",
                    f"Deleting '{d.name}' would orphan '{rec.from_name}' ({rec.type}), "
                    f"which is being replaced — verify the new version drops the reference.",
                    object=d.name, via=rec.from_name,
                    ledger_id="dangling-cross-reference-silently-dropped",
                ))
            else:
                report.findings.append(SimFinding(
                    "error", "delete_orphans_reference",
                    f"Deleting '{d.name}' orphans '{rec.from_name}' ({rec.type}), which "
                    f"still references it — the reference would be silently dropped on apply.",
                    object=d.name, via=rec.from_name,
                    ledger_id="dangling-cross-reference-silently-dropped",
                ))

    # 2) Hostability: a field Replace that changes the field's type.
    for it, rep in replaced:
        if rep.get("type") == "Field":
            base_ft = _field_type(it)
            fld = rep.find(".//Field")
            new_ft = ""
            if fld is not None:
                new_ft = fld.get("fieldtype") or fld.get("fieldType") or ""
            if base_ft and new_ft and base_ft != new_ft:
                report.findings.append(SimFinding(
                    "error", "field_type_change_unhostable",
                    f"Replacing field '{it.name}' changes its type ({base_ft} → {new_ft}); "
                    f"the patched file would not host.",
                    object=it.name,
                    ledger_id="field-replace-sametype-ok-typechange-unhostable",
                ))

    # Resulting shape: base counts adjusted by adds/deletes.
    base_counts = Counter(it.section for it in base_artifact.items.values() if not it.is_folder)
    sections = set(base_counts) | set(add_counts) | set(del_counts)
    report.resulting_counts = {
        s: base_counts.get(s, 0) + add_counts.get(s, 0) - del_counts.get(s, 0)
        for s in sections
    }
    report.deltas = {
        s: add_counts.get(s, 0) - del_counts.get(s, 0)
        for s in sections
        if add_counts.get(s, 0) - del_counts.get(s, 0) != 0
    }
    return report
