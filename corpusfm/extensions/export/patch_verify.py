"""Targeted post-apply verification — did the patch do exactly what it intended?

This is the "verify" end of the predict → apply → verify loop. The simulated apply
(patch_simulate.py) PREDICTS the resulting schema; after the patch is applied — to a
sandbox copy, leaving production untouched — this CONFIRMS it, by comparing the
patch's intended changes against what actually changed between the before and after
artifacts.

It is "targeted" in that it judges the diff against the patch's *intent* rather than
re-reviewing the whole schema: every AddAction/DeleteAction/ReplaceAction is checked
to have landed, and any change that was NOT in the patch is surfaced as collateral.

  • confirmed  — an intended change that landed (add present, delete gone, replace changed).
  • missing    — an intended change that did NOT land → an apply failure (error).
  • unexpected — a real before→after change the patch did not ask for → collateral (warning;
                 often benign, e.g. an incidental re-render, but worth a human glance).

Public API:
    verify_applied_patch(patch_xml, before_artifact, after_artifact) -> VerifyReport

Pure-local: operates on two already-ingested artifacts via the comparator. No FileMaker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from corpusfm.extensions.export.patch_coherence import (
    _OBJ_TAG_SECTION,
    _PAYLOAD_CATALOGS,
    _parse,
)

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact

_ACTION_TO_KIND = {"Add": "added", "Delete": "removed", "Replace": "changed"}


@dataclass
class VerifyFinding:
    status: str       # "confirmed" | "missing" | "unexpected"
    action: str       # "Add" | "Delete" | "Replace" | "" (unexpected has no intended action)
    section: str
    name: str
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status, "action": self.action,
            "section": self.section, "name": self.name, "message": self.message,
        }


@dataclass
class VerifyReport:
    confirmed: list = field(default_factory=list)   # list[VerifyFinding]
    missing: list = field(default_factory=list)     # list[VerifyFinding] — apply failures
    unexpected: list = field(default_factory=list)  # list[VerifyFinding] — collateral

    @property
    def applied_cleanly(self) -> bool:
        """Every intended change landed (collateral does not fail the verdict)."""
        return not self.missing

    @property
    def exact(self) -> bool:
        """Intended changes landed AND nothing else changed."""
        return not self.missing and not self.unexpected

    def to_dict(self) -> dict:
        return {
            "applied_cleanly": self.applied_cleanly,
            "exact": self.exact,
            "intended_count": len(self.confirmed) + len(self.missing),
            "confirmed_count": len(self.confirmed),
            "missing_count": len(self.missing),
            "unexpected_count": len(self.unexpected),
            "confirmed": [f.to_dict() for f in self.confirmed],
            "missing": [f.to_dict() for f in self.missing],
            "unexpected": [f.to_dict() for f in self.unexpected],
        }


def _intended_changes(structure, before: "Artifact") -> list:
    """Extract (action, section, name) the patch intends, from its action elements.

    Delete/Replace target by UUID → resolve the name+section via the before artifact.
    Field names are normalised to ``Table::Field`` to match the comparator's field diff.
    """
    uuid_to_item = {it.fm_uuid: it for it in before.items.values() if it.fm_uuid}
    out: list = []
    for action in structure:
        if action.tag == "AddAction":
            for catalog in list(action):
                if catalog.tag in _PAYLOAD_CATALOGS:
                    continue
                if catalog.tag == "FieldsForTables":
                    for fc in catalog.iter("FieldCatalog"):
                        bt = fc.find("BaseTableReference")
                        table = bt.get("name") if bt is not None else ""
                        for fld in fc.iter("Field"):
                            if fld.get("name"):
                                out.append(("Add", "FieldsForTables", f"{table}::{fld.get('name')}"))
                    continue
                for obj in catalog.iter():
                    sec = _OBJ_TAG_SECTION.get(obj.tag)
                    if sec and obj.get("name") and obj.get("name") != "--":
                        out.append(("Add", sec, obj.get("name")))
        elif action.tag == "DeleteAction":
            ir = action.find("ItemReference")
            uid = ir.get("UUID") if ir is not None else None
            it = uuid_to_item.get(uid) if uid else None
            if it is not None:
                out.append(("Delete", it.section, it.name))
        elif action.tag == "ReplaceAction":
            rep = action.find("Replace")
            uid = rep.get("UUID") if rep is not None else None
            it = uuid_to_item.get(uid) if uid else None
            if it is not None:
                out.append(("Replace", it.section, it.name))
    return out


def _actual_changes(before: "Artifact", after: "Artifact") -> dict:
    """Map (section, kind) -> set(names) of what actually changed, kind in
    {added, removed, changed}. Field names are normalised to Table::Field."""
    from corpusfm.core.comparator import compare_artifacts

    cr = compare_artifacts(before, after)
    actual: dict = {}
    for section, sr in cr.sections.items():
        for kind in ("added", "removed", "changed"):
            names = getattr(sr, kind)
            if names:
                actual.setdefault((section, kind), set()).update(names)
    for table, sr in cr.fields.items():
        for kind in ("added", "removed", "changed"):
            for fname in getattr(sr, kind):
                actual.setdefault(("FieldsForTables", kind), set()).add(f"{table}::{fname}")
    return actual


def verify_applied_patch(
    patch_xml: str, before_artifact: "Artifact", after_artifact: "Artifact"
) -> VerifyReport:
    """Confirm a patch's intended changes landed in the after artifact, and flag
    any change the patch did not ask for."""
    report = VerifyReport()
    root = _parse(patch_xml)
    structure = None
    if root is not None:
        structure = root.find("Structure")
        if structure is None and root.tag == "Structure":
            structure = root
    if structure is None:
        report.missing.append(VerifyFinding(
            "missing", "", "", "", "Patch could not be parsed; nothing verified."))
        return report

    intended = _intended_changes(structure, before_artifact)
    actual = _actual_changes(before_artifact, after_artifact)

    consumed: set = set()  # (section, kind, name) of actual changes matched to intent
    for action, section, name in intended:
        kind = _ACTION_TO_KIND[action]
        names = actual.get((section, kind), set())
        if name in names:
            report.confirmed.append(VerifyFinding("confirmed", action, section, name))
            consumed.add((section, kind, name))
        else:
            verb = {"Add": "was not added", "Delete": "was not removed",
                    "Replace": "did not change"}[action]
            report.missing.append(VerifyFinding(
                "missing", action, section, name,
                f"{action}Action target '{name}' {verb} after apply."))

    # Collateral: any actual change not accounted for by an intended action.
    for (section, kind), names in actual.items():
        for name in names:
            if (section, kind, name) not in consumed:
                report.unexpected.append(VerifyFinding(
                    "unexpected", "", section, name,
                    f"'{name}' was {kind} but the patch did not request it."))

    return report
