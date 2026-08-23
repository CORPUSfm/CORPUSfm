"""Intra-patch semantic coherence checker for FMUpgradeToolPatch XML.

A generated patch can be structurally perfect (every action well-formed, every
verdict patchable) yet *semantically incoherent*: it may reference an object that
exists in neither the base file nor the patch, set a field via a table occurrence
whose base table does not carry that field, or emit a referrer before the object it
references. FMUpgradeTool applies AddActions in document order without pre-resolving
forward references (ledger: intra-patch-ordering-required), so these break at apply
time as dangling endpoints — exactly the gap the rich CMP_Operations re-run exposed
(a new script's Set Field targeted a `Projects` TO while the new field lived on
`Clients`).

This is a static, schema-graph-only pre-flight — no FileMaker, no FMUpgradeTool. It
runs a generated patch against the base Artifact it will apply to and returns warnings
before the patch is offered or applied.

Public API:
    check_patch_coherence(patch_xml: str, base_artifact: Artifact) -> CoherenceReport

Three checks, all guarding against false positives (only a curated allowlist of
reference types that point at user catalog objects is resolved — locale/font/theme/
layout-object references are FM built-in vocabulary and are deliberately not checked):

  1. dangling_reference  — a *Reference (by name and/or UUID) to a catalog object that
                           exists in neither the base artifact nor the patch's own adds.
  2. field_not_on_to /   — a FieldReference qualified by a TableOccurrenceReference whose
     unknown_to            base table does not carry that field (or whose TO is unknown).
  3. ordering            — a reference resolves only via a patch-added object that appears
                           LATER in document order than the referrer (FM would dangle it).

Also surfaces replace_target_missing / delete_target_missing (a Replace/Delete whose
UUID is not in the base artifact — it would match nothing) and unparseable_patch.
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact


# Object element tag → section. Mirrors fmupgrade._OBJ_TYPE (kept local so the
# checker imports without pulling the generator + coverage gate).
_OBJ_TAG_SECTION: dict[str, str] = {
    "Script":             "ScriptCatalog",
    "CustomFunction":     "CustomFunctionsCatalog",
    "ValueList":          "ValueListCatalog",
    "Layout":             "LayoutCatalog",
    "BaseTable":          "BaseTableCatalog",
    "TableOccurrence":    "TableOccurrenceCatalog",
    "Relationship":       "RelationshipCatalog",
    "PrivilegeSet":       "PrivilegeSetsCatalog",
    "Account":            "AccountsCatalog",
    "Theme":              "ThemeCatalog",
    "CustomMenuSet":      "CustomMenuSetCatalog",
    "ExternalDataSource": "ExternalDataSourceCatalog",
}

# Reference element tag → section it must resolve in. Conservative allowlist:
# only references that point at named user catalog objects. FieldReference is
# handled separately (field-on-TO). Everything NOT here — LanguageReference,
# FontReference, LayoutThemeReference, LayoutObjectReference, WindowReference,
# BaseDirectoryReference, CallbackScriptReference, CustomMenuReference — is FM
# built-in / formatting vocabulary and is intentionally not resolved (the probe's
# noise came from treating those as dangling).
_CHECKED_REF_SECTION: dict[str, str] = {
    "ScriptReference":         "ScriptCatalog",
    "CustomFunctionReference": "CustomFunctionsCatalog",
    "ValueListReference":      "ValueListCatalog",
    "LayoutReference":         "LayoutCatalog",
    "BaseTableReference":      "BaseTableCatalog",
    "TableOccurrenceReference": "TableOccurrenceCatalog",
    "RelationshipReference":   "RelationshipCatalog",
    "PrivilegeSetReference":   "PrivilegeSetsCatalog",
    "CustomMenuSetReference":  "CustomMenuSetCatalog",
    "DataSourceReference":     "ExternalDataSourceCatalog",
}

# Catalogs that carry step/calc PAYLOAD for an already-added object — they never
# introduce a new referable object, only references to one.
_PAYLOAD_CATALOGS = {"StepsForScripts", "CalcsForCustomFunctions"}


# ---------------------------------------------------------------------------
# Report shapes
# ---------------------------------------------------------------------------

@dataclass
class CoherenceFinding:
    severity: str       # "error" | "warning"
    kind: str           # dangling_reference | field_not_on_to | unknown_to | ordering | ...
    message: str
    referrer: str = ""   # the patch object/action the finding is about
    reference: str = ""  # the offending reference, e.g. "Projects::ApprovedBy"
    ledger_id: str = ""  # the capability-ledger rule this enforces, when applicable

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "message": self.message,
            "referrer": self.referrer,
            "reference": self.reference,
            "ledger_id": self.ledger_id,
        }


@dataclass
class CoherenceReport:
    findings: list = field(default_factory=list)  # list[CoherenceFinding]
    checked_references: int = 0
    resolved_references: int = 0

    @property
    def errors(self) -> list:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def is_coherent(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "is_coherent": self.is_coherent,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "checked_references": self.checked_references,
            "resolved_references": self.resolved_references,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# World model — base artifact + patch-added objects, with add positions
# ---------------------------------------------------------------------------

class _World:
    """Everything that exists for resolution: base artifact objects plus the
    patch's own added objects, the latter tagged with their document-order index
    so referent-first ordering can be checked.
    """

    def __init__(self) -> None:
        # section -> {name -> add_index}  (base objects use index -1 = "already exists")
        self.names: dict[str, dict[str, int]] = {}
        self.uuids: dict[str, dict[str, int]] = {}
        # table occurrence name -> base table name (None = external / unverifiable)
        self.to_base_table: dict[str, Optional[str]] = {}
        # base table name -> {field name -> add_index}
        self.table_fields: dict[str, dict[str, int]] = {}

    def add_name(self, section: str, name: str, idx: int) -> None:
        if name:
            self.names.setdefault(section, {}).setdefault(name, idx)

    def add_uuid(self, section: str, uid: str, idx: int) -> None:
        if uid:
            self.uuids.setdefault(section, {}).setdefault(uid, idx)

    def add_field(self, table: str, fname: str, idx: int) -> None:
        if table and fname:
            self.table_fields.setdefault(table, {}).setdefault(fname, idx)

    def name_index(self, section: str, name: str) -> Optional[int]:
        return self.names.get(section, {}).get(name)

    def uuid_index(self, section: str, uid: str) -> Optional[int]:
        return self.uuids.get(section, {}).get(uid)


_BASE = -1  # add_index sentinel meaning "present in the base artifact"


def _strip_decl(xml_str: str) -> str:
    s = (xml_str or "").strip()
    if s.startswith("<?"):
        end = s.find("?>")
        if end != -1:
            s = s[end + 2:].strip()
    return s


def _parse(xml_str: str) -> Optional[ET.Element]:
    s = _strip_decl(xml_str)
    if not s:
        return None
    try:
        return ET.fromstring(s)
    except ET.ParseError:
        return None


def _to_base_table_of(to_elem: ET.Element) -> Optional[str]:
    """Resolve a TableOccurrence element to its base table name, or None when the
    occurrence is external (DataSourceReference) — field membership is unverifiable
    across files, so we do not flag it."""
    src = to_elem.find("BaseTableSourceReference")
    if src is not None:
        bt = src.find("BaseTableReference")
        if bt is not None and bt.get("name"):
            return bt.get("name")
        if src.find("DataSourceReference") is not None:
            return None
    # Some shapes nest BaseTableReference directly.
    bt = to_elem.find("BaseTableReference")
    return bt.get("name") if bt is not None else None


def _build_base_world(artifact: "Artifact") -> _World:
    w = _World()
    for it in artifact.items.values():
        section = it.section
        if section == "FieldsForTables":
            if it.is_folder:
                continue
            if "::" in it.name:
                table, fname = it.name.split("::", 1)
            elif it.folder_path:
                table, fname = it.folder_path[0], it.name
            else:
                continue
            w.add_field(table, fname, _BASE)
            continue
        # Generic object: name (+ xml_key fallback) and UUID resolve in this section.
        if not it.is_folder:
            w.add_name(section, it.name, _BASE)
            if it.xml_key and it.xml_key != it.name:
                w.add_name(section, it.xml_key, _BASE)
            w.add_uuid(section, it.fm_uuid, _BASE)
        if section == "TableOccurrenceCatalog" and not it.is_folder:
            elem = _parse(it.xml_sources[0].xml) if it.xml_sources else None
            w.to_base_table[it.name] = _to_base_table_of(elem) if elem is not None else None
    return w


# ---------------------------------------------------------------------------
# Pass 1 — collect the patch's own added objects into the world
# ---------------------------------------------------------------------------

def _collect_added(action: ET.Element, idx: int, w: _World) -> None:
    """Register every object an AddAction introduces, tagged with document index."""
    for catalog in list(action):
        ctag = catalog.tag
        if ctag in _PAYLOAD_CATALOGS:
            continue  # step/calc payload — no new object
        if ctag == "FieldsForTables":
            for fc in catalog.iter("FieldCatalog"):
                bt = fc.find("BaseTableReference")
                table = bt.get("name") if bt is not None else ""
                for fld in fc.iter("Field"):
                    if fld.get("name"):
                        w.add_field(table, fld.get("name"), idx)
            continue
        # Object elements live directly under the catalog or inside an ObjectList.
        for obj in catalog.iter():
            section = _OBJ_TAG_SECTION.get(obj.tag)
            if section is None:
                continue
            name = obj.get("name")
            if not name or name == "--":  # unnamed wrapper / folder close marker
                continue
            w.add_name(section, name, idx)
            uel = obj.find("UUID")
            if uel is not None and (uel.text or "").strip():
                w.add_uuid(section, uel.text.strip(), idx)
            if obj.get("UUID"):
                w.add_uuid(section, obj.get("UUID"), idx)
            if section == "TableOccurrenceCatalog":
                w.to_base_table.setdefault(name, _to_base_table_of(obj))


# ---------------------------------------------------------------------------
# Pass 2 — check references, in document order, against the assembled world
# ---------------------------------------------------------------------------

def _iter_refs(elem: ET.Element, parent_tag: Optional[str] = None):
    """Yield (element, parent_tag) for the subtree, parent-aware so a
    TableOccurrenceReference qualifying a FieldReference can be skipped."""
    for child in elem:
        yield child, elem.tag
        yield from _iter_refs(child, elem.tag)


def _resolve(section: str, name: str, uid: str, w: _World) -> Optional[int]:
    """Lowest add_index at which (name|uuid) resolves in section, or None."""
    candidates = []
    if name:
        i = w.name_index(section, name)
        if i is not None:
            candidates.append(i)
    if uid:
        i = w.uuid_index(section, uid)
        if i is not None:
            candidates.append(i)
    if not candidates:
        return None
    # Prefer a base hit (-1) over a later-added one for ordering purposes.
    return min(candidates)


def _check_field_ref(fr: ET.Element, idx: int, referrer: str, w: _World,
                     report: CoherenceReport) -> None:
    fname = fr.get("name")
    tor = fr.find("TableOccurrenceReference")
    to_name = tor.get("name") if tor is not None else ""
    if not fname or not to_name:
        return  # global/unqualified field ref — nothing to verify against a TO
    report.checked_references += 1
    ref = f"{to_name}::{fname}"

    if to_name not in w.to_base_table and w.name_index("TableOccurrenceCatalog", to_name) is None:
        report.findings.append(CoherenceFinding(
            "error", "unknown_to",
            f"Set Field references table occurrence '{to_name}', which exists in "
            f"neither the file nor the patch.",
            referrer=referrer, reference=ref, ledger_id="intra-patch-ordering-required",
        ))
        return

    base_table = w.to_base_table.get(to_name)
    if base_table is None:
        # External or base table unknown — cannot verify field membership; count as
        # resolved (the TO itself is known) and move on.
        report.resolved_references += 1
        return

    fields = w.table_fields.get(base_table)
    if not fields:
        # No field knowledge for this table — be conservative, do not flag.
        report.resolved_references += 1
        return

    if fname not in fields:
        report.findings.append(CoherenceFinding(
            "error", "field_not_on_to",
            f"Field '{fname}' is referenced through table occurrence '{to_name}' "
            f"(base table '{base_table}'), but '{base_table}' has no field '{fname}'. "
            f"The field and the occurrence it is set through must share a base table.",
            referrer=referrer, reference=ref,
        ))
        return

    # ordering: a patch-added field must precede the step that sets it.
    add_idx = fields[fname]
    report.resolved_references += 1
    if add_idx != _BASE and add_idx > idx:
        report.findings.append(CoherenceFinding(
            "error", "ordering",
            f"Field '{ref}' is set before it is added in the patch. Emit the field "
            f"AddAction before the script that sets it.",
            referrer=referrer, reference=ref, ledger_id="intra-patch-ordering-required",
        ))


def _check_generic_ref(el: ET.Element, idx: int, referrer: str, w: _World,
                       report: CoherenceReport) -> None:
    section = _CHECKED_REF_SECTION[el.tag]
    name = el.get("name") or ""
    uid = el.get("UUID") or ""
    if not name and not uid:
        return
    report.checked_references += 1
    ref = name or uid

    add_idx = _resolve(section, name, uid, w)
    if add_idx is None:
        report.findings.append(CoherenceFinding(
            "error", "dangling_reference",
            f"{el.tag} '{ref}' resolves to no {section} object in the file or the patch.",
            referrer=referrer, reference=ref, ledger_id="dangling-cross-reference",
        ))
        return

    report.resolved_references += 1
    if add_idx != _BASE and add_idx > idx:
        report.findings.append(CoherenceFinding(
            "error", "ordering",
            f"{el.tag} '{ref}' is referenced before the object is added in the patch. "
            f"Emit the referenced object before its referrer (referent-first order).",
            referrer=referrer, reference=ref, ledger_id="intra-patch-ordering-required",
        ))


def _action_label(action: ET.Element, idx: int) -> str:
    """A short human label for the action, for finding.referrer."""
    for catalog in list(action):
        for obj in catalog.iter():
            if _OBJ_TAG_SECTION.get(obj.tag) and obj.get("name") and obj.get("name") != "--":
                return f"{action.tag}[{idx}] {obj.tag} '{obj.get('name')}'"
        sr = catalog.find(".//ScriptReference")
        if sr is not None and sr.get("name"):
            return f"{action.tag}[{idx}] '{sr.get('name')}'"
        return f"{action.tag}[{idx}] {catalog.tag}"
    return f"{action.tag}[{idx}]"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _check_steps_linkage(actions, base_artifact, report) -> None:
    """Catch the silent step-drop: a <StepsForScripts> add only attaches its steps when its
    <ScriptReference> carries an explicit, non-zero id that matches the <ScriptCatalog><Script>
    shell added in the same patch with that SAME id (or an existing script's id). FMUpgradeTool
    links steps to the shell BY ID — id="0" / name-only / a mismatched id all drop the steps and
    the script lands empty (verified live 26.0.1.68;
    fm2026-crossfile-script-steps-need-matching-explicit-id)."""
    LID = "fm2026-crossfile-script-steps-need-matching-explicit-id"
    # name -> id of every script SHELL added in the patch (id may be "0"/None).
    shell_id_by_name: dict = {}
    for action in actions:
        if action.tag != "AddAction":
            continue
        for scr in action.findall("./ScriptCatalog/Script"):
            shell_id_by_name.setdefault(scr.get("name", ""), scr.get("id"))
    for idx, action in enumerate(actions):
        if action.tag != "AddAction":
            continue
        sref = action.find("./StepsForScripts/Script/ScriptReference")
        if sref is None:
            continue
        # only matters when steps are actually carried
        if action.find("./StepsForScripts/Script/ObjectList") is None and \
           action.find("./StepsForScripts/Script/StepList") is None:
            continue
        rid, rname = sref.get("id"), sref.get("name", "")
        label = _action_label(action, idx)
        shell_id = shell_id_by_name.get(rname)  # None if the script isn't added in this patch
        if rname in shell_id_by_name:
            # Steps for a NEWLY-ADDED script — must carry the shell's explicit non-zero id.
            if not shell_id or shell_id == "0":
                report.findings.append(CoherenceFinding(
                    "error", "script_steps_no_explicit_id",
                    f"Script '{rname}' is added with id=\"0\" (or no id), so FMUpgradeTool "
                    f"reassigns it and its steps cannot link — they silently drop and the script "
                    f"lands EMPTY. Give the <ScriptCatalog><Script> AND this <ScriptReference> the "
                    f"SAME explicit, non-colliding id (e.g. id=\"990001\").",
                    referrer=label, reference=rname, ledger_id=LID))
            elif rid != shell_id:
                report.findings.append(CoherenceFinding(
                    "error", "script_steps_id_mismatch",
                    f"StepsForScripts ScriptReference id={rid!r} does not match the added script "
                    f"'{rname}' shell id={shell_id!r}. FMUpgradeTool links steps to the shell BY "
                    f"ID; a mismatch drops the steps (empty script). Use the same id on both.",
                    referrer=label, reference=rname, ledger_id=LID))
        elif not rid or rid == "0":
            # Steps target a script not added here (an existing one) but carry no usable id.
            report.findings.append(CoherenceFinding(
                "error", "script_steps_no_explicit_id",
                f"StepsForScripts for '{rname}' has no explicit non-zero id on its ScriptReference "
                f"and no matching script is added in this patch — the steps cannot link and will "
                f"silently drop. Reference the target script by its real id, or add the script "
                f"shell with a matching explicit id.",
                referrer=label, reference=rname, ledger_id=LID))


def check_patch_coherence(patch_xml: str, base_artifact: "Artifact") -> CoherenceReport:
    """Check a generated FMUpgradeToolPatch for intra-patch semantic coherence
    against the base artifact it will apply to."""
    report = CoherenceReport()
    root = _parse(patch_xml)
    if root is None:
        report.findings.append(CoherenceFinding(
            "error", "unparseable_patch", "Patch XML is not well-formed; cannot check.",
        ))
        return report

    structure = root.find("Structure")
    if structure is None and root.tag == "Structure":
        structure = root
    if structure is None:
        report.findings.append(CoherenceFinding(
            "error", "no_structure", "Patch has no <Structure> element; nothing to check.",
        ))
        return report

    w = _build_base_world(base_artifact)
    actions = list(structure)

    # Pass 1: assemble the full world (so referent-first ordering can distinguish
    # "added later" from "never added").
    for idx, action in enumerate(actions):
        if action.tag == "AddAction":
            _collect_added(action, idx, w)

    # Pass 2: resolve every reference, in document order.
    for idx, action in enumerate(actions):
        referrer = _action_label(action, idx)

        if action.tag == "ReplaceAction":
            rep = action.find("Replace")
            uid = rep.get("UUID") if rep is not None else None
            section = None
            if rep is not None:
                # Replace type → section, via the object-tag map's values.
                for tag, sec in _OBJ_TAG_SECTION.items():
                    if rep.get("type") == tag:
                        section = sec
                        break
                if rep.get("type") == "Field":
                    section = "FieldsForTables"
            if uid and section and section != "FieldsForTables":
                if w.uuid_index(section, uid) is None:
                    report.findings.append(CoherenceFinding(
                        "warning", "replace_target_missing",
                        f"ReplaceAction targets UUID {uid} ({section}), which is not in "
                        f"the base file — it would match no existing object.",
                        referrer=referrer, reference=uid,
                    ))
            continue

        if action.tag == "DeleteAction":
            ir = action.find("ItemReference")
            uid = ir.get("UUID") if ir is not None else None
            if uid:
                # Delete targets resolve across all sections by UUID.
                found = any(uid in m for m in w.uuids.values())
                if not found:
                    report.findings.append(CoherenceFinding(
                        "warning", "delete_target_missing",
                        f"DeleteAction targets UUID {uid}, which is not in the base file.",
                        referrer=referrer, reference=uid,
                    ))
            continue

        if action.tag != "AddAction":
            continue

        # AddAction: walk its subtree for references.
        for el, parent_tag in _iter_refs(action):
            tag = el.tag
            if tag == "FieldReference":
                _check_field_ref(el, idx, referrer, w, report)
            elif tag == "TableOccurrenceReference" and parent_tag == "FieldReference":
                continue  # qualifier — covered by the field-on-TO check
            elif tag in _CHECKED_REF_SECTION:
                _check_generic_ref(el, idx, referrer, w, report)

    _check_steps_linkage(actions, base_artifact, report)
    return report
