"""Validate a FileMaker clipboard clip (`fmxmlsnippet type="FMObjectList"`) — packet 1024 §4.

FileMaker's worst paste failure is SILENT: on paste it blanks references it can't resolve
(`<Field Missing>`, `<Table Missing>`, an unresolved script/layout) rather than erroring. So the
one guarantee no generic clipboard tool can offer — and the one this project's index makes possible
— is a PRE-PASTE resolution check against a specific target file.

The validation ladder (each rung independent, all best-effort — never raises):

  1. well-formed XML                — `extract_clip_xml` (ingestion.clip) already covers this
  2. snippet schema / clip kind     — root is <fmxmlsnippet type="FMObjectList">; first child → class
  3. block balance                  — If/End If, Loop/End Loop nesting across the step stream
  4. reference resolution           — every Field/Script/Layout/Table/ValueList/CustomFunction the
                                       clip REFERENCES either resolves against the target index or is
                                       reported "will paste unresolved" (the moat)
  5. calc parse                     — each <Calculation> parses; its TO::field / value-list refs feed
                                       rung 4 too

Reference resolution keys on NAMES (the reliable cross-dialect join): the clipboard dialect carries
`id` + `name` on bare <Script>/<Field>/<Layout>/… elements, while the artifact index is keyed by
name + fm_uuid (NOT the volatile numeric FM id), so names are what join. A Field reference resolves
against its TABLE OCCURRENCE (its `table` attr) — a missing TO is the common silent-paste break;
field-name-on-TO is a documented v1 boundary (we confirm the TO exists, not each field within it).

Pure functions over a parsed clip + an optional TargetIndex — no backend/MCP coupling.
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field as _field

# Clip reference element tag → the target catalog section whose NAME set resolves it.
_REF_SECTION = {
    "Script": "ScriptCatalog",
    "Layout": "LayoutCatalog",
    "Table": "BaseTableCatalog",
    "BaseTable": "BaseTableCatalog",
    "ValueList": "ValueListCatalog",
    "CustomFunction": "CustomFunctionsCatalog",
    # a Field reference resolves via its TableOccurrence (the `table` attr), not the base table
    "Field": "TableOccurrenceCatalog",
}


@dataclass
class ClipRef:
    kind: str            # Script | Field | Layout | Table | ValueList | CustomFunction
    name: str            # the referenced object's name (the join key)
    table: str = ""      # for a Field: its TableOccurrence name (what actually must resolve)
    ident: str = ""      # the clip's numeric FM id (informational; not the join key)
    origin: str = "step" # "step" (an element inside a Step) | "calc" (mined from a Calculation)

    def resolve_key(self) -> tuple:
        """(section, name) to look up in the target index."""
        if self.kind == "Field":
            return ("TableOccurrenceCatalog", self.table)
        return (_REF_SECTION.get(self.kind, self.kind), self.name)


@dataclass
class ValidationResult:
    well_formed: bool
    schema_ok: bool = False
    kind: str = ""
    fm_class: str = ""
    blocks_balanced: bool = True
    block_errors: list = _field(default_factory=list)
    references: list = _field(default_factory=list)   # [{kind,name,table,resolved,origin}]
    calc_errors: list = _field(default_factory=list)   # [{calc,error}]
    error: str = ""                                     # set only when well_formed is False

    @property
    def unresolved(self) -> list:
        """References that would PASTE unresolved — a real silent-<Missing> risk. Excludes intentional
        FM constructs ($variable targets, <unknown>/<Current Table> placeholders) and 'listed' (no
        target) refs. Back-compat: a ref dict may predate `status`, so fall back to the resolved flag."""
        return [r for r in self.references
                if (r["status"] == "unresolved" if "status" in r else not r["resolved"])]

    @property
    def intentional(self) -> list:
        """FM-emitted non-catalog references — variable targets + placeholder tokens — reported so a
        reader sees them, but NOT a paste risk (packet 1043)."""
        return [r for r in self.references if r.get("status") in ("variable", "placeholder")]

    @property
    def unverifiable(self) -> list:
        """Field-level references we could NOT confirm because the target holds no field evidence for
        their table (an external table / incomplete evidence) — packet 1058. Reported and NOT counted
        as resolved, so a clip against an incomplete target never reads as 'fully resolved'; but not a
        confident paste-risk either (the field may well exist where we can't see)."""
        return [r for r in self.references if r.get("status") == "unverifiable"]


# ── Target index (built from a parsed Artifact) ─────────────────────────────────

class TargetIndex:
    """Per-section NAME sets from a parsed artifact — what a reference must resolve against.

    Carries two extra maps for FIELD-LEVEL resolution of object-definition calc references (packet
    1058): ``to_base_tables`` (TableOccurrence name → its base-table name) and ``table_fields``
    (base-table name → the set of its field names). A ``TO::field`` reference in a field-definition or
    custom-function calc resolves to the field within its TO's base table — a granularity the TO-only
    check (kept for Step references) can't offer."""

    def __init__(self, section_names: dict, *, to_base_tables: dict | None = None,
                 table_fields: dict | None = None):
        self._names = {sec: set(names) for sec, names in section_names.items()}
        self._to_base = dict(to_base_tables or {})
        self._table_fields = {t: set(f) for t, f in (table_fields or {}).items()}

    @classmethod
    def from_artifact(cls, artifact) -> "TargetIndex":
        section_names: dict = {}
        to_base: dict = {}
        table_fields: dict = {}
        for it in artifact.items.values():
            if getattr(it, "is_folder", False):
                continue
            section_names.setdefault(it.section, set()).add(it.name)
            if it.section == "TableOccurrenceCatalog":
                bt = (getattr(it, "attributes", {}) or {}).get("baseTable")
                if bt:
                    to_base[it.name] = bt
            elif it.section == "FieldsForTables" and "::" in (getattr(it, "xml_key", "") or ""):
                tbl, fld = it.xml_key.split("::", 1)
                table_fields.setdefault(tbl, set()).add(fld)
        return cls(section_names, to_base_tables=to_base, table_fields=table_fields)

    def has(self, section: str, name: str) -> bool:
        return bool(name) and name in self._names.get(section, ())

    def field_status(self, qualifier: str, field_name: str) -> str:
        """FIELD-LEVEL resolution of a ``qualifier::field`` reference (packet 1058). ``qualifier`` is the
        calc's TableOccurrence (or, in a TO-less target, a base table directly). Returns:

        - ``resolved``     — the qualifier's base table is known, ITS field list is known, field present;
        - ``unresolved``   — the base table's field list is known and the field is NOT in it (a confident
                             miss, e.g. ``Contacts::MissingField``), OR the qualifier names no known
                             TO/base table at all (the TO itself is missing);
        - ``unverifiable`` — the base table is known but we hold NO field evidence for it (an external
                             table whose fields don't leak / incomplete evidence). Must NOT be reported
                             as resolved — we cannot confirm the field exists."""
        base = self._to_base.get(qualifier)
        if base is None and qualifier in self._table_fields:
            base = qualifier                 # TO-less target: the qualifier is the base table itself
        if base is None:
            return "unresolved"              # no such TO / base table → the qualifier is missing
        fields = self._table_fields.get(base)
        if not fields:
            return "unverifiable"            # base table known, but its fields are not evidenced here
        return "resolved" if field_name in fields else "unresolved"


# ── Rung 4: reference extraction ────────────────────────────────────────────────

def extract_clip_references(root: ET.Element) -> list:
    """Collect the references a clip makes — the objects it POINTS AT, not the objects it defines.

    Two passes with deliberately different scopes:

    - ELEMENT references live INSIDE <Step> subtrees (a Perform Script's <Script>, a Set Field's
      <Field>, a Go to Layout's <Layout>, …). This pass stays Step-scoped: a clip's TOP-LEVEL
      <Script>/<Field>/… children are the objects being DEFINED, not references, and must be skipped.
    - CALCULATIONS are mined tree-WIDE (packet 1058 P2). A <Calculation> can be a <Step> child (script
      clips) OR a direct child of a top-level object definition — a calculation FIELD (an XMFD
      field-definition clip) or a custom-function body. The old Step-only scope made a field-def clip
      report "0 references / all resolved" while its formula referenced real fields — a false clean. So
      a calc's TO::field + value-list refs are collected wherever the calc lives; a calc can't hide a
      broken ref."""
    from corpusfm.formula import analyze

    refs: list = []
    step_calc_ids: set = set()
    for step in root.iter("Step"):
        for tag, section in _REF_SECTION.items():
            for el in step.iter(tag):
                nm = el.get("name") or ""
                if tag == "Field" and not nm:
                    # <Field>$var</Field>: a variable / self target, not a field-on-TO (name in text)
                    nm = (el.text or "").strip()
                refs.append(ClipRef(
                    kind=tag if tag != "BaseTable" else "Table",
                    name=nm,
                    table=el.get("table") or "",
                    ident=el.get("id") or "",
                    origin="step",
                ))
        for calc in step.iter("Calculation"):
            step_calc_ids.add(id(calc))       # remember which calcs belong to a <Step>
    # Tree-wide calc mining. A calc's ORIGIN distinguishes how its field refs resolve:
    #   - "calc"      → a <Step>-nested calc (a Set Field / If formula): TO-level resolution (the v1
    #                   boundary — a Step's field ref confirms its TableOccurrence exists);
    #   - "def_calc"  → an OBJECT-DEFINITION calc: a calculation FIELD (XMFD field-def clip) or a
    #                   custom-function body, sitting directly under its top-level object, NOT a <Step>.
    #                   These resolve at FIELD level (TO::field must name a real field in the target).
    # A field-def calc carries its table context on <Calculation table="…">, so pass it as implicit_to →
    # an UNqualified field name resolves against that table rather than being dropped.
    for calc in root.iter("Calculation"):
        text = "".join(calc.itertext())
        if not text.strip():
            continue
        origin = "calc" if id(calc) in step_calc_ids else "def_calc"
        try:
            fr = analyze(text, implicit_to=(calc.get("table") or None))
        except Exception:
            continue
        for f in fr.field_refs:
            refs.append(ClipRef(kind="Field", name=f.field, table=f.table, origin=origin))
        for vl in fr.vl_refs:
            refs.append(ClipRef(kind="ValueList", name=vl, origin=origin))
    return _dedupe(refs)


def _dedupe(refs: list) -> list:
    seen, out = set(), []
    for r in refs:
        key = (r.kind, r.name, r.table)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _intentional_kind(r: "ClipRef") -> str:
    """A reference FileMaker itself emits that is NOT a resolvable catalog object, so it must not read
    as a silent-paste risk (packet 1043): a `$variable` field/target, or an angle-bracket placeholder
    token (`<unknown>`, `<Current Table>`). Returns 'variable' | 'placeholder' | ''."""
    if r.kind == "Field" and ((r.name or "").startswith("$") or (r.table or "").startswith("$")):
        return "variable"
    target = ((r.table if r.kind == "Field" else r.name) or "").strip()
    if target.startswith("<") and target.endswith(">"):
        return "placeholder"
    return ""


def resolve_references(refs: list, index: "TargetIndex | None") -> list:
    """Classify each reference against the target index. `status` ∈ resolved | unresolved | variable |
    placeholder | listed. A `variable`/`placeholder` ref is an intentional FM construct — reported but
    NOT counted as unresolved (packet 1043). With no index, real refs are 'listed' (reported, not
    judged). `resolved` stays bool|None for back-compat; `status` is the precise signal."""
    out = []
    for r in refs:
        section, name = r.resolve_key()
        intent = _intentional_kind(r)
        if intent:
            resolved, status = None, intent
        elif index is None:
            resolved, status = None, "listed"
        elif r.kind == "Field" and r.origin == "def_calc":
            # An object-definition (field-def / custom-function) calc reference → FIELD-LEVEL check:
            # the field must exist in its TO's base table, not merely the TO. `unverifiable` means the
            # target holds no field evidence for that table (external / incomplete) — reported, NOT
            # counted as resolved, so a target with incomplete field evidence can't read as fully clean.
            section = "FieldsForTables"
            fstat = index.field_status(r.table, r.name)
            if fstat == "resolved":
                resolved, status = True, "resolved"
            elif fstat == "unverifiable":
                resolved, status = None, "unverifiable"
            else:
                resolved, status = False, "unresolved"
        else:
            resolved = index.has(section, name)
            status = "resolved" if resolved else "unresolved"
        out.append({
            "kind": r.kind, "name": r.name, "table": r.table,
            "origin": r.origin, "resolved": resolved, "status": status,
            "resolves_against": section,
        })
    return out


# ── Rung 3: block balance ───────────────────────────────────────────────────────

def check_block_balance(root: ET.Element) -> list:
    """Check If/End If and Loop/End Loop nesting across the clip's step stream.

    Role (opener/continue/closer) comes from the structure catalog's `block_role` (packet 072-A —
    no hardcoded step-id frozensets). Pairing FAMILY is derived from FM's own naming: a closer
    'End X' matches an opener named 'X' — generic, no per-step table to drift."""
    from corpusfm.core.rendering.step_renderer import _block_roles
    roles = _block_roles()
    errors: list = []
    stack: list = []   # [(opener_name, step_index)]
    for i, step in enumerate(root.iter("Step")):
        try:
            sid = int(step.get("id", "-1"))
        except ValueError:
            sid = -1
        role = roles.get(sid)
        name = step.get("name", "")
        if role == "opener":
            stack.append((name, i))
        elif role == "closer":
            want = name[4:].strip() if name.startswith("End ") else ""
            if not stack:
                errors.append(f"step {i}: '{name}' has no matching opener")
            elif want and stack[-1][0] != want:
                errors.append(
                    f"step {i}: '{name}' closes a '{stack[-1][0]}' block "
                    f"(opened at step {stack[-1][1]}) — crossed nesting")
                stack.pop()
            else:
                stack.pop()
        elif role == "continue":
            if not stack:
                errors.append(f"step {i}: '{name}' outside any block")
    for name, idx in stack:
        errors.append(f"step {idx}: '{name}' block is never closed")
    return errors


# ── The ladder ──────────────────────────────────────────────────────────────────

def validate_clip(clip_xml: str, target: "TargetIndex | None" = None) -> ValidationResult:
    """Run the full validation ladder over a clip string. Never raises."""
    from corpusfm.ingestion.clip import classify_clip, _strip_xml_decl

    text = clip_xml.decode("utf-8", "replace") if isinstance(clip_xml, bytes) else clip_xml
    # A declared encoding (FM clips sometimes say utf-16 even as text) makes ET refuse a Unicode
    # string, so strip the declaration and parse the text directly — robust to the declared charset.
    try:
        root = ET.fromstring(_strip_xml_decl(text))
    except Exception as exc:
        return ValidationResult(well_formed=False, error=str(exc))

    res = ValidationResult(well_formed=True)
    if root.tag == "fmxmlsnippet" and (root.get("type") or "") == "FMObjectList":
        res.schema_ok = True
    elif root.tag == "FMObjectTransfer":
        # A DIFFERENT clipboard container (custom menus / menu sets) — well-formed but not the
        # FMObjectList dialect this ladder resolves. Report it honestly rather than fail parse.
        res.kind = "FMObjectTransfer (custom menu / unsupported clip container)"
        return res
    info = classify_clip(text)
    if info:
        res.kind = info["kind"]
        res.fm_class = info["fm_class"]

    res.block_errors = check_block_balance(root)
    res.blocks_balanced = not res.block_errors

    res.references = resolve_references(extract_clip_references(root), target)

    # Parse every calculation in the clip — tree-wide, not just under <Step> — so a field-definition /
    # custom-function calc's syntax error is reported too (packet 1058 P2).
    for calc in root.iter("Calculation"):
        text = "".join(calc.itertext())
        if not text.strip():
            continue
        try:
            from corpusfm.formula import parse
            _, errs = parse(text)
            if errs:
                res.calc_errors.append({"calc": text[:80], "error": str(errs[0])})
        except Exception as exc:
            res.calc_errors.append({"calc": text[:80], "error": str(exc)})
    return res
