"""Extract every reference one FM file makes into its sibling files.

Pure, deterministic analysis over a loaded Artifact (no FM, no network). Mirrors the
on-demand pattern of workflows.py / structure_intent.py — derived, not stored.

The channels (all confirmed against real multi-file solutions in xmlsamples):
  • ExternalDataSourceCatalog — declares which sibling files this file opens, and the
    path each resolves to (the linking key: data-source alias → target file name).
  • TableOccurrenceCatalog — external TOs (type ExternalDataSourceReference) borrow a
    sibling's base table; carry the external base-table name when present (≈ 80% of the
    time in the wild; the rest carry only the data source, so we fall back to the TO name).
  • RelationshipCatalog — join predicates whose field sits on an external TO are the KEY
    fields the sibling relies on (and the local side's type lets us infer the external type).
  • Calculations (fields/CFs/scripts) — TO::field references where the TO is external.
  • ValueListCatalog / LayoutCatalog — fields drawn from / placed from external TOs.
  • StepsForScripts — cross-file Perform Script calls (DataSourceReference + ScriptReference),
    and Set Field writes into an external field (the written $var/TO::field is a naming signal
    for the otherwise id-only target — the script-var candidate of #1b).

Public API:
    extract_external_references(artifact) -> ExternalReferenceSet
"""

from __future__ import annotations

import re
from corpusfm.core import safe_xml as ET

from corpusfm.core.filenames import ensure_fmp12
from ._types import (
    ExternalDataSource, ExternalRef, ExternalReferenceSet,
    ExternalDataSourceEntry, ExternalDataSourceIndex,
    KIND_TABLE, KIND_KEY_FIELD, KIND_CALC_FIELD, KIND_VL_FIELD,
    KIND_LAYOUT_FIELD, KIND_SCRIPT,
)

# FM universal-path schemes. A <UniversalPathList> may concatenate several (file:Foo
# then fmnet:/host/Foo) with no separator; split on the scheme boundary.
_SCHEME_RE = re.compile(r'(file:|filemac:/|filewin:/|fmnet:/|fmcloud:/)')
# A TO::field reference inside calculation text (FM qualified field reference).
_QUALIFIED_FIELD_RE = re.compile(r'([A-Za-z_][\w ]*?)::([A-Za-z_][\w ]*)')


def _xml(item) -> str:
    return item.xml_sources[0].xml if item.xml_sources else ""


def _file_name_from_path(path: str) -> str:
    """Derive the target file name from one path string (basename, .fmp12 stripped)."""
    p = path.strip()
    for scheme in ("file:", "filemac:/", "filewin:/", "fmnet:/", "fmcloud:/"):
        if p.startswith(scheme):
            p = p[len(scheme):]
            break
    p = p.rstrip("/").split("/")[-1]            # basename
    if p.lower().endswith(".fmp12"):
        p = p[:-6]
    return p.strip()


def _paths_from_universal(text: str) -> list:
    """Split a (possibly multi-scheme, concatenated) UniversalPathList into path strings."""
    if not text:
        return []
    # Re-insert a delimiter before each scheme, then split.
    marked = _SCHEME_RE.sub(lambda m: "\x00" + m.group(1), text)
    return [seg for seg in (s.strip() for s in marked.split("\x00")) if seg]


def _resolve_target_file(ds: ExternalDataSource) -> str:
    """The target FM file name, canonicalized WITH the .fmp12 suffix (the project standard).

    Prefers the relative `file:` name, else the first resolvable basename. This is a known
    FileMaker file reference (ODBC sources are filtered out downstream), so we fill in the
    suffix FM may have omitted — making file-to-file matching robust to FM's looseness."""
    file_scheme = [p for p in ds.paths if p.startswith("file:")]
    for cand in file_scheme + ds.paths:
        name = _file_name_from_path(cand)
        if name:
            return ensure_fmp12(name)
    return ""


def _iter_data_sources(artifact):
    """Yield EVERY ExternalDataSourceCatalog entry as an ExternalDataSource (target file resolved), in
    artifact-item order and WITHOUT deduplication — the single parser (packet 1118). `_parse_data_sources`
    (name-keyed, deduped) and `build_external_data_source_index` (id+name, ambiguity-aware) both consume
    it, so there is exactly one place that reads the catalog XML."""
    for item in artifact.items.values():
        if item.section != "ExternalDataSourceCatalog":
            continue
        try:
            el = ET.fromstring(_xml(item))
        except ET.ParseError:
            continue
        paths: list = []
        for upl in el.iter("UniversalPathList"):
            paths.extend(_paths_from_universal(upl.text or ""))
        ds = ExternalDataSource(
            name=el.get("name", ""), ds_id=el.get("id", ""),
            ds_type=el.get("type", "FileMaker"), paths=paths,
        )
        ds.target_file = _resolve_target_file(ds)
        yield ds


def _parse_data_sources(artifact) -> dict:
    """Map data-source alias → ExternalDataSource (target file resolved). Name-keyed, last-wins on a
    duplicate name; entries without a name are skipped — the long-standing cross-file behavior, unchanged."""
    out: dict = {}
    for ds in _iter_data_sources(artifact):
        if ds.name:
            out[ds.name] = ds
    return out


def build_external_data_source_index(artifact) -> ExternalDataSourceIndex:
    """The single public external-data-source authority (packet 1118). Reads the artifact's
    ExternalDataSourceCatalog via the shared parser and returns a read-only index keyed by id AND name,
    ambiguity-aware. It decides NO target clip fact — only whether a step reference resolves to one unique
    FileMaker sibling, for privacy-safe reporting."""
    return ExternalDataSourceIndex(entries=tuple(
        ExternalDataSourceEntry(ds_id=ds.ds_id, name=ds.name, ds_type=ds.ds_type,
                                paths=tuple(ds.paths), target_file=ds.target_file)
        for ds in _iter_data_sources(artifact)))


def _external_to_index(artifact, ds_by_name: dict) -> dict:
    """Map local external-TO name → (target_file, external_table_or_'', data_source).

    An external TO points at a sibling via DataSourceReference (alias) and, usually, names
    the external base table via BaseTableReference. When the base table isn't carried we
    leave it empty (the caller falls back to the TO name, flagged inferred)."""
    out: dict = {}
    for item in artifact.items.values():
        if item.section != "TableOccurrenceCatalog" or item.is_folder:
            continue
        try:
            el = ET.fromstring(_xml(item))
        except ET.ParseError:
            continue
        src = el.find("BaseTableSourceReference")
        if src is None or src.get("type") != "ExternalDataSourceReference":
            continue
        ds_ref = src.find("DataSourceReference")
        if ds_ref is None:
            continue
        alias = ds_ref.get("name", "")
        ds = ds_by_name.get(alias)
        if ds is None or not ds.is_filemaker:    # skip ODBC/SQL sources — not a sibling FM file
            continue
        bt_ref = src.find("BaseTableReference")
        ext_table = bt_ref.get("name", "") if bt_ref is not None else ""
        out[el.get("name", item.name)] = (ds.target_file, ext_table, alias)
    return out


def _qualified_field_refs(text: str) -> list:
    """(to, field) pairs from TO::field references in calculation text."""
    if not text or "::" not in text:
        return []
    return [(m.group(1).strip(), m.group(2).strip()) for m in _QUALIFIED_FIELD_RE.finditer(text)]


# ── layout label adjacency (a naming signal for id-only external fields) ──────

def _bounds(obj) -> tuple:
    """(top, left, bottom, right) of a LayoutObject's own Bounds, or None."""
    b = obj.find("Bounds")
    if b is None:
        return None
    try:
        return (float(b.get("top", 0)), float(b.get("left", 0)),
                float(b.get("bottom", 0)), float(b.get("right", 0)))
    except (TypeError, ValueError):
        return None


def _label_text_of(obj) -> str:
    """The readable label text of a Text LayoutObject (joined <Data>), trimmed; '' if none.

    A label is a non-field Text object whose StyledText carries the caption that, by FM
    convention, names the field beside it. Skip long blocks (paragraphs, not field labels).
    """
    if obj.find(".//FieldReference") is not None:
        return ""
    parts = [d.text for d in obj.iter("Data") if d.text and d.text.strip()]
    txt = " ".join(parts).strip().rstrip(":").strip()
    return txt if 0 < len(txt) <= 40 else ""


def _best_label(field_bounds: tuple, labels: list) -> str:
    """The caption most likely to name a field at `field_bounds`.

    FM developers put the label to the LEFT of the field (same row) or directly ABOVE it.
    Prefer the nearest left label with vertical overlap; else the nearest top label with
    horizontal overlap. Gaps are bounded so an unrelated distant caption isn't claimed."""
    ft, fl, fb, fr = field_bounds
    best, best_score = "", None
    for (lt, ll, lb, lr), txt in labels:
        v_overlap = not (lb < ft or lt > fb)
        h_overlap = not (lr < fl or ll > fr)
        if lr <= fl + 4 and v_overlap and 0 <= (fl - lr) <= 40:
            score = (0, fl - lr)            # left of field, nearest wins
        elif lb <= ft + 4 and h_overlap and 0 <= (ft - lb) <= 30:
            score = (1, ft - lb)            # above field, nearest wins
        else:
            continue
        if best_score is None or score < best_score:
            best, best_score = txt, score
    return best


def _iter_external_layout_fields(lay, ext_to_names: set):
    """Yield (to_name, field_name, field_id, adjacent_label) for each external-field
    placement on a layout. Fields and labels are grouped by their immediate container (the
    ObjectList of a layout part / portal / tab panel) so a field is paired with a caption in
    its own container. The label is "" when the placement carries no bounds (only real FM
    layouts do) — the field reference is still yielded for coverage."""
    # Any element with direct LayoutObject children is a container; handles both the real
    # <ObjectList> grouping and the bare <Object> wrapper used in fixtures, each level on its own.
    for ol in (el for el in lay.iter() if el.find("LayoutObject") is not None):
        children = ol.findall("LayoutObject")   # direct children only — nested lists handle their own
        labels: list = []
        fields: list = []
        for o in children:
            fref = o.find(".//FieldReference")
            if fref is not None:
                tref = fref.find("TableOccurrenceReference")
                if tref is not None and tref.get("name", "") in ext_to_names:
                    fields.append((_bounds(o), tref.get("name", ""), fref.get("name", ""), fref.get("id", "")))
                continue
            b = _bounds(o)
            txt = _label_text_of(o)
            if b is not None and txt:
                labels.append((b, txt))
        for (b, to_name, fname, fid) in fields:
            label = _best_label(b, labels) if b is not None else ""
            yield (to_name, fname, fid, label)


# ── script field-writes (a naming signal for id-only external fields) ─────────

# A value calc that is exactly one variable ($v / $$v) — the var name names the target.
_LONE_VAR_RE = re.compile(r'^\$\$?([A-Za-z_]\w*)$')
# …or exactly one qualified field reference TO::Field — the field part is the signal.
_LONE_QUALIFIED_RE = re.compile(r'^[A-Za-z_][\w ]*?::([A-Za-z_][\w ]*)$')


def _simple_value_name(text: str) -> str:
    """A naming signal from a step's VALUE calc — only when it's a SINGLE $variable or a
    single TO::field reference (anything compound is too noisy to name a field from)."""
    t = (text or "").strip()
    m = _LONE_VAR_RE.match(t)
    if m:
        return m.group(1)
    m = _LONE_QUALIFIED_RE.match(t)
    if m:
        return m.group(1).strip()
    return ""


def _iter_script_field_writes(root, ext_to_names: set):
    """Yield (to_name, field_name, field_id, value_name) for each script step that WRITES a
    value into an external-TO field (Set Field and the structurally-identical field-target
    steps). The target is a Parameter[@type='FieldReference']; cross-file targets carry id
    only (name=""). When the written value is a single $variable or TO::field, its name is a
    (loose) naming signal for that id-only target — the script-var candidate of #1b."""
    for step in root.iter("Step"):
        pvs = step.find("ParameterValues")
        if pvs is None:
            continue
        params = pvs.findall("Parameter")
        fref = next((p.find("FieldReference") for p in params
                     if p.get("type") == "FieldReference" and p.find("FieldReference") is not None), None)
        if fref is None:
            continue
        tref = fref.find("TableOccurrenceReference")
        if tref is None or tref.get("name", "") not in ext_to_names:
            continue
        value_name = ""
        for p in params:
            if p.get("type") == "Calculation":
                txt = "".join(t.text or "" for t in p.iter("Text"))
                value_name = _simple_value_name(txt)
                if value_name:
                    break
        yield (tref.get("name", ""), fref.get("name", ""), fref.get("id", ""), value_name)


def extract_external_references(artifact) -> ExternalReferenceSet:
    """Every reference `artifact` makes into its sibling files."""
    ds_by_name = _parse_data_sources(artifact)
    ext_to = _external_to_index(artifact, ds_by_name)   # to_name → (file, table, alias)
    refs: list = []

    def _table_for(to_name: str):
        """(target_file, external_table, alias) for an external TO, or None."""
        return ext_to.get(to_name)

    # 1) The external TOs themselves (a borrowed table is a reference to its file).
    for to_name, (tfile, table, alias) in ext_to.items():
        refs.append(ExternalRef(
            target_file=tfile, data_source=alias, kind=KIND_TABLE,
            external_table=table, external_to=to_name,
            via_section="TableOccurrenceCatalog", via_name=to_name))

    # Local field types, so a join against a local field can type the external one.
    local_field_type = _local_field_types(artifact)
    local_to_base = _local_to_base_table(artifact)

    # 2) Relationships — key fields on an external TO (and the local side, for typing).
    for item in artifact.items.values():
        if item.section != "RelationshipCatalog" or item.is_folder:
            continue
        try:
            rel = ET.fromstring(_xml(item))
        except ET.ParseError:
            continue
        for jp in rel.iter("JoinPredicate"):
            sides = []
            for side_tag in ("LeftField", "RightField"):
                side = jp.find(side_tag)
                if side is None:
                    continue
                fref = side.find("FieldReference")
                if fref is None:
                    continue
                # The TableOccurrenceReference is a CHILD of FieldReference (the field's
                # context), not a sibling under LeftField/RightField.
                tref = fref.find("TableOccurrenceReference")
                if tref is None:
                    continue
                # A cross-file join field carries id only — name="" (the name isn't in the
                # export when the target file is missing). Keep the id; it's the identity.
                sides.append((tref.get("name", ""), fref.get("name", ""), fref.get("id", "")))
            for i, (to_name, fname, fid) in enumerate(sides):
                tinfo = _table_for(to_name)
                if not tinfo:
                    continue
                tfile, table, alias = tinfo
                # the OTHER side, if local, gives a name + type to infer from
                other = sides[1 - i] if len(sides) == 2 else ("", "", "")
                local_type = _lookup_local_type(other[0], other[1], local_to_base, local_field_type)
                refs.append(ExternalRef(
                    target_file=tfile, data_source=alias, kind=KIND_KEY_FIELD,
                    external_table=table, external_to=to_name,
                    external_field=fname, external_field_id=fid,
                    via_section="RelationshipCatalog", via_name=item.name,
                    local_join_field=f"{other[0]}::{other[1]}" if other[0] and other[1] else "",
                    detail=local_type or ""))

    # 3) Calculations across fields / CFs / scripts — TO::field where TO is external.
    for item in artifact.items.values():
        if item.section not in ("FieldsForTables", "CustomFunctionsCatalog", "ScriptCatalog"):
            continue
        for src in item.xml_sources:
            for to_name, fname in _qualified_field_refs(src.xml):
                tinfo = _table_for(to_name)
                if not tinfo:
                    continue
                tfile, table, alias = tinfo
                refs.append(ExternalRef(
                    target_file=tfile, data_source=alias, kind=KIND_CALC_FIELD,
                    external_table=table, external_to=to_name, external_field=fname,
                    via_section=item.section, via_name=item.name))

    # 4) Value lists drawing from an external TO field.
    for item in artifact.items.values():
        if item.section != "ValueListCatalog" or item.is_folder:
            continue
        try:
            vl = ET.fromstring(_xml(item))
        except ET.ParseError:
            continue
        for tref in vl.iter("TableOccurrenceReference"):
            to_name = tref.get("name", "")
            tinfo = _table_for(to_name)
            if not tinfo:
                continue
            tfile, table, alias = tinfo
            fref = vl.find(".//FieldReference")
            refs.append(ExternalRef(
                target_file=tfile, data_source=alias, kind=KIND_VL_FIELD,
                external_table=table, external_to=to_name,
                external_field=(fref.get("name", "") if fref is not None else ""),
                external_field_id=(fref.get("id", "") if fref is not None else ""),
                via_section="ValueListCatalog", via_name=item.name))

    # 5) Layout objects bound to an external TO field — and the text label beside each,
    #    a naming signal for the (usually id-only) external field.
    ext_to_names = set(ext_to)
    for item in artifact.items.values():
        if item.section != "LayoutCatalog" or item.is_folder:
            continue
        seen_lo: set = set()
        for src in item.xml_sources:
            try:
                lay = ET.fromstring(src.xml)
            except ET.ParseError:
                continue
            for to_name, fname, fid, label in _iter_external_layout_fields(lay, ext_to_names):
                tinfo = _table_for(to_name)
                if not tinfo:
                    continue
                tfile, table, alias = tinfo
                # cross-file layout placements carry id only (name=""); identity = (table, name|id)
                key = (tfile, to_name, fname or f"#{fid}")
                if key in seen_lo:
                    continue
                seen_lo.add(key)
                ref = ExternalRef(
                    target_file=tfile, data_source=alias, kind=KIND_LAYOUT_FIELD,
                    external_table=table, external_to=to_name,
                    external_field=fname, external_field_id=fid,
                    via_section="LayoutCatalog", via_name=item.name)
                if label and not fname:        # a caption only helps when the name is missing
                    ref.name_hint = label
                    ref.hint_source = "layout_label"
                    ref.hint_evidence = f"{ensure_fmp12(artifact.identity.file_name)}/{item.name}: label {label!r} beside the field"
                refs.append(ref)

    # 6) Cross-file Perform Script calls — and script field-writes into external fields
    #    (whose written value can name the otherwise id-only target).
    seen_sw: set = set()
    for item in artifact.items.values():
        if item.section != "ScriptCatalog" or item.is_folder:
            continue
        for src in item.xml_sources:
            try:
                root = ET.fromstring(src.xml)
            except ET.ParseError:
                continue
            for lst in root.iter("List"):
                ds_ref = lst.find("DataSourceReference")
                if ds_ref is None:
                    continue
                ds = ds_by_name.get(ds_ref.get("name", ""))
                if ds is None or not ds.is_filemaker:
                    continue
                for sref in lst.findall("ScriptReference"):
                    sname = sref.get("name", "")
                    if sname:
                        refs.append(ExternalRef(
                            target_file=ds.target_file, data_source=ds.name, kind=KIND_SCRIPT,
                            external_script=sname,
                            via_section="ScriptCatalog", via_name=item.name))
            for to_name, fname, fid, value_name in _iter_script_field_writes(root, ext_to_names):
                tinfo = _table_for(to_name)
                if not tinfo:
                    continue
                tfile, table, alias = tinfo
                # dedup per (file, TO, field, value): same field written from the same var in
                # many scripts is one signal; from a DIFFERENT var it's a second candidate.
                key = (tfile, to_name, fname or f"#{fid}", value_name)
                if key in seen_sw:
                    continue
                seen_sw.add(key)
                ref = ExternalRef(
                    target_file=tfile, data_source=alias, kind=KIND_CALC_FIELD,
                    external_table=table, external_to=to_name,
                    external_field=fname, external_field_id=fid,
                    via_section="ScriptCatalog", via_name=item.name)
                if value_name and not fname:    # a value names the field only when the name is gone
                    ref.name_hint = value_name
                    ref.hint_source = "script_var"
                    ref.hint_evidence = (f"{ensure_fmp12(artifact.identity.file_name)}/{item.name}: "
                                         f"Set Field target written from '{value_name}'")
                refs.append(ref)

    return ExternalReferenceSet(
        source_file=ensure_fmp12(artifact.identity.file_name),
        data_sources=[d for d in ds_by_name.values()],
        refs=refs,
    )


# ── local-side type lookup (for inferring an external key field's type) ───────

# FM stores the field's type as the word itself on the @datatype attribute
# ("Text" / "Number" / "Date" / …) — not a numeric code.
_VALID_FIELD_TYPES = {"Text", "Number", "Date", "Time", "Timestamp", "Container"}


def _local_to_base_table(artifact) -> dict:
    """Local TO name → base table name (for LOCAL TOs only)."""
    out: dict = {}
    for item in artifact.items.values():
        if item.section != "TableOccurrenceCatalog" or item.is_folder:
            continue
        try:
            el = ET.fromstring(_xml(item))
        except ET.ParseError:
            continue
        src = el.find("BaseTableSourceReference")
        if src is None or src.get("type") == "ExternalDataSourceReference":
            continue
        bt = src.find("BaseTableReference")
        if bt is not None:
            out[el.get("name", item.name)] = bt.get("name", "")
    return out


def _local_field_types(artifact) -> dict:
    """`BaseTable::Field` → FM type name, for local fields."""
    out: dict = {}
    for item in artifact.items.values():
        if item.section != "FieldsForTables" or item.is_folder:
            continue
        try:
            f = ET.fromstring(_xml(item))
        except ET.ParseError:
            continue
        dt = f.get("datatype") or f.get("dataType") or ""
        if dt in _VALID_FIELD_TYPES and "::" in item.name:
            out[item.name] = dt
    return out


def _lookup_local_type(to_name: str, field: str, to_base: dict, field_types: dict) -> str:
    if not to_name or not field:
        return ""
    base = to_base.get(to_name)
    if not base:
        return ""
    return field_types.get(f"{base}::{field}", "")
