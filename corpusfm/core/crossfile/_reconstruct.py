"""Reconstruct a missing file's external INTERFACE from its siblings' references to it.

Given the sibling artifacts of a solution and the name of a missing file X, aggregate every
external reference to X (extracted per-sibling) into a skeleton: the tables X must expose,
the fields each table must carry (with a confidence-scored inferred type), and the scripts
X must publish. Coverage is the UNION of what the siblings ask of X — it grows with more
siblings, and it is the recoverable surface ONLY. Anything no sibling references is a blind
spot, listed explicitly and never fabricated.

Public API:
    reconstruct_interface(target_file, artifacts) -> ReconstructedInterface
    infer_field_type(*, used_as_key, local_join_type, calc_hint) -> (type, confidence, rationale)
"""

from __future__ import annotations

from corpusfm.core.filenames import ensure_fmp12
from ._extract import extract_external_references
from ._types import (
    NameCandidate,
    ReconstructedField, ReconstructedTable, ReconstructedScript, ReconstructedInterface,
    KIND_TABLE, KIND_KEY_FIELD, KIND_CALC_FIELD, KIND_VL_FIELD, KIND_LAYOUT_FIELD, KIND_SCRIPT,
)

_FIELD_KINDS = (KIND_KEY_FIELD, KIND_CALC_FIELD, KIND_VL_FIELD, KIND_LAYOUT_FIELD)

# Per-signal base confidence for a SUGGESTED field name (#1b). A name read from calc text is
# (nearly) certain. join_partner and layout_label are BALANCED as NAME signals: ground-truth
# validation (2026-06-14) showed FM joins like-TYPED fields but the two key sides are usually
# named DIFFERENTLY (join-partner *name* inference scored 0/2), while a caption sitting beside
# a field on a layout literally labels it — so neither outranks the other for a NAME (the join
# partner's strength is TYPE inference, handled separately in infer_field_type). script_var is
# the loosest. Corroboration across signals/siblings boosts.
_CANDIDATE_BASE = {"calc": 0.9, "join_partner": 0.7, "layout_label": 0.7, "script_var": 0.35}
_CORROBORATION_BOOST = 0.1
_CONFIDENCE_CAP = 0.95


def _collect_candidates(hints: list, read_name: str) -> list:
    """Aggregate naming hints into ranked NameCandidates (deduped, corroboration-boosted).

    `hints` is a list of (name, source, evidence). `read_name` is a name actually read from
    calc text (the strongest signal) or "" . Same name from ≥2 distinct sources/siblings →
    a confidence boost. Placeholder/empty names are dropped."""
    agg: dict = {}
    def _add(name: str, source: str, evidence: str):
        n = (name or "").strip()
        if not n or _is_placeholder(n):
            return
        rec = agg.setdefault(n.lower(), {"name": n, "conf": 0.0, "src": set(), "ev": set()})
        rec["conf"] = max(rec["conf"], _CANDIDATE_BASE.get(source, 0.3))
        rec["src"].add(source)
        if evidence:
            rec["ev"].add(evidence)
    if read_name:
        _add(read_name, "calc", "read from calc text (TO::field)")
    for name, source, evidence in hints:
        _add(name, source, evidence)
    out = []
    for rec in agg.values():
        conf = rec["conf"]
        if len(rec["src"]) >= 2 or len(rec["ev"]) >= 2:
            conf = min(_CONFIDENCE_CAP, conf + _CORROBORATION_BOOST)
        out.append(NameCandidate(name=rec["name"], confidence=conf,
                                 source="+".join(sorted(rec["src"])),
                                 evidence="; ".join(sorted(rec["ev"])[:4])))
    out.sort(key=lambda c: (-c.confidence, _norm(c.name)))
    return out


def _merge_candidate_lists(a: list, b: list) -> list:
    """Union two candidate lists by name (max confidence, union evidence)."""
    by_name: dict = {}
    for c in list(a) + list(b):
        key = _norm(c.name)
        cur = by_name.get(key)
        if cur is None or c.confidence > cur.confidence:
            by_name[key] = c
    return sorted(by_name.values(), key=lambda c: (-c.confidence, _norm(c.name)))

_BLIND_SPOTS = [
    "Field NAMES of relationship/layout refs — FM stores cross-file field refs by internal ID "
    "only (name is blank in the export, especially once the target file went missing). A name "
    "is recovered ONLY from calc text (TO::field) or INFERRED from the local join partner.",
    "Field options (auto-enter, validation, indexing, storage) — never referenced cross-file.",
    "Calculation/CF formula bodies of the missing file.",
    "Internal scripts (those no sibling calls) and the step bodies of all its scripts.",
    "Layouts, themes, custom menus, value-list definitions, privilege sets, accounts.",
    "Any table or field that no sibling references — invisible from the outside.",
    "Exact base-table names where an external TO carried only the data source (inferred from the TO).",
    "Field DATA TYPES are INFERRED from usage, not read — treat low-confidence types as guesses.",
]


def infer_field_type(*, used_as_key: bool, local_join_type: str = "",
                      calc_hint: str = "") -> tuple:
    """(inferred_type, confidence, rationale) for a reconstructed external field.

    The strongest, honest signal is a relationship join against a LOCAL field of known type
    (FM joins like-typed fields) → adopt that type at high confidence. Otherwise we stay
    conservative: a key with no typed local side is *probably* Text/Number but undeterminable,
    so we say so rather than guess a side.
    """
    if local_join_type:
        return (local_join_type, 0.85,
                f"joins to a local field of type {local_join_type} (FM joins like-typed fields)")
    if calc_hint:
        return (calc_hint, 0.5, f"used in a {calc_hint}-typed calculation context")
    if used_as_key:
        return ("unknown", 0.3,
                "used as a relationship key (indexed match field; exact type not determinable from references)")
    return ("unknown", 0.1, "name referenced but no type signal available")


def _norm(name: str) -> str:
    # General name normalizer — tables, fields, scripts, candidate names. NOT file names.
    return (name or "").strip().lower()


def _norm_file(name: str) -> str:
    # FILE-name match key: canonical (suffixed) form so a bare name and a Foo.fmp12
    # reference unify. Only for file-to-file comparisons, never object names.
    return ensure_fmp12((name or "").strip().lower())


def _base_table_from_to(to_name: str) -> str:
    """Infer the external base table from a TO name when the export didn't carry one.

    This developer convention (verified against real solutions by field-id overlap):
    a TO named `A»B»C` reaches base table C through a relationship path; `@X` is a base-
    table anchor TO. So the base table is the segment after the last `»`, `@` stripped.
    Heuristic — flagged name_is_inferred; the source TOs are kept in `from_tos`.
    """
    n = (to_name or "").strip()
    if "»" in n:
        n = n.rsplit("»", 1)[-1].strip()
    if n.startswith("@"):
        n = n[1:].strip()
    return n


def _partner_field(local_join_field: str) -> str:
    """The FIELD part of a `TO::Field` local join partner (the inferred external name)."""
    return local_join_field.split("::", 1)[1].strip() if "::" in local_join_field else ""


def _is_placeholder(name: str) -> bool:
    """A field display name that isn't a real recovered/inferred name (id-only)."""
    return (not name) or name.startswith("field #") or name == "(unnamed field)"


def _ids_of(t):
    return {f.field_id: f for f in t.fields if f.field_id}


def _named_ids(idmap):
    return {fid: f.name for fid, f in idmap.items() if not _is_placeholder(f.name)}


def _absorb(a, b, *, union: bool):
    """Fold inferred table b's field evidence into a (a keeps its own name). Cross-fill a's
    blank field names / unknown types from b by field id; when `union`, also adopt fields only
    b reached. Records b's name in a.merged_from."""
    a_ids = _ids_of(a)
    for fid, bf in _ids_of(b).items():
        af = a_ids.get(fid)
        if af is None:
            if union:
                a.fields.append(bf)
                a_ids[fid] = bf
            continue
        if _is_placeholder(af.name) and not _is_placeholder(bf.name):
            af.name, af.name_is_inferred, af.rationale = bf.name, bf.name_is_inferred, bf.rationale
        if bf.inferred_type != "unknown" and af.inferred_type == "unknown":
            af.inferred_type, af.confidence, af.rationale = bf.inferred_type, bf.confidence, bf.rationale
        af.used_as_key = af.used_as_key or bf.used_as_key
        af.referenced_by = sorted(set(af.referenced_by) | set(bf.referenced_by))
        af.candidate_names = _merge_candidate_lists(af.candidate_names, bf.candidate_names)
    a.from_tos += b.from_tos
    a.referenced_by_files += b.referenced_by_files
    a.merged_from.append(b.name)


def _merge_duplicate_tables(tables: dict) -> dict:
    """Fold same-physical-table aliases together, validating inferred names against real ones.

    The evidence is the externally-referenced field-id set (FM field ids are stable in the
    target file's own id space). Two passes, both conservative — a single conflicting shared
    NAMED id blocks a merge, and a real base-table name is never dropped:

    Pass 1 — BASE-TABLE-NAME VALIDATION (raw-XML grounded). A real `BaseTableReference` name
      that one sibling carried in its raw XML is authoritative; the ~20% of external TOs that
      carry only a data source produced a *guessed* name (from the TO name). When an
      inferred-name table shares an AGREEING named field id with a real-name table, they are
      the same physical table → fold the inferred one into the real one (union its fields),
      replacing the guess with the real name (the guess is kept in `merged_from`). Needs a
      shared named anchor — a stronger bar than pass 2, because it crosses the real/inferred
      line. A real table with no recovered field names anchors nothing and absorbs nothing.

    Pass 2 — INFERRED↔INFERRED aliases (PricingLine ≡ ContractPricingLine): the smaller
      field-id subset folds into the larger, cross-filling a name one TO recovered onto the
      same id another TO left blank.
    """
    tabs = list(tables.values())
    # largest field-id set first → absorb smaller subsets into it
    tabs.sort(key=lambda t: (-len(_ids_of(t)), _norm(t.name)))
    alive = list(tabs)
    absorbed: set = set()

    def _drop(b):
        absorbed.add(id(b))
        return [x for x in alive if x is not b]

    # Pass 1 — validate inferred names against authoritative real ones.
    for a in tabs:
        if id(a) in absorbed or a.name_is_inferred:
            continue                                       # absorber must be a REAL-named table
        a_named = _named_ids(_ids_of(a))
        if not a_named:
            continue                                       # no named field → nothing to anchor on
        for b in tabs:
            if b is a or id(b) in absorbed or not b.name_is_inferred:
                continue
            b_named = _named_ids(_ids_of(b))
            shared = set(a_named) & set(b_named)
            if not shared or any(a_named[i] != b_named[i] for i in shared):
                continue                                   # need ≥1 agreeing anchor, no conflict
            _absorb(a, b, union=True)                      # real name validates+replaces the guess
            alive = _drop(b)

    # Pass 2 — fold inferred aliases of the same table together.
    for a in tabs:
        if id(a) in absorbed or not a.name_is_inferred:
            continue
        a_ids = _ids_of(a); a_named = _named_ids(a_ids)
        for b in tabs:
            if b is a or id(b) in absorbed or not b.name_is_inferred:
                continue
            b_ids = _ids_of(b); b_named = _named_ids(b_ids)
            if not b_ids or not set(b_ids) <= set(a_ids):
                continue                                   # B not a subset of A
            shared_named = set(a_named) & set(b_named)
            if any(a_named[i] != b_named[i] for i in shared_named):
                continue                                   # a real name conflict → different tables
            if not (shared_named or (set(b_named) - set(a_named))):
                continue                                   # need a named anchor, not shared blanks
            _absorb(a, b, union=False)
            alive = _drop(b)

    return {_norm(t.name): t for t in alive}


def reconstruct_interface(target_file: str, artifacts) -> ReconstructedInterface:
    """Aggregate every reference to `target_file` across `artifacts` into its interface."""
    tgt = _norm_file(target_file)
    # Display the target in the canonical (suffixed) form too — it's a known FM file.
    iface = ReconstructedInterface(target_file=ensure_fmp12(target_file))

    tables: dict = {}      # tkey → ReconstructedTable
    scripts: dict = {}     # name → ReconstructedScript
    fwork: dict = {}       # (tkey, fident) → mutable working record for a field

    def _table_key(ref) -> tuple:
        """(display_name, name_is_inferred, source_to) for a ref's table."""
        if ref.external_table:
            return (ref.external_table, False, ref.external_to)
        # No base-table name carried — infer it from the external TO (developer convention),
        # else fall back to the data source alias. Flagged inferred either way.
        if ref.external_to:
            return (_base_table_from_to(ref.external_to) or ref.external_to, True, ref.external_to)
        return (ref.data_source or "(unknown table)", True, "")

    for art in artifacts:
        src_file = ensure_fmp12(art.identity.file_name)
        if _norm_file(src_file) == tgt:
            continue   # the file reconstructing itself contributes nothing
        refset = extract_external_references(art)
        contributed = False
        for ref in refset.refs:
            if _norm_file(ref.target_file) != tgt:
                continue
            contributed = True

            if ref.kind == KIND_SCRIPT:
                s = scripts.get(ref.external_script)
                if s is None:
                    s = scripts[ref.external_script] = ReconstructedScript(name=ref.external_script)
                s.called_by_files.append(src_file)
                continue

            tname, t_inferred, source_to = _table_key(ref)
            tkey = _norm(tname)
            t = tables.get(tkey)
            if t is None:
                t = tables[tkey] = ReconstructedTable(name=tname, name_is_inferred=t_inferred)
            elif t_inferred is False and t.name_is_inferred:
                t.name, t.name_is_inferred = tname, False   # a real base-table name upgrades an inferred one
            t.referenced_by_files.append(src_file)
            if source_to:
                t.from_tos.append(source_to)

            if ref.kind == KIND_TABLE:
                continue   # table-level reference; no specific field

            # Field identity: by NAME when the export carries it (calc text), else by the
            # internal field ID (relationship/layout cross-file refs are id-only). Skip if
            # neither is present (nothing to hang a field on).
            name, fid = ref.external_field, ref.external_field_id
            if name:
                fident = ("n", _norm(name))
            elif fid:
                fident = ("i", fid)
            else:
                continue

            wkey = (tkey, fident)
            w = fwork.get(wkey)
            if w is None:
                w = fwork[wkey] = {"name": "", "name_inferred": False, "field_id": fid,
                                   "used_as_key": False, "local_type": "", "name_from": "",
                                   "refs": [], "hints": [], "read_name": "", "table": t}
            if fid and not w["field_id"]:
                w["field_id"] = fid
            # explicit (read) name wins over any inferred one
            if name and not (w["name"] and not w["name_inferred"]):
                w["name"], w["name_inferred"] = name, False
            if name:
                w["read_name"] = name                        # a name actually read (calc text)
            w["refs"].append(f"{src_file}:{ref.via_section}/{ref.via_name}")
            if ref.name_hint:                                # context-mined caption (#1b)
                w["hints"].append((ref.name_hint, ref.hint_source, ref.hint_evidence))

            if ref.kind == KIND_KEY_FIELD:
                w["used_as_key"] = True
                if ref.detail and not w["local_type"]:
                    w["local_type"] = ref.detail            # local join field's type
                pf = _partner_field(ref.local_join_field)
                if pf:
                    w["hints"].append((pf, "join_partner",
                                       f"{src_file}: joins local {ref.local_join_field}"))
                    if not w["name"]:                        # infer the name from the join partner
                        w["name"], w["name_inferred"], w["name_from"] = pf, True, ref.local_join_field
        if contributed:
            iface.contributing_files.append(src_file)

    # materialize fields from working records onto their tables
    for (tkey, fident), w in fwork.items():
        ftype, conf, why = infer_field_type(
            used_as_key=w["used_as_key"], local_join_type=w["local_type"])
        display = w["name"] or (f"field #{w['field_id']}" if w["field_id"] else "(unnamed field)")
        if w["name_inferred"] and w["name_from"]:
            why = f"name inferred from join partner {w['name_from']}; " + why
        f = ReconstructedField(
            name=display, field_id=w["field_id"], name_is_inferred=w["name_inferred"],
            inferred_type=ftype, confidence=conf, rationale=why,
            used_as_key=w["used_as_key"], referenced_by=w["refs"],
            candidate_names=_collect_candidates(w["hints"], w["read_name"]))
        w["table"].fields.append(f)

    # fold same-physical-table aliases together (PricingLine ≡ ContractPricingLine, etc.),
    # cross-filling names a sibling recovered through one TO onto another's blanks
    tables = _merge_duplicate_tables(tables)

    # stable ordering: tables by name; fields key-first then by name; scripts by name
    for t in tables.values():
        t.fields.sort(key=lambda x: (not x.used_as_key, _norm(x.name)))
    iface.tables = sorted(tables.values(), key=lambda t: _norm(t.name))
    iface.scripts = sorted(scripts.values(), key=lambda s: _norm(s.name))
    iface.blind_spots = list(_BLIND_SPOTS)
    return iface
