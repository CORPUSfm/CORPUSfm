"""Generate a self-contained HTML Diff report for two FM snapshots.

Public API:
    generate_diff_html(inp: ArtifactDiffInput) -> Path

Only changed items are included — unchanged items are omitted.
"""

from __future__ import annotations

import difflib
import json
import tempfile
from corpusfm.core import safe_xml as ET
from datetime import datetime, timezone
from pathlib import Path

import corpusfm
from corpusfm.app.sections import SECTION_ORDER
from corpusfm.core.git_formatter._renderer import DEFAULT_LARGE_THRESHOLD, large_marker

_VENDOR_DIR = Path(__file__).parent / "vendor"
_ASSETS_DIR = Path(__file__).parent / "assets"

_SECTION_LABELS = {k: v for k, v in SECTION_ORDER}


def _load_vendor(name: str) -> str:
    p = _VENDOR_DIR / name
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _load_asset(name: str) -> str:
    p = _ASSETS_DIR / name
    content = p.read_text(encoding="utf-8") if p.exists() else ""
    if content.startswith("<?xml"):
        content = content[content.index("?>") + 2:].lstrip()
    return content

def _load_highlight_asset() -> str:
    """The ONE FM syntax highlighter (packet 1295): the Explorer's canonical
    templates/explorer_highlight.js, inlined VERBATIM into the Diff page. Loaded straight from
    the templates directory — never a second copy, never the Explorer generator's private
    loader. A guard asserts the exact asset bytes appear once per generated page and that this
    module defines no tokenizer of its own."""
    return (Path(__file__).parent / "templates" / "explorer_highlight.js").read_text(encoding="utf-8")



def _bound_line(ln: str) -> str:
    """Oversize presentation cap (packet 1282): a rendered line whose UTF-8 encoding exceeds the
    git formatter's 512 KiB threshold is replaced with its `[LARGE_CONTENT: …, SHA256: …]` marker
    BEFORE diffing and highlighting — identical blobs then diff as one equal marker line, a
    changed blob as one - / + pair, and the multi-megabyte text never enters SequenceMatcher,
    the Python highlighters, or the page."""
    encoded = ln.encode("utf-8")
    if len(encoded) <= DEFAULT_LARGE_THRESHOLD:
        return ln
    return ln[: len(ln) - len(ln.lstrip())] + large_marker(encoded)


def _bound_body(body: str) -> str:
    # BYTES, not characters (packet 1295 closed a 1282 hole): a body under the threshold in
    # Python characters can exceed it in UTF-8 bytes, and the threshold is a byte bound. The
    # char fast path stays only where it PROVES the byte bound (4 bytes/char worst case).
    if not body or len(body) * 4 <= DEFAULT_LARGE_THRESHOLD:
        return body
    if len(body.encode("utf-8")) <= DEFAULT_LARGE_THRESHOLD:
        return body
    return "\n".join(_bound_line(ln) for ln in body.splitlines())


def _step_diff_lines(lines_a: list[str], lines_b: list[str]) -> list[str]:
    """Compute unified-style diff between two lists of rendered step lines."""
    lines_a = [_bound_line(l) for l in lines_a]
    lines_b = [_bound_line(l) for l in lines_b]
    out: list[str] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, lines_a, lines_b, autojunk=False).get_opcodes():
        if tag == "equal":
            out.extend(f"  {l}" for l in lines_a[i1:i2])
        elif tag in ("replace", "delete"):
            out.extend(f"- {l}" for l in lines_a[i1:i2])
            if tag == "replace":
                out.extend(f"+ {l}" for l in lines_b[j1:j2])
        elif tag == "insert":
            out.extend(f"+ {l}" for l in lines_b[j1:j2])
    return out


# High-stakes change detection: some changes are dangerous out of proportion to how
# they look in a diff — a field going stored↔unstored or global (breaks indexing /
# match keys / finds), or a privilege set's access changing. Flag them for a badge so
# they aren't a buried line. Tokens are matched against changed (+/-) diff lines.
_HIGH_STAKES = {
    "FieldsForTables": (("Storage:", "Indexing:", "Repetitions:"), "storage"),
    "PrivilegeSetsCatalog": (("Records ", "Layouts ", "Value Lists", "Scripts ",
                              "Create=", "Edit=", "Delete=", "access to", "Custom"), "permission"),
}


def _high_stakes_flags(section_key: str, diff_lines: list) -> list:
    spec = _HIGH_STAKES.get(section_key)
    if not spec:
        return []
    tokens, label = spec
    for ln in diff_lines:
        if ln[:1] in ("+", "-") and any(t in ln for t in tokens):
            return [label]
    return []


_FLAG_LABEL = {"storage": "⚠ STORAGE", "permission": "⚠ PERMISSION"}


def _flags_html(item: dict) -> str:
    return "".join(
        f'<span class="hs-badge hs-{f}">{_FLAG_LABEL.get(f, f.upper())}</span>'
        for f in item.get("flags", []))


def _fmt_ts(ts: str) -> str:
    try:
        d, t = ts.split("_", 1)
        return f"{d} {t[:2]}:{t[2:4]}"
    except Exception:
        return ts


# ── Artifact helpers ───────────────────────────────────────────────────────────

def _make_section_index(art) -> "dict[str, dict]":
    """Build {section: {name: ArtifactItem}} from an Artifact."""
    idx: dict = {}
    for item in art.items.values():
        idx.setdefault(item.section, {})[item.name] = item
    return idx


def _fields_items_by_table(art) -> "dict[str, dict]":
    """Build {table: {field_name: ArtifactItem}} for FieldsForTables non-folder items."""
    tables: dict = {}
    for item in art.items.values():
        if item.section != "FieldsForTables" or item.is_folder:
            continue
        name = item.name
        if "::" in name:
            table, field = name.split("::", 1)
        elif item.folder_path:
            table, field = item.folder_path[0], name
        else:
            continue
        tables.setdefault(table, {})[field] = item
    return tables


def _layout_behavior_lines(item) -> list:
    """A deterministic list of a layout's object behavior calcs (hide-when +
    conditional-formatting conditions), for the Diff's own layout comparison.

    These calcs are intentionally NOT in rendered_text (see render_layout), so the
    Diff compares them separately — keeping layout presentation logic out of the
    shared rendered layer. Lines are sorted so the diff is order-independent."""
    from corpusfm.core.layout_objects import extract_layout_objects
    xml = item.xml_sources[0].xml if item.xml_sources else ""
    out: list = []
    for o in extract_layout_objects(xml):
        who = o.label or o.field or o.name or o.type
        if o.hide:
            out.append(f"[{who}] hide when: {o.hide}")
        for c in (o.cond_format_calcs or []):
            out.append(f"[{who}] conditional format: {c}")
        if o.anchors:
            out.append(f"[{who}] anchored: {' + '.join(o.anchors)}")
    return sorted(out)


def _build_data_from_artifacts(inp: "ArtifactDiffInput") -> dict:
    """Build diff data dict from two Artifact objects — no XML re-parse."""
    from corpusfm.core.comparator import compare_artifacts

    art_a = inp.artifact_a
    art_b = inp.artifact_b
    cr = compare_artifacts(art_a, art_b)

    idx_a = _make_section_index(art_a)
    idx_b = _make_section_index(art_b)

    ts_a = _fmt_ts(inp.meta_a.timestamp)
    ts_b = _fmt_ts(inp.meta_b.timestamp)

    metadata = {
        "label_a": cr.label_a,
        "label_b": cr.label_b,
        "timestamp_a": ts_a,
        "timestamp_b": ts_b,
        "fm_key": inp.meta_b.file_name,
        "total": cr.total_real,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "app_version": corpusfm.__version__,
        # Ingest build of each side — the version that baked its rendered_text (the
        # Diff fingerprint). If they differ, a "change" could be a render-version skew.
        "build_a": art_a.provenance.corpusfm_build or "?",
        "build_b": art_b.provenance.corpusfm_build or "?",
    }

    sections: list[dict] = []

    for section_key, section_label in SECTION_ORDER:
        sec_data: dict = {"key": section_key, "label": section_label,
                          "added": [], "removed": [], "changed": []}
        has_any = False

        if section_key == "FieldsForTables":
            if cr.fields:
                flds_a = _fields_items_by_table(art_a)
                flds_b = _fields_items_by_table(art_b)
                tables: list[dict] = []
                for table, sr in cr.fields.items():
                    tbl: dict = {"name": table, "added": list(sr.added),
                                 "removed": list(sr.removed), "changed": []}
                    for fn in sr.changed:
                        item_a = flds_a.get(table, {}).get(fn)
                        item_b = flds_b.get(table, {}).get(fn)
                        b_a = (item_a.rendered_text or "").splitlines() if item_a else []
                        b_b = (item_b.rendered_text or "").splitlines() if item_b else []
                        fdiff = _step_diff_lines(b_a, b_b)
                        fentry = {"name": fn, "diff_lines": fdiff}
                        flags = _high_stakes_flags("FieldsForTables", fdiff)
                        if flags:
                            fentry["flags"] = flags
                        tbl["changed"].append(fentry)
                    tables.append(tbl)
                sec_data["tables"] = tables
                has_any = True

        elif section_key == "LayoutCatalog":
            # Layout-object behavior calcs (hide / conditional formatting) are NOT in
            # rendered_text (see render_layout), so the Diff compares them itself — and
            # flags a layout as changed on a behavior-calc change even when its
            # rendered_text is identical. Kept separate from the shared rendered layer.
            sr = cr.sections.get(section_key)
            items_a = idx_a.get(section_key, {})
            items_b = idx_b.get(section_key, {})
            if sr:
                for n in sr.added:
                    item = items_b.get(n)
                    is_fldr = item.is_folder if item else False
                    sec_data["added"].append({"name": n, "is_folder": is_fldr,
                        "body": "(folder)" if is_fldr else ((item.rendered_text or "") if item else "")})
                    has_any = True
                for n in sr.removed:
                    item = items_a.get(n)
                    is_fldr = item.is_folder if item else False
                    sec_data["removed"].append({"name": n, "is_folder": is_fldr,
                        "body": "(folder)" if is_fldr else ((item.rendered_text or "") if item else "")})
                    has_any = True
            rt_changed = set(sr.changed) if sr else set()
            for n in items_a:
                ib = items_b.get(n)
                ia = items_a[n]
                if ib is None or ia.is_folder or ib.is_folder:
                    continue
                entry = {"name": n}
                if n in rt_changed:
                    entry["diff_lines"] = _step_diff_lines(
                        (ia.rendered_text or "").splitlines(), (ib.rendered_text or "").splitlines())
                ba, bb = _layout_behavior_lines(ia), _layout_behavior_lines(ib)
                if ba != bb:
                    bdiff = [l for l in _step_diff_lines(ba, bb) if l[:1] in ("+", "-")]
                    if bdiff:
                        entry["behavior_lines"] = bdiff
                if "diff_lines" in entry or "behavior_lines" in entry:
                    sec_data["changed"].append(entry)
                    has_any = True
            sec_data["changed"].sort(key=lambda e: e["name"].lower())

        else:
            sr = cr.sections.get(section_key)
            if not sr or not sr.has_diff:
                continue
            items_a = idx_a.get(section_key, {})
            items_b = idx_b.get(section_key, {})

            for n in sr.added:
                item = items_b.get(n)
                is_fldr = item.is_folder if item else False
                body = "(folder)" if is_fldr else ((item.rendered_text or "") if item else "")
                entry: dict = {"name": n, "body": body}
                if section_key == "ScriptCatalog":
                    entry["is_folder"] = is_fldr
                sec_data["added"].append(entry)
                has_any = True

            for n in sr.removed:
                item = items_a.get(n)
                is_fldr = item.is_folder if item else False
                body = "(folder)" if is_fldr else ((item.rendered_text or "") if item else "")
                entry = {"name": n, "body": body}
                if section_key == "ScriptCatalog":
                    entry["is_folder"] = is_fldr
                sec_data["removed"].append(entry)
                has_any = True

            for n in sr.changed:
                item_a = items_a.get(n)
                item_b = items_b.get(n)
                is_fldr = (item_b.is_folder if item_b else False) or (item_a.is_folder if item_a else False)
                lines_a = (item_a.rendered_text or "").splitlines() if item_a else []
                lines_b = (item_b.rendered_text or "").splitlines() if item_b else []
                diff = _step_diff_lines(lines_a, lines_b)
                entry = {"name": n, "diff_lines": diff}
                flags = _high_stakes_flags(section_key, diff)
                if flags:
                    entry["flags"] = flags
                if section_key == "ScriptCatalog":
                    entry["is_folder"] = is_fldr
                    entry["count_a"] = len(lines_a)
                    entry["count_b"] = len(lines_b)
                sec_data["changed"].append(entry)
                has_any = True

        if has_any:
            sections.append(sec_data)

    # The behavioral workflow-delta SUMMARY is no longer emitted into the Diff (inbox
    # packet 002, Batch 2): Diff is the human lens over concrete changed artifact content.
    # `_workflow_deltas` is kept (below) as a builder for MCP + tests.
    return {"metadata": metadata, "sections": sections}


# ── Workflow (behavioral) delta ─────────────────────────────────────────────

def _workflow_deltas(art_a, art_b) -> list:
    """Behavioral-level diff: how each workflow's blast radius changed between versions
    ("Send now writes 5 more fields, reaches a new table"). Matches workflows by entry
    script; reports added/removed writes/reads/calls/conditions/triggers + new/removed
    entry points. The rung-4 view diffed — what the solution now DOES differently."""
    try:
        from corpusfm.core.workflows import extract_workflows
        wa = {w.entry_name: w for w in extract_workflows(art_a, max_workflows=2000).workflows}
        wb = {w.entry_name: w for w in extract_workflows(art_b, max_workflows=2000).workflows}
    except Exception:
        return []

    _FIELDS = ("writes", "reads", "calls", "conditions", "triggers", "sql_tables", "lands_in")
    out: list = []
    for name in sorted(set(wa) | set(wb)):
        a, b = wa.get(name), wb.get(name)
        if a and not b:
            out.append({"name": name, "status": "removed"})
            continue
        if b and not a:
            out.append({"name": name, "status": "new",
                        "writes": len(b.writes), "reads": len(b.reads), "calls": len(b.calls)})
            continue
        changes: dict = {}
        for f in _FIELDS:
            sa, sb = set(getattr(a, f)), set(getattr(b, f))
            added, removed = sorted(sb - sa), sorted(sa - sb)
            if added or removed:
                changes[f] = {"added": added, "removed": removed}
        if changes:
            out.append({"name": name, "status": "changed", "changes": changes})
    return out


# ── Data builder ───────────────────────────────────────────────────────────────


# ── CSS ────────────────────────────────────────────────────────────────────────

_CSS = """\
:root{
  --bg:#111315;--surface:#191b1d;--surface-2:#222529;--surface-hover:#292d31;
  --border:#30353a;--border-2:#383d42;
  --text:#d2d6da;--text-dim:#7c838a;--text-2:#b9bec3;--text-3:#9ea4aa;
  --control-fill:#59636c;--interactive:#b3bac1;--interactive-tint:rgba(179,186,193,.12);
  --focus-ring:#b3bac1;--primary:var(--interactive);--primary-tint:var(--interactive-tint);
  --code-bg:#181a1d;--code-text:#d4d4d4;
  --link:#4e9eff;--warning:#f5a623;--text-muted:#555;
  --unused:#e8742a;--unused-bg:#1f1000;
  --diff-add:#3fb950;--diff-rem:#f85149;--diff-chg:#73a0c5;
  --diff-add-bg:#1a3a24;--diff-add-bd:#2a5030;
  --diff-rem-bg:#3a1a1a;--diff-rem-bd:#502020;
  --diff-chg-bg:#162634;--diff-chg-bd:#28465e;
}
[data-theme="light"]{
  --bg:#f4f5f6;--surface:#fff;--surface-2:#e9ebed;--surface-hover:#dfe2e5;
  --border:#d1d5d8;--border-2:#b9bec3;
  --text:#1a1a1a;--text-dim:#666666;--text-2:#444444;--text-3:#6b6b6b;
  --control-fill:#4f5962;--interactive:#47515a;--interactive-tint:rgba(79,89,98,.10);
  --focus-ring:#59636c;--primary:var(--interactive);--primary-tint:var(--interactive-tint);
  --code-bg:#e8e8e8;--code-text:#383a42;
  --link:#2a7ae4;--warning:#c47d00;--text-muted:#9898a8;
  --unused:#c85e10;--unused-bg:#fff0e6;
  --diff-add:#1a7f37;--diff-rem:#cf222e;--diff-chg:#356a94;
  --diff-add-bg:#dafbe1;--diff-add-bd:#aceebb;
  --diff-rem-bg:#ffebe9;--diff-rem-bd:#ffb8b0;
  --diff-chg-bg:#e5f0f8;--diff-chg-bd:#a9c6dc;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh}
button:focus-visible,a:focus-visible{
  outline:2px solid var(--focus-ring);outline-offset:2px}
#hdr{background:var(--surface);border-bottom:1px solid var(--border);
  padding:.6rem 1.5rem;display:flex;align-items:center;gap:.75rem}
#hdr-wordmark-dark,#hdr-wordmark-light{flex-shrink:0;display:flex;align-items:center}
#hdr-wordmark-dark svg,#hdr-wordmark-light svg{height:26px;width:auto;display:block}
#hdr-wordmark-light{display:none}
[data-theme="light"] #hdr-wordmark-dark{display:none}
[data-theme="light"] #hdr-wordmark-light{display:flex}
#hdr h1{font-size:1rem;font-weight:600;color:var(--text);white-space:nowrap;margin:0}
#hdr .sub{font-size:.8rem;color:var(--text-dim);flex:1;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#hdr-btns{display:flex;align-items:center;gap:.4rem;flex-shrink:0}
.icon-btn{display:flex;align-items:center;justify-content:center;width:32px;height:32px;
  background:none;border:none;color:var(--text-3);cursor:pointer;border-radius:6px;flex-shrink:0}
.icon-btn:hover{color:var(--primary)}
[data-theme="dark"] #theme-moon{display:none}
[data-theme="light"] #theme-sun{display:none}
#total-bar{padding:.45rem 1.5rem;font-size:.82rem;color:var(--text-dim);
  border-bottom:1px solid var(--border)}
#total-bar strong{color:var(--text)}
#summary{padding:.6rem 1.5rem;display:flex;flex-wrap:wrap;gap:.4rem;
  position:sticky;top:0;z-index:100;background:var(--bg);
  border-bottom:1px solid var(--border)}
.sum-card{background:var(--surface);border:none;border-radius:4px;
  padding:.4rem .7rem;min-width:110px;cursor:pointer;transition:background .15s}
.sum-card:hover{background:var(--surface-hover)}
.sum-card .sec-name{font-size:.72rem;color:var(--text-dim);
  text-transform:uppercase;letter-spacing:.04em}
.sum-card .counts{font-size:.88rem;font-weight:600;margin-top:.2rem}
.add{color:var(--diff-add)}.rem{color:var(--diff-rem)}.chg{color:var(--diff-chg)}
.diff-add{display:block;color:var(--diff-add);background:rgba(63,185,80,.08);border-left:3px solid var(--diff-add);padding-left:.4rem}
.diff-rem{display:block;color:var(--diff-rem);background:rgba(248,81,73,.08);border-left:3px solid var(--diff-rem);padding-left:.4rem}
.diff-eq{display:block;color:var(--code-text);border-left:3px solid transparent;padding-left:.4rem}
.step-verb{color:var(--script-verb)}.step-cmt{color:var(--script-comment)}.step-str{color:var(--script-string)}
.step-field{color:var(--script-field)}.step-bracket{color:var(--script-punct)}.step-sep{color:var(--script-punct)}
.step-warn{color:var(--warning)}
.cf-cmt{color:var(--calc-comment)}.cf-str{color:var(--calc-string)}.cf-num{color:var(--calc-number)}
.cf-field{color:var(--calc-field)}.cf-func{color:var(--calc-function)}.cf-kw{color:var(--calc-keyword)}
.cf-op{color:var(--calc-operator)}
#content{padding:.5rem 1.5rem 2.5rem}
.sec-block{margin-bottom:1.25rem}
.sec-hdr{font-size:.9rem;font-weight:700;color:var(--primary);padding:.45rem 0;
  margin-bottom:.5rem;cursor:pointer;
  display:flex;align-items:center;gap:.5rem;user-select:none}
.sec-label{flex:1}
.sec-counts{font-size:.75rem;font-weight:400;color:var(--text-dim)}
.sec-caret{display:flex;align-items:center;color:var(--text-3);flex-shrink:0;
  transition:transform .2s;transform:rotate(0deg)}
.sec-block.closed .sec-caret{transform:rotate(-90deg)}
.item-block{margin:.35rem 0}
.item-hdr{padding:.3rem .6rem;border-radius:4px;cursor:pointer;
  display:flex;align-items:center;gap:.5rem;font-size:.82rem;font-weight:600;
  user-select:none;transition:filter .1s}
.item-hdr:hover{filter:brightness(1.08)}
.item-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hs-badge{flex-shrink:0;margin-left:.5rem;padding:.05rem .4rem;border-radius:3px;font-size:.64rem;font-weight:700;letter-spacing:.04em}
.hs-storage{background:rgba(245,166,35,.18);color:#f5a623;border:1px solid rgba(245,166,35,.5)}
.hs-permission{background:rgba(221,0,0,.16);color:#ff6b6b;border:1px solid rgba(221,0,0,.5)}
.wd-row{display:flex;gap:.6rem;align-items:baseline;padding:.3rem .6rem;border-bottom:1px solid var(--border,#2e2e2e);flex-wrap:wrap}
.wd-tag{flex-shrink:0;font-size:.62rem;font-weight:700;letter-spacing:.04em;padding:.05rem .4rem;border-radius:3px}
.wd-new{background:rgba(91,191,143,.16);color:#5bbf8f;border:1px solid rgba(91,191,143,.5)}
.wd-chg{background:var(--diff-chg-bg);color:var(--diff-chg);border:1px solid var(--diff-chg-bd)}
.wd-rem{background:rgba(221,0,0,.14);color:#ff6b6b;border:1px solid rgba(221,0,0,.45)}
.wd-name{font-weight:600;font-family:'SFMono-Regular',Consolas,monospace;font-size:.82rem;flex-shrink:0}
.wd-detail{font-size:.74rem;display:flex;gap:.7rem;flex-wrap:wrap}
.wd-add{color:#5bbf8f}
.wd-del{color:#e0794b}
.item-caret{display:flex;align-items:center;color:var(--text-3);flex-shrink:0;
  transition:transform .2s;transform:rotate(-90deg)}
.item-hdr.open .item-caret{transform:rotate(0deg)}
.tag-add{background:var(--diff-add-bg);border:1px solid var(--diff-add-bd);color:var(--diff-add)}
.tag-rem{background:var(--diff-rem-bg);border:1px solid var(--diff-rem-bd);color:var(--diff-rem)}
.tag-chg{background:var(--diff-chg-bg);border:1px solid var(--diff-chg-bd);color:var(--diff-chg)}
.icon{font-size:.85rem;flex-shrink:0}
.item-body{display:none;background:transparent;
  margin:.2rem 0 .4rem;overflow:hidden}
.item-body.open{display:block}
.item-body pre{padding:.65rem .75rem;font-size:.75rem;
  font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;
  white-space:pre-wrap;word-break:break-word;line-height:1.55;
  color:var(--code-text);overflow-x:auto}
.tbl-name{font-size:.8rem;font-weight:600;color:var(--text-2);
  margin:.5rem 0 .2rem;padding:.2rem .5rem}
.behav-lbl{font-size:.7rem;font-weight:600;color:var(--diff-chg);text-transform:uppercase;
  letter-spacing:.04em;margin:.5rem 0 .15rem}
.field-row{font-size:.78rem;padding:.15rem .6rem;border-radius:4px;margin:.1rem 0}
.field-add{background:var(--diff-add-bg);color:var(--diff-add)}
.field-rem{background:var(--diff-rem-bg);color:var(--diff-rem)}
#back-top{position:fixed;bottom:1.5rem;right:1.5rem;background:var(--surface);
  border:none;color:var(--text-dim);border-radius:6px;
  padding:.35rem .85rem;font-size:.8rem;cursor:pointer;z-index:200;
  box-shadow:0 2px 8px rgba(0,0,0,.35)}
#back-top:hover{color:var(--primary)}
"""

# ── HTML template ──────────────────────────────────────────────────────────────

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="corpusfm-calculation-palette" content="{calculation_palette}">
<meta name="corpusfm-script-palette" content="{script_palette}">
<meta name="corpusfm-syntax-palette-version" content="{palette_version}">
<title>{title}</title>
<style>{css}</style>
<script>(function(){{try{{var t=localStorage.getItem('fmc_theme');document.documentElement.setAttribute('data-theme',t||'dark');}}catch(e){{document.documentElement.setAttribute('data-theme','dark');}}}})()</script>
</head>
<body>
<div id="hdr">
  <div id="hdr-wordmark-dark">{header_wordmark}</div>
  <div id="hdr-wordmark-light">{header_wordmark_light}</div>
  <h1>Diff</h1>
  <div class="sub">{label_a} &nbsp;↔&nbsp; {label_b}</div>
  <div id="hdr-btns">
    <button id="theme-btn" class="icon-btn" type="button" onclick="_toggleTheme()" title="Toggle theme">
      <svg id="theme-sun" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
      <svg id="theme-moon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"/></svg>
    </button>
    <button class="icon-btn" type="button" onclick="_saveDiff()" title="Save As…">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/></svg>
    </button>
  </div>
</div>
<div id="total-bar">
  <strong>{total}</strong> difference{total_s} &nbsp;·&nbsp; {ts_a} vs {ts_b}
  &nbsp;·&nbsp; ingested A {build_a} / B {build_b}
  &nbsp;·&nbsp; Generated {generated_at} &nbsp;·&nbsp; CorpusFM {app_version}
</div>
<div id="summary">
{summary_cards}
</div>
<div id="content">
{sections_html}
</div>
<button id="back-top" onclick="window.scrollTo({{top:0,behavior:'smooth'}})" title="Back to top">↑ Top</button>
<script>
async function _saveDiff() {{
  var filename = {filename};
  var html = '<!DOCTYPE html>\\n' + document.documentElement.outerHTML;
  var blob = new Blob([html], {{type: 'text/html; charset=utf-8'}});
  if (window.showSaveFilePicker) {{
    try {{
      var handle = await window.showSaveFilePicker({{
        suggestedName: filename,
        types: [{{description: 'HTML file', accept: {{'text/html': ['.html']}}}}]
      }});
      var writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      return;
    }} catch (e) {{
      if (e.name === 'AbortError') return;
    }}
  }}
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function(){{URL.revokeObjectURL(url);}}, 1000);
}}
// ONE FM syntax highlighter (packet 1295): the canonical Explorer asset is inlined VERBATIM
// below via a .format replacement VALUE — values are not brace-parsed, so the old hand-copied,
// brace-doubled fork (and its CAUTION hazard) is gone. This file defines no tokenizer.
{highlight_js}
// Diff-only presentation adapters — no token rules, no escaping fork. Every path below reads
// textContent and writes ONLY the canonical highlighter's escaped output back as innerHTML, so
// FM-controlled text (an <img onerror=...> in a step name, a closing script tag in a calc)
// stays text. (No literal closing-script-tag may appear in THIS block either — it would end it.)
function _dhEsc(s){{return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
function hlLine(raw){{
  var trimmed=raw.trimStart();
  if(!trimmed)return _dhEsc(raw);
  var indent=raw.slice(0,raw.length-trimmed.length);
  return _dhEsc(indent)+fmStepHighlight(trimmed);
}}
// Load-time highlighting driven by TRUSTED classification emitted at generation time:
// data-hl="step"|"calc" names the tokenizer; data-diff marks two-character-prefixed diff spans
// (the prefix stays OUTSIDE the tokenizer). Unclassified <pre> blocks (folders, layout
// behavior) stay plain. data-hl-done makes the pass idempotent, so a saved copy of the page
// reopens without double-processing.
(function(){{
  document.querySelectorAll('pre[data-hl]').forEach(function(pre){{
    if(pre.getAttribute('data-hl-done'))return;
    var mode=pre.getAttribute('data-hl');
    if(pre.hasAttribute('data-diff')){{
      pre.querySelectorAll('.diff-add,.diff-rem,.diff-eq').forEach(function(span){{
        var t=span.textContent,pfx=t.slice(0,2),body=t.slice(2);
        span.innerHTML=_dhEsc(pfx)+(mode==='calc'?fmHighlight(body):hlLine(body));
      }});
    }} else if(mode==='calc'){{
      pre.innerHTML=fmHighlight(pre.textContent);   // whole body: a multiline /* */ stays one comment
    }} else {{
      pre.innerHTML=pre.textContent.split('\\n').map(hlLine).join('\\n');   // backslash-n stays literal in this regular Python str
    }}
    pre.setAttribute('data-hl-done','1');
  }});
}})();
// Theme toggle// Theme toggle
function _toggleTheme() {{
  var t = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
  try {{ localStorage.setItem('fmc_theme', t); }} catch(e) {{}}
}}
// Section accordion — starts open, click closes
document.querySelectorAll('.sec-hdr').forEach(function(hdr) {{
  var block = hdr.closest('.sec-block');
  var body = block.querySelector('.sec-body');
  hdr.addEventListener('click', function() {{
    block.classList.toggle('closed');
    body.style.display = block.classList.contains('closed') ? 'none' : '';
  }});
}});
// Item accordion — starts closed, click opens
document.querySelectorAll('.item-hdr').forEach(function(hdr) {{
  var body = hdr.nextElementSibling;
  hdr.addEventListener('click', function() {{
    body.classList.toggle('open');
    hdr.classList.toggle('open');
  }});
}});
// Scroll to section if clicked from summary
document.querySelectorAll('.sum-card[data-sec]').forEach(card => {{
  card.addEventListener('click', () => {{
    const el = document.getElementById('sec-' + card.dataset.sec);
    if (el) el.scrollIntoView({{behavior: 'smooth'}});
  }});
}});
// Keyboard navigation: j/k = next/prev section, t = top, ? = shortcut help
(function() {{
  var _kbdEl = null;
  function _secHdrs() {{ return Array.from(document.querySelectorAll('.sec-hdr')); }}
  document.addEventListener('keydown', function(e) {{
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === 'Escape') {{
      if (_kbdEl) {{ _kbdEl.remove(); _kbdEl = null; }}
      return;
    }}
    if (e.key === 't') {{
      window.scrollTo({{top: 0, behavior: 'smooth'}});
      return;
    }}
    if (e.key === 'j' || e.key === 'k') {{
      var hdrs = _secHdrs();
      var scrollY = window.scrollY;
      if (e.key === 'j') {{
        var next = hdrs.find(function(h) {{ return h.offsetTop > scrollY + 4; }});
        if (next) next.scrollIntoView({{behavior: 'smooth', block: 'start'}});
      }} else {{
        var above = hdrs.filter(function(h) {{ return h.offsetTop < scrollY - 4; }});
        if (above.length) above[above.length - 1].scrollIntoView({{behavior: 'smooth', block: 'start'}});
      }}
      return;
    }}
    if (e.key === '?') {{
      if (_kbdEl) {{ _kbdEl.remove(); _kbdEl = null; return; }}
      _kbdEl = document.createElement('div');
      _kbdEl.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:900;display:flex;align-items:center;justify-content:center';
      _kbdEl.innerHTML = '<div style="background:#1a1c23;border:1px solid #444;border-radius:8px;padding:1.25rem 1.5rem;min-width:300px;font-family:system-ui,sans-serif;color:#fafafa;box-shadow:0 8px 32px rgba(0,0,0,.5)">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.85rem"><strong style="font-size:.95rem">Keyboard shortcuts</strong>' +
        '<button onclick="this.closest(\\'[style*=fixed]\\').remove()" style="background:none;border:none;color:#888;cursor:pointer;font-size:1.1rem;line-height:1">✕</button></div>' +
        '<table style="border-collapse:collapse;font-size:.82rem;width:100%">' +
        '<tr><td style="padding:.28rem .6rem .28rem 0;white-space:nowrap"><kbd style="background:#1e2030;border:1px solid #444;border-radius:3px;padding:.05rem .35rem;font-family:monospace;font-size:.75rem">j</kbd></td><td style="color:#ccc;padding:.28rem 0">Next changed section</td></tr>' +
        '<tr><td><kbd style="background:#1e2030;border:1px solid #444;border-radius:3px;padding:.05rem .35rem;font-family:monospace;font-size:.75rem">k</kbd></td><td style="color:#ccc">Previous changed section</td></tr>' +
        '<tr><td><kbd style="background:#1e2030;border:1px solid #444;border-radius:3px;padding:.05rem .35rem;font-family:monospace;font-size:.75rem">t</kbd></td><td style="color:#ccc">Back to top</td></tr>' +
        '<tr><td><kbd style="background:#1e2030;border:1px solid #444;border-radius:3px;padding:.05rem .35rem;font-family:monospace;font-size:.75rem">?</kbd></td><td style="color:#ccc">Show / hide this reference</td></tr>' +
        '<tr><td><kbd style="background:#1e2030;border:1px solid #444;border-radius:3px;padding:.05rem .35rem;font-family:monospace;font-size:.75rem">Esc</kbd></td><td style="color:#ccc">Close this panel</td></tr>' +
        '</table></div>';
      _kbdEl.addEventListener('click', function(ev) {{ if (ev.target === _kbdEl) {{ _kbdEl.remove(); _kbdEl = null; }} }});
      document.body.appendChild(_kbdEl);
      return;
    }}
  }});
}})();
</script>
</body>
</html>
"""


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _js_str(value: str) -> str:
    """A safe JS string literal for a <script> block: JSON-encode + split `</` so an FM name
    containing `</script>` can't close the element. The filename derives from the FM `File=`
    attribute (attacker-influenceable) — never interpolate it into JS raw."""
    return json.dumps(value).replace("</", "<\\/")


def _diff_pre(lines: list[str]) -> str:
    parts = []
    for ln in lines:
        if ln.startswith("+ "):
            parts.append(f'<span class="diff-add">{_esc(ln)}</span>')
        elif ln.startswith("- "):
            parts.append(f'<span class="diff-rem">{_esc(ln)}</span>')
        else:
            parts.append(f'<span class="diff-eq">{_esc(ln)}</span>')
    return "".join(parts)


def _render_html(data: dict, filename: str = "diff.html", syntax_palettes: object = None) -> str:
    from corpusfm.extensions.export.syntax_palettes import palette_css, resolve_selection
    selected = resolve_selection(syntax_palettes)
    meta = data["metadata"]
    sections = data["sections"]

    # Summary cards
    cards = []
    for sec in sections:
        key = sec["key"]
        label = sec["label"]
        added   = len(sec.get("added", []))
        removed = len(sec.get("removed", []))
        changed = len(sec.get("changed", []))
        if sec.get("tables"):
            for t in sec["tables"]:
                added   += len(t.get("added", []))
                removed += len(t.get("removed", []))
                changed += len(t.get("changed", []))
        parts = []
        if added:   parts.append(f'<span class="add">+{added}</span>')
        if removed: parts.append(f'<span class="rem">-{removed}</span>')
        if changed: parts.append(f'<span class="chg">~{changed}</span>')
        counts = "&nbsp;".join(parts) if parts else "—"
        cards.append(
            f'<div class="sum-card" data-sec="{_esc(key)}">'
            f'<div class="sec-name">{_esc(label)}</div>'
            f'<div class="counts">{counts}</div>'
            f'</div>'
        )

    # The behavioral "Behavioral changes (workflows)" summary block is no longer rendered
    # (inbox packet 002, Batch 2) — Diff shows concrete changed artifact content only.
    sec_blocks = []

    for sec in sections:
        key = sec["key"]
        label = sec["label"]
        added   = sec.get("added", [])
        removed = sec.get("removed", [])
        changed = sec.get("changed", [])
        tables  = sec.get("tables")

        a_count = len(added) + (sum(len(t.get("added",[])) for t in (tables or [])) if tables else 0)
        r_count = len(removed) + (sum(len(t.get("removed",[])) for t in (tables or [])) if tables else 0)
        c_count = len(changed) + (sum(len(t.get("changed",[])) for t in (tables or [])) if tables else 0)
        count_parts = []
        if a_count: count_parts.append(f'<span class="add">+{a_count} added</span>')
        if r_count: count_parts.append(f'<span class="rem">-{r_count} removed</span>')
        if c_count: count_parts.append(f'<span class="chg">~{c_count} changed</span>')
        counts_str = " &nbsp; ".join(count_parts)

        inner = []

        is_script = (key == "ScriptCatalog")
        is_cf = (key == "CustomFunctionsCatalog")

        # Added
        for item in added:
            name = item["name"]
            is_fldr = item.get("is_folder")
            tag = "📁" if is_fldr else "✅"
            raw_body = _bound_body(item.get("body", ""))
            # ONE highlighter (packet 1295): bodies ship ESCAPED; the page's load-time pass
            # highlights them via the trusted data-hl classification. Folders stay plain.
            body = _esc(raw_body)
            if is_script and not is_fldr:
                pre_attrs = ' data-hl="step"'
            elif is_cf and not is_fldr:
                pre_attrs = ' data-hl="calc"'
            else:
                pre_attrs = ""
            inner.append(
                f'<div class="item-block">'
                f'<div class="item-hdr tag-add"><span class="icon">{tag}</span>'
                f'<span class="item-name">{_esc(name)}</span>'
                f'<span class="item-caret"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg></span></div>'
                f'<div class="item-body"><pre{pre_attrs}>{body}</pre></div>'
                f'</div>'
            )

        # Removed
        for item in removed:
            name = item["name"]
            is_fldr = item.get("is_folder")
            tag = "📁" if is_fldr else "❌"
            raw_body = _bound_body(item.get("body", ""))
            # ONE highlighter (packet 1295): bodies ship ESCAPED; the page's load-time pass
            # highlights them via the trusted data-hl classification. Folders stay plain.
            body = _esc(raw_body)
            if is_script and not is_fldr:
                pre_attrs = ' data-hl="step"'
            elif is_cf and not is_fldr:
                pre_attrs = ' data-hl="calc"'
            else:
                pre_attrs = ""
            inner.append(
                f'<div class="item-block">'
                f'<div class="item-hdr tag-rem"><span class="icon">{tag}</span>'
                f'<span class="item-name">{_esc(name)}</span>'
                f'<span class="item-caret"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg></span></div>'
                f'<div class="item-body"><pre{pre_attrs}>{body}</pre></div>'
                f'</div>'
            )

        # Changed
        for item in changed:
            name = item["name"]
            tag = "📁" if item.get("is_folder") else "🔄"
            diff_lines = item.get("diff_lines", [])
            body_parts = []
            if diff_lines:
                diff_html = _diff_pre(diff_lines)
                if is_cf:
                    pre_attrs = ' data-hl="calc" data-diff="1"'
                elif is_script:
                    pre_attrs = ' data-hl="step" data-diff="1"'
                else:
                    pre_attrs = ""
                body_parts.append(f"<pre{pre_attrs}>{diff_html}</pre>")
            # Layout-object behavior delta (Diff-specific — separate from rendered_text).
            behav = item.get("behavior_lines", [])
            if behav:
                body_parts.append(
                    '<div class="behav-lbl">⚡ Layout behavior — hide / conditional formatting</div>'
                    f'<pre>{_diff_pre(behav)}</pre>')
            inner.append(
                f'<div class="item-block">'
                f'<div class="item-hdr tag-chg"><span class="icon">{tag}</span>'
                f'<span class="item-name">{_esc(name)}</span>{_flags_html(item)}'
                f'<span class="item-caret"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg></span></div>'
                f'<div class="item-body">{"".join(body_parts)}</div>'
                f'</div>'
            )

        # Fields (special table grouping)
        if tables:
            for tbl in tables:
                tname = tbl["name"]
                inner.append(f'<div class="tbl-name">{_esc(tname)}</div>')
                for fn in tbl.get("added", []):
                    inner.append(f'<div class="field-row field-add">✅ {_esc(fn)}</div>')
                for fn in tbl.get("removed", []):
                    inner.append(f'<div class="field-row field-rem">❌ {_esc(fn)}</div>')
                for fc in tbl.get("changed", []):
                    diff_html = _diff_pre(fc.get("diff_lines", []))
                    inner.append(
                        f'<div class="item-block">'
                        f'<div class="item-hdr tag-chg"><span class="icon">🔄</span>'
                        f'<span class="item-name">{_esc(fc["name"])}</span>{_flags_html(fc)}'
                        f'<span class="item-caret"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg></span></div>'
                        f'<div class="item-body"><pre data-hl="calc" data-diff="1">{diff_html}</pre></div>'
                        f'</div>'
                    )

        sec_blocks.append(
            f'<div class="sec-block" id="sec-{_esc(key)}" data-sec="{_esc(key)}">'
            f'<div class="sec-hdr">'
            f'<span class="sec-label">{_esc(label)}</span>'
            f'<span class="sec-counts">{counts_str}</span>'
            f'<span class="sec-caret"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg></span>'
            f'</div>'
            f'<div class="sec-body">{"".join(inner)}</div>'
            f'</div>'
        )

    total = meta["total"]
    return _HTML.format(
        title=f"CorpusFM Diff — {_esc(meta['label_a'])} ↔ {_esc(meta['label_b'])}",
        css=_CSS + "\n" + palette_css(selected),
        calculation_palette=selected.calculation,
        script_palette=selected.script,
        palette_version=selected.as_dict()["version"],
        header_wordmark=_load_asset("corpusfm-wordmark-darkmode.svg"),
        header_wordmark_light=_load_asset("corpusfm-wordmark-lightmode.svg"),
        label_a=_esc(meta["label_a"]),
        label_b=_esc(meta["label_b"]),
        total=total,
        total_s="" if total == 1 else "s",
        ts_a=_esc(meta["timestamp_a"]),
        ts_b=_esc(meta["timestamp_b"]),
        generated_at=_esc(meta["generated_at"]),
        app_version=_esc(meta["app_version"]),
        build_a=_esc(meta.get("build_a", "?")),
        build_b=_esc(meta.get("build_b", "?")),
        summary_cards="\n".join(cards),
        sections_html="\n".join(sec_blocks),
        highlight_js=_load_highlight_asset(),
        filename=_js_str(filename),
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_diff_html(inp: "ArtifactDiffInput", syntax_palettes: object = None) -> Path:
    """Build a self-contained Diff HTML for two artifacts.

    Accepts an ArtifactDiffInput (artifact-based).
    Returns a Path to a file in a system temp directory.
    """
    from corpusfm.extensions.export.contracts import ArtifactDiffInput

    if not isinstance(inp, ArtifactDiffInput):
        raise TypeError("generate_diff_html requires an ArtifactDiffInput")
    data = _build_data_from_artifacts(inp)

    meta = data["metadata"]
    ts_a = inp.meta_a.timestamp
    ts_b = inp.meta_b.timestamp
    out_name = f"{meta['fm_key']}_{ts_a}_vs_{ts_b}_diff.html"
    html = _render_html(data, filename=out_name, syntax_palettes=syntax_palettes)

    tmp_dir = Path(tempfile.mkdtemp(prefix="corpusfm_diff_"))
    # Slugify the ON-DISK name only (packet 082): fm_key derives from the untrusted FM `File=`
    # attribute — path metacharacters must not steer the write outside tmp_dir. The filename
    # embedded in the HTML is escaped separately in _render_html.
    from corpusfm.core.git_formatter._renderer import slugify as _slugify
    out_path = tmp_dir / _slugify(out_name)
    out_path.write_text(html, encoding="utf-8")
    return out_path
