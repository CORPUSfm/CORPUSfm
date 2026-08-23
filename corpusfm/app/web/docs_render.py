"""In-app documentation — render bundled markdown articles.

Articles are markdown files in ``corpusfm/app/web/docs/`` that ship in the repo, so they are
version-locked to the app (whoever runs app version X reads the docs that shipped with X).
Documentation is NEVER stored in the database. Each file carries a small YAML frontmatter:

    ---
    title: ISV Workflow
    slug: isv-workflow      # URL slug (/docs/<slug>); defaults to the filename stem
    order: 20               # sort order in the table of contents
    status: published       # only 'published' is listed/served — drafts stay hidden
    ---
    # ...markdown body...

Only published articles surface, so half-written drafts can sit in the tree without showing.
Per-article ``gate:`` metadata limits articles to signed-in users with the matching access. There
is no public/internal content split or export filter: every supported feature may be documented.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_DOCS_DIR = Path(__file__).parent / "docs"

# In-app docs are authored articles ONLY (this directory). They are an operational/user-facing
# surface for installed, authenticated operators. The dev/agent source of truth — CLAUDE*.md and
# .claude/memory/*.md — is deliberately NOT live-surfaced here: it stays in the repo for agents,
# and are not a second documentation source. (Reconsolidated 2026-06-24:
# previously this file rendered CLAUDE*.md as a "Development" section and .claude/memory/*.md as a
# "Memory" section; both were removed so app docs ≠ a live view over agent working context.)
_SECTION_ORDER = {"Documentation": 0, "Guides": 10}
_DEFAULT_SECTION = "Documentation"

# Cross-reference rewriting (for surfaced dev/memory content): [[wikilinks]] and links to other
# surfaced .md files become in-app /docs/<slug> links; an unresolved [[name]] degrades to code text.
_WIKILINK = re.compile(r"\[\[([^\]\|]+?)\]\]")
_MDLINK = re.compile(r"(?<!\!)\[([^\]]+)\]\(([^)]+)\)")


@dataclass
class DocMeta:
    slug: str
    title: str
    order: int
    status: str
    gate: str              # "" (ungated) or an access gate (e.g. "settings") — see list_docs(gates=)
    section: str           # TOC group: "Documentation" | "Guides"
    path: Path


def _parse(path: Path) -> tuple[DocMeta, str]:
    text = path.read_text(encoding="utf-8")
    meta: dict = {}
    body = text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                meta = yaml.safe_load(parts[1]) or {}
            except Exception:
                meta = {}
            body = parts[2]
    if not isinstance(meta, dict):
        meta = {}
    slug = str(meta.get("slug") or path.stem)
    # Authored reference articles default to Documentation. Problem-centered decision guides opt in
    # to the explicit Guides section; gated authored docs remain alongside reference articles.
    section = str(meta.get("section", "")).strip() or _DEFAULT_SECTION
    return (
        DocMeta(
            slug=slug,
            title=str(meta.get("title") or slug),
            order=int(meta.get("order", 100)),
            status=str(meta.get("status", "published")).lower(),
            gate=str(meta.get("gate", "")).strip(),
            section=section,
            path=path,
        ),
        body,
    )


def _iter_source_metas() -> list[DocMeta]:
    """Every authored article in docs/, unsorted/unfiltered (frontmatter-driven).

    Only authored docs are surfaced in-app — the dev/agent context (CLAUDE*.md, .claude/memory)
    is NOT a live view here; it stays in the repo for agents.
    """
    out: list[DocMeta] = []
    if _DOCS_DIR.exists():
        for p in sorted(_DOCS_DIR.glob("*.md")):
            try:
                meta, _ = _parse(p)
            except Exception:
                continue
            out.append(meta)
    return out


def list_docs(*, gates=None) -> list[DocMeta]:
    """Published articles, sorted by (order, title). Empty if the docs dir is absent.

    ``gates`` enforces per-article access: when a set is passed, an article carrying a
    ``gate:`` frontmatter is dropped unless that gate is in the set. ``gates=None`` (the
    default) disables gate filtering entirely — used by tests and by standalone (all-access)
    where there are no per-user gates.
    """
    out: list[DocMeta] = []
    for meta in _iter_source_metas():
        if meta.status != "published":
            continue
        if gates is not None and meta.gate and meta.gate not in gates:
            continue
        out.append(meta)
    out.sort(key=lambda m: (_SECTION_ORDER.get(m.section, 99), m.order, m.title.lower()))
    return out


def group_by_section(metas: list[DocMeta]) -> list[tuple[str, list[DocMeta]]]:
    """Group an (already-sorted) meta list into ordered (section, [meta]) pairs for a grouped TOC."""
    groups: list[tuple[str, list[DocMeta]]] = []
    for m in metas:
        if not groups or groups[-1][0] != m.section:
            groups.append((m.section, []))
        groups[-1][1].append(m)
    return groups


def _slugify(text: str) -> str:
    s = re.sub(r"<[^>]+>", "", text).strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "section"


def _add_heading_anchors(tokens) -> None:
    """Give every heading a stable, de-duplicated ``id`` so articles can intra-link to a
    subject and the drawer/full page can deep-link ``/docs/<slug>#<anchor>``. Done on the token
    stream (no extra dependency vs. the mdit anchors plugin)."""
    seen: dict[str, int] = {}
    for i, tok in enumerate(tokens):
        if tok.type != "heading_open":
            continue
        inline = tokens[i + 1] if i + 1 < len(tokens) else None
        text = inline.content if inline is not None else ""
        base = _slugify(text)
        n = seen.get(base, 0)
        seen[base] = n + 1
        anchor = base if n == 0 else f"{base}-{n}"
        tok.attrSet("id", anchor)


def _link_map() -> dict:
    """Map a referenced name/filename (stem, basename, and lowercase forms) → its in-app slug,
    for rewriting [[wikilinks]] and cross-doc .md links between authored articles."""
    out: dict = {}
    for m in _iter_source_metas():
        for k in (m.path.stem, m.path.stem.lower(), m.path.name, m.path.name.lower()):
            out.setdefault(k, m.slug)
    return out


def _transform_doc_links(body: str) -> str:
    """Rewrite cross-references between authored articles so they navigate in-app: a ``[[name]]``
    wikilink → a /docs link when the target is another authored article (else inline code — e.g.
    a ``[[memory-note]]`` reference that is no longer surfaced), and a markdown link to another
    authored ``.md`` file → its /docs slug. Source-code/external links pass through."""
    name_to_slug = _link_map()

    def _wl(m):
        name = m.group(1).strip()
        slug = name_to_slug.get(name) or name_to_slug.get(name.lower())
        return f"[{name}](/docs/{slug})" if slug else f"`{name}`"

    def _ml(m):
        text, target = m.group(1), m.group(2)
        head, _, anchor = target.partition("#")
        base = head.split("/")[-1]
        slug = name_to_slug.get(base) or name_to_slug.get(base.lower())
        if not slug:
            return m.group(0)
        return f"[{text}](/docs/{slug}{('#' + anchor) if anchor else ''})"

    return _MDLINK.sub(_ml, _WIKILINK.sub(_wl, body))


def render_doc(slug: str) -> tuple[str | None, str | None]:
    """(title, rendered_html) for a published article, or (None, None) if not found."""
    for meta in list_docs():
        if meta.slug == slug:
            _, body = _parse(meta.path)
            body = _transform_doc_links(body)
            from markdown_it import MarkdownIt
            # "default" preset = CommonMark + tables + strikethrough; html=False (the bundled
            # markdown is trusted, but we keep raw-HTML escaping on as defense-in-depth).
            md = MarkdownIt("default")
            tokens = md.parse(body)
            _add_heading_anchors(tokens)
            html = md.renderer.render(tokens, md.options, {})
            return meta.title, html
    return None, None
