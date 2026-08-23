"""Curated FileMaker calculation/script presentation palettes (packet 1308).

Token classification stays in ``templates/explorer_highlight.js``.  This module owns only the
colors applied to those stable classes.  A renderer receives a two-id selection and embeds the
resolved values; generated HTML never carries the full catalog or a preference lookup.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PALETTE_VERSION = 1
DEFAULT_PALETTE = "classic"

_LABELS = {
    "classic": ("Classic", "The familiar CORPUSfm syntax treatment."),
    "graphite": ("Graphite", "A quiet, reduced-saturation treatment."),
    "color-safe": ("Color-safe", "Hue and luminance separation without a red/green dependency."),
    "high-contrast": ("High contrast", "Stronger luminance contrast for low-vision use."),
}

# Roles are deliberately language-neutral here.  ``palette_css`` maps one selected family to
# explicit calculation roles and the independently selected family to explicit script roles.
_COLORS = {
    "classic": {
        "dark": {"plain": "#d2d6da", "comment": "#6a9955", "string": "#ce9178",
                 "number": "#b5cea8", "field": "#9cdcfe", "function": "#dcdcaa",
                 "keyword": "#569cd6", "operator": "#b9bec3", "verb": "#4e9eff",
                 "punct": "#8f969c", "closer": "#9aa1a7"},
        "light": {"plain": "#24282c", "comment": "#007400", "string": "#a31515",
                  "number": "#067248", "field": "#001080", "function": "#795e26",
                  "keyword": "#0000ff", "operator": "#4f565c", "verb": "#1b62b8",
                  "punct": "#62686d", "closer": "#5d646a"},
    },
    "graphite": {
        "dark": {"plain": "#d2d6da", "comment": "#85927b", "string": "#c3a69a",
                 "number": "#aab89f", "field": "#9eb7c4", "function": "#c2b9a0",
                 "keyword": "#9faec4", "operator": "#b2b8bd", "verb": "#a8b5c4",
                 "punct": "#8f969c", "closer": "#9aa1a7"},
        "light": {"plain": "#24282c", "comment": "#55644d", "string": "#76594f",
                  "number": "#53644d", "field": "#496371", "function": "#6a6049",
                  "keyword": "#4e5e75", "operator": "#4f565c", "verb": "#4a5e73",
                  "punct": "#62686d", "closer": "#5d646a"},
    },
    "color-safe": {
        "dark": {"plain": "#d2d6da", "comment": "#b6a36a", "string": "#e39a72",
                 "number": "#d1c56e", "field": "#79bde8", "function": "#c2a2e8",
                 "keyword": "#62c7c5", "operator": "#b5bbc1", "verb": "#80aef2",
                 "punct": "#8f969c", "closer": "#9aa1a7"},
        "light": {"plain": "#24282c", "comment": "#685800", "string": "#8a3f1f",
                  "number": "#665900", "field": "#17618b", "function": "#69458d",
                  "keyword": "#006c6a", "operator": "#4f565c", "verb": "#245c9d",
                  "punct": "#62686d", "closer": "#5d646a"},
    },
    "high-contrast": {
        "dark": {"plain": "#f2f4f5", "comment": "#b7d7a8", "string": "#ffd0b5",
                 "number": "#f7e58b", "field": "#b8dcff", "function": "#eee0a6",
                 "keyword": "#c9c6ff", "operator": "#e6e8ea", "verb": "#a9d1ff",
                 "punct": "#d7dadd", "closer": "#d7dadd"},
        "light": {"plain": "#151719", "comment": "#2c4e25", "string": "#6b3421",
                  "number": "#544900", "field": "#174f75", "function": "#514400",
                  "keyword": "#39356d", "operator": "#34383c", "verb": "#174f75",
                  "punct": "#34383c", "closer": "#34383c"},
    },
}


@dataclass(frozen=True)
class SyntaxPaletteSelection:
    calculation: str = DEFAULT_PALETTE
    script: str = DEFAULT_PALETTE

    def as_dict(self) -> dict[str, str | int]:
        return {"calculation": self.calculation, "script": self.script,
                "version": PALETTE_VERSION}


def clean_palette_id(value: object) -> str:
    value = str(value or "").strip().lower()
    return value if value in _COLORS else DEFAULT_PALETTE


def resolve_selection(value: object = None) -> SyntaxPaletteSelection:
    if isinstance(value, SyntaxPaletteSelection):
        return SyntaxPaletteSelection(clean_palette_id(value.calculation), clean_palette_id(value.script))
    data = value if isinstance(value, dict) else {}
    return SyntaxPaletteSelection(
        clean_palette_id(data.get("calculation", data.get("calculation_palette", DEFAULT_PALETTE))),
        clean_palette_id(data.get("script", data.get("script_palette", DEFAULT_PALETTE))),
    )


def catalog() -> list[dict[str, str | int]]:
    return [{"id": key, "label": label, "description": description,
             "version": PALETTE_VERSION} for key, (label, description) in _LABELS.items()]


def _vars(prefix: str, colors: dict[str, str]) -> str:
    roles = ("plain", "comment", "string", "number", "field", "function", "keyword",
             "operator", "verb", "punct", "closer")
    return ";".join(f"--{prefix}-{role}:{colors[role]}" for role in roles)


def palette_css(value: object = None) -> str:
    """CSS containing exactly one calculation and one script family."""
    selected = resolve_selection(value)
    calc = _COLORS[selected.calculation]
    script = _COLORS[selected.script]
    marker = (f"/* CORPUSfm syntax palettes v{PALETTE_VERSION}: "
              f"calculation={selected.calculation}; script={selected.script} */")
    return "\n".join((
        marker,
        ":root{" + _vars("calc", calc["dark"]) + ";" + _vars("script", script["dark"]) + "}",
        '[data-theme="light"]{' + _vars("calc", calc["light"]) + ";" +
        _vars("script", script["light"]) + "}",
    ))


def catalog_css() -> str:
    """All curated values for live account-page specimens (never used in generated output)."""
    chunks: list[str] = []
    for key, colors in _COLORS.items():
        selector = f'[data-syntax-palette="{key}"]'
        chunks.append(selector + "{" + _vars("calc", colors["dark"]) + ";" +
                      _vars("script", colors["dark"]) + "}")
        chunks.append(f'[data-theme="light"] {selector}' + "{" +
                      _vars("calc", colors["light"]) + ";" +
                      _vars("script", colors["light"]) + "}")
    return "\n".join(chunks)


def highlighter_source() -> str:
    return (Path(__file__).parent / "templates" / "explorer_highlight.js").read_text(encoding="utf-8")
