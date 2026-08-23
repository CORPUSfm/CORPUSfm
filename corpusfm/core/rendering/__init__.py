"""Human-readable rendering of FM script steps and catalog section items.

Public API:
    load_catalog(version)                              -> (catalog_dict, warning | None)
    render_step(step_elem, catalog, show_hidden)       -> RenderedStep
    render_script(script_elem, catalog, ...)           -> list[RenderedStep]
    render_section_item(section_key, name, xml_str)    -> RenderedItem
    RenderedStep                                       — dataclass
    RenderedItem                                       — dataclass
"""

from corpusfm.core.rendering.catalog import load_catalog
from corpusfm.core.rendering.step_renderer import RenderedStep, render_script, render_step
from corpusfm.core.rendering.section_renderer import RenderedItem, render_section_item

__all__ = [
    "load_catalog",
    "render_step", "render_script", "RenderedStep",
    "render_section_item", "RenderedItem",
]
