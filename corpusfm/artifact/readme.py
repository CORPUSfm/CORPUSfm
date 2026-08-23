"""The artifact's self-description — the first thing a reader sees inside the JSON.

An artifact is routinely handed to something that has never met CORPUSfm: an AI asked to work on
a solution, a script, a developer opening the download. Everything that file needs to be understood
correctly has to travel INSIDE it, because nothing else will arrive with it.

It lives in the artifact, not in the download zip. A README member in the zip explains the zip and
is lost the moment anyone extracts the payload, hands the JSON along, or reads the artifact out of
storage or over MCP — which is every path that matters. Carried as the artifact's own first key, it
survives all of them.

Editing this text never invalidates an already-downloaded artifact — an artifact has no content
identity to disturb (packet 1216 removed it).
"""

from __future__ import annotations

ARTIFACT_README = (
    "This file is a CORPUSfm artifact: a structured snapshot of one FileMaker solution's schema. "
    "It is self-contained — there is no companion file to fetch — and it can be uploaded back into "
    "CORPUSfm unchanged.\n"
    "\n"
    "WHAT IS IN IT\n"
    "  identity              which FileMaker file this came from, its root UUID, its FM version.\n"
    "  sections              the schema sections present, in order.\n"
    "  items                 every schema object, keyed by item_id. Each item carries its name, the\n"
    "                        original FileMaker XML it was parsed from (xml_sources), and a rendered\n"
    "                        plain-text form (rendered_text) meant to be read.\n"
    "  xref_map              directed references between items — what calls, uses, or depends on what.\n"
    "  completeness_profile  what this snapshot could NOT account for. Read it before concluding that\n"
    "                        something is missing from the solution.\n"
    "\n"
    "WHAT IT IS NOT\n"
    "This is not the .fmp12 file, and it is not the whole schema. FileMaker exports several different\n"
    "projections of one internal model, each lossy in a different way, and this artifact was built\n"
    "from one of them — the `type` field says which. All of them carry the design layer (structure,\n"
    "logic, calculations, the relationship graph) and drop runtime state, stored data, and layout\n"
    "geometry; an fmClip is narrower still, a fragment with no cross-references. Absence here is not\n"
    "proof of absence in the file.\n"
    "\n"
    "READING IT\n"
    "Prefer rendered_text to understand an object; go to xml_sources when you need FileMaker's exact\n"
    "syntax. item_ids are stable within a snapshot. Object names are not unique across types, so two\n"
    "items may share a name and mean different things."
)
