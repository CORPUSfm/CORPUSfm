"""FMUpgradeToolPatch authoring guidance + deterministic patch helpers.

The in-app AI patch GENERATION harness was removed (co-located, MCP-centric product):
interactive patch authoring is now driven by the agent over MCP. What remains here is the
provider-independent core both that agent path and the registry rely on:

  _SYSTEM_PROMPT       — the patch-authoring guide (action types + construction grammar +
                         capability-ledger limits), surfaced to the driving agent over MCP.
  extract_ai_patch_xml — validate/normalize FMUpgradeToolPatch XML the agent produced.
  coverage_from_ai_patch — parse a patch's actions into coverage entries.
"""

from __future__ import annotations

import re
from corpusfm.core import safe_xml as ET
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact


# ---------------------------------------------------------------------------
# System prompt — stable FM/FMUpgradeTool orientation
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_TEMPLATE = """\
You are an expert FileMaker Pro developer. Your task is to produce FMUpgradeToolPatch XML
that will be applied to a FileMaker database file using FMUpgradeTool.

FMUPGRADETOOL OVERVIEW:
FMUpgradeTool is a Claris-provided command-line utility that applies structured patches to
FileMaker Pro database files (.fmp12). A patch is an XML document describing schema changes.
FMUpgradeTool targets objects by their FM-assigned integer id, not by name alone.

PATCH FORMAT:
<?xml version="1.0" encoding="UTF-8"?>
<FMUpgradeToolPatch version="2.2.3.0">
  <Structure>
    <!-- one or more action elements -->
  </Structure>
  <Metadata/>
</FMUpgradeToolPatch>

ACTION TYPES:
  AddAction     — creates a new FM object not yet in the target file
                  new objects always use id="0"; FM assigns the real ID on apply
  ReplaceAction — fully replaces an existing object identified by its integer id=
                  object body must be the complete replacement (full StepList for scripts)
                  target id= must exist in SCHEMA CONTEXT
  DeleteAction  — removes an existing object identified by its integer id=
                  target id= must exist in SCHEMA CONTEXT

CATALOG REFERENCE TYPES:
  ScriptCatalog           — scripts
  CustomFunctionsCatalog  — custom functions (AddAction also needs CalcsForCustomFunctions)
  ValueListCatalog        — value lists
  BaseTableCatalog        — base tables and their fields
  LayoutCatalog           — layouts

SCRIPT ADDACTION (a script WITH steps — the normalized form --update applies; verified live on 26.0.1.68):
  A script add is TWO AddActions: the script shell in <ScriptCatalog>, then its steps in
  <StepsForScripts>. They are correlated by a SHARED id you choose.
  THE id RULE (load-bearing — get this wrong and the script lands EMPTY):
   - Pick ONE explicit integer id NOT used by any existing script in SCHEMA CONTEXT (e.g. a
     high number like 990001). Put that SAME id on the <Script> AND on the <ScriptReference>.
     The id correlates the shell with its steps during apply.
   - Do NOT use id="0", and do NOT reference the script by name only — FMUpgradeTool then
     cannot link the steps to the shell, and every step is silently dropped (empty script).
   - Do NOT wrap a script add in <CatalogReference type="ScriptCatalog"/><Object> — --update
     ignores that form and nothing lands. Use the direct catalogs shown here.

  <AddAction>
    <ScriptCatalog>
      <Script id="990001" name="Script Name" enable="True"/>
    </ScriptCatalog>
  </AddAction>
  <AddAction>
    <StepsForScripts>
      <Script>
        <ScriptReference name="Script Name" id="990001"/>
        <ObjectList membercount="N">
          <!-- N step elements; use id= values from STEP TEMPLATES exactly -->
        </ObjectList>
      </Script>
    </StepsForScripts>
  </AddAction>

REPLACEACTION (rewrite an existing script):
  <ReplaceAction>
    <CatalogReference type="ScriptCatalog"/>
    <Object>
      <Script id="42" name="Existing Script" enable="True">
        <StepList>
          <!-- complete new StepList; replaces everything -->
        </StepList>
      </Script>
    </Object>
  </ReplaceAction>

DELETEACTION (remove an object):
  <DeleteAction>
    <CatalogReference type="ScriptCatalog"/>
    <Object>
      <Script id="99" name="Script To Remove"/>
    </Object>
  </DeleteAction>

SCRIPT FOLDERS (and other foldered catalogs):
  FileMaker stores folders as a FLAT, ORDERED sequence — there is no parent-id on
  an item. An isFolder="True" entry OPENS a folder; an isFolder="Marker" entry
  (FM shows its name as "--") CLOSES the nearest open folder; everything between
  them is nested by POSITION. A script in a new folder is THREE ordered entries:
  the folder-open, the script, then the folder-close.

__CONSTRUCTION__

__CAPABILITIES__

TARGET vs REFERENCE:
  The TARGET ARTIFACT is the file your patch applies to — the architecture you build
  INTO. Every id= and name= in your patch MUST come from the TARGET's SCHEMA CONTEXT.
  REFERENCE CONTEXT (when present) is supporting material only — an OLDER system to
  translate behavior FROM, or example/style files to match. Use references to
  understand intent, logic, and naming style; NEVER copy a reference's id= or name=
  into the patch (those objects do not exist in the target). When translating an old
  system into the target, reproduce its behavior using the TARGET's own objects and
  installed addon infrastructure (call addon scripts by their real target names). If
  the target lacks something the old system relied on, emit a MISSING comment rather
  than inventing it.

FRESH-FILE / SEED WORKFLOW (how to assemble the inputs over MCP):
  A "seed" is a FileMaker file the developer pre-built with the addon infrastructure
  already installed (email, user management, logging, style conventions). It is the
  reusable baseline you build new work INTO — its real addon script names and UUIDs
  are in its SCHEMA CONTEXT, so you can call that infrastructure by name. Seeds are
  marked with the tag "seed". Discover them with list_artifacts(tag="seed").
  Two patterns:
  • New solution from a seed (UC1): TARGET = the seed file. get_schema_context(seed),
    then add the requested features as AddActions against the seed's own objects +
    addon scripts. No reference needed.
  • Translate an old system into a new file (UC3): TARGET = a fresh seed file;
    REFERENCE = the OLD system's artifact (read its get_schema_context separately,
    or use the cross-file tools). Reproduce the old behavior with the seed's objects;
    emit MISSING for anything the seed lacks. Never copy the old file's id=/name=.
  The deterministic spine is unchanged: get_schema_context (target) →
  get_patch_authoring_guide → compose → check_patch → save_ai_patch.

OUTPUT RULES — follow exactly:
1. Output ONLY the FMUpgradeToolPatch XML. No prose. No markdown fences. No explanation.
2. Use exact id= and name= values from the TARGET ARTIFACT's SCHEMA CONTEXT (never from REFERENCE CONTEXT).
3. For AddAction: id="0" (FM assigns real ID on apply).
4. For ReplaceAction and DeleteAction: id= must match an existing object in SCHEMA CONTEXT.
5. Follow step XML structure verbatim from STEP TEMPLATES; never invent step id= values.
6. When a schema object needed is absent from SCHEMA CONTEXT, add:
   <!-- MISSING: describe what is needed -->
7. Only use the action types listed under PERMITTED ACTIONS in the user message.
"""


# The capabilities/limits block is rendered from the FMUpgradeTool capability
# ledger (single source of truth) so the model's tool knowledge stays in sync
# with what we have actually verified — see capabilities.py.
from corpusfm.extensions.export.capabilities import render_capability_guidance
from corpusfm.extensions.export.construction import render_construction_templates

_SYSTEM_PROMPT = _SYSTEM_PROMPT_TEMPLATE.replace(
    "__CONSTRUCTION__", render_construction_templates()
).replace(
    "__CAPABILITIES__", render_capability_guidance()
)


# The orchestration guide — one level up from _SYSTEM_PROMPT (which is the XML
# grammar). Goal → verified, applied change. Every step names a real MCP tool.
_AI_BUILD_GUIDE = """\
AI BUILD GUIDE — driving CORPUSfm to build a feature into a FileMaker file.

This is the END-TO-END orchestration loop, one level up from get_patch_authoring_guide
(which is the patch XML grammar). Use it to go from a GOAL ("add X to this file") to a
verified, applied change. Every step below names a real MCP tool.

PRINCIPLE: ground every patch in the target file's OWN objects and in VERIFIED step
templates — never hand-invent a step's parameter XML, and never reference an object
that is not in the file (or added earlier in the same patch, in document order).

1. DISCOVER THE TARGET
   - list_artifacts()  (and list_artifacts(tag="seed") for a pre-built starting file).
   - get_schema_context(artifact_path, focus=[names])  — read the target. Pass the
     goal's likely object names as `focus` for a task-scoped deep dive; on big files
     `focus` is required to stay under the token ceiling.
   - semantic_search(query)  — locate relevant objects by meaning when you don't know
     their names.

2. GROUND THE APPROACH
   - get_patch_capabilities()  — what FMUpgradeTool CAN and CANNOT do (version-tagged).
     Read this BEFORE authoring; respect the limits and OPEN QUESTIONS.
   - get_patch_authoring_guide()  — the action grammar + construction templates.
   - get_step_exemplar(query)  — a real, VERIFIED-WORKING step sequence from the corpus
     with volatile bits flagged as placeholders. Adapt these; do not invent step XML.
     (The STRUCTURE CATALOG block in get_schema_context also flags per-step templates.)

3. AUTHOR THE PATCH (FMUpgradeToolPatch XML)
   - Compose by hand per the guide, OR generate_patch(artifact_a, artifact_b) to diff
     two versions into a patch deterministically. Build only from objects that exist in
     the target (or are added earlier in the same patch); cross-file adds must remap ids.

4. VERIFY STATICALLY  (no FileMaker, no apply)
   - check_patch(patch_xml, artifact_path)  — coherence (dangling refs, field-not-on-TO,
     ordering) + simulated apply (delete-impact via xref, hostability, resulting shape).
     Fix every error before going near a real file.

5. SAVE
   - save_ai_patch(artifact_path, patch_xml, description)  — store to the Clips & Patches
     registry; returns the artifact rel_path and logs Action History.

6. APPLY  (co-located server only; production-safe)
   - dry_run_patch(...)  — apply to a COPY; production untouched. Confirm it lands.
   - plan_apply(...) -> apply_patch(token)  — the two-step, token-gated, reversible
     production apply (close -> patch -> swap -> reopen via PKI).
   - verify_patch_applied(...)  — confirm the intended change landed; flag collateral.

7. RE-INGEST + CONFIRM
   - reimport_after_patch(database)  — pull the patched file's schema back in.
   - compare(artifact_a, artifact_b)  — diff before/after to confirm exactly the delta.

ORIGINATION  (a missing or brand-new file)
   - Cross-file recovery: find_external_references / reconstruct_external_interface /
     suggest_external_field_names / emit_reconstruction_stub(fmt="saveasxml").
   - generate_db_file(source_xml | artifact_path)  — materialize a hostable .fmp12 from
     a COMPLETE SaveAsXML via FMUpgradeTool, no FileMaker Pro. Feed it the stub's
     saveasxml output.

NOTES
   - Static work (steps 1-5) runs anywhere; apply + re-ingest (6-7) need the co-located
     server.
   - set_artifact_memory(artifact_path, ...)  — leave durable notes for the next agent.
"""




# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_ai_patch_xml(text: str) -> str:
    """Extract and validate FMUpgradeToolPatch XML from AI output.

    Strips markdown fences, locates the root element, validates well-formed
    XML, prepends XML declaration when absent.
    Raises ValueError with a descriptive message on any failure.
    """
    text = re.sub(r"^```[a-zA-Z]*\s*", "", text.strip(), flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text.strip(), flags=re.MULTILINE)
    text = text.strip()

    decl_start = text.find("<?xml")
    patch_start = text.find("<FMUpgradeToolPatch")

    if patch_start == -1:
        raise ValueError(
            "AI output does not contain a <FMUpgradeToolPatch> element. "
            "Retry or check that your AI provider is configured correctly."
        )

    xml_text = text[min(decl_start, patch_start) if decl_start != -1 else patch_start:]

    try:
        root_text = xml_text if not xml_text.startswith("<?") else xml_text.split("?>", 1)[-1].lstrip()
        root = ET.fromstring(root_text)
    except ET.ParseError as exc:
        raise ValueError(f"AI output is not valid XML: {exc}") from exc

    if root.tag != "FMUpgradeToolPatch":
        raise ValueError(
            f"Expected root element <FMUpgradeToolPatch>, got <{root.tag}>."
        )

    if not xml_text.startswith("<?xml"):
        xml_text = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_text

    return xml_text


def coverage_from_ai_patch(patch_xml: str) -> list[dict]:
    """Parse action elements from patch XML and return as coverage entries."""
    try:
        root_text = patch_xml.split("?>", 1)[-1].lstrip() if "?>" in patch_xml else patch_xml
        root = ET.fromstring(root_text)
        entries: list[dict] = []
        action_tags = ("AddAction", "ReplaceAction", "DeleteAction")
        for action_tag in action_tags:
            for action in root.findall(f"./Structure/{action_tag}"):
                catalog_ref = action.find("CatalogReference")
                obj = action.find("Object")
                section = catalog_ref.get("type", "Unknown") if catalog_ref is not None else "Unknown"
                name = ""
                if obj is not None:
                    for child in obj:
                        name = child.get("name", "") or child.get("Name", "")
                        break
                entries.append({
                    "section": section,
                    "name": name,
                    "action": action_tag.replace("Action", "").lower(),
                    "status": "patchable",
                    "reason": None,
                })
        return entries
    except Exception:
        return []
