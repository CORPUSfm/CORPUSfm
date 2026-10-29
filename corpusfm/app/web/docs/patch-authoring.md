---
title: Patch authoring
slug: patch-authoring
order: 130
status: published
public: true
public_section: Workflows
---

# Patch authoring

A **patch** (`FMUpgradeToolPatch`) is one XML file that carries schema changes — added or
changed scripts, fields, layouts, and more — into any FileMaker file matching the baseline,
without touching data. CORPUSfm produces patches two ways: the deterministic
[ISV diff](/docs/isv-workflow), and an AI assistant authoring one over [MCP](/docs/mcp).

This article is about the **AI-authored** path: how an assistant composes a patch that actually
applies, instead of one that looks right and silently drops half its content.

## The grammar comes from the tool, not from guessing

The patch format has exact rules, and FileMaker's upgrade tool is unforgiving about them: a
structurally valid patch can pass validation and apply, yet quietly drop steps if an id doesn't
line up. So the assistant doesn't improvise. It pulls the rules:

- **The authoring guide** describes the action grammar (Add / Replace / Delete), the catalog
  reference types, and the construction templates for each object kind.
- **The capability ledger** records what the upgrade tool *actually* can and can't express,
  each claim tagged with how it was verified. The assistant builds within those limits and
  **flags** what the tool can't do rather than fabricating it.
- **Step exemplars** return real, working step sequences from your corpus — object-level
  grounding so a patch is built from steps that genuinely ingested, with the volatile bits
  (field names, calculations, layout names) marked as placeholders to fill.

## Ground in the real schema

Before composing, the assistant reads the **target** artifact's schema context — every id and
name a patch must reference comes from there. When translating behavior from another file, that
file is **reference** material only: reproduce its behavior with the *target's* own objects and
installed add-on infrastructure; never copy a reference file's internal ids.

## Check before you trust

Every authored patch goes through a static **coherence + simulation** check before it's allowed
near a file. That check catches the failures the upgrade tool's own validation misses:

- **Dangling references** — a step that points at a script, field, or layout that exists
  neither in the file nor in the patch. (The tool applies these and silently drops the step.)
- **Delete impact** — surviving objects that still reference something the patch deletes.
- **Field-on-table mismatches** and **ordering** — a reference that only resolves via a
  patch-added object appearing too late in the patch.
- **Hostability** — a change that would produce a file that won't open.

A patch that passes is consistent and would host. From there it goes to the
[apply loop](/docs/applying-patches).

## Existing layouts

**What CORPUSfm does today.** Its patch generator does not edit existing layouts, and the
assistant's authoring guidance only *adds* layouts. That's the current implementation, not a limit
of the upgrade tool: every layout has its own UUID, and the tool can change layouts with the results
below.

CORPUSfm's checks, dry run and apply don't block a layout Replace or Delete that you write yourself.
If you do write one, rely on the dry run's Verify step, and treat the results below as findings, not
rules. A result that worked held for the tested build and file. One that failed may behave
differently on another build, file or form.

The upgrade tool itself can do more. In testing it could:
- **Delete a layout**, or **delete one object** on it.
- **Edit one object in place**, keeping its identity: text, position and size, colours and fonts,
  field binding, tooltip, name, tab order, value list, control style, hide condition, conditional
  formatting, script trigger, and a button's script and parameter. A patched trigger fired and a
  patched button ran its new script when clicked.
- **Edit objects inside containers** by targeting them directly: a tab panel's or portal's children,
  a group member, a button-bar segment.
- **Edit a popover** (title, position, a new object in its panel) through its button, keeping the
  panel's identity. This was 26.0.3.309 only: 22.0.6.600 crashed on every popover edit.
- **Change a web viewer's URL calculation**, and a tab control's default front tab.
- **Relabel a button-bar segment or give it a script**; a patched segment ran its new script when
  clicked, on both builds.
- **Add objects to an existing container or layout**, but only by replacing the container or whole
  layout, at the cost of new identities for the objects already there.
- **Replace a whole layout** (26.0.3.309 only). On one older file an old web viewer blocked it until
  that web viewer was replaced with its own XML.

This table is what it actually did in testing:
- **Builds:** FMUpgradeTool 22.0.6.600 and 26.0.3.309, on copies of Claris starter files.
- **Visual and behavior checks:** FileMaker Pro 26.0.3 for 26.0.3.309 results; FileMaker Pro 22.0.6
  for the 22.0.6.600 results shown as rendered.
- **Full detail:** the assistant's `get_patch_capabilities` tool lists every tested form and
  condition.

| What was tried | 22.0.6.600 | 26.0.3.309 | Strongest proof |
|---|---|---|---|
| Delete a layout by its own UUID | landed | landed | rendered |
| Replace a whole layout with complete Layout XML | no-op | collateral | rendered |
| Whole-layout Replace on the Contacts file shipped with FileMaker Pro 22.0.6 | no-op | no-op | xml |
| Whole-layout Replace on new blank files created in FileMaker Pro 22.0.6 and 26.0.3 | no-op | landed | xml |
| Unblock it by replacing the old web viewer with its own XML | no-op | landed | rendered |
| Layout Replace without its parts | not tested | destructive | rendered |
| Replace one layout object by its own UUID | landed | landed | rendered |
| Object Replace without a LayoutReference sibling | not tested | no-op | xml |
| Delete one layout object | landed | landed | rendered |
| Partial LayoutObject payload | not tested | destructive | rendered |
| Portal Replace without its children | not tested | destructive | xml |
| Text to Rectangle type change | discrepancy | discrepancy | rendered |
| Fill, text colour and size, resize | not tested | landed | rendered |
| Field binding of an edit box | not tested | collateral | rendered |
| Hide condition | landed | landed | rendered |
| Conditional formatting | landed | landed | rendered |
| Object script trigger | collateral | collateral | behavioral |
| Button label, button script and parameter | collateral | landed | behavioral |
| Add an object directly to an existing layout | not tested | no-op | xml |
| Further chart cases | not tested | not tested | — |
| Retext an object inside a tab panel | not tested | landed | rendered |
| Tab panel Replace without its children | not tested | destructive | xml |
| Tab panel Replace with its children (tab label, object name) | not tested | collateral | behavioral |
| Tab control Replace (default front tab) | not tested | collateral | rendered |
| Add an object to an existing tab panel | not tested | collateral | rendered |
| Web viewer URL calculation | not tested | landed | rendered |
| Switch a layout's theme through whole-layout Replace | not tested | failed | xml |
| Popover button Replace with its panel | refused | collateral | behavioral |
| Popover panel targeted directly | no-op | no-op | xml |
| Slide control Replace without its panels | no-op | destructive | xml |
| Chart Replace, even with unchanged XML | destructive | destructive | rendered |
| Group Replace with or without its members | destructive | destructive | rendered |
| Relabel a button-bar segment | landed | landed | rendered |
| Give a button-bar segment a script action | landed | landed | behavioral |
| Add a button-bar segment | refused | collateral | rendered |

**Outcomes:**
- **Landed:** the intended change, and nothing else.
- **Collateral:** the intended change, plus an unintended one.
- **Failed:** the intended change didn't land, but something else changed.
- **Refused:** the tool reported an error and applied nothing.
- **No-op:** nothing changed.
- **Destructive:** content was lost.
- **Discrepancy:** the tool accepted something its documentation calls unsupported.
- **Unconfirmed:** the change is in the XML, but its effect wasn't seen.

**Proof, from weakest to strongest:**
- **xml:** the file's own before/after export.
- **rendered:** FileMaker Pro drew it.
- **behavioral:** it ran.

**What the tests showed:**
- **Success messages prove nothing.** The tool reported success on every patch above, including the
  ones that changed nothing and the ones that lost content.
- **Replace swaps the whole object; it doesn't merge.**
  - A layout without its parts lost every object.
  - A portal without its children lost them.
  - A partial object lost its text.
- **Identity isn't always kept.**
  - Replacing a whole layout gave every object on it a new identity.
  - Replacing a portal, tab panel or tab control together with its children recreated the children.
  - That's also the only way an object was added to an existing container.
- **Edit boxes lose a link.** Replacing an edit box dropped its accessibility label link.
- **Type changes:** a Text object became a Rectangle although the documentation says type changes
  aren't supported. Treat that as a documentation discrepancy, not as a technique.
- **Whole-layout Replace depends on build and file.**
  - 22.0.6.600 never applied it, including on a new file created in FileMaker Pro 22.0.6.
  - 26.0.3.309 applied it to new files from either version and to two starter files.
  - It ignored it on one older starter file, even after that file was re-saved by each tool or
    recovered. The cause was that file's web viewer. Replacing the web viewer with its own unchanged
    XML, or deleting it, made the Replace work on 26.0.3.309. The blocking state is internal and doesn't appear in
    the export, so this is one file's finding, not a general fix.
- **Theme:** a theme switch through whole-layout Replace was ignored, yet every object was still
  recreated.
- **Charts break invisibly.** The export carries none of a chart's settings, configured or not.
  Replacing a chart, even with its own unchanged XML, wiped them: it drew as a black box on both
  builds. Comparing exports can't catch this; looking at the result can.
- **Popovers are a partial exception.** Replacing a popover button together with its panel kept the
  panel's identity, but objects already inside the panel were recreated. Aiming the change at the
  panel directly did nothing.
- **22.0.6.600 can crash.** Any popover button or button bar Replace crashed it, leaving an unchanged
  copy at the output path. It also enlarged a group 50-fold when the group was replaced without its members.
- **Conditional formatting works when its condition is enabled.** An early test used an option value
  that disables the condition.
- **Other side effects, with the conditions they were seen under:**
  - 22.0.6.600 rewrote a button's time-format option.
  - On 26.0.3.309, deleting a portal's field also removed its Table View column.
  - 26.0.3.309 added a custom-menu catalog to each of the three tested files that had none, even
    when the patch itself changed nothing.
- **What the testing didn't cover:**
  - Other upgrade-tool builds.
  - Customer files: the tests used Claris starter files and new blank files.
  - Further chart cases, which were skipped on purpose.
  - The table and the assistant's tool list every tested form; anything not listed is unknown,
    not unsupported.
