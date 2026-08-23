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
