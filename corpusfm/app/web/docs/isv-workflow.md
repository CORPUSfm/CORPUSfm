---
title: ISV Workflow
slug: isv-workflow
order: 120
status: published
public: true
public_section: Workflows
---

# The ISV workflow

The **ISV Tool** turns a CORPUSfm diff into an `FMUpgradeToolPatch` — one XML file that
carries your schema changes (scripts, fields, layouts, and more) into any FileMaker file
matching the baseline, **without touching data**.

It's built for **ISV deployments** — one product, many client sites, schema updates that must
reach every site reliably.

## Steps

1. Import the **baseline** (the schema currently at client sites) and your **new version**.
2. On the **Artifacts** page, open the baseline's detail and click **Patch (ISV)**.
3. Pick the new version (B) in the ISV Tool and **read the Coverage report** — for this exact
   pair it lists, object by object, what will land and what won't (and why). *That report is
   the part that matters.*
4. **Generate**, then download `patch.xml` for distribution — or, on a co-located server,
   dry-run and apply right from the tool.
5. Client sites run:

   ```
   FMUpgradeTool --validatePatch -patch_path patch.xml -src_path clientfile.fmp12
   FMUpgradeTool --update -src_path clientfile.fmp12 -patch_path patch.xml -dest_path patched.fmp12
   ```

## The Coverage report is the source of truth

What a patch can and can't express for *your* change is decided per-patch. The Coverage
report flags anything **not patchable** with its reason — trust that report for this patch
rather than any general capability list, because it's computed from the actual diff.

On a **co-located** server (CORPUSfm running on the FileMaker Server box), the ISV Tool can
also **dry-run** the patch against a sandbox copy and **apply** it to a hosted file — the live
file is backed up first and restored automatically if anything fails, and production is never
touched during the dry-run.
