---
title: Merging a schema with its add-on
slug: merge
order: 55
status: published
public: true
public_section: Workflows
---

# Merging a schema with its add-on

**Merging** combines a solution's schema export with its **add-on** package into one artifact with
the add-on objects' real names resolved. Why you'd want it: when a solution uses FileMaker add-ons,
the host export refers to add-on-contributed objects (scripts, layouts, fields) by internal **UUID
names** — there are no human-readable names anywhere in the host export for them. The add-on package
*does* carry the readable names, so merging the two brings them together.

## Why it matters

- **Readable names** — add-on scripts and fields show their real names instead of
  `com.fmi.script.UUID-…`.
- **Accurate dead-ends** — the merged view can tell an add-on *internal worker* (called only by
  other add-on scripts) from a genuinely unused object, so [dead-end analysis](/docs/explorer)
  stops reporting false positives.
- **A unified cross-reference graph** — references that crossed the host/add-on boundary now
  resolve.

## How to merge

Use the **Merge Tool**: pick the **SaveAsXML** snapshot and its matching **add-on**, and create
the merged artifact. The two must share the same root identity — they have to be the host file
and an add-on actually installed in it. CORPUSfm checks this before merging.

The result is a normal artifact in [the Catalog](/docs/artifacts-catalog) (type *MergedXML*).
[Explore](/docs/explorer), [diff](/docs/diff), [export](/docs/git-export), and
[index](/docs/semantic-search) it like any other.

## When you don't need it

If your solution uses no add-ons, the plain schema export is already complete — there's nothing
to merge. Merge is specifically the fix for the add-on naming and dead-end ambiguity.
