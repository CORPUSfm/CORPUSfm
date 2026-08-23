---
title: Tags & filtering
slug: tags
order: 60
status: published
public: true
public_section: Concepts
---

# Tags & filtering

Tags organize the catalog. They come in two kinds: **your tags** (labels you apply) and
**system tags** (facts CORPUSfm derives).

## Your tags

Apply one or more free-form labels to any artifact — `client-acme`, `seed`, `production`,
whatever fits your workflow. A tag spans many artifacts, so it doubles as a saved grouping you
can filter to from the [Catalog](/docs/artifacts-catalog).

Manage them on the **Tags** page: see every known tag with its count, jump to its artifacts,
rename, or delete it. Tags are stored with your data, so they survive across sessions and
travel with a backup.

Tags are **per artifact** — applying a tag to one version of a file does not bleed onto its
other versions or onto sibling files.

### The `seed` convention

One tag has a conventional meaning: **`seed`**. Mark a baseline file (your starting framework,
with add-ons already installed) `seed`, and an AI assistant working over [MCP](/docs/mcp) can
discover it as the foundation to build a new module from.

## System tags

System tags are computed from each artifact's own facts every time you look — you don't set
them, and there is nothing stored to drift out of date:

- **Type** — SaveAsXML, AddonXML, MergedXML, and so on.
- **Origin** — how the artifact arrived (import, job, merge, …).
- **FileMaker version** — the version that produced the export.
- **Indexed / Unindexed** and **Summarized / Unsummarized** — whether the artifact is in the
  [semantic search index](/docs/semantic-search) and whether it has AI summaries. These are
  *live*: they reflect the state right now, so they stay correct as you index and de-index.

System tags appear in the filter facets alongside your tags, so "all FileMaker 2026 add-ons
that aren't indexed yet" is just three facet clicks.
