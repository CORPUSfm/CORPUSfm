---
title: Comparing versions (Diff)
slug: diff
order: 50
status: published
public: true
public_section: Workflows
---

# Comparing versions

The **Diff** compares any two artifacts and shows, section by section, exactly what changed —
added, removed, and modified objects, with the changed detail highlighted.

Launch it from the **Diff Tool** (pick A and B), or straight from [the Catalog](/docs/artifacts-catalog)
by selecting two artifacts. From the **Runs** history you can diff a job's run against the
previous successful run in one click.

## What it compares

The Diff works off each artifact's **rendered text** — the same readable rendering you see in
[Explorer](/docs/explorer). That means it compares what an object *does*, not just its raw
bytes, so cosmetic re-encodings don't show up as changes and real behavioral changes do.

It surfaces, per section:

- **Scripts** — step-by-step, with changed steps highlighted.
- **Fields** — type, calculation, auto-enter, validation, indexing.
- **Layouts** — including a **"Layout behavior"** delta that catches changes to hide
  conditions, conditional formatting, and object anchoring even when the visible content is
  otherwise identical.
- **Relationships, value lists, custom functions, security**, and the rest of the catalog.

## Cross-file objects

When an artifact references objects in another file (external table-occurrences and value
lists), the Diff marks them so you can tell a genuine change from a cross-file reference.

## A and B are just two versions

The Diff is symmetric — A and B are simply "the two things you're comparing." Use it to review
what a sprint changed, to confirm a deployment landed, or to audit drift between two client
sites. When you need to *carry* a set of changes from one file into another, that's the
[ISV workflow](/docs/isv-workflow).
