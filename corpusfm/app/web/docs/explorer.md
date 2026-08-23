---
title: Exploring a schema
slug: explorer
order: 40
status: published
public: true
public_section: Workflows
---

# Exploring a schema

The **Explorer** is an interactive, single-file view of one artifact (or several at once). It's
the lens you reach for to *understand* a solution — what's there, how it connects, and what
isn't used.

Launch it from [the Catalog](/docs/artifacts-catalog): select one artifact and **Explore**, or
select several to open a merged browsing session across them.

The Explorer is the human inspection lens: it shows the artifact's own structure directly,
so you can read and verify it yourself. Derived, AI-oriented perspectives over the same
artifact (workflows, security reach, the data model, AI usage) are served through
[MCP](/docs/mcp) for an AI assistant, rather than as extra panels here.

## Layout

- **Sidebar** — every catalog section (tables, fields, scripts, layouts, value lists, custom
  functions, relationships, security, and more), grouped into folders that mirror FileMaker.
  Filter, sort per section, and fold groups.
- **Detail pane** — the selected object, with tabs:
  - **Rendered** — a readable rendering: script steps with line numbers and syntax
    highlighting, field calculations, custom-function formulas, privilege detail.
  - **Tree / Attributes / Raw** — the underlying structure and the original FileMaker XML.
  - **Graph** (relationships) / **Wireframe** (layouts) where they apply.

## Cross-references

Every object carries its **XRef** — what it uses and what uses it. A script shows the scripts
it calls, the scripts and triggers that call it, and the fields it touches. A field shows the
scripts, layouts, value lists, and calculations that reference it. This is how you trace impact
before changing anything.

## Dead-end analysis

Explorer flags objects that nothing references — likely-unused scripts, fields, value lists,
and layouts. Toggle **Show Unused** to focus on them.

One caveat worth knowing: in a solution that uses **add-ons**, some add-on scripts are internal
workers called only by other add-on scripts under UUID names, which can look like dead ends
from the host file alone. [Merging the add-on](/docs/merge) resolves those names so the
analysis is accurate.

## The relationship graph

The relationship tab draws the graph three ways — **By Table**, **As Built**, and **Discover**
(a force layout that pulls hub table-occurrences to the center and sizes nodes by how many
relationships touch them). Use it to find the spine of a solution and its isolated corners.

## Keyboard shortcuts

Explorer is keyboard-friendly: `[` / `]` move between sections, `u` toggles unused, `1`–`5`
switch detail tabs, `g` full-screens the graph, and `?` shows the full shortcut list.
