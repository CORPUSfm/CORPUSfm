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

## Searching

The search box at the top looks through **every file loaded into this Explorer**, whichever file
tab is selected, and each result names the file it belongs to. It always searches object **names**
and their ordinary text: field definitions and calculations, custom-function formulas, value
lists, layouts and the rest.

Script contents are split into two kinds you control with **search options** — the gear at the
right end of the search box:

- **Comments** — on by default. Finds words in script comments.
- **Script steps** — off by default. Turn it on to find scripts that use a step, or a word in a
  step's parameters or calculations. For example, search **Execute FileMaker Data API** to find
  every script that calls it, wherever the step sits in the script.

Each result says what matched (**Name**, **Text**, **Comment**, **Script step** or an
**External script reference**) and shows the matching line. Search is textual: a step's name
written inside another step's calculation also counts as a script-step match. It does not prove
the step runs, and a disabled step still matches. A very long script-step value, over 2,000
characters, shows as a size marker and is not searched. A script whose steps can't be told apart
is searched as a whole only with Script steps on. Close misspellings are found too, anywhere in
the text. The options reset each time you open an Explorer. Choosing a result opens
that object; it doesn't jump to the matching line.

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
