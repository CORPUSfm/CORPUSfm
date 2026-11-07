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
  - **Graph** (table occurrences and relationships) / **Wireframe** (layouts) where they apply.

## Searching

The search box at the top looks through **every file loaded into this Explorer**, whichever file
tab is selected, and each result names the file it belongs to. It always searches object **names**
and their ordinary text: field definitions and calculations, custom-function formulas, value
lists, layouts and the rest.

**Search options** — the gear at the right end of the search box — set how it matches and where it
looks. Matching has two choices:

- **Exact** — the default. Finds the characters you typed, in that order, anywhere in the text.
  Capitals don't matter; spaces inside your search and punctuation do. `Timestamp` finds a longer function name and
  the word inside a formula. A result whose whole name is your query comes first.
- **Fuzzy** — also finds close misspellings and similar text, anywhere in the text, so it can
  return things that don't contain what you typed.

Script contents are split into two kinds you can search:

- **Comments** — on by default. Finds words in script comments.
- **Script steps** — off by default. Turn it on to find scripts that use a step, or a word in a
  step's parameters or calculations. For example, search **Execute FileMaker Data API** to find
  every script that calls it, wherever the step sits in the script.

Each result says what matched (**Name**, **Text**, **Comment**, **Script step** or an
**External script reference**) and shows the matching line. Search is textual: a step's name
written inside another step's calculation also counts as a script-step match. It does not prove
the step runs, and a disabled step still matches. A very long script-step value, over 2,000
characters, shows as a size marker and is not searched. A script whose steps can't be told apart
is searched as a whole only with Script steps on. The options reset each time you open an Explorer.
Choosing a result opens that object; it doesn't jump to the matching line.

The list shows at most 200 results. Exact tells you the full count when there are more. Fuzzy stops
early, so it says more may exist; narrow the search or use Exact to see them.

## Narrow windows

Explorer keeps every action on a small window or phone. Below about 900 pixels wide, the selected object takes
the whole width and **Browse**, above it, opens files, sections and the object list. Choosing an object closes
Browse; reopening returns you to the same section, filter and place in the list. Press Escape or the close
button to leave without choosing. References open above the object instead of beside it.

Below about 760 pixels, search takes its own row, and theme, About and Save move to the **⋯** menu. Statistics
stays in the toolbar.

## Statistics

The chart icon at the top right, just after the search box, opens **Statistics** for the selected file; switching file
tabs switches the report, and a combined Explorer never adds its files together. Each summary leads
to a ranked list you can sort and filter, and each row opens the object. **Back** returns to the
report as you left it. Choosing an object doesn't jump to its step or calculation; the row names it.

These are facts, not judgements: nothing here says a script is too long or an object is a problem.

- **Script length** — every stored step, matching the line numbers on a script, beside the
  non-comment count. Comments, blank and disabled steps overlap, so they don't add up to the total.
- **Step size** — characters in each step as fully rendered, including its labels. It isn't raw XML
  or bytes, and values the renderer hides, such as passwords, aren't counted.
- **Calculations** — every stored calculation in any object, with where it sits. That includes
  small ones such as a default repetition of 1, and each one counts even if its text matches another.
- **Layout objects** — every stored entry, including groups, tab controls, what's inside them and
  Table View columns, with a breakdown by type.
- **Relationships** — connected groups of table occurrences, and the fewest jumps between any two you
  choose. One jump is one relationship, followed in either direction. A table occurrence reaches
  itself in 0 jumps; two that aren't connected have no path.
- **References** — targets a reference points at, grouped, with every place that refers to them.

**Reading the References list.** *Not found in snapshot* means this export offered an identity no
catalog item carries; it doesn't prove the live file lacks it. *Marked Missing* means FileMaker
itself wrote a Missing marker into a calculation. The rest aren't proof of anything broken: a target
can be *ambiguous*, have *no target set* (FileMaker stores that for a blank setting too), be *in
another file* (not checked there) or have a *catalog incomplete*, as in an add-on. Only script, layout,
value list, table occurrence, field and custom menu references are examined; names inside formulas are
checked only through FileMaker's own markers, and a reference built at runtime can't be seen. So an
empty list isn't proof of a clean file, and **Unused** is a different thing and isn't listed here.

Anything that couldn't be read is reported as not measured, never as zero. Statistics come from the
stored export, so generate a new Explorer to see them; re-ingesting isn't needed.

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

A custom function counts as used when a script calculation, field, layout, custom menu or another
custom function names it. That means it is referenced in stored content, not that it runs: a call
in a disabled step counts, and a call built as text for `Evaluate` can't be seen. Outside scripts,
a function called with no arguments and no parentheses may not be recognized yet, so treat Unused
as a prompt to look rather than proof. References are recorded when a file is ingested, so
re-ingest an older artifact and generate a new Explorer to pick up script calls.

## The relationship graph

Open a table occurrence or a relationship and **Rendered** shows the graph, on **As Built**, FileMaker's own positions, or
**By Table**. The second tab lists the same selection's immediate connections, one row each, across the full width:

- On an occurrence, **Relationships** names its base table or external source, then one row per relationship: the related
  occurrence, every condition, and **Create** and **Delete** for each side, labelled with that side's occurrence.
- On a relationship, **Table Occurrences** lists its two occurrences with their source and their own Create and Delete, then every
  condition. **Flip sides** swaps the order without changing what the relationship means; each side keeps its own settings.

Choose an occurrence or a condition there to step to it and stay on that tab. Moving between Rendered and the second tab keeps
your view, your arrangement and As Built or By Table.

Choosing a box or a line selects it and centers it at a readable size, without moving anything on the map. If a
relationship's two ends don't both fit at that size, it centers on the first and the other is a pan or a click away. An
occurrence with no captured position is left off and counted. Boxes use FileMaker's saved colors and view, collapsed, related fields or full, at sizes
that approximate FileMaker's. Each relationship is one connection: short branches leave its field rows (or the
header, where a field can't be identified) and join one line with one marker. The marker shows the operator, or
every different operator in condition order (for example `× =`) when the conditions differ; the tip and the details
list each condition in full. Two relationships between the same boxes stay two lines. Notes from the graph
appear behind the boxes. Hover over or tab to a box or line to see its full name and details.

Each note has a narrow top bar: drag it to move the note. Its buttons show the note's full text in a window you can
read and copy from (close it, or press `Esc`), and collapse or expand it. Note text can be selected and copied, and
the wheel scrolls a long note. Drag the corner of an expanded note to resize it.

On As Built you can drag a box or note to try a different arrangement. **Reset** puts every box and note back, with its
captured size and collapsed state, and closing or reloading the page does too; nothing is saved to the file or to Save As. Drag the background to pan, use the wheel to zoom,
**Refocus** to return to the selection at a readable size, and **Fit** to see everything. Neither moves anything on the map. Back and
`Alt`+`→` return to an object and center it at a readable size, as selecting it does; where you had panned to isn't kept.

## Keyboard shortcuts

Explorer is keyboard-friendly: `[` / `]` move between sections, `u` toggles unused, `1`–`5`
switch detail tabs, `g` full-screens the graph, and `?` shows the full shortcut list.
