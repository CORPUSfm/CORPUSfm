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

## Aligning objects: By ID or By Name

Before it can compare two objects, the Diff has to decide which object in A corresponds to which
in B. You choose how with **Align by** in the Diff's own header, and you can switch back and forth
as often as you like:

- **By ID** (the default) pairs objects whose FileMaker internal serial ID is the same, within the
  same section and kind (a field is scoped by its own table's ID). Two objects with the same ID but
  different names are shown as **Same ID, different name** — the Diff never claims a rename.
- **By Name** pairs objects whose name is exactly the same, case-sensitively (a field by its table
  and field name). This suits two files built separately whose objects have the same names but
  different internal IDs.

The two modes are independent — neither falls back to the other, and a matching ID or name does not
prove two objects share a history. Whatever cannot be paired stays visible under **Not aligned**:

- **ambiguous** — more than one object on a side shares the key (for example several `--`
  folder-end markers by name), so none of them is guessed;
- **missing matching key** — the object carries no ID (library items, for instance) or no name
  (relationships and file-access authorizations have none, so By Name never pairs them), or a
  field's table cannot be resolved to one table with its own unique ID.

Folders, folder-end markers, separators and ordinary objects are kept apart: one never pairs with
another, even when they share an ID or a name.

The header counts differences and not-aligned items separately, so a report with nothing changed
still tells you when something needs review.

**Switching inside the report.** A Diff opens **By ID** unless it was launched another way, and
both comparisons of the same two artifacts are already inside the report — switching shows the
other one instantly, with no new capture from FileMaker and no connection to CORPUSfm needed. The
counts, summary, sections and explanation all change together. **Save As** keeps both comparisons
and remembers which one you were looking at; the saved file is named for it (`…_byid_diff.html` or
`…_byname_diff.html`) and still switches when opened offline. Without JavaScript, a report shows only
the comparison it opened with.

**Recent activity → Diff** shows the mode each comparison opened in and reopens it that way with
**Re-run**, from the same two stored artifacts. A comparison made before alignment modes existed
shows **By Name (legacy)**; re-running it uses today's Name mode, which shows the duplicates the old
report could hide. A report generated before the switch existed does not gain it; re-run it.

**Content still compares as rendered.** Alignment only decides the pairs. References inside a
script or calculation are compared as they read, so two objects can still differ where they name
other objects differently.

The ISV workflow's **View Diff (by name)** opens By Name, matching how the patch beside it pairs
objects; the report can still switch to By ID.

## Cross-file objects

When an artifact references objects in another file (external table-occurrences and value
lists), the Diff marks them so you can tell a genuine change from a cross-file reference.

## A and B are just two versions

The Diff is symmetric — A and B are simply "the two things you're comparing." Use it to review
what a sprint changed, to confirm a deployment landed, or to audit drift between two client
sites. When you need to *carry* a set of changes from one file into another, that's the
[ISV workflow](/docs/isv-workflow).
