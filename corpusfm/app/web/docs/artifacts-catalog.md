---
title: The Artifacts catalog
slug: artifacts-catalog
order: 20
status: published
public: true
public_section: Concepts
---

# The Artifacts catalog

The **Artifacts** page is the home of everything CORPUSfm has stored — every imported schema,
every automated pull, every merged or generated artifact. It's both your library and your
**selection workspace**: you pick artifacts here and launch tools against them.

## Cards and selection

Each artifact is a card showing its file name, type, and when it was captured. The card type
badge tells you what it is — a schema snapshot (SaveAsXML), an add-on, a merged artifact, or a
generated one.

- **Select** a card with its **+/×** control. Selected cards **lift** into a sticky *Action
  space* above the filter bar.
- You can also **drag** across the grid to select a range.
- With a selection active, the toolbar offers the actions that make sense for it —
  **Explore**, **Diff**, **Merge**, tag, **Index**/**Reindex** (add to or refresh the search
  index), and optional **Summaries** — plus **Delete** as a standalone, confirm-gated control.
  Removing something from the search index (**De-index**) is a per-artifact action on the
  **detail pop-over** (next to Reindex, confirm-gated), not a bulk selection action.

A single click on a card opens its **detail pop-over** (below). Selection is the multi-card
path; the pop-over is the single-card path.

## Filtering and facets

The filter bar narrows the catalog without leaving the page. It is **faceted**: as you pick
filters, the counts beside each facet reflect what's available.

- **Search** matches an artifact's name, description, and notes.
- **Tags** and **system tags** (type, FileMaker version, indexed/unindexed) filter the set.
  See [Tags & filtering](/docs/tags).
- **Latest-only** collapses each file to its most recent version.
- Active filters appear as removable chips inside the bar.

For large catalogs the page is **paginated on the server** — it fetches one page at a time
rather than loading everything, so a big corpus stays responsive.

## The detail pop-over

Opening a card gives you the artifact up close:

- **Name and description** — editable. The description is yours to annotate.
- **Notes** ("Agent notes") — read-only by default; an AI assistant working over
  [MCP](/docs/mcp) can leave context here. Click **Edit** to add your own.
- **History** — this artifact's activity trail: its arrival, diffs, Explorer exports, patches,
  merges, and enrichment (summaries / indexing). A **merged** artifact also shows a
  **Merged from** line in its Overview, linking back to the two source artifacts.
- **Related** — how this artifact connects to others in the catalog, in three sections:
  **Byte-identical** (other artifacts whose stored source is identical — CORPUSfm never
  deduplicates or blocks a re-import, so for a job lineage this shows which scheduled runs
  captured an unchanged schema, and for manual imports it flags an accidental re-import),
  **Same file** (other snapshots of the same FileMaker file, its add-on companion, or merged
  versions — everything sharing the file's root), and **Built from this** (any merged artifact
  that used this one as a source). If nothing connects, the section is empty.
- **Actions** — the type-appropriate set: Explore, **Index**/**Reindex** (add to or refresh the
  search index — no summaries required), optional **Summaries**/**Re-summarize**, the patch tools
  (for the right types), a per-item **Delete** (far-left trash), and **Download**. Summaries are
  optional descriptions; they do not enable search on their own — indexing does.
- **Download** — every artifact downloads the same way, as **`<name>.artifact.zip`**: one file
  holding one document. It is an ordinary zip, so any tool — or an AI you hand it to — can open it,
  and the name says what it is. Inside is a single `.artifact` carrying the artifact's notes,
  memory and tags, the full FileMaker script-step catalog (so a reader can name any step, not just
  the ones this file uses), and CORPUSfm's parsed form of the artifact itself — never the original
  ingested XML. A patch, clip, script or calc carries its own text as the payload; you can still
  fetch that on its own with the raw download, which keeps its own extension inside the zip
  (**`.patch`**, **`.fmclip`**). **Every download is compressed** — the artifact, the raw file, and
  retained source XML alike, the last because a real export runs to tens or hundreds of megabytes.

The detail pop-over shows the artifact's inspectable reality — its name, notes, health,
history, and downloads. Derived, AI-oriented perspectives over an artifact (object
evidence and change-impact, workflows, security reach, the data model, AI usage) are
served through [MCP](/docs/mcp) for an AI assistant to read, rather than as human-UI tabs.

## What you can do from here

The catalog is the launch point for the rest of CORPUSfm:

- [Explore](/docs/explorer) one or several artifacts.
- [Compare](/docs/diff) any two.
- [Merge](/docs/merge) a schema with its add-on.
- [Export to Git](/docs/git-export) for version-controlled, diff-friendly text.
- **Generate summaries** (AI one-line descriptions) and **Index** for [semantic search](/docs/semantic-search) — select artifacts, then choose the action. Each runs as a background job with a **Stop** control (partial work is kept), and appears only when its AI provider is [configured](/docs/settings). Import stays fast; enrichment is this separate, interruptible step.
- **Download** a selection — the toolbar's **Download** action streams the selected artifacts as a
  **single `.zip` bundle** (each item as its own portable `.zip` envelope), then that one file
  downloads. This is deliberate: browsers block or prompt on multiple simultaneous downloads, so a
  server-side bundle is more reliable than firing one download per artifact. Unzip it to get each
  `.zip` back (re-importable via Import).
- **Re-ingest** — refresh a schema artifact's derived data (rendered text, cross-references, gap
  analysis, structure) by re-running the whole pipeline from its **stored source XML**, replacing it
  **in place** (same identity — your notes/tags are kept). It re-indexes/re-summarizes only if the
  artifact already was. Available per-artifact in the detail pop-over and in bulk from the selection
  toolbar; shown only for schema artifacts that **retained their source** (a deliverable, or one whose
  source was deleted to reclaim space, is skipped — re-upload it to refresh). Distinct from **Reindex**,
  which only re-embeds the existing text. It's queued — watch progress on the Queue.

## Paste a clip

The **Paste** button (next to Import) turns FileMaker clipboard content into a catalog artifact —
without a file. Import handles files; Paste handles what you copy.

- **What it accepts** — the deliverable *text* types: an **fmClip** (what you get when you copy
  script steps, fields, tables, value lists, or custom functions in FileMaker — an
  `fmxmlsnippet` clip), an **fmCalc** (a calculation you copied from FileMaker's calc editor), or
  an **fmScript** (fmscript.org script text). Pasting a *file* (a schema XML, an add-on, or a
  downloaded artifact `.zip`) sends you to **Import** instead.
- **Type is recognized where it can be** — an fmClip is detected automatically (it's XML with a
  known root); calculation and script text are indistinguishable from ordinary text, so you pick
  the type from the dropdown. Whatever is detected is a suggestion you can override.
- **It names itself.** Every paste gets a structural name derived from the XML — a complete named
  object keeps its name (`fmClip: UMA.APP.Features.Goto`), otherwise a count describes it
  (`fmClip: 7 Script Steps`, `fmClip: 3 Fields`, `fmClip: 2 Objects`); a calculation or script becomes
  `fmCalc: Untitled Calc` / `fmScript: Untitled Script`. The name is never required and always editable —
  it's just a findable default so pasted artifacts don't collide in the catalog.
- **Fragments are welcome.** A partial selection — a few steps from inside a loop, one field — is a
  valid paste. The pop-over shows a heads-up if a clip's blocks are unbalanced or its references
  won't resolve here, but it never blocks the save. Recognition (is it a clip at all) is the only
  requirement.
- **Size limit — 8 MB.** A paste is capped at **8 MB** of text (measured as encoded bytes, so
  multi-byte characters count for more than one). This applies to both the auto-inspect on paste and
  the save. A larger paste is declined with **"Paste too large."** and nothing is stored. A real
  FileMaker clip is text and sits well under this, so reaching the cap usually means the content
  isn't a clip.
- **Global paste** — you can also just press **⌘V / Ctrl-V** anywhere on the Artifacts page: text
  opens Paste, a copied file is sniffed and routed (a clip is stored; a schema export / add-on /
  an artifact `.zip` opens Import, pre-loaded). Pastes into a search or name field behave normally. This works
  in current **Safari** and **Chromium** browsers (Edge/Chrome).
- **Drop files onto the window** — drag one or more files anywhere onto the Artifacts page and a
  "Drop to import" cue appears. Each file is recognized by its **content**, not its extension, and
  routed on its own: a **schema export** (`FMSaveAsXML`), an **add-on** (`.fmaddon`), or a downloaded
  an artifact **`.zip`** queues through Import (with per-file progress for large exports); a **FileMaker clip**
  (`fmxmlsnippet`) is stored straight to the catalog. A **`.fmp12`** or a **DDR report** (`FMPReport`)
  is declined per file with the fix (export *Save a Copy as XML → Include details* instead), while the
  valid files in the same drop still queue. Dropping files never disturbs the drag-to-**select** gesture
  (dragging a card onto the selection space still selects it). Import stays available as its own button.

To hand a clip *back* to FileMaker, open the fmClip's detail and use the **Raw** tab — it shows the
clip XML with a **Copy** button. The browser can't write FileMaker's native clipboard flavor, so
reconstitute it with the MBS plugin (`Clipboard.SetFileMakerData`) or FmClipTools, then paste into
FileMaker.
