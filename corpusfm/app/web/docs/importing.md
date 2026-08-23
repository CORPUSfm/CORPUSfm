---
title: Importing schema
slug: importing
order: 30
status: published
public: true
public_section: Get started
---

# Importing schema

CORPUSfm reads FileMaker's own schema export. Everything else — Explorer, Diff, search,
automation — works off the **artifact** produced at import. An artifact is a self-contained,
analyzed snapshot: the parsed schema plus cross-references, dead-end analysis, rendered text,
and a completeness profile, all versioned by import time.

Not sure whether to import once or automate collection? [Choose the schema import path that fits the
file and server](/docs/choose-schema-import-path).

## What you can import

| Source | How you make it in FileMaker | CORPUSfm |
|---|---|---|
| **Schema XML** (`FMSaveAsXML`) | *File → Save a Copy as XML → Include details for analysis tools* | **The primary source.** Full schema. |
| **Add-on** (`.fmaddon`) | *File → Save a Copy as XML → Add-on Package* | Secondary — the companion to a host file that uses add-ons. |
| **Clip** (`FMObjectList`) | Copy objects to the clipboard, paste as text | A fragment — a few objects, useful for reference. |

Import from the **Artifacts** page: the **Import** button opens a pop-over where you drop a
schema XML or add-on package (or paste clip XML). A batch of files imports together, each
labeled by the schema's own file name.

The pop-over **uploads each file's bytes** to the server, one file at a time — this is the only part
that runs in your browser, so the pop-over **stays open and locked while it runs** (uploads can't
survive leaving the page); a **Cancel** button stops it, and it releases the moment every file is
handed off. Each handed-off file becomes a **durable pending import** the moment it lands, so from
there the server does the rest — **parsing and cataloguing run in the background**, survive navigating
away *and* survive a server restart, so once the pop-over releases you're free to go watch on
[the Queue page](/docs/queue). If an embedder or an AI summary provider is configured, the pop-over
offers **Add to search index** (enables semantic search — no summaries needed) and, separately,
**Generate AI summaries** (optional descriptions) to run automatically afterwards on the background
queue — the import itself never waits on them.

A file that's still importing shows on the Queue page but **never as a half-finished card in the
Catalog** — an artifact appears there only once it's fully analyzed.

## What's rejected, and why

- **Schema XML without analysis detail** (`Has_DDR_INFO="False"`) — re-export with *Include
  details for analysis tools* checked. Without it the deep catalogs are missing.
- **Database Design Report** (`FMPReport`, from *Tools → Database Design Report*) — a different,
  older format with strictly less data and no stable object identity. Export `FMSaveAsXML`
  instead.
- **FileMaker older than 21** — see the version floor below.

## Version floor: FileMaker 21+

CORPUSfm requires **FileMaker 21 or newer**. Earlier versions don't emit the analysis detail
CORPUSfm depends on, and their internal reference values are volatile enough to produce false
differences between otherwise-identical schemas. FileMaker 2026 is first-class.

A file that lacks the analysis section is rejected at import with the reason and the fix, so you
never end up with a half-analyzed artifact.

## About add-ons

If your solution uses FileMaker add-ons, the schema XML is still the authoritative source — but
add-on-contributed scripts appear under internal UUID names, which makes "is this script
actually unused?" ambiguous from the host file alone. Import the **add-on package** alongside
the host and [merge the two](/docs/merge) to resolve those names and get accurate dead-end
analysis.

## After import

The artifact lands in [the Catalog](/docs/artifacts-catalog). From there you can
[explore](/docs/explorer) it, [compare](/docs/diff) it against another version,
[tag](/docs/tags) it, or [index it for semantic search](/docs/semantic-search).
