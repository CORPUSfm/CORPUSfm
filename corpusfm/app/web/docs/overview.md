---
title: Overview
slug: overview
order: 10
status: published
public: true
public_section: Get started
---

# CORPUSfm

**CORPUSfm** is a schema-intelligence platform for FileMaker developers. It ingests
FileMaker's schema export (*Save a Copy as XML → Include details for analysis tools*),
stores versioned snapshots as **artifacts**, and exposes each schema through several lenses —
an interactive Explorer, a color-coded Diff, Git export, and an MCP server that lets an AI
assistant work with your schema directly.

## Your first artifact

Use this checklist after you have signed in. It ends with your FileMaker solution open in
Explorer, so every step has something visible to verify.

### Before you begin

- You need a FileMaker 21 or newer file that you can open in FileMaker Pro.
- Your CORPUSfm account needs **Library + MCP** access. If **Artifacts** is absent from the
  sidebar, ask a CORPUSfm administrator for that access.
- If you are an administrator, check **Settings → Health** first. Continue when storage and
  the application are ready. Other users can continue when the Artifacts page loads normally.

### Import and inspect

1. In FileMaker Pro, choose **File → Save a Copy as XML** and enable **Include details for
   analysis tools**. Save the schema XML somewhere your browser can reach.
2. In CORPUSfm, open **Artifacts**, choose **Import**, and drop or select that XML file.
3. Wait until the upload is handed to the server. You may leave the pop-over after that. If
   processing continues in the background, open **Queue** to watch it.
4. Return to **Artifacts**. The import is complete when a card carrying the FileMaker file's
   name appears; CORPUSfm never shows a half-built artifact in the catalog.
5. Select the artifact card and choose **Explore**. Explorer should open with the schema's
   tables, fields, scripts, layouts, relationships, and other catalogs in its sidebar.

You now have a verified first artifact. For the import rules and failure messages, see
[Importing schema](/docs/importing). To learn the inspection surface, continue with
[Exploring a schema](/docs/explorer).

### Useful next recipes

- Import a later export of the same file and [compare the two artifacts](/docs/diff).
- [Tag the artifact](/docs/tags) or [index it for semantic search](/docs/semantic-search).
- [Connect an AI assistant over MCP](/docs/mcp).
- [Create a Job](/docs/jobs) when you are ready to automate repeat imports.

### Problem-solving guides

When the route is the question, start with a guide: [choose an import path](/docs/choose-schema-import-path),
[repair an MCP connection](/docs/mcp-client-cannot-connect), or [work out why an update is not appearing
or applying](/docs/update-not-appearing-or-applying).

## How CORPUSfm is organized

Everything in CORPUSfm follows one model: **ingest → transform → maybe persist**.

- **Ingest** turns a FileMaker schema export into an *artifact* — a self-contained, analyzed
  snapshot. See [Importing schema](/docs/importing).
- **Transform** views that artifact through a lens — [Explorer](/docs/explorer),
  [Diff](/docs/diff), [Git export](/docs/git-export) — or feeds it to an
  [AI assistant over MCP](/docs/mcp).
- **Persist** keeps versioned artifacts in the **Catalog**, where you tag, filter, compare,
  and index them. See [The Artifacts catalog](/docs/artifacts-catalog).

## Finding your way around

The sidebar is grouped by what you're doing:

- **Automation** — [*Jobs*](/docs/jobs) pull schema from FileMaker Server on a schedule;
  *Monitoring* watches their health, and *Runs* records completed automation.
- **Library** — your stored schema: [*Artifacts*](/docs/artifacts-catalog) (the catalog),
  [*Tags*](/docs/tags), *MCP*, and the *ISV Tool* when your account has that access.
- **System** — About and Queue for everyone, plus Logs and Settings for administrators.

Explorer, Diff, and Merge are actions on the Artifacts catalog rather than separate sidebar pages.
Select the artifacts you want, then choose [Explore](/docs/explorer), [Diff](/docs/diff), or
[Merge](/docs/merge) from the action bar.

## Where documentation lives

This in-app documentation covers **using and configuring** the version of CORPUSfm you are
running. Open a page or pop-over's **?** button for its relevant article, or use the
documentation drawer to search all articles.

The repository `README` owns acquiring and installing the application plus the recovery
procedures that must remain available when CORPUSfm itself cannot be reached. The verified
installer package owns the platform-specific installation commands.
