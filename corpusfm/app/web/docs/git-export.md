---
title: Git export
slug: git-export
order: 90
status: published
public: true
public_section: Workflows
---

# Git export

CORPUSfm can write any artifact out as **per-object text files** and push them to a Git
repository. Because each script, field, and table becomes its own readable `.txt`, a normal
`git diff` shows exactly what changed between versions — and the same text is ideal for feeding
to an AI assistant.

Many files map cleanly to one repository: each FileMaker file lands under its own folder, and
successive versions of that file diff cleanly over time.

## What gets written

Two text forms per object (under `<FileName>/rendered/…` and `<FileName>/structured/…`),
plus a Mermaid ERD of the data model:

- **Rendered** — the human-readable FileMaker rendering: script steps, calculation formulas,
  relationship predicates, field definitions (the same view as the Explorer's *Rendered* tab),
  enriched with a one-line summary and a cross-reference block.
- **Structured** — the stable identity facts: name, internal ID, UUID, and key attributes.

The **original ingested `.xml` is never written** — the export is readable code, so a `git diff`
shows a changed script step or tweaked calc, not noisy XML.

A **job** can choose which forms it writes — **Export content**: *Rendered + structured* (the
default), *Rendered only*, or *Structured only*. Pick one when a repository only needs the
human-readable view, or only the identity facts.

## Credentials

A **registration** in **Settings → Integrations** is one Git credential, of one of two types:

- **PAT** (a personal access token over HTTPS) — reaches *many* repositories. The repository is
  chosen downstream, on the job or the artifact, and is editable there.
- **Deploy key** (SSH) — bound to **one** repository. The repository is fixed.

The secret (token or private key) is **encrypted at rest** and stored **in CORPUSfm's own
database** (not a file on the server), so your credentials are **portable** — they survive a
reinstall, a restore, or moving the database, and travel with the rest of your data. CORPUSfm
**verifies a credential before trusting it** — the **Test** button does an authenticated check
against the remote.

> Use a **fine-grained PAT** scoped to the repositories you want, with **Contents:
> read/write**. There's no human at the server to complete a 2FA or OAuth prompt, so a held,
> scoped token is the right fit.

## Where the repository is chosen

- On a **job**, pick the credential and (for a PAT) the target repository. Each run exports and
  pushes, then stamps the produced artifact with that target.
- On an **artifact**, the **Export** tab shows the stored target, lets you repoint it (the
  repository is editable for a PAT, fixed for a deploy key), and **Export & push** reports
  whether the push landed.

An artifact owns its Git target independently of the job that made it — so you can re-export an
old artifact to a different repository later without disturbing the job.
