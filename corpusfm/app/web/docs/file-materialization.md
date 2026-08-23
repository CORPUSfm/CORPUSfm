---
title: Materializing files
slug: file-materialization
order: 160
status: published
public: true
public_section: Workflows
---

# Materializing files

Patches carry *incremental* change into an existing file. The other origination path builds a
**whole, hostable file** from a complete schema export — no FileMaker Pro in the loop.

On a co-located server, CORPUSfm can take a complete `FMSaveAsXML` (assembled or reconstructed)
and materialize a working `.fmp12` from it, then optionally verify that it hosts cleanly on
FileMaker Server using a sandbox slot — production is never touched.

> **Requires FileMaker Server 2026.** Materialization uses `FMUpgradeTool --generateDBFile`, which
> **only the FMS 2026 (26.x) build carries**. FMS 2024 has no `FMUpgradeTool` at all; FMS 2025's 22.x
> tool can apply patches but **cannot** materialize files. This is gated by your FileMaker Server
> *version*, not your operating system. The **Settings → Health** tab reports availability (the
> `generate_db_file` row) and the feature stays hidden where the 26.x tool isn't present.

## What it consumes

The input is a **complete schema export**, not a patch. The minimum that materializes a hostable
file is base tables, a table-occurrence for each, and named fields — enough for FileMaker to open
the file to a normal state. From there a [patch](/docs/applying-patches) can layer on the rest.

## Reconstructing a missing file

This pairs with CORPUSfm's **cross-file reconstruction**. When a solution spans several files
and one is missing, the files that *reference* it still describe its external interface — the
tables, key fields, and scripts they reach into. CORPUSfm aggregates those references into an
interface skeleton, names what it can deduce (from join partners, layout labels, calculation
references), and is explicit about its **blind spots** — it never fabricates a field it can't
evidence.

That skeleton can be emitted as a complete schema export and materialized into a real, hostable
file — recovering a missing file's interface from its siblings alone.

## One honest caveat

A freshly materialized file hosts, but its default account has no extended privileges, so OData
access needs an account added by the developer. A reconstruction skeleton deliberately emits no
accounts — security is a blind spot it won't guess at.
