---
title: Applying patches
slug: applying-patches
order: 140
status: published
public: true
public_section: Workflows
---

# Applying patches

On a **co-located** server (CORPUSfm running on the FileMaker Server box), a patch doesn't have
to leave the building to be applied. CORPUSfm can dry-run it against a sandbox copy and apply it
to a hosted file — with production protected at every step.

> **Requires FileMaker Server 2025 or newer.** Apply uses FileMaker Server's own bundled
> `FMUpgradeTool` (FMS 2025 ships the 22.x build; FMS 2026 the 26.x build). **FMS 2024 ships no
> `FMUpgradeTool`, so apply is unavailable there** — this is determined by your FileMaker Server
> *version*, not your operating system (the behavior is identical on Windows and Linux). The
> **Settings → Health** tab reports your box's status and won't offer apply if the tool isn't present.

This is the "confirm" half of the loop that begins with [patch authoring](/docs/patch-authoring)
or the [ISV diff](/docs/isv-workflow).

## The verification ladder

A patch passes through progressively stronger checks. The cheap ones run first so a bad patch
fails fast and free:

1. **Coherence** — references inside the patch resolve.
2. **Simulation** — the schema the patch would *produce* is consistent and would host, deletes
   included.
3. **Dry-run** — the patch is really applied by the upgrade tool to a **copy**. Production is
   never touched; nothing is swapped or reopened.
4. **Verify** — the dry-run result is re-ingested and compared against intent: every change the
   patch meant to make is confirmed to have landed, and any collateral change is flagged.
5. **Apply** — only then, the real apply to the hosted file.

## How apply protects production

The real apply is a close → patch → swap → reopen sequence with safeguards:

- The live file is **backed up first** and **restored automatically** if anything fails.
- During the dry-run, production is **never opened** — the sandbox is a separate, pre-provisioned
  slot.
- CORPUSfm's **own storage database can never be a patch target** — it's refused at every
  control point, by name, regardless of how a request arrives.
- The apply is **two-step and token-gated** over [MCP](/docs/mcp): an assistant plans the apply,
  then confirms it with a token — so a destructive operation is always an explicit second act.

## Apply targets — the compartment

On **both** Linux and Windows, what a real apply (or a dry-run) may target is governed by the
**apply compartment** — see [The apply compartment](/docs/settings#apply-compartment). Applying needs a
**verified compartment** on this installation; with none, every target is refused, whatever the
restriction is set to. With the compartment restriction **on** (the default), an apply may target only
a file **hosted from that verified compartment**; anything hosted from FileMaker's default database
directories is refused *before the database is closed*, and a target CORPUSfm cannot positively locate
in a patch zone fails closed. Turning the restriction **off** — for a dedicated patch box — widens the
eligible set to any hosted database except the storage database.

CORPUSfm's own storage database is refused in **every** state. (The older Windows
`windows_apply_allowlist` is superseded by this folder-scoped model and is now ignored.)

## Materializing a whole file

The upgrade tool can also build a **complete, hostable `.fmp12` from a full schema export** —
not a patch, but a whole file. That's a different capability, covered in
[Materializing files](/docs/file-materialization).
