---
title: The AI build loop
slug: ai-build-loop
order: 150
status: published
public: true
public_section: AI
---

# The AI build loop

This is the end-to-end path an AI assistant follows to take a *goal* — "add a contacts module",
"wire an approval workflow" — and land it as a verified schema change, all over
[MCP](/docs/mcp). CORPUSfm is the substrate the assistant drives; it isn't itself the
generator.

The assistant can pull the whole orchestration as a single build guide; the steps below are the
shape of it.

## The loop

1. **Discover** — find the target file and any reference material: list artifacts (by
   [tag](/docs/tags) — e.g. a `seed` baseline), pull schema context, search semantically.
2. **Ground** — read the [authoring](/docs/patch-authoring) grammar, the capability ledger, and
   real step exemplars from the corpus, so the patch is built from what genuinely works.
3. **Author** — compose the patch against the target's own ids and installed add-on
   infrastructure, flagging anything the tool can't express rather than fabricating it.
4. **Check** — run the static coherence + simulation gate. Fix and re-check until it's
   consistent and would host.
5. **Save** — store the patch as an artifact, so it's a first-class, reviewable thing in the
   [Catalog](/docs/artifacts-catalog).
6. **Apply, safely** — dry-run against the sandbox, verify intent landed, then the token-gated
   two-step apply. See [Applying patches](/docs/applying-patches).
7. **Confirm** — re-ingest the patched file and compare, so "it worked" is *shown*, not assumed.

## Where the reach ends

The assistant is honest about limits. Some things a schema patch can't express — for instance,
a privilege gate is implemented as script logic, not fabricated as a constructible privilege
set; a change that needs a base table the file doesn't have is flagged as missing rather than
invented. The capability ledger is what keeps generation inside what the tool can actually do.

## Two origination paths

- **Incremental change to an existing file** → a **patch** (this loop).
- **A whole new file** → assemble a complete schema export and **materialize** it. See
  [Materializing files](/docs/file-materialization).
