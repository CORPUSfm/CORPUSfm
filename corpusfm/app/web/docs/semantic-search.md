---
title: Semantic search & the index
slug: semantic-search
order: 70
status: published
public: true
public_section: AI
---

# Semantic search & the index

Beyond exact-name filtering, CORPUSfm can search your schema by **meaning** — "where do we
calculate sales tax", "scripts that email a customer" — and return the relevant objects even
when they don't contain those words. This is powered by a **vector index**.

**Indexing is the search substrate; AI summaries are optional.** The index is built from each
object's own rendered text, so semantic search works the moment an artifact is indexed —
*with or without* summaries. Summaries are a separate, optional enrichment (see
[the catalog](/docs/artifacts-catalog)); when you also have summaries, they add an extra
searchable layer on top of the raw index, but they are never required for search.

## Turning it on

Semantic search is optional and needs an **embedding model**. Configure one in
**Settings → Integrations**, under *Semantic search*:

- Point it at a local, keyless endpoint — **Ollama** or **LM Studio** — or any
  OpenAI-compatible embeddings endpoint. A preset fills in the endpoint URL; **List models**
  then discovers what that endpoint actually serves so you can pick one. Typical pairs:
  **OpenAI** `https://api.openai.com/v1` with `text-embedding-3-small`; **Ollama** (local, free)
  `http://localhost:11434/v1` with `nomic-embed-text`.
- **The endpoint is reached from the CORPUSfm server**, not from your browser: indexing runs on that
  box, so the URL must be reachable from there (`localhost` means the server itself).
- **List models** shows everything the endpoint serves, chat and embedding models alike, with no
  reliable way to tell them apart. **Test** is what proves the model you picked actually embeds.
- **API key:** leave it blank only when the endpoint needs no key (a default local Ollama or LM Studio).
  An authenticated endpoint such as Open WebUI needs one. The embedding key is independent of the chat key.
- **Open WebUI** is an authenticated endpoint: use the **Open WebUI** preset (your Open WebUI
  address followed by `/ollama/v1`) and paste an Open WebUI API key. An administrator enables API
  keys in Open WebUI, and each user creates one in their account settings. **List models** and
  **Test** use the key you typed, so you need not save first. A test with a newly typed key is not
  stored, though: **Save**, then **Test** again to mark the saved configuration verified.
- A **saved** key is only sent to the endpoint it was saved with. After changing the URL to a
  different host, type the key again: **Save** refuses to keep the old key for a new host unless you
  enter the new key or clear the stored one.
- **Clear stored key** removes the stored key when you **Save**; **Cancel** (or **Undo**) keeps it.
- **Embedding batch size** is a throughput setting only — see
  [Embedding batch size](settings.md#embedding-batch-size). It never changes the index, so it needs no reindex.
- **Changing the embedder changes the vector space**: after switching model or provider, reindex your
  artifacts (see [when to reset it](#the-index-is-a-separate-store-and-when-to-reset-it) below).
- Or pick **Azure OpenAI** and enter the resource URL, api-version, embedding **deployment**, and
  key — the embedding endpoint is fully independent of the chat model (own provider + own key). See
  [Azure OpenAI](settings.md#azure-openai) in Settings.
- Click **Test** to verify it embeds. Once verified, indexing controls light up across the app.

For standing up a local Ollama embedder end-to-end — install, CPU tuning, and uninstall per OS — see the
full [Ollama setup guide](/docs/ollama).

## Indexing artifacts

- On the **Import** pop-over, tick **Add to search index** to make new imports searchable
  immediately — no summaries needed.
- In the catalog, the Action space (over a selection) and each artifact's pop-over offer
  **Index** (add to search) and **Reindex** (refresh an already-indexed artifact in place).
- Removing an artifact from the index (**De-index**) is a per-artifact action on each artifact's
  **detail pop-over** (next to Reindex, confirm-gated). It removes just that artifact's entries —
  each artifact (each version) is indexed **independently**, keyed by its own record, so de-indexing
  or reindexing one snapshot never touches another. **Settings → Storage → Semantic index** keeps only
  the vector count and the whole-index **Reset**.
- [Jobs](/docs/jobs) can index each pull automatically; each snapshot is its own index entry, so you
  index (and de-index) whichever versions you want and search them independently.

> **Indexing a large file is CPU-heavy.** A local, CPU-only embedder will **saturate the CPU for the
> duration** of a big index (thousands of forward passes). It's a background job that survives leaving
> the page, but on a **co-located** box it shares CPU with FileMaker Server — **lower the embedder's CPU
> priority** so it yields to FMS under load (full speed when the box is idle). On Linux,
> `corpusfm setup-embeddings --low-priority` does this; see the [Ollama setup guide](/docs/ollama) for
> per-OS steps.

Search results are labelled with the layer they matched — **object_raw** (the rendered-text
substrate) or **object_summary** (an optional AI-summary layer) — so you can see the evidence
behind each hit.

## The index is a separate store — and when to reset it

This is the one piece worth understanding. The vector index lives in **its own store**,
separate from your FileMaker schema data. Clearing one never clears the other. Two consequences,
both handled by **Settings → Storage → Reset semantic index**:

1. **Orphans after a data wipe.** If the schema data store is cleared out of band, the index
   doesn't know — its entries linger, pointing at artifacts that no longer exist. (Deleting an
   artifact from within CORPUSfm *does* clean up its index entries; a raw external wipe does
   not.) **Reset** brings the two back in sync.
2. **Changing the embedding model.** The index bakes in the **dimension** of whatever embedder
   built it, and it tracks that dimension — not the model's identity. Switch to a model with a
   *different* dimension and writes fail outright (CORPUSfm detects this and rebuilds
   automatically). Switch to a *different model of the same dimension* and the vectors would
   silently become incomparable — CORPUSfm guards this by remembering the model and rebuilding
   when it changes. **Reset** is the manual escape hatch for either case.

If search ever feels stale or wrong after you've changed embedders or cleared data, **Reset the
index and re-index** — it's quick and it's the correct fix.

## What gets indexed

Only the meaningful catalog sections are embedded — scripts, fields, layouts, custom functions,
and the like. So a file's index entry count is naturally smaller than its raw object count;
that's expected, not a truncation.
