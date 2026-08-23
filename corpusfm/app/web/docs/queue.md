---
title: The queue
slug: queue
order: 75
status: published
public: false
---

# The queue

Background work in CORPUSfm runs on one shared server queue, **oldest first**. The **Queue** page (under
System) is the system-wide view: every job in flight, which step it's on, and anything that failed.
Because some steps — generating AI summaries for a large file — can take many minutes, this is where you
see *what's holding up the show*. Anyone signed in can watch; you can act on **your own** jobs (admins can
act on anyone's).

## One job, one pipeline

Each row is a single job walking a short **pipeline of steps**. The row shows the whole pipeline as a
trail of chips, with the **highlighted chip** marking the step it's on right now:

- **Import** — `upload → ingest`, then any enrichment you opted into (`→ summarize → index`). *Upload* is
  your browser sending the file's bytes; *ingest* parses them into an artifact; the enrichment steps follow.
- **Job run** — a scheduled or manual `pull` from FileMaker Server.
- **Enrichment** — `summarize` and/or `index` on an existing artifact (from the catalog's Summaries /
  Index actions or the MCP tools).
- **Deliverable** — saving a patch, clip, script, or calc.

A job stays a **single row** for its whole life — as it finishes one step and moves to the next, the
highlight advances along its trail. It leaves the queue only when the whole pipeline is done.

## Why a queue

The slow work — one AI call per object when summarizing, thousands per file — runs **one at a time per
kind of step**, so the search index isn't corrupted and the AI endpoint isn't overwhelmed. Rather than
rejecting a request when something's already running, CORPUSfm queues it: every job takes its place in
line and runs when its turn comes. Nothing is lost; you don't retry by hand.

Different kinds of step run alongside each other — an import can *ingest* while an unrelated artifact is
being *indexed* — but within one kind it's strictly first in, first out.

## Status and controls

Each row shows a status and its owner:

- **Running** — a worker is on its current step now. It runs to the end of that step (there's no
  mid-step stop).
- **Queued** — waiting its turn. **Cancel** removes it before it starts.
- **Failed** — a step errored, with the message shown. The job rests on that step for you to **Restart**
  (re-run the current step) or **Delete**; **Clear failed** removes them all. A failure is *try-once* —
  CORPUSfm never silently retries, so you decide what happens next.

## Uploading happens in your browser

Sending a file's bytes to the server is the only part of an import that runs in your browser — it shows
per-file in the **Import** pop-over while it runs. Once uploaded, the import is a server job (above) that
survives leaving the page. On an HTTPS box with a valid certificate, an upload also keeps going in the
background if you navigate away mid-upload.
