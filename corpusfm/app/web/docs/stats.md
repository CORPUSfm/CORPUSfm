---
title: System Stats
slug: stats
order: 76
status: published
public: false
---

# System Stats

**Stats** (under System) shows how CORPUSfm itself has been performing. Anyone signed in can open it.
It is read-only: there is nothing to configure, reset or delete.

## What it records

One summary per minute, kept for **seven days**:

- **CORPUSfm memory and CPU** — the CORPUSfm process tree (the web process plus any child processes
  sampled at that moment) and the web process on its own. This is CORPUSfm, not FileMaker
  Server. Host available memory appears as a separate context graph.
- **FileMaker database calls** — how many calls CORPUSfm made, how long they took (p50, p95, max),
  errors, and the peak number in flight.
- **Catalog, cache and queue-view work** — catalog synchronization passes, the indexed-membership
  cache, and the reads behind the Queue view.
- **Queue lanes and generation** — work started, completed and failed on each background lane, busy
  time, how long items waited, and Explorer/Diff generation jobs.

Only numbers are kept. Stats never records file, artifact, job or account names, server addresses,
URLs, queries, database objects, error messages or credentials.

## Reading the graphs

- Choose **1 hour**, **24 hours** or **7 days**. **Earlier** and **Later** move through the retained
  history by that range; **Return to now** comes back to the present.
- Times are shown in your browser's local time zone; hover the time range to see the exact UTC window.
- Each line's legend shows its **minimum, mean and maximum** for the window. Select a legend entry to
  hide or show that line — this only changes the view.
- Hover over a graph, or focus it and use the arrow keys, to read the values at one point.
- **A gap means nothing was recorded** — CORPUSfm was not running, or a sample could not be taken. It
  is never drawn as zero. A counter that reads zero means CORPUSfm was running and nothing happened.

## When history is unavailable

If CORPUSfm cannot write its history, the page says so and shows only the most recent minutes it holds
in memory. Collection problems never affect the rest of CORPUSfm.
