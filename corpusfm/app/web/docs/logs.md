---
title: Application Log
slug: logs
order: 84
status: published
public: false
---

# Application Log

The **Logs** page is a read-only view of CORPUSfm's own application log — the running record the server
writes as it works. It's the place to look when something isn't behaving and you want the raw detail
behind it.

At the top it shows the log file's location, size, and when it was last written. Below that is the log
itself, tailing the most recent entries.

## Filters

- **Lines** — how many recent lines to show (50 up to 5000). The view always shows the *newest* entries.
- **Level** — **ALL**, or narrow to **WARNING** / **ERROR** to cut straight to problems.

**Refresh** re-reads the file with the current filters.

## How it relates to the other review pages

- **Logs** (this page) — the raw application log, for troubleshooting *how* something happened.
- **[Monitoring](/docs/monitoring)** — health and alerts: *whether* something is wrong.
- **[Runs](/docs/runs)** — the per-job execution ledger: *what* each job run did.

The log is a diagnostic tail, not a permanent audit trail — it rolls over as the server runs.
