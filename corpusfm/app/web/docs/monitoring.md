---
title: Monitoring
slug: monitoring
order: 82
status: published
public: false
---

# Monitoring

The **Monitoring** page is a glanceable health view of your automation: which alerts are firing right
now, the health of every job, and a history of alerts. A **health dot in the navigation** carries the
signal everywhere, so a problem is visible no matter which page you landed on.

## Scheduler status

At the top, a badge shows whether the background **scheduler** — the process that runs jobs on their
schedule and evaluates alerts — is running, with the time it last checked in. If it stops, that badge
turns to a warning and a `scheduler_stopped` alert fires, so a dead scheduler can't hide.

## Current alerts

The live conditions CORPUSfm watches for:

- **Job failed** — a job's last run ended in error.
- **Job overdue** — a scheduled job hasn't run within its grace period after its expected time.
- **Zero-diff suspicion** — a git-exporting job produced *no* changes for several consecutive runs, a
  possible sign the export silently broke.
- **Scheduler stopped** — the scheduler process isn't responding (see above).
- **Disk low** — free space where artifacts are stored dropped below the threshold.

Each firing alert shows its severity, the job it concerns, and a message. **Acknowledge** (the ✓) hides
an alert for a configurable window (Settings → Notifications → *Suppress*) — useful when you already know
about a problem and don't want to keep seeing it. The condition still evaluates; it's just suppressed
from the Current-alerts list and from outbound notifications until the window passes.

## Job health

A row per job: its source, schedule, last run, and status (`ok` / `overdue` / `—`). This is the
at-a-glance "is everything current?" table. For the full run-by-run ledger, see [Runs](/docs/runs); to
configure a job, see [Jobs & automation](/docs/jobs).

## Alert history

A dated log of alerts that have fired, newest first — the trail of what went wrong and when. Alert
history and your acknowledgements are **stored with your data** (in CORPUSfm's database, not a local
file), so they travel with the corpus and survive a reinstall, restore, or database move.

## Where alerts go

Besides this page, alerts can be dispatched to external channels (a webhook, email) — configure them
under **Settings → Notifications**. The Monitoring page is always the default, no-setup channel.
