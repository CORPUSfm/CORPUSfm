---
title: Jobs & automation
slug: jobs
order: 80
status: published
public: true
public_section: Workflows
---

# Jobs & automation

A **Job** is a named unit of automation: it pulls a schema export from FileMaker Server,
ingests it into an [artifact](/docs/artifacts-catalog), and optionally indexes it and exports
it to Git — on a schedule, on demand, or on a webhook.

If you have not chosen between a browser import, a Local job, and a remote-server job, start with
[Choose how to bring a FileMaker schema into CORPUSfm](/docs/choose-schema-import-path).

## The file-centric model

On a co-located server, the **file is the unit of automation**. The **Jobs** page is a gallery
of every database hosted on the server. Each card shows whether that file is automated and how
— "Nightly · 02:00", "2 jobs", or "Not automated" — with a green accent on the automated ones.

You attach automation by opening a file's pop-over and adding jobs to it. A file can carry
several jobs (say, an hourly index refresh and a nightly Git export). **Each job carries its
own connection credential** — entered on the job, stored encrypted with the job's record
(never in a config file), and read only when the job runs.

## Readiness

Before a job can run it has to be **provable** — the file reachable, its credential working,
the export add-on present, and OData responding. The pop-over walks you through verifying each
job once; the result is stored with the job so the gallery can show readiness at a glance.

Two jobs that target the **same file** never run at once — if one is already running, the other
simply waits its turn (it's queued, not refused).

## What a job carries

- **A trigger** — manual, a **schedule**, or a webhook. See
  [Schedules](#schedules-run-on-the-servers-clock) below.
- **A server** — **Local** (the co-located FileMaker Server, the default) or a registered
  **remote server**. A remote-server job pulls over the network via *push*: CORPUSfm asks the remote
  server to run the addon's `PostToServer` script, and the server posts its schema back to CORPUSfm.
  Register remote servers under [Settings → FileMaker](/docs/settings#remote-servers); a remote job
  takes its credential from that server record, not from the fields below. If you hold the **Settings**
  gate you can also add a server with **＋** beside the Server selector, or **Edit** the one currently
  selected, without leaving this page; Settings remains where the whole collection is managed and where
  a server is removed. Remote jobs are
  **analysis only** (Explorer / Diff / cross-reference / git export) — never patching. Because the
  remote server posts *back* to this CORPUSfm, a remote job needs a **callback address** that server can
  reach (an internal/LAN `https://` address is fine; a loopback one won't work from another host). It
  comes from the **server record's own Callback URL** — so two remote servers on different networks can
  each be right about a different one — falling back to this install's
  [**MCP address**](/docs/settings#mcp-address) when the record carries none.
- **Its connection credential** — the FileMaker account a **Local** job pulls with (see above). A
  remote job uses its server's OData account instead.
- **Artifact tags** — tag names the job applies to each artifact it produces, as ordinary
  [tags](/docs/tags).
- **Index-on-ingest** — embed each pull for [semantic search](/docs/semantic-search). Each
  artifact owns its own index; deleting the artifact removes its index with it.
- **Retention** — keep only the last *N* artifacts for this job. Pruned versions are removed cleanly —
  their search index and history go with them, exactly as a manual delete.
- **Export timeout** — how long CORPUSfm waits for FileMaker to write the export, in minutes. Leave
  it blank for the default of 10 minutes; raise it for very large files. The export is one blocking
  call with no progress signal, so this is a hard limit rather than a hint — when it is reached the
  run fails instead of finishing late.
- **Git export** — push each pull as version-controlled text to a repository. See
  [Git export](/docs/git-export).

## Schedules run on the server's clock

A schedule is two things: **which days of the week**, and **what time**. That is all of it.

Pick the days with the seven toggles — Sunday first, one letter each — then set the hour and the
minute. The toggles show all seven days at once, so the letters are read by position; the jobs list
spells the days out, because a row only shows the ones you picked.

A schedule means the wall clock of the machine CORPUSfm is installed on — not UTC, and not the
clock on the computer you are reading this from. A job set for `02:00` runs at two in the morning
**there**. The job form shows the server's current time beside the fields so you can set a schedule
without working anything out, and every scheduled time CORPUSfm shows you is labelled with the clock
it is in. If the server cannot tell CORPUSfm what its time zone is, schedules fall back to UTC and
say so rather than quietly pretending to be local.

Four things follow from that, and they are worth knowing before you rely on a schedule:

- **Saving a schedule does not run the job.** It waits for its next matching time — and the very
  next minute counts, so a schedule set at 08:30:12 for 08:31 does run at 08:31. **Run now** is the
  only thing that starts a job immediately.
- **A missed time is not made up later.** CORPUSfm checks once a minute. If CORPUSfm was down — or
  **paused** because it could not read its database — when a job was due, that occurrence is simply
  gone. It does not fire the moment the machine or the database comes back. This matters most after
  a long outage, where the alternative is every idle job in the system starting at once.
- **A job already running does not stack.** If the previous run is still going when the next time
  comes round, that occurrence is skipped rather than queued behind it.
- **A crash can occasionally run a job twice.** If the server dies in the moment between starting a
  job and recording that it started, the next check can start it again. It is rare, it is not
  corruption, and it is worth recognising rather than investigating.

Schedules have **minute** resolution.

### If a job says "Schedule needs updating"

Earlier versions of CORPUSfm took a cron expression. Those were converted automatically: `0 2 * * *`
became *Every day at 02:00*, `0 3 * * 0` became *Sun at 03:00*, and so on.

A few cron expressions say things the current model deliberately does not offer — an interval
(`*/5 * * * *`), a day of the month, the second Monday, two different hours in one day. Rather than
guess at something close, CORPUSfm **stops running that job** and marks it **Schedule needs
updating**. The old expression is shown on the job so you can see what it used to say. Choose the
days and time you want and save; the old expression is then discarded.

This is deliberate. A job quietly running at a time you did not choose is much harder to notice
than a job that tells you it needs attention.

**Daylight saving is treated plainly, not cleverly.** Twice a year the server's local clock does
something unusual, and CORPUSfm follows it rather than compensating:

- On the morning clocks go **forward**, the skipped hour never happens on the server's clock, so a
  job scheduled inside it does not run that day.
- On the morning clocks go **back**, the repeated hour happens twice, so a job scheduled inside it
  runs twice that day.

Both are one-day-a-year effects of the clock itself. If a job must never miss and never repeat,
schedule it outside the hour your region shifts.

## Runs

Every execution is recorded as a **Run** with its status, trigger, duration, and the artifact it
produced. Job, run, and artifact are linked by identity, so the trail stays correct even as files
are renamed — and each run snapshots what it needs to display, so the history still renders after
a job is deleted.

The **Runs** page lists **successful** runs. Each row carries its own actions: **Job** (open the
job that produced it), **Explore** (its artifact), **Diff** (against the previous artifact from
that same job — disabled on a job's first run), and **Filter** (narrow the page to that job).

Failures are not listed here, because a failure is something to fix rather than to keep: a failing
job turns its file card red on the [Jobs](/docs/jobs) page with its error, and the failed work
parks on the [Queue](/docs/queue) for a **Restart** or **Delete**. Failed runs *are* still
recorded — an AI client can retrieve any run, including a failed one, by its run id.

## Monitoring

Job health and failure alerts have their own page — see [Monitoring](/docs/monitoring).
