---
title: Choose how to bring a FileMaker schema into CORPUSfm
slug: choose-schema-import-path
order: 10
status: published
public: true
public_section: Get started
section: Guides
---

# Choose how to bring a FileMaker schema into CORPUSfm

## Problem

You want to import schema from a FileMaker file, but CORPUSfm offers more than one path. The right
choice depends on whether this is a one-time snapshot, a file hosted beside CORPUSfm, or a file on a
different FileMaker Server.

All three routes produce the same kind of artifact. They differ in who creates the schema export and
whether CORPUSfm can repeat the work later.

## Choose a solution

| Route | Use it for | What it needs |
|---|---|---|
| **Solution 1 — Import in the browser** | One file now, or an occasional snapshot | A detailed schema XML you can reach from your browser |
| **Solution 2 — Add a Local job** | Repeat collection from the co-located FileMaker Server | A hosted file, its job credential, and a successful readiness check |
| **Solution 3 — Add a remote-server job** | Repeat collection from a different FileMaker Server | A registered remote server, reachable callback address, and verified server credential |

Start with the browser route unless you already know the import should repeat. A Job is maintained
automation, not a requirement for creating a useful artifact.

## Solution 1 — Import in the browser

**Use this when:** you need one snapshot now, you are evaluating CORPUSfm, or you do not administer
the FileMaker Server that hosts the file.

1. In FileMaker Pro, choose **File → Save a Copy as XML** and enable **Include details for analysis
   tools**.
2. In CORPUSfm, open **Artifacts**, choose **Import**, and select the schema XML.
3. Keep the import pop-over open until the browser finishes handing off the file. You can then use
   **Queue** while CORPUSfm processes it.
4. Return to **Artifacts** and open the resulting card in Explorer.

**Done when:** the file has a completed artifact card and Explorer opens its catalogs. The detailed
accepted formats and rejection messages remain in [Importing schema](/docs/importing).

## Solution 2 — Add a Local job

**Use this when:** CORPUSfm is co-located with the FileMaker Server that hosts the file and you want
on-demand, scheduled, or webhook-driven snapshots.

1. Open **Jobs** and keep the server selector on **Local**.
2. Open the hosted file, choose **Add job**, and name the automation.
3. Enter the FileMaker account credential for this job. Choose its trigger and any artifact options.
4. Save the job, then choose **Verify**. Resolve each readiness message before relying on a schedule.
5. Choose **Run now** for the first proof rather than waiting for the next scheduled time.

**Done when:** the job is verified, its run completes, and its artifact opens from the file or run.
The maintained field, readiness, and scheduling details are in [Jobs & automation](/docs/jobs).

## Solution 3 — Add a remote-server job

**Use this when:** the FileMaker file is hosted on another server and that server can post its export
back to this CORPUSfm installation.

1. Ask a CORPUSfm administrator to register the server under **Settings → FileMaker → Remote
   servers** and verify its OData credential.
2. Set the server record's callback address to an `https://` CORPUSfm address that the remote server
   can reach. A loopback address cannot work from another host.
3. Open **Jobs**, select the registered server, open the file, and add the job.
4. Save and verify the job, then use **Run now** for the first proof.
5. Confirm the posted schema becomes an artifact. Remote jobs are analysis-only; they do not make
   changes to the remote FileMaker file.

**Done when:** the remote run completes and its artifact is available in Explorer. See the
[server and credential fields](/docs/jobs#what-a-job-carries) for the maintained connection model.

## If none works

Record the route you selected, the FileMaker file and server shown in CORPUSfm, the exact readiness or
Queue message, and whether any artifact card appeared. An administrator can then check **Settings →
Health**, **Monitoring**, and **Logs** for the same time.

Do not send the schema XML, a FileMaker password, or a full unreviewed log unless the person helping
you has established a secure way to receive it.
