---
title: An update does not appear or cannot be applied
slug: update-not-appearing-or-applying
order: 30
status: published
public: true
public_section: Troubleshooting
section: Guides
---

# An update does not appear or cannot be applied

## Problem

You expected a newer CORPUSfm build, but the update is not appearing, **Apply update & restart** is not
offered, or the page says another update path is required. These messages distinguish different server
states; they are not interchangeable failures.

## Choose a solution

| What Updates reports | Use this route |
|---|---|
| No recent result, or only a passive notice | **Solution 1 — Refresh the release channel** |
| **Update available (code-only)** | **Solution 2 — Apply the inspected code update** |
| **Needs the installer**, stale runtime stamp, or missing source credential | **Solution 3 — Follow the installer handoff** |
| Divergence or another explicit refusal | **Solution 4 — Preserve the evidence and stop** |

Do not turn an installer handoff or divergence refusal into a code-only update by changing the checkout
manually. The page is telling you which authority owns the next step.

## Solution 1 — Refresh the release channel

**Use this when:** the page has not checked recently, the sidebar only reports that an update may be
available, or an update is not appearing yet.

1. Sign in with **Settings** access and open **Settings → CORPUSfm → Updates**.
2. Choose **Check for updates**. This is a deliberate refresh; the passive sidebar notice does not
   install anything.
3. Read the complete result before choosing a next action.

**Done when:** the page reports **Up to date**, offers a code-only update, or names the installer or
review path that applies to this server. See [Updates](/docs/settings#updates) for the maintained
description of the update authority and MCP equivalents.

## Solution 2 — Apply the inspected code update

**Use this when:** the refreshed result says **Update available (code-only)** and offers **Apply update
& restart**.

**Warning:** applying restarts CORPUSfm and temporarily disconnects browser and MCP sessions. It does
not restart FileMaker Server.

1. Review the displayed target version and release information.
2. Choose **Apply update & restart** and confirm the exact update you inspected.
3. Wait for CORPUSfm to return, then sign in or reconnect the MCP client if needed.
4. Open Updates again and refresh the result.

**Done when:** the running version reflects the inspected update and the page reports **Up to date**.
An MCP client can use `update_status` after reconnecting for the same confirmation.

## Solution 3 — Follow the installer handoff

**Use this when:** Updates says the release needs the installer, the running build stamp is stale, or
the installed checkout has no source-pull credential.

**Warning:** the installer uses elevated rights and may perform FileMaker Server work. Read its plan
and interruption notice before consenting. FileMaker Server administrator credentials are entered for
that run; do not store them in a command or support message.

Updates offers the installer command only when the server has confirmed that the published installer
moves this installation forward:

- **A compatible installer is published** — the command is shown. If Updates calls it an
  **intermediate installer update**, it moves the installation forward but another installer release
  may still be needed before the advertised update is reached.
- **No compatible installer has been published** — the published installer would not move this
  installation forward. No command is shown. Keep using CORPUSfm and check again after the next
  installer release.
- **Installer availability could not be confirmed** — the check could not read the installer
  channel, the result is older than a few hours, or the installation changed since it was taken.
  Choose **Check for updates** again. If it persists, treat it as Solution 4.

1. Keep the Updates result visible and copy the installer command it displays, when one is provided.
2. Run that exact handoff on the CORPUSfm server using the elevated shell named by the installer
   package. Do not substitute a command from another server or an older package.
3. Review the installer plan and continue only when the target installation and stated work are right.
4. After it completes, return to CORPUSfm and choose **Check for updates** again.

**Done when:** the running and checkout versions agree and Updates reports **Up to date**. The verified
installer package remains the authority for platform-specific commands and recovery if CORPUSfm is not
reachable.

## Solution 4 — Preserve the evidence and stop

**Use this when:** the checkout is reported as diverged, the privileged updater refuses the target, or
the page reports an error that is not resolved by the named installer handoff.

1. Do not reset, force-pull, delete, or replace the installed checkout.
2. Record the current version, target version or commit, exact refusal text, and the time of the check.
3. Ask the person maintaining the release or installer to reconcile that evidence with the installed
   package provenance before changing the server.

**Done when:** the maintainer identifies a supported code-only or installer route and the server can
complete it without bypassing the refusal.

## If none works

Collect the Updates result, current and target versions, server platform, time of the attempt, and the
small relevant section of the installer or updater log. Remove credentials, tokens, private package
addresses, and request headers before sharing it. Do not publish a full installation log without
reviewing it for secrets.
