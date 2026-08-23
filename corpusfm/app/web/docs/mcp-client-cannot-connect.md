---
title: MCP client cannot connect
slug: mcp-client-cannot-connect
order: 20
status: published
public: true
public_section: Troubleshooting
section: Guides
---

# MCP client cannot connect

## Problem

You added CORPUSfm to an MCP client, but sign-in did not open, approval did not finish, or the client
does not show CORPUSfm tools. A browser approval by itself is not the final proof: the client must
return to the MCP address and complete a harmless request.

## Choose a solution

| What you observe | Start here |
|---|---|
| The browser opened or the connection used to work | **Solution 1 — Reconnect with OAuth** |
| The browser never opens, the address is rejected, or discovery fails | **Solution 2 — Verify the address and client flow** |
| The client cannot perform MCP OAuth | **Solution 3 — Use a personal manual token** |

OAuth is the usual route. A manual token is a compatibility path, not an extra step after OAuth.

## Solution 1 — Reconnect with OAuth

**Use this when:** an approval partly completed, the client previously worked, or the client asks you
to sign in again.

1. Sign in to CORPUSfm and open **Library → MCP**.
2. Copy the MCP address shown there; do not reuse an address from another server.
3. If the failed client appears under **OAuth connections**, choose **Disconnect** for that entry.
   Remove or disconnect the stale server entry in the client as well.
   If the browser showed `Client ID … not found`, also clear the client's saved sign-in for this
   server (Claude Code: `claude mcp logout <name>`) — it reused a registration from before this server
   was reinstalled, and a fresh sign-in re-registers it.
4. Add the displayed address again. Complete sign-in and review the consent page before choosing
   **Approve**.
5. Return to the client and ask it to list CORPUSfm capabilities or artifacts.

**Done when:** the client appears under **OAuth connections** and a harmless capability or artifact
listing returns from the intended CORPUSfm server.

## Solution 2 — Verify the address and client flow

**Use this when:** the client never opens a browser, reports discovery or transport failure, or may be
pointed at the wrong CORPUSfm installation.

1. Compare the client configuration with the exact address under **Library → MCP**, including the
   `https://` host, CORPUSfm prefix, and `/mcp` path (the older `/mcp/` form also works).
2. Confirm the MCP page says the endpoint is active. If it is not active or no address is shown, give
   that visible state to an administrator; do not invent a replacement URL.
3. Follow the client-specific sign-in action shown on **Library → MCP**. Some clients add a server and
   start OAuth as separate actions.
4. Watch which stage fails: opening the address, browser sign-in, consent, the return to the client,
   or the first tool request. Retry OAuth only after correcting that stage.

**Done when:** the browser returns control to the same client registration and the client can complete
a capability or artifact listing. The underlying connection model is documented in
[Working with an AI assistant](/docs/mcp#connecting).

## Solution 3 — Use a personal manual token

**Use this when:** the MCP client supports HTTP headers but cannot perform MCP OAuth.

**Warning:** a manual token acts as your CORPUSfm account and is shown only once. Treat it like a
password; do not paste it into support messages, screenshots, shell history, or shared configuration.

1. Under **Library → MCP**, create a named manual token for this client.
2. Copy the generated client configuration while the token is visible. Keep the exact MCP address and
   HTTP transport shown by CORPUSfm.
3. Add that configuration to the client and connect.
4. Ask the client for a harmless capability or artifact listing.

**Done when:** the request returns from the intended CORPUSfm server. Delete the token from **Library
→ MCP** when that client no longer needs access. See
[Advanced — manual tokens](/docs/mcp#advanced-manual-tokens) for the maintained configuration forms.

## If none works

Record the client name and version, the MCP host and path with all credentials removed, the stage that
failed, the sanitized error text, and whether CORPUSfm lists an OAuth connection for the client. An
administrator can compare that with **Settings → MCP** and server logs.

Never share an OAuth credential, bearer token, password, private browser callback, or an unreviewed
log containing request headers.
