---
title: Working with an AI assistant (MCP)
slug: mcp
order: 100
status: published
public: true
public_section: AI
---

# Working with an AI assistant (MCP)

CORPUSfm exposes its schema intelligence to AI assistants through an **MCP server**. MCP (the
Model Context Protocol) is an open standard, so **any MCP-capable client** — Claude Code, Codex,
Cursor, VS Code, or another agent that speaks MCP over HTTP — connects to CORPUSfm and works with
your schema **directly** (reading objects, searching, comparing versions) instead of you copying
XML back and forth.

The assistant connects with **its own** access; many clients run on a subscription or plan you
already have (for example a Claude subscription), so there's no separate CORPUSfm API key to manage
and no schema leaving for a third-party service beyond the assistant you choose.

If you already tried to connect and it did not complete, use
[MCP client cannot connect](/docs/mcp-client-cannot-connect) to select a recovery path.

## Connect your first client

Use OAuth when your MCP client supports it. You will approve the client in your browser; there is no
token to copy and the connection receives only your CORPUSfm access.

### Before you begin

- Sign in to CORPUSfm with the account the assistant should act as.
- Open **Library → MCP**. If MCP is absent, ask an administrator for **Library + MCP** access.
- Confirm the page shows an MCP address. If it does not, an administrator must configure that address
  under Settings before an OAuth client can discover sign-in.

### Connect and verify

1. Copy the MCP address shown under **Library → MCP**.
2. Add that address as an HTTP MCP server in your client. The client should open CORPUSfm in your
   browser.
3. Sign in if asked, review the tools the client is requesting, and choose **Approve**.
4. Return to **Library → MCP**. The client should now appear under **OAuth connections**.
5. Return to the client and ask it to list its CORPUSfm tools or list your artifacts. A successful
   connection shows CORPUSfm tools and returns only data your account may access.

If the client never opens a browser, check the client-specific instructions on **Library → MCP**
first. Some clients start sign-in separately—for example, Codex uses `codex mcp login <name>` after
the server is added. If the client does not support OAuth for MCP, use
[Advanced — manual tokens](#advanced-manual-tokens). If OAuth opened but the client cannot connect,
confirm it uses the exact displayed address, then disconnect the failed entry and approve a fresh
connection.

**Hosted connectors are not supported.** Claude.ai and Claude Desktop *custom connectors* and
ChatGPT's web connectors connect from the vendor's cloud — to a public address, with a callback that is
not on your machine — and cannot complete sign-in with CORPUSfm. Use Claude Code, or the Codex CLI /
ChatGPT desktop app (which share one local MCP configuration), instead.

**Codex, non-interactive.** The interactive `codex` session prompts before a CORPUSfm tool call; the
non-interactive `codex exec` cancels any call that would prompt ("user cancelled MCP tool call"), and
`approval_policy = "never"` does not cover MCP tools. Pre-approve the tools you want it to use, per tool,
in `~/.codex/config.toml` — `[mcp_servers.<name>.tools.get_server_info]` then `approval_mode = "approve"`
(modes: `auto`, `prompt`, `writes`, `approve`) — or pass the same key with `-c` on the command line.

**If your browser shows `Client ID … not found`,** the client reused a registration it saved for this
server before the server was reinstalled. Clear that client's saved sign-in for this server (Claude
Code: `claude mcp logout <name>`) and connect again — it re-registers automatically.

## Connecting

The MCP server is served at your CORPUSfm address under `/mcp` (HTTP transport; the older `/mcp/` form keeps working). **Library → MCP** is
the one place your MCP access lives — it shows whether the endpoint is active, lists the clients you've
connected, and lets you connect more. There are two ways in.

### OAuth sign-in (the usual way)

Add the MCP address shown on the page to a compatible client. The client opens your browser, you
**sign in to CORPUSfm** as yourself and **approve** the connection on a consent page listing the tools
your account may use — **no token is ever copied** into the client's configuration. The connection then
acts as **you**, with your current gates.

Each client you approve appears under **OAuth connections** with its name, the CORPUSfm MCP address it
is connected to, when you connected, what you approved, and when you'd need to **sign in again**.
**Disconnect** revokes **only that one connection**: that client stops working
immediately, your other connections and your manual tokens are untouched, no other person's connection
to the same client is affected, and reconnecting means signing in and approving again — nothing is left
approved behind the scenes.

### How long a connection lasts

**Stay connected while you use CORPUSfm, signing in again after 30 days of inactivity or
one year.** Those are the two limits under the default (**Standard**) policy: a connection you keep using
goes on working — the client renews its access **silently in the background**, with no browser prompt
and no consent screen — but it expires if you don't use it for **30 days**, and it always expires **one
year** after you approved it. Each successful silent renewal moves the inactivity date out; nothing moves
the one-year date.

The **Sign in again by** column shows whichever comes first. It is worked out from when you approved this
connection and when it **last renewed successfully** — those are the only moments CORPUSfm records. There
is no log of what a client did in between, so the date moves when the client actually renews (it does that
on its own schedule while you're working), not on each individual request it makes.

An administrator can select a tighter policy for the whole server (**Settings → OAuth connection
lifetime**): **Reduced** is 7 days inactive / 90 days maximum, **Strict** is 1 day inactive / 30 days
maximum. Choosing a tighter one shortens existing connections straight away.

A connection also stops working — before either limit — when you **Disconnect**, when an administrator
deactivates your account, when the server's **MCP address changes** (every connection is bound to the
address it was approved for, so a new one no longer matches), or when CORPUSfm detects a **reused**
credential, which revokes that whole connection as a precaution. In every case you reconnect the same
way: add the address, sign in, approve.

There is nothing to switch on: OAuth sign-in is available whenever the server has an MCP address. If it
does not have one, no client can discover the sign-in at all — an administrator sets the address in
Settings — and manual tokens remain the way in.

### Advanced — manual tokens

For clients or development setups that **can't do OAuth sign-in**, mint a **named bearer token** on
the same page. You can mint **many** (one per app — e.g. `laptop-claude`, `work-cursor`); each is
**shown once**, and you delete one to revoke it (there's no rotate — delete the old, mint a new).
Deleting a token never affects your other tokens or your OAuth connections, and you never need both
for the same client.

When you mint, the pop-over gives the ready-to-paste connect details for several clients:

```
claude mcp add --transport http corpusfm-<your-host> <your-base>/corpusfm/mcp \
  --header "Authorization: Bearer <token>"
```

...and a JSON block for **Cursor** (`mcpServers`) and **VS Code** (`servers`). The
registration name is **derived from this server's host** (e.g. `corpusfm-devservice-microk12`) so each
box you connect to gets a distinct name — it must be unique in your client, and it also becomes the tool
prefix (`mcp__corpusfm-devservice-microk12__…`). Rename it if you prefer, but keep it distinct per
server. The three pieces are the same everywhere — point your MCP client at the **URL**
`<your-base>/corpusfm/mcp`, use the **HTTP** (streamable) transport, and send the
**`Authorization: Bearer <token>`** header. Any MCP client that accepts those will connect.

Either way in, the connection carries exactly your own access gates, so the assistant **sees and can use
only the tools your gates allow** — tools you can't use don't even appear in its list. After adding the
server, restart your assistant so it picks up the tools.

There is no server-wide token and no administrator master key: **every way in belongs to a person**, so
what an assistant can do is always exactly what its owner can do. On a brand-new server, where nobody has
a token yet and the web UI may not be reachable, an administrator mints the first one on the box itself
with `corpusfm users mint-mcp-token <username>`.

## What the assistant can do

Once connected, the assistant has tools to **understand** your corpus:

- **List and filter artifacts** (including by [tag](/docs/tags)).
- **Pull schema context** for a file — its tables, fields, scripts, relationships, security —
  shaped for the assistant to reason over, with the option to focus on one neighborhood.
- **Semantic search** across [indexed](/docs/semantic-search) artifacts — search works from an
  artifact's index alone (no summaries needed); each hit is labelled with the layer it matched.
- **Compare** two artifacts and read a section in full.
- **Reconstruct a missing file's interface** from the sibling files that reference it.
- **Read neutral evidence and change impact** for an object — its inbound/outbound references and
  what appears to depend on it, each edge marked `observed` or `inferred`. These are facts, never a
  verdict (a zero count is "no observed dependents", not "safe to delete").
- **Pull compressed perspectives** over an artifact: its workflows (what a user can do + the data
  each action touches — list them compactly or fetch one entry in full by name), security reach
  (what each privilege set can access), data model (the real table-to-table model under the
  table-occurrence graph), AI usage (which FileMaker native-AI capabilities it uses), and the
  workflow deltas between two artifacts. Rows carry stable object IDs where useful, so the assistant
  can hand a result straight to the evidence tools.

These compressed perspectives are the agent surface — the human surfaces (the Artifacts catalog,
Explorer, and Diff) show the artifact's own structure for you to read and verify directly. This
makes the assistant a genuine collaborator on schema questions: "what calls this script", "what
would break if I remove this field", "find every place we compute a discount".

## Building changes over MCP

On a co-located server, the MCP surface also lets a capable assistant **author and apply schema
changes** — composing a patch grounded in the real schema, checking it, and applying it through
the safe apply loop. That path has its own documentation:

- [Patch authoring](/docs/patch-authoring)
- [The AI build loop](/docs/ai-build-loop)
- [Applying patches](/docs/applying-patches)

## Full FMS API control

CORPUSfm can also give an assistant broad FileMaker Server control over MCP — listing databases and
their status, opening/closing/pausing/resuming/flushing a hosted database, listing clients and
messaging or disconnecting them, and listing schedules. These drive the FMS **Admin API** through
the stored [Admin API PKI key](/docs/settings#admin-api-key-pki) — **no admin password is held**.

This is the sharpest surface on the bus, so it sits behind three rails:

1. **A server-wide switch, off by default.** An admin must turn on *"Expose broad FileMaker Server
   controls over MCP"* at **Settings → MCP**. While it's off, these tools are **hidden from every
   assistant's tool list and refused if called** — so an agent never even sees FMS administration as
   part of its normal build loop.
2. **The per-user Full FMS API gate.** Even with the switch on, a token only carries the gates its
   owner holds, and an assistant only *sees* the tools its gates allow.
3. **Two-step plan → execute for anything that changes state.** Closing a database, disconnecting a
   client, or messaging clients is never a single call: the assistant first runs a `plan_…` tool
   that touches nothing and reports the blast radius (the database's current status, who the client
   is, or "broadcast to ALL N clients"), a human reviews it, then an `execute_…` call applies it.
   Read-only listing tools are direct.

Two hard boundaries are always on: CORPUSfm's own storage database can never be opened/closed/paused
by these tools, and **server-process restarts are not exposed** (the Admin API has no restart
endpoint; that stays an installer/console action).
