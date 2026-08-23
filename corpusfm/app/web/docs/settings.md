---
title: Settings & configuration
slug: settings
order: 110
status: published
public: false
---

# Settings & configuration

Everything CORPUSfm needs to run is configured in **Settings**, an operator console organised into
seven sections — **CORPUSfm** (version, restart, updates, this installation's external address),
**Health** (read-only capability status), **Access** (users + gates), **FileMaker** (server
connection, Admin API/PKI, apply compartment), **MCP** (the MCP service and its token, plus every
MCP-scoped switch), **Storage** (archive, blob encryption, semantic index, storage backend), and
**Integrations** (AI, Git export, notifications, the FM add-on). Access and FileMaker appear only on
a co-located server install.

The **CORPUSfm** tab holds the installation's own properties, and it is where a setting goes when no
other tab clearly owns it — every other tab names something CORPUSfm talks to, or a concern that cuts
across all of them. This article covers what each control does. Install, upgrade, and
troubleshooting — the things you need when the app *isn't* reachable — live in the project README
instead; everything here is for tuning a running install.

Settings persist to the storage backend (the FileMaker database) when one is active, so they
follow the install rather than any one browser. A few presentation choices are remembered
**per device** in the browser instead — those are called out below.

## App preferences

App-shell preferences are **personal** (per user) and live on the **Your account** page (System
menu), not here — each person sets their own:

- **Landing page** — where `/` sends you. Any page you can reach, including About or Documentation.
  If you ever lose access to your chosen page, `/` falls back to Documentation rather than a dead end.
- **Documentation drawer side** — the default side the docs drawer opens from (right or left).
  A per-device flip in the drawer header still overrides this on the current browser.
- **Add-on locale** — the language used to resolve add-on object names when you import a `.fmaddon`
  (you can also pick a locale per import).

### Appearance

Under **Your account → Appearance**, choose calculation and script colors independently from four
curated families: Classic, Graphite, Color-safe, and High contrast. The specimens update immediately
in the current light or dark theme, so you can judge both languages before saving. These are
presentation choices only—the syntax rules do not change, and arbitrary colors or rule editing are
not offered.

A newly generated Explorer or Diff copies the exact selected calculation and script values into its
self-contained HTML, along with the palette names and version. It does not consult your account again
and has no palette control of its own. Existing generated files therefore retain the appearance they
were created with; regenerate one when you want it to use a newer preference.

## Archive directory

On the local dev/test path, this is where artifacts are stored on disk. On a co-located server
install the storage backend is the FileMaker database instead, and this control gives way to a
note saying so — there's no local directory to choose.

## Blob encryption

Stored binary blobs (the artifact data, source XML, name maps, and deliverables) are always
compressed; **blob encryption** additionally wraps them with a key held by the install. It is
**off by default** so a restored database is readable directly through the admin account with no
install key.

Turning it on (or off) re-encodes **every** stored blob, so it runs as a single locked,
decoupled job behind a progress page — that's why the toggle commits through a confirm dialog
rather than saving silently.

### File-level Encryption At Rest (EAR)

Blob encryption above is CORPUSfm's own layer. Separately, FileMaker offers **Encryption At Rest
(EAR)**, which encrypts the whole hosted `.fmp12` file. CORPUSfm supports an administrator enabling
EAR **after installation**, but CORPUSfm does not apply, require, detect, or manage it. Once
FileMaker Server has opened the encrypted file, CORPUSfm reads and writes it through OData exactly
as it would an unencrypted file.

Use this post-installation recipe:

1. Finish installing CORPUSfm and verify that storage works.
2. Open `CORPUSfm_DB` offline as `CORPUSfm-Admin` and complete FileMaker's required first password
   change. FMDeveloperTool cannot use an account that is still waiting for that change.
3. Make a verified backup, stop CORPUSfm writes, and close `CORPUSfm_DB` in FileMaker Server.
4. Enable EAR on the closed file with FileMaker Pro's Developer Utilities or
   `FMDeveloperTool --enableEncryption`. CORPUSfm stores its containers inside the database; there
   is no CORPUSfm external-container data to transfer.
5. Put the encrypted file back at the same CORPUSfm database location and filename, then open it in
   FileMaker Server with its EAR password. Choose **Save Password** if the file should reopen
   automatically after a Database Server restart.
6. Confirm CORPUSfm storage is healthy, open an artifact, and perform an upload-and-download check.

If you choose to enable EAR on the storage database, two things stay **your** responsibility, and
CORPUSfm cannot manage them for you:

- **FileMaker Server needs the encryption password to open the file.** Save it in the FileMaker
  Server Admin Console so the database re-opens automatically after a restart; otherwise an
  unattended reboot leaves the storage database closed and CORPUSfm offline until it is opened.
- **Keep the password with your backups.** A backup or a move to another box carries the
  encrypted file, so the destination FileMaker Server will need that same password to open it.
  CORPUSfm does not store, transmit, recover, or reset the EAR password. If it is lost, the
  encrypted database cannot be recovered.

FileMaker Server's default secure-database policy also refuses a file whose Full Access account has
a blank password. For an encrypted file, that refusal can look like an incorrect EAR password even
when the EAR password is right; check both conditions.

## Users & access

CORPUSfm has named user accounts, each with its own login and password. Five access **gates**
govern what a user can reach — **Automation**, **Library + MCP**, **Patching**, **Full FMS API**,
and **Settings** (= full admin) — applied identically to the web UI and to that user's MCP token.
Documentation and your own account page are always available, so a user with no gates still has a
place to land.

- **Change your own password** on the **Your account** page (System menu).
- **Admins** (anyone with the Settings gate) manage everyone in **Settings → Access**: create
  users, set their gates, reset passwords, activate/deactivate. (Each user manages their own MCP
  tokens at Library → MCP — there is no admin token management.)
  Guardrails: you can't remove your own admin access or delete the last admin.
- **The first admin** is created by the installer during setup — a browser never creates it. An
  install that finds no admin and can't make one stops rather than finishing, so you never end up
  with a running box nobody can sign in to. A silent install therefore needs `--admin-user` /
  `--admin-pass` (Windows: `-AdminUser` / `-AdminPass`), or the matching `CORPUSFM_ADMIN_USER` /
  `CORPUSFM_ADMIN_PASS` environment variables.
- **Locked out of the web UI?** Recover from the box itself with
  `corpusfm users set-password <name>` (or `users create <name> --admin`) as the service user. This
  needs the storage database **reachable** — it writes to the same table the web UI reads, so it is
  not a remedy for a storage outage. When storage is down, the sign-in page says exactly that
  instead of claiming no users are configured; fix the connection and your accounts return
  untouched. If you need into the FileMaker file itself while CORPUSfm is unreachable, that is the
  file's own local `[Full Access]` account, outside the app.

User accounts, their gates, and their personal MCP tokens live **in the storage database** (encrypted),
so they **travel with your corpus**: if you move CORPUSfm to a new box, everyone keeps their
existing logins and tokens — nothing to re-create. Only passwords never leave as plaintext (just
one-way hashes are stored). Passwords protect access; they are not the blob-encryption key.

## Updates

Shows the current build and whether the install is behind the tracked branch. When it is,
**Apply update & restart** pulls the new code and restarts the service. This needs a source
checkout with repository access; a packaged build without it simply reports the available
version.

An **"Update available"** notice also appears in the sidebar footer for **everyone** — a passive
heads-up (checked every couple of hours) that a newer build is ready. It's shown to all users on
purpose, so anyone who notices can tell an admin; applying it still happens here, in Settings →
Updates.

The **same** update authority is also reachable over MCP through four stable tools —
`server_capabilities` (which build am I talking to, and how to reconnect the client),
`update_check` (the exact pending update), `update_apply` (authorize one exact code-only update),
and `update_status` (confirm which update landed after the restart). They drive the identical
fast-forward-only, installer-aware, import-probed sequence as this page — the `settings`-gated
tools require the exact head from `update_check`, refuse anything needing the installer, and the
self-update drops the MCP connection (reconnect, then `update_status`). There is no automatic or
scheduled update; applying is always an explicit action.

If the result is not the update path you expected, use
[An update does not appear or cannot be applied](/docs/update-not-appearing-or-applying) to distinguish
a refresh, a code-only update, an installer handoff, and a state that should be reviewed before change.

## Notifications

Where run outcomes are announced — so a failed overnight job reaches you without opening the
app. Configure the channel and which events fire.

## AI summaries & embeddings

Two **optional**, independent providers power artifact enrichment — you can configure one, both,
or neither. **Indexing is the search substrate; summaries are optional descriptions** — the two are
independent, and semantic search never requires summaries. In Settings, embeddings are listed first:

- **Embeddings** — the vectors behind [semantic search](semantic-search.md). Enables search and MCP
  retrieval from each object's rendered text; no summaries required.
- **Summaries** — a chat model that writes the one-line descriptions shown across the catalog. Does
  not enable search on its own; when an embedder is also configured, summaries add an extra searchable
  layer on top of the raw index.

Both accept keyless local presets (Ollama, LM Studio) as well as hosted keys, and each has a
**Test** button that proves the chosen model actually responds. See
[Semantic search & the index](semantic-search.md) for how the embedding index is used and when
to reset it. Interactive AI work is the assistant over [MCP](mcp.md), not these providers.

A hosted **API key** is stored **encrypted in the storage database** (never in plain team settings,
never shown back to the browser — the Settings page reports only whether a key is **set**). Because it
lives with the corpus, it **travels** with the database — no need to re-enter it on a new box. Enter a new key to replace it, or use the clear control to remove it.

**Enrichment is separate from import.** Importing an artifact is fast — it does not run AI. To
enrich, go to the **Catalog**, select one or more artifacts, and choose **Index**/**Reindex**
(embeddings — the search substrate) or the optional **Summaries** (chat model); each runs as a
background job you can **Stop** at any time (partial work is kept). The two actions are independent —
each appears only when its provider is configured — and search works from indexing alone. Removing
something from the index (**De-index**) is a per-artifact action on the artifact's detail pop-over
(next to Reindex); each artifact (each version) is indexed **independently**, so re-indexing or
de-indexing one snapshot never affects another.
**Settings → Storage → Semantic index** keeps only the vector count and the whole-index **Reset**.
Automated **jobs** and **bearer-token push** still enrich on their own as they pull.
Agents can do the same over [MCP](mcp.md): `index_artifact` for search, `summarize_artifact` for the
optional descriptions.

### Choosing a summary (chat) model

Summaries are short, one-line descriptions, generated **one call per object** — so favour a
small, fast, **non-thinking** chat model:

- **Recommended:** a non-thinking instruct model — e.g. **`llama3.1:8b`** locally, or a small
  hosted model (`gpt-4o-mini`-class, `claude-haiku`). These answer in a few tokens and never
  stall.
- **Avoid for summaries:** *thinking / reasoning* models (e.g. **`qwen3`**, **`deepseek-r1`**,
  OpenAI o-series). They spend a large, **variable** amount of their token budget on hidden
  reasoning before the one line — which makes thousands of summaries slow and can leave an
  object **un-summarized** when the reasoning overruns the budget. The **Test chat model**
  button will tell you when this happens (*"reached the token limit before answering"*). Reach
  for a reasoning model for interactive analysis over [MCP](mcp.md) instead, not for this
  batch one-liner job. (CORPUSfm strips a model's `<think>…</think>` output automatically, so a
  thinking model that *does* finish stays clean — it's just the wrong tool for the volume.)

### Choosing an embedding model

The embedder is unrelated to the chat model — it only turns each object's rendered text into a
vector, so *reasoning never enters into it*; pick by **dimension and quality**, not speed of thought.

- **Recommended:** a small local embedder — **`nomic-embed-text`** (keyless via Ollama) covers
  schema search well; reach for **`mxbai-embed-large`** or a hosted embedder
  (`text-embedding-3-small`, Jina) only if you want a little more retrieval quality.
- **CPU-only works — but a large index saturates CPU, so let it yield on a shared box.** A GPU is
  optional: the embedder is small enough to run **CPU-only**, and running it local keeps the schema on the
  box with no key and no outbound network. For small files the load is brief, but indexing a **large**
  schema is thousands of forward passes back-to-back — the embedder will **peg the CPU for the whole
  duration** of that index (this is expected, not a fault). On a **co-located** box the embedder shares CPU
  with FileMaker Server, so **lower Ollama's CPU priority** — it then runs full speed when the box is idle
  and backs off under contention (better than a hard cap for on-demand indexing). On Linux,
  `corpusfm setup-embeddings --install-ollama` offers this, or `--low-priority` applies it non-interactively
  (a `CPUWeight=20` systemd drop-in). Windows and macOS are manual — see the full
  [local embedder setup guide](/docs/ollama).
- **Changing embedder means reindexing.** A different model (or dimension) produces incompatible
  vectors, so switching requires a **Reset** and a fresh index — see
  [Semantic search & the index](semantic-search.md). Pick one and stay on it.
- **One-command local setup.** On the server, an admin can run `corpusfm setup-embeddings` to stand
  up a local Ollama embedder (with consent), pull `nomic-embed-text`, point CORPUSfm at the loopback
  endpoint, and verify it — all in one step, no outbound network. It never installs anything without
  consent and never manages Ollama's updates (that stays yours). Re-runnable and safe to repeat. Add
  **`--low-priority`** to also lower Ollama's CPU priority on a co-located Linux box (see the CPU note
  above), and **`--uninstall`** to undo it all (clears config + priority drop-in, and removes Ollama if
  CORPUSfm installed it). Full per-OS detail — install, tuning, uninstall — is in the
  [local embedder setup guide](/docs/ollama). **On Windows, run it from an interactive session** — the
  Ollama installer can't complete headless over SSH (detect/pull/wire/test still work once Ollama is up).

### Embedding batch size

Indexing sends each object's rendered text to the embedder to be turned into a vector. The **Embedding
batch size** (on the Semantic-search pop-over) is how many objects go in **one** `/embeddings` request —
a throughput dial, not a quality one. It changes only how the work is chunked; it never changes a vector,
so **changing it needs no reindex** and never clears the endpoint's **Verified** state.

- **Auto (recommended)** is right for most setups: **16** for a local endpoint (a loopback/`*.local`
  address), **128** for a remote one. Those two defaults pull in opposite directions on purpose — here's
  why, and when to override them.
- **Local endpoints — leave it small.** A local CPU embedder processes a batch **one object at a time**,
  and a big batch becomes a single long request that can hit the per-request time limit and park a large
  file's index as failed. Because the endpoint is on the box, the extra round-trips of a small batch cost
  almost nothing — so 16 is both safe and free. A **GPU-backed** local embedder can go a bit higher
  (**32–64**); above that there's little to gain on one machine.
- **Remote/hosted endpoints — bigger is faster.** Against a hosted endpoint (Azure OpenAI, OpenAI, Jina)
  every request pays real network + TLS, so batching only 16 at a time makes far more round-trips than
  necessary. Raising the batch to **256 or 512** on a large schema cuts the request count — and the wall
  time — substantially. The ceiling is **2048** (the hosted `/embeddings` array cap).
- **Pick a value, then Save.** The selector just stages the value like the other fields; the **Save**
  button on the pop-over persists it. If an endpoint ever returns fewer vectors than you sent (some
  endpoints silently drop inputs on an oversized batch), indexing stops with a clear *"try a smaller
  batch"* message rather than writing a corrupt index — lower the batch and reindex.

### Azure OpenAI

Both the chat model and the embedder can run against **Azure OpenAI** — useful when your
organization's only sanctioned AI is an Azure resource. Pick **Azure OpenAI** in the provider
selector (it's offered on both the Summaries and Semantic-search pop-overs), then enter:

- **Azure resource URL** — the resource root, `https://<resource>.openai.azure.com` (no path).
- **API version** — e.g. `2024-10-21` (a value your resource serves; leave blank to use the
  built-in default).
- **Deployment** — the *deployment name* (Azure routes the model in the URL, so this is the
  deployment, not a model id like `gpt-4o-mini`). The chat and embedding endpoints each take
  their own deployment.
- **API key** — the resource key (sent as the Azure `api-key` header).

The chat and embedding endpoints are **fully independent** — each has its own provider, resource
URL, deployment, and key, even when they point at the same Azure resource. They can be two
different resources entirely (a chat deployment on one, an embedder on another). Use **Test chat
model** / **Test embedding endpoint** to confirm each live before it's trusted. Azure doesn't list
deployments the way a local endpoint lists models, so the **List models** helper is hidden for
Azure — type the deployment name from the Azure portal. Switching the embedder to (or from) Azure
changes the vector space, so **reindex** afterwards (see [Semantic search](semantic-search.md)).

## FileMaker Server

CORPUSfm runs co-located on the FileMaker Server box, so there is **one** server. This card shows
its status and lets you edit the connection. Jobs read schema from this server; it is also the
host of the storage backend.

**TLS / certificates.** Public TLS can terminate at an edge proxy or firewall with a real
certificate while FileMaker Server keeps its own internal or self-signed certificate for CORPUSfm's
local calls. That is fully supported: CORPUSfm builds the links it shows you (and the MCP URL) from
the public address the proxy forwards, and it checks the FileMaker connection for **reachability,
sign-in, and OData access — not for who owns the public certificate**. So a self-signed internal
certificate is normal and is **not** flagged as a problem on the Health tab; a server that is
genuinely unreachable, a rejected sign-in, or OData turned off **are** flagged. CORPUSfm does not
manage your public certificate and never changes FileMaker Server's TLS settings.

## Remote servers

Beyond the co-located server, you can register **additional FileMaker servers** that Jobs pull from
over the network — for teams whose files live on more than one box. This is **analysis only**
(Explorer / Diff / cross-reference / git export); the patching and file-generation tools are never
used against a remote server.

A remote pull works by *push*, so the net flow is inbound: CORPUSfm triggers the addon's
`PostToServer` script on the remote server over OData, and that server posts its schema **back** to
CORPUSfm's `/api/upload`. Each push carries a **one-time token** minted for that run, so a captured
token is useless afterward.

Registering a server needs its **host** and its **fmsadmin account** (username + password) — the
Admin-API credential CORPUSfm uses to list that server's hosted files. **Save verifies the credential
first:** if the account can't reach the server's Admin API and enumerate its files, nothing is stored,
so every registered server shows as **verified**. File access for each pull is the per-**job** OData
credential, set on the job — not here.

A **Verify TLS certificate** toggle is offered per server, **off by default** because FileMaker Server
certificates are commonly self-signed or hostname-scoped. Turn it **on** when the server presents a
certificate CORPUSfm can validate — CORPUSfm then verifies TLS on every Admin-API and push call to that
server.

- **The one-time token is the authorization.** Each push is authenticated by the per-run token minted
  for it — there is no separate allowlist, enable/disable switch, or source-IP pin to maintain. A
  captured token is useless once its run has landed.
- **Adding a server verifies it.** Saving reaches the server's Admin API and lists its files before
  storing anything (an unreachable server is rejected), so a registered server is confirmed reachable at
  the moment you add it — there is no separate Test step.
- **The addon's `PostToServer` script must be enabled** in each file you want to pull (it ships
  disabled — enable it by disabling its guard *Exit Script* step, as in the FM Addon section).

> **Deployment note.** The remote FileMaker Server POSTs its schema back to CORPUSfm's **External
> CORPUSfm address** (below), so that address must be reachable from the remote box and must be
> **`https://`** (a remote push carries a live one-time token, which never crosses the network in
> cleartext — an `http://` callback is rejected unless it is `localhost`). Override it per job (the
> PostToServer method field) when a specific job needs unusual routing. Whether CORPUSfm verifies the
> remote server's own TLS certificate is the per-server **Verify TLS** toggle above (off by default).

The credentials for a remote server live encrypted in CORPUSfm's own database and never travel to
the browser. Manage remote servers under **Settings → FileMaker**; pick one per job on the
[Jobs](/docs/jobs) page's **Server** field.

## MCP address

*Settings → **MCP** tab.*

The **MCP address** is the `https://` base another machine uses to reach this CORPUSfm, **including its
web prefix** — e.g. `https://this-host/corpusfm` or `https://192.168.1.50/corpusfm`. It is the
**audience every OAuth connection is bound to**: a client checks that the address CORPUSfm advertises is
the one it connected on, and refuses the sign-in if they differ. It is also the base of externally
generated links (e.g. MCP container-download URLs), and the fallback callback for a remote FileMaker
push job whose **server record** carries none of its own.

It only has to be **reachable from another host**, so an **internal/LAN IP is valid** — it does not need
to be internet-public, and a hostname is not required. It must be `https://`; CORPUSfm checks only the
URL *shape*, so a **self-signed or expired certificate is not rejected** here — whether a given client
trusts that certificate is client-specific. A **loopback** address (`127.0.0.1` / `localhost`) is
rejected, because another machine can't reach your loopback; local co-located pushes keep using the local
path automatically.

**You do not have to set one.** At startup a box with no address configured **asserts one itself**, from
the addresses its own network interfaces answer on — the first one, deterministically, with loopback and
link-local excluded. That is *locally detected*, not verified: the box cannot know a client can reach it.
If the guess is wrong, this field is how you correct it, and Settings also **proposes the address of the
page you're viewing** — the **Use detected** button fills the field *and* saves in one action.

**Changing it disconnects every client, and takes effect only at a restart.** The address is bound into
the OAuth issuer when the process starts, so the running CORPUSfm keeps advertising the old one until it
restarts — and once the new one is live, every existing grant stops matching and everyone signs in again.
Settings says all of this before you confirm, then asks one question: **Restart CORPUSfm now?**

- **Yes** — the supported service restart is scheduled and the new address is live in a few seconds.
- **No** — the value is saved and applies at the next restart, whenever that is. Settings marks the
  field **Pending restart** and keeps showing what the box is *actually* serving, so the page never
  displays one identity while discovery and the consent screen serve another.

**Clearing** the address leaves nothing for a client to discover: OAuth sign-in has nowhere to serve
until one is set again. Named bearer tokens keep working throughout.

*Upgrade note:* the earlier `CORPUSFM_PUSH_CALLBACK_URL` and `CORPUSFM_PUBLIC_BASE_URL` environment
variables are both retired and neither is read. An existing persisted callback in `install.yaml` is
migrated automatically on upgrade. A per-server **Callback URL** (Settings → FileMaker → Remote servers)
still overrides this address for that peer's push jobs.

## Storage backend

Reports the installation-managed FileMaker database that holds CORPUSfm's own data. The application
does not select or activate another installed backend. This database is special — it is never a
target of schema-changing tooling, only read and written as CORPUSfm's own store.

### If CORPUSfm can't reach its storage database

This page needs storage to load, so if the connection is what broke you are reading this after the
fact — which is the point of writing it down now. Recovery happens **on the FileMaker Server box**,
not here:

First open the storage file in FileMaker Pro with `[Full Access]` and set
`CORPUSfm-Automation`'s password to its own account name. Then run the installed repair:

```bash
sudo /opt/CORPUSfm/bin/corpusfm-installer --repair-storage-access
```

```powershell
powershell -ExecutionPolicy Bypass -File `
  'C:\Program Files\CORPUSfm\bin\corpusfm-installer.ps1' `
  -RepairStorageAccess
```

The installer rotates that known recovery value to a fresh random credential, proves it, and commits
it to the installation-owned authority. A web-service restart does not attempt this repair. **The
full procedure is in the README**, where it remains readable when this page is not.

### The storage file's own FileMaker accounts — change one of them

`CORPUSfm_DB.fmp12` ships with three FileMaker accounts, and one of them has a **published default
password you should change**:

- **`CORPUSfm-Automation`** — the only account CORPUSfm itself uses. Its password is randomized
  during installation, so you never type it and never need it.
  It has OData access only, and FileMaker itself prevents it from writing the derived index fields.
- **`CORPUSfm-Admin`** — a `[Full Access]` account for opening the file directly in FileMaker Pro. It
  ships with the password **`changemenow`**, the same on every install. **CORPUSfm never signs in with
  this account**, so changing its password breaks nothing here. Change it in FileMaker Pro under
  File → Manage → Security.
- **`[Guest]`** — disabled.

**Why the account exists rather than being removed:** it is the only way into the file if the
automation credential is ever lost or corrupted. Recovery has a FileMaker half — open the file as
`CORPUSfm-Admin` and reset `CORPUSfm-Automation`'s password back to `CORPUSfm-Automation` — and a
CORPUSfm half that re-asserts the credential from the server box. Remove the `[Full Access]` account
and the first half becomes impossible.

**This is also written in the README**, deliberately. If the storage connection is what broke, you
cannot reach this page to read it.

## Admin API key (PKI)

A public-key credential for the FileMaker Server **Admin API**, generated and held by CORPUSfm. It
lets unattended automation (scheduled jobs, opening/closing databases, and the Full FMS API tools)
authenticate **without** an admin password — and it survives an admin-password change, so it's the
durable choice for automation.

**An installed CORPUSfm has exactly one, and the installer establishes it.** The identity is created
and registered on FileMaker Server during installation, its private half is stored encrypted in the
installation's own secrets directory, and its name and public fingerprint are recorded in the
installation's manifest. Everything that talks to the Admin API — the Jobs file list, Health and
readiness, patch apply, and the Full FMS API tools — uses that one identity, and uses it only when
the stored key and the manifest agree. Uninstall removes it.

So the per-server **Generate / Test / Forget** controls in this pop-over **do not act on an installed
box** — they manage an older per-connection key store that an installation does not use, and creating
a second key there would replace the registration the installation depends on. The pop-over says so
instead of offering the buttons. To re-establish or repair the identity on a server, use
`corpusfm-lifecycle admin-identity` there.

**Where to look when it is not working:** Settings → **Health** and the readiness report name the
state directly — no identity published, present but unreadable by the service, unusable, or a stored
key that disagrees with what this installation published. Those are four different repairs, so the
message names which one you have.

## MCP service

*Settings → **MCP** tab.*

The **MCP service** section shows whether the endpoint is mounted and reachable. It is **fail-closed**:
on a server it always mounts and always authenticates, so a request carrying no credential is refused.
There is **no service token and no master key** — every credential belongs to a named person, which
means every action over MCP has an owner and is revoked by deleting that person's token or
deactivating their account. Each person mints their own **personal token** at
[Library → MCP](mcp.md); it authenticates as that user, carries their gates, and is revocable per user.
The first one on a new box is minted on the server with `corpusfm users mint-mcp-token <username>`.

The section also states where clients connect and what they get when they do: anyone with a CORPUSfm
account can connect an MCP client at that address, and their access follows their current gates. See
[OAuth sign-in](#oauth-sign-in) for how that sign-in works and how a connection is ended.

## MCP capabilities

*Settings → **MCP** tab.*

Two server-wide switches decide which families of tools MCP exposes at all. Both are **off by
default**, and while one is off its tools are hidden from every assistant's tool list and refused if
called — a kill switch that sits above every user's gates rather than beside them.

Turning one on does not grant it. The per-user gate named on the row is still required, every mutating
operation is a reviewed two-step *plan → execute*, and CORPUSfm's own storage database is never a
target. Neither switch needs a restart.

- **FMS controls** — see [FMS admin tools over MCP](#fms-admin-tools-over-mcp).
- **Patch / apply** — see [Patch / apply tools over MCP](#patch--apply-tools-over-mcp).

## FMS admin tools over MCP

*Settings → **MCP** tab.*

The **MCP capabilities** section has an **FMS controls** switch that governs
whether an AI assistant can reach the [Full FMS API tools](mcp.md#full-fms-api-control) (list
databases / clients / schedules, control a hosted database, and disconnect or message clients). It
is **off by default**.

While it's off, those tools are **hidden from every assistant's tool list and refused if called** —
a server-wide kill switch, independent of any user's gates. Turn it on only when you want an
assistant holding the **Full FMS API** gate to drive FMS administration. Even then the rails stay:
every state-changing operation is a reviewed two-step *plan → execute*, the tool list a token sees
is still filtered to its gates, and CORPUSfm's own storage database is always off-limits. The
setting takes effect immediately — no restart.

## Patch / apply tools over MCP

*Settings → **MCP** tab.*

The **MCP capabilities** section has a **Patch / apply** switch beside the one above. It governs
whether an AI assistant can reach the **apply / materialize** tools: applying a
generated patch to a hosted file, dry-running an apply against a copy, materializing a database file,
and promoting a generated database into the hosting folder. Like the FMS switch it is **off by
default**, so a freshly installed box exposes MCP as **analysis-only** — enabling it to apply or
materialize against your production FileMaker files is a conscious, per-box opt-in.

While it's off, those tools are **hidden from every assistant's tool list and refused if called**.
Patch *authoring* and read-only checks are unaffected — an assistant can still generate a patch,
statically check it, look up capabilities, and save a patch/clip/script/calc to the catalog; only the
verbs that touch a real FileMaker file disappear. When you turn it on the rails stay: the per-user
**Patching** gate is still required, every apply/materialize op is a reviewed two-step *plan →
execute*, and CORPUSfm's own storage database is never a target. The setting takes effect immediately
— no restart.

## OAuth sign-in

*Settings → **MCP** tab.*

A standards-compatible MCP client connects by **OAuth sign-in**: you add the server's MCP address to the
client, the client opens a browser, you **sign in as an existing CORPUSfm user** the same way you sign in
to the app, and you **approve** the connection on a consent page that lists the tools your account is
allowed to use. No password is ever typed into the MCP client or stored in its configuration — you only
ever enter it on CORPUSfm's own sign-in page.

The connection then acts as **you**, with **your current gates** — exactly like a named token. If an
administrator changes your permissions, the client's access changes with them on the next request.
Signing in alone never grants every tool.

**There is no switch.** OAuth sign-in is available whenever this box has a usable MCP address, because
that address is the audience every grant is bound to — a client that reached the server has, by
definition, an address to bind to. The MCP tab's **MCP service** section reports the address clients
connect at, or says the box is serving none; it reads the address the process is actually serving, not a
stored setting, so it cannot disagree with what the server advertises. Named per-user tokens are a
separate rail and are unaffected either way.

**Ending a connection.** Each person manages **their own** on the [MCP page](/docs/mcp#connecting): every
client they approved is listed there and **Disconnect** revokes exactly that one connection (their grant
only — no other user, no other client, no manual token), after which that client must sign in and approve
again. Deactivating an account ends every connection it owns, at once. There is no admin-wide switch that
ends everybody's connections in one action, and no admin-wide connection dashboard, device list or
last-used telemetry; organization-wide single sign-on is a later release.

## OAuth connection lifetime

*Settings → **MCP** tab.*

How long an **OAuth connection** keeps working before the person has to sign in again. Two limits apply
to every connection:

- an **inactivity** limit — measured from the connection's last successful sign-in or silent renewal, and
  moved out by each further successful renewal;
- an **absolute maximum**, measured from when the connection was approved and **never** extended.

Pick one of three policies:

| Policy | Inactivity | Maximum |
|---|---|---|
| **Standard** (default) | 30 days | 1 year |
| **Reduced** | 7 days | 90 days |
| **Strict** | 1 day | 30 days |

These are the complete choices — there is no free-form duration, no "never expires", and no per-person
exception. A fresh installation, and one saved before this setting existed, reads as **Standard**.

**This is not a sign-in or session duration.** The access credential rotates silently in the
background; nobody is asked to sign in while their connection is inside both limits. The limits decide
when the *connection* ends, not how often someone types a password. The inactivity clock follows those
renewals, because credential issuance is what CORPUSfm records — there is no per-request usage history
behind this setting, and none is displayed anywhere.

Choosing a **tighter** policy shortens existing connections immediately — a connection granted under
Standard is held to the new limits from the moment you save. Choosing a **looser** one applies only to
connections approved from then on: a connection granted under Strict is never silently promoted to a
one-year connection. The setting is read as each connection is used, so it takes effect **without a
restart**, and it is recorded in the audit log.

A connection can also end earlier — see [Disconnect](/docs/mcp#how-long-a-connection-lasts) — when the
person disconnects it, when the account is deactivated or deleted, when the MCP address changes (every
grant is bound to it), or when CORPUSfm detects a reused credential.

## Generated database hosting folder

When CORPUSfm **materializes a new database file** from a schema (the *generate database* tool), the
file has to live somewhere FileMaker Server can host it. CORPUSfm uses a **formal, named hosting
folder** — a folder registered with FMS as an **Additional Database Folder** — so a generated file is
**hosted in place**, with no copy into the server's own `Databases` directory.

**The installer does all of this. There is no checklist for you to follow.** During installation it
creates the folder, sets its permissions, registers it with FileMaker Server in one of the two
additional-folder slots, reads the registration back, and then **proves** the folder works by placing a
small sandbox file in it and having FMS open and close it. Only a folder that survives every one of
those steps is recorded as verified, and only a verified folder may host anything.

To point CORPUSfm at a different location — a specific data drive, say — pass
**`--patch-hosting-dir`** (Linux) or **`-PatchHostingDir`** (Windows) at install time. Without it the
installer picks its own default and prints the path it used.

### When it cannot finish, it stops — it does not improvise

The folder is a boundary, so the installer would rather refuse than half-configure it. What that looks
like:

- **A path it will not accept.** A path inside — or containing — FileMaker Server's own directories,
  the CORPUSfm storage directory, a symbolic link, a relative path, a filesystem root, or a path that
  climbs back into a protected directory. These are refused **before anything is created**.
- **No free slot.** FileMaker Server offers **two** additional-folder slots. CORPUSfm takes one, and
  reuses the existing registration if your folder is already registered. **If both slots are already
  in use by other paths, the installer refuses and changes neither of them.** It does not evict
  anybody, and there is no fallback that copies generated files into the server's own `Databases`
  directory — that route no longer exists on any platform.
- **Registered but unproven.** If the folder registers but the open/close proof does not succeed — the
  sandbox never reaches *open*, or the service account is denied access — the folder is left
  **unverified**, and CORPUSfm treats unverified exactly as it treats absent: generation and apply
  refuse. A folder that looks configured but has never been shown to work is not something to build on.
- **Something failed partway.** If the failure happened before anything changed, the installer says so
  and nothing needs undoing. If a directory had already been created, it rolls back **what this run
  created** — never a folder that was already there — and restores the slot to the value it captured
  before touching it. If a rollback cannot restore the slot, it reports that **manual action is
  required** and names it, and it deliberately leaves the directory in place rather than deleting
  something it can no longer account for.

Each of these is reported with the state, the reason, and the next action to take.

**On uninstall,** the hosting folder is **never deleted while it contains databases** — those are your
work product; the uninstaller leaves them and tells you where they are.

## Apply compartment

*Settings → **FileMaker** tab. It constrains which FileMaker files an apply may target, so it stays
with FileMaker even though the patch/apply **MCP switch** moved to the MCP tab.*

CORPUSfm keeps its own FileMaker files in **named, visible folders** so that *what CORPUSfm may touch*
is a physical fact, not a matter of trust. There are two homes:

| Folder | Holds |
|---|---|
| `Data/Databases/CORPUSfm/` | the **storage database** — CORPUSfm's own data. Never a patch/apply target. |
| the **patch compartment** (e.g. `/opt/CORPUSfm-Hosted`) | everything CORPUSfm may host or patch: **generated** databases hosted in place, and the one **sandbox** file used for dry-runs. |

The patch compartment is a formal FMS **Additional Database Folder**, and it is **proven, not
configured**. The installer provisions it and then verifies it end to end; only a compartment that
passed that proof authorizes anything. A folder that was merely registered — or merely written into a
settings file — is not a compartment.

**The compartment is the prerequisite; the switch below is only a narrowing.** With no verified
compartment, patching and applying are refused on this installation whatever the switch says. Inert
**materialization** still works (a generated file lands in a private quarantine and the result says so),
because a file FileMaker Server neither knows nor serves changes nothing.

The **Apply compartment** switch (Settings → FileMaker) governs what a patch/apply/dry-run is allowed to
target **within that already-authorized world**. It is **on by default**:

- **On (Restricted, default).** A patch, apply, or dry-run may target only a file **hosted from the
  verified compartment**. A file hosted from FileMaker's default database directories (the top level of
  `Databases`, or any other subfolder) is **refused before the database is ever closed**, and a target
  CORPUSfm cannot positively locate inside a patch zone **fails closed**. This is what keeps a typo'd or
  stale database name from ever landing a patch on a live customer file.
- **Off (Unrestricted).** For a **dedicated patch box** — a server stood up specifically to patch files —
  turn it off to widen the eligible set to any hosted database **except** the storage database. This is
  the maximum-capability mode; use it only where that is the machine's whole purpose.

The **storage database is refused in every state**, independent of this switch and of the *Patch / apply
over MCP* switch above it. Those two switches reinforce each other and cover different surfaces:

| Patch / apply over MCP | Apply compartment | What can be patched |
|---|---|---|
| Off (default) | — | nothing over MCP — the apply/materialize tools are hidden and refused |
| On | On (default) | only files hosted from the verified compartment |
| On | Off | any hosted database **except** the storage database — and still only when a verified compartment exists |

To patch a customer file while the compartment restriction is on, either host that file from the
compartment, or turn the restriction off for a dedicated patch box. The switch takes effect immediately —
no restart. (A legacy `windows_apply_allowlist` in `install.yaml`, from before this folder-scoped model,
is now ignored — apply targets are scoped by folder, not by name.)

## External sign-in (SSO / LDAP)

CORPUSfm can delegate **web sign-in** to the same identity provider your organization already uses for
FileMaker Server — **OIDC / OAuth** (Google, Microsoft/Entra, Okta, Amazon…) and **AD / LDAP**. Local
username/password is always retained as a per-user option and a mandatory **break-glass** admin. **Your
IdP enforces MFA** — CORPUSfm adds no separate two-factor step.

Configure it at **Settings → Access → External sign-in**. Authentication proves *who* the user is;
authorization stays CORPUSfm's five access gates. A first-time SSO user is **auto-created with zero
access** (they reach only Documentation and their own account) until a group mapping or an admin grants
gates — so turning SSO on exposes nothing.

**OIDC setup checklist:**

1. In your IdP, register a new application (a "web" / "confidential" client). Set its **redirect URI** to
   `https://<your-corpusfm-host>/corpusfm/auth/oidc/callback`. Set the **same** value in the **Redirect
   URI** field in Settings (rather than leaving it blank to be derived from the request host) so a
   spoofed `Host` header can never reshape it — and set the `CORPUSFM_ALLOWED_HOSTS` environment variable
   to your host(s) on the co-located install.
2. Copy the **Issuer URL**, **Client ID**, and **Client secret** into Settings → Access → External
   sign-in, enable OIDC, and **Save**. (The client secret is stored encrypted and never shown again —
   leave it blank on later edits to keep it.)
3. If your IdP puts group memberships under a non-standard claim, set **Groups claim** to match.
4. Add **Group → access mapping** rows so a user's IdP groups grant CORPUSfm gates (e.g. your
   `CORPUSfm-Admins` group → *Settings*). Gates are re-evaluated on every login. No matching group → no
   access.
5. Sign out and confirm the **Sign in with SSO** button appears on the login screen.

**AD / LDAP** (the completeness path — heavier, org-specific) uses the same group mapping: enable it, set
the server URI, base DN, an optional service **bind DN + password**, the user filter, and the group
attribute. LDAP users sign in with their directory username/password on the normal login form. Prefer an
**`ldaps://`** server URI (or a directory that enforces signing/sealing on `ldap://`) — a plain `ldap://`
with simple bind sends the bind and user passwords in cleartext. *(LDAP requires the `ldap3` library on
the server; the toggle is disabled if it isn't installed.)*

**Break-glass:** at least one **local-password admin** must always exist — CORPUSfm refuses to remove,
deactivate, or de-admin the last local administrator, so you can always sign in even if the IdP is
unreachable.
