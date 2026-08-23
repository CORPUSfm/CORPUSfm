---
title: Local embedder (Ollama) — per-OS setup
slug: ollama
order: 72
status: published
public: false
---

# Local embedder (Ollama) — per-OS setup

Semantic search needs an **embedder** — a small model that turns each object's rendered text into a
vector. The simplest, keyless, no-outbound-network choice is a **local Ollama** running the
`nomic-embed-text` model on the CORPUSfm box; CORPUSfm just points at its loopback endpoint
(`http://127.0.0.1:11434/v1`). This page is the per-OS reference for **installing, tuning, and removing**
it.

> **CORPUSfm does not manage Ollama.** It can *install* it for you on Linux (with consent) and point at
> it, but you own it from there — updates, and the tuning below, are yours. Ollama is the vendor's
> software; the commands here run *their* installer or documented steps.

## The quick path (Linux — one command)

On a Linux server, the CLI does the whole thing:

```
corpusfm setup-embeddings --install-ollama      # install Ollama (consent), pull the model, wire + verify
```

It also **asks whether to lower Ollama's CPU priority** so a big index yields to co-located FileMaker
Server (see [CPU](#read-this-first-cpu)). For a scripted, non-interactive run, add `--low-priority` to opt
in without the prompt, and `--yes` to skip consent:

```
corpusfm setup-embeddings --install-ollama --low-priority --yes
```

Re-runnable and safe to repeat. On Windows/macOS the install is manual (below); once Ollama is present,
`corpusfm setup-embeddings` (without `--install-ollama`) still pulls, wires, and verifies. Run it **as the
service user in server mode** so the config lands in the FileMaker database, not a dev file.

## Read this first: CPU

An embedder runs **CPU-only** fine (no GPU needed), but indexing a **large** schema is thousands of
forward passes back-to-back — Ollama will **peg the CPU for the duration** of that index. That's expected,
not a fault. On a **co-located** box it shares the CPU with FileMaker Server, so make it **yield**: lower
Ollama's CPU priority so it runs **full speed when the box is idle** and **backs off under contention**.
Indexing is on-demand, so this is better than a hard cap (which would throttle even when the box is free)
or an off-peak schedule. **CORPUSfm automates this on Linux; Windows and macOS are documented manual steps
below.**

---

## Linux

The vendor installer sets Ollama up as a **systemd service** (`ollama.service`) under an `ollama` user;
models live in `/usr/share/ollama/.ollama/models`.

### Install
```
curl -fsSL https://ollama.com/install.sh | sh     # or: corpusfm setup-embeddings --install-ollama
sudo systemctl status ollama                       # confirm it's running
ollama pull nomic-embed-text                        # the embedding model (setup-embeddings does this too)
```

### Lower its CPU priority (recommended, co-located)
`setup-embeddings --install-ollama` offers this at install time; to apply it yourself, drop a `CPUWeight`
override (cgroup v2 default is 100 → 20 favors FMS under contention, full speed when idle):
```
sudo mkdir -p /etc/systemd/system/ollama.service.d
printf '[Service]\nCPUWeight=20\n' | sudo tee /etc/systemd/system/ollama.service.d/corpusfm-cpu.conf
sudo systemctl daemon-reload && sudo systemctl restart ollama
```
Verify with `systemctl show ollama -p CPUWeight`. To restore, delete that file and reload. For anything
beyond this — keep-alive, parallelism — see Ollama's own docs at <https://docs.ollama.com/faq> (set
`OLLAMA_*` env vars via `sudo systemctl edit ollama.service`).

### Uninstall
`corpusfm setup-embeddings --uninstall` clears CORPUSfm's config, removes the priority drop-in, and — **if
CORPUSfm installed Ollama** — removes Ollama too (it never touches an Ollama you installed yourself). Add
`--keep-ollama` to remove only CORPUSfm's footprint. The equivalent manual steps (Ollama ships no Linux
uninstaller):
```
sudo systemctl stop ollama && sudo systemctl disable ollama
sudo rm -f /etc/systemd/system/ollama.service
sudo rm -rf /etc/systemd/system/ollama.service.d      # the CORPUSfm CPU-priority drop-in
sudo systemctl daemon-reload
sudo rm -f "$(command -v ollama)"                      # the binary (usually /usr/local/bin/ollama)
sudo rm -rf /usr/share/ollama                          # the ollama user's home + downloaded models
sudo userdel ollama; sudo groupdel ollama
```
The vector index is separate (CORPUSfm data) — it stays until you **Reset** it in
**Settings → Storage → Semantic index**.

---

## Windows

Ollama on Windows is a **manual install** (CORPUSfm doesn't automate it here). Models live in
`%USERPROFILE%\.ollama\models`.

### Install
Download **OllamaSetup.exe** from <https://ollama.com/download/windows> and run it — it installs
**per-user, no admin required**, serves on `localhost:11434`, and needs an **interactive session** (it
can't complete headless over SSH). Where `winget` is available you can instead:
```
winget install Ollama.Ollama
ollama pull nomic-embed-text
```
Once Ollama is up, `corpusfm setup-embeddings` (no `--install-ollama`) will pull, wire, and verify.

### Lower its CPU priority (recommended, co-located)
Set a persistent **Below Normal** priority for `ollama.exe` via an Image File Execution Options registry
value (**needs admin** — a higher privilege than the per-user install). In an elevated PowerShell:
```
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ollama.exe\PerfOptions'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name CpuPriorityClass -PropertyType DWord -Value 5 -Force | Out-Null
```
(`5` = Below Normal.) Restart Ollama so it re-launches at the new priority. To undo, delete the
`PerfOptions` key. A non-persistent alternative: Task Manager → *Details* → `ollama.exe` → *Set priority*
→ *Below normal* (resets on restart).

### Uninstall
```
winget uninstall Ollama.Ollama
#   or: Settings → Apps → Installed apps → Ollama → Uninstall
```
Models may linger in `%USERPROFILE%\.ollama` — delete that folder if you want them gone. Then clear the
embedder in **Settings → Integrations → Semantic search**.

---

## macOS (from-source deployments only)

macOS isn't a packaged CORPUSfm target (source only), so this is lighter. Models live in `~/.ollama/models`.

### Install
```
brew install ollama && brew services start ollama      # or download the app from https://ollama.com/download
ollama pull nomic-embed-text
```

### Lower its CPU priority (recommended, co-located)
Run Ollama under launchd with `Nice` / `ProcessType=Background`, or `nice`/`renice` the `ollama` process
so it yields to FileMaker Server. Run big indexes when the Mac is otherwise idle.

### Uninstall
```
brew services stop ollama && brew uninstall ollama     # or quit the app and move it to the Trash
rm -rf ~/.ollama                                        # downloaded models
```
Then clear the embedder in **Settings → Integrations → Semantic search**.

---

## After setup

- Pick a model and stay on it — **changing the embedder means a Reset + reindex** (different dimensions).
  See [Semantic search & the index](/docs/semantic-search).
- Model recommendations and the endpoint fields live in [Settings](/docs/settings#ai-summaries-embeddings).
- Indexing runs on the [queue](/docs/queue), one job at a time, in the background.
