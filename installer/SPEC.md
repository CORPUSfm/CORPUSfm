# CORPUSfm Installer — Governing Spec

The installer is a **bounded subproject** of CORPUSfm: it lives in `installer/`, stays attached
to this repo (it depends on the app — imports `corpusfm.install`, reads `requirements-server.txt`,
knows the app's entry points), and ships per-platform implementations of ONE shared design. A
separate-repo split is deferred to the public-repo milestone.

**Repository layout** — platform scripts live in per-platform folders; shared/build files stay at
the `installer/` root:

```
installer/
  SPEC.md  package-installer.sh  requirements-server.txt    # governing doc · build · shared manifest
  linux/   install.sh  uninstall.sh  _cfm_lib.sh  cfm-db-helper.sh  cfm-web-proxy.sh
  windows/ install.ps1  uninstall.ps1  _cfm_lib.ps1  cfm-proxy-exec.ps1
```

Release **bundles flatten** (the zip holds `install.sh` + its lib side-by-side, no `linux/` prefix),
so the self-clone bootstrap still finds the library beside the installer. The per-folder split keeps
the clean boundary for a future per-platform sparse-checkout (so a Linux box need not carry the
Windows scripts). `cfm_section`/lib sourcing is `$SCRIPT_DIR`/`$PSScriptRoot`-relative, so it travels
with the scripts; only `install.sh`'s broker-path + self-reexec references are folder-qualified.

**Governing principle — parity except where a better tool changes the outcome.**
- **The orchestrated *process* is identical across platforms** (same stages, same order, same
  boundary contracts, same *option interface*).
- **Tools diverge only where the platform's best tool genuinely differs** (systemd vs WinSW,
  nginx vs IIS, …). Every divergence must name the contract it still satisfies and why the tool
  differs — otherwise it's drift, not a decision.
- **Knowledge flows both ways.** A capability one platform surfaces becomes shared. Example:
  Windows needed an FMS-location override (FMS on a non-C: drive) → `--fms-root` is a **universal
  flag on every installer**, even though each platform spells it in its own idiom and auto-detects
  a different default.
- **End-to-end by default, with surgical opt-outs.** The installer carries enough logic to do the
  *entire* known-good install with **no gaps** — PKI registration, storage bootstrap, proxy, all of
  it — "do it like we know it." It must not punt a real step to a manual follow-up. BUT every
  fallible/optional stage has a `--no-<stage>` opt-out, so when a stage is the cause of a problem
  (or doesn't apply to a deployment) the operator disables **just that stage** and the rest of the
  install still completes. Default = everything; opt-outs = a scalpel, not a mode. `--no-pki` is the
  archetype: skip the FMS Admin-API PKI registration, finish a working install, wire PKI by hand
  later. Verify adapts — it never asserts a stage that was opted out.

Implementations:
- `install.sh` / `uninstall.sh` — Linux (Ubuntu). The reference deployment.
- `install.ps1` / `uninstall.ps1` — Windows Server (2019/2022/2025).

> **THE TWO UNINSTALLERS ARE LAUNCHERS (packet 1246-09, stage 6).** They remove nothing. Each
> elevates, builds one strict privileged request, calls `corpusfm-lifecycle uninstall start|resume`,
> reads exactly one JSON result and prints it; every decision about what may be deleted, and every
> deletion, belongs to the lifecycle component, which makes them from what the installation RECORDED
> about itself and re-proves each target immediately before acting. **Their options are exactly
> `--yes` · `--force` · `--silent` · `--verbose`**, and every other spelling — `--keep-data`,
> `--fm-admin-user`, `--fm-admin-pass`, `-InstallRoot`, `-ConfigHome`, `-Site`, `-FmsRoot`,
> `-Prefix` — is **refused as unknown**, not accepted and ignored. Neither reads a credential: when
> a recorded operation proves it needs an FMS administrator, the CLI reads the console itself.
>
> **The Windows launcher asks for a RUNTIME first (packet 1000-14), and Linux does not.** Windows
> will not unlink a running image or remove a directory a live process is standing in, and the
> launcher runs `<install_root>\python\python.exe` — so `uninstall.ps1` calls
> `corpusfm-lifecycle uninstall runtime --destination <its own protected temp dir>`, which copies
> **the component's own** interpreter and product code out, proves the copy by running it, and
> returns the executable to drive the uninstall with; the launcher then steps its own working
> directory out to `%TEMP%`. It stages a copy, not a plan: the verb reads no pending record, names
> no target and takes no install root. **The destination it is given is verified, not trusted** — the
> staged leaf must not already exist and is never adopted, and its parent is judged as a protected
> directory by the same privileged-input policy the request file gets, because the verb is reachable
> without the launcher. POSIX unlinks a running image and removes a live working directory, so
> `uninstall.sh` runs the installed lifecycle interpreter and removes it from under itself. Its
> **result reader is different**: the fixed Ubuntu `/usr/bin/python3` stdlib JSON reader is proved
> before the boundary and survives the terminal-footprint removal, because a second invocation of
> the just-unlinked installed interpreter cannot start even though the lifecycle process that was
> already running completes normally.
>
> Two clauses elsewhere in this document describe the retired scripts and are kept as history: the
> uninstaller credential `die` in §4 (the rule survives — a launcher that cannot perform FMS work
> cannot perform it without FMS authority) and `--keep-data`'s selective preservation (retired: it
> left an installation the installer refused to reinstall over).

---

## Behavioral contract (how it acts)

1. **Re-run == resume, and re-run == auto-upgrade.** Every stage is idempotent; there is no separate
   "repair" mode — running the installer again safely continues from wherever a prior run stopped.
   **Re-running on an EXISTING install auto-detects it and enters the idempotent UPGRADE flow with no
   flag** — Linux keys off the installed venv (`/opt/CORPUSfm/venv`), Windows off the existing install
   (it has no `-Upgrade` switch). **There is no force-upgrade flag on either platform**: re-running the
   installer IS the upgrade command. A truly-fresh
   box (no durable marker — e.g. a partial install that never reached the venv) does a fresh install.
   Detection is conservative and happens in **Settings (§3), before any Progress (§7) mutation**; the
   upgrade self-pull still passes the origin + clean-tree trust rails. (Non-interactive upgrade:
   Linux `install.sh --yes`; **Windows `install.ps1 -Yes -FmAdminPass <pass>` — NOT
   `-NoBootstrap`, which rewrites a minimal marker and drops the storage config**; see
   the Windows install notes in `docs/`.)
2. **Fail-fast, stay re-runnable, never break FMS.** On an *unexpected* failure (not a `--no-X`
   opt-out): stop with a clear message + the log path, leave the box in a re-runnable state, and
   **never leave FMS's web server broken** (the prime directive — the IIS isolation / nginx
   validate-and-rollback both serve this).
3. **"Done" means working, not installed (the health gate).** `verify` confirms real function, not
   just "service started": the app **reaches the storage backend** (readiness), **PKI actually
   authenticates** (a test Admin-API call) when PKI is enabled, and every enabled service is live.
   A `--no-X` stage is skipped, never asserted.
4. **Secrets — minimal, unadvertised.** Public source acquisition and updates are anonymous; no
   repository credential is shipped or stored. The **FM admin password is required in most runs but NEVER stored** — it is used
   transiently for PKI registration + storage bootstrap, then discarded. **PKI or nothing:** the
   only persistent FMS-admin auth is the registered PKI key; there is no stored-password fallback,
   so `--no-pki` (or a failed PKI step) simply degrades the apply/admin features and the install
   still completes. The app's own secrets (MCP token, session secret, crypto key) are generated +
   persisted (encrypted where the app already encrypts). The **storage backend** authenticates with
   its own *dedicated least-privilege app account*, whose credential is stored encrypted in
   `install.yaml` — distinct from the admin password.
5. **Unattended is first-class.** Given the right flags the installer runs zero-prompt
   (`--silent`/`--yes` + `--fm-admin-pass`/env + any `--no-X`); this is a supported mode, not an
   afterthought (it's what a release/automation run needs).
6. **Lifecycle + upgrade channel.** Verbs: install / upgrade / uninstall. **Code-only** changes go
   through the in-app Updates button (`git pull` + restart); anything touching **proxy / services /
   deps / DB** goes through re-running the installer. Same split on every platform.

## Interaction flow (how it talks)

Every script — installer, uninstaller, and any future operational script — walks the **same ten
sections in order**. This is the normative contract; a script conforms or it is wrong.

Two cross-cutting rules govern the whole flow:

- **Mutation boundary — §6 | §7.** Sections 1–6 are read-only or ask-permission: any failure there
  **dies clean**, with nothing changed and nothing to undo. §7 is the *only* section that touches
  the system. This is what makes fail-fast safe.
- **Active-settings scope.** The effective settings scope §4/§5/§6 uniformly: **ask only for
  permissions an enabled action needs (§4), probe only the targets an enabled action touches (§5),
  announce only actions that will actually run (§6).** `--no-pki` ⇒ no PKI cred prompt, no PKI
  probe, no PKI line in the plan.

**§1 — Hello.** "I am this script. I do this thing." Identity + purpose, one breath.

**§2 — Self-check.** Is logging working? Is my source complete (a self-bootstrapped clone fully
landed)? Do the input parameters cohere? Do I hold the privilege merely to *run*? If anything
doesn't add up, say what and **die.** Never bypassed.

**§3 — Echo of settings.** The effective settings for this run (defaults + overrides + which
`--no-X` are on), with brevity — the operator sees exactly the run they're getting.

**§4 — Acquire permissions.** Ask for the permissions/credentials it doesn't yet hold (e.g. the FM
admin password an enabled stage needs). **Die without.** Don't ask for what we know we don't need.
Pure acquisition — *no* confirmation here (that's §6). Credentials are used transiently, **never
stored** (PKI or nothing).

> **Invariant — credentials are the *means*, never consent.** Acquiring credentials at §4 NEVER
> accepts mutation; only §6 does. Providing `--fm-admin-pass`/`-FmAdminPass` (or the env) must NOT
> skip §6 — it only supplies what §7 will need. Only an explicit consent mode may suppress the
> interactive wait; **never** a credential variable or an inferred scope.
>
> **Scope skip retired 2026-08-12.** Re-running an installer selects an update; it does not itself
> consent to the plan that the incoming installer measured. Interactive installation and update
> both show the complete plan and wait. `--yes` / `-Yes` suppress only that wait, while silent mode
> is the fully unattended consent mode. Uninstall also always confirms unless one of its explicit
> consent modes was selected.

> **§6 is the mutation boundary, and it is enforced (packet 1228).** Nothing in §1–§5 may change the
> system. Both installers violated this until 2026-07-31: Windows enabled FMS's global ARR proxy
> toggle, created five directories and rewrote an ACL tree in §5; Linux ran its self-pull against the
> installed checkout in §3 and then suppressed §6 entirely via `CFM_PULLED`, so an upgrade that
> fetched code was never consented to in either run. Those mutations now live at the top of §7, and
> `CFM_PULLED` means only what its name says — a re-exec sentinel, on a run whose consent was
> genuinely taken first.

**§5 — Detection (credentialed).** With permissions in hand and per settings, test all related
areas and validate orientation to system and goals: can the script *see / change / delete / create*
each target, **as only required by settings**? If it can't meet the goals, express the conundrum
and **die.** Never bypassed. (Honest limit: this proves *no known blocker*, not guaranteed success —
creation can't be fully proven without creating.)

**§6 — Announce + confirm.** Express the actions the script will attempt, with brevity, and ask for
confirmation. **Die without.** Don't display an action that won't be performed under the given
settings. *At this point the script is written and finite — we know what is possible, and mutation
is accepted.* (We know the full intended action **set**, because §5 lifted the credential veil; we
do **not** know every outcome, emergent sub-step, or drift between probe and act — which is exactly
why §7 carries recovery and §8 reports a real tally.)

**§7 — Progress & status.** Perform each action in order; show a progress bar when warranted;
display each outcome. On a step failure, attempt **retry or recovery**; if that fails, **jump
straight to §8** (no silent continuation past a fatal step, no blocking on a human — execution is
non-interactive).

**§8 — Summarize.** The verdict for §7: `8/8 steps completed`, or `7/8: failed on <action>`
(steps 8 were not attempted). Always emitted.

**§9 — Next steps for the admin.** Whatever pathing the outcome allows: the success handoff ("open
https://<host>/corpusfm/", connect MCP at `<prefix>/mcp/`, ...) OR remediation ("fix X, then
re-run" / where the troubleshooting docs live).

**§10 — Farewell, on full success only.** The installer says **"Thank you!"**, the uninstaller says
**"Goodbye!"** — emitted only when everything went well.

### The consent + output flags — three distinct states (packet 1230)

**Applies to all four Tier-1 scripts.** They are separate variables, never one boolean: collapse them
and the output distinction disappears the next time someone simplifies.

| Flag | Grants | Does NOT grant |
|---|---|---|
| `--yes` / `-Yes` | consent: no §6 wait, no §4 prompt. **Normal output. Errors still stop the run.** | anything about failures or authority |
| `--force` / `-Force` | consent, **plus** continue past a failed step (best-effort) | authority over FMS |
| `--silent` / `-Silent` | consent, **plus** decoration suppressed and detail routed to the transcript | authority; error tolerance |
| `--verbose` / `-Verbose` | command detail on the console (it always reaches the transcript) | — orthogonal to all of the above |

> **No flag substitutes for a credential.** These grant permission to proceed *without being asked*;
> none grants authority over FileMaker Server. A credentialed action is performed with the credential
> or it is not performed — never on the strength of a flag. **A missing credential is not an ERROR; it
> is an absent PRECONDITION.** You may force past a step that failed. You may not force past not
> having the right to act. `--force` tolerates a step that FAILED — never a check that REFUSED, and
> never `--allow-dirty`'s supply-chain trust rails, which stay their own flag.

> **`--force` is UNINSTALL-ONLY, and that is a decision — not a gap.** Every installer stage where
> "keep going" is legitimate is served by a surgical `--no-<stage>` opt-out; the stages without one
> (system packages, the bundled Python, the venv, dependencies, the health verify) are ones where
> continuing produces a box that cannot work — which is what §7.3's *"done means working, not
> installed"* exists to prevent. The two cases differ in kind: **on install a fallible stage is
> OPTIONAL** (the operator can decline it, so the tool is a flag that says *skip this one*); **on
> uninstall it is CONDITIONALLY PRESENT** (nobody decides whether the PKI key is there — you find
> out, and the need is *keep going and report what you could not do*). Contract satisfied on both
> sides: every fallible stage has an escape. **Do not "restore parity" by adding `--force` to an
> installer.**

> **A declared flag must be WIRED, not merely accepted.** It must reach the library's gear
> (`CFM_SILENT`/`$script:CfmSilent`, `CFM_VERBOSE`/`$script:CfmVerbose`, …) **before the first
> primitive call.** Three defects of this shape existed at once until packet 1230 — `uninstall.ps1`
> accepted `-Verbose` and ignored it, `install.ps1 -Silent` printed everything anyway, and neither
> uninstaller had `--silent`. All three *accepted* their flag correctly, so a test written against
> acceptance passes against every one of them. **Assert the effect, never the acceptance.**

> **Both uninstallers open a transcript**, outside the tree they delete — `/var/log/corpusfm/` on
> Linux, `%TEMP%` on Windows. `--silent` RELOCATES output; without a transcript it would DESTROY it,
> on the script whose failures are least recoverable.

### `--silent` (and `--yes`)

`--silent` is **not** a global mute. It may skip the two *blocking* sections and trim *decoration* —
it may **never** skip a gate that can die (§2, §5) or the verdict (§8).

| § | Interactive | `--silent` |
|---|---|---|
| 1 Hello | banner | suppressed |
| 2 Self-check | runs; die on fail | **runs; die on fail** |
| 3 Echo settings | printed | logged, not printed |
| 4 Acquire perms | **prompt** for missing creds | **no prompt** — creds from flag/env; **missing ⇒ die** |
| 5 Detection | runs; die on fail | **runs; die on fail** |
| 6 Announce + confirm | print plan, **wait y/N** | plan to log, **no wait** (consent pre-granted by the flag) |
| 7 Progress | progress bar + live outcome | terse line-per-step to log; no bar |
| 8 Summarize | printed | printed/logged |
| 9 Next steps | printed | logged |
| 10 Farewell | on full success | suppressed |

`--silent` changes *how* a script communicates, never *whether* it validates: a silent run that
can't get creds at §4 or fails orientation at §5 still dies — it just dies without having asked.

**The table above is written for an INSTALLER. Two clauses read differently on an uninstaller, and
both are stated rather than left to inference (packet 1230):**

- **§4 "missing ⇒ die" applies there too, and for a stronger reason** — see the uninstaller credential
  rule in §7.3. It is not that the credential is optional; it is that no flag confers FMS authority.
- **§8 "always emitted" cannot hold for a script that ABORTS on failure.** Both installers `die` at
  the failing step and never reach §8, and that is correct — they never claim a success they did not
  earn. A script that *continues* past failures (either uninstaller) must register named steps and
  emit the real `N/M` verdict. **Rejected alternative:** rewriting both installers onto the step
  runner to buy a nicer error message. Not worth it; a `die` is already honest.

---

## Script conformance (which scripts, how fully, enforced how)

**THE TWO INSTALLERS WALK PHASES 1–21 IN §4H's ORDER** — that ordered structure is the invariant,
and `tests/test_installer_parity.py` compares the two real phase lists rather than either against a
fixed expectation. `uninstall.sh` and `uninstall.ps1` keep the ceremonial section skeleton: a
section with no work to do is **not omitted; it degrades to a one-line ceremonial no-op**, because a
uniform log shape means the operator always knows where they are.

> **CORRECTED 2026-08-06 by packet 1246-04-05 (A8).** *Superseded wording, kept as the history it
> is:* **"Every shipped CLI script walks all ten sections, in order — the skeleton is invariant. …
> the conformance test reduces to 'all ten `section` calls, in order' with no per-script subset
> logic."** That described the pre-1246-04 installers. §4B replaced the ten-section skeleton in both
> installers with twenty-one numbered phases, so the claim was false on the two scripts it most
> mattered for, and `test_script_conformance.py::test_walks_all_ten_sections_in_order` was retired
> as **DELETE WITH SUBJECT** with the ordered-structure obligation moving to the parity module.
> `tests/test_docs_factual_guard.py` now fails the build if a live ten-section invariant returns.

The tier sets **how full each section is, not whether it exists**:

| Tier | Scripts | Section fill |
|---|---|---|
| **1 — operator-facing lifecycle** | `install.sh`, `install.ps1`, `uninstall.sh`, `uninstall.ps1` | §1/§4/§6/§10 are **rich + interactive** (greeting, credential prompt, announce+confirm, farewell). **SHIPPED + test-enforced.** |
| **2 — security brokers + config helpers** | `cfm-db-helper.sh`, `cfm-web-proxy.sh`, `cfm-proxy-exec.sh`, `cfm-proxy-exec.ps1` | **NOT forced onto the skeleton — deliberately.** `cfm-db-helper.sh` is a sudoers-NOPASSWD **root broker**, kept minimal + auditable, with stdout consumed by its callers. The retained Linux preflight helper reads the FMS web configuration; the installed proxy executors publish provider-rendered families with backup+validate+rollback and never render policy themselves. Forcing ceremonial sections onto these privileged boundaries is not "within reason." A later, careful pass *may* unify just their **output primitives** (source the lib for `info/ok/warn/die`) without the ceremonial section skeleton (the *ten-section* count was retired for the installers by §4B's 21 phases; corrected 2026-08-06 by 1246-04-05) — and only with re-validation. |
| **2 — security brokers (packet 1246-03 — ⚠ UNCOMMITTED DESIGN, not installed on either box)** | `corpusfm-update.sh`, `corpusfm-update.ps1` | Same exemption and the same reason as `cfm-db-helper.sh`: a fixed, root-owned, one-shot **privileged boundary**, kept minimal and auditable. It takes no parameters, is invoked by a systemd one-shot unit (Linux) or a fixed scheduled task the service SID may run but not modify (Windows), and reads exactly two fields — a correlation id and `expected_head` — from a fixed root-owned request path. See *The privileged update boundary* below. |
| **retired / build** | `cfm-mcp-ctl.sh` (retired), `cfm-storage-swap.sh` (retired packet 085 — its only app caller, the migrate-into-new-file engine, is deleted; `install.sh` removes the installed copy + NOPASSWD grant), `package-installer.sh` (Tier-3 build/release) | exempt |
| **3 — dev/build** | `build/*.sh`, `package-installer.sh` | exempt (not shipped, not operator-facing) |

### The enforcement mechanism: a shared per-language library

Prose rules drift; a sourced skeleton cannot. There are **two shipped libraries** — `_cfm_lib.sh`
and `_cfm_lib.ps1` (twin APIs) — that every Tier-1 script sources and builds on; that single rule is
what makes all the others real and closes the "Linux looks nothing like Windows" gap:

- **Five canonical output primitives, identical names + behavior in both languages:**
  `hello` · `info` · `ok` · `warn` · `die` (PowerShell: `Hello`/`Info`/`Ok`/`Warn`/`Die`). A script
  **must not** define its own (`header`/`success`/… are banned in script bodies — they live in the
  library only). `--silent` muting (`CFM_SILENT` / `$script:CfmSilent`) is baked into the primitives.
- **A section runner** — `cfm_section "<title>"` / `Section "<title>"` — that emits a uniform,
  numbered boundary (even for a no-op body) and is what the conformance test reads for order.
- **The §7 step-runner** — `cfm_step "<name>" <fn> [recover] [retries]` + `cfm_run_steps` +
  `cfm_summary` (PowerShell: `Cfm-Step`/`Cfm-RunSteps`/`Cfm-Summary`): register ordered named
  steps each with a retry/recover handler; on a hard failure it short-circuits to §8 and emits the
  `N/M` tally automatically. This is the one piece of new machinery, and it makes §8's "7/8: failed
  on X" honest.

### Library naming rule (packet 1231)

**`cfm_<name>` (bash) ⇄ `Cfm-<Name>` (PowerShell) — the same word, in the same order, spelled in each
language's idiom.** This is the §3 flag rule (`--fms-root` ⇄ `-FmsRoot`) applied to the library: the
*word* is shared, only the punctuation differs. A reader of one script must be able to find the
counterpart in the other without a lookup. `tests/test_script_conformance.py` enforces it.

**Two sanctioned exceptions, listed by name so neither reads as an oversight:**

1. **The five output primitives** — `hello`/`Hello` … `die`/`Die`. Already identical modulo case, and
   the highest-frequency calls in all four scripts.
2. **`cfm_section` ⇄ `Section`.** A bare, unambiguous noun whose two spellings read as the same
   thing. Renaming it would churn ~20 call sites and risk a PowerShell-only runtime failure for zero
   operator-visible change. **Do not "finish the job" here.**

**Trade-off, recorded so it is reopened deliberately rather than tidied away:** `Cfm-Summary` and
`Cfm-RunSteps` are **not** PowerShell approved-verb form, and a PowerShell-fluent contributor will
recognise that. Cross-platform legibility was chosen over verb convention because these are private
dot-sourced script libraries — nothing is exported, nothing is discovered by verb, and
`PSScriptAnalyzer` appears nowhere in this repository. If that changes, this is the decision to
revisit.
- **Shared silence + the common-interface flags** (§3 below): a helper and an installer-under-
  `--silent` reach the *same* non-interactive path — ceremony and silence are one gear.

### §7 task-tree parity (one tree, OS-specific leaves)

The §1–§10 contract is parity at the *section* level. The same principle binds the **work inside
§7**: the install/uninstall **task tree is one shared tree across platforms, varied only by the
OS-specific *tool* for each task — never by which tasks exist.** Every step on one platform has a
counterpart on the other unless the task is genuinely meaningless there (and that exception must be
named). The **uninstall tree is the install tree in reverse** — anything install *registers with an
external system* (FMS), uninstall must *deregister*.

| Install / Uninstall task | Linux leaf | Windows leaf |
|---|---|---|
| services | systemd unit | WinSW service |
| reverse proxy | nginx block (FMS web) | isolated IIS app + pool |
| firewall | UFW rule | *none* — loopback behind IIS (named exception) |
| storage DB (deploy / close+delete) | fmsadmin + Admin API | fmsadmin.exe + Admin API |
| **Admin-API PKI key (register / deregister)** | Admin API | Admin API |
| install tree + data | `/opt/CORPUSfm` | `C:\CORPUSfm` + ProgramData |
| service account | `corpusfm` user | *none* — LocalSystem (named exception) |

**Drift this caught — BOTH CLOSED (verified 2026-07-31, packet 1229):**
- ~~Windows `uninstall.ps1` does not deregister the PKI key~~ — **closed `1b70b214`, 2026-06-24.**
  It calls `pki.deregister_local_key` and reports removed/not-removed.
- ~~Linux `uninstall.sh` does not remove the nginx proxy block~~ — **closed `ab14a493`, 2026-06-24.**
  `step_remove_proxy` drives `cfm-web-proxy.sh remove`; the mode exists.

> **Why these are struck through rather than deleted, and why this genre is now closed.** Both were
> recorded as owed and stayed that way for five weeks after being fixed. `1b70b214` is the worked
> example: **the commit that closed the PKI gap is the commit that wrote it down as owed** — its
> diffstat is `uninstall.ps1` +35 and this file +30. The text was born stale, and three later edits to
> this file did not catch it.
>
> On 2026-07-31 it caused real waste: a packet was scoped and authorised to close both gaps, and only
> verifying against code before writing stopped two finished tasks from being executed.
>
> **A "gaps to close" list inside a contract has no lifecycle.** Nothing moves it, nothing closes it,
> nothing shows it as stale. An open packet is visible in the ledger and either executes or closes by
> decision. **So this document states what must be TRUE; anything OWED becomes a packet.** Do not open
> a new work list here — open a packet. *(Same ruling as `docs/`: "the plan should now mostly live in
> the code and packets," developer, 2026-07-31.)*

A task that one platform skips for a real reason (firewall, service account) is fine — but it is a
**named leaf exception**, not silent drift.

### The conformance test (the static enforcer)

`tests/test_script_conformance.py` asserts, per **Tier-1** script: it sources the shared library; it
defines **no** local output primitives; and it invokes **all ten** sections, in declared order
(start-with match on the canonical titles). It also checks both libraries exist and are ASCII-only.
It fails the moment a Tier-1 script drifts back into a bespoke shape. The Tier-2 brokers are out of
scope on purpose (see the tier table above).

---

## Conventions (locked)

- **Dependency pinning** — pin the **interpreter** (CPython **3.13.14**, both platforms — Linux
  bundles python-build-standalone, Windows the python.org embeddable, both SHA256-pinned) for
  reproducibility; let the single-purpose tools (MinGit, WinSW) **float to GitHub-latest** (stable,
  low-churn), with a pin-override available if a release ever regresses.
- **Golden reference** — "do it like we know it" means the proven **`fms-server` Linux deployment**
  is the canonical correct behavior; every platform's outcome is measured against it.
- **Logging** — the console **is** the interaction flow (§1 Hello -> ... -> §10 farewell); a full
  timestamped transcript also goes to a per-run log under `<ConfigHome>/logs/`, and the fail-fast
  message (behavioral contract #2) cites that path.
- **Self-contained bootstrap (the root of trust)** — the **bootstrap installer is the unit of
  distribution**: a single file handed to a box, depending on nothing pre-staged but the OS + FMS.
  It acquires the current public release anonymously, verifies its manifest and digests, deploys it,
  and then **mints the per-box FMS Admin-API PKI pair** — born *on the box*, never shipped. Source
  updates use anonymous HTTPS; the installer does not mint a GitHub deploy key for the application
  checkout. This holds on every platform. Transient operational credentials
  (e.g. the FM admin password to close the storage DB) are **§4 acquires**, prompted and never
  stored — not shipped secrets.
- **Accepted exposure — FM admin password on argv.** The pre-PKI bootstrap calls `fmsadmin -u … -p
  "$FM_ADMIN_PASS"`, which puts the password on the process command line, briefly visible via `ps`
  to other local users while each call runs. This is **accepted**: `fmsadmin` has no documented
  stdin/file password path; the installer is short-lived + admin-run; and the *durable* automation
  path is password-free (Admin-API PKI, minted on the box). It is **minimized** — `FM_ADMIN_PASS`
  is `unset` immediately after the last `fmsadmin`/PKI use in both `install.sh` and `uninstall.sh`,
  and each call site carries an in-code `NOTE (accepted exposure)`. Revisit only if a future
  `fmsadmin` gains a non-argv password input.

## The OS layout, service identities and the privileged update boundary (packet 1246-03)

⚠ **DESIGN IN PROGRESS, UNCOMMITTED.** This whole section describes packet 1246-03's work in the
working tree, not installed behavior. **Both existing boxes still use the pre-1246-03 layout.**

**One selected software root; fixed OS locations for everything mutable.** `InstallDir` is
administrator-owned and not runtime-writable. Config, state, secrets, logs and the run directory are
**derived from the platform**, never selected: `/etc/corpusfm`, `/var/lib/corpusfm/{state,secrets}`,
`/var/log/corpusfm`, `/run/corpusfm` on Linux; `C:\ProgramData\CORPUSfm\{config,state,secrets,logs,run}`
on Windows. There is no second selectable `ConfigHome` and no environment override — the application
resolves them through `lifecycle/app_paths.py`, which requires a valid agreeing locator and manifest
on an installed runtime and refuses rather than guessing when that record cannot be read. Development
and tests select a development layout explicitly; absence of an installation record is not a
production fallback.

**Who installs this, and who converts the two existing boxes.** **1246-04** is the single integrator:
it composes 1246-03's renderers, policies and artifacts into the fresh / rerun / update flow, publishes
the manifest's `paths` block, and starts nothing before publication. **It does not accept the old
format as an ordinary update input.** The two development installations are converted **once**, by
**1246-10**, after the destination is complete — a bounded private installer operation against their
exact measured topologies, retained until the developer explicitly authorizes its removal, and never a
runtime compatibility mode. *(Superseded, kept: earlier drafts of this section said publication happened
inside a general `lifecycle/cutover.py`. That cutover is removed — developer ruling, 2026-08-03.)*

**Genuinely unprivileged runtime, on both platforms.**

- **Linux** — the non-login `corpusfm` system user, unchanged; what changed is `$INSTALL_DIR/src`,
  which was `0770 root:corpusfm` and is now root-owned and not group-writable. Every deployment git
  operation runs as root (the `gitsu` seam), because the reason they ran as the service — so a
  service-user `git pull` would not trip dubious-ownership — is precisely the reason the service
  could rewrite the code it executes.
- **Windows** — each service now carries an explicit `<serviceaccount>NT SERVICE\<id>`. The previous
  definition named **no account at all**, so both services ran as LocalSystem *by omission*. That
  distinction is why the emitter (`lifecycle/service_identity.py`) cannot render a definition without
  an identity: a check that the identity "is not LocalSystem" passes against a definition that names
  nothing. Matching `icacls` grants are applied after registration, because the virtual SIDs do not
  exist before it.

**Installed secrets are read-only to both runtime services, with no per-file exception.** MCP access
is user-account-centric and resolves through storage; the installer provisions no server-wide MCP
credential. An update removes the retired `.mcp_env` from both its fixed-secrets and legacy install-root
locations before either service starts.
Missing, substituted, symlinked, wrongly owned or wrongly protected all fail closed, and on a
published installation the runtime never creates it.

**The privileged update boundary.** The web process no longer updates itself — **the self-pull path
is deleted, not conditioned.** It writes a request to
a fixed root-owned path and triggers one fixed operation — `systemctl start
corpusfm-update.service` through a one-command `/etc/sudoers.d/corpusfm-update` grant on Linux, a
fixed scheduled task the service SID may run but not modify on Windows. The elevated script accepts
**no** ref, path, command or environment. It reads two fields: a correlation id, and `expected_head`
— a **refusal-only consent precondition**. The elevated side resolves `origin/main` itself and
refuses if the tip differs; the supplied value is never passed to git and never makes an otherwise
ineligible update eligible, because every other gate (expected origin, clean tree, forward-only, path
classification) is evaluated on the independently resolved tip. Its single reachable effect is a
refusal. The elevated side then writes a root-owned, service-**readable** outcome record — operation
id, trigger id, requested and observed tip, state, reason, rollback result, resulting head, and the
log **location** — carrying no secret.

The deployed checkout and its runtime build stamp are one update transaction. After applying the
approved HEAD, the elevated side reads that public HEAD's tracked `release-build.txt`, writes and
reads back `corpusfm/_build.txt`, and only then loads or restarts the new runtime. The public
repository's intentionally short Git history is not a product-version authority. A same-head
invocation can therefore repair a stale stamp. Any later rollback restores both the prior Git HEAD
and the prior stamp state; success is published only after the resulting HEAD and declared build
agree.

## 1. The orchestration spine (identical on every platform)

| # | Stage | Guarantees |
|---|---|---|
| 1 | **Preflight** | privilege (root/Administrator); OS supported; **FMS present**; web-server modules present; web port free; internet egress |
| 2 | **Dependency bootstrap** | a usable Python + git are present (delivered if missing) |
| 3 | **Source** | verified public repo at `…/src`; anonymous HTTPS origin; exact bundled commit; version from tracked `release-build.txt` |
| 4 | **Python env + deps** | `installer/requirements-server.txt` installed into an isolated interpreter; core imports verified |
| 5 | **Config marker** | `install.yaml` written: `mode: server`, `web_prefix`, `web_port` (via `corpusfm.install`) |
| 6 | **MCP token** | generated once, persisted, injected into the web service env |
| 7 | **Service(s)** | `corpusfm-web` (uvicorn) + `corpusfm-scheduler` (cron daemon) running + restart-on-failure |
| 8 | **Reverse proxy** | app fronted behind FMS's web server at `web_prefix`, FMS undisturbed |
| 9 | **Verify** | loopback app + proxied prefix + **FMS coexistence** all assert; summary printed |

`uninstall` reverses 5–8 + removes the tree, **never touching FMS's own config**, and verifies FMS
is undisturbed at the end.

---

## 2. Boundary contracts (the parity invariants — must be byte-identical in meaning)

These are what make the two installers interchangeable from the app's point of view. Change one
and you change both.

- **ONE FOLDER — everything belonging to CORPUSfm outside the FileMaker Server folder lives in a
  single directory, WITHOUT EXCEPTION** (developer ruling, 2026-08-01). The install root is the only
  place CORPUSfm occupies. Anything the product owns — software, venv, bundled Python, secrets,
  `install.yaml`, logs, the archive, generated hosted databases — is a child of it. The FMS tree is
  the one place outside it CORPUSfm touches, and that is FileMaker's directory, not ours.

  **This is ASPIRATIONAL TODAY and neither installer satisfies it.** Recorded here as the contract
  because it governs every future change to installer layout, not because it describes current code.
  Current state, measured 2026-08-01:

  | | Linux | Windows |
  |---|---|---|
  | the app (+ secrets, marker, archive) | `/opt/CORPUSfm` | `C:\CORPUSfm` |
  | secrets / marker / logs | *(inside the app folder ✓)* | **`C:\ProgramData\CORPUSfm` ✗** |
  | generated hosted DBs | **`/opt/CORPUSfm-Hosted` ✗** | **`<fms-drive>:\CORPUSfm-Hosted` ✗** |

  So Linux is **two** and Windows is **three**; the target is **one** on both.

  **Why it is not being fixed now, stated so the gap is not mistaken for an oversight:** *"We can't
  fix the installers at this time without having the installer relocating everything to itself. And
  all the security gets re-adjusted."* (developer, 2026-08-01). Both moves are real work — the
  Windows one is an **ACL** change on the directories holding `corpus.key` and `machine.key`,
  because `ConfigHome` is tree-locked to SYSTEM+Administrators precisely so those files do
  not inherit `C:\ProgramData`'s default `Users:(RX)`, while `InstallRoot` is deliberately **not**
  tree-locked (its `proxy\web.config` must stay IIS-readable). Merging means breaking inheritance on
  the proxy subfolders instead of separating the trees — achievable, security-relevant, and owed its
  own packet and box validation.

  **The hosting folder is included in "without exception", and that is the harder half.** It is
  outside the install root **by choice, not by constraint** — packet 1061's probe established the FMS
  Console accepts an Additional Database Folder outside the FMS tree, and says nothing about ours.
  What forces the current layout is that generated `.fmp12` files are **user work product that must
  survive uninstall**, and the simplest way to guarantee that was to put them where the tree removal
  cannot reach. **Selective preservation inside one tree is the alternative and it already exists** —
  Linux `--keep-data` preserves `.corpusfm` and `archive` in place with a `find … ! -name` sweep, and
  `step_preserve_hosting` already handles a hosting folder that sits *inside* the tree by moving it
  out first. Bringing it in means inverting that step, not inventing a mechanism.

  **Until this lands, a second folder is a KNOWN DEBT, never a licence.** Do not add a new top-level
  CORPUSfm directory on either platform for any reason; a new one is a contract violation, whereas
  the two recorded above are recorded debt.

- **`install.yaml`** — same schema/keys on every platform (`mode`, `web_prefix`, `web_port`,
  storage fields). Written via `corpusfm.install`, never hand-rolled.
- **Loopback + prefix** — the app binds `127.0.0.1:<web_port>` (default **8533**) with
  `--root-path <web_prefix>` (default **/corpusfm**); the proxy strips the prefix and forwards the
  plain path. The app keys "served over https" off the `web_prefix` **marker**, not a header.
- **TLS topology** — public TLS may terminate at an **edge proxy** (real cert) while FMS keeps its
  **internal/self-signed** cert for CORPUSfm's loopback Admin-API/OData. Browser-facing URLs (+ the
  advertised MCP URL) come from the **forwarded host/proto**, not the loopback; internal FMS calls use
  the configured `verify_ssl` (**default `False`** — self-signed internal is intentional, **not** a
  health failure), while real unreachable/auth/OData-disabled errors stay visible. CORPUSfm never owns
  the public cert nor toggles FMS TLS.
- **MCP** — folded into the web app at `<web_prefix>/mcp/`; token persisted in a side file and
  passed in the web service env (fail-closed: no token → not mounted).
- **Config home** — all runtime state under one root (`Path.home()/.corpusfm`): `install.yaml`,
  logs, crypto key, vector index. Platforms may relocate the root, but it stays single + fixed.
- **Verify assertions** — loopback responds, proxied prefix responds, FMS's own endpoint still
  serves. Same three checks everywhere.
- **OS support ≠ capability tier.** The installer/platform contract is **OS support** (it runs + serves
  + coexists); it asserts install HEALTH up to **readiness Tier 1** (storage + web + app). The
  **apply/generative capability tier is gated by the FMS *version*, not the OS** — `find_tool()` detects
  FileMaker Server's bundled `FMUpgradeTool` (none on FMS 2024 → Tier 1 analysis-only; 22.x on FMS 2025 →
  Tier 2 apply, no `--generateDBFile`; 26.x on FMS 2026 → Tier 2 apply + generate). So the installer
  **succeeds identically on every supported OS at any FMS version** — it never gates on capability; the
  Settings → Health tab reports the box's actual tier. Box-validated across all three FMS versions × both
  OS families (the capability rows are identical at the same FMS version regardless of OS).

---

## 3. Common option interface

Flags are defined by **semantic name**; each platform spells it in its native idiom (bash
`--kebab`, PowerShell `-Pascal`). **Universal** = must exist on every installer.

> **REWRITTEN 2026-08-06 by packet 1246-04-05, after the 1246-04 family shipped.** The table below
> used to describe fifteen options, most of which **no longer exist**: §4H retired eighteen Linux and
> fifteen Windows spellings **with no alias**, and each now falls through to an unknown-option
> refusal. A spec that lists a retired flag is worse than one that omits it — a reader builds a
> command line from it and the installer refuses. What follows is what the two scripts actually
> accept, verified by `tests/test_installer_parity.py`, which derives the set from both files and
> asserts they are equal.

**TEN SWITCHES IN NINE SEMANTIC GROUPS, identical in meaning on both platforms.**

| Semantic | Linux (`install.sh`) | Windows (`install.ps1`) | Universal? | Default / detection |
|---|---|---|---|---|
| Install location | `--install-dir` | `-InstallDir` | **yes** | Linux `/opt/CORPUSfm`; Windows `C:\Program Files\CORPUSfm` |
| Patch hosting folder | `--patch-hosting-dir` | `-PatchHostingDir` | yes | `<install-dir>-Hosted` (Linux) / the FMS data drive (Windows) |
| FMS location | `--fms-root` | `-FmsRoot` | yes | Linux `/opt/FileMaker/FileMaker Server`; Windows auto-detected from the service path |
| Proxy policy — manage | `--proxy-policy-add` | `-ProxyPolicyAdd` | yes | records `managed` for a front, through `proxy-public add` |
| Proxy policy — ignore | `--proxy-policy-ignore` | `-ProxyPolicyIgnore` | yes | records `ignored`, through `proxy-public ignore` |
| Repair storage access | `--repair-storage-access` | `-RepairStorageAccess` | yes | selects storage mode `repair_storage_access` **and** the `repair` verb — never `bootstrap` |
| Replace an existing directory | `--replace-existing-install` | `-ReplaceExistingInstall` | yes | refuses a non-empty directory carrying no CORPUSfm installation unless given |
| Non-interactive | `--silent` | `-Silent` | yes | interactive |
| Consent | `--yes` | `-Yes` | yes | prompts |
| Verbose | `--verbose` / `-v` | `-Verbose` | yes | concise; full output always reaches the log |
| Discard an incomplete fresh-install attempt (packet 1398) | `--discard-incomplete-attempt` | `-DiscardIncompleteAttempt` | yes | a rerun over an attempt that stopped part-way offers Inspect / Discard / Quit; `--silent` refuses without this switch; a discard always ends the invocation |

*(`-h`/`--help` exists on Linux only, and that is not a parity gap: PowerShell supplies comment-based
help and `-?` for every script intrinsically, so a Windows `-Help` parameter would be a redundant
switch added to satisfy a checker.)*

**EVERY OTHER SPELLING IS RETIRED WITH NO ALIAS** — `--port` · `--prefix` · `-ConfigHome` · `-Site` ·
`--no-pull` · `--ref` · `--allow-dirty` · `--enable-mcp` · `--no-mcp` · `--no-scheduler` ·
`--mcp-*` · `--fm-admin-user` · `--fm-admin-pass` · `--admin-user` · `--admin-pass` · `--git-pat` ·
`--assume-yes` · `-NoBootstrap` · `-NoPki` · and, on the UNINSTALLERS only, `--keep-data`/`-KeepData`
(packet 1246-09 stage 6 — it left an installation the installer refused to reinstall over, so
retiring it removes the state and not merely the flag). **Credentials never travel in argv (§6)**: the FM Server
administrator and the first CORPUSfm administrator arrive through the approved environment
variables, and the installer passes the FMS credential onward as a length-prefixed binary frame on
the provider's stdin. The loopback port and URL prefix are **implementation constants published by
`composition foundation`**, not inputs. MCP and the scheduler **always install**.

### Opt-out flags (one per fallible/optional stage)

> **VERIFIED 2026-07-31 (packet 1229) — this table describes the MODEL, and the code does not yet
> match it.** Measured, zero occurrences each:
> - **`install.sh` lacks** `--no-pki`, `--no-bootstrap`, `--no-proxy` (and `--prefix`).
> - **`install.ps1` lacks** `-NoProxy`, `-NoScheduler`.
>
> Six real gaps. **They are OWED and they need packets** — one decision each, because a missing flag
> is not automatically a gap: `-InstallRoot` and the absent Windows firewall step are the precedent
> that a platform difference can be a deliberate divergence instead. Do not treat this table as a
> statement of what exists.
>
> **This matters beyond bookkeeping:** packet 1230's ruling that `--force` is uninstall-only rests on
> *"every fallible installer stage already has a surgical opt-out."* That is true of this table and
> **false of Linux today**. The ruling stands and its reasoning holds once the opt-outs exist — but
> until then the alternative to `--force` is partly missing rather than merely unused.


Default behaviour runs every stage. Each `--no-<stage>` disables exactly one and lets the rest
complete; `verify` skips the assertion for any opted-out stage.

| Opt-out | Disables | When you'd use it |
|---|---|---|
| `--no-pki` | FMS Admin-API PKI registration | PKI registration errors (cert/host/perm); apply features degrade, install still completes |
| `--no-bootstrap` | storage-DB self-bootstrap (`CORPUSfm_DB` create + initial ingest) | FMS storage setup misbehaves; configure via the in-app wizard instead |
| `--no-proxy` | the reverse-proxy stage | proxy/IIS/nginx step is the problem; run loopback-only + wire the proxy by hand |
| `--no-scheduler` | the `corpusfm-scheduler` service | a box that should not auto-run jobs |
| `--no-mcp` | MCP token + mount *(exists both)* | no agent access wanted |
| `--no-pull` | git fetch on upgrade *(exists both)* | install the current checkout as-is |

### Conformance gaps (the work list)

**Completeness — DONE on Windows (`install.ps1`):** PKI registration (`--no-pki`), storage-DB
bootstrap via `run_bootstrap` (`--no-bootstrap`), and the real-OData health gate are all shipped +
proven on the box, matching `install.sh` end-to-end.

**Knowledge to flow back to Linux (`install.sh`):**
- **OData auto-enable** — Windows turns the OData + Data API connectors ON via the Admin API
  (`PATCH /fmi/admin/api/v2/fmodata/config`) when off; **`install.sh` does NOT** — it dies telling
  the operator to enable OData manually. Backport the auto-enable (a real "no gaps" win Windows
  surfaced first).
- **`--no-pki` / `--no-bootstrap` / `--no-proxy` / `--no-scheduler` opt-outs** — Windows has the
  first two; add the full opt-out set to `install.sh`.

**Flag parity (Linux missing what Windows has):**
- **`--fms-root` SHIPPED on `install.sh`** (packet 017): overrides the FMS root (default
  `/opt/FileMaker/FileMaker Server`); `FM_DB_DIR` derives from it. `fmsadmin` is still invoked via
  PATH (the FMS installer puts it there). Linux FMS install location is otherwise fixed by FMS itself.
- **Add `--prefix` to `install.sh`** (Windows has it; Linux fixes `/corpusfm`).

**Windows remaining (lower):** the `CORPUSfm_Sandbox` dry-run-apply slot (install.sh provisions it;
install.ps1 defers it to the FMUpgradeTool-apply-on-Windows work); WS2022/2025 coverage.

### Structural conformance to the §1–§10 contract (the alignment work list)

The four scripts each invented their own shape and output vocabulary (`header/info/success` vs
`Info/Ok/Warn`, different ordering, missing sections) — this was the real "Linux looks nothing like
Windows" divergence.

1. **✅ DONE — Shared per-language libraries** `_cfm_lib.sh` + `_cfm_lib.ps1`: the five canonical
   primitives (`--silent` muting baked in), the `cfm_section`/`Section` runner (emits the boundary
   even for a no-op body), and the **§7 step-runner** (`cfm_step`/`cfm_run_steps`/`cfm_summary` ⇄
   `Cfm-Step`/`Cfm-RunSteps`/`Cfm-Summary` — hard failure short-circuits to §8 + auto-emits the
   `N/M` tally). *Ceremony and silence are the same gear.*
2. **✅ DONE — The conformance test** `tests/test_script_conformance.py` (extends §5) — Tier-1 scripts
   source the lib, define no local primitives, and both libs exist + are ASCII-only. *(Superseded
   clause, kept: "and walk all ten sections in order" — retired for the two INSTALLERS by §4B's
   21-phase structure; corrected 2026-08-06 by 1246-04-05. The uninstallers still walk the
   sections.)*
3. **✅ DONE — Migrated all four Tier-1 scripts** onto the skeleton (`uninstall.sh`, `uninstall.ps1`,
   `install.ps1`, `install.sh`): behavior-preserving refactor + the missing sections (§3 echo, §8
   tally, §10 farewell-gated-on-success, creds moved into §4). `install.sh`'s gate was reordered
   (creds → detection → confirm) — its only cross-section dependency, `IS_UPGRADE`, is set in §3
   before §4, so the reorder is sound. Validated: conformance 15/15, shellcheck at the HEAD baseline
   (no new findings), ASCII-clean. **Still owed: re-validation on the real Linux + Windows boxes**
   (the golden-reference rule — the PowerShell path could not be runtime-checked off-box).
4. **DEFERRED (by design) — the Tier-2 brokers** (`cfm-db-helper.sh`, `cfm-web-proxy.sh`) are NOT
   on the skeleton (security/FMS-config reasons above). A later careful pass *may* unify just
   their output primitives.

**Release packaging:** `package-installer.sh` publishes immutable releases beneath
`outputs/server/series-2/releases/0.<rev>/` and a series-scoped `series-2/latest.json`. Each release has
`release.json`, two platform ZIPs and their `.sha256` sidecars. Each ZIP contains its installer and
library and verifier, a complete `corpusfm.bundle` at the packaged `main` HEAD, a digest-covered
installer runtime, `READ-ME-FIRST.txt`, and `installer-manifest.json`. The per-ZIP descriptor inventories
the payload through a descriptor-hashed `installer-files.sha256`; `release.json` inventories the
completed ZIPs, avoiding any circular claim that a ZIP contains its own digest. Each packaged
installer validates that descriptor and every payload digest before classification or lifecycle
work, materializes the exact adjacent `corpusfm.bundle` without a repository download, and carries
the verified series/version identity into its displayed plan. No repository credential is installed;
the later privileged update channel fetches the public origin anonymously. The published
installation manifest records that installer identity separately from the application build:
schema 2 carries `series`, installer `version`, bundle protocol, and whether the source was a
verified `package` or a `development` checkout. Schema 1 remains readable application history but
has no installer route. Later installers advance a schema-2 record only within its published series.
An ordinary installer refuses a cross-series change because that authority belongs exclusively to a
designated incoming bridge.
A direct checkout has no release descriptor, says so, and records an explicitly non-package
development identity. Existing release
directories are never overwritten. The ordinary bare installer may still self-clone. A recognized
Series 1 installation refuses before ordinary install work begins. The distribution exposes no
standalone uninstaller.

**The signing seam (packet 1380-04):** a signed Windows release cannot be built in one pass, because
the signer is an external, manually dispatched workflow and signing an earlier representation and then
rewriting it is forbidden. `package-installer.sh` therefore pauses in the middle. With
`--stage-signing-candidate DIR` it materializes every final member
plus the 11-occurrence Windows signing inventory, and stops before anything is archived. With
`--finalize-signing-candidate DIR [--signed-members DIR]` it adopts the signed byte streams and only
then builds the nested runtime archive, payload digest file, descriptor, outer ZIP, sidecar,
`release.json` and `latest.json`. With neither flag it runs both halves against a temporary
candidate, which is the ordinary unsigned development build, so the local path rehearses the released
one instead of being a second implementation of it. `installer/windows_signing.py` owns the
inventory: 11 distributed occurrences over 10 distinct streams (the outer `_cfm_lib.ps1` and the
nested runtime's copy are one library, signed once and placed in both positions), the completeness
check that refuses any PowerShell in the Windows package the inventory does not name, the adoption
check that refuses a body altered outside its signature block, and the final pass that reopens the
finished archives and proves each occurrence carries the bytes that were signed. The Linux peer is
built by the same run and is deliberately unsigned.

**Stable bootstrap handoff:** the public release publishes no standalone bootstrap outside its ZIPs
(decision D14); each package carries the bootstrap in its runtime archive and the installer installs
it as the durable entry point. A bootstrap accepts either an
exact local ZIP plus sidecar or an HTTPS distribution base, selects `latest.json` only inside the
explicit/published compatibility series, verifies the release inventory, ZIP digest and packaged
descriptor, then creates one protected, one-use `.bootstrap-handoff.json` in the extracted bundle.
The handoff contains installer/application identity, protocols, ZIP digest, consent mode, transcript
and nonce; it contains no password, PAT, repository/ref or caller-selected executable. Both
installers validate its canonical location, protection, descriptor agreement, consent and
transcript, delete it, and only then enter their ordinary orchestration. Direct bundle execution
remains supported until live bootstrap runs prove the new entry point on both platforms. A
schema-1 published installation is retired and has no bootstrap route; an ordinary bootstrap never
crosses series.

---

## 4. Justified tool divergences (parity does NOT mean identical tools)

### FileMaker-owned web-front lifecycle

**FileMaker Server owns the web-server process. Never start, stop, restart, reload, or signal its
nginx/Apache process or an apparent OS service directly, except for the one Windows capability
described below.** On Linux, every web-front lifecycle action
must go through the verb/object combination that the installed `fmsadmin help` declares. The
deployed FMS build declares `HTTPSERVER` for `START`, `STOP`, and `RESTART`; activation normally uses
the shared `fmsadmin restart httpserver` operation. Error 10007 (`Requested object does not exist`)
from a declared verb means the running FMS deployment has no corresponding object available; it is
not evidence that direct nginx/Apache control is permitted. In particular, do not use `nginx -s`,
signals, `pkill`, or `systemctl` against nginx/Apache even when FMS is running a distribution binary from `/usr/sbin` and
the distribution's own service appears inactive. FMS is the supervisor; bypassing it can leave the
web front down or out of agreement with FMS. On Windows, direct installation evidence established
that the optional Claris front has no working Admin API lifecycle verb, while its own nginx supports
a configuration reload. The installer-owned proxy executor therefore has one narrow exception:
for an independently observed active Claris front, `publish-active` and `remove-active` atomically
write only CORPUSfm's marked include family, run `nginx -t`, and issue `nginx -s reload` using the
executable, prefix and main configuration derived beneath the verified FMS root. A validation or
reload failure restores the prior family byte-exactly and reloads it; a failed restorative reload
retains recovery evidence and refuses. No caller-selected executable or general lifecycle verb is
accepted.

Read-only inspection of configuration, `/proc`, listeners, and a non-activating syntax validation is
permitted. Publication and validation do not grant activation authority: the executor writes and
validates, while the lifecycle engine selects the platform's one bounded activation operation. On
Linux that is the supported `fmsadmin` action. On Windows, IIS publication is its own activation
path; an active optional Claris front uses the exact executor transaction above rather than treating
`fmsadmin restart httpserver` as a Windows-nginx control.

| Concern | Linux | Windows | Why the tool differs |
|---|---|---|---|
| Service manager | systemd units | WinSW services | OS-native process supervision |
| Reverse proxy | nginx — FMS **owns** it; edit FMS's config in place (re-applied on FMS upgrade) | default IIS = **isolated IIS application(s)** in our own `web.config` (never FMS's shared rewrite); optional Claris **nginx** front (`Use Nginx Web Server`, FMS 2025+) = one **`###CORPUSFM` marked include** in the unique 443 server block. An inactive Claris front uses the ordinary byte-safe publish/remove transaction. An active Claris front uses only the executor's explicit active verbs, which bind write → parse → reload and byte-exact restore → restorative reload into one refusal-capable transaction. | FMS bundles nginx (Linux always; Windows optional from FMS 2025). Windows default is the OS's IIS; editing IIS's *shared* rewrite config breaks FMS `/fmi/` (500.50), so under nginx the narrow marked-include is the sanctioned managed-config exception (packet 1176 proved no vendor drop-in exists). |
| Python delivery | system `python3` + venv | **embeddable Python ZIP** (no venv) | the Windows MSI installer leaves machine-wide registration a file-delete can't undo → reinstall trap; embeddable = extract-and-delete, always clean |
| Privilege | `sudo` helper scripts + sudoers | service account / ACLs | no `sudo` on Windows |
| Web-server reload | `fmsadmin restart httpserver` | IIS publication needs no reload. Active Claris nginx uses only the bounded installer-owned `nginx -t` then `nginx -s reload` transaction above; inactive Claris publication performs no reload. | the isolated IIS app applies without restarting FMS; Windows Claris has no working Admin API lifecycle verb on the observed FMS release, so the exact FMS-owned nginx process is reloaded without exposing general process control |

| Deleting the hosted storage DB on uninstall | Request the exact recorded database close, wait until the Admin API reports runtime status `CLOSED`, then re-read the database registry. A matching `CLOSED` row is expected and proves the registration is not serving; an absent row also passes. Any open/transitional/unknown/unreadable result retains the file. | close, then **poll-delete for ~120s** until the OS lock clears, nudging with `fmsadmin remove`; report honestly if still locked | **The OS gives Windows a backstop Linux does not have** (packet 1237). Windows polls because `Remove-Item` *fails* while FMS holds the `.fmp12` lock — that failure is the signal, and it also means a genuinely failed close cannot delete a live database. Linux has **no mandatory locking**: `rm -f` on a file FMS still has open always succeeds, so the Admin API's `CLOSED` observation is load-bearing. FileMaker keeps closed databases in its registry, so disappearance from the list is not required and presence alone is not an open/hosted verdict. The exact recorded file is removed only after the close request succeeds, the asynchronous close reaches `CLOSED`, and the immediate read-back is `CLOSED` or absent. |

Rule: a new divergence is allowed only if it (a) keeps every §2 contract and (b) is recorded here
with its justification.

---

## 5. Validation harness (the parity enforcer)

Each platform ships a scripted **install → idempotent upgrade → uninstall → reinstall-from-scratch**
cycle that asserts the §2 contracts and FMS coexistence at each step. Parity is proven by *both*
harnesses asserting the *same* contracts — not by reading the scripts.

**Three guard layers (packet 019 — keep all three current with each lesson):**
- **Static contract tests** — fast, always: `tests/test_installer_*` assert anonymous public source
  authority and no persistent source credential, first-admin, **output-warning**
  (FMS-restart / data-removal / creds-transient stay visible), path/parity (fixed `/opt/CORPUSfm`,
  `--fms-root`, Windows `-InstallRoot/-ConfigHome/-FmsRoot`, ASCII-only `.ps1`), and §1–§10 contracts.
- **Simulation tests** — `tests/installer_sim/` + `tests/test_installer_sim.py`: prove decision paths
  against fake commands without a live box (public source reconciliation and first-admin password
  via environment rather than argv).
- **Live release gate** — `scripts/installer_release_gate.py` + `docs/installer-release-gate.md`: the
  repeatable fresh-install → anonymous public source + health → clean-uninstall proof on both boxes, fixed 11-section
  report. **Validate-before-tag**: never cut a release until this passes on both, from the built bundle.

A future `detect/build/render/apply/verify/report` refactor of the procedural scripts is planned but
**not started** — no domain is refactored without its
static + simulation + live-gate coverage already green.

---

## 6. Adding a platform (the checklist)

1. Implement the §1 spine in the platform's idiom.
2. Satisfy every §2 contract exactly.
3. Provide every **universal** §3 flag (native spelling); document any platform-only flags.
4. For each tool choice that differs, add a justified row to §4.
5. Ship the §5 validation cycle; it must go green incl. FMS coexistence.
6. Update `installer/README.md` (operational) — keep naming hygiene per the disclosure policy.
