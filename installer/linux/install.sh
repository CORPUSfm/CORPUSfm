#!/usr/bin/env bash
# CORPUSfm Server — Install / Upgrade Script
# Supported: Ubuntu Server 20.04, 22.04, 24.04 LTS
#
# Run as root from the repo root, or from anywhere — the script locates
# the repo relative to its own path.
#
# Usage:
#   sudo ./installer/linux/install.sh [OPTIONS]
#
# Options (parent 1246-04 §4H.1 — ten switches, nine semantic groups; the same set on Windows):
#   --install-dir DIR           Installation directory (default: /opt/CORPUSfm)
#   --patch-hosting-dir DIR     CORPUSfm patch hosting folder (default: <install-dir>-Hosted)
#   --fms-root DIR              FileMaker Server install root (default /opt/FileMaker/FileMaker Server);
#                               the storage DB directory is derived from it
#   --proxy-policy-add TYPE     Manage this reverse-proxy front (repeatable; TYPE or 'all')
#   --proxy-policy-ignore TYPE  Leave this reverse-proxy front alone (repeatable; TYPE or 'all')
#   --repair-storage-access     Repair automation access to an existing storage database
#   --replace-existing-install  Authorize moving an existing, non-empty install directory that
#                               carries no CORPUSfm installation trace
#   --yes                       Consent pre-granted; skip the confirmation wait (normal output)
#   --silent                    Non-interactive: inputs from the environment, fail loud on a missing
#                               required input
#   -v, --verbose               Stream full command output to the console. Concise by default — the
#                               detail always goes to /var/log/corpusfm/install-<timestamp>.log, and
#                               a failure prints the log path
#
# CREDENTIALS ARE NEVER PASSED AS OPTIONS. Supply them in the environment:
#   FM_ADMIN_USER / FM_ADMIN_PASS            FileMaker Server administrator
#   CORPUSFM_ADMIN_USER / CORPUSFM_ADMIN_PASS  first CORPUSfm web administrator (fresh install)
# A password on a command line is visible in the process table and in shell history; the installer
# reads these from the environment, copies them into shell variables, and unexports them before any
# child process runs.
#
# RETIRED, and REJECTED as unknown options — not aliased, not ignored:
#   --port  --no-pull  --ref  --allow-dirty  --enable-mcp  --no-mcp  --no-scheduler  --mcp-port
#   --mcp-host  --mcp-loopback  --mcp-token  --mcp-lan-subnet  --fm-admin-user  --fm-admin-pass
#   --admin-user  --admin-pass  --git-pat  --assume-yes
# The loopback port and the /corpusfm mount are implementation constants published by the
# installation manifest; MCP and the scheduler always install; there is no version, branch or
# rollback choice; and no credential travels in argv. (--hosting-dir was RENAMED to
# --patch-hosting-dir; --install-dir is new.)
#
# Upgrade: acquire and run a current verified Series 2 package. An existing installation is detected
# automatically, and the package advances it only to the exact application commit it carries.
#
# Updates button: the installer wires src/ as a protected checkout whose fixed privileged updater
# fetches the public origin anonymously, then applies an exact consented fast-forward. No source
# credential or deploy key is generated. No flags are needed.
# A git clone is the ONLY supported source (the dist-tarball/rsync path was retired —
# a non-git source fails loudly).
#
# Code-only updates may use the in-app Updates button; installation changes require a new package.

set -euo pipefail
# The deployed checkout is root-owned executable code, not a Python bytecode cache. Every installer
# Python child inherits this; the unprivileged services cannot write the tree after ownership is set.
export PYTHONDONTWRITEBYTECODE=1

# Keep the invocation intact across the root re-exec.  Argument parsing below consumes "$@";
# without this copy a non-root invocation silently lost every selected location at sudo.
ORIGINAL_ARGS=("$@")

# Logging begins before argument parsing, location selection, clock diagnosis and source
# acquisition. Those observations are part of the installation result, and an installer that exits
# before the ten-section ceremony still owes a durable record. The shared library may not exist yet
# on the supported bare-install.sh path, so this narrow early capture uses only Bash + tee. Once the
# package/library is available, cfm_early_log_finish restores the original streams and the ordinary
# timestamped primitives continue in the SAME CFM_LOG.
if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "${ORIGINAL_ARGS[@]}"
fi
CFM_LOG="${CFM_LOG:-/var/log/corpusfm/install-$(date +%Y%m%d-%H%M%S).log}"
mkdir -p /var/log/corpusfm
touch "$CFM_LOG"
chmod 640 "$CFM_LOG"
export CFM_LOG
printf '%s  === early transcript opened (pid=%s) ===\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" >>"$CFM_LOG"
exec 3>&1 4>&2
exec > >(tee -a -- "$CFM_LOG" >&3) 2> >(tee -a -- "$CFM_LOG" >&4)
CFM_EARLY_CAPTURE_ACTIVE=true
cfm_early_log_finish() {
    $CFM_EARLY_CAPTURE_ACTIVE || return 0
    exec 1>&3 2>&4
    exec 3>&- 4>&-
    wait || true
    CFM_EARLY_CAPTURE_ACTIVE=false
}

# ── Paths ───────────────────────────────────────────────────────────────────────
INSTALL_DIR=/opt/CORPUSfm
INSTALL_DIR_EXPLICIT=false
# The installer-owned asset tree, a fixed SIBLING of the Git checkout inside the install root:
# `<install root>/assets/{db,addon}`. The application derives the same location from the published
# install root (`app_paths.ASSETS_DIRNAME`); this name and that constant must agree. It is not a
# selectable location — there is no flag — because a second configurable path is a second place for
# an installation to disagree with itself.
CFM_ASSETS_DIRNAME=assets
CFM_ASSETS_PAYLOAD_SHA256=""
SERVICE_USER=corpusfm
# The account FileMaker Server itself runs as. Named because the patch-compartment request states
# BOTH identities — ours and FMS's — so it can decide who may host from the compartment; every
# `chown fmserver:fmsadmin` below is the same fact spelled a second time.
FMS_SERVICE_USER=fmserver
# CO-LOCATED IS THE ONLY SHIPPED DEPLOYMENT, so the FileMaker host the provider verbs reach is this
# machine. It is not an option: an install that had to be told where its own FileMaker Server is
# would not be co-located.
CFM_FMS_HOST=localhost
# The proxy fronts a LINUX box can present, from `proxy_inventory.inventory()`: `iis` and
# `claris-nginx` are answered `Windows-only front` there, so naming them here would ask this box
# about fronts it structurally cannot have. `all` is a PUBLIC selector and is never a request value.
CFM_PROXY_TYPES=(fms-nginx apache)
WEB_SERVICE=corpusfm
MCP_SERVICE=corpusfm-mcp
SCHED_SERVICE=corpusfm-scheduler
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFM_INSTALLER_SERIES=""
CFM_INSTALLER_VERSION=""
CFM_PACKAGE_APPLICATION_VERSION=""
CFM_PACKAGE_COMMIT=""
CFM_HANDOFF_CONSENT=""
if [[ -f "$SCRIPT_DIR/installer-manifest.json" ]]; then
    _bundle_verifier="$SCRIPT_DIR/cfm-verify-installer-bundle.sh"
    [[ -f "$_bundle_verifier" ]] || {
        printf '  x Installer bundle refused: cfm-verify-installer-bundle.sh is missing\n' >&2
        exit 2
    }
    _bundle_identity="$(bash "$_bundle_verifier" "$SCRIPT_DIR")" || exit $?
    IFS=$'\t' read -r CFM_INSTALLER_SERIES CFM_INSTALLER_VERSION \
        CFM_PACKAGE_APPLICATION_VERSION CFM_PACKAGE_COMMIT <<<"$_bundle_identity"
    [[ -n "$CFM_INSTALLER_SERIES" && -n "$CFM_INSTALLER_VERSION" \
       && -n "$CFM_PACKAGE_APPLICATION_VERSION" && -n "$CFM_PACKAGE_COMMIT" ]] || {
        printf '  x Installer bundle refused: verifier returned an incomplete identity\n' >&2
        exit 2
    }
    printf '  + Installer bundle verified: %s / %s / %s\n' \
        "$CFM_INSTALLER_SERIES" "$CFM_INSTALLER_VERSION" "${CFM_PACKAGE_COMMIT:0:12}"
fi
if [[ -n "${CFM_BOOTSTRAP_HANDOFF:-}" ]]; then
    [[ -n "$CFM_INSTALLER_SERIES" ]] || {
        printf '  x Bootstrap handoff refused: delegated execution requires a packaged installer\n' >&2
        exit 2
    }
    _handoff_verifier="$SCRIPT_DIR/cfm-verify-bootstrap-handoff.sh"
    [[ -x "$_handoff_verifier" ]] || {
        printf '  x Bootstrap handoff refused: verifier is missing or not executable\n' >&2
        exit 2
    }
    _handoff_identity="$(bash "$_handoff_verifier" "$CFM_BOOTSTRAP_HANDOFF" "$SCRIPT_DIR")" \
        || exit $?
    IFS=$'\t' read -r _handoff_series _handoff_version _handoff_app _handoff_commit \
        _handoff_transcript CFM_HANDOFF_CONSENT <<<"$_handoff_identity"
    [[ "$_handoff_series" == "$CFM_INSTALLER_SERIES" \
       && "$_handoff_version" == "$CFM_INSTALLER_VERSION" \
       && "$_handoff_app" == "$CFM_PACKAGE_APPLICATION_VERSION" \
       && "$_handoff_commit" == "$CFM_PACKAGE_COMMIT" ]] || {
        printf '  x Bootstrap handoff refused: handoff and verified bundle identities disagree\n' >&2
        exit 2
    }
    [[ "${CFM_LOG:-}" == "$_handoff_transcript" ]] || {
        printf '  x Bootstrap handoff refused: transcript continuity disagrees\n' >&2
        exit 2
    }
fi
# install.sh lives at installer/linux/, so the repo root is TWO levels up. (One level was a reorg
# regression: it made REPO_DIR=installer/, so the package check failed → every run self-bootstrapped
# a temp clone, the in-place self-pull condition `REPO_DIR == $INSTALL_DIR/src` never matched, and an
# upgrade run silently never advanced the deployed checkout — it ran on stale code.)
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFM_RUNTIME_TMP=""
BOOT_CLONE=""
CFM_RUNTIME_ROOT="$REPO_DIR"
if [[ -n "$CFM_INSTALLER_SERIES" ]]; then
    _runtime_archive="$SCRIPT_DIR/installer-runtime.zip"
    [[ -f "$_runtime_archive" ]] || {
        printf '  x Installer bundle refused: installer-runtime.zip is missing\n' >&2
        exit 2
    }
    command -v unzip >/dev/null 2>&1 || {
        printf '  x Installer bundle refused: unzip is required to open its protected runtime\n' >&2
        exit 2
    }
    CFM_RUNTIME_TMP="$(mktemp -d)"
    unzip -q "$_runtime_archive" -d "$CFM_RUNTIME_TMP" || {
        rm -rf "$CFM_RUNTIME_TMP"
        printf '  x Installer bundle refused: protected runtime extraction failed\n' >&2
        exit 2
    }
    CFM_RUNTIME_ROOT="$CFM_RUNTIME_TMP"
fi
trap '[[ -z "$CFM_RUNTIME_TMP" ]] || rm -rf "$CFM_RUNTIME_TMP" 2>/dev/null || true' EXIT

# Series 1 is retired. Its exact final payload is held under retired/series-1 for historical custody,
# never as an executable migration path in a Series 2 package.
LEGACY_1246_MARKER=/opt/CORPUSfm/.corpusfm/install.yaml
CURRENT_MANIFEST=/opt/CORPUSfm/manifest/installation.json
if [[ -f "$LEGACY_1246_MARKER" && ! -f "$CURRENT_MANIFEST" ]]; then
    printf '  x Series 1 installation detected. Series 2 has no in-place legacy takeover; uninstall the old installation before running this package.\n' >&2
    exit 2
fi
# Canonical source authority for the installed checkout and privileged updater.
REPO_URL="https://github.com/CORPUSfm/CORPUSfm.git"
# FMS Databases dir. The storage DB lives in a dedicated CORPUSfm/ SUBFOLDER
# (FMS auto-scans subfolders + hosts by name; top-level honored for legacy pre-subfolder installs).
# FMS install root. Linux FMS installs to a FIXED /opt/FileMaker/FileMaker Server (unlike Windows,
# which is drive/dir-configurable), so this is normally an invariant — but --fms-root / FMS_ROOT
# overrides it for a non-standard FMS location (the DB dir is derived from it). `fmsadmin` itself is
# invoked via PATH (the FMS installer puts it there); add it to PATH if your FMS is non-standard.
[[ -n "${FMS_ROOT+x}" ]] && FMS_ROOT_EXPLICIT=true || FMS_ROOT_EXPLICIT=false
FMS_ROOT="${FMS_ROOT:-/opt/FileMaker/FileMaker Server}"
FM_DB_DIR="$FMS_ROOT/Data/Databases"
# The storage database's name, stated once for the key-provisioning corpus proof. The rest of
# this script still spells it inline at its fifteen other sites; naming it here is not a
# refactor, it is the one place a NAME has to be data rather than prose.
FM_DATABASE="CORPUSfm_DB"

# ── Bundled Python (CORPUSfm ships its own CPython — no distro-Python dependency) ──
# python-build-standalone (astral-sh) install_only tarballs = PGO+LTO-optimized normal CPython,
# relocatable + manylinux-compatible. Everything is PINNED (exact version + release tag + SHA256);
# "latest" is never fetched. A future version bump = re-pin these three + regenerate the Linux lock.
# NOT free-threaded/no-GIL, NOT the experimental JIT — the standard optimized build.
PY_FULL="3.13.14"            # pinned CPython
PY_PBS_TAG="20260623"        # pinned python-build-standalone release
PY_BASE="$INSTALL_DIR/python"
PY_HOME="$PY_BASE/$PY_FULL"  # VERSIONED dir → a built venv references a STABLE path across bumps
PY_BUNDLED="$PY_HOME/bin/python3"
# Arch-specific pinned asset + SHA256 (FMS 2024 Linux matrix = AMD64/ARM64).
case "$(uname -m)" in
    x86_64|amd64)  PY_ARCH="x86_64";  PY_SHA256="7fd02919461b368adafea3896ad082f5c4f759816d69681dcc6559bfbcd892af" ;;
    aarch64|arm64) PY_ARCH="aarch64"; PY_SHA256="1199b22c83725a339ebaef36d39476d037fb7267187513090b6cc83bb4579477" ;;
    *)             PY_ARCH="";        PY_SHA256="" ;;
esac
PY_ASSET="cpython-${PY_FULL}+${PY_PBS_TAG}-${PY_ARCH}-unknown-linux-gnu-install_only.tar.gz"
PY_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PY_PBS_TAG}/${PY_ASSET}"

# ── Defaults ────────────────────────────────────────────────────────────────────
# Web runs loopback-only behind the FMS web server at WEB_PREFIX (the co-located
# deployment). 8533 is a distinctive loopback port (off the old public 8501).
WEB_PORT=8533
WEB_PREFIX=/corpusfm
# CORPUSfm hosting folder (packet 1061): the formal, install-configurable FMS Additional Database
# Folder that hosts generated .fmp12 files IN PLACE. NOT hardcoded — --hosting-dir / HOSTING_DIR env
# override it (a client whose FMS lives on another volume points it there). Default is a TOP-LEVEL,
# clearly-named sibling of the install dir (${INSTALL_DIR}-Hosted) — deliberately OUTSIDE $INSTALL_DIR
# so `rm -rf $INSTALL_DIR` on uninstall never touches user-generated databases (the preserve rule).
# Provisioned corpusfm:fmsadmin 2775 (setgid) so fmserver can host from it R/W + write its own
# RC_Data_FMS bookkeeping. Enabling the FMS additional-folder slot is a GUIDED-MANUAL Console step (no
# Admin-API endpoint exists — box-probed).
[[ -n "${HOSTING_DIR+x}" ]] && HOSTING_DIR_EXPLICIT=1 || HOSTING_DIR_EXPLICIT=""
HOSTING_DIR="${HOSTING_DIR:-${INSTALL_DIR}-Hosted}"
# MCP and the scheduler ALWAYS install (§4H.2). These stay as CONSTANTS because the sections below
# still read them; what is gone is every flag that could set them. There is no opt-out to express.
ENABLE_MCP=true
ENABLE_SCHEDULER=true
MCP_PORT=8765
MCP_HOST=0.0.0.0      # LAN-reachable (co-located, MCP-centric product) — auto-token + UFW-scoped
MCP_LAN_SUBNET=""     # scope the UFW rule to a subnet instead of opening the port to all
# §4H.1 — the four NEW switches. Declared here because `set -u` is on and the parser appends to the
# two arrays before anything else could create them.
# The definitions phase 20 installed and READ BACK. Phase 21 starts exactly this set — it is the
# mechanism behind "identity, not merely order".
VERIFIED_UNITS=()
PROXY_POLICY_ADD=()
PROXY_POLICY_IGNORE=()
REPAIR_STORAGE_ACCESS=false      # --repair-storage-access: the one bounded repair mode
REPLACE_EXISTING_INSTALL=false   # --replace-existing-install: authorize moving an unrecognized dir
SILENT=false          # --silent: non-interactive (inputs from flags/env; fail loud on missing required input)
ASSUME_YES=false      # --yes/--assume-yes: skip the pre-install confirmation prompt (keep normal output). Was referenced at the confirm gate but never defaulted (085) → `set -u` aborted a non-silent fresh install.
VERBOSE=false         # --verbose/-v: stream full command output (pip/git/download/diagnostics) to the console too
#                       (concise by default — that detail always goes to the install-log transcript regardless)
# FM admin creds may also be supplied via the FM_ADMIN_USER / FM_ADMIN_PASS environment.
FM_ADMIN_USER="${FM_ADMIN_USER:-}"
_CFM_FM_PASS_IN="${FM_ADMIN_PASS:-}"
# UNEXPORT IT IMMEDIATELY (packet 1236, finding 4). The value is copied into this shell variable
# above; leaving the ENVIRONMENT entry in place means every child inherits the FM administrator
# password — apt-get, git, and pip, which runs third-party package code — for most of the install.
# The old code did not clear it until well after all of those had run.
#
# This is not a nicety: SPEC S4 says credentials are "used transiently, never stored", and packet 1234
# now tells the operator so at the prompt. A variable inherited by pip is not transient in the sense
# the operator will hear. The narrow re-export around the one child that needs it (the PKI step) is
# the correct pattern and stays; it was the BROAD window that was the defect.
unset FM_ADMIN_PASS
FM_ADMIN_PASS="${_CFM_FM_PASS_IN:-}"
# The FIRST CORPUSfm WEB admin (named-user login) — distinct from the FM Server admin above. The
# browser no longer creates the first account, so a fresh install creates it here. Via flags
# (--admin-user/--admin-pass) or env (CORPUSFM_ADMIN_USER/CORPUSFM_ADMIN_PASS); else prompted.
CFM_ADMIN_USER="${CORPUSFM_ADMIN_USER:-}"
CFM_ADMIN_PASS="${CORPUSFM_ADMIN_PASS:-}"
CFM_BUILD_VERSION=""
CFM_BUILD_COMMIT=""

# git-deploy is AUTOMATIC when installing from a git clone (vs a dist tarball): src/
# becomes a service-user-owned checkout so the in-app Updates button (git pull) works.
# No flags — the installer detects the clone and wires it. The pull credential is the
# anonymous HTTPS against the public repository; no source credential or SSH deploy key.
# The tracked branch is `main` and forward-only; there is no channel, tag or SHA to choose (§4H.2),
# so this is a CONSTANT the git-checkout blocks read, not an input.
GIT_TRACKED_BRANCH="main"
# Public acquisition is anonymous. Retired private-era credential files are removed when a
# published installation is reconciled; no token input or credential helper remains.

# ── Output ──────────────────────────────────────────────────────────────────────
# Output primitives (hello/info/ok/warn/die) + the cfm_section/step runners come from the shared
# library (_cfm_lib.sh), sourced below. These raw color vars remain only for the few raw printf/echo
# lines that run in the PRE-CEREMONY block (before the library is guaranteed loaded) and for the
# decorative banner rules in the body.
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

# Restart the web service, clearing any prior start-rate-limit FIRST. A deploy can restart the
# service more than once (units section + proxy section), and repeated installs in a short window
# accumulate starts — with the unit's StartLimitBurst that otherwise trips "start-limit-hit" and
# `set -e` aborts the install mid-way. reset-failed zeroes the counter so the restart always runs.
# RESTART, never START (developer direction 2026-08-03). `systemctl restart` starts a stopped unit,
# so on a fresh install this would have started a service against an unpublished legacy layout --
# the one thing the ruling forbids outright. Guarded on "already running", which is the only case a
# NO PRE-PHASE-21 START PATH EXISTS (packet 1246-04-03). `restart_web` lived here and was the
# last way a service could come up before phase 21 — it survived from a design in which a
# LAYOUT CUTOVER owned the transition. Phase 9 quiesces; phase 21 starts the verified set;
# nothing in between may start or restart anything, directly or through a helper.


# ── Shared library (defensive source) ─────────────────────────────────────────────
# Source the SS1-SS10 contract library when it's beside us (the normal case: a git clone or the
# release ZIP ships install.sh + _cfm_lib.sh together). The bare-installer path
# (install.sh run ALONE) self-clones below and re-sources from the fresh clone there.
# shellcheck source=installer/linux/_cfm_lib.sh
# shellcheck disable=SC1091
[ -f "$SCRIPT_DIR/_cfm_lib.sh" ] && source "$SCRIPT_DIR/_cfm_lib.sh"

# ── Lifecycle composition helpers (packet 1246-04-03) ───────────────────────────
# Every lifecycle verb reads a ROOT-OWNED request file. Requests are written under a mode-0700
# directory with umask 077 and REMOVED when the invocation ends: a request may name an installation
# and an operation, and it must never name a credential (§6). The provider CLIs read secrets from
# their own authorities, not from what the installer hands them.
LC_REQ_DIR="/run/corpusfm-lifecycle.$$"
# TWO defects, both measured on fms-server 2026-08-08, and each alone aborts every install.
#
# 1. PYTHONPATH. `corpusfm` is NOT installed into the venv — no pip install -e, no .pth — so every
#    invocation in this file makes it importable with PYTHONPATH="$INSTALL_DIR/src". This array was
#    the ONE exception, and the omission was invisible because `export PYTHONPATH` at the CLI-wrapper
#    heredoc below LOOKS like a shell-level export and is a line of the GENERATED wrapper.
#
# 2. The module. It was `-m corpusfm.lifecycle.cli`, and `cli.py` has NO `if __name__ == "__main__"`
#    guard — so Python imported it as __main__, called nothing, and exited 0 with no output. That is
#    exactly the "`corpusfm-lifecycle status --json` produced no output (exit 0)" this installer
#    reported before aborting. The runnable entry point is the PACKAGE, `-m corpusfm.lifecycle`,
#    whose __main__.py calls cli.main().
#
# Fixing only the first would have produced a silent exit 0 instead of a loud ImportError — a
# quieter failure, not a working install.
CFM_LIFECYCLE=(env "PYTHONPATH=$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" -m corpusfm.lifecycle)
LC_RUNTIME_KIND=installed
LC_RUNTIME_PY="$INSTALL_DIR/venv/bin/python"
LC_RUNTIME_SOURCE="$INSTALL_DIR/src"
INSTALLATION_ID=""
CFM_GENERATION=0
#: Set by phase 18 when storage composed `first_administrator_owed`. Declared here so phase 19 can
#: read it on every path, including one that never reaches phase 18's fresh branch.
CFM_FIRST_ADMIN_OWED=false

# An update records exactly which CURRENT services it quiesced.  A refusal that leaves no recovery
# owed must not turn an otherwise-working collaborator box into an outage; conversely an unresolved
# lifecycle operation or a half-replaced runtime must stay stopped.  These flags make that boundary
# explicit and keep the original installer failure authoritative if a best-effort restart also fails.
QUIESCED_ACTIVE_UNITS=()
QUIESCE_RESTORE_ARMED=false
QUIESCE_RESTORE_READY=false
LEAVE_SERVICES_STOPPED=false
PHASE21_OWNS_START=false
LEAVE_SERVICES_STOPPED_FILE="$LC_REQ_DIR/leave-services-stopped"

lc_cleanup() {
    rm -rf "$LC_REQ_DIR" 2>/dev/null || true
    [[ -z "${CFM_RUNTIME_TMP:-}" ]] || rm -rf "$CFM_RUNTIME_TMP" 2>/dev/null || true
    [[ -z "${BOOT_CLONE:-}" ]] || rm -rf "$BOOT_CLONE" 2>/dev/null || true
}
lc_journal_is_resolved() {
    local journal="$1"
    "$INSTALL_DIR/venv/bin/python" - "$journal" <<'PY' >/dev/null 2>&1
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
if not isinstance(value, dict) or value.get("state") != "resolved":
    raise SystemExit(1)
PY
}
lc_exit() {
    local rc=$? unit journal="${CFM_STATE_DIR:-/var/lib/corpusfm/state}/lifecycle-journal.json"
    local leave_stopped="$LEAVE_SERVICES_STOPPED"
    trap - EXIT
    set +e
    [[ -f "$LEAVE_SERVICES_STOPPED_FILE" ]] && leave_stopped=true
    lc_cleanup
    if [[ "$rc" -ne 0 ]] && $QUIESCE_RESTORE_ARMED && $QUIESCE_RESTORE_READY \
       && ! $leave_stopped && ! $PHASE21_OWNS_START; then
        # A present record is safe to restart over only when it says RESOLVED.  Missing means no
        # lifecycle work is owed; unreadable/open/checkpointed/needs_recovery stays stopped.
        if [[ -f "$journal" ]] && ! lc_journal_is_resolved "$journal"; then
            warn "The update failed with lifecycle recovery still owed; previously active services remain stopped."
        else
            for unit in "${QUIESCED_ACTIVE_UNITS[@]}"; do
                systemctl is-active --quiet "$unit" 2>/dev/null && continue
                if systemctl start "$unit"; then
                    warn "The update failed; restored previously active service $unit."
                else
                    warn "The update failed, and previously active service $unit could not be restored."
                fi
            done
        fi
    elif [[ "$rc" -ne 0 ]] && $QUIESCE_RESTORE_ARMED && ! $QUIESCE_RESTORE_READY \
         && ! $leave_stopped && ! $PHASE21_OWNS_START; then
        warn "The update failed while the runtime replacement was incomplete; services remain stopped."
    fi
    exit "$rc"
}
trap lc_exit EXIT

lc_request() {          # lc_request <name> <json>  → prints the path
    mkdir -p "$LC_REQ_DIR"; chmod 700 "$LC_REQ_DIR"
    local f="$LC_REQ_DIR/$1.json"
    ( umask 077; printf '%s' "$2" > "$f" )
    chown root:root "$f" 2>/dev/null || true
    printf '%s' "$f"
}

# Map a lifecycle exit code onto this installer's behaviour. The six result words and the codes are
# the shipped contract; 4 means the REQUEST was refused, which is our defect, never the box's.
lc_dispatch() {         # lc_dispatch <exit> <what>
    case "$1" in
        0) return 0 ;;
        1) die "$2 refused before changing anything (failed_before_change)." ;;
        2) die "$2 was rolled back; the installation is unchanged (rolled_back)." ;;
        3) LEAVE_SERVICES_STOPPED=true; : > "$LEAVE_SERVICES_STOPPED_FILE"; die "$2 needs an administrator action before the install can continue (manual_action_required)." ;;
        4) die "$2: the installer built a request this build does not accept — this is an installer defect." ;;
        5) LEAVE_SERVICES_STOPPED=true; : > "$LEAVE_SERVICES_STOPPED_FILE"; die "$2 stopped safely part-way (incomplete_safe). The services stay STOPPED. Re-run the installer to resume; do not start anything by hand." ;;
        *) die "$2 returned an unrecognised exit status $1." ;;
    esac
}

# Run a provider without flattening its structured result into an exit-code message. The shared
# application disposition boundary below interprets the complete result together with its journal.
LC_RAW_OUT=""; LC_RAW_RC=0
lc_run_raw() {          # lc_run_raw <verb...> --request <file>
    if $LC_FEED_CREDENTIAL; then
        LC_RAW_OUT="$(lc_fms_frame | "${CFM_LIFECYCLE[@]}" "$@" 2>&1)" \
            && LC_RAW_RC=0 || LC_RAW_RC=$?
    else
        LC_RAW_OUT="$("${CFM_LIFECYCLE[@]}" "$@" 2>&1)" && LC_RAW_RC=0 || LC_RAW_RC=$?
    fi
    printf '%s\n' "$LC_RAW_OUT" >> "$CFM_LOG" 2>/dev/null || true
}

# WHICH STORAGE VERB THIS INVOCATION MAY RUN, decided by the SHIPPED boundary from the phase-14
# OBSERVATION (correction C1). The installer chose the verb from the repair flag alone, so an
# ordinary update ran `bootstrap` with `mode=forward_update` — which `proven_fresh` rejects — and
# died at phase 18 with every service already stopped by phase 9.
lc_storage_route() {    # lc_storage_route <observation-json>  → prints bootstrap|repair|skip
    local out
    out="$(printf '%s' "$1" | PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" -c \
'import json, sys
from corpusfm.lifecycle.cli import storage_route_for_observation as route
try:
    payload = json.load(sys.stdin)
except ValueError as exc:
    sys.stderr.write("the storage observation is not readable JSON: %s\n" % exc)
    raise SystemExit(1)
verb, reason = route(payload, mode=sys.argv[1], repair_requested=(sys.argv[2] == "true"))
sys.stderr.write(reason + "\n")
if verb is None:
    raise SystemExit(1)
sys.stdout.write(verb)' \
        "$CFM_STORAGE_MODE" "$($REPAIR_STORAGE_ACCESS && echo true || echo false)" \
        2>>"$CFM_LOG")" \
        || die "storage cannot be routed from this machine's own observation — see $CFM_LOG for the
     state it reported. Nothing was changed."
    printf '%s' "$out"
}

# THE FMS CREDENTIAL FRAME (correction C3). `CredentialLease.from_frame` reads two length-prefixed
# UTF-8 fields — four-byte big-endian length, then bytes — and refuses on a short read, a trailing
# byte or an empty field. The installers already acquired and VERIFIED this account at phase 7, so
# asking the lifecycle layer to prompt for it again is asking a second time for something we hold —
# and `prompt` cannot be answered at all by a `--silent` run.
#
# The two values reach the frame generator on ITS OWN STDIN, never argv (a process list is world
# readable) and never the environment (inherited by every child). `set -o pipefail` is in force, so
# a frame that could not be produced fails the pipeline rather than handing the provider a truncated
# read that `from_frame` would then refuse for the wrong reason.
lc_fms_frame() {
    printf '%s\0%s' "$FM_ADMIN_USER" "$FM_ADMIN_PASS" \
        | "$LC_RUNTIME_PY" -c \
'import struct, sys
raw = sys.stdin.buffer.read()
account, sep, password = raw.partition(b"\0")
if not sep:
    sys.stderr.write("the credential pair was not separated\n")
    raise SystemExit(1)
out = sys.stdout.buffer
for field in (account, password):
    out.write(struct.pack(">I", len(field)))
    out.write(field)
out.flush()'
}

lc_resume_orphaned_uninstall() {  # terminal uninstall journal + package runtime -> one resume only
    local installation_id="$1" transport=prompt reqdir request out rc parsed result reason detail
    if $SILENT; then
        if [[ -n "$FM_ADMIN_USER" && -n "$FM_ADMIN_PASS" ]]; then transport=stdin
        else transport=none
        fi
    fi
    reqdir="$(mktemp -d /run/corpusfm-installer-uninstall-recovery.XXXXXX)"
    chmod 700 "$reqdir"
    request="$reqdir/request.json"
    ( umask 077; "$LC_RUNTIME_PY" - "$request" "$installation_id" "$transport" <<'PY'
import json, os, sys
path, installation_id, transport = sys.argv[1:]
payload = {"schema_version": 2, "installation_id": installation_id,
           "actor": os.environ.get("SUDO_USER") or "root", "force": False,
           "credential_transport": transport}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
    ) || { rm -rf "$reqdir"; die "Could not build the package-owned uninstall recovery request."; }
    chown root:root "$request" 2>/dev/null || true
    rc=0
    if [[ "$transport" == stdin ]]; then
        out="$(lc_fms_frame | "${CFM_LIFECYCLE[@]}" uninstall resume --request "$request")" || rc=$?
    else
        out="$("${CFM_LIFECYCLE[@]}" uninstall resume --request "$request")" || rc=$?
    fi
    printf '%s\n' "$out" >>"$CFM_LOG" 2>/dev/null || true
    parsed="$(printf '%s' "$out" | "$LC_RUNTIME_PY" -c '
import json, sys
raw=json.load(sys.stdin)
if not isinstance(raw, dict): raise SystemExit(1)
for key in ("result", "reason", "detail"): print(raw.get(key) or "")
')" || { rm -rf "$reqdir"; die "Uninstall recovery returned no readable result (exit $rc); its journal remains."; }
    rm -rf "$reqdir"
    result="$(printf '%s\n' "$parsed" | sed -n 1p)"
    reason="$(printf '%s\n' "$parsed" | sed -n 2p)"
    detail="$(printf '%s\n' "$parsed" | sed -n 3p)"
    case "$rc" in
        0) die "The interrupted uninstall recovery completed ($result). Re-run this Series 2
     package to begin a separate fresh installation invocation." ;;
        3|5) die "The interrupted uninstall remains safely resumable ($result; $reason).
     $detail
     Re-run this same verified Series 2 package; its recovery runtime will resume it again." ;;
        *) die "The interrupted uninstall recovery refused or failed (exit $rc; $result; $reason).
     $detail
     Its journal and recovery evidence remain untouched." ;;
    esac
}

# `stdin` when we hold a verified FMS administrator, `absent` when we do not. Never `prompt`: the
# value is already held, and a prompt in an unattended run is a hang rather than a refusal.
lc_fms_transport() {
    if [[ -n "${FM_ADMIN_PASS:-}" && -n "${FM_ADMIN_USER:-}" ]]; then printf 'stdin'
    else printf 'absent'; fi
}

#: Set true only around a verb that needs FMS authority; `lc_run` then feeds it the frame.
LC_FEED_CREDENTIAL=false

lc_run() {              # lc_run <what> <verb...> --request <file>
    local what="$1"; shift
    local out rc
    if $LC_FEED_CREDENTIAL; then
        out="$(lc_fms_frame | "${CFM_LIFECYCLE[@]}" "$@" 2>&1)" && rc=0 || rc=$?
    else
        out="$("${CFM_LIFECYCLE[@]}" "$@" 2>&1)" && rc=0 || rc=$?
    fi
    printf '%s\n' "$out" >> "$CFM_LOG" 2>/dev/null || true
    lc_dispatch "$rc" "$what"
    printf '%s' "$out"
}

lc_json_field() { printf '%s' "$1" | "$INSTALL_DIR/venv/bin/python" -c \
    'import json,sys;v=json.load(sys.stdin).get(sys.argv[1]);print("" if v is None else v)' \
    "$2" 2>/dev/null || true; }

# The same read, but for a STRUCTURED value. `lc_json_field` prints Python's repr of a dict, which is
# not JSON (single quotes, `True`) and cannot be pasted into the next request. Every provider returns
# its composed `candidate` as an object, so the commit needs this one.
lc_json_object() { printf '%s' "$1" | "$INSTALL_DIR/venv/bin/python" -c \
    'import json,sys;v=json.load(sys.stdin).get(sys.argv[1]);print("" if v is None else json.dumps(v))' \
    "$2" 2>/dev/null || true; }

# The OS locations, read from `lifecycle.os_layout` rather than restated here. `storage_dirs` and
# `protected_dirs` are the compartment's FORBIDDEN neighbours — a sandbox must not overlap the
# directories CORPUSfm keeps its own state and its own lifecycle records in — so a literal that
# drifts from the layout silently stops protecting the directory it names.
CFM_CONFIG_DIR=""; CFM_STATE_DIR=""; CFM_SECRETS_DIR=""; CFM_LOG_DIR=""; CFM_RUN_DIR=""
lc_load_os_layout() {
    local out
    out="$(PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" -c \
        'from corpusfm.lifecycle.os_layout import platform_os_layout as p
l = p()
print(l.config_dir); print(l.state_dir); print(l.secrets_dir); print(l.log_dir); print(l.run_dir)' \
        2>/dev/null)" || die "could not read this platform's OS layout."
    { read -r CFM_CONFIG_DIR; read -r CFM_STATE_DIR; read -r CFM_SECRETS_DIR
      read -r CFM_LOG_DIR;    read -r CFM_RUN_DIR; } <<< "$out"
    [[ -n "$CFM_SECRETS_DIR" && -n "$CFM_STATE_DIR" ]] \
        || die "the OS layout reported no secrets or state directory."
}

# A JSON array literal from the remaining arguments. Used for `types`, `storage_dirs` and
# `protected_dirs`, which the parsers require as real lists rather than strings.
lc_json_array() {
    local first=1 out="["
    for _v in "$@"; do
        [[ $first -eq 1 ]] && first=0 || out+=","
        out+="\"$_v\""
    done
    printf '%s]' "$out"
}

# Commit one provider, then verify its journal is resolved and discard it. The discard is REQUIRED,
# not tidy-up: storage answers foreign_open on the PRESENCE of any journal record, so a leftover one
# stops the NEXT provider before it starts.
#
# THE OPERATION ID AND THE CANDIDATE BOTH COME FROM THE PROVIDER (packet 1246-04-04, correction B).
# The installer used to mint a UUID, put it in the provider's request and then commit against it.
# No provider request schema accepts `operation_id` — the provider mints its own and returns it — so
# every one of those requests was refused, and the id the commit named was one nothing had ever
# used. `lc_provider_run` below is the only place either value is obtained.
lc_commit_provider() {  # lc_commit_provider <provider> <operation_id> <inspected_gen> <candidate-json>
    local prov="$1" op="$2" gen="$3" cand="$4" req out committed
    [[ -n "$op" ]]   || die "$prov returned no operation_id; refusing to invent one."
    [[ -n "$cand" && "$cand" != "null" ]] \
        || die "$prov composed no candidate; there is nothing to commit."
    req="$(lc_request "commit-$prov" "$(printf '{"schema_version":1,"provider":"%s","operation_id":"%s","installation_id":"%s","inspected_generation":%s,"candidate":%s,"install_dir":"%s","actor":"installer"}' \
        "$prov" "$op" "$INSTALLATION_ID" "$gen" "$cand" "$INSTALL_DIR")")"
    out="$(lc_run "$prov composition" composition commit-provider --request "$req")"
    committed="$(lc_json_field "$out" committed_generation)"
    [[ "$committed" == "$((gen + 1))" ]] \
        || die "$prov committed generation '$committed', expected $((gen + 1)) — refusing to continue."
    CFM_GENERATION="$committed"
    ok "$prov composed at generation $committed"
}

# Retire one provider's journal record through the shipped boundary. §4H.5 requires the discard and
# the installers CLAIMED it; until correction A there was no verb that performed one, so the claim
# was false and the next provider met a journal record its predecessor had left behind.
lc_discard_provider() {  # lc_discard_provider <provider> <operation_id> [installation_id]
    local prov="$1" op="$2" inst="${3:-$INSTALLATION_ID}" req
    [[ -n "$op" ]] || die "$prov returned no operation_id; its journal cannot be discarded."
    [[ -n "$inst" ]] || die "$prov journal names no installation identity; refusing to guess."
    if [[ "$prov" == proxy ]]; then
        req="$(lc_request "retire-$prov" "$(printf '{"schema_version":1,"operation_id":"%s","installation_id":"%s","actor":"installer"}' \
            "$op" "$inst")")"
        lc_run "$prov artifact retirement" proxy retire --request "$req" >/dev/null
        ok "$prov artifacts retired"
    fi
    req="$(lc_request "discard-$prov" "$(printf '{"schema_version":1,"provider":"%s","operation_id":"%s","installation_id":"%s","actor":"installer"}' \
        "$prov" "$op" "$inst")")"
    lc_run "$prov journal discard" composition discard-provider --request "$req" >/dev/null
    ok "$prov journal discarded"
}

# Ask the application-owned, versioned disposition contract. The shell supplies data only: the
# provider's JSON, invocation identity and the journal record left by that provider. It does not
# interpret result words, candidate/result exceptions, or recovery verbs itself.
LC_CONDITION=""; LC_COMPOSE=false; LC_RETIRE_PROVIDER=""; LC_RECOVERY_COMMAND=""
LC_DISPOSITION_REASON=""; LC_FIRST_ADMIN_OWED=false; LC_DISPOSITION_OUT=""
lc_preflight_disposition() {
    local out
    out="$(PYTHONPATH="$LC_RUNTIME_SOURCE" "$LC_RUNTIME_PY" -c \
'import json, sys
from corpusfm.lifecycle.installer_disposition import classify
with open(sys.argv[1], encoding="utf-8") as handle:
    journal = json.load(handle)
request = {
    "schema_version": 1, "phase": "preflight", "provider": None, "exit_code": None,
    "installation_id": None, "expected_generation": None, "mode": None,
    "install_dir": sys.argv[2], "platform": "posix", "provider_result": None,
    "journal": journal,
}
if sys.argv[3] == "package":
    request["recovery_python"] = sys.argv[4]
    request["recovery_source"] = sys.argv[5]
print(json.dumps(classify(request), separators=(",", ":"), sort_keys=True))' \
        "$CFM_JOURNAL_FILE" "$INSTALL_DIR" "$LC_RUNTIME_KIND" "$LC_RUNTIME_PY" \
        "$LC_RUNTIME_SOURCE" 2>>"$CFM_LOG")" \
        || die "The shared installer-disposition boundary could not classify the prior lifecycle
     journal. It remains untouched; see $CFM_LOG."
    LC_DISPOSITION_OUT="$out"
    printf '%s\n' "$out" >> "$CFM_LOG" 2>/dev/null || true
    LC_CONDITION="$(lc_json_field "$out" condition)"
    LC_RETIRE_PROVIDER="$(lc_json_field "$out" retire_provider)"
    LC_OP="$(lc_json_field "$out" operation_id)"
    LC_RECOVERY_COMMAND="$(lc_json_field "$out" recovery_command)"
    LC_DISPOSITION_REASON="$(lc_json_field "$out" reason)"
}

lc_provider_disposition() {    # lc_provider_disposition <provider> <exit> <result-json>
    local provider="$1" rc="$2" payload="$3" out
    out="$(printf '%s' "$payload" | PYTHONPATH="$REPO_DIR" "$INSTALL_DIR/venv/bin/python" -c \
'import json, os, sys
from corpusfm.lifecycle.installer_disposition import classify
payload = json.load(sys.stdin)
journal = None
try:
    with open(sys.argv[7], encoding="utf-8") as handle:
        journal = json.load(handle)
except FileNotFoundError:
    pass
request = {
    "schema_version": 1, "phase": "provider", "provider": sys.argv[1],
    "exit_code": int(sys.argv[2]), "installation_id": sys.argv[3],
    "expected_generation": int(sys.argv[4]), "mode": sys.argv[5],
    "install_dir": sys.argv[6], "platform": "posix",
    "provider_result": payload, "journal": journal,
}
print(json.dumps(classify(request), separators=(",", ":"), sort_keys=True))' \
        "$provider" "$rc" "$INSTALLATION_ID" "$CFM_GENERATION" "$CFM_STORAGE_MODE" \
        "$INSTALL_DIR" "$CFM_JOURNAL_FILE" 2>>"$CFM_LOG")" \
        || die "$provider returned a lifecycle result the shared installer-disposition boundary
     refused. The journal remains untouched; see $CFM_LOG."
    LC_DISPOSITION_OUT="$out"
    printf '%s\n' "$out" >> "$CFM_LOG" 2>/dev/null || true
    LC_CONDITION="$(lc_json_field "$out" condition)"
    LC_COMPOSE="$(lc_json_field "$out" compose)"
    LC_RETIRE_PROVIDER="$(lc_json_field "$out" retire_provider)"
    LC_OP="$(lc_json_field "$out" operation_id)"
    LC_RECOVERY_COMMAND="$(lc_json_field "$out" recovery_command)"
    LC_DISPOSITION_REASON="$(lc_json_field "$out" reason)"
    LC_FIRST_ADMIN_OWED="$(lc_json_field "$out" first_administrator_owed)"
}

lc_apply_provider_disposition() {  # lc_apply_provider_disposition <what>
    local what="$1" prior_feed
    if [[ -n "$LC_RETIRE_PROVIDER" && "$LC_RETIRE_PROVIDER" != None ]]; then
        prior_feed="$LC_FEED_CREDENTIAL"
        LC_FEED_CREDENTIAL=false
        lc_discard_provider "$LC_RETIRE_PROVIDER" "$LC_OP"
        LC_FEED_CREDENTIAL="$prior_feed"
    fi
    case "$LC_CONDITION" in
        continue) return 0 ;;
        correct_and_rerun)
            die "$what stopped without leaving recovery owed: $LC_DISPOSITION_REASON
     Correct the reported condition, then re-run the installer." ;;
        recover_first)
            LEAVE_SERVICES_STOPPED=true; : > "$LEAVE_SERVICES_STOPPED_FILE"
            warn "$LC_DISPOSITION_REASON"
            die "$what left an operation that must be recovered before installation continues.
     Run this exact command, then re-run the installer:
     $LC_RECOVERY_COMMAND" ;;
        *) die "$what received unknown installer condition '$LC_CONDITION'; the journal remains untouched." ;;
    esac
}

# Run one provider verb and hand back the shared disposition, operation id and candidate.
LC_OP=""; LC_CANDIDATE=""; LC_AWAITING=""; LC_PROVIDER_OUT=""
lc_provider_run() {     # lc_provider_run <what> <candidate-key|-> <verb...> --request <file>
    local what="$1" key="$2"; shift 2
    local out provider
    lc_run_raw "$@"
    out="$LC_RAW_OUT"
    LC_PROVIDER_OUT="$out"
    LC_AWAITING="$(lc_json_field "$out" awaiting_composition)"
    if [[ "$key" == "-" ]]; then
        LC_CANDIDATE=""
    else
        LC_CANDIDATE="$(lc_json_object "$out" "$key")"
    fi
    case "$what" in
        "admin_identity reconcile") provider=admin_identity ;;
        "patch compartment apply") provider=patch ;;
        "proxy reconcile") provider=proxy ;;
        storage\ *) provider=storage ;;
        *) die "no provider identity is registered for '$what'." ;;
    esac
    lc_provider_disposition "$provider" "$LC_RAW_RC" "$out"
    lc_apply_provider_disposition "$what"
}

# A dormant FMS web front can be installed but unusable (measured: nginx active while Apache's
# stock SSL configuration names an absent server.pem). The proxy provider correctly leaves that
# inactive front untouched; make its exact validator finding visible instead of burying it in the
# lifecycle JSON log. This is a warning because the selected live front still validates strictly.
lc_report_inactive_proxy_skips() {
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && warn "$line"
    done < <(printf '%s' "$LC_PROVIDER_OUT" | "$INSTALL_DIR/venv/bin/python" -c '
import json, sys
payload = json.load(sys.stdin)
for item in payload.get("per_type", []):
    detail = item.get("detail") or ""
    if item.get("action") == "none" and detail.startswith("inactive "):
        print(detail)
')
}

# ── Arg parsing ─────────────────────────────────────────────────────────────────
# TEN SWITCHES IN NINE SEMANTIC GROUPS (parent §4H.1), identical in meaning on both platforms.
#
# EIGHTEEN spellings are RETIRED with no alias (§4H.2). Every one falls through to `*)` and dies as
# an unknown option. An option that still parses but no longer does anything is worse than one that
# is gone: the operator's command line keeps working while its meaning changes underneath them.
#
#   --port                      the loopback port is an implementation constant published by
#                               `composition foundation`; the proxy tool owns the fronts
#   --no-pull --ref --allow-dirty   a clean expected origin and forward-only `main` are MANDATORY.
#                               The trust rails these parameterised are kept and are not optional;
#                               the SELF-PULL itself is retired with them
#   --enable-mcp --no-mcp --no-scheduler --mcp-*   MCP and the scheduler ALWAYS install; runtime
#                               auth, per-user gates and job configuration decide use
#   --fm-admin-user --fm-admin-pass --admin-user --admin-pass --git-pat
#                               secrets never travel in argv (§6); the approved environment
#                               secrets replace them
#   --assume-yes                alias removed; `--yes` only
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)        INSTALL_DIR="$2"; INSTALL_DIR_EXPLICIT=true; shift 2 ;;
        --patch-hosting-dir)  HOSTING_DIR="$2"; HOSTING_DIR_EXPLICIT=1; shift 2 ;;
        --fms-root)           FMS_ROOT="$2"; FMS_ROOT_EXPLICIT=true; FM_DB_DIR="$FMS_ROOT/Data/Databases"; shift 2 ;;
        --proxy-policy-add)     PROXY_POLICY_ADD+=("$2"); shift 2 ;;
        --proxy-policy-ignore)  PROXY_POLICY_IGNORE+=("$2"); shift 2 ;;
        --repair-storage-access)    REPAIR_STORAGE_ACCESS=true; shift ;;
        --replace-existing-install) REPLACE_EXISTING_INSTALL=true; shift ;;
        --yes)        ASSUME_YES=true; shift ;;
        --silent)     SILENT=true; shift ;;
        --verbose|-v) VERBOSE=true; shift ;;
        -h|--help)
            sed -n '/^# Usage:/,/^[^#]/{ /^#/p }' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) die "Unknown option: $1  (use --help)" ;;
    esac
done

if [[ -n "${CFM_BOOTSTRAP_HANDOFF:-}" ]]; then
    _actual_consent=interactive
    $ASSUME_YES && _actual_consent=yes
    $SILENT && _actual_consent=silent
    [[ "$_actual_consent" == "$CFM_HANDOFF_CONSENT" ]] \
        || die "Bootstrap handoff consent '$CFM_HANDOFF_CONSENT' disagrees with invocation '$_actual_consent'."
    rm -f -- "$CFM_BOOTSTRAP_HANDOFF"
    unset CFM_BOOTSTRAP_HANDOFF
    ok "Bootstrap handoff consumed; continuing with the verified installer bundle"
fi

# Canonicalize the selected software root before re-deriving or publishing anything beneath it.
# `realpath -m` is lexical for missing paths, so a fresh root need not exist yet; the result is
# absolute and carries no trailing separator except `/` itself.
INSTALL_DIR="$(realpath -m -- "$INSTALL_DIR")" \
    || die "--install-dir could not be normalized: $INSTALL_DIR"

# ── Re-derive every path that DEPENDS on a parseable input (packet 1246-04-03) ────
# These are assigned above, before the parser runs, because the blocks that declare them are
# prologue. That was harmless while `--install-dir`, `--patch-hosting-dir` and `--fms-root` did not
# exist or could not move them. `--install-dir` is NEW in 1246-04-02, and without this the flag was
# silently ignored by everything derived early: the bundled interpreter installed to the DEFAULT
# /opt/CORPUSfm however the operator invoked the installer.
#
# Re-derived here, immediately after parsing and before any consumer, rather than by moving the
# declarations: they are read by the prologue helpers too, so they must exist in both places.
#
# TRANSITIVELY. Re-deriving PY_BASE alone is not enough — PY_HOME is computed FROM it, also before
# the parser, so it kept the default and the extraction still targeted /opt/CORPUSfm. A partial
# re-derivation is the same defect one level down.
PY_BASE="$INSTALL_DIR/python"
PY_HOME="$PY_BASE/$PY_FULL"
PY_BUNDLED="$PY_HOME/bin/python3"
# HOSTING_DIR needs the EXPLICIT/DEFAULT distinction, which `${VAR:-default}` cannot express here:
# by this point the variable is already populated by the pre-parse default, so a second `:-` would
# read that default as if the operator had supplied it. The parser records the explicit case
# instead, and only the default is re-derived from the final INSTALL_DIR.
if [[ -z "${HOSTING_DIR_EXPLICIT:-}" ]]; then
    HOSTING_DIR="${INSTALL_DIR}-Hosted"
fi
FM_DB_DIR="$FMS_ROOT/Data/Databases"
CFM_LIFECYCLE=(env "PYTHONPATH=$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" -m corpusfm.lifecycle)

# --silent → non-interactive output (the library mutes hello/info/section banners, keeps ok/warn/die).
$SILENT && export CFM_SILENT=true || true
# --verbose → cfm_run streams full command output to the console (always captured to the log too).
$VERBOSE && export CFM_VERBOSE=true || true
# --yes → consent pre-granted, normal output. The library's cfm_confirm reads this; the S6 body never
# tests a flag directly, so there is exactly one place consent can be granted (packet 1228).
$ASSUME_YES && export CFM_ASSUME_YES=true || true

# ── Pre-ceremony: root and source acquisition (library not guaranteed loaded yet) ────────────────
# This block runs BEFORE the ten cfm_section blocks. In the bare-installer case the library isn't
# beside us until the self-clone below, so any output here uses RAW printf/echo + exit (NOT die/info).
# ── Pre-acquisition installation and location observation ─────────────────────
# A release installer may have to fetch its source before the ordinary lifecycle CLI from that
# source exists.  An ALREADY-PUBLISHED installation, however, owns a bundled interpreter and a
# locator at the fixed platform path.  Use those two existing authorities read-only so a failed
# fetch cannot erase what was known about the running installation, and so published paths replace
# defaults before any network acquisition.  Directory presence alone is never called an install.
PREEXISTING_STATE="none"
PREEXISTING_INSTALL_DIR=""
PREEXISTING_FMS_ROOT=""
PREEXISTING_HOSTING_DIR=""
PREEXISTING_BUILD=""
PREEXISTING_INSTALLER_SERIES=""
PREEXISTING_SERVICE="not-present"
PREEXISTING_HTTP="not-checked"

observe_published_install_pre_acquisition() {
    local locator=/etc/corpusfm/locator.json hinted python observed
    [[ -r "$locator" ]] || return 0
    # This extraction only locates the installed interpreter.  That interpreter then parses and
    # validates both complete JSON documents before any value becomes installer authority.
    hinted="$(sed -nE 's/^[[:space:]]*"install_dir"[[:space:]]*:[[:space:]]*"([^"[:cntrl:]]+)"[[:space:]]*,?[[:space:]]*$/\1/p' "$locator" | head -1)"
    [[ "$hinted" == /* ]] || return 0
    python="$hinted/venv/bin/python"
    [[ -x "$python" ]] || return 0
    observed="$($python - "$locator" <<'PY' 2>/dev/null
import json, os, sys
from pathlib import Path

locator_path = Path(sys.argv[1])
locator = json.loads(locator_path.read_text(encoding="utf-8"))
install_dir = locator.get("install_dir")
relative = locator.get("manifest_relative_path")
if not isinstance(install_dir, str) or not os.path.isabs(install_dir):
    raise SystemExit(2)
if not isinstance(relative, str) or os.path.isabs(relative) or ".." in Path(relative).parts:
    raise SystemExit(2)
manifest = json.loads((Path(install_dir) / relative).read_text(encoding="utf-8"))
if manifest.get("installation_id") != locator.get("installation_id"):
    raise SystemExit(2)
paths = manifest.get("paths")
if not isinstance(paths, dict) or paths.get("install_dir") != install_dir:
    raise SystemExit(2)
installer = manifest.get("installer")
if not isinstance(installer, dict) or not isinstance(installer.get("series"), str):
    raise SystemExit(2)
build_path = Path(install_dir) / "src" / "corpusfm" / "_build.txt"
build = build_path.read_text(encoding="utf-8").strip()
values = [install_dir, paths.get("fms_root"), paths.get("patch_hosting_dir"), build,
          installer["series"]]
for value in values[:3]:
    if not isinstance(value, str) or not os.path.isabs(value) or any(c in value for c in "\r\n\t"):
        raise SystemExit(2)
build = values[3]
if not build.isdigit() or int(build) < 1:
    raise SystemExit(2)
print("\n".join((values[0], values[1], values[2], str(build), values[4])))
PY
)" || return 0
    mapfile -t _pre_lines <<<"$observed"
    [[ ${#_pre_lines[@]} -eq 5 ]] || return 0
    PREEXISTING_STATE="published"
    PREEXISTING_INSTALL_DIR="${_pre_lines[0]}"
    PREEXISTING_FMS_ROOT="${_pre_lines[1]}"
    PREEXISTING_HOSTING_DIR="${_pre_lines[2]}"
    PREEXISTING_BUILD="${_pre_lines[3]}"
    PREEXISTING_INSTALLER_SERIES="${_pre_lines[4]}"
    systemctl is-active --quiet "$WEB_SERVICE.service" 2>/dev/null \
        && PREEXISTING_SERVICE="active" || PREEXISTING_SERVICE="inactive"
    command -v curl >/dev/null 2>&1 \
        && PREEXISTING_HTTP="$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "https://localhost${WEB_PREFIX}/" 2>/dev/null || printf 000)"
}

report_preexisting_after_acquisition_failure() {
    printf '  x Requested install/update: FAILED during source acquisition; no CORPUSfm mutation phase began.\n' >&2
    if [[ "$PREEXISTING_STATE" == published ]]; then
        printf '  ! Existing installation (separate read-only observation): PUBLISHED build 0.%s\n' "$PREEXISTING_BUILD" >&2
        printf '    install=%s  service=%s  local-web-http=%s\n' \
            "$PREEXISTING_INSTALL_DIR" "$PREEXISTING_SERVICE" "$PREEXISTING_HTTP" >&2
    else
        printf '  ! Existing installation (separate read-only observation): NOT ESTABLISHED.\n' >&2
    fi
}

observe_published_install_pre_acquisition

if [[ "$PREEXISTING_INSTALLER_SERIES" == series-1 ]]; then
    printf '  x Series 1 installation detected at %s. Series 2 will not overwrite, upgrade, adopt or convert it. Run the installed Series 1 uninstaller, then run this Series 2 package again. No Series 2 mutation phase began.\n' \
        "$PREEXISTING_INSTALL_DIR" >&2
    exit 2
fi

if [[ "$PREEXISTING_STATE" == published ]]; then
    if $INSTALL_DIR_EXPLICIT && [[ "$(realpath -m -- "$INSTALL_DIR")" != "$PREEXISTING_INSTALL_DIR" ]]; then
        printf '  x Published CORPUSfm root is %s, not the explicitly selected %s. Nothing has been acquired or changed.\n' \
            "$PREEXISTING_INSTALL_DIR" "$INSTALL_DIR" >&2
        exit 2
    fi
    if $FMS_ROOT_EXPLICIT && [[ "$(realpath -m -- "$FMS_ROOT")" != "$PREEXISTING_FMS_ROOT" ]]; then
        printf '  x Published FileMaker Server root is %s, not the explicitly selected %s. Nothing has been acquired or changed.\n' \
            "$PREEXISTING_FMS_ROOT" "$FMS_ROOT" >&2
        exit 2
    fi
    if [[ -n "$HOSTING_DIR_EXPLICIT" ]] && [[ "$(realpath -m -- "$HOSTING_DIR")" != "$PREEXISTING_HOSTING_DIR" ]]; then
        printf '  x Published apply-compartment folder is %s, not the explicitly selected %s. Nothing has been acquired or changed.\n' \
            "$PREEXISTING_HOSTING_DIR" "$HOSTING_DIR" >&2
        exit 2
    fi
    INSTALL_DIR="$PREEXISTING_INSTALL_DIR"
    FMS_ROOT="$PREEXISTING_FMS_ROOT"
    HOSTING_DIR="$PREEXISTING_HOSTING_DIR"
elif $SILENT && { ! $INSTALL_DIR_EXPLICIT || ! $FMS_ROOT_EXPLICIT || [[ -z "$HOSTING_DIR_EXPLICIT" ]]; }; then
    printf '  x Silent fresh installation requires explicit --install-dir, --fms-root, and --patch-hosting-dir before acquisition. No installation state has been changed. Log: %s\n' "$CFM_LOG" >&2
    exit 2
fi

INSTALL_DIR="$(realpath -m -- "$INSTALL_DIR")"
FMS_ROOT="$(realpath -m -- "$FMS_ROOT")"
HOSTING_DIR="$(realpath -m -- "$HOSTING_DIR")"
FM_DB_DIR="$FMS_ROOT/Data/Databases"
SUPPORT_DIR="$FM_DB_DIR/CORPUSfm-Support"
PY_BASE="$INSTALL_DIR/python"
PY_HOME="$PY_BASE/$PY_FULL"
PY_BUNDLED="$PY_HOME/bin/python3"
CFM_LIFECYCLE=(env "PYTHONPATH=$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" -m corpusfm.lifecycle)

FMS_LOCATION_STATE="not detected"
if command -v fmsadmin >/dev/null 2>&1; then
    _fmsadmin_real="$(readlink -f "$(command -v fmsadmin)" 2>/dev/null || true)"
    _active_fms_root="${_fmsadmin_real%/Database Server/bin/fmsadmin}"
    if [[ -n "$_fmsadmin_real" && "$_active_fms_root" != "$_fmsadmin_real" ]]; then
        [[ "$(realpath -m -- "$_active_fms_root")" == "$FMS_ROOT" ]] || {
            printf '  x Active fmsadmin resolves under %s, not selected FMS root %s. Nothing has been acquired or changed.\n' \
                "$_active_fms_root" "$FMS_ROOT" >&2
            exit 2
        }
        FMS_LOCATION_STATE="confirmed by active fmsadmin"
    fi
fi

printf '  Installation locations (resolved before acquisition):\n'
printf '    FileMaker Server: %s  [%s]\n' "$FMS_ROOT" "$FMS_LOCATION_STATE"
printf '    FMS databases:   %s\n' "$FM_DB_DIR"
printf '    CORPUSfm:        %s\n' "$INSTALL_DIR"
printf '    Apply hosting:   %s\n' "$HOSTING_DIR"
printf '    Apply support:   %s\n' "$SUPPORT_DIR"
if [[ "$PREEXISTING_STATE" == published ]]; then
    printf '    FMS recognition: previously published; current live state not yet confirmed (phase 16 proves it)\n'
else
    printf '    FMS recognition: not yet confirmed (phase 16 proves it)\n'
fi
if ! $SILENT && ! $ASSUME_YES; then
    printf '  Use these locations? [y/N] '
    read -r _location_answer
    case "$_location_answer" in y|Y|yes|YES) : ;; *) printf '  - Declined before acquisition; nothing has been changed.\n'; exit 0 ;; esac
fi

# A bad local clock can make TLS and release metadata misleading, but it is diagnostic unless the
# actual acquisition fails. Compare with a remote HTTPS Date header only in visible mode; inability
# to obtain that observation is non-fatal and never causes apt or clock changes.
if ! $SILENT && command -v curl >/dev/null 2>&1; then
    _remote_date="$(curl -fsSI --connect-timeout 3 --max-time 8 https://github.com/ 2>/dev/null \
        | tr -d '\r' | awk 'BEGIN{IGNORECASE=1} /^date:/ && !seen{sub(/^[^:]*:[[:space:]]*/, ""); print; seen=1}' \
        || true)"
    if [[ -n "$_remote_date" ]]; then
        _remote_epoch="$(date -u -d "$_remote_date" +%s 2>/dev/null || true)"
        _local_epoch="$(date -u +%s)"
        if [[ "$_remote_epoch" =~ ^[0-9]+$ ]]; then
            _clock_delta=$(( _local_epoch - _remote_epoch ))
            (( _clock_delta < 0 )) && _clock_delta=$(( -_clock_delta ))
            if (( _clock_delta > 300 )); then
                printf '  ! CLOCK WARNING: server UTC differs from the remote HTTPS date by about %s seconds; continuing because acquisition may still succeed.\n' "$_clock_delta" >&2
            fi
        fi
    fi
fi

# ── Anonymous public HTTPS source authority ──────────────────────────────────────
# gitsu: run git against the deployed checkout AS ROOT (packet 1246-03).
#
# It used to run as $SERVICE_USER, which required src/ to be service-writable -- and that is the
# defect this packet removes: a service that can rewrite the code it executes holds, in effect, the
# privilege of anyone who can reach the service. The deployed tree is now root-owned and
# service-READABLE, so every git operation here is root's, and the runtime's own update path goes
# through the fixed one-shot unit instead of touching this tree at all.
#
# The name is kept deliberately: it is the seam every deployment git call already goes through, so
# changing WHO it runs as is one edit rather than twenty. safe.directory stays -- the checkout is
# root-owned now, but the flag costs nothing and survives an operator who chowns it back.
gitsu() {
    git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" "$@"
}

# ── Public source update domain (detect → build → apply → verify) ─────────────────

source_origin_https() {   # build (pure): any origin URL → the clean HTTPS origin we want (SSH→HTTPS; REPO_URL fallback)
    local origin="${1:-}"
    case "$origin" in git@github.com:*) origin="https://github.com/${origin#git@github.com:}" ;; esac
    [[ -n "$origin" ]] || origin="$REPO_URL"   # origin unreadable → we know where the repo lives
    printf '%s' "$origin"
}

detect_source_state() {   # detect (read-only): "origin|credential.helper|core.sshCommand" for the checkout
    [[ -d "$INSTALL_DIR/src/.git" ]] || { printf '|<no-checkout>|'; return 0; }
    printf '%s|%s|%s' \
        "$(gitsu remote get-url origin 2>/dev/null || true)" \
        "$(gitsu config --get credential.helper 2>/dev/null || true)" \
        "$(gitsu config --get core.sshCommand 2>/dev/null || true)"
}

verify_public_source() {   # verify (read-only): anonymous HTTPS can reach the remote (exit 0)
    [[ -d "$INSTALL_DIR/src/.git" ]] || return 1
    gitsu ls-remote origin HEAD >/dev/null 2>&1
}

configure_public_source() {   # apply: public origin, no inherited private credential mechanisms
    [[ -d "$INSTALL_DIR/src/.git" ]] || return 1
    gitsu remote set-url origin "$REPO_URL" 2>/dev/null || return 1
    gitsu config --unset-all credential.helper 2>/dev/null || true
    gitsu config --unset core.sshCommand 2>/dev/null || true
    # Every `git config` above runs as root and may replace .git/config as root:root AFTER the
    # recursive root:$SERVICE_USER protection pass. The service must read origin + fetched refs to
    # classify a privileged update observation, but it must never write deployed Git metadata.
    chown "root:$SERVICE_USER" "$INSTALL_DIR/src/.git/config"
    chmod 640 "$INSTALL_DIR/src/.git/config"
    rm -f "$INSTALL_DIR/.git-pat" "$INSTALL_DIR/.git-pat-helper" "$INSTALL_DIR/.git-credentials"
    return 0
}

# ── First-admin domain (detect → build → apply → verify) ────────────────────────────────
# The browser no longer mints the first account (anti-race), so a FRESH install creates it here.
# detect = the Python users_exist probe (the one source of truth); build = the pure create-decision
# below (NEVER sees the password value); apply = env-passed create_user (never argv/log); verify =
# users_exist post-create. The apply + interactive prompt stay inline (tightly coupled to the
# env-passed sudo invocation); the decision is the extracted, simulatable seam.
detect_first_admin_state() {   # detect (read-only): "1" users exist · "0" none · "?" can't tell
    # raise_on_error=True is load-bearing (packet 1201): the default form SWALLOWS a storage failure
    # and answers "no users", so an outage during an upgrade re-run read as a FRESH box and the
    # installer tried to create an admin against an unreachable store. Raising makes it "?" instead.
    [[ -x "$INSTALL_DIR/venv/bin/python" ]] || { printf '?'; return 0; }
    (cd "$INSTALL_DIR/src" && PYTHONPATH="$INSTALL_DIR/src" sudo -u "$SERVICE_USER" -H \
        "$INSTALL_DIR/venv/bin/python" -c "from corpusfm.app.web import users; print('1' if users.users_exist(raise_on_error=True) else '0')" 2>/dev/null) || printf '?'
}

build_first_admin_plan() {   # build (pure): state + creds-present + pw-length → action token.
    # $1 = state (1|0|?), $2 = has-pass (1|0), $3 = pw length. Never receives the password value.
    # Packet 1201 — the fail tokens are FATAL, and the split is on KNOWLEDGE, not on outcome:
    # state 0 means the store was READ and is empty, so "no admin" is a fact and an install that
    # completes anyway ships an unreachable box. State ? means the read FAILED — that is not "no
    # admin", and failing an upgrade re-run over a transient read would repeat the same overclaim
    # one layer up. ? reports loudly and continues.
    case "$1" in
        1) printf 'preserve' ;;
        0)
            if [[ "${2:-0}" != 1 ]]; then printf 'fail:no-pass'
            elif [[ "${3:-0}" -lt 8 ]]; then printf 'fail:short-pass'
            else printf 'create'; fi ;;
        *) printf 'warn:unknown' ;;
    esac
}

build_storage_plan() {   # build (pure): storage-bootstrap decision from observed state → action token.
    # $1 = bootstrap completed (1|0), $2 = fm_odata backend already set in install.yaml (1|0),
    # $3 = stored-credential activate probe (1 ok · 0 failed · - not-probed). The KEY invariant: a
    # completed install whose stored credential can't be activated re-bootstraps — it NEVER silently
    # falls back to LocalBackend (which would look "installed" but lose FM OData storage).
    [[ "$1" != 1 ]] && { printf 'bootstrap'; return; }     # never bootstrapped → bootstrap
    [[ "$2" == 1 ]] && { printf 'preserve'; return; }      # done + backend already active → nothing to do
    [[ "$3" == 1 ]] && { printf 'activate'; return; }      # done, backend unset, stored cred good → just activate
    printf 'rebootstrap'                                   # done but stored cred unusable → re-bootstrap
}

# ── Supply-chain guards for the privileged self-pull (origin identity + clean tree) ─────
# A self-pull fetches code that is then run AS ROOT on the re-exec, so before any fetch we verify the
# checkout points at the expected CORPUSfm repo (not a redirected remote) and that the deployed tree
# is unmodified. Mirrors corpusfm.updater.verify_origin / is_dirty (the in-app Updates path).
normalize_remote() {   # any git remote URL → "github.com/<org>/<repo>" lowercased (form-independent)
    local u="${1:-}"
    u="${u%.git}"; u="${u%/}"
    u="${u#https://}"; u="${u#http://}"; u="${u#ssh://}"; u="${u#git://}"
    u="${u#git@}"
    u="${u//github.com:/github.com/}"   # scp-style host:path → host/path
    u="${u#*@}"                         # strip any userinfo (x-access-token:TOKEN@host)
    printf '%s' "$u" | tr 'A-Z' 'a-z'
}
EXPECTED_REMOTE="$(normalize_remote "$REPO_URL")"

assert_origin() {   # refuse to self-pull from anything but the expected CORPUSfm repo
    local got norm
    got="$(gitsu remote get-url origin 2>/dev/null || true)"
    norm="$(normalize_remote "$got")"
    if [[ "$norm" != "$EXPECTED_REMOTE" ]]; then
        die "Upgrade refused — the checkout origin is not the expected CORPUSfm repository.
       expected: $EXPECTED_REMOTE
       found:    ${norm:-<none>}
     A production upgrade pulls code that is then run as root; an unexpected remote is a supply-chain
     risk. Fix it: git remote set-url origin $REPO_URL
     This rail is unconditional — there is no flag that installs from an unexpected origin."
    fi
}

assert_clean_tree() {   # modified TRACKED code is a red flag before a privileged pull; untracked
    local dirty
    dirty="$(gitsu status --porcelain --untracked-files=no 2>/dev/null || true)"
    [[ -z "$dirty" ]] && return 0
    die "Refused — the deployed checkout has local modifications to tracked files:
$(printf '%s\n' "$dirty" | sed 's/^/         /' | head -20)
     Commit or stash them, then re-run. This rail is unconditional: there is no flag that
     installs over a modified checkout."
}

# A verified package is an exact application commit, but "exact" must never mean "allowed to move
# backwards".  The package checkout has the complete history ending at the selected commit, while
# the deployed checkout has the complete history ending at the installed commit.  Ask each repository
# the ancestry question it can answer: the package proves a forward move; the deployment proves a
# stale package.  Anything else is divergence.  This is read-only and runs before credentials,
# consent, service quiescence, runtime staging, or any deployed-byte mutation.
classify_package_source_relation() { # deployed-head package-head -> same|forward|stale|diverged
    local deployed_head="$1" package_head="$2"
    [[ "$deployed_head" == "$package_head" ]] && { printf 'same'; return 0; }
    if git -C "$REPO_DIR" -c safe.directory='*' merge-base --is-ancestor \
        "$deployed_head" "$package_head" 2>/dev/null; then
        printf 'forward'; return 0
    fi
    if gitsu merge-base --is-ancestor "$package_head" "$deployed_head" 2>/dev/null; then
        printf 'stale'; return 0
    fi
    printf 'diverged'
}

CFM_DEPLOYED_HEAD_BEFORE=""
preflight_package_source_advance() {
    local deployed_head package_head deployed_build package_build relation
    [[ -n "$CFM_INSTALLER_SERIES" && -d "$INSTALL_DIR/src/.git" \
       && -d "$REPO_DIR/.git" && "$REPO_DIR" != "$INSTALL_DIR/src" ]] || return 0

    assert_origin
    assert_clean_tree
    deployed_head="$(gitsu rev-parse HEAD 2>/dev/null || true)"
    package_head="$(git -C "$REPO_DIR" -c safe.directory='*' rev-parse HEAD 2>/dev/null || true)"
    [[ "$deployed_head" =~ ^[0-9a-f]{40}$ && "$package_head" =~ ^[0-9a-f]{40}$ \
       && "$package_head" == "$CFM_PACKAGE_COMMIT" ]] \
        || die "Package source advance refused — the installed or packaged commit could not be resolved exactly. Nothing has been changed."

    deployed_build="$(gitsu rev-list --count "$deployed_head" 2>/dev/null || printf '?')"
    package_build="$(git -C "$REPO_DIR" -c safe.directory='*' rev-list --count "$package_head" 2>/dev/null || printf '?')"
    info "Installed source before package: 0.$deployed_build @ $deployed_head"
    info "Verified package source:          0.$package_build @ $package_head"

    relation="$(classify_package_source_relation "$deployed_head" "$package_head")"
    case "$relation" in
        same) info "Package source matches the installed checkout — same-version reinstall permitted" ;;
        forward) ok "Package source is a forward update of the installed checkout" ;;
        stale)
            die "Package source advance refused — verified package 0.$package_build is older than installed source 0.$deployed_build. Nothing has been changed.
     Acquire a newer CORPUSfm installer package; this installer never downgrades an installation." ;;
        *)
            die "Package source advance refused — the installed and packaged histories have diverged. Nothing has been changed.
     Resolve the deployed checkout deliberately; this installer never replaces divergent history." ;;
    esac
    CFM_DEPLOYED_HEAD_BEFORE="$deployed_head"
}

# ── Bundled Python: download + checksum-verify + extract the pinned CPython ─────────
# Idempotent: reuse an already-present interpreter at the pinned version; otherwise fetch the
# pinned tarball, VERIFY the SHA256 before extraction (supply-chain trust), and place it at the
# VERSIONED $PY_HOME. The version in the path means a future bump installs ALONGSIDE the old one
# (never disturbing the venv the running service still depends on) — the swap is a venv swap only.
ensure_bundled_python() {
    local got=""
    [[ -x "$PY_BUNDLED" ]] && got="$("$PY_BUNDLED" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])' 2>/dev/null || true)"
    if [[ "$got" == "$PY_FULL" ]]; then
        ok "Bundled CPython $PY_FULL already present ($PY_HOME)"
        return 0
    fi
    [[ -n "$PY_SHA256" ]] || die "No pinned bundled-Python build for this CPU ($(uname -m)) — only x86_64 + aarch64 Linux are shipped."
    command -v curl &>/dev/null || die "curl is required to fetch the bundled Python."
    local tmp; tmp="$(mktemp -d)"
    info "Downloading bundled CPython $PY_FULL ($PY_ARCH, python-build-standalone $PY_PBS_TAG)..."
    curl -fsSL --retry 3 -o "$tmp/py.tar.gz" "$PY_URL" \
        || { rm -rf "$tmp"; die "Bundled Python download failed: $PY_URL"; }
    info "Verifying checksum (SHA256)..."
    printf '%s  %s\n' "$PY_SHA256" "$tmp/py.tar.gz" | sha256sum -c - &>/dev/null \
        || { rm -rf "$tmp"; die "Bundled Python checksum MISMATCH — refusing to install (expected $PY_SHA256)."; }
    info "Extracting to $PY_HOME ..."
    mkdir -p "$tmp/x"
    tar -xzf "$tmp/py.tar.gz" -C "$tmp/x" || { rm -rf "$tmp"; die "Bundled Python extract failed."; }
    [[ -x "$tmp/x/python/bin/python3" ]] || { rm -rf "$tmp"; die "Unexpected bundled-Python layout (no python/bin/python3)."; }
    mkdir -p "$PY_BASE"
    rm -rf "$PY_HOME"
    mv "$tmp/x/python" "$PY_HOME"
    rm -rf "$tmp"
    [[ -x "$PY_BUNDLED" ]] || die "Bundled Python missing after install at $PY_BUNDLED."
    ok "Bundled CPython $PY_FULL installed ($PY_HOME)"
}

prepare_package_recovery_runtime() {
    # Build entirely beneath the package's private temporary checkout. Nothing is restored into or
    # written beneath INSTALL_DIR before the interrupted operation has been resumed.
    local root="$BOOT_CLONE/recovery-runtime" archive="$BOOT_CLONE/recovery-python.tar.gz"
    local python venv req constraints pytag recovery_source_archive
    [[ -n "$BOOT_CLONE" && -d "$BOOT_CLONE" ]] \
        || die "The verified package has no private workspace for lifecycle recovery."
    command -v curl >/dev/null 2>&1 \
        || die "curl is required to prepare the verified package recovery runtime."
    info "Preparing a temporary package-owned lifecycle recovery runtime"
    recovery_source_archive="$CFM_RUNTIME_ROOT/corpusfm-recovery-source.zip"
    [[ -f "$recovery_source_archive" ]] \
        || die "The verified package lacks its private lifecycle recovery source."
    mkdir -p "$root/source"
    unzip -q "$recovery_source_archive" -d "$root/source" \
        || die "The verified lifecycle recovery source could not be opened."
    [[ -f "$root/source/corpusfm/lifecycle/__main__.py" ]] \
        || die "The lifecycle recovery source archive has an unexpected layout."
    curl -fsSL --retry 3 -o "$archive" "$PY_URL" \
        || die "The pinned recovery Python download failed; the lifecycle journal remains untouched."
    printf '%s  %s\n' "$PY_SHA256" "$archive" | sha256sum -c - >/dev/null 2>&1 \
        || die "Recovery Python checksum mismatch; refusing to execute it. The journal remains untouched."
    mkdir -p "$root/extract"
    tar -xzf "$archive" -C "$root/extract" \
        || die "The verified recovery Python could not be extracted; the journal remains untouched."
    python="$root/extract/python/bin/python3"
    [[ -x "$python" ]] || die "The pinned recovery Python archive has an unexpected layout."
    venv="$root/venv"
    "$python" -m venv "$venv" \
        || die "The temporary recovery venv could not be created; the journal remains untouched."
    "$venv/bin/pip" install --upgrade pip >>"$CFM_LOG" 2>&1 \
        || die "The temporary recovery pip bootstrap failed; the journal remains untouched."
    req="$CFM_RUNTIME_ROOT/installer/requirements-server.txt"
    pytag="$("$venv/bin/python" -c 'import sys;print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
    constraints="$CFM_RUNTIME_ROOT/installer/constraints-server-${pytag}.txt"
    [[ -f "$req" && -f "$constraints" ]] \
        || die "The verified package lacks its locked recovery dependency set."
    "$venv/bin/pip" install -r "$req" -c "$constraints" >>"$CFM_LOG" 2>&1 \
        || die "The temporary recovery dependencies could not be installed; the journal remains untouched."
    LC_RUNTIME_KIND=package
    LC_RUNTIME_PY="$venv/bin/python"
    LC_RUNTIME_SOURCE="$root/source"
    CFM_LIFECYCLE[1]="PYTHONPATH=$LC_RUNTIME_SOURCE"
    CFM_LIFECYCLE[2]="$LC_RUNTIME_PY"
    ok "Verified package recovery runtime ready; the installed root is still untouched"
}

# The release package carries the exact application commit as a local Git bundle. Series 2 has no
# bare-script path and never asks the application checkout to supply installer-owned files.
if [[ ! -d "$REPO_DIR/corpusfm" ]]; then
    BOOT_CLONE="$(mktemp -d)"
    _package_bundle="$SCRIPT_DIR/corpusfm.bundle"
    [[ -n "$CFM_INSTALLER_SERIES" && -f "$_package_bundle" ]] || {
        rm -rf "$BOOT_CLONE"
        printf '  x Series 2 requires a complete verified installer package; loose scripts and application checkouts are not installation sources.\n' >&2
        exit 2
    }
    command -v git &>/dev/null || {
        rm -rf "$BOOT_CLONE"
        printf '  x git is required to open the verified package source; no package was installed.\n' >&2
        exit 1
    }
    echo -e "${CYAN}  ▶ Materializing the exact source carried by the verified installer package...${NC}"
    git clone -q --no-hardlinks --branch main "$_package_bundle" "$BOOT_CLONE/repo" || {
        rm -rf "$BOOT_CLONE"
        printf '  x verified package source could not be materialized; no installation mutation began.\n' >&2
        exit 1
    }
    git -C "$BOOT_CLONE/repo" remote set-url origin "$REPO_URL"
    [[ "$(git -C "$BOOT_CLONE/repo" rev-parse HEAD)" == "$CFM_PACKAGE_COMMIT" ]] || {
        rm -rf "$BOOT_CLONE"
        printf '  x package source commit disagrees with its verified descriptor.\n' >&2
        exit 1
    }
    REPO_DIR="$BOOT_CLONE/repo"
    echo -e "${GREEN}  ✓ Exact package source ready — no repository download required${NC}"
fi

[[ -d "$REPO_DIR/corpusfm" ]] || \
    die "corpusfm package not found at $REPO_DIR/corpusfm after verified package materialization."

# End the raw early capture only after the package and shared library are available. Open the
# ordinary timestamped transcript on the same file, preserving argument, location, clock and
# acquisition output above as the first part of this one durable record.
cfm_early_log_finish
cfm_log_init "/var/log/corpusfm/install-$(date +%Y%m%d-%H%M%S).log"

# ── S1 Hello ──────────────────────────────────────────────────────────────────
cfm_section "Hello"
hello "CORPUSfm Server Installer"


# ═══ PHASE 1 — Research — inspect and classify without mutation ════════════════════════
# ── S2 Self-check ─────────────────────────────────────────────────────────────
# Root is already ensured (the pre-ceremony EUID re-exec). The CORPUSfm package is present
# (the self-bootstrap above guarantees it). Library is sourced. Orientation is complete.
cfm_section "Self-check"
ok "CORPUSfm package present, running as root, library loaded"

# ── S5 Detection ──────────────────────────────────────────────────────────────
# Read-only orientation only: OS check, Python present, FileMaker Server present. The mutating
# work (apt installs, venv, services, FM deploy) all lives under Progress, never here.
cfm_section "Detection"

# ── Ubuntu version check ─────────────────────────────────────────────────────────
info "Checking OS..."
command -v lsb_release &>/dev/null || die "lsb_release not found — Ubuntu required."
DISTRIB=$(lsb_release -is)
UBUNTU_VERSION=$(lsb_release -rs)
[[ "$DISTRIB" == "Ubuntu" ]] || die "Ubuntu required. Detected: $DISTRIB"
case "$UBUNTU_VERSION" in
    20.04|22.04|24.04) ok "Ubuntu $UBUNTU_VERSION" ;;
    *) die "Unsupported Ubuntu version: $UBUNTU_VERSION (supported: 20.04, 22.04, 24.04)" ;;
esac

# (fresh-vs-upgrade already decided above, before credential handling)

# ── Python runtime: bundled (no system Python required) ──────────────────────────
# CORPUSfm ships its own CPython — the distro's Python is irrelevant. The actual download/extract
# happens under Progress (staged before any service stop); here we just confirm a supported CPU.
info "Python runtime: bundled CPython $PY_FULL (python-build-standalone) — no system Python required"
[[ -n "$PY_ARCH" ]] || die "Unsupported CPU architecture '$(uname -m)' — bundled Python ships for x86_64 + aarch64 Linux only."

# ── FileMaker Server present? (orientation only — the FM mutation work runs under Progress) ──
# DEFINED BEFORE ITS FIRST CALL (correction F7). It was defined ~40 lines BELOW this call, so the
# first invocation exited 127 — bash defines functions in execution order — and `if fms_present`
# read that as false. The whole OData preflight, whose entire purpose is to fail EARLY on an
# OData-disabled box, never ran on any install. One definition, unconditional, read-only, unchanged.
fms_present() {   # detect (read-only): FMS installed AND its helper service is up (no mutation)
    command -v fmsadmin &>/dev/null && systemctl is-active --quiet fmshelper.service 2>/dev/null
}

if fms_present; then
    ok "FileMaker Server present"
    # OData PREFLIGHT (pre-mutation): CORPUSfm's storage/backend path REQUIRES the FM OData API.
    # Check it HERE in Detection — before Python/deps/services/proxy/helpers — so an OData-disabled
    # box fails EARLY with actionable guidance instead of after the whole install (the old check sat
    # in the Progress FMS block, post-mutation). 200 or 401 = enabled (401 = up + unauthenticated,
    # expected); anything else (000/404/500/502/…) = not ready. We never auto-enable it (no FMS
    # auto-toggle — the operator enables it, deliberately). The Data API is NOT required here: it's a
    # runtime dependency of the Jobs DDR-pull only (fms_client), not of install/bootstrap.
    info "Checking OData API (required for the FileMaker storage backend)..."
    _odata_pre=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 15 \
        "https://localhost/fmi/odata/v4/" 2>/dev/null || echo "000")
    case "$_odata_pre" in
        200|401) ok "OData API enabled (HTTP $_odata_pre)" ;;
        *) die "OData API is required but not responding (HTTP $_odata_pre). Enable it in the FM Server Admin Console (https://localhost/admin-console → Configuration → Connectivity → FileMaker OData API → Enable), then re-run." ;;
    esac

    # fmsadmin group (NON-FATAL — never blocks the install). The install runs as ROOT, and root drives
    # `fmsadmin` WITHOUT group membership (verified on Ubuntu 22.04/FMS 2025), so installation never
    # needs it — we do NOT require root in the group and do NOT auto-add anyone (FMS group membership
    # is the operator's to set). A NON-root user, however, needs the `fmsadmin` group to run fmsadmin
    # admin commands. So warn precisely where it matters:
    #   (a) the invoking operator, for MANUAL `fmsadmin` use;
    #   (b) the corpusfm SERVICE user, ONLY for the optional `fms_local` Job source (fmsadmin run
    #       script) or the patch-apply fmsadmin fallback — core operation uses PKI + OData/Data-API.
    _inv="${SUDO_USER:-}"
    if [[ -n "$_inv" && "$_inv" != "root" ]] && ! id -nG "$_inv" 2>/dev/null | tr ' ' '\n' | grep -qx fmsadmin; then
        warn "Operator '$_inv' is not in the 'fmsadmin' group — needed only to run 'fmsadmin' MANUALLY (the install itself runs as root and does not need it). Enable manual use with:  sudo usermod -aG fmsadmin $_inv   (then log out/in or reboot for the group to take effect)."
    fi
    info "fmsadmin group: not required for install (root) or core operation (PKI + OData). The '$SERVICE_USER' service user needs it ONLY for optional 'fms_local' Jobs or the patch-apply fmsadmin fallback — add then with:  sudo usermod -aG fmsadmin $SERVICE_USER && sudo systemctl restart $WEB_SERVICE"
else
    info "FileMaker Server not detected (or not running) — FM deploy/bootstrap will be skipped/deferred."
fi

# ── FMS discovery domain (detect → build) ───────────────────────────────────────────────
# Linux FMS installs to a FIXED root (/opt/FileMaker/FileMaker Server) unless --fms-root overrides it;
# the Databases dir is derived from it (FM_DB_DIR, above). These read-only/pure leaves name the two
# repeated FMS-orientation decisions so they're a single source of truth (and simulatable).
fms_storage_db_path() {   # build (pure): resolve the storage DB's on-disk path under a Databases dir.
    # $1 = FM Databases dir, $2 = DB stem. Prefers the CORPUSfm/ subfolder (current layout) over the
    # legacy top-level. Echoes the path, or nothing if absent — the caller decides how to fail.
    local dir="$1" stem="$2"
    if [[ -f "$dir/CORPUSfm/$stem.fmp12" ]]; then printf '%s' "$dir/CORPUSfm/$stem.fmp12"
    elif [[ -f "$dir/$stem.fmp12" ]]; then printf '%s' "$dir/$stem.fmp12"; fi
}

install_root_state() { # path published-here -> empty|current|unaccounted|foreign
    local root="$1" published_here="${2:-false}"
    [[ -d "$root" ]] || { printf 'empty'; return; }
    [[ -n "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] \
        || { printf 'empty'; return; }
    [[ "$published_here" == true ]] && { printf 'current'; return; }
    # These are CORPUSfm traces, not proof that the current lifecycle record owns the directory.
    # The replacement flag never converts, adopts or discards them.
    if [[ -e "$root/src" || -e "$root/venv" || -e "$root/services" || -e "$root/.corpusfm" ]]; then
        printf 'unaccounted'; return
    fi
    printf 'foreign'
}

prepare_install_root() { # path published-here replacement-consent -> establish safe selected root
    local root="$1" published_here="${2:-false}" replace="${3:-false}" state aside
    state="$(install_root_state "$root" "$published_here")"
    case "$state" in
        empty|current) : ;;
        foreign)
            [[ "$replace" == true ]] \
                || die "$root exists, is not empty, and carries no CORPUSfm installation. Re-run with --replace-existing-install to move it aside, or choose another --install-dir. Nothing has been changed."
            aside="${root}.replaced-$(date +%Y%m%d-%H%M%S)"
            mv -- "$root" "$aside" \
                || die "Could not move the unrelated install directory aside; nothing was replaced."
            warn "Moved the existing directory aside to $aside (--replace-existing-install)"
            ;;
        unaccounted)
            die "$root carries CORPUSfm files that no agreeing installation record owns. --replace-existing-install cannot convert or discard them. Resolve that installation deliberately, then re-run. Nothing has been changed."
            ;;
        *) die "Could not classify the selected install directory; nothing has been changed." ;;
    esac
}

check_install_root() { # path published-here replacement-consent -> read-only admissibility
    local root="$1" published_here="${2:-false}" replace="${3:-false}" state
    state="$(install_root_state "$root" "$published_here")"
    case "$state" in
        empty|current) : ;;
        foreign)
            [[ "$replace" == true ]] \
                || die "$root exists, is not empty, and carries no CORPUSfm installation. Re-run with --replace-existing-install to move it aside, or choose another --install-dir. Nothing has been changed."
            ;;
        unaccounted)
            die "$root carries CORPUSfm files that no agreeing installation record owns. --replace-existing-install cannot convert or discard them. Resolve that installation deliberately, then re-run. Nothing has been changed."
            ;;
        *) die "Could not classify the selected install directory; nothing has been changed." ;;
    esac
}


# ═══ PHASE 2 — Classify — fresh or valid new-format update ═════════════════════════════
# ── Fresh vs upgrade (decided before credentials — upgrade never touches FM) ──
# Auto-detection only: the durable marker is the installed venv. There is no force flag — re-running
# the installer IS the upgrade command on both platforms.
IS_UPGRADE=false
[[ -d "$INSTALL_DIR/venv" ]] && IS_UPGRADE=true
$IS_UPGRADE && info "Existing install found — upgrade mode" || info "Fresh install"

# The package identity is already verified and materialized.  Prove here—while the running services
# are untouched—that it is not older than the deployed checkout.  The mutation boundary rechecks the
# exact installed HEAD so this read-only decision cannot be invalidated silently before reset.
preflight_package_source_advance

# Capture the scheduler unit's PRIOR presence now, before we (re)write it below. An upgrade of a box
# that predates the scheduler unit will otherwise silently activate previously-inert scheduled Jobs
# (packet 1023 finding 1) — this flag lets the enable/start step ask/warn on that first activation.
SCHED_UNIT_PREEXISTED=false
[[ -f "/etc/systemd/system/$SCHED_SERVICE.service" ]] && SCHED_UNIT_PREEXISTED=true


# ── The SELF-PULL IS RETIRED (parent §4H.2, packet 1246-04-02) ────────────────────
# `--no-pull`, `--ref` and `--allow-dirty` are gone, and with them the installer's habit of
# fetching new code and re-exec'ing itself mid-run. There is no version, branch, channel or
# rollback CHOICE to express, so there is nothing for the installer to decide here.
#
# The TRUST RAILS those flags parameterised are NOT retired, and no flag can waive them any more:
# `--allow-dirty` is gone, so on the SUPPORTED IN-PLACE UPDATE PATH — re-running the installer from
# the installation's own `src/` checkout — an unexpected origin or a modified tracked file refuses,
# unconditionally.
#
# SCOPE, stated exactly, because an earlier wording here overstated it (corrected 2026-08-06). These
# rails run on that path and no other. They do NOT adjudicate the provenance of a fresh install or
# of an external checkout an administrator chose to install from, and they are NOT a defence against
# a malicious installer or a general supply-chain attack. An administrator who installs from an
# unusual checkout owns that choice; CORPUSfm does not attempt to police it.
if $IS_UPGRADE && [[ "$REPO_DIR" == "$INSTALL_DIR/src" && -d "$REPO_DIR/.git" ]]; then
    git config --global --add safe.directory "$REPO_DIR" 2>/dev/null || true
    info "Verifying installation source (origin + working tree)..."
    assert_origin        # expected remote only — mandatory, no flag can waive it
    assert_clean_tree    # no local modifications — mandatory, no flag can waive it
fi


# ═══ PHASE 3 — Prior-operation routing ═════════════════════════════════════════════════

# An operation already in flight OWNS this box. Resuming, finalizing or aborting it is the whole of
# this invocation — cleanup is never combined with new work, because a run that repairs and then
# installs cannot say which half a later failure belongs to.
#
# ROUTED ON THE FIELDS `status --json` ACTUALLY EMITS (packet 1246-04-04, correction C). This block
# used to grep for `"requires_recovery": true`. **There is no such key and there never was** —
# `requires_recovery()` is an internal `Journal` predicate — so the guard matched nothing, on every
# box, and the installer walked straight over an unresolved operation. The emitted vocabulary is
# `journal ∈ none|invalid|open|checkpointed|needs_recovery|resolved`, with `journal_operation`,
# `journal_mode` and `journal_subsystem` beside it.
#
# On a fresh box there is no venv yet, so `status` cannot run at all. That is NOT unresolved
# evidence: an installation that does not exist has no operation in flight, and the empty answer is
# treated as such — explicitly, rather than by an unread failure.
# THE GATE IS THE STATE, NOT THE INTERPRETER (correction R7). This block used to run only when
# `status --json` produced output — so a box with an OPEN JOURNAL and a broken or missing
# interpreter walked straight past its own unresolved operation. And the exit code was discarded, so
# a `status` that failed at runtime, or emitted a diagnostic into stdout, read as an empty answer
# and therefore as "settled". Both directions failed OPEN. They now fail closed.
#
# The journal path is a FIXED platform location (`lifecycle/layout.py::posix_layout`), so its
# presence can be established without running anything at all.
CFM_JOURNAL_FILE=/var/lib/corpusfm/state/lifecycle-journal.json
_lc_locator=missing
_lc_manifest=missing
_lc_install_dir=""
_lc_read_status=true
if [[ -e "$CFM_JOURNAL_FILE" && "$LC_RUNTIME_KIND" != package \
      && -n "$CFM_INSTALLER_SERIES" && -f "$CFM_RUNTIME_ROOT/corpusfm-recovery-source.zip" ]]; then
    # A verified package must classify and recover with the code it carries even when the old
    # installed interpreter is still runnable.  "Runnable" does not mean "contains the fix needed
    # to parse this retained operation" — packet 1275's live 0.2477 record is that exact case.
    prepare_package_recovery_runtime
    info "Inspecting the retained lifecycle journal with the verified package runtime"
fi
if [[ ! -x "$INSTALL_DIR/venv/bin/python" ]]; then
    if [[ -e "$CFM_JOURNAL_FILE" ]]; then
        # A terminal uninstall can remove the installed interpreter immediately before it removes
        # the journal. The verified package already materialized its exact application source in a
        # private temporary checkout. Build a checksum-pinned temporary Python for that authenticated
        # source, execute recovery in this invocation, and never rebuild/overwrite the install root.
        [[ -n "$CFM_INSTALLER_SERIES" && -f "$CFM_RUNTIME_ROOT/corpusfm-recovery-source.zip" ]] \
            || die "This machine holds a CORPUSfm lifecycle journal at $CFM_JOURNAL_FILE but the
     installed runtime is gone. Re-run from a complete verified Series 2 package; a loose script
     cannot supply recovery authority. The journal remains untouched."
        prepare_package_recovery_runtime
        info "Installed lifecycle runtime is absent; inspecting the journal with the verified package runtime"
    else
        _lc_read_status=false
        info "No prior CORPUSfm installation detected — nothing to recover."
    fi
fi
if $_lc_read_status; then
# stdout and stderr are captured SEPARATELY, and the exit status is kept. An unresolved or invalid
# status legitimately exits non-zero AND carries valid JSON, so the parsed STATE is what routes —
# never the exit code alone, and never "non-zero means nothing to see".
_lc_state="$("${CFM_LIFECYCLE[@]}" status --json 2>>"$CFM_LOG")" && _lc_rc=0 || _lc_rc=$?
if [[ -z "${_lc_state//[[:space:]]/}" ]]; then
    die "\`corpusfm-lifecycle status --json\` produced no output (exit $_lc_rc). This installer
     cannot establish whether an operation is in flight and will not guess. See $CFM_LOG. Nothing
     has been changed."
fi
# EXACTLY ONE PARSEABLE JSON OBJECT. A second document, a diagnostic that reached stdout, or a
# truncated write all refuse here rather than being read field-by-field into a false "settled".
if ! printf '%s' "$_lc_state" | "$LC_RUNTIME_PY" -c \
'import json, sys
raw = sys.stdin.read()
try:
    value = json.loads(raw)
except ValueError as exc:
    sys.stderr.write("status --json is not one parseable JSON object: %s\n" % exc)
    raise SystemExit(1)
if not isinstance(value, dict):
    sys.stderr.write("status --json is not a JSON object\n")
    raise SystemExit(1)
if "journal" not in value or "locator" not in value:
    sys.stderr.write("status --json is missing a required field\n")
    raise SystemExit(1)' 2>>"$CFM_LOG"; then
    die "\`corpusfm-lifecycle status --json\` did not return one well-formed status object (exit
     $_lc_rc). See $CFM_LOG. This installer will not route an operation from output it cannot read,
     and it has changed nothing."
fi
if [[ -n "$_lc_state" ]]; then
    _lc_journal="$(lc_json_field "$_lc_state" journal)"
    _lc_j_op="$(lc_json_field "$_lc_state" journal_operation)"
    _lc_j_mode="$(lc_json_field "$_lc_state" journal_mode)"
    _lc_j_sub="$(lc_json_field "$_lc_state" journal_subsystem)"
    _lc_locator="$(lc_json_field "$_lc_state" locator)"
    _lc_manifest="$(lc_json_field "$_lc_state" manifest)"
    _lc_install_dir="$(lc_json_field "$_lc_state" install_dir)"
    case "$_lc_journal" in
        none|"")
            : ;;                    # settled — this invocation may proceed
        invalid)
            die "This installation's lifecycle journal is unreadable. It remains untouched; inspect
     $CFM_JOURNAL_FILE before any installation work." ;;
        open|checkpointed|needs_recovery|resolved)
            _lc_j_record="$("$LC_RUNTIME_PY" - "$CFM_JOURNAL_FILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.dumps(json.load(handle), separators=(",", ":")))
PY
)" || die "The lifecycle journal could not be read directly; it remains untouched."
            _lc_j_inst="$(lc_json_field "$_lc_j_record" installation_id)"
            if [[ "$LC_RUNTIME_KIND" == package && "$_lc_j_mode" == uninstall ]]; then
                [[ -n "$_lc_j_inst" ]] \
                    || die "The interrupted uninstall journal names no installation identity; it remains untouched."
                info "Resuming the interrupted uninstall with the verified package runtime"
                lc_resume_orphaned_uninstall "$_lc_j_inst"
            fi
            lc_preflight_disposition
            if [[ "$LC_CONDITION" == recover_first ]]; then
                warn "$LC_DISPOSITION_REASON"
                if [[ "$LC_RUNTIME_KIND" == package ]]; then
                    info "Running the operation-bound recovery with the verified package runtime"
                    if bash -c "$LC_RECOVERY_COMMAND"; then
                        die "The prior lifecycle recovery completed. Re-run this Series 2 package
     to begin a separate installation invocation."
                    fi
                    die "The prior lifecycle recovery did not complete. Its journal and recovery
     evidence remain in place. Re-run this same verified Series 2 package to try recovery again."
                else
                    die "A prior lifecycle operation must be recovered before installation continues.
     Run this exact command, then re-run the installer:
     $LC_RECOVERY_COMMAND"
                fi
            elif [[ "$LC_CONDITION" == continue && -n "$LC_RETIRE_PROVIDER" ]]; then
                lc_discard_provider "$LC_RETIRE_PROVIDER" "$LC_OP" "$_lc_j_inst"
                ok "Spent $LC_RETIRE_PROVIDER journal retired; this invocation may continue"
                _lc_journal=none
            else
                die "The shared installer-disposition boundary returned '$LC_CONDITION' for the
     prior journal without a safe retirement. The record remains untouched."
            fi
            ;;
        *)
            # `invalid`, or a word this build does not know. Neither is routed and neither is
            # assumed harmless.
            die "This installation's lifecycle journal reads '$_lc_journal', which this installer
     cannot route. Inspect it with corpusfm-lifecycle status --json. Nothing has been changed."
            ;;
    esac
    # Foreign or contradictory IDENTITY evidence refuses too, for the same reason and unchanged.
    case "$_lc_locator" in
        missing|present) : ;;
        *) die "This installation's locator reads '$_lc_locator'; refusing to work over evidence
     that cannot be read. Nothing has been changed." ;;
    esac
    if [[ "$_lc_locator" == "present" && "$_lc_manifest" != "valid" ]]; then
        die "This installation publishes a locator but its manifest reads '$_lc_manifest'; refusing
     to work over a record that disagrees with itself. Nothing has been changed."
    fi
fi
fi          # end: an installed or verified-package runtime read status strictly

PUBLISHED_HERE=false
if [[ "$_lc_locator" == present ]]; then
    [[ -n "$_lc_install_dir" ]] \
        || die "The published installation record names no software root; refusing before mutation."
    _lc_install_dir="$(realpath -m -- "$_lc_install_dir")" \
        || die "The published installation root could not be normalized; refusing before mutation."
    [[ "$_lc_install_dir" == "$INSTALL_DIR" ]] \
        || die "The published installation belongs to $_lc_install_dir, not the selected root $INSTALL_DIR. Nothing has been changed."
    PUBLISHED_HERE=true
    IS_UPGRADE=true
fi

# `--replace-existing-install` is deliberately narrow: it may move aside only a non-empty selected
# root with no CORPUSfm trace and no agreeing published record. It never converts or discards an old,
# partial or contradictory CORPUSfm installation. This gate follows lifecycle classification but
# precedes credentials, consent and every write beneath the selected root.
check_install_root "$INSTALL_DIR" "$PUBLISHED_HERE" "$REPLACE_EXISTING_INSTALL"

# ═══ PHASE 4 — Accept and validate the authoritative inputs ════════════════════════════
# ── S3 Settings ───────────────────────────────────────────────────────────────
cfm_section "Settings"
echo "  Repo:             $REPO_DIR"
if [[ -n "$CFM_INSTALLER_SERIES" ]]; then
    echo "  Installer:        $CFM_INSTALLER_SERIES / $CFM_INSTALLER_VERSION"
    echo "  Package source:   $CFM_PACKAGE_APPLICATION_VERSION @ ${CFM_PACKAGE_COMMIT:0:12}"
else
    echo "  Installer:        direct checkout (no release descriptor)"
fi
echo "  CORPUSfm root:    $INSTALL_DIR"
echo "  FMS root:         $FMS_ROOT"
echo "  FMS databases:    $FM_DB_DIR"
echo "  Apply hosting:    $HOSTING_DIR"
echo "  Apply support:    $SUPPORT_DIR"
echo "  FMS recognition:  current live state is not inferred from directory presence; phase 16 reads and proves it"
echo "  Port:             $WEB_PORT"
$ENABLE_MCP && echo "  MCP:     folded into the web app at ${WEB_PREFIX}/mcp/ (user-authenticated)" || echo "  MCP:     disabled"


# ═══ PHASE 5 — Preflight — credential-free ═════════════════════════════════════════════
# The credential-REQUIRED determination. Credential-free by construction: it reads
# configuration only. Phase 6's plan consumes its result, so it must precede phase 6.
# ── FM Server credentials ─────────────────────────────────────────────────────────
# Needed for FM bootstrap (fresh install) AND, when the reverse-proxy config actually changes,
# for the FMS web-server restart that activates it (`fmsadmin restart httpserver`). The proxy step
# is now idempotent — on a routine upgrade where the proxy is unchanged it does NOT restart, so
# the creds simply go unused for that step.
# Providing the creds IS the consent to that restart; install then proceeds without further
# prompts. (The DB deploy/bootstrap section is still upgrade-skipped — see below.)
#
# Smarter: on an UPGRADE, the ONLY thing that needs FM admin creds is the FMS web-server restart
# that activates a CHANGED reverse proxy (the corpusfm systemd restart + the storage-schema
# migration do NOT use fmsadmin). So if the proxy is already current we don't need them at all this
# run. `cfm-web-proxy.sh check` decides that by reading config files only (root, but no creds).
# Fresh installs always need creds (DB deploy + bootstrap + first proxy activation).
NEED_FMS_CREDS=true
if $IS_UPGRADE && [[ -z "$FM_ADMIN_PASS" ]] \
   && [[ -f "$CFM_RUNTIME_ROOT/installer/linux/cfm-web-proxy.sh" ]]; then
    if CFM_MCP_ENABLED="$($ENABLE_MCP && echo 1 || echo 0)" \
       bash "$CFM_RUNTIME_ROOT/installer/linux/cfm-web-proxy.sh" check "$WEB_PREFIX" "$WEB_PORT" >/dev/null 2>&1; then
        NEED_FMS_CREDS=false   # exit 0 = proxy already current → no FMS restart → no creds needed
    fi
fi

# Required authority is acquired and proven before the final plan/consent boundary. A credential is
# a means, never consent; successful authentication cannot skip the confirmation that follows.
if $NEED_FMS_CREDS; then
    fms_present || die "FileMaker Server is not active and reachable at the selected FMS root. The installer will not start it."
    if $SILENT; then
        [[ -n "$FM_ADMIN_USER" && -n "$FM_ADMIN_PASS" ]] \
            || die "--silent requires FM_ADMIN_USER and FM_ADMIN_PASS before installation."
    else
        echo ""
        info "FileMaker Server admin credentials are required for this plan."
        info "  They are used for this run only and are never written to disk."
        [[ -n "$FM_ADMIN_USER" ]] || read -rp "  FM Server admin account username: " FM_ADMIN_USER
        FM_ADMIN_USER="${FM_ADMIN_USER:-admin}"
        while [[ -z "$FM_ADMIN_PASS" ]]; do
            read -rsp "  FM Server admin account password: " FM_ADMIN_PASS; echo ""
            [[ -n "$FM_ADMIN_PASS" ]] || warn "The FM Server admin password cannot be blank."
        done
    fi
    info "Verifying FM Server credentials..."
    if ! fmsadmin -u "$FM_ADMIN_USER" -p "$FM_ADMIN_PASS" list files &>/dev/null; then
        unset FM_ADMIN_PASS
        die "FM Server admin login failed. Check credentials and re-run; nothing has been installed by this run."
    fi
    ok "FM Server is active and reachable; administrator '$FM_ADMIN_USER' authenticated"
fi

# A fresh installation always owes its first CORPUSfm administrator. Capture and validate it now,
# while declining the complete plan can still leave the box without partial CORPUSfm state.
if ! $IS_UPGRADE; then
    if $SILENT; then
        [[ -n "$CFM_ADMIN_USER" && -n "$CFM_ADMIN_PASS" ]] \
            || die "--silent fresh install requires CORPUSFM_ADMIN_USER and CORPUSFM_ADMIN_PASS."
    else
        [[ -n "$CFM_ADMIN_USER" ]] || read -rp "  First CORPUSfm admin username [admin]: " CFM_ADMIN_USER
        CFM_ADMIN_USER="${CFM_ADMIN_USER:-admin}"
        if [[ -z "$CFM_ADMIN_PASS" ]]; then
            read -rsp "  First CORPUSfm admin password (min 8 chars): " CFM_ADMIN_PASS; echo ""
            read -rsp "  Confirm CORPUSfm admin password: " _CFM_PASS2; echo ""
            [[ "$CFM_ADMIN_PASS" == "$_CFM_PASS2" ]] || die "CORPUSfm admin passwords did not match."
            unset _CFM_PASS2
        fi
    fi
    [[ -n "$CFM_ADMIN_USER" ]] || die "The first CORPUSfm admin username cannot be blank."
    [[ ${#CFM_ADMIN_PASS} -ge 8 ]] \
        || die "The first CORPUSfm admin password must be at least 8 characters."
fi


# ═══ PHASE 6 — Complete plan ═══════════════════════════════════════════════════════════
# Every interactive install and update crosses the same explicit final-consent boundary. Re-running
# an installer selects the update operation; it does not silently consent to the measured changes.
# Only --yes/--silent or the verified bootstrap handoff may pre-grant that consent.

# THE RE-EXEC CONSENT TOKEN IS GONE with the self-pull (packet 1246-04-02). It existed so a run
# that fetched new code and exec'd itself could carry the operator's consent into the child. There
# is no child: the installer installs the checkout it was invoked from. Consent is taken once, here,
# by the run that will do the work — which is what packet 1236 wanted and could not have while a
# re-exec existed.

# ── S6 Confirm ──────────────────────────────────────────────────────────────────
# Informed consent — outline what needs sudo/fmsadmin, allow decline before any mutation. The plan is
# ANNOUNCED unconditionally; only an explicit consent mode may skip the wait.
#
# NEVER skipped now (packet 1246-04-02). The one path that used to skip it was the post-self-pull
# re-exec, and the self-pull is retired: the run that takes consent is the run that does the work.
cfm_section "Confirm"
# Supply-chain transparency: the privileged helpers + systemd units written below are copied from
# THIS checkout, so a root install/upgrade trusts the checkout's state. Print exactly which commit
# is being installed (and loudly flag an uncommitted/dirty tree) BEFORE any root-owned file is
# written, so the operator can verify what they're trusting. (-c safe.directory='*' keeps the
# root-run read from tripping git's dubious-ownership guard on a service-/operator-owned checkout.)
if [[ -d "$REPO_DIR/.git" ]]; then
    _CFM_REV="$(git -C "$REPO_DIR" -c safe.directory='*' rev-parse --short HEAD 2>/dev/null || echo unknown)"
    _CFM_DESC="$(git -C "$REPO_DIR" -c safe.directory='*' describe --tags --always 2>/dev/null || true)"
    _CFM_DIRTY=""
    [[ -n "$(git -C "$REPO_DIR" -c safe.directory='*' status --porcelain 2>/dev/null)" ]] \
        && _CFM_DIRTY="   ** UNCOMMITTED CHANGES in this checkout **"
    info "Installing privileged helpers from commit ${_CFM_REV}${_CFM_DESC:+ (${_CFM_DESC})}${_CFM_DIRTY}"
fi
# ANNOUNCE ALWAYS (SPEC S6) — the plan is printed even when the wait is skipped. Only the WAIT is
# conditional; a silent run still records what it was about to do.
if true; then
    echo ""
    info "This $($IS_UPGRADE && echo upgrade || echo install) will:"
    echo "    • update the code + Python venv, rewrite the systemd unit(s), and restart CORPUSfm (sudo)"
    if $NEED_FMS_CREDS; then
        echo "    • apply the FMS reverse proxy at ${WEB_PREFIX} — this RESTARTS the FMS web server:"
        echo "        a few-second interruption of WebDirect, the Data & OData APIs, and the Admin"
        echo "        Console; connected web clients reconnect. (FileMaker Pro clients on fmnet are"
        echo "        unaffected.) Needs FMS admin creds."
    else
        echo "    • FMS reverse proxy at ${WEB_PREFIX} is already current — NO FMS web-server restart"
    fi
    $IS_UPGRADE && echo "    • update the app code + services (no in-place storage-schema migration; a schema-build change requires a fresh install)" \
                || echo "    • deploy + bootstrap the CORPUSfm storage DB — needs FMS admin creds"
    echo "  sudo is required; FMS admin credentials were requested above (for the steps above)."
    $NEED_FMS_CREDS && echo "  FMS administrator:      $FM_ADMIN_USER  (authenticated)"
    ! $IS_UPGRADE && echo "  First CORPUSfm admin:   $CFM_ADMIN_USER  (input validated)"
    cfm_confirm "Proceed?"
fi


# ═══ PHASE 7 — Preparation complete; no required question remains ═════════════════════

# ── System packages — before the first installation-tree write ────────────────────────
# A busy or unavailable package manager is an environmental refusal, not a partial CORPUSfm
# installation. Keep it ahead of the fixed-layout and $INSTALL_DIR creation so the ordinary retry
# sees the same fresh box after apt releases its lock.
info "Checking apt packages..."
PKGS_NEEDED=()
# rsync (legacy deploy helper) + curl/ca-certificates for the bundled-Python download. No
# system python-venv: CORPUSfm ships its own CPython, so no distro Python/venv package is needed.
for pkg in rsync curl ca-certificates; do
    dpkg -s "$pkg" &>/dev/null 2>&1 || PKGS_NEEDED+=("$pkg")
done

if [[ ${#PKGS_NEEDED[@]} -gt 0 ]]; then
    info "Installing: ${PKGS_NEEDED[*]}"
    apt-get update -qq
    apt-get install -y -qq "${PKGS_NEEDED[@]}"
fi
ok "System dependencies satisfied"

# Re-observe after the external package-manager boundary, then consume replacement consent. No
# earlier step moves or writes beneath the selected installation root, so an apt refusal leaves a
# foreign root byte-for-byte where the operator put it and a fresh root absent/empty for retry.
prepare_install_root "$INSTALL_DIR" "$PUBLISHED_HERE" "$REPLACE_EXISTING_INSTALL"

# ── S4 Permissions ──────────────────────────────────────────────────────────────
# Acquire the FM admin credentials BEFORE the read-only detection checks + the consent prompt.
cfm_section "Permissions"


# ═══ PHASE 8 — Establish or verify the layout and preconditions ════════════════════════
# ── Service user ─────────────────────────────────────────────────────────────────
# A first-ever install has no service identity yet. Establish it before any `install -o`
# operation names that identity; reinstall and upgrade take the idempotent existing-user branch.
info "Service User"
CREATED_SERVICE_ACCOUNT=false
if ! id -u "$SERVICE_USER" &>/dev/null; then
    info "Creating system user: $SERVICE_USER"
    useradd \
        --system \
        --home-dir "$INSTALL_DIR" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --user-group \
        "$SERVICE_USER"
    CREATED_SERVICE_ACCOUNT=true
    ok "User $SERVICE_USER created"
else
    ok "User $SERVICE_USER already exists"
fi

# ── Fixed OS state locations (packet 1246-03) ────────────────────────────────────
# Conventional locations own mutable state; the installer owns ONE software root. Before this,
# `HOME=$INSTALL_DIR` made ~/.corpusfm live inside the install tree and mutable state live inside
# `src/` itself — with `src` group-writable to the service, which is a service that can rewrite the
# code it executes. These directories are created root-owned; only state, logs and run are writable
# by the service, and `secrets` deliberately is NOT (parent D4).
info "Fixed OS state locations"
install -d -m 0755 -o root -g root /etc/corpusfm
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" /var/lib/corpusfm/state
install -d -m 0755 -o root -g root /var/lib/corpusfm/secrets
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" /var/log/corpusfm
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" /run/corpusfm
ok "State locations ready (/etc/corpusfm, /var/lib/corpusfm, /var/log/corpusfm, /run/corpusfm)"

# Installed secrets are provider-owned and read-only to both runtime services. No individual secret
# carries a runtime-writable exception.

# ── Update inbox and outcome: TWO authorities (packet 1246-03, ruling 2026-08-03) ─
# The service writes the request, so the inbox is service-writable. The OUTCOME is root's word about
# what the elevated operation did, and a directory the service can create/delete/rename entries in
# would let it forge one naming its own trigger id -- correlation is not authentication. So the
# outcome directory is root-owned and merely readable by the service, and `update_service` REFUSES
# to trigger until it has verified that.
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$INSTALL_DIR/.corpusfm/update-inbox"
install -d -m 0755 -o root -g root "$INSTALL_DIR/.corpusfm/update-outcome"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" /var/lib/corpusfm/state/update-inbox
install -d -m 0755 -o root -g root /var/lib/corpusfm/state/update-outcome
ok "Update inbox (service-writable) and outcome (root-owned) separated"

# ── Directory structure ──────────────────────────────────────────────────────────
info "Directories"
info "Creating directory structure..."

# Root install dir
mkdir -p "$INSTALL_DIR"
chown root:root "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"

# Source tree - root-owned, service-READABLE. Packet 1246-03: it used to be 0770 root:corpusfm so
# the in-app updater could `git pull` into it as the service user. A service that can rewrite the
# code it executes holds, in effect, the privilege of anyone who can reach the service; the update
# now goes through the root-owned one-shot below, so the service needs no write access here at all.
mkdir -p "$INSTALL_DIR/src"
chown root:"$SERVICE_USER" "$INSTALL_DIR/src"
chmod 750 "$INSTALL_DIR/src"

# Venv — root:corpusfm, read-only for service user
mkdir -p "$INSTALL_DIR/venv"
chown root:"$SERVICE_USER" "$INSTALL_DIR/venv"
chmod 750 "$INSTALL_DIR/venv"

# Runtime data belongs to the published /var/lib and /var/log layout. Do not create archive/logs/
# history directories inside the deployed checkout: the privileged updater deliberately inspects
# ignored paths too, and a checkout containing runtime data is not eligible for unattended update.

# Config dir (HOME/.corpusfm for install.yaml) — owned by service user
mkdir -p "$INSTALL_DIR/.corpusfm"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.corpusfm"
chmod 750 "$INSTALL_DIR/.corpusfm"

ok "Directory structure ready"


# ═══ PHASE 9 — QUIESCE UPDATE — stop every existing CORPUSfm service ═══════════════════
# ── Stop services for upgrade ────────────────────────────────────────────────────
if $IS_UPGRADE; then
    info "Stopping Services"
    QUIESCE_RESTORE_ARMED=true
    # The ordinary in-place updater may already have advanced source while the live venv is old.
    # Nothing is restartable until the replacement venv and its source binding are proven together.
    QUIESCE_RESTORE_READY=false
    for _unit in "$WEB_SERVICE" "$SCHED_SERVICE"; do
        if systemctl is-active --quiet "$_unit" 2>/dev/null; then
            QUIESCED_ACTIVE_UNITS+=("$_unit")
            info "Stopping $_unit..."
            systemctl stop "$_unit" || die "could not quiesce $_unit for the update"
        fi
    done
fi


# ═══ PHASE 10 — Install code and immutable helpers — FIRST byte replacement ═════════════
# ── S7 Progress ───────────────────────────────────────────────────────────────
# All mutation/work, in its existing order.
cfm_section "Progress"

# ── Bundled Python runtime + replacement venv (STAGED before stopping the service) ────────────
# CORPUSfm ships its own CPython so a Linux box never depends on the distro's Python. Everything
# that can fail — download, checksum, extract, venv build, dependency install — runs HERE, into
# STAGING paths, while the OLD app keeps running. Only once the new runtime is proven do we stop
# the service and swap it in (below). A failure here die()s with the old app still alive.
info "Bundled Python runtime"
ensure_bundled_python

# Build the replacement venv at a STAGING path from the bundled interpreter — recreated every run
# (always rebuild on upgrade; never reuse an old venv). The venv references $PY_HOME (a versioned,
# stable path), so a future Python bump never strands it. The dependency install (the likeliest
# failure) happens NOW, before any service stop — so a failed runtime prep leaves the old app up.
VENV_STAGE="$INSTALL_DIR/venv.new"
rm -rf "$VENV_STAGE"
info "Building replacement venv from bundled CPython $PY_FULL..."
cfm_run "venv create" "$PY_BUNDLED" -m venv "$VENV_STAGE" || die "Could not create the venv from bundled Python ($PY_BUNDLED)."
cfm_run "pip self-upgrade" "$VENV_STAGE/bin/pip" install --upgrade pip || die "pip self-upgrade failed in the staged venv — old app left running."
# Build the venv from the repo we are installing FROM (always present), not the not-yet-synced
# src/ — so the staging happens before the Source section. Box-validated dependency lock, keyed to
# the bundled interpreter (constraints-server-py<MAJ><MIN>.txt). Apply only the lock that MATCHES;
# with no match, resolve UNPINNED (the pre-lock behavior) rather than force a mismatched lock.
REQ_FILE_BOOT="$CFM_RUNTIME_ROOT/installer/requirements-server.txt"
PYTAG="$("$VENV_STAGE/bin/python" -c 'import sys;print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
CONSTRAINTS_FILE="$CFM_RUNTIME_ROOT/installer/constraints-server-${PYTAG}.txt"
if [[ -f "$CONSTRAINTS_FILE" ]]; then
    info "Using dependency lock: $(basename "$CONSTRAINTS_FILE") (full pip output in the install log; --verbose to watch)"
    cfm_run "pip install (locked)" "$VENV_STAGE/bin/pip" install -r "$REQ_FILE_BOOT" -c "$CONSTRAINTS_FILE" \
        || die "Dependency install failed (lock $(basename "$CONSTRAINTS_FILE")) — old app left running."
else
    info "No dependency lock for ${PYTAG} — resolving unpinned (add constraints-server-${PYTAG}.txt to pin)."
    cfm_run "pip install (unpinned)" "$VENV_STAGE/bin/pip" install -r "$REQ_FILE_BOOT" \
        || die "Dependency install failed — old app left running."
fi
ok "Replacement runtime staged (bundled CPython $PY_FULL + dependencies) — old app still running"

# ── Source ──────────────────────────────────────────────────────────────────────
info "Source"
# Installing FROM a git clone makes src/ a protected checkout for the fixed privileged updater.
# No flags or GitHub authentication are needed; future fetches use anonymous HTTPS
# (configure_public_source below). A non-git source is refused below (the
# dist-tarball/rsync path is retired).
# We run as root; if the operator's clone is owned by another user, git's
# dubious-ownership guard would make rev-parse + clone fail and SILENTLY drop us to the
# dist path (no checkout and no Updates button). Mark it safe up front so
# a real clone always takes the git path; the phase-21 post-install verification catches any residue.
git config --global --add safe.directory "$REPO_DIR" 2>/dev/null || true
git config --global --add safe.directory "$REPO_DIR/.git" 2>/dev/null || true
# git-deploy is the only install path now; dist-rsync is retired.
# REPO_DIR must be a git checkout, or we FAIL LOUDLY rather than silently degrade.
if [[ "$REPO_DIR" == "$INSTALL_DIR/src" ]]; then
    # Running from the installed checkout itself (in-place upgrade). Source + git
    # remote are already wired — do NOT re-run git ops here (src may be transiently root-owned
    # mid-install, which would trip git's dubious-ownership guard and abort with services stopped).
    # The final authority pass below normalizes the public origin and removes credential helpers.
    info "Running from the installed checkout — source already in place."
    REQ_FILE="$CFM_RUNTIME_ROOT/installer/requirements-server.txt"
elif git -C "$REPO_DIR" rev-parse --is-inside-work-tree &>/dev/null; then
    if [[ -d "$INSTALL_DIR/src/.git" ]]; then
        # An administrator running an EXTERNAL checkout chose that checkout as this invocation's
        # payload.  Leaving an older deployed tree in place makes the new installer drive the old
        # lifecycle package -- the exact script/product skew the Windows lane already refuses.
        # Fetch only the committed HEAD from the local checkout (no network, no working-tree edits),
        # verify what arrived, and make the deployed tree agree before any installed Python runs.
        # Before changing that tree, prove the CURRENT deployed source/venv pair still agrees. This
        # narrowly permits a read-only preflight/fetch failure to restore the old service; the
        # in-place updater cannot make this claim because it may already have advanced source.
        _cfm_old_bound="$(sudo -u "$SERVICE_USER" -H env -u PYTHONPATH \
            "$INSTALL_DIR/venv/bin/python" -c \
            'import corpusfm; print(corpusfm.__file__)' 2>/dev/null || true)"
        case "$_cfm_old_bound" in
            "$INSTALL_DIR/src/"*) QUIESCE_RESTORE_READY=true ;;
        esac
        [[ -z "$(git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" \
            status --porcelain --untracked-files=no)" ]] \
            || die "the deployed checkout has modified tracked files; refusing to replace them"
        _cfm_source_head="$(git -C "$REPO_DIR" -c safe.directory='*' rev-parse HEAD)" \
            || die "could not resolve the external checkout's committed HEAD"
        if [[ -n "$CFM_DEPLOYED_HEAD_BEFORE" ]]; then
            _cfm_deployed_head_now="$(git -c safe.directory="$INSTALL_DIR/src" \
                -C "$INSTALL_DIR/src" rev-parse HEAD 2>/dev/null || true)"
            [[ "$_cfm_deployed_head_now" == "$CFM_DEPLOYED_HEAD_BEFORE" ]] \
                || die "the deployed checkout changed after the package was approved; refusing to replace it"
        fi
        info "Existing git checkout — advancing it to the selected local payload ($_cfm_source_head)..."
        git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" \
            fetch -q --no-tags "$REPO_DIR" HEAD \
            || die "could not import the selected local payload into the deployed checkout"
        _cfm_fetched_head="$(git -c safe.directory="$INSTALL_DIR/src" \
            -C "$INSTALL_DIR/src" rev-parse FETCH_HEAD)" \
            || die "the imported local payload has no readable commit"
        [[ "$_cfm_fetched_head" == "$_cfm_source_head" ]] \
            || die "the imported local payload does not match the selected checkout"
        QUIESCE_RESTORE_READY=false  # the first deployed-byte mutation follows
        git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" \
            reset -q --hard "$_cfm_source_head" \
            || die "could not advance the deployed checkout to the selected local payload"
        [[ "$(git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" rev-parse HEAD)" \
            == "$_cfm_source_head" ]] \
            || die "the deployed checkout did not advance to the selected local payload"
        # The package import above names FETCH_HEAD, not origin/main. On an upgrade that left the
        # remote-tracking ref at the pre-upgrade commit while HEAD and the build stamp advanced to
        # the verified package commit. The Settings page's read-only update classification then
        # compared the new HEAD with that stale ref and reported a false divergent tree immediately
        # after a successful upgrade. Align the cached tracking ref to the SAME already-verified
        # commit; the privileged updater's next network observation may advance it normally.
        git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" \
            update-ref "refs/remotes/origin/$GIT_TRACKED_BRANCH" "$_cfm_source_head" \
            || die "could not align origin/$GIT_TRACKED_BRANCH with the verified deployed payload"
        [[ "$(git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" \
            rev-parse "origin/$GIT_TRACKED_BRANCH")" == "$_cfm_source_head" ]] \
            || die "origin/$GIT_TRACKED_BRANCH did not read back at the verified deployed payload"
    else
        info "Git clone detected — wiring src/ for the in-app Updates button..."
        # Seed src/ from the operator's LOCAL clone (offline; committed $GIT_TRACKED_BRANCH only,
        # not their working-tree edits). Move only .git in, then restore the tree —
        # untracked runtime dirs (archive/, logs/) survive.
        TMP=$(mktemp -d)
        git clone -q --local --no-hardlinks "$REPO_DIR" "$TMP/repo" \
            || die "could not local-clone $REPO_DIR"
        mv "$TMP/repo/.git" "$INSTALL_DIR/src/.git"; rm -rf "$TMP"
        chown -R root:"$SERVICE_USER" "$INSTALL_DIR/src"
        # Ordering matters: make the durable public origin and promisor markers usable
        # BEFORE the tree reset — a reset to an older --ref whose tree holds a blob this blobless seed
        # deferred must be able to lazy-fetch that blob (which lives ONLY at the durable origin — the temp
        # bootstrap is itself blobless), or it would fail and silently fall back to HEAD/main.
        # 1) Origin = the plain public HTTPS repo URL (no token and no SSH).
        git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" remote set-url origin "$REPO_URL"
        # 2) If the SEED ($REPO_DIR) was a blobless partial clone — the bare-installer bootstrap path
        #    (packet 1172) — the `git clone --local --no-hardlinks` above copied its partial object store
        #    but DROPPED the promisor config, so src/ would treat its deferred historical blobs as
        #    corruption (failed lazy fetch, fsck broken links). Restore the exact markers a native
        #    --filter clone carries, promisor remote = the DURABLE HTTPS origin just set above (never the
        #    deleted bootstrap temp). No-op for a full operator clone (no partialclonefilter to propagate).
        _seed_filter="$(git -C "$REPO_DIR" config --get remote.origin.partialclonefilter 2>/dev/null || true)"
        if [[ -n "$_seed_filter" ]]; then
            git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" config core.repositoryformatversion 1
            git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" config extensions.partialClone origin
            git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" config remote.origin.promisor true
            git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" config remote.origin.partialclonefilter "$_seed_filter"
            # 3) Normalize anonymous public access now so a deferred-blob reset can fetch.
            configure_public_source || true
        fi
        # 4) Restore the requested ref's tree — after the durable origin and promisor markers
        #    are in place, so a deferred-blob ref resolves instead of silently degrading to HEAD.
        git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" reset -q --hard "$GIT_TRACKED_BRANCH" 2>/dev/null \
            || git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" reset -q --hard HEAD
    fi
    # Root owns the deployed code; the service group only reads it (packet 1246-03). The old rule
    # here was the opposite -- "the service user must own src BEFORE its git ops" -- because those
    # git ops ran as the service. They run as root now, so the ownership that made them work is
    # exactly the ownership that let a compromised service replace its own code.
    chown -R root:"$SERVICE_USER" "$INSTALL_DIR/src"
    # g-w is the whole property: the service group reads and traverses, and cannot write. Deliberately
    # NOT a blanket `chmod 640` -- that strips the executable bit from the installer scripts inside the
    # deployed tree, and the in-place upgrade re-execs itself from exactly there.
    chmod -R g-w,o-rwx "$INSTALL_DIR/src"
    # Git rejects a root-owned checkout when the service invokes even read-only commands unless a
    # protected configuration names that exact tree as safe. Install the service HOME's global
    # trust record as root-owned/read-only; do not rely on `-c safe.directory` in verification,
    # because application callers do not receive that command-line exception.
    git config --file "$INSTALL_DIR/.gitconfig" --replace-all safe.directory "$INSTALL_DIR/src"
    chown root:"$SERVICE_USER" "$INSTALL_DIR/.gitconfig"
    chmod 640 "$INSTALL_DIR/.gitconfig"
    REQ_FILE="$CFM_RUNTIME_ROOT/installer/requirements-server.txt"
    ok "Git checkout ready — privileged updates will fetch origin/$GIT_TRACKED_BRANCH anonymously"
else
    die "CORPUSfm requires a verified Series 2 package or a complete public Git checkout. If this checkout belongs to another user, run 'git config --global --add safe.directory $REPO_DIR' and re-run."
fi

# Detect + clear a stale leftover from the retired dist-rsync path: requirements-server.txt at the
# src ROOT (the git layout uses installer/requirements-server.txt). Warn + remove so a box that was
# once dist-installed is flagged. (corpusfm/_build.txt is NOT stale — it is the version stamp the
# running service reads; the installer writes it below.)
for _stale in "$INSTALL_DIR/src/requirements-server.txt"; do
    if [[ -f "$_stale" ]]; then
        warn "Stale dist-install leftover detected — removing: $_stale"
        rm -f "$_stale"
    fi
done

# ── Version stamp ──────────────────────────────────────────────────────────────────
# Write the declared public release build to corpusfm/_build.txt so the RUNNING SERVICE reads its
# version from a file instead of shelling out to git at runtime — git on the service's PATH is not
# guaranteed (the 0.0 class of bug). git stays the dev fallback. Written here (shell, no venv needed)
# as the service user so ownership is correct; on the installer's post-self-pull pass it reflects the
# final deployed HEAD. (corpusfm/_build.txt is gitignored — an untracked runtime file.)
if [[ -d "$INSTALL_DIR/src/.git" ]]; then
    _BUILD="$(tr -d ' \t\r\n' < "$INSTALL_DIR/src/release-build.txt" 2>/dev/null || true)"
    CFM_BUILD_COMMIT="$(git -c safe.directory="$INSTALL_DIR/src" -C "$INSTALL_DIR/src" rev-parse HEAD 2>/dev/null || true)"
    if [[ "$_BUILD" =~ ^[1-9][0-9]*$ ]]; then
        CFM_BUILD_VERSION="0.$_BUILD"
        printf '%s\n' "$_BUILD" > "$INSTALL_DIR/src/corpusfm/_build.txt"
        chown root:"$SERVICE_USER" "$INSTALL_DIR/src/corpusfm/_build.txt"
        chmod 640 "$INSTALL_DIR/src/corpusfm/_build.txt"
        ok "Version stamp written (0.$_BUILD)"
    else
        die "The published source has no valid release-build.txt identity."
    fi
fi
if [[ -n "$CFM_INSTALLER_SERIES" ]]; then
    [[ "$CFM_PACKAGE_APPLICATION_VERSION" == "$CFM_BUILD_VERSION" \
       && "$CFM_PACKAGE_COMMIT" == "$CFM_BUILD_COMMIT" ]] || die \
        "the verified installer bundle describes $CFM_PACKAGE_APPLICATION_VERSION @ $CFM_PACKAGE_COMMIT,
     but the deployed source is $CFM_BUILD_VERSION @ $CFM_BUILD_COMMIT; refusing to publish a mixed installation."
    CFM_INSTALLER_SOURCE=package
else
    CFM_INSTALLER_SERIES=series-2
    CFM_INSTALLER_VERSION="$CFM_BUILD_VERSION"
    CFM_INSTALLER_SOURCE=development
fi
CFM_INSTALLER_BUNDLE_PROTOCOL=1

# ── Series 2 runtime assets (packet 1257) ─────────────────────────────────────────
# The storage database, the paired add-on distribution and the four seed envelopes no longer travel
# inside the application Git bundle — they are a separate, digest-covered payload built from two
# pinned asset repositories at package construction.
#
# THEY GO IN A SIBLING OF THE CHECKOUT, NEVER INSIDE IT. Placing them under `src/` made them
# untracked content in a Git working tree, and `tree_inspection` refuses ANY untracked path so that
# a privileged update never builds on something git cannot account for. Measured on fms-dev at
# 0.2438: every provider composed, then phase 20 refused with 33 "untracked content that is not an
# installer artifact" problems and the services were never started. Widening that allowlist was
# considered and rejected — the checkout is on the service's import path, so the fix is to keep
# non-source bytes out of it, not to teach the gate to ignore them.
if [[ -n "$CFM_INSTALLER_SERIES" ]]; then
    _cfm_assets="$SCRIPT_DIR/corpusfm-assets.zip"
    [[ -f "$_cfm_assets" ]] || die "the verified installer package carries no Series 2 asset payload."
    _cfm_assets_tmp="$(mktemp -d)"
    unzip -q -o "$_cfm_assets" -d "$_cfm_assets_tmp" \
        || { rm -rf "$_cfm_assets_tmp"; die "the Series 2 asset payload could not be opened."; }
    for _cfm_a in db addon; do
        [[ -d "$_cfm_assets_tmp/$_cfm_a" ]] \
            || { rm -rf "$_cfm_assets_tmp"; die "asset payload is missing its $_cfm_a content."; }
        rm -rf "${INSTALL_DIR:?}/$CFM_ASSETS_DIRNAME/$_cfm_a"
        mkdir -p "$INSTALL_DIR/$CFM_ASSETS_DIRNAME/$_cfm_a"
        cp -a "$_cfm_assets_tmp/$_cfm_a/." "$INSTALL_DIR/$CFM_ASSETS_DIRNAME/$_cfm_a/"
    done
    rm -rf "$_cfm_assets_tmp"
    # Administrator-owned, application-READABLE, application-NOT-writable: the service reads seeds
    # and the add-on distribution, and must never be able to rewrite what it is seeded from.
    chown -R root:"$SERVICE_USER" "$INSTALL_DIR/$CFM_ASSETS_DIRNAME"
    chmod -R u=rwX,g=rX,o= "$INSTALL_DIR/$CFM_ASSETS_DIRNAME"
    [[ -f "$INSTALL_DIR/$CFM_ASSETS_DIRNAME/db/CORPUSfm_DB.fmp12" \
       && -f "$INSTALL_DIR/$CFM_ASSETS_DIRNAME/addon/CORPUSfm_ADDON.fmaddon" \
       && -d "$INSTALL_DIR/$CFM_ASSETS_DIRNAME/addon/CORPUSfm_ADDON" ]] \
        || die "Series 2 runtime assets are not present after placement."
    # The checkout must carry NO asset content. Asserted here rather than trusted, because the whole
    # 0.2438 failure was assets sitting where the eligibility gate would later find them.
    [[ ! -e "$INSTALL_DIR/src/db" && ! -e "$INSTALL_DIR/src/addon" ]] \
        || die "asset content is present inside the deployed checkout; refusing to publish an installation a privileged update would reject."
    CFM_ASSETS_PAYLOAD_SHA256="$(sha256sum "$_cfm_assets" | cut -d' ' -f1)"
    ok "Series 2 runtime assets placed ($CFM_ASSETS_DIRNAME/db, $CFM_ASSETS_DIRNAME/addon; payload ${CFM_ASSETS_PAYLOAD_SHA256:0:12})"
fi

# ── Anonymous public HTTPS source ────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR/src/.git" ]]; then
    info "Configuring anonymous public update source..."
    configure_public_source || die "The public update source could not be configured."
    verify_public_source || die "The public update source could not be read anonymously."
    ok "Public update source configured (CORPUSfm/CORPUSfm)."
fi

# ── Activate the staged runtime (swap the freshly-built venv into place) ───────────
# The bundled Python + the replacement venv were built into staging paths ABOVE, before the
# service was stopped — so a runtime-prep failure could never take the old app down. Services are
# stopped now (upgrade) / not yet started (fresh), so the swap is safe. Always replaced (recreate
# the venv every upgrade). The venv references $PY_HOME, so the swap is purely a directory move.
info "Python Environment"
[[ -x "$VENV_STAGE/bin/python" ]] || die "Staged venv missing at $VENV_STAGE — runtime prep did not complete."
QUIESCE_RESTORE_READY=false
rm -rf "$INSTALL_DIR/venv"
mv "$VENV_STAGE" "$INSTALL_DIR/venv"
# The staged venv's console-script shebangs hardcode the staging path ($VENV_STAGE/bin/python);
# rewrite them to the live path so `venv/bin/pip` (and other entry-points) work after the move. The
# app + service only ever invoke `venv/bin/python -m …` (shebang-independent), but a self-consistent
# venv avoids a surprising "pip: cannot execute" for a maintainer. pyvenv.cfg / the python symlinks
# reference $PY_HOME (the versioned interpreter), not the venv path, so they are unaffected.
grep -rIlZ -- "$VENV_STAGE/bin/python" "$INSTALL_DIR/venv/bin" 2>/dev/null \
    | xargs -0 -r sed -i "s|$VENV_STAGE/bin/python|$INSTALL_DIR/venv/bin/python|g" 2>/dev/null || true
# Prune any superseded bundled-Python versions now that the live venv references $PY_FULL (keeps
# $PY_BASE from accumulating across future version bumps; a no-op on the common same-version run).
if [[ -d "$PY_BASE" ]]; then
    for _pyd in "$PY_BASE"/*; do
        [[ -d "$_pyd" && "$(basename "$_pyd")" != "$PY_FULL" ]] && rm -rf "$_pyd"
    done
fi
# Ensure the venv AND the bundled interpreter it references are readable by the service user.
chown -R root:"$SERVICE_USER" "$INSTALL_DIR/venv" "$PY_HOME"
chmod -R 750 "$INSTALL_DIR/venv" "$PY_HOME"

ok "Python environment ready (bundled CPython $PY_FULL active)"

# ── The venv's binding to the deployed source (packet 1246-10-04) ─────────────────
# `ExecStart=<venv>/bin/python -m corpusfm.app.web` cannot import an application that is not on the
# interpreter's path, and CORPUSfm is deliberately NOT pip-installed into the venv — a service that
# can rewrite the code it executes is the authority this layout exists to withhold. Every installer
# invocation passes `PYTHONPATH` explicitly; the rendered unit is the one caller that cannot,
# because its environment is a closed allowlist. Measured on fms-server 2026-08-08: both services
# failed `ModuleNotFoundError: No module named 'corpusfm'`, status 1, with canonical definitions.
#
# A `.pth` in the venv's own site-packages is the binding, and it belongs to the ADMINISTRATOR: the
# file is root-owned and service-unwritable, so the service gains a path it may read and may not
# redirect. The unit's environment is untouched — no PYTHONPATH, no HOME, no widened allowlist.
info "Source binding"
CFM_SITE_PACKAGES="$("$INSTALL_DIR/venv/bin/python" -c \
    'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null || true)"
[[ -n "$CFM_SITE_PACKAGES" && -d "$CFM_SITE_PACKAGES" ]] \
    || die "could not determine the venv's site-packages directory; refusing to guess it."
CFM_PTH="$CFM_SITE_PACKAGES/corpusfm-source.pth"
( umask 022; printf '%s\n' "$INSTALL_DIR/src" > "$CFM_PTH.tmp" )
[[ "$(cat "$CFM_PTH.tmp")" == "$INSTALL_DIR/src" ]] \
    || die "the source binding read back as something other than $INSTALL_DIR/src."
mv "$CFM_PTH.tmp" "$CFM_PTH"
chown root:"$SERVICE_USER" "$CFM_PTH"
chmod 0640 "$CFM_PTH"
# PROVEN AS THE SERVICE, WITH PYTHONPATH UNSET — the unit has no PYTHONPATH, so a check that
# inherited one would prove nothing about the thing that actually starts.
# Match the rendered unit's WorkingDirectory as well as its environment.  When an update is driven
# from an external checkout, Python otherwise places that checkout's current directory before the
# administrator-owned .pth and this proof rejects the correct installed binding for the wrong
# reason.
_cfm_bound="$(cd "$INSTALL_DIR" && sudo -u "$SERVICE_USER" -H env -u PYTHONPATH \
    "$INSTALL_DIR/venv/bin/python" -c \
    'import corpusfm; print(corpusfm.__file__)' 2>/dev/null || true)"
[[ -n "$_cfm_bound" ]] \
    || die "the service identity cannot import corpusfm from its own venv, so the services would
     fail to start. The source binding at $CFM_PTH did not take."
case "$_cfm_bound" in
    "$INSTALL_DIR/src/corpusfm/"*) ;;
    *) die "the service identity imports corpusfm from $_cfm_bound, which is not beneath
     $INSTALL_DIR/src. Refusing to start services against a source tree this installation does not
     own." ;;
esac
ok "Source binding established and proven as $SERVICE_USER ($CFM_PTH)"
QUIESCE_RESTORE_READY=true

# ── CLI wrapper ───────────────────────────────────────────────────────────────────
info "CLI"
info "Installing /usr/local/bin/corpusfm..."
cat > /usr/local/bin/corpusfm << WRAPPER
#!/usr/bin/env bash
# CORPUSfm CLI wrapper — generated by installer
export HOME=$INSTALL_DIR
export PYTHONPATH=$INSTALL_DIR/src
exec $INSTALL_DIR/venv/bin/python -m corpusfm.server.cli "\$@"
WRAPPER
chmod +x /usr/local/bin/corpusfm
ok "CLI available: corpusfm --help"

# ── Installed uninstaller ────────────────────────────────────────────────────────
# The public installer package deliberately exposes no standalone uninstaller. Its private source
# payload carries the launcher input, and installation turns that input into this installation's
# one canonical local entry point. The lifecycle runtime it invokes is the venv/source tree already
# installed and bound above. No download or Git operation belongs to the resulting uninstaller.
UNINSTALLER_PATH="$INSTALL_DIR/uninstall.sh"
UNINSTALLER_LIB="$INSTALL_DIR/_cfm_lib.sh"
install -m 0755 -o root -g root "$CFM_RUNTIME_ROOT/installer/linux/uninstall.sh" "$UNINSTALLER_PATH"
install -m 0644 -o root -g root "$CFM_RUNTIME_ROOT/installer/linux/_cfm_lib.sh" "$UNINSTALLER_LIB"
cmp -s "$CFM_RUNTIME_ROOT/installer/linux/uninstall.sh" "$UNINSTALLER_PATH" \
    || die "the installed uninstaller did not read back as the payload launcher."
cmp -s "$CFM_RUNTIME_ROOT/installer/linux/_cfm_lib.sh" "$UNINSTALLER_LIB" \
    || die "the installed uninstaller support library did not read back as the payload library."
[[ -x "$UNINSTALLER_PATH" ]] || die "the installed uninstaller is not executable: $UNINSTALLER_PATH"
ok "Installed uninstaller provisioned and read back ($UNINSTALLER_PATH)"

# ── Installed installer bootstrap ────────────────────────────────────────────────
# The downloaded package is caller-owned and may be removed after this run. Preserve the stable
# Series 2 acquisition/verification launcher inside the installation. Public release acquisition is
# anonymous, so the verified bootstrap is installed byte-for-byte and carries no secret.
INSTALLER_ENTRY_POINT="$INSTALL_DIR/bin/corpusfm-installer"
INSTALLER_BOOTSTRAP_SOURCE="$CFM_RUNTIME_ROOT/installer/bootstrap/linux/bootstrap.sh"
INSTALLER_BOOTSTRAP_STAGE="$INSTALL_DIR/bin/.corpusfm-installer.$$"
[[ -f "$INSTALLER_BOOTSTRAP_SOURCE" ]] \
    || die "the verified installer runtime carries no Linux bootstrap source."
mkdir -p "$INSTALL_DIR/bin"
install -m 0755 -o root -g root "$INSTALLER_BOOTSTRAP_SOURCE" "$INSTALLER_BOOTSTRAP_STAGE"
install -m 0755 -o root -g root "$INSTALLER_BOOTSTRAP_STAGE" "$INSTALLER_ENTRY_POINT"
rm -f "$INSTALLER_BOOTSTRAP_STAGE"
cmp -s "$INSTALLER_BOOTSTRAP_SOURCE" "$INSTALLER_ENTRY_POINT" \
    || die "the installed durable bootstrap did not read back byte-for-byte."
[[ "$(stat -c '%U:%G:%a' "$INSTALLER_ENTRY_POINT")" == "root:root:755" ]] \
    || die "the installed durable bootstrap is not root:root 0755."
ok "Durable public installer provisioned ($INSTALLER_ENTRY_POINT)"

# ── Scoped DB helper (co-located only; fresh AND upgrade) ────────────────────────
# The unprivileged service user cannot write the FMS Databases dir (owner fmserver).
# This installs a fixed-purpose root broker + a narrow NOPASSWD sudoers rule so the
# in-app sandbox/apply loop can place/copy-out/remove .fmp12 files there — the ONLY
# elevation the service gets. Co-located installs only (where a Databases dir exists);
# re-asserted on every run (idempotent). NOT installable by the in-app Updates button
# (that runs as the service user, no root) — this is why it lives in the installer.
if command -v fmsadmin &>/dev/null; then
    info "Scoped DB helper"
    HELPER_SRC="$CFM_RUNTIME_ROOT/installer/linux/cfm-db-helper.sh"
    HELPER_DST="$INSTALL_DIR/bin/cfm-db-helper"
    SUDOERS_DST="/etc/sudoers.d/corpusfm-db-helper"
    if [[ -f "$HELPER_SRC" ]]; then
        mkdir -p "$INSTALL_DIR/bin"
        install -m 0755 -o root -g root "$HELPER_SRC" "$HELPER_DST"
        SUDOERS_TMP="$(mktemp)"
        printf '%s ALL=(root) NOPASSWD: %s\n' "$SERVICE_USER" "$HELPER_DST" > "$SUDOERS_TMP"
        if visudo -cf "$SUDOERS_TMP" >/dev/null 2>&1; then
            install -m 0440 -o root -g root "$SUDOERS_TMP" "$SUDOERS_DST"
            ok "Scoped DB helper installed ($HELPER_DST; sudoers validated)"
        else
            warn "sudoers validation failed — DB helper NOT enabled (in-app sandbox/apply disabled)"
        fi
        rm -f "$SUDOERS_TMP"
    else
        warn "cfm-db-helper.sh not found in repo — skipping (in-app sandbox/apply disabled)"
    fi

    # Root-owned handoff dir for the TOCTOU-closed place() path (cfm-db-helper mkhandoff/rmhandoff).
    # root:root 0711 — the service can traverse INTO a handoff subdir to write its payload file but
    # can never create/rename entries here, so it cannot symlink-swap a place source. Idempotent.
    install -d -m 0711 -o root -g root /var/lib/corpusfm/handoff \
        && ok "Handoff dir provisioned (/var/lib/corpusfm/handoff; root:root 0711)" \
        || warn "could not provision /var/lib/corpusfm/handoff — place() falls back to the /tmp path"

    # ── CORPUSfm hosting folder (packet 1061; fresh AND upgrade) ─────────────────────
    # A formal FMS Additional Database Folder that hosts GENERATED .fmp12 files IN PLACE (no move into
    # the fmserver-owned Databases dir). corpusfm:fmsadmin 2775 setgid so: (a) fmserver can host the
    # files R/W (group-write) and (b) fmserver can create its own RC_Data_FMS bookkeeping (setgid group
    # + group-write); corpusfm keeps write to materialize new files. NOT deleted on uninstall when
    # non-empty (generated DBs are user work product). Idempotent. The lifecycle patch provider
    # registers and reads back the additional-folder slot at phase 16.
    info "CORPUSfm hosting folder"
    if install -d -o "$SERVICE_USER" -g fmsadmin "$HOSTING_DIR" 2>/dev/null && chmod 2775 "$HOSTING_DIR" 2>/dev/null; then
        # NOT recorded in install.yaml, and the call that tried to is GONE. `corpusfm set-hosting-dir`
        # was retired with the `hosting_dir` marker key by packet 1246-05-02 — "an install.yaml key is
        # a configured claim, and the compartment has to be a PROVEN one" (corpusfm/install.py). The
        # subcommand no longer exists, so the invocation failed on every install and printed a warning
        # whose remedy named the same retired command. The path is recorded where it now belongs:
        # `composition foundation` publishes it as `paths.patch_hosting_dir` (phase 11), and phase 16
        # proves the compartment. Nothing here has to persist anything.
        ok "Hosting folder provisioned ($HOSTING_DIR; corpusfm:fmsadmin 2775 setgid) — recorded in the installation manifest as patch_hosting_dir"
    else
        warn "Could not provision the hosting folder at '$HOSTING_DIR' (is the 'fmsadmin' group present?) — generated files fall back to the _generated/ quarantine + broker-promote."
    fi

    # ── CORPUSfm support folder (packet 1066; fresh AND upgrade) ─────────────────────
    # A named, FMS-auto-scanned SUBFOLDER of the Databases dir that homes CORPUSfm tooling files and is
    # one half of the apply COMPARTMENT (with the hosting folder). corpusfm:fmsadmin 2775 setgid so the
    # unprivileged service can stat it for the compartment membership check AND write files there
    # DIRECTLY (it owns the dir — no broker needed here, unlike the fmserver-owned top-level dir), while
    # fmserver (group fmsadmin) can scan + host from it. With the compartment restriction on (default), a
    # file hosted from here is a valid patch/apply target. Idempotent. (The sandbox slot stays on the
    # broker's top-level path for now — its physical relocation into this folder needs the broker to
    # write a subfolder and is deferred; the gate does not depend on it.)
    info "CORPUSfm support folder"
    SUPPORT_DIR="$FM_DB_DIR/CORPUSfm-Support"
    if install -d -o "$SERVICE_USER" -g fmsadmin "$SUPPORT_DIR" 2>/dev/null && chmod 2775 "$SUPPORT_DIR" 2>/dev/null; then
        # Same retirement as the hosting folder above: `corpusfm set-support-dir` and the `support_dir`
        # marker key went with packet 1246-05-02. The compartment is PROVEN by the patch provider at
        # phase 16, never claimed by a marker file, so the directory is all this step owes.
        ok "Support folder provisioned ($SUPPORT_DIR; corpusfm:fmsadmin 2775 setgid) — the apply compartment is proven at phase 16, not recorded here"
    else
        warn "Could not provision the support folder at '$SUPPORT_DIR' (is the 'fmsadmin' group present?) — the apply compartment will have only the hosting folder."
    fi

fi

# ── Retire the storage-swap capability (packet 085) ───────────────────────────────
# Its only app caller — the migrate-into-new-file storage engine — is deleted (085 is
# fresh-install-only; FileMaker moves the database and a Recovery File carries the Corpus Key). A NOPASSWD root grant with no consumer is
# pure attack surface, so remove the installed copy + grant a prior install left. Idempotent.
rm -f "$INSTALL_DIR/bin/cfm-storage-swap" /etc/sudoers.d/corpusfm-storage-swap 2>/dev/null || true

# ── Retire the scoped MCP control helper (obsolete with the folded-in MCP) ────────
# cfm-mcp-ctl brokered restart/port-reconcile for the standalone :8765 service. Folded in,
# there's no separate unit to restart and no port to reconcile.
# Remove the helper + its sudoers grant if a prior install left them. Idempotent.
rm -f "$INSTALL_DIR/bin/cfm-mcp-ctl" /etc/sudoers.d/corpusfm-mcp-ctl 2>/dev/null || true

# ── Deploy-decision helpers (packet 1238) ─────────────────────────────────────────
# `fm_db_hosted <name>` — 0 hosted / 1 not hosted / 2 COULD NOT ASK — lives in `_cfm_lib.sh`.
# It started here; the uninstaller needs the identical three-answer question (packet 1237), and one
# definition beats two. Its rationale travelled with it.
#
# Never write the shipped blank template over an existing file. A fresh install has nothing to
# overwrite, so a file at the destination means this run's premise is wrong — and on Linux there is
# no mandatory locking, so `cp` would open a live FMS-hosted .fmp12 O_TRUNC and rewrite the
# customer's artifacts, users, settings and AI keys underneath FileMaker Server's own descriptor.
# This guard is the load-bearing one: it holds even if the hosted check above is defeated.
# 0 = deployed, 1 = refused (destination exists), 2 = copy failed.
fm_deploy_template() {
    local src="$1" dest="$2"
    [[ -e "$dest" ]] && return 1
    cp "$src" "$dest" || return 2
    chmod 660 "$dest" 2>/dev/null || true
    return 0
}

# ── Preview temp cleanup ──────────────────────────────────────────────────────────
# Explorer/Diff write a self-contained HTML to /tmp/corpusfm_{explorer,diff}_* served via an
# in-memory task→path map. The app sweeps them (startup + on each generation), but this
# tmpfiles.d rule is the app-independent safety net: the already-running
# systemd-tmpfiles-clean.timer (daily) reclaims the space for any preview temp older than 6h.
# (systemd's default /tmp age is 30d — far too long for GB-sized previews accumulating daily.)
info "Preview temp cleanup"
info "Installing /etc/tmpfiles.d/corpusfm.conf..."
cat > /etc/tmpfiles.d/corpusfm.conf << 'TMPFILES'
# CORPUSfm — age out Explorer/Diff/patch preview temp artifacts (space reclaimed daily via
# systemd-tmpfiles-clean.timer). The app also sweeps these on startup + on each generation.
d /run/corpusfm 0750 corpusfm corpusfm -
e /tmp/corpusfm_explorer_* - - - 6h
e /tmp/corpusfm_diff_* - - - 6h
e /tmp/corpusfm_patch_* - - - 6h
TMPFILES
systemd-tmpfiles --create /etc/tmpfiles.d/corpusfm.conf 2>/dev/null || true
ok "Preview temp-cleanup rule installed (6h, via systemd-tmpfiles-clean.timer)"


# ═══ PHASE 11 — Foundation publication — generation 1 ═══════════════════════════════════

# The FIRST write of this installation. Publishes the manifest at generation 1 — the seven PathsBlock
# fields and the fixed web facts — reads it back, then publishes the locator. The installer supplies
# only the three paths it classified; the five OS locations come from the platform layout and the web
# facts are implementation constants, so neither appears in this request.
# FRESH vs UPDATE IS DECIDED BY THE PUBLISHED RECORD, NOT BY THE VENV (packet 1246-04-04,
# correction D). `$IS_UPGRADE` classifies the CODE installation — it is what decides that an upgrade
# never touches FileMaker — and it answered from `[[ -d $INSTALL_DIR/venv ]]`. A venv is not a
# published installation: a box whose record was never published, or was removed, has one. So the
# foundation runs for a genuinely UNPUBLISHED installation and for nothing else, and an update reads
# the generation the manifest actually holds.
#
# The old update branch set `CFM_GENERATION=1` unconditionally. On a box at generation 5 every
# provider then committed against `inspected_generation=1` and the manifest's own compare-and-swap
# refused — an update that could not complete on any installation that had ever been updated.
lc_load_os_layout
_lc_state="$("${CFM_LIFECYCLE[@]}" status --json 2>/dev/null || true)"
_lc_locator="$(lc_json_field "$_lc_state" locator)"
_lc_manifest="$(lc_json_field "$_lc_state" manifest)"
if [[ "$_lc_locator" != "present" ]]; then
    [[ "$_lc_locator" == "missing" || -z "$_lc_locator" ]] \
        || die "the installation locator reads '$_lc_locator'; refusing to publish a foundation over it."
    INSTALLATION_ID="$(cat /proc/sys/kernel/random/uuid)"
    [[ "$CFM_BUILD_VERSION" =~ ^0\.[0-9]+$ ]] \
        || die "the deployed checkout has no exact build version; refusing to publish an unidentified installation."
    [[ "$CFM_BUILD_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || die "the deployed checkout has no exact commit; refusing to publish an unidentified installation."
    _lc_req="$(lc_request foundation "$(printf '{"schema_version":1,"installation_id":"%s","install_dir":"%s","patch_hosting_dir":"%s","fms_root":"%s","version":"%s","commit":"%s","installer_series":"%s","installer_version":"%s","installer_bundle_protocol":%s,"installer_source":"%s","installer_entry_point":"%s","created_service_account":%s,"privilege_helpers":["/etc/sudoers.d/corpusfm-db-helper","/etc/sudoers.d/corpusfm-update","/etc/tmpfiles.d/corpusfm.conf"],"cli_shim":"/usr/local/bin/corpusfm","support_dir":"%s","uninstaller_path":"%s","actor":"installer"}' \
        "$INSTALLATION_ID" "$INSTALL_DIR" "$HOSTING_DIR" "$FMS_ROOT" \
        "$CFM_BUILD_VERSION" "$CFM_BUILD_COMMIT" "$CFM_INSTALLER_SERIES" \
        "$CFM_INSTALLER_VERSION" "$CFM_INSTALLER_BUNDLE_PROTOCOL" "$CFM_INSTALLER_SOURCE" \
        "$INSTALLER_ENTRY_POINT" \
        "$CREATED_SERVICE_ACCOUNT" "$SUPPORT_DIR" \
        "$UNINSTALLER_PATH")")"
    _lc_out="$(lc_run "foundation publication" composition foundation --request "$_lc_req")"
    CFM_GENERATION="$(lc_json_field "$_lc_out" generation)"
    [[ "$CFM_GENERATION" == "1" ]] || die "foundation published generation '$CFM_GENERATION', expected 1."
    [[ "$(lc_json_field "$_lc_out" uninstaller_path)" == "$UNINSTALLER_PATH" ]] \
        || die "foundation did not read back the canonical installed uninstaller."
    [[ "$(lc_json_field "$_lc_out" installer_entry_point)" == "$INSTALLER_ENTRY_POINT" ]] \
        || die "foundation did not read back the canonical installed installer."
    ok "Installation record published at generation 1 ($INSTALLATION_ID)"
else
    # UPDATE. The record must agree with THIS invocation before a single provider runs: an
    # installation record naming another directory is not this installation, and composing into it
    # would move another installation's manifest.
    [[ "$_lc_manifest" == "valid" ]] \
        || die "this installation's manifest reads '$_lc_manifest'; refusing to update over it."
    INSTALLATION_ID="$(lc_json_field "$_lc_state" installation_id)"
    _lc_recorded_dir="$(lc_json_field "$_lc_state" install_dir)"
    CFM_GENERATION="$(lc_json_field "$_lc_state" generation)"
    [[ -n "$INSTALLATION_ID" ]] || die "this installation publishes no identity; refusing to update it."
    [[ "$_lc_recorded_dir" == "$INSTALL_DIR" ]] \
        || die "the published installation is at '$_lc_recorded_dir', this invocation installs to
     '$INSTALL_DIR'. Refusing to compose into another installation's record."
    [[ "$CFM_GENERATION" =~ ^[0-9]+$ && "$CFM_GENERATION" -ge 1 ]] \
        || die "the published manifest reports generation '$CFM_GENERATION'; refusing to update it."
    _lc_req="$(lc_request publish-installer "$(printf '{"schema_version":1,"installation_id":"%s","expected_generation":%s,"install_dir":"%s","version":"%s","commit":"%s","installer_series":"%s","installer_version":"%s","installer_bundle_protocol":%s,"installer_source":"%s","installer_entry_point":"%s","actor":"installer"}' \
        "$INSTALLATION_ID" "$CFM_GENERATION" "$INSTALL_DIR" "$CFM_BUILD_VERSION" \
        "$CFM_BUILD_COMMIT" "$CFM_INSTALLER_SERIES" "$CFM_INSTALLER_VERSION" \
        "$CFM_INSTALLER_BUNDLE_PROTOCOL" "$CFM_INSTALLER_SOURCE" "$INSTALLER_ENTRY_POINT")")"
    _lc_out="$(lc_run "installer identity publication" composition publish-installer --request "$_lc_req")"
    CFM_GENERATION="$(lc_json_field "$_lc_out" generation)"
    [[ "$CFM_GENERATION" =~ ^[0-9]+$ && "$CFM_GENERATION" -ge 1 ]] \
        || die "installer identity publication returned invalid generation '$CFM_GENERATION'."
    [[ "$(lc_json_field "$_lc_out" installer_entry_point)" == "$INSTALLER_ENTRY_POINT" ]] \
        || die "installer identity publication did not read back the canonical installed installer."
    ok "Existing installation record verified and installer identity published ($INSTALLATION_ID at generation $CFM_GENERATION)"
fi

# ═══ PHASE 12 — Machine and Corpus keys — through published authority ═══════════════════
# ── At-rest encryption keys (materialize AS THE SERVICE USER, once) ─────────────────
# TWO keys, never crossed (split packet 1007; named packet 1246-02):
#   corpus.key  — the Corpus Key. Encrypts everything the CORPUS owns. It is PORTABLE: a Recovery
#                 File carries it, and only it, to another machine.
#   machine.key — the Machine Key. Encrypts what belongs to THIS installation (the FMS PKI private
#                 key). Never exported, never carried by a Recovery File, never replaced by an
#                 adoption — which is what keeps a box's own PKI working after its corpus moves.
# crypto.get_corpus_key()/get_machine_key() write $HOME/.corpusfm/{corpus,machine}.key on first use. Later
# installer Python runs as ROOT with HOME=$INSTALL_DIR (e.g. PKI registration) — if one of those is the
# first to touch encryption, it creates a key as root:root and the service can never decrypt it. So
# create BOTH now as $SERVICE_USER. On upgrades they already exist and are simply reused.
# An installation made before the 1246-02 naming holds its keys under the old names, and the key
# resolver reads those. So the guard tests BOTH names: seeing only the old pair must not look like
# "no keys" and mint a fresh Corpus Key beside a corpus that is already encrypted under the old one.
# THE PRIVILEGED INSTALLER PROVISIONS THESE, and the two guards this replaced could not (measured on
# fms-server, 2026-08-08). They tested `$INSTALL_DIR/.corpusfm/{corpus,secret,machine,server}.key` —
# the RETIRED home — so on a published 1246-03 installation they read a directory the resolver no
# longer uses and reported "no keys" beside a perfectly good one. Worse, the creation ran as
# $SERVICE_USER, and the FIXED secrets directory is administrator-owned and deliberately NOT
# service-writable: `machine.key` could not be created, the failure downgraded to a warning, and
# phase 15 then refused with `prerequisite_required: authoritative_machine_key`. There is no later
# "first use" — nothing in the runtime writes there. A fresh install could not complete.
#
# So this runs as ROOT, through the published authority, and it is FATAL. The rules it enforces —
# the Corpus Key is irreplaceable and is never generated beside an existing corpus; the Machine Key
# is replaceable and is generated when absent; neither retired filename is consulted — live in
# `corpusfm.lifecycle.key_provisioning`, not in this script.
_lc_req="$(lc_request provision-keys "$(printf '{"schema_version":1,"actor":"installer","flavour":"posix","service_account":"%s","database_name":"%s","database_search_dirs":%s}' \
    "$SERVICE_USER" "$FM_DATABASE" "$(lc_json_array "$FM_DB_DIR" "$HOSTING_DIR")")")"
lc_run "key provisioning" provision-keys --request "$_lc_req" >/dev/null
ok "Corpus and Machine keys established at $CFM_SECRETS_DIR and proven through the published resolvers"

# ── Install marker ────────────────────────────────────────────────────────────────
# The application owns this mutable runtime marker. Its path comes from the published OS layout;
# `$INSTALL_DIR/.corpusfm/install.yaml` is the retired pre-1246 home and is not a runtime fallback.
INSTALL_YAML="$CFM_CONFIG_DIR/install.yaml"
if [[ ! -f "$INSTALL_YAML" ]]; then
    info "Install Marker"
    info "Writing install.yaml through the application marker authority..."
    # `/etc/corpusfm` remains administrator-owned. Pre-create the one application-owned file at
    # 0600 so secure_fs can write it in place as the service without granting directory mutation.
    install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" /dev/null "$INSTALL_YAML"
    cfm_run "write install marker" sudo -u "$SERVICE_USER" -H \
        env PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" -c \
        "from corpusfm.install import write_install_marker; write_install_marker('server', '1.0')" \
        || die "Could not write the current installation marker at $INSTALL_YAML."
fi

# Prove the running identity sees this exact published path and reads server mode. The write test is
# also required: Settings owns the mutable fields in this file and rewrites it in place.
_CFM_MARKER_READBACK="$(sudo -u "$SERVICE_USER" -H env PYTHONPATH="$INSTALL_DIR/src" \
    "$INSTALL_DIR/venv/bin/python" -c \
    'from corpusfm.install import marker_path, read_install_config; c = read_install_config(); print(marker_path()); print(c.get("mode", ""))' \
    2>>"$CFM_LOG")" || die "The $SERVICE_USER service account could not read the installation marker."
_CFM_MARKER_PATH="${_CFM_MARKER_READBACK%%$'\n'*}"
_CFM_MARKER_MODE="${_CFM_MARKER_READBACK##*$'\n'}"
[[ "$_CFM_MARKER_PATH" == "$INSTALL_YAML" ]] \
    || die "The application resolves install.yaml at $_CFM_MARKER_PATH, not $INSTALL_YAML."
[[ "$_CFM_MARKER_MODE" == "server" ]] \
    || die "The installation marker reports mode '$_CFM_MARKER_MODE', not server."
sudo -u "$SERVICE_USER" -H test -w "$INSTALL_YAML" \
    || die "The installation marker is not writable by the $SERVICE_USER service account."
[[ "$(stat -c '%U:%G %a' "$INSTALL_YAML")" == "$SERVICE_USER:$SERVICE_USER 600" ]] \
    || die "The installation marker is not protected as $SERVICE_USER:$SERVICE_USER 0600."
ok "Install marker read back as server at $INSTALL_YAML (service-owned 0600)"

# ── Asset root readback (packet 1257) ─────────────────────────────────────────────
# Read the asset root back through the APPLICATION's own resolver, not by restating the path this
# script used. That is the whole point: the installer places bytes and the application derives their
# location from the published install root, so a readback that recomputed the path locally would
# agree with itself and prove nothing. It runs here because it needs the published record, which
# phase 11 wrote. The service user performs it — if the account that must READ the seeds cannot,
# this installation is not usable regardless of what root can see.
if [[ -n "$CFM_INSTALLER_SERIES" ]]; then
    _cfm_seen_assets="$(sudo -u "$SERVICE_USER" -H "$INSTALL_DIR/venv/bin/python" -c \
        'from corpusfm.lifecycle import app_paths; print(app_paths.assets_dir())' 2>/dev/null || true)"
    [[ "$_cfm_seen_assets" == "$INSTALL_DIR/$CFM_ASSETS_DIRNAME" ]] \
        || die "the application resolves its asset root to '${_cfm_seen_assets:-<unresolved>}', not $INSTALL_DIR/$CFM_ASSETS_DIRNAME."
    sudo -u "$SERVICE_USER" -H test -r "$_cfm_seen_assets/db/CORPUSfm_DB.fmp12" \
        || die "the service account cannot read the placed storage-database template."
    sudo -u "$SERVICE_USER" -H test -r "$_cfm_seen_assets/addon/CORPUSfm_ADDON.fmaddon" \
        || die "the service account cannot read the placed add-on package."
    # Application-READABLE, application-NOT-writable.
    ! sudo -u "$SERVICE_USER" -H test -w "$_cfm_seen_assets/db/CORPUSfm_DB.fmp12" \
        || die "the placed assets are writable by the service account; they are administrator-owned."
    ok "Asset root read back by the application at $_cfm_seen_assets (payload sha256 $CFM_ASSETS_PAYLOAD_SHA256; read-only to $SERVICE_USER)"
fi


# ═══ PHASE 13 — Render and install the privileged updater ═══════════════════════════════
# ── Privileged one-shot updater (packet 1246-03) ─────────────────────────────────
# The in-app Updates button no longer pulls into the checkout the service is running from. It writes
# a request and triggers ONE fixed unit; everything else is decided by root. The service's whole
# grant is `systemctl start corpusfm-update.service` - no path, no ref, no command, no environment.
info "Privileged one-shot updater"
UPDATER_SRC="$CFM_RUNTIME_ROOT/installer/linux/corpusfm-update.sh"
UPDATER_DST="$INSTALL_DIR/bin/corpusfm-update"
if [[ -f "$UPDATER_SRC" ]]; then
    mkdir -p "$INSTALL_DIR/bin"
    # ── THE ADMINISTRATOR-OWNED LIBRARY AND ENTRY POINTS (correction R6) ──────────
    # The renderer emits `<install>/bin/tree_inspection.py`, `<install>/bin/publish_outcome.py`,
    # `<install>/bin/bytecode_cleanup.py` and
    # `<install>/lib`. **Linux created none of them**, so the rendered updater refused on every
    # trigger and the in-app update path was installed and inert. Windows has created all three
    # since its conversion; this is the Linux half of the same requirement.
    #
    # OUTSIDE THE CHECKOUT, deliberately (R7b). Both updaters used to put the checkout on PYTHONPATH
    # and run `-m corpusfm.lifecycle.tree_inspection`, so a modified helper inside a modified tree
    # declared that tree clean. The judge and the publisher must not live in what they judge.
    #
    # STAGED THEN REPLACED. A half-copied library under an elevated script is worse than none: the
    # updater would import part of a package. Each is written beside its target and moved into place,
    # and `mv` within one filesystem is atomic.
    _cfm_lib_stage="$INSTALL_DIR/lib.staging.$$"
    rm -rf "$_cfm_lib_stage"
    mkdir -p "$_cfm_lib_stage"
    cp -a "$INSTALL_DIR/src/corpusfm" "$_cfm_lib_stage/corpusfm" \
        || die "could not stage the administrator-owned library for the privileged updater"
    [[ -d "$_cfm_lib_stage/corpusfm/lifecycle" ]] \
        || die "the staged library holds no corpusfm/lifecycle — refusing to install an updater that
     would load its own judge from the checkout it judges"
    rm -rf "$INSTALL_DIR/lib"
    mv "$_cfm_lib_stage" "$INSTALL_DIR/lib"
    for _cfm_entry in tree_inspection.py:tree_inspection.py outcome_publisher.py:publish_outcome.py bytecode_cleanup.py:bytecode_cleanup.py; do
        _cfm_from="$INSTALL_DIR/src/corpusfm/lifecycle/${_cfm_entry%%:*}"
        _cfm_to="$INSTALL_DIR/bin/${_cfm_entry##*:}"
        install -m 0644 -o root -g root "$_cfm_from" "$_cfm_to.tmp" \
            || die "could not install $_cfm_to for the privileged updater"
        mv "$_cfm_to.tmp" "$_cfm_to"
    done
    # ADMINISTRATOR-OWNED, NOT SERVICE-WRITABLE. The updater runs as root and loads these; a service
    # identity that could write them could choose what judges its own checkout.
    chown -R root:root "$INSTALL_DIR/lib" "$INSTALL_DIR/bin"
    chmod -R go-w "$INSTALL_DIR/lib" "$INSTALL_DIR/bin"
    # READ BACK BEFORE RENDERING. A path the renderer will bake into a root script must exist now,
    # be owned by root, and not be group- or world-writable — checked, not assumed.
    for _cfm_owned in "$INSTALL_DIR/lib/corpusfm/lifecycle/tree_inspection.py" \
                      "$INSTALL_DIR/bin/tree_inspection.py" \
                      "$INSTALL_DIR/bin/publish_outcome.py" \
                      "$INSTALL_DIR/bin/bytecode_cleanup.py"; do
        [[ -f "$_cfm_owned" ]] || die "$_cfm_owned was not installed; refusing to render an updater
     that would name a path with nothing at it"
        [[ "$(stat -c '%U' "$_cfm_owned")" == "root" ]] \
            || die "$_cfm_owned is not root-owned; refusing to render an updater that loads it"
        [[ -z "$(find "$_cfm_owned" -perm /022 -print -quit)" ]] \
            || die "$_cfm_owned is group- or world-writable; refusing to render an updater that
     loads it"
    done
    ok "Administrator-owned library + entry points installed ($INSTALL_DIR/lib, $INSTALL_DIR/bin)"
    # RENDERED BY THE SHIPPED RENDERER, not by this script (packet 1246-04-04, correction F).
    #
    # This used to be a five-expression `sed` over a template carrying NINE placeholders. The four
    # it never wrote — @@HELPER@@, @@PUBLISHER@@, @@LIB_DIR@@, @@GIT@@ — survived into the installed
    # artifact as literal paths, and the `grep -q '@@'` below is what caught it: the install died
    # here rather than installing a root script that would have run `@@GIT@@`. A second renderer is
    # how a template gains a placeholder its installer does not know about.
    #
    # The verified package runtime supplies the template bytes. The application renderer derives
    # every installation-specific value from the published record; the installer supplies no path
    # substitution and cannot aim the resulting elevated artifact elsewhere.
    HOME="$INSTALL_DIR" PYTHONPATH="$INSTALL_DIR/src" \
        "$INSTALL_DIR/venv/bin/python" - "$UPDATER_SRC" "$UPDATER_DST.tmp" <<'RENDER' \
        || die "the one-shot updater could not be rendered from this installation's own record"
import sys
from corpusfm.lifecycle.update_boundary import render_linux_updater
with open(sys.argv[1], encoding="utf-8") as source:
    rendered = render_linux_updater(source.read())
with open(sys.argv[2], "w", encoding="utf-8") as target:
    target.write(rendered)
RENDER
    # Belt and braces. The renderer already refuses on a surviving placeholder, but it only knows
    # the nine it derives — this catches a TENTH one added to the template and to nothing else.
    if grep -q '@@' "$UPDATER_DST.tmp"; then
        rm -f "$UPDATER_DST.tmp"
        die "the one-shot updater still has unrendered placeholders — refusing to install it"
    fi
    install -m 0755 -o root -g root "$UPDATER_DST.tmp" "$UPDATER_DST"
    rm -f "$UPDATER_DST.tmp"
    cat > /etc/systemd/system/corpusfm-update.service << UNIT
[Unit]
Description=CORPUSfm one-shot code update

[Service]
Type=oneshot
User=root
ExecStart=$UPDATER_DST
UNIT
    UPD_SUDOERS_TMP="$(mktemp)"
    printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl start corpusfm-update.service\n' \
        "$SERVICE_USER" > "$UPD_SUDOERS_TMP"
    if visudo -cf "$UPD_SUDOERS_TMP" >/dev/null 2>&1; then
        install -m 0440 -o root -g root "$UPD_SUDOERS_TMP" /etc/sudoers.d/corpusfm-update
        systemctl daemon-reload 2>/dev/null || true
        ok "One-shot updater installed ($UPDATER_DST; sudoers validated)"
    else
        warn "sudoers validation failed - the in-app update path stays disabled"
    fi
    rm -f "$UPD_SUDOERS_TMP"
else
    warn "corpusfm-update.sh not found at $UPDATER_SRC - in-app updates disabled"
fi

# ── The proxy executor (ruling 2026-08-08) ───────────────────────────────────────
# OUTSIDE the updater branch above, and that is the whole point of where this sits. Everything in
# `$INSTALL_DIR/bin` used to be installed INSIDE `if [[ -f "$UPDATER_SRC" ]]`, and the executor was
# installed by nothing at all — `cfm-proxy-exec` appeared nowhere in either installer, and `git log
# -S` says it never had. Measured on fms-server 2026-08-08: a fresh install reached generation 3 and
# phase 17 refused with `/opt/CORPUSfm/bin/cfm-proxy-exec.sh does not exist`. No fresh install could
# pass the proxy provider on either platform.
#
# `proxy_transaction.executor_script` resolves `<InstallDir>/bin/cfm-proxy-exec.sh` and NOTHING else
# — no source tree, no PATH, no cwd — deliberately, because this file is handed root authority over
# FileMaker Server's own web configuration. So the installer's job is to put the shipped bytes
# exactly there, prove they are the shipped bytes, and refuse otherwise. A missing updater may
# disable updates; it may never suppress this.
info "Proxy executor"
PROXY_EXEC_SRC="$CFM_RUNTIME_ROOT/installer/linux/cfm-proxy-exec.sh"
PROXY_EXEC_DST="$INSTALL_DIR/bin/cfm-proxy-exec.sh"
[[ -f "$PROXY_EXEC_SRC" ]] \
    || die "the proxy executor is not in this payload at $PROXY_EXEC_SRC — the proxy provider would
     refuse at phase 17 and no install can complete without it"
mkdir -p "$INSTALL_DIR/bin"
# STAGED BESIDE THE DESTINATION, then moved: `mv` within one filesystem is atomic, so no reader ever
# sees a half-copied file at the path a root-authority resolver reads.
install -m 0755 -o root -g root "$PROXY_EXEC_SRC" "$PROXY_EXEC_DST.tmp" \
    || die "could not stage the proxy executor at $PROXY_EXEC_DST.tmp"
mv "$PROXY_EXEC_DST.tmp" "$PROXY_EXEC_DST" \
    || { rm -f "$PROXY_EXEC_DST.tmp"; die "could not install the proxy executor at $PROXY_EXEC_DST"; }
# READ BACK THE STATE, never the command's exit status. Each check answers one way the file could
# exist at the right path and still not be the thing the resolver may run as root.
[[ -f "$PROXY_EXEC_DST" && ! -L "$PROXY_EXEC_DST" ]] \
    || die "$PROXY_EXEC_DST is not a regular file"
[[ "$(stat -c '%U' "$PROXY_EXEC_DST")" == "root" ]] \
    || die "$PROXY_EXEC_DST is not root-owned; refusing to install an executor the service could replace"
[[ -x "$PROXY_EXEC_DST" ]] || die "$PROXY_EXEC_DST is not executable"
[[ -z "$(find "$PROXY_EXEC_DST" -perm /022 -print -quit)" ]] \
    || die "$PROXY_EXEC_DST is group- or world-writable; refusing to install an executor that runs as root"
_cfm_pe_src="$(sha256sum "$PROXY_EXEC_SRC" | cut -d' ' -f1)"
_cfm_pe_dst="$(sha256sum "$PROXY_EXEC_DST" | cut -d' ' -f1)"
[[ -n "$_cfm_pe_src" && "$_cfm_pe_src" == "$_cfm_pe_dst" ]] \
    || die "the installed proxy executor does not match the shipped source ($_cfm_pe_src vs $_cfm_pe_dst)"
ok "Proxy executor installed ($PROXY_EXEC_DST; root:root 0755, digest verified against the payload)"


# ═══ PHASE 14 — Provider prerequisites and observation ══════════════════════════════════

# Read-only observation. Only now is it known which providers need FileMaker authority this run;
# nothing here mutates and nothing here holds a credential.
#
# EVERY ONE OF THESE TAKES `--request` (packet 1246-04-04, correction B). They were invoked with no
# request at all, and `--request` is `required=True` on all four — so argparse refused before any
# observation happened, and the `|| true` made the refusal invisible. The requests are built here
# with EXACTLY their verb's key set; a key this build does not accept is a refusal, not a warning.
#
# THE MODE. `fresh_install` when this invocation published the foundation, `forward_update`
# otherwise — the same classification phase 11 made, from the same published record, not a second
# opinion. `--repair-storage-access` overrides it for storage alone (see phase 18).
if [[ "$CFM_GENERATION" == "1" ]]; then CFM_MODE="fresh_install"; else CFM_MODE="forward_update"; fi
CFM_STORAGE_MODE="$CFM_MODE"
$REPAIR_STORAGE_ACCESS && CFM_STORAGE_MODE="repair_storage_access"

# Shared fragments. Written once so the observe and the mutate request cannot drift apart.
lc_admin_identity_request() {   # lc_admin_identity_request <credential_input>
    printf '{"schema_version":1,"actor":"installer","installation_id":"%s","install_dir":"%s","fms_root":"%s","secrets_dir":"%s","host":"%s","mode":"%s","expected_generation":%s,"credential_input":"%s"}' \
        "$INSTALLATION_ID" "$INSTALL_DIR" "$FMS_ROOT" "$CFM_SECRETS_DIR" "$CFM_FMS_HOST" \
        "$CFM_MODE" "$CFM_GENERATION" "$1"
}
lc_storage_request() {          # lc_storage_request <mode>
    printf '{"schema_version":1,"actor":"installer","installation_id":"%s","install_dir":"%s","fms_root":"%s","fms_database_dir":"%s","secrets_dir":"%s","host":"%s","mode":"%s","expected_generation":%s}' \
        "$INSTALLATION_ID" "$INSTALL_DIR" "$FMS_ROOT" "$FM_DB_DIR" "$CFM_SECRETS_DIR" \
        "$CFM_FMS_HOST" "$1" "$CFM_GENERATION"
}
# `disposition` and `credential_input` are the only difference between status and reconcile, and
# both are structural: `composed_candidate` says this is the INTEGRATOR surface, and the credential
# is a TRANSPORT TOKEN — `absent`, `prompt`, `stdin` or `fd:<n>` — never a value (§6).
lc_proxy_request() {            # lc_proxy_request status|reconcile
    local tail=""
    [[ "$1" == "reconcile" ]] \
        && tail=",\"disposition\":\"composed_candidate\",\"credential_input\":\"$(lc_fms_transport)\""
    printf '{"schema_version":1,"actor":"installer","installation_id":"%s","install_dir":"%s","fms_root":"%s","expected_generation":%s,"mcp_metadata":true,"port":%s,"prefix":"%s","types":%s%s}' \
        "$INSTALLATION_ID" "$INSTALL_DIR" "$FMS_ROOT" "$CFM_GENERATION" "$WEB_PORT" \
        "$WEB_PREFIX" "$(lc_json_array "${CFM_PROXY_TYPES[@]}")" "$tail"
}
# The compartment request names no installation, no generation and no operation: it RETURNS candidate
# facts rather than writing them, so its key set is the ten facts below and nothing else.
lc_patch_request() {
    printf '{"requested":"%s","install_dir":"%s","fms_root":"%s","fms_database_dir":"%s","storage_dirs":%s,"protected_dirs":%s,"service_identity":{"flavour":"posix","account":"%s","role":"web"},"fms_identity":{"flavour":"posix","account":"%s","role":"fms"},"flavour":"posix","seed":"%s"}' \
        "$HOSTING_DIR" "$INSTALL_DIR" "$FMS_ROOT" "$FM_DB_DIR" \
        "$(lc_json_array "$CFM_STATE_DIR" "$CFM_SECRETS_DIR")" \
        "$(lc_json_array "$CFM_CONFIG_DIR" "$CFM_LOG_DIR" "$CFM_RUN_DIR")" \
        "$SERVICE_USER" "$FMS_SERVICE_USER" "$INSTALL_DIR/$CFM_ASSETS_DIRNAME/db/CORPUSfm_DB.fmp12"
}

# NO patch-compartment inspection here. It authenticates to the FMS Admin API with THIS
# installation's PKI identity, which phase 15 creates — so on a fresh box it can only report
# `api_required_unavailable`, and recording that as an observed prerequisite states a conclusion
# about an identity that does not exist yet. Phase 16 inspects, once phase 15 has published one.
_lc_req="$(lc_request proxy-status "$(lc_proxy_request status)")"
"${CFM_LIFECYCLE[@]}" proxy status --request "$_lc_req" >>"$CFM_LOG" 2>&1 || true
_lc_req="$(lc_request admin_identity-observe "$(lc_admin_identity_request absent)")"
"${CFM_LIFECYCLE[@]}" admin-identity observe --request "$_lc_req" >>"$CFM_LOG" 2>&1 || true
# THE STORAGE OBSERVATION HERE IS A PREREQUISITE RECORD, NOT THE ROUTING AUTHORITY. Phase 18 takes
# its own (packet 1246-10-04): this one runs BEFORE phase 15 publishes the Admin-API machine
# identity, so `list_databases()` cannot answer and the database-known and hosted axes are UNKNOWN
# by construction — which classifies every box, fresh or not, as `indeterminate`. stdout and stderr
# are captured SEPARATELY: the result is a JSON document and a diagnostic line merged into it would
# make it unparseable.
_lc_req="$(lc_request storage-observe "$(lc_storage_request "$CFM_STORAGE_MODE")")"
"${CFM_LIFECYCLE[@]}" storage observe --request "$_lc_req" >>"$CFM_LOG" 2>&1 || true
ok "Provider prerequisites observed"

# ═══ PROVIDER ORDER — RULED 2026-08-08, and the order IS the dependency ═════════════════
#
# admin_identity(2) → patch_compartment(3) → proxy(4) → storage(5).
#
# It was patch(2) → proxy(3) → admin_identity(4) → storage(5), and that cannot work on a genuinely
# fresh co-located box: the patch compartment authenticates to the FMS Admin API with THIS
# installation's PKI identity, and the old phase 17 was where that identity was created. Measured on
# fms-server 2026-08-08 — patch-compartment refused `api_required_unavailable`, "no co-located
# FileMaker Server Admin API PKI key is configured", and the install stopped there.
#
# The canonical Admin API identity is UNCONDITIONAL maintained infrastructure on a supported
# co-located installation, not a side effect of asking for the patch compartment. On update the same
# provider runs and takes the genuine already-published no-change path: no rotation, no second
# identity, no generation consumed.
#
# Generations are NOT written here. `lc_commit_provider` advances CFM_GENERATION, so each provider
# takes the number its POSITION earns; moving a block moves its generation with it. The labels are
# documentation and the controls assert the committed numbers instead.

# ═══ PHASE 15 — ADMIN IDENTITY — Protocol F — generation 2 ══════════════════════════════

# PROTOCOL F — admin_identity leaves its entry UNRESOLVED for the commit, then finalizes against the
# generation the commit produced, and the boundary discards the journal.
# A WORKING MACHINE IDENTITY THE MANIFEST ALREADY CARRIES COMPOSES NOTHING (correction R6). It
# consumes no generation and opens no journal, so there is nothing here to commit, finalize or
# discard — and calling `commit-provider` anyway is exactly the `ProviderMismatch` that killed every
# update of a box whose identity was already working.
_lc_req="$(lc_request admin_identity-reconcile "$(lc_admin_identity_request "$(lc_fms_transport)")")"
LC_FEED_CREDENTIAL=true
lc_provider_run "admin_identity reconcile" candidate admin-identity reconcile --request "$_lc_req"
LC_FEED_CREDENTIAL=false
_lc_ai_op="$LC_OP"
if [[ "$LC_COMPOSE" == True || "$LC_COMPOSE" == true ]]; then
    lc_commit_provider admin_identity "$_lc_ai_op" "$CFM_GENERATION" "$LC_CANDIDATE"
    _lc_fin="$(lc_request admin_identity-finalize "$(printf '{"schema_version":1,"operation_id":"%s","installation_id":"%s","committed_generation":%s,"actor":"installer"}' \
        "$_lc_ai_op" "$INSTALLATION_ID" "$CFM_GENERATION")")"
    lc_run "admin_identity finalize" admin-identity finalize --request "$_lc_fin" >/dev/null
    ok "admin_identity finalized"
    lc_discard_provider admin_identity "$_lc_ai_op"
else
    ok "admin_identity already published — no generation consumed and no journal opened"
fi

# ═══ PHASE 16 — PATCH — Protocol P — generation 3 ═══════════════════════════════════════

# PROTOCOL P — patch-compartment alone. Its `apply` RESOLVES its own journal before returning, so the
# commit requires a RESOLVED entry and there is no finalize verb: the sequence ends at the discard.
#
# The request is the compartment's own ten-key schema — no operation id, no installation id, no
# generation. It RETURNS `operation_id` and a `candidate` already shaped as `{patch, patch_hosting_dir}`,
# which is exactly what `commit-provider` parses, so the candidate is passed through rather than
# rebuilt from a field the result does not carry.
_lc_req="$(lc_request patch-apply "$(lc_patch_request)")"
lc_provider_run "patch compartment apply" candidate patch-compartment apply \
    --request "$_lc_req" --mode "$CFM_MODE"
if [[ "$LC_COMPOSE" == True || "$LC_COMPOSE" == true ]]; then
    lc_commit_provider patch "$LC_OP" "$CFM_GENERATION" "$LC_CANDIDATE"
    lc_discard_provider patch "$LC_OP"
else
    ok "patch compartment already satisfied — no generation consumed and no journal opened"
fi

# ═══ PHASE 17 — PROXY — Protocol F — generation 4 ═══════════════════════════════════════

# PROTOCOL F — proxy leaves its entry UNRESOLVED for the commit, then finalizes against the
# generation the commit produced, and the boundary discards the journal.
#
# `candidates` (plural) is the one place the four providers' result shapes differ: proxy composes ONE
# ENTRY PER FRONT, so its result is a mapping of proxy type to entry and `commit-provider` reads it
# under the key `proxy_policy`. The other three return a `candidate` object already in the shape the
# commit parses.
#
# FINALIZE takes `committed_generation` and `operation_id` — never `generation`, never `install_dir`.
# The generation it names is the one the COMMIT produced, which is why it is read back rather than
# echoed from the value the reconcile inspected.
_lc_req="$(lc_request proxy-reconcile "$(lc_proxy_request reconcile)")"
LC_FEED_CREDENTIAL=true
lc_provider_run "proxy reconcile" candidates proxy reconcile --request "$_lc_req"
LC_FEED_CREDENTIAL=false
lc_report_inactive_proxy_skips
_lc_proxy_op="$LC_OP"
if [[ "$LC_COMPOSE" == True || "$LC_COMPOSE" == true ]]; then
    lc_commit_provider proxy "$_lc_proxy_op" "$CFM_GENERATION" \
        "$(printf '{"proxy_policy":%s}' "$LC_CANDIDATE")"
    _lc_fin="$(lc_request proxy-finalize "$(printf '{"schema_version":1,"operation_id":"%s","installation_id":"%s","committed_generation":%s,"actor":"installer"}' \
        "$_lc_proxy_op" "$INSTALLATION_ID" "$CFM_GENERATION")")"
    lc_run "proxy finalize" proxy finalize --request "$_lc_fin" >/dev/null
    ok "proxy finalized"
    lc_discard_provider proxy "$_lc_proxy_op"
else
    ok "proxy already satisfied — no generation consumed and no journal opened"
fi

# ── Declared proxy POLICY (parent §4H.1) ──────────────────────────────────────────
# `--proxy-policy-add` and `--proxy-policy-ignore` were collected into two arrays and passed
# NOWHERE (finding F4/B9): two supported options that changed nothing. They move POLICY, which is a
# different act from reconciling routing — `managed` means CORPUSfm owns that front, `ignored` means
# it does not — so they run through `proxy-public`, the surface that owns policy, after the reconcile
# whose result they would otherwise contradict.
# THE VERB GROUP IS `proxy-public`, NOT `proxy`. `proxy` is the INTEGRATOR surface and declares only
# status/reconcile/finalize/abort; `add` and `ignore` live on the public surface, which takes a
# selector and no `--request`. Sending them to `proxy` exits 2 from argparse — which would have
# aborted the run at phase 16, AFTER generation 3 was committed and the proxy journal discarded.
for _t in "${PROXY_POLICY_ADD[@]}"; do
    "${CFM_LIFECYCLE[@]}" proxy-public add "$_t" >>"$CFM_LOG" 2>&1 \
        || die "could not record proxy policy 'managed' for '$_t'."
    ok "proxy policy: $_t managed"
done
for _t in "${PROXY_POLICY_IGNORE[@]}"; do
    "${CFM_LIFECYCLE[@]}" proxy-public ignore "$_t" >>"$CFM_LOG" 2>&1 \
        || die "could not record proxy policy 'ignored' for '$_t'."
    ok "proxy policy: $_t ignored"
done
# ── The NON-PROXY consequences of a composed front ─────────────────────────────────
#
# THE SECOND PUBLISHER IS GONE (packet 1246-10-04). This is where `cfm-web-proxy.sh` used to run,
# AFTER the provider above had already published, validated, activated and health-checked the front.
# On Linux the two now collide by construction: the provider writes the current `# CORPUSFM` block,
# the retired helper appended its own legacy `###CORPUSFM` block including the SAME file, and the
# helper's own restart then could not load a configuration with a duplicate include.
#
# Measured on fms-server 2026-08-08: generations 1-4 all composed, the helper ran, and nginx did not
# come back — so phase 18 observed OData one second later, reported `fms_unreachable`, and the run
# died at storage with the web front down. The provider is the SOLE Linux proxy publisher and
# activator; nothing here touches the FMS web server.
#
# What survives is exactly what was never the helper's to own: the deployment marker the app reads,
# and the retirement of an obsolete public firewall rule. Both are consequences of a front that IS
# composed, so they hang off the provider's success rather than off a second helper's exit code.
# THE ROUTE MARKER WRITE IS RETIRED (packet 1246-10-04). `write_web_deployment` copied the prefix
# and port into `install.yaml`, and the app read them from there — two stores for one fact. The
# proxy provider composes the route into the MANIFEST, and `app.web.__main__` and
# `deployment.web_prefix`/`local_base_url` now derive it from that published projection. Copying it
# back would re-create the disagreement this removes: measured on fms-server 2026-08-08, the app
# bound its development default `:8501` while the proxy forwarded to `:8533`.
# app is loopback-only — retire any old public web-port firewall rule
command -v ufw >/dev/null 2>&1 && ufw delete allow 8501/tcp >/dev/null 2>&1 || true
# (no restart here: phase 17 activated the front and phase 21 owns every service start)
ok "CORPUSfm fronted at ${WEB_PREFIX}/ via the FMS web server (app on loopback :$WEB_PORT)"


# ═══ PHASE 18 — STORAGE — Protocol F — generation 5 ═════════════════════════════════════

# PROTOCOL F — storage leaves its entry UNRESOLVED for the commit, then finalizes against the
# generation the commit produced, and the boundary discards the journal.
# STORAGE composition-ready: a fresh success may report `incomplete_safe` with a
# first_administrator_owed candidate. That exact predicate — and only it — is composable;
# any other incomplete_safe stops the run through lc_dispatch.
#
# THE VERB FOLLOWS THE MODE (parent §4H.1; finding F4/B9). `--repair-storage-access` set a variable
# nothing read. `repair_storage_access` is a real member of `storage_identity.MODES` and `repair` is
# a real shipped verb, so the option now selects both — one bounded repair, never a second
# bootstrap of an installation that already has one.
# ROUTED FROM THE OBSERVATION, never from the flag alone (correction C1). `bootstrap` is reachable
# from exactly one state — `proven_fresh` on a fresh install — so there is no path from a failed
# anything to a bootstrap, and "never reinterpret a failed bootstrap as an update plan" is
# structural rather than a promise. Every unroutable state refused above, before any mutation.
# OBSERVED HERE, WHERE THE AUTHORITY EXISTS (packet 1246-10-04). The phase-14 observation ran before
# phase 15 published the Admin-API machine identity, so its database-known and hosted axes were
# UNKNOWN and its state was `indeterminate` on every box — measured on fms-server 2026-08-08, where
# a fresh install stopped here with "storage cannot be routed". Routing reads THIS observation.
_lc_req="$(lc_request storage-observe "$(lc_storage_request "$CFM_STORAGE_MODE")")"
CFM_STORAGE_OBSERVATION="$("${CFM_LIFECYCLE[@]}" storage observe --request "$_lc_req" 2>>"$CFM_LOG")" \
    || true      # a state this build refuses to route still EMITS its classification; the route judges it
printf '%s\n' "$CFM_STORAGE_OBSERVATION" >> "$CFM_LOG" 2>/dev/null || true
_lc_st_route="$(lc_storage_route "$CFM_STORAGE_OBSERVATION")"
if [[ "$_lc_st_route" == "skip" ]]; then
    ok "storage: the published corpus is reachable — no verb, no journal, no generation consumed"
else
_lc_st_verb="$_lc_st_route"
_lc_req="$(lc_request "storage-$_lc_st_verb" "$(lc_storage_request "$CFM_STORAGE_MODE")")"
lc_provider_run "storage $_lc_st_verb" candidate storage "$_lc_st_verb" --request "$_lc_req"
if [[ "$LC_FIRST_ADMIN_OWED" == True || "$LC_FIRST_ADMIN_OWED" == true ]]; then
    CFM_FIRST_ADMIN_OWED=true
    info "storage composed a candidate and owes only its first administrator (phase 19)"
else
    CFM_FIRST_ADMIN_OWED=false
fi
_lc_st_op="$LC_OP"
# A repair that composed nothing is terminal and consumes no generation; one that composed a
# candidate follows the same commit/finalize/discard every Protocol F provider does.
if [[ "$LC_COMPOSE" != True && "$LC_COMPOSE" != true ]]; then
    ok "storage $_lc_st_verb completed with nothing to compose — no generation consumed"
else
lc_commit_provider storage "$_lc_st_op" "$CFM_GENERATION" "$LC_CANDIDATE"
_lc_fin="$(lc_request storage-finalize "$(printf '{"schema_version":1,"operation_id":"%s","installation_id":"%s","committed_generation":%s,"actor":"installer"}' \
    "$_lc_st_op" "$INSTALLATION_ID" "$CFM_GENERATION")")"
lc_run "storage finalize" storage finalize --request "$_lc_fin" >/dev/null
# The journal must be RESOLVED before it is discarded — `Journal.discard` refuses an unresolved
# record, so this is a read-back of what finalize claims rather than a second opinion about it.
_lc_j="$(lc_json_field "$("${CFM_LIFECYCLE[@]}" status --json 2>/dev/null || true)" journal)"
[[ "$_lc_j" == "resolved" ]] \
    || die "storage finalized but its journal reads '$_lc_j', not resolved; refusing to discard it."
ok "storage finalized"
lc_discard_provider storage "$_lc_st_op"
_lc_j="$(lc_json_field "$("${CFM_LIFECYCLE[@]}" status --json 2>/dev/null || true)" journal)"
[[ "$_lc_j" == "none" ]] \
    || die "storage's journal reads '$_lc_j' after the discard; refusing to continue over it."
fi          # end: the repair/bootstrap composed a candidate
fi          # end: storage was not routed to `skip`
# ── THE LEGACY FM / STORAGE TAIL IS DELETED (packet 1246-10-04) ───────────────────
# It ran AFTER the lifecycle storage provider had composed, finalized and discarded generation 5,
# and it was a SECOND authority for the same things: it deployed the database, provisioned the
# sandbox, polled OData, bootstrapped the service account, attempted its OWN password rotation, and
# wrote the storage credential into install.yaml and server_configs.yaml.
#
# Measured on fms-server 2026-08-08, immediately after a successful adoption at generation 5: it
# read a 401 as "accessible" — 401 because the provider had already rotated the credential and this
# path held a different one — then tried to rotate again (`FM script error 212 from
# 'Cfm.SRV.ChangeAutomationPassword'`) and reported the FM backend not activated. The same shape as
# the retired proxy helper one phase earlier: two publishers of one thing.
#
# THE LIFECYCLE STORAGE PROVIDER IS THE SOLE INSTALLER AUTHORITY for corpus deployment and
# adoption, the automation credential, the corpus identity and storage composition. The sandbox is
# NOT reattached: the patch-compartment provider at phase 16 owns and records it.
#
# The late inline PKI block that also lived in this region IS DELETED and stays deleted (ruling,
# 2026-08-08). It minted a SECOND keypair, wrote `src/fms_admin_pki.yaml` and re-registered the
# public key AFTER phase 15 had already established, authenticated and published the canonical
# identity — two authorities for one installation, with the manifest naming one fingerprint while
# FMS trusted another. `fms_admin_pki.yaml` is a RETIRED authority: the canonical identity lives in
# the published secrets store and is named in the manifest, neither installer writes or reads the
# old file, and a control fails the build if either block returns.
unset FM_ADMIN_PASS

# ── FINAL LAYOUT PROTECTION, after every provider has written (packet 1246-10-04) ──
# The SAME canonical request as phase 12, deliberately. The keys are reused — that operation never
# overwrites a Corpus Key — and this second invocation exists for the OTHER half of what it does:
# it re-applies and re-verifies the shared layout protection now that the providers have written
# their artifacts. The storage provider writes its credential record private at 0600 root-owned,
# which is correct at creation and unreadable by the service; `protection.READ_ONLY_SECRETS` makes
# it root-owned, service-group-readable and service-unwritable, exactly like the keys beside it.
#
# Measured on fms-server 2026-08-08: without this, the service identity could read neither
# `locator.json` (its directory was not traversable) nor `storage_access.json`, so a PUBLISHED
# installation resolved as unpublished and the runtime would have taken the LocalBackend path —
# the split-brain the runtime cutover exists to end, arriving through file modes instead of code.
#
# It runs AFTER storage finalize/discard (or the skip) and BEFORE any service-user projection,
# administrator or service work below. There is no shell chmod/chown policy here and no second
# protection implementation: the ordering is this script's, the policy is the protector's.
_lc_req="$(lc_request provision-keys-final "$(printf '{"schema_version":1,"actor":"installer","flavour":"posix","service_account":"%s","database_name":"%s","database_search_dirs":%s}' \
    "$SERVICE_USER" "$FM_DATABASE" "$(lc_json_array "$FM_DB_DIR" "$HOSTING_DIR")")")"
lc_run "final layout protection" provision-keys --request "$_lc_req" >/dev/null
ok "Layout protection re-applied and verified after every provider wrote"

# The Admin API identity is published by phase 15 for the running service, not merely for the
# elevated installer. Prove that the final protection pass made the provider's root-created record
# readable by that service identity without printing any part of the credential.
_ADMIN_IDENTITY_FILE="$CFM_SECRETS_DIR/admin_identity.yaml"
[[ -f "$_ADMIN_IDENTITY_FILE" ]] \
    || die "The published Admin API identity is missing at $_ADMIN_IDENTITY_FILE."
sudo -u "$SERVICE_USER" -H test -r "$_ADMIN_IDENTITY_FILE" \
    || die "The published Admin API identity is not readable by the $SERVICE_USER service account."
ok "Published Admin API identity is readable by the service account"

# ── The src/ storage-DB refresh is RETIRED (packet 1257) ──────────────────────────
# It copied `$REPO_DIR/db/CORPUSfm_DB.fmp12` into `$INSTALL_DIR/src/db/` and chowned the result
# `$SERVICE_USER:$SERVICE_USER`. Every part of that is now wrong in a way that would undo this
# packet:
#
#   * its SOURCE is gone — step 8 relinquished asset custody, so the application repository has no
#     `db/` and the guard was already a permanent no-op;
#   * its DESTINATION is inside the Git checkout, which must hold no untracked content or the next
#     privileged update refuses the installation;
#   * its OWNERSHIP made the storage-DB template writable by the service account, and the service
#     must never be able to rewrite what it is seeded from.
#
# The template arrives with the verified asset payload and is placed, read-only, under
# `$INSTALL_DIR/$CFM_ASSETS_DIRNAME/db/`. Nothing refreshes it in place: a schema-build change is a
# fresh install (packet 1007 / 085).

# ── THE LEGACY server_configs STORAGE REGISTRATION IS DELETED (packet 1246-10-04) ──
# It re-derived the storage connection from `install.yaml` — the retired authority — and wrote it
# into `server_configs.yaml` as the service user, carrying the automation credential with it. Both
# stores are superseded: the lifecycle storage provider composes the corpus into the installation
# manifest and holds the credential in the published secrets store. Re-registering from the old
# file would reintroduce a second storage authority that disagrees with the manifest.

# (The pre-085 "Storage schema" migrate-storage step is GONE: in-place schema migration is
# retired — a DB behind the shipped schema Build trips the app's build-mismatch gate ("fresh
# install required"); FileMaker moves the database. The upgrade self-pull
# re-execs the refreshed installer, so an older deployed install.sh never reaches here.)

# ── Reclaim the config tree for the service user (box-gate finding, packet 1008) ──
# Root-context steps write into `$INSTALL_DIR/.corpusfm` (0600) — `write_web_deployment` after the
# proxy provider composes is the current one — and a file left root:root there is unreadable by the
# service, which then silently falls back to LocalBackend: Tier 1 fails, the first admin lands in
# the wrong backend, and restore's preflight cannot read the deployment. Reclaim the tree NOW,
# before the service-user steps below read it. The app reads its config live, so this also
# self-heals an already-running web service on its next read.
# (The rotated-credential half of this rationale is gone with the legacy bootstrap: the storage
# credential lives in the published secrets store, not in `install.yaml`.)
if [[ -d "$INSTALL_DIR/.corpusfm" ]]; then
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.corpusfm"
fi

# ── Indexed-slot projection backfill (idempotent; no-op when already current) ──
# Fills newly-added query slots on HISTORICAL records —
# slots fill only on commit, so rows stored before a slot existed need a one-time re-projection.
# OData-only (no DB close/swap), so it runs with the web service UP. Marker-gated: a no-op once the
# projection version matches; until it completes, the picker uses its scan fallback. (packet 014 B)
if [[ -x "$INSTALL_DIR/venv/bin/python" ]]; then
    info "Projection backfill"
    # Fold the per-record / up-to-date chatter into the transcript; show only the section outcome.
    if cfm_run "projection backfill" sudo -u "$SERVICE_USER" -H env PYTHONPATH="$INSTALL_DIR/src" \
            "$INSTALL_DIR/venv/bin/python" -m corpusfm.server.cli backfill-storage-projections; then
        ok "Projections current"
    else
        warn "Projection backfill did not complete — the picker uses the scan fallback until it does"
    fi
fi


# ═══ PHASE 19 — Post-composition installation work ══════════════════════════════════════
# ── First CORPUSfm admin (named-user login) ─────────────────────────────────────
# The browser no longer creates the first account (anti-race), so a FRESH install creates it here.
# Existing users are PRESERVED (never overwritten on upgrade/re-run). The password is passed to the
# child via the environment ONLY — never on the command line (process list) and never logged/echoed.
_HAS_USERS=$(detect_first_admin_state)
if [[ "$_HAS_USERS" == "0" ]]; then
    info "First CORPUSfm admin"
    CFM_ADMIN_USER="${CFM_ADMIN_USER:-admin}"
    _HAS_PASS=0; [[ -n "$CFM_ADMIN_PASS" ]] && _HAS_PASS=1
fi
case "$(build_first_admin_plan "$_HAS_USERS" "${_HAS_PASS:-0}" "${#CFM_ADMIN_PASS}")" in
preserve)
    ok "CORPUSfm admin already configured — preserving existing users" ;;
warn:unknown)
    # …UNLESS phase 18 already told us. When storage composed `first_administrator_owed` it read the
    # user table and found it EMPTY, so "we cannot tell" is not a tie — it is a later, worse read of
    # a question already answered, and continuing would report a box nobody can sign in to as done.
    if $CFM_FIRST_ADMIN_OWED; then
        LEAVE_SERVICES_STOPPED=true
        die "storage reported that this installation owes its first administrator, and whether one
         exists can no longer be determined. The services stay STOPPED. Restore storage and re-run
         the installer."
    fi
    # The read FAILED — we do NOT know whether an admin exists, so we neither claim one nor abort an
    # upgrade over a transient outage. Saying nothing (the old behavior) was the worst of the three.
    warn "Could not determine whether a CORPUSfm admin exists — storage was unreachable. If the login page reports no users once storage is back, create one: sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/python -m corpusfm.server.cli users create <name> --admin" ;;
fail:no-pass)
    die "No CORPUSfm admin exists and none was supplied — a box nobody can sign in to is not a completed install. Provide CORPUSFM_ADMIN_USER/CORPUSFM_ADMIN_PASS) and re-run." ;;
fail:short-pass)
    die "The CORPUSfm admin password must be at least 8 characters — no admin was created. Re-run with a longer CORPUSFM_ADMIN_PASS." ;;
create)
    # THROUGH THE SHIPPED STORAGE VERB (packet 1246-04-04, correction R5 step 8). This used to call
    # `users.create_user` directly, bypassing the provider that owns the user store — so the one act
    # that decides whether anybody can sign in had no lock, no journal, no read-back and no result
    # word. `storage create-first-admin` has all four, and it PROVES the account read back before
    # reporting `completed`.
    #
    # ORDER IS THE CONTRACT: this runs at phase 19, after phase 18 committed, finalized and
    # discarded the storage candidate. Creating the administrator first would put a row in a store
    # whose composition the installation record does not yet acknowledge.
    #
    # THE PASSWORD TRAVELS ON STDIN, never in the request. `admin_credential_input` is the TRANSPORT
    # TOKEN `stdin`; the request JSON is written to a root-owned file and carries no secret (§6).
    _lc_req="$(lc_request storage-create-first-admin "$(printf '{"schema_version":1,"actor":"installer","installation_id":"%s","install_dir":"%s","fms_root":"%s","fms_database_dir":"%s","secrets_dir":"%s","host":"%s","mode":"%s","expected_generation":%s,"admin_username":"%s","admin_credential_input":"stdin"}' \
        "$INSTALLATION_ID" "$INSTALL_DIR" "$FMS_ROOT" "$FM_DB_DIR" "$CFM_SECRETS_DIR" \
        "$CFM_FMS_HOST" "$CFM_MODE" "$CFM_GENERATION" "$CFM_ADMIN_USER")")"
    _lc_out="$(printf '%s' "$CFM_ADMIN_PASS" | "${CFM_LIFECYCLE[@]}" storage create-first-admin \
        --request "$_lc_req" 2>&1)" && _lc_rc=0 || _lc_rc=$?
    printf '%s\n' "$_lc_out" >> "$CFM_LOG" 2>/dev/null || true
    unset CFM_ADMIN_PASS
    _lc_result="$(lc_json_field "$_lc_out" result)"
    if [[ "$_lc_rc" -eq 0 && "$_lc_result" == "completed" ]]; then
        ok "First CORPUSfm admin '$CFM_ADMIN_USER' created (full admin)"
    elif [[ "$_lc_rc" -eq 0 && "$_lc_result" == "no_change" ]]; then
        # `no_change` is returned ONLY after `users_exist` proved True on a real backend read — an
        # outage answers `manual_action_required`, not "already there". So this word IS the proof.
        ok "A CORPUSfm administrator already exists — existing users preserved"
    else
        lc_dispatch "$_lc_rc" "creating the first CORPUSfm administrator"
        LEAVE_SERVICES_STOPPED=true
        die "creating the first CORPUSfm administrator returned '$_lc_result'; this box has no way
     in. The services stay STOPPED. Fix the reported error and re-run the installer."
    fi ;;
esac
unset CFM_ADMIN_PASS


# ═══ PHASE 20 — Install and READ BACK the final service definitions ═════════════════════
# ── Final service definitions — CANONICAL, from lifecycle/service_identity ────────
# RENDERED, not hand-written (packet 1246-04-03). These units used to be transitional heredocs
# carrying legacy `.corpusfm` grants, written on the assumption that a LAYOUT CUTOVER would later
# replace them with the real thing. There is no cutover, so what is installed here IS the final
# definition and it comes from the one place that defines it: `lifecycle/service_identity`.
#
# That module derives every ReadWritePaths entry from the published OS layout. Installed secrets are
# read-only to both roles; neither receives a per-file exception. Rendering here rather than restating
# the remaining role boundaries keeps one contract.
info "Rendering final service definitions from lifecycle/service_identity..."
for _role in web scheduler; do
    _unit="$([[ $_role == web ]] && echo "$WEB_SERVICE" || echo "$SCHED_SERVICE")"
    PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" - "$_role" "/etc/systemd/system/$_unit.service" "$INSTALL_DIR" <<'RENDER' \
        || die "Could not render the $_role service definition."
import sys
from corpusfm.lifecycle import os_layout, service_identity as si
role, target, install_dir = sys.argv[1], sys.argv[2], sys.argv[3]
spec = si.systemd_unit_spec(role, os_layout.posix_os_layout(), install_dir=install_dir,
                            description=f"CORPUSfm {role}")
open(target, "w").write(si.render_systemd_unit(spec))
RENDER
    # READ BACK: what is on disk must be what the canonical renderer produced, and it must name an
    # unprivileged identity. A definition that failed to write, or wrote partially, must not reach
    # phase 21 — which starts exactly this set.
    PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" - "$_role" "/etc/systemd/system/$_unit.service" "$INSTALL_DIR" <<'VERIFY' \
        || die "The installed $_role definition does not match the canonical rendering."
import sys
from corpusfm.lifecycle import os_layout, service_identity as si
role, target, install_dir = sys.argv[1], sys.argv[2], sys.argv[3]
spec = si.systemd_unit_spec(role, os_layout.posix_os_layout(), install_dir=install_dir,
                            description=f"CORPUSfm {role}")
want = si.render_systemd_unit(spec)
got = open(target).read()
assert got == want, f"{target} differs from the canonical rendering"
assert si.systemd_definition_names_an_identity(got), f"{target} names no unprivileged identity"
VERIFY
    ok "$_unit definition installed and read back (canonical)"
    VERIFIED_UNITS+=("$_unit")
done

# ── Retire the global MCP token ─────────────────────────────────────────────────
# MCP access is user-account-centric. The endpoint mounts by deployment mode and every credential
# resolves through storage, so neither a fresh install nor an update provisions a file-backed token.
# Remove both locations used by earlier installers before either runtime service starts.
_retired_mcp_env=false
for _mcp_env in "$CFM_SECRETS_DIR/.mcp_env" "$INSTALL_DIR/.mcp_env"; do
    if [[ -e "$_mcp_env" || -L "$_mcp_env" ]]; then
        rm -f -- "$_mcp_env"
        _retired_mcp_env=true
    fi
done
$_retired_mcp_env && ok "Retired the previous global MCP token; MCP access now uses named users"

# ── Retire the old standalone MCP service (folded into the web app now) ────────────
# Migration: a box upgrading from the separate-service era has corpusfm-mcp.service on
# :8765. Stop + disable + remove it, and drop its LAN firewall rule(s). Idempotent — a
# fresh install (or a re-run) simply finds nothing to retire.
if [[ -f "/etc/systemd/system/${MCP_SERVICE}.service" ]]; then
    info "Retiring the standalone $MCP_SERVICE service (folded into the web app)..."
    systemctl stop "$MCP_SERVICE" 2>/dev/null || true
    systemctl disable "$MCP_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${MCP_SERVICE}.service"
    systemctl daemon-reload 2>/dev/null || true
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw delete allow "${MCP_PORT}/tcp" >/dev/null 2>&1 || true
        # Scoped form (allow from <subnet> to any port <PORT>): delete by rule number,
        # bounded so a failing delete can't loop. Numbers shift after each delete → re-query.
        for _ in 1 2 3 4 5; do
            n="$(ufw status numbered 2>/dev/null | grep -E "(^|[^0-9])${MCP_PORT}([^0-9]|$)" | grep -i ALLOW | head -1 | sed -E 's/^\[[[:space:]]*([0-9]+).*/\1/')"
            [[ -z "$n" ]] && break
            yes | ufw delete "$n" >/dev/null 2>&1 || break
        done
    fi
    ok "Standalone MCP service retired."
fi

# ── Firewall ──────────────────────────────────────────────────────────────────────
# Nothing to open: the web app binds 127.0.0.1:$WEB_PORT (loopback only) and is reached solely
# through the FMS reverse proxy on :443. A UFW allow for $WEB_PORT would be unnecessary (loopback
# isn't firewalled) and a latent footgun if the bind host ever changed — so we DON'T add one, and
# we proactively REMOVE any stale public rule from older installs that did. (The old :$MCP_PORT MCP
# LAN rule is retired in the migration step above.)
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ufw status 2>/dev/null | grep -qE "(^|[^0-9])${WEB_PORT}/tcp[[:space:]]+ALLOW"; then
        info "Firewall"
        info "Removing the unnecessary public UFW rule for loopback-only port $WEB_PORT..."
        ufw delete allow "$WEB_PORT/tcp" >/dev/null 2>&1 || true
        ok "Stale $WEB_PORT/tcp allow removed (access is via the FMS proxy only)"
    fi
fi


# Installer-run Python imports can leave bytecode caches while root still owns the new tree. They
# are reproducible, never application data, and the privileged update gate correctly refuses any
# ignored importable content. Remove those caches before starting the read-only service tree, and
# retire only EMPTY legacy runtime directories left by older installers (rmdir never removes data).
find "$INSTALL_DIR/src" -type d -name __pycache__ -prune -exec rm -rf -- {} +
for _legacy_runtime in archive logs history; do
    rmdir "$INSTALL_DIR/src/$_legacy_runtime" 2>/dev/null || true
done
_cfm_tree_report="$($PY_BUNDLED "$INSTALL_DIR/bin/tree_inspection.py" "$INSTALL_DIR/src" 2>>"$CFM_LOG")" \
    || die "The deployed checkout is not eligible for privileged updates: $_cfm_tree_report"
ok "Deployed checkout contains no runtime or bytecode residue"

# ═══ PHASE 21 — Start exactly the definitions phase 20 verified, then readiness ═════════
# Phase 10 created this credential-bearing launcher as root-only. Reassert and read back that
# boundary after every later recursive install-tree permission operation and before any service is
# started, so the displayed handoff can never name a service-readable credential.
chown root:root "$INSTALLER_ENTRY_POINT"
chmod 0700 "$INSTALLER_ENTRY_POINT"
[[ "$(stat -c '%U:%G:%a' "$INSTALLER_ENTRY_POINT")" == "root:root:700" ]] \
    || die "the durable installer bootstrap lost its root-only protection before service start."

# START, on BOTH paths. Phase 9 quiesced every service and nothing has started one since — the
# installer has no pre-phase-21 restart path at all. So this phase enables and STARTS exactly the
# definitions phase 20 installed and read back, and it does so identically whether this run was a
# fresh install or an update. An earlier version left the update path alone "because the layout
# cutover owns the restart"; the cutover is gone, and that branch left every upgrade finished with
# the product stopped.
if $IS_UPGRADE && ! $SCHED_UNIT_PREEXISTED; then
    warn "This update is activating the scheduler for the first time; previously inert scheduled Jobs may now run."
fi
PHASE21_OWNS_START=true
systemctl daemon-reload
for _unit in "${VERIFIED_UNITS[@]}"; do
    systemctl enable "$_unit" 2>/dev/null || true      # boot behaviour; starts nothing
    systemctl reset-failed "$_unit" 2>/dev/null || true
    systemctl start "$_unit" || die "$_unit failed to start after its definition was verified."
    ok "$_unit started (definition verified at phase 20)"
done

# ── POST-START VERIFICATION (parent §4H; restored by the 1246-04-03 post-closure correction) ──
#
# **This was LOST, not retired.** The 21-phase conversion moved the work into phases and the S8
# Summary block did not come with it — so `install.sh` started the units and printed "installed
# successfully" without checking anything, while `install.ps1` kept its whole Verify stage. Two
# comments still referred to "the self-test above", which is how the loss stayed invisible.
#
# It runs HERE, after phase 21 started exactly the definitions phase 20 verified and before any
# success banner, because a verification that runs before the services start proves nothing about
# the installation an operator is about to be told is finished. **A critical failure refuses
# success** — `die` below — rather than printing a warning under a green banner.
#
# The mechanisms are Linux's; the OBLIGATIONS are the parent's and are the same on both platforms:
# the units are running, the app answers on loopback, the FMS-proxied route answers while FMS's own
# route still coexists, unauthenticated MCP is refused, the first-boot MCP address is persisted and
# discoverable, and storage is genuinely readable.
cfm_section "Summary"
CFM_SELFTEST_CRIT=0

# 1. EVERY VERIFIED UNIT IS ACTIVE. Not "the ones we expected" — exactly the set phase 20 read back
#    and phase 21 started, so a unit added later cannot be silently unverified.
for _unit in "${VERIFIED_UNITS[@]}"; do
    if systemctl is-active --quiet "$_unit"; then
        ok "$_unit active"
    else
        warn "$_unit is NOT active — check: journalctl -u $_unit -n 50"
        CFM_SELFTEST_CRIT=1
    fi
done

# 2. THE APP ANSWERS ON LOOPBACK. Polled, because the unit reaching `active` precedes the socket
#    being bound and a single request races startup.
CFM_ST_HTTP=000
for _i in $(seq 1 30); do
    CFM_ST_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        "http://127.0.0.1:$WEB_PORT/login" 2>/dev/null || echo 000)
    [[ "$CFM_ST_HTTP" =~ ^(200|30[0-9]|401)$ ]] && break
    sleep 2
done
if [[ "$CFM_ST_HTTP" =~ ^(200|30[0-9]|401)$ ]]; then
    ok "Loopback login responds (HTTP $CFM_ST_HTTP)"
else
    warn "The app did NOT answer healthily on loopback after ~60s (got $CFM_ST_HTTP)"
    CFM_SELFTEST_CRIT=1
fi

# 3. THE PROXIED ROUTE ANSWERS, AND FMS STILL COEXISTS. Both halves, because a proxy edit that
#    works for CORPUSfm and breaks FMS's own :443 is not a successful install — it is an outage we
#    caused. Coexistence is a WARNING and not critical: FMS's own health is not ours to gate on.
CFM_ST_PROXY=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    "https://127.0.0.1${WEB_PREFIX}/" 2>/dev/null || echo 000)
if [[ "$CFM_ST_PROXY" =~ ^(200|30[0-9]|401)$ ]]; then
    ok "Proxied ${WEB_PREFIX}/ responds (HTTP $CFM_ST_PROXY)"
else
    warn "The FMS-proxied route ${WEB_PREFIX}/ did not respond (got $CFM_ST_PROXY)"
    CFM_SELFTEST_CRIT=1
fi
CFM_ST_FMS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    "https://127.0.0.1/fmi/mwpew/wpe/info" 2>/dev/null || echo 000)
[[ "$CFM_ST_FMS" == "200" ]] \
    && ok "FMS /fmi/ still healthy: HTTP 200 (coexistence verified)" \
    || warn "FMS /fmi/ returned HTTP $CFM_ST_FMS (check the FMS web server)"

# 4. UNAUTHENTICATED MCP IS REFUSED. The folded-in MCP is reachable on a public HTTPS URL, so a 200
#    here is a security regression — and it is exactly the kind a unit suite cannot see, because it
#    depends on the token, the environment and the proxy all being right on THIS box.
CFM_ST_MCP=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -X POST \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    "http://127.0.0.1:$WEB_PORT/mcp/" 2>/dev/null || echo 000)
if [[ "$CFM_ST_MCP" == "401" ]]; then
    ok "MCP fail-closed (rejects unauthenticated access: HTTP 401)"
else
    warn "MCP did NOT reject unauthenticated access (got $CFM_ST_MCP, expected 401) — check user authentication before exposing this box."
    CFM_SELFTEST_CRIT=1
fi

# 5. THE FIRST-BOOT MCP ADDRESS WAS PERSISTED AND DISCOVERY IS LIVE. The application detects a
#    candidate before constructing the MCP app, then writes it through its own install.yaml authority.
#    Package 0.2344 proved that the corrected application found the right candidate but the canonical
#    unit's ProtectSystem=strict sandbox denied that write; the process froze discovery off and the
#    installer still declared success. Read the application's resolver as the service user and require
#    the persisted source, then exercise all three exact host-root discovery routes through the FMS
#    proxy. No installer-owned address is invented here and no second write is performed.
_CFM_LOCATOR="$CFM_CONFIG_DIR/locator.json"
_CFM_CONFIG_DAC="$(stat -c '%U:%G' "$CFM_CONFIG_DIR" 2>/dev/null || true)|$(stat -c '%U:%G' "$_CFM_LOCATOR" 2>/dev/null || true)|$(stat -c '%U:%G:%a' "$INSTALL_YAML" 2>/dev/null || true)"
if [[ "$_CFM_CONFIG_DAC" == "root:root|root:root|$SERVICE_USER:$SERVICE_USER:600" ]] \
   && ! sudo -u "$SERVICE_USER" test -w "$CFM_CONFIG_DIR" \
   && ! sudo -u "$SERVICE_USER" test -w "$_CFM_LOCATOR" \
   && sudo -u "$SERVICE_USER" test -w "$INSTALL_YAML"; then
    ok "Config authority separated (root-owned directory + locator; service-owned 0600 install.yaml)"
else
    warn "Config authority is NOT separated as required (observed $_CFM_CONFIG_DAC)"
    CFM_SELFTEST_CRIT=1
fi

CFM_ST_MCP_ADDRESS=$(sudo -u "$SERVICE_USER" -H env PYTHONPATH="$INSTALL_DIR/src" \
    "$INSTALL_DIR/venv/bin/python" -c "
from corpusfm.app.web.deployment import external_base
try:
    address = external_base()
    print(('OK:' + address.value) if address.value and address.source == 'persisted'
          else 'FAIL:' + (address.source or 'none'))
except Exception as exc:
    print('FAIL:' + type(exc).__name__)" 2>/dev/null | tail -1 || printf 'FAIL:unreadable')
if [[ "$CFM_ST_MCP_ADDRESS" == OK:* ]]; then
    ok "MCP address persisted on first boot (${CFM_ST_MCP_ADDRESS#OK:})"
else
    warn "The first-boot MCP address was NOT persisted ($CFM_ST_MCP_ADDRESS) — OAuth discovery cannot be served."
    CFM_SELFTEST_CRIT=1
fi

# 5b. THE APPLICATION CAN READ, BUT CANNOT MODIFY, THE CHECKOUT AUTHORITY. Root's final `git config`
# in phase 10 used to leave config root:root 0640: root could prove the origin while the running app
# saw `unknown`. Ask through the service identity and require the clean HTTPS origin it actually
# consumes. This does NOT fetch: network/ref refresh belongs to the fixed privileged updater. The
# three negative write checks preserve the root-owned deployed-code boundary.
CFM_ST_SOURCE_ORIGIN=$(sudo -u "$SERVICE_USER" env HOME="$INSTALL_DIR" git \
    -C "$INSTALL_DIR/src" \
    remote get-url origin 2>/dev/null || true)
CFM_ST_SOURCE_HEAD=$(sudo -u "$SERVICE_USER" env HOME="$INSTALL_DIR" git \
    -C "$INSTALL_DIR/src" rev-parse HEAD 2>/dev/null || true)
CFM_ST_SOURCE_NORM=$(normalize_remote "$CFM_ST_SOURCE_ORIGIN")
CFM_ST_GIT_CONFIG_DAC=$(stat -c '%U:%G:%a' "$INSTALL_DIR/src/.git/config" 2>/dev/null || true)
CFM_ST_GIT_TRUST_DAC=$(stat -c '%U:%G:%a' "$INSTALL_DIR/.gitconfig" 2>/dev/null || true)
if [[ "$CFM_ST_SOURCE_ORIGIN" == https://* \
      && "${CFM_ST_SOURCE_ORIGIN#https://}" != *@* \
      && "$CFM_ST_SOURCE_NORM" == "$EXPECTED_REMOTE" \
      && "$CFM_ST_SOURCE_HEAD" == "$CFM_BUILD_COMMIT" \
      && "$CFM_ST_GIT_CONFIG_DAC" == "root:$SERVICE_USER:640" \
      && "$CFM_ST_GIT_TRUST_DAC" == "root:$SERVICE_USER:640" ]] \
      && ! sudo -u "$SERVICE_USER" test -w "$INSTALL_DIR/src" \
      && ! sudo -u "$SERVICE_USER" test -w "$INSTALL_DIR/src/.git" \
      && ! sudo -u "$SERVICE_USER" test -w "$INSTALL_DIR/src/.git/config" \
      && ! sudo -u "$SERVICE_USER" test -w "$INSTALL_DIR/.gitconfig"; then
    ok "Checkout authority readable by the service (canonical token-free origin; deployed Git metadata remains read-only)"
else
    warn "Checkout authority is NOT safely readable by the service (origin=${CFM_ST_SOURCE_NORM:-unknown})"
    CFM_SELFTEST_CRIT=1
fi

CFM_ST_DISCOVERY=""
for _path in \
    "/.well-known/oauth-protected-resource${WEB_PREFIX}/mcp" \
    "/.well-known/oauth-protected-resource${WEB_PREFIX}/mcp/" \
    "/.well-known/oauth-authorization-server${WEB_PREFIX}/mcp" \
    "/.well-known/openid-configuration${WEB_PREFIX}/mcp"; do
    _code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        "https://127.0.0.1${_path}" 2>/dev/null || echo 000)
    [[ "$_code" == "200" ]] || CFM_ST_DISCOVERY+=" ${_path}=${_code}"
done
if [[ -z "$CFM_ST_DISCOVERY" ]]; then
    ok "OAuth discovery live on first boot (protected resource + authorization server + OIDC metadata)"
else
    warn "OAuth discovery is NOT complete on first boot:${CFM_ST_DISCOVERY}"
    CFM_SELFTEST_CRIT=1
fi

# 6. STORAGE IS GENUINELY USABLE AND THE SHIPPED DEFAULT SET IS PRESENT. Startup seeds a fresh
#    catalog asynchronously, so one early count is not a completion predicate: package 0.2342 saw
#    one record, accepted it, and all four appeared shortly afterward. Poll the SAME backend the app
#    uses for at most 60 seconds and require the four exact name/type pairs. Additional user
#    artifacts are allowed; this readback never invokes a second seeder.
info "Waiting for the four required default artifacts..."
CFM_ST_STORAGE=""
_CFM_LAST_MISSING=""
for ((_CFM_SEED_TRY=0; _CFM_SEED_TRY<31; _CFM_SEED_TRY++)); do
CFM_ST_STORAGE=$(sudo -u "$SERVICE_USER" -H env PYTHONPATH="$INSTALL_DIR/src" \
    "$INSTALL_DIR/venv/bin/python" -c "
import urllib3
# CATEGORY-SCOPED. The loopback OData call runs with verify_ssl=False, so InsecureRequestWarning is
# expected and must not pollute this line's output — but a bare disable_warnings() silences every
# urllib3 warning class, and this snippet is the one place that decides whether storage is usable.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from corpusfm.storage import get_backend
    rows = list(get_backend().iter_artifact_metas())
    present = {(str(m.name), str(m.artifact_type)) for m in rows}
    required = (
        ('CORPUSfm_DB', 'SaveAsXML'),
        ('CORPUSfm_ADDON', 'SaveAsXML'),
        ('CORPUSfm_ADDON', 'AddonXML'),
        ('CORPUSfm_ADDON', 'MergedXML'),
    )
    missing = ['%s/%s' % pair for pair in required if pair not in present]
    print(('MISSING:' + ', '.join(missing)) if missing else 'OK:%d' % len(rows))
except Exception as exc:
    print('FAIL:' + type(exc).__name__)" 2>/dev/null | tail -1 || printf 'FAIL:unreadable')
    [[ "$CFM_ST_STORAGE" == OK:* ]] && break
    if [[ "$CFM_ST_STORAGE" == MISSING:* ]]; then
        _CFM_MISSING="${CFM_ST_STORAGE#MISSING:}"
        if [[ "$_CFM_MISSING" != "$_CFM_LAST_MISSING" ]]; then
            info "Default artifacts not complete yet — missing: $_CFM_MISSING"
            _CFM_LAST_MISSING="$_CFM_MISSING"
        fi
        [[ $_CFM_SEED_TRY -lt 30 ]] && sleep 2
        continue
    fi
    break
done
case "$CFM_ST_STORAGE" in
    OK:*) ok "Storage reachable; all four required default artifacts installed (${CFM_ST_STORAGE#OK:} total)" ;;
    MISSING:*) warn "Required default artifacts did not complete within 60 seconds — missing: ${CFM_ST_STORAGE#MISSING:}"
        CFM_SELFTEST_CRIT=1 ;;
    *) warn "Storage is NOT reachable ($CFM_ST_STORAGE) — check Settings → Connections."
       CFM_SELFTEST_CRIT=1 ;;
esac

# 7. THE NAMED-USER STATE, CHECKED AFTER THE INSTALL. Phase 19's detection ran BEFORE the services
#    existed; this asks the running installation. Three outcomes, not two: a storage outage is
#    UNKNOWN, never a claim that no user exists (packet 1201).
CFM_ST_LOGIN=$(sudo -u "$SERVICE_USER" -H env PYTHONPATH="$INSTALL_DIR/src" \
    "$INSTALL_DIR/venv/bin/python" -c "
from corpusfm.app.web import users
try:
    print('1' if users.users_exist(raise_on_error=True) else '0')
except Exception:
    print('?')" 2>/dev/null | tail -1 || printf '?')
case "$CFM_ST_LOGIN" in
    1) ok "Login user configured" ;;
    0) warn "No login user yet — create the first admin: corpusfm users create <name> --admin"
       CFM_SELFTEST_CRIT=1 ;;
    *) warn "Could not verify the login user — storage was unreachable. This does NOT mean there is none." ;;
esac

# ANY CRITICAL FAILURE REFUSES SUCCESS. The banner and Next steps are below and are unreachable from
# here on a degraded install — which is the whole point: an installer that prints "installed
# successfully" over a broken box is worse than one that fails.
[[ $CFM_SELFTEST_CRIT -eq 0 ]] \
    || die "Post-install verification FAILED — the installation is degraded (see above). Fix the
     reported condition and re-run the installer; refusing to report success."
ok "Post-install verification passed"

# ── S9 Next steps ─────────────────────────────────────────────────────────────
cfm_section "Next steps"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  CORPUSfm installed successfully${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
# THE OPERATOR DISPLAY BASE (correction F6). `CFM_BASE` was read three times here and ASSIGNED
# NOWHERE, so `set -u` aborted the final summary — after phase 21 had already started the services.
# The install had worked and reported a crash.
#
# The published locator is used when the installation has one; otherwise an EXPLICIT placeholder,
# which is a display string and nothing else. It is derived here, before the first line that reads
# it, and it never becomes routing authority: no configuration consumes it, and `deployment` refuses
# to derive an external base from a loopback value rather than inventing one.
CFM_BASE="$(PYTHONPATH="$INSTALL_DIR/src" HOME="$INSTALL_DIR" "$INSTALL_DIR/venv/bin/python" -c \
'from corpusfm.app.web import deployment
try:
    base = deployment.external_base()
except Exception:
    base = ""
print((base or "").rstrip("/"))' 2>/dev/null || true)"
[[ -n "${CFM_BASE:-}" ]] || CFM_BASE="https://<your-fms-host>${WEB_PREFIX}"
echo "  Web UI:    ${CFM_BASE}/   (via the FMS web server; app on loopback :$WEB_PORT)"
echo "  Installer: sudo $INSTALLER_ENTRY_POINT"
echo "  Cleanup:   You may delete the original extracted installer package and ZIP; the installed launcher is the durable entry point."
if [[ "${LOGIN_STATE:-1}" == "0" ]]; then
    echo "  First admin: corpusfm users create <name> --admin   (run on this box; the login page can't create it)"
fi
if $ENABLE_MCP; then
    echo "  MCP:       folded into the web app — ${CFM_BASE}/mcp/ (stateless streamable-HTTP, user-authenticated)"
    echo "  Connect:   mint YOUR OWN token at Library → MCP, then:"
    echo "             claude mcp add --transport http corpusfm ${CFM_BASE}/mcp/   (or omit the header entirely and sign in via the browser)"
    echo "             (trailing slash required; the copy-paste line incl. your token is on Library → MCP; restart Claude Code after adding)"
fi
echo ""
echo "  Logs:      journalctl -u $WEB_SERVICE -f"
[[ -n "${CFM_LOG:-}" ]] && echo "  Install log: $CFM_LOG  (full transcript; re-run with --verbose to watch live)"
echo "  Status:    systemctl status $WEB_SERVICE"
$ENABLE_SCHEDULER && echo "  Scheduler: systemctl status $SCHED_SERVICE"
echo "  CLI:       corpusfm --help"
echo "  Data:      $CFM_STATE_DIR/archive/"
echo ""
if $IS_UPGRADE; then
    echo "  Upgrade complete."
    # Post-update refresh notice (packet 1062) — the SAME notice the web first-load banner shows.
    # Idempotent: the just-restarted service runs the flow on boot; this prints its result (or a
    # no-op line). Never fails the install.
    UPD_NOTICE=$(sudo -u "$SERVICE_USER" -H env PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" -m corpusfm.server.cli update-notice 2>/dev/null || true)
    [[ -n "$UPD_NOTICE" ]] && echo "  $UPD_NOTICE"
fi
echo ""

# ── S10 Farewell ────────────────────────────────────────────────────────────────
# Reached ONLY on full success — the phase-21 post-install verification die()s on any critical failure.
cfm_section "Farewell"
ok "Thank you!"
