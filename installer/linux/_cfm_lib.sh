# shellcheck shell=bash
# _cfm_lib.sh - CORPUSfm shared script library (the SS1-SS10 contract skeleton).
#
# Sourced by every Tier-1/Tier-2 bash script (installer SPEC.md, "Script conformance").
# It is the enforcement mechanism: scripts use these primitives + the section/step runners and
# MUST NOT define their own (header/success/etc. are banned in script bodies). The PowerShell
# twin is _cfm_lib.ps1 - keep the two APIs identical in name + behavior.
#
# Provides:
#   - five canonical output primitives: hello info ok warn die   (--silent muting baked in)
#   - cfm_section <title>          : the section runner (labels the log even for a no-op body)
#   - cfm_step / cfm_run_steps     : the SS7 step-runner (retry/recover, hard-fail -> jump to SS8)
#   - cfm_summary                  : the SS8 tally ("N/N completed" | "k/N: failed on <step>")
#
# Sourced, never executed. Assumes the caller runs `set -euo pipefail`; the step-runner brackets
# failures itself so a failing step never trips the caller's `set -e`.

# Idempotent guard - safe to source more than once (an installer that re-execs itself).
[ -n "${CFM_LIB_SOURCED:-}" ] && return 0
CFM_LIB_SOURCED=1

# -- Silence ---------------------------------------------------------------------------------------
# CFM_SILENT=true  -> non-interactive: suppress decoration (hello / section banners / info),
# keep ok+warn (state), always keep die (failure). Set by the caller's --silent/--yes parsing
# BEFORE the first primitive call, or via the CFM_SILENT env. "Ceremony and silence are the same
# gear": a helper and an installer-under---silent share this one non-interactive path.
CFM_SILENT="${CFM_SILENT:-false}"
cfm_is_silent() { [ "$CFM_SILENT" = true ]; }

# -- Colors (TTY only) -----------------------------------------------------------------------------
if [ -t 1 ]; then
    CFM_RED=$'\033[0;31m'; CFM_GREEN=$'\033[0;32m'; CFM_YELLOW=$'\033[1;33m'
    CFM_CYAN=$'\033[0;36m'; CFM_DIM=$'\033[2m'; CFM_NC=$'\033[0m'
else
    CFM_RED=''; CFM_GREEN=''; CFM_YELLOW=''; CFM_CYAN=''; CFM_DIM=''; CFM_NC=''
fi

# -- Transcript log + verbosity (always-on install log; --verbose console detail) ------------------
# Two orthogonal output controls layered over the primitives:
#   CFM_LOG     - path to an always-on transcript. When set (via cfm_log_init), EVERY primitive +
#                 section banner is ALSO appended as a plain, timestamped line, and cfm_run streams
#                 a command's full output to it. Console output is UNCHANGED, so this is invisible
#                 to the operator until something fails (die points them at it).
#   CFM_VERBOSE - "true" shows cfm_run command output on the CONSOLE too (concise by default: that
#                 detail goes only to the log). Set by the caller's --verbose parsing or the env.
# Both default off, so a script that never calls cfm_log_init behaves exactly as before.
CFM_LOG="${CFM_LOG:-}"
CFM_VERBOSE="${CFM_VERBOSE:-false}"
cfm_is_verbose() { [ "$CFM_VERBOSE" = true ]; }
_cfm_ts() { date '+%Y-%m-%d %H:%M:%S'; }
# Append one plain, timestamped line to the transcript (no-op when no log / unwritable).
_cfm_logline() { [ -n "$CFM_LOG" ] && printf '%s  %s\n' "$(_cfm_ts)" "$*" >>"$CFM_LOG" 2>/dev/null; return 0; }

# cfm_log_init <path> - begin the always-on transcript. Reuses CFM_LOG from the env when already set
# (so a self-pull re-exec continues ONE transcript instead of splitting it). An unwritable path
# disables the transcript rather than failing the install. Exports CFM_LOG for any re-exec'd child.
cfm_log_init() {
    [ -n "$CFM_LOG" ] || CFM_LOG="$1"
    mkdir -p "$(dirname "$CFM_LOG")" 2>/dev/null || true
    if ! : >>"$CFM_LOG" 2>/dev/null; then CFM_LOG=""; return 0; fi
    export CFM_LOG
    _cfm_logline "=== transcript opened (verbose=$CFM_VERBOSE, pid=$$) ==="
}

# cfm_run <label> <cmd> [args...] - run a command as part of the install. Its combined output is
# ALWAYS captured to the transcript; it reaches the console only under --verbose (concise default).
# Returns the command's exit code, so callers keep `cfm_run ... || die "..."`. With neither a log
# nor verbose it just runs the command (pre-Batch-4 behavior).
cfm_run() {
    local label="$1"; shift
    _cfm_logline "\$ [$label] $*"
    if [ -z "$CFM_LOG" ] && ! cfm_is_verbose; then "$@"; return $?; fi
    local rc=0
    if cfm_is_verbose; then
        if [ -n "$CFM_LOG" ]; then "$@" 2>&1 | tee -a "$CFM_LOG"; rc=${PIPESTATUS[0]}
        else "$@"; rc=$?; fi
    else
        "$@" >>"$CFM_LOG" 2>&1; rc=$?
    fi
    return $rc
}

# -- The five canonical primitives -----------------------------------------------------------------
# hello : SS1 identity line ("I am this script. I do this thing.") - decoration, muted when silent.
# info  : progress narration - decoration, muted when silent.
# ok    : a positive state result - always shown (it is the record of what happened).
# warn  : a non-fatal problem - always shown.
# die   : a fatal problem - always shown, to stderr, then exit 1.
# Each also records a plain timestamped line to the transcript (when active) - the console form is
# unchanged, so the transcript is a complete, greppable history without altering what the operator sees.
hello() { _cfm_logline "==> $*"; cfm_is_silent || printf '%s\n%s==>%s %s\n' "" "$CFM_CYAN" "$CFM_NC" "$*"; }
info()  { _cfm_logline "  > $*"; cfm_is_silent || printf '%s  > %s%s\n' "$CFM_CYAN" "$*" "$CFM_NC"; }
ok()    { _cfm_logline "  + $*"; printf '%s  + %s%s\n' "$CFM_GREEN" "$*" "$CFM_NC"; }
warn()  { _cfm_logline "  ! $*"; printf '%s  ! %s%s\n' "$CFM_YELLOW" "$*" "$CFM_NC"; }
die()   {
    _cfm_logline "  x $*"
    printf '%s  x %s%s\n' "$CFM_RED" "$*" "$CFM_NC" >&2
    if [ -n "$CFM_LOG" ]; then
        _cfm_logline "(install aborted - see this transcript)"
        printf '%s    full install log: %s%s\n' "$CFM_DIM" "$CFM_LOG" "$CFM_NC" >&2
    fi
    exit 1
}

# -- Section runner --------------------------------------------------------------------------------
# cfm_section "<title>" - opens one of the ten contract sections. Emits a uniform, numbered
# boundary so every script's transcript has the SAME shape, even when the body is a ceremonial
# no-op. Under --silent the banner collapses to a single dim line (still present, for the record).
CFM_SECTION_NO=0
cfm_section() {
    CFM_SECTION_NO=$((CFM_SECTION_NO + 1))
    _cfm_logline "=== S$CFM_SECTION_NO  $* ==="
    if cfm_is_silent; then
        printf '%s-- S%d %s --%s\n' "$CFM_DIM" "$CFM_SECTION_NO" "$*" "$CFM_NC"
    else
        printf '\n%s=== S%d  %s ===%s\n' "$CFM_CYAN" "$CFM_SECTION_NO" "$*" "$CFM_NC"
    fi
}

# -- Consent (SS6) ---------------------------------------------------------------------------------
# cfm_confirm "<prompt>" ["<skip_reason>"] - the ONE consent gate (packet 1228). Every Tier-1 script
# calls this; none hand-rolls a prompt. The prompt STRING lives here and nowhere else, so the four
# scripts cannot disagree about what the operator types - which is exactly how they came to disagree
# (bash `[y/N]` vs PowerShell "Type 'yes' to continue", split by OS rather than by consequence).
#
# Proceeds without waiting when EITHER:
#   * a consent flag is set - CFM_SILENT / CFM_ASSUME_YES / CFM_FORCE - which IS a pre-given
#     confirmation, or
#   * <skip_reason> is non-empty: the caller's SCOPE answer, computed before SS6.
#
# The scope answer arrives as ONE value the caller computes, never as logic in here: the library
# cannot know what "outside this install's footprint" means for a given script. That also keeps the
# SS6 body greppable - it references one name plus the consent flags and nothing else, which is what
# lets the conformance guard still prove "credentials are never consent" after the SPEC's absolute
# form was relaxed.
#
# NEVER add a credential variable to this function or its callers' SS6 bodies. A supplied password is
# the MEANS to mutate; it is not permission (packet 020).
# CONSENT IS NOT INHERITED (packet 1236, finding 3). These start false ALWAYS - never seeded from the
# environment - so a stale `export`, a `sudo -E`, or a wrapper script cannot turn a first run into an
# unconfirmed one. A caller grants consent by setting them AFTER parsing its own flags.
#
# The `${VAR:-false}` idiom used here previously came from CFM_SILENT, where it is legitimate: silence
# is an OUTPUT mode that a Tier-2 helper genuinely inherits from its caller ("ceremony and silence are
# the same gear", SPEC). Consent is not an output mode, and copying the idiom carried a property that
# should not have travelled with it. CFM_FORCE was the sharper case: exported, it granted INSTALLER
# consent through a flag the installers deliberately do not accept, routing around the uninstall-only
# ruling entirely.
CFM_ASSUME_YES=false
CFM_FORCE=false
cfm_confirm() {
    local prompt="${1:-Proceed?}" skip="${2:-}" reply=""
    if [ "$CFM_SILENT" = true ] || [ "$CFM_ASSUME_YES" = true ] || [ "$CFM_FORCE" = true ]; then
        info "Proceeding (consent pre-granted by flag)."
        return 0
    fi
    if [ -n "$skip" ]; then
        info "Proceeding - $skip."
        return 0
    fi
    read -rp "  $prompt [y/N] " reply
    case "$reply" in
        [Yy]) return 0 ;;
        *) echo "  Aborted - nothing changed."; exit 0 ;;
    esac
}

# -- Step runner (SS7) + tally (SS8) ---------------------------------------------------------------
# Register ordered, named steps; run them in order; on a step failure attempt retry then an
# optional recover hook; if it still fails, STOP (no silent continuation past a fatal step) and
# leave the failure recorded for cfm_summary. Parallel indexed arrays keep it bash-3.2-safe.
CFM_STEP_NAMES=()      # display name per step
CFM_STEP_FNS=()        # the function/command that performs the step
CFM_STEP_RECOVER=()    # optional recover function (empty = none)
CFM_STEP_RETRIES=()    # retry count on failure (0 = try once)
CFM_STEP_TOTAL=0
CFM_STEP_DONE=0
CFM_FAILED_STEP=""     # name of the step that ultimately failed ("" = none)

cfm_step_reset() {
    CFM_STEP_NAMES=(); CFM_STEP_FNS=(); CFM_STEP_RECOVER=(); CFM_STEP_RETRIES=()
    CFM_STEP_TOTAL=0; CFM_STEP_DONE=0; CFM_FAILED_STEP=""
}

# cfm_step "<name>" "<fn>" ["<recover_fn>"] ["<retries>"]
cfm_step() {
    CFM_STEP_NAMES+=("$1")
    CFM_STEP_FNS+=("$2")
    CFM_STEP_RECOVER+=("${3:-}")
    CFM_STEP_RETRIES+=("${4:-0}")
    CFM_STEP_TOTAL=$((CFM_STEP_TOTAL + 1))
}

# Run a single registered step (by index) with retry + recover. Returns 0 on success, 1 on
# ultimate failure. Brackets the call so the caller's `set -e` is never tripped by a try.
_cfm_run_one() {
    local i="$1" name="${CFM_STEP_NAMES[$1]}" fn="${CFM_STEP_FNS[$1]}"
    local recover="${CFM_STEP_RECOVER[$1]}" retries="${CFM_STEP_RETRIES[$1]}"
    local attempt=0 rc=0
    while :; do
        rc=0; ( "$fn" ) || rc=$?
        [ "$rc" -eq 0 ] && return 0
        if [ "$attempt" -lt "$retries" ]; then
            attempt=$((attempt + 1))
            warn "step '$name' failed (rc=$rc) - retry $attempt/$retries"
            continue
        fi
        break
    done
    if [ -n "$recover" ]; then
        warn "step '$name' failed - attempting recovery"
        if ( "$recover" ); then ok "recovered after '$name'"; return 0; fi
    fi
    return 1
}

# cfm_run_steps - run all registered steps in order. On the first ultimate failure, record it and
# STOP (jump straight to SS8) -- UNLESS CFM_FORCE is set, in which case record it and CONTINUE.
# Returns 0 iff everything completed.
#
# The force branch is what makes `--force` mean what the SPEC says (packet 1235). Until now the flag
# reached cfm_confirm and nothing else: the runner never consulted it, so `--force` granted consent
# and no more, while the SPEC advertised "continue past a failed step". Fail-closed, but a governing
# document asserting behaviour the code lacks is the defect packet 1229 exists to cure.
#
# EVERY failure is recorded, not just the first (CFM_FAILED_STEPS), so SS8 cannot report N/N after a
# forced run walked past two of them. A best-effort mode that ends in a clean verdict is worse than no
# best-effort mode at all.
CFM_FAILED_STEPS=()
cfm_run_steps() {
    local i
    for ((i = 0; i < CFM_STEP_TOTAL; i++)); do
        info "${CFM_STEP_NAMES[$i]} ..."
        if _cfm_run_one "$i"; then
            CFM_STEP_DONE=$((CFM_STEP_DONE + 1))
            ok "${CFM_STEP_NAMES[$i]}"
        else
            CFM_FAILED_STEPS+=("${CFM_STEP_NAMES[$i]}")
            [ -z "$CFM_FAILED_STEP" ] && CFM_FAILED_STEP="${CFM_STEP_NAMES[$i]}"
            if [ "$CFM_FORCE" = true ]; then
                warn "step '${CFM_STEP_NAMES[$i]}' failed - continuing (--force)"
                continue
            fi
            return 1
        fi
    done
    [ ${#CFM_FAILED_STEPS[@]} -eq 0 ] || return 1
    return 0
}

# cfm_summary - SS8 verdict. Echoes the tally; returns 0 iff everything completed.
cfm_summary() {
    if [ ${#CFM_FAILED_STEPS[@]} -eq 0 ] && [ -z "$CFM_FAILED_STEP" ]; then
        ok "$CFM_STEP_DONE/$CFM_STEP_TOTAL steps completed"
        return 0
    fi
    if [ ${#CFM_FAILED_STEPS[@]} -gt 1 ]; then
        warn "$CFM_STEP_DONE/$CFM_STEP_TOTAL: failed on ${#CFM_FAILED_STEPS[@]} steps - ${CFM_FAILED_STEPS[*]}"
    else
        warn "$CFM_STEP_DONE/$CFM_STEP_TOTAL: failed on '$CFM_FAILED_STEP'"
    fi
    return 1
}

# -- Asking FileMaker Server a question (packets 1238, 1237) ---------------------------------------
# fm_db_hosted <name> - is this database hosted? THREE answers, not two:
#   0 = hosted   1 = not hosted   2 = COULD NOT ASK
#
# The two-answer form (`fmsadmin ... list files | grep -q NAME`) reports the PIPELINE's status, which
# is grep's, so a call that FAILED - credentials rejected (exit 9, empty stdout), FMS down mid-restart
# - is indistinguishable from a clean "not hosted". Both installers acted on that: install.sh deployed
# the shipped blank template over whatever was at the destination, and Linux has no mandatory locking
# to stop it. Capture the status separately and let the caller decide what a non-answer means.
#
# Lives here rather than in either script because BOTH need it, and because it is the only
# language-independent way to name FMS's state: `close` failing because a database is not hosted and
# `close` failing because FMS refused are the same exit code with different English prose, and a
# localised FMS matches no English pattern at all.
#
# Reads FM_ADMIN_USER / FM_ADMIN_PASS from the caller's environment at call time.
fm_db_hosted() {
    local name="$1" out rc=0
    out=$(fmsadmin -u "$FM_ADMIN_USER" -p "$FM_ADMIN_PASS" list files 2>/dev/null) || rc=$?
    [[ $rc -ne 0 ]] && return 2
    grep -qiw -- "$name" <<<"$out" && return 0
    return 1
}
