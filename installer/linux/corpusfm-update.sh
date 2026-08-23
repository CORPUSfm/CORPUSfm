#!/bin/bash
# corpusfm-update — the fixed, root-owned, one-shot code update (packet 1246-03, decision E4).
#
# The unprivileged corpusfm service may TRIGGER this and may pass it NOTHING. It is invoked by a
# systemd one-shot unit whose ExecStart is this script with no arguments; the service's only grant is
# `systemctl start corpusfm-update.service` through /etc/sudoers.d/corpusfm-update. That is the same
# shape as cfm-db-helper — one command, one purpose, auditable in ten lines of sudoers.
#
# WHY THE SERVICE CANNOT DO THIS ITSELF: a service that can rewrite its own code has, in effect, the
# privilege of whoever can reach the service. It holds no route to the checkout, to git or to any
# ref; this script is the only thing that advances the deployed tree.
#
# THE ONE VALUE THE CALLER SUPPLIES is `expected_head`, and it can only cause a REFUSAL. This script
# resolves origin/main itself and refuses if the resolved tip is not the one the administrator
# authorized. It never checks out the supplied value, never passes it to git, and never lets it make
# an otherwise-ineligible update eligible — every other gate below is evaluated on the tip THIS
# script resolved. (Developer ruling, 2026-08-02.)
#
# Reads the request from a fixed root-owned path; writes the outcome to a fixed root-owned,
# service-READABLE path. Neither is a caller-chosen location.
set -euo pipefail

# ── SILENCE IS STRUCTURAL, AND IT IS THE FIRST THING THAT HAPPENS ─────────────────────
#
# This process now has NO stdout and NO stderr. Everything below inherits that, so no command --
# named by a test or not, existing today or added tomorrow -- can put a byte on a stream this
# script does not control. On an installed box those streams are the journal, and what reaches the
# journal was decided by whatever the child felt like printing.
#
# Three rounds of this packet tried the other way: redirect the invocations, then enumerate them,
# then census them. Each round the claim was refuted by an invocation nobody had listed -- `git
# fetch`, then the command substitutions, then `systemctl is-active`, then a bare `sleep`. A list of
# commands is a list that is wrong the moment somebody adds one, which is the same lesson the
# environment denylist taught two rounds earlier.
#
# ADMINISTRATOR-VISIBLE INFORMATION HAS TWO HOMES, BOTH VALIDATED: the outcome record, written by
# the installed publisher through `UpdateOutcome` + the structural secret fence, and `log()`, which
# writes fixed sentences and validated values to fd 3. Neither is a process stream.
#
# THIS IS THE FIRST EXECUTED STATEMENT, before the first external action rather than merely before
# the interesting ones. An earlier placement sat after `mkdir` and the log open, which left a real
# gap: whatever ran before the boundary could still speak, and a poison that fires on EVERY command
# duly escaped through it. fd 3 is opened below and is unaffected by redirecting 1 and 2 -- that is
# why the log survives and everything else does not.
exec 1>/dev/null 2>/dev/null

# ── FIXED LOCATIONS. No environment override, deliberately. ───────────────────────────
# These were `${CFM_INSTALL_DIR:-…}`-style overrides so tests could redirect them. That is authority
# in an environment variable, inside a script that runs as root and rewrites the code the box
# executes: anything that could set CFM_SRC_DIR could choose the tree this script advances. The
# installer RENDERS these values into the installed copy, so the artifact on disk
# names exactly one installation and nothing at run time can point it elsewhere. Tests exercise this
# script by rendering their own copy, which is a test seam rather than a production input.
INSTALL_DIR="@@INSTALL_DIR@@"
STATE_DIR="@@STATE_DIR@@"
LOG_DIR="@@LOG_DIR@@"
SRC="@@SRC_DIR@@"
VENV_PY="@@VENV_PY@@"
# The tree inspector, as an ADMINISTRATOR-OWNED FILE outside the checkout (R7b). It used to be run
# as `PYTHONPATH="$SRC" python -m corpusfm.lifecycle.tree_inspection`, which loads the judge from
# the tree being judged: a modified helper inside a modified checkout declares that checkout clean.
# The helper imports only the standard library, so it runs from here with nothing to resolve.
HELPER="@@HELPER@@"
# The outcome PUBLISHER, in the same administrator-owned location and for the same reason (N2).
# This script collects the fields; that boundary validates them against the record schema and the
# structural secret fence and performs the atomic write. Nothing here composes JSON any more, so
# there is one implementation of "what may be written into an outcome" rather than three.
PUBLISHER="@@PUBLISHER@@"
# The administrator-owned Python library the publisher and the classifier are loaded from. It is
# deliberately NOT $SRC: both are judgments about the checkout, and a judge loaded from the tree it
# judges is R7b.
LIB_DIR="@@LIB_DIR@@"
# An ABSOLUTE git (R7a). A bare `git` is whatever PATH says, and PATH is settable by anything that
# can set an environment variable on this elevated process.
GIT="@@GIT@@"
REQUEST_FILE="$STATE_DIR/update-inbox/update_request.json"
OUTCOME_FILE="$STATE_DIR/update-outcome/update_outcome.json"
LOG_FILE="$LOG_DIR/update.log"
EXPECTED_ORIGIN="https://github.com/CORPUSfm/CORPUSfm.git"
# The scheduler is restarted and verified here.  The web process is the caller waiting for this
# operation's outcome; update_service schedules its supervised SIGTERM only after the success
# response flushes.  Restarting it here killed the outcome reader and reported a completed update
# as trigger_failed.
SERVICES=(corpusfm-scheduler)

# The allowlist lives in the Python helper (`ALLOWED_EXACT`) and nowhere else. A second copy
# here was never read and could only ever disagree with the one that decides.

# BUILT, not filtered. Unsetting the variables I happened to think of leaves the ones I did not:
# HOME reaches a ~/.gitconfig, XDG_CONFIG_HOME reaches the same file by another route,
# GIT_CONFIG_PARAMETERS injects config directly, and the next release adds more. So the environment
# is CLEARED and then written -- a denylist here is a list that is wrong the moment it is written.
for _v in $(compgen -e); do
    case "$_v" in
        PATH|IFS|HOME|LC_ALL|LANG|TERM|SHELL|PWD|SUDO_USER|SUDO_UID|SUDO_GID|_) ;;
        *) unset "$_v" 2>/dev/null || true ;;
    esac
done
export PATH=/usr/bin:/bin
export IFS=$' \t\n'
export HOME="$INSTALL_DIR"
export XDG_CONFIG_HOME="$INSTALL_DIR/.no-config"
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export LC_ALL=C

mkdir -p "$STATE_DIR/update-inbox" "$STATE_DIR/update-outcome" "$LOG_DIR" >/dev/null 2>&1
exec 3>>"$LOG_FILE"
log() { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" "$*" >&3; }


# The preflight refusals log rather than echo, because after the line above there is nowhere for an
# echo to go. They exit WITHOUT an outcome on purpose: the publisher is one of the things being
# checked for, so there may be nothing able to write one.
[[ -x "$GIT" ]] || { log "REFUSED: $GIT is not executable"; exit 1; }
[[ -f "$HELPER" ]] || { log "REFUSED: $HELPER is missing"; exit 1; }
[[ -f "$PUBLISHER" ]] || { log "REFUSED: $PUBLISHER is missing"; exit 1; }
CLEANER="$INSTALL_DIR/bin/bytecode_cleanup.py"
[[ -f "$CLEANER" ]] || { log "REFUSED: $CLEANER is missing"; exit 1; }

OP_ID="$(date -u '+%Y%m%d%H%M%S' 2>/dev/null)-$$"
TRIGGER_ID=""
REQUESTED=""
OBSERVED=""
RESULT_HEAD=""

# The outcome record: root writes it 0644 so the service can READ it and correlate its trigger with
# what actually happened. It carries SHAs, states and the log LOCATION — never a secret.
#
# THIS FUNCTION WRITES NOTHING. It hands fixed, named fields to the installed publisher, which
# validates them and performs the write. The heredoc that used to live here composed JSON in shell,
# which meant a hand-rolled `json_escape` (a real defect: a carriage return in a planted filename
# produced an outcome nobody could parse) AND a record that never met the structural secret fence
# every other lifecycle record goes through. A refusal from the publisher leaves NO outcome, which
# the service reads as "no result" — correct, and better than a record we could not vouch for.
write_outcome() {
    local state="$1" reason="$2" detail="$3" rolled_back="${4:-false}"
    local err
    local rc=0
    if ! "$VENV_PY" -I "$PUBLISHER" "$STATE_DIR" \
            "operation_id=$OP_ID" \
            "trigger_id=$TRIGGER_ID" \
            "state=$state" \
            "requested_head=$REQUESTED" \
            "observed_head=$OBSERVED" \
            "resulting_head=$RESULT_HEAD" \
            "started_utc=$STARTED" \
            "ended_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" \
            "reason_code=$reason" \
            "detail=$detail" \
            "log_path=$LOG_FILE" \
            "rolled_back=$rolled_back" >/dev/null 2>&1; then
        rc=$?
        # The publisher's own message is redacted, but it is still child output, and "prefer not
        # retaining it" applies to the trusted component too. The exit status says everything an
        # administrator can act on: the record was refused and nothing was written.
        log "NO OUTCOME PUBLISHED (publisher exit $rc)"
    fi
}

STARTED="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"

die() {
    log "REFUSED/FAILED: $2"
    write_outcome "$1" "$2" "$3" "${4:-false}"
    exit 1
}

# ── the request ───────────────────────────────────────────────────────────────────────
# A fixed path, and only two fields are read out of it. Anything else in the file is ignored —
# there is no field that could become a ref, a path, a command or an environment entry.
[[ -f "$REQUEST_FILE" ]] || die refused no_request "no update request was recorded"
TRIGGER_ID="$("$VENV_PY" -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("trigger_id",""))' "$REQUEST_FILE" 2>/dev/null || true)"
REQUESTED="$("$VENV_PY" -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("expected_head",""))' "$REQUEST_FILE" 2>/dev/null || true)"
[[ "$TRIGGER_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || die refused bad_trigger_id "the trigger id is not a plain identifier"
[[ "$REQUESTED" =~ ^[0-9a-f]{40,64}$ ]] || die refused bad_expected_head "expected_head is not a full commit SHA"

log "operation $OP_ID for trigger $TRIGGER_ID; administrator authorized ${REQUESTED:0:12}"

# ── preconditions, every one evaluated on what THIS script resolves ───────────────────
[[ -d "$SRC/.git" ]] || die failed not_git_deployment "$SRC is not a git checkout"

# CANONICAL comparison, never a substring. `*"$EXPECTED_ORIGIN"*` accepts
# https://evil.example/github.com/CORPUSfm/CORPUSfm.git, which is a
# different server entirely. Normalise the few spellings git legitimately produces, then compare
# for equality.
ORIGIN="$("$GIT" -C "$SRC" -c safe.directory='*' remote get-url origin 2>/dev/null || true)"
CANON="${ORIGIN%.git}"; CANON="${CANON%/}"
CANON="${CANON#git@github.com:}"
CANON="${CANON#https://github.com/}"
CANON="${CANON#ssh://git@github.com/}"
if [[ "$CANON" != "CORPUSfm/CORPUSfm" ]]; then
    die refused origin_mismatch "the checkout origin is not the expected CORPUSfm repository"
fi

# THE WHOLE TREE, inspected by a bounded Python helper rather than parsed in shell.
#
# Git pathnames are not a shell datatype: quoted spellings, embedded newlines and non-UTF-8 bytes
# each produced a real defect in the shell version, and each fix produced a subtler one. The helper
# reads NUL-delimited porcelain INCLUDING ignored files (`.gitignore` covers archive/ and
# __pycache__/, so a planted `archive/__init__.py` never reached the old check at all), allows only
# exact installer artifacts, and returns JSON so nothing here has to parse a pathname.
# STDERR IS DISCARDED, not folded into the JSON. `2>&1` merged the helper's diagnostics into the
# document we then parse, so a crashing helper produced unparseable "problems" and, worse, put raw
# child output on a path that ends in the outcome record. The helper's STDOUT is a bounded JSON
# document; nothing else from it is kept.
# Retire only ordinary generated .pyc files in ordinary __pycache__ directories.  The
# administrator-owned cleaner refuses links, nested directories and every non-.pyc entry; the
# tree inspector below still sees and refuses all arbitrary ignored/importable content.
"$VENV_PY" -I "$CLEANER" "$SRC" >/dev/null 2>&1 \
    || die refused unclean_tree "runtime bytecode residue could not be safely retired"
TREE_JSON="$("$VENV_PY" "$HELPER" "$SRC" 2>/dev/null)" \
    && TREE_RC=0 || TREE_RC=$?
if [[ "$TREE_RC" -ne 0 ]]; then
    TREE_DETAIL="$(printf '%s' "$TREE_JSON" | "$VENV_PY" -I -c 'import json,sys
try:
    print("; ".join(json.load(sys.stdin).get("problems", []))[:400])
except Exception:
    print("the deployed checkout could not be inspected")' 2>/dev/null || true)"
    # The ONE piece of child-derived text that is retained, and it goes to exactly one place: the
    # trusted publisher, which runs the structural secret fence over the whole record before writing
    # it. Nothing here logs it.
    die refused unclean_tree "$TREE_DETAIL"
fi

# NO RAW CHILD OUTPUT CROSSES THIS BOUNDARY (N2). git's stderr used to reach this process's own
# stderr and therefore the journal, unread and unfenced -- and a fetch failure is where a REMOTE
# gets to choose the text. Exit status is the whole signal; the bytes are discarded.
"$GIT" -C "$SRC" -c safe.directory='*' fetch --quiet origin main >/dev/null 2>&1 \
    || die failed fetch_failed "could not fetch origin/main"

# `2>/dev/null` on EVERY capture, not just the ones that were obviously risky. A command
# substitution passes the child's stderr straight through to this process's stderr, which on an
# installed box is the journal -- so `rev-parse`, `diff` and `merge-base` were each an unfenced
# path for text a remote or a tampered checkout composed. Exit status and stdout are the signal.
OLD_HEAD="$("$GIT" -C "$SRC" -c safe.directory='*' rev-parse HEAD 2>/dev/null)"
OBSERVED="$("$GIT" -C "$SRC" -c safe.directory='*' rev-parse origin/main 2>/dev/null)"
# CAPTURED IS NOT VALIDATED. Two commit ids decide what gets merged and what the outcome record
# says landed, and they arrive as whatever the child printed. A value that is not a commit id is a
# child that did something else -- refuse rather than carry it forward into a merge argument.
[[ "$OLD_HEAD"  =~ ^[0-9a-f]{40,64}$ ]] || die failed head_unreadable "the deployed head could not be read as a commit"
[[ "$OBSERVED" =~ ^[0-9a-f]{40,64}$ ]] || die failed head_unreadable "origin/main could not be resolved to a commit"

# Forward only. A tip that is not a descendant of HEAD is not an update.
if [[ "$OLD_HEAD" != "$OBSERVED" ]]; then
    "$GIT" -C "$SRC" -c safe.directory='*' merge-base --is-ancestor "$OLD_HEAD" "$OBSERVED" \
        >/dev/null 2>&1 || die refused not_fast_forward "origin/main is not a fast-forward of the deployed head"
fi

# CLASSIFY. Privileged change classes refuse the in-app path and name the elevated installer.
CHANGED="$("$GIT" -C "$SRC" -c safe.directory='*' diff --name-only "$OLD_HEAD..$OBSERVED" 2>/dev/null)"
if [[ -n "$CHANGED" ]]; then
    # The verdict goes to STDOUT and stderr is discarded (N2): the classifier's own sentence is
    # bounded text that the publisher will fence, but a traceback from a failed import is raw child
    # output and must not be retained. Merging the two put both on the same path.
    if ! CLASSIFY="$(printf '%s\n' "$CHANGED" | PYTHONPATH="$LIB_DIR" "$VENV_PY" -c '
import sys
from corpusfm.lifecycle import update_boundary as ub
paths = [p.strip() for p in sys.stdin if p.strip()]
result = ub.classify(paths)
if result.requires_installer:
    sys.stdout.write(result.reason())
    raise SystemExit(1)
' 2>/dev/null)"; then
        die refused needs_installer "$CLASSIFY"
    fi
fi

# CONSENT, EVALUATED LAST. EXACT equality (ruling O2), and deliberately AFTER the
# fast-forward and classification gates above -- every one of those is decided on the tip THIS
# script resolved, so the administrator's value can only ever REFUSE. Comparing it first put it
# in FRONT of those gates, which is the shape of a value that selects rather than consents. A prefix
# match would let a 7-character abbreviation authorize every commit sharing it, including one nobody
# has seen yet -- which is the very case where the administrator should be sent back to update_check.
if [[ "$OBSERVED" != "$REQUESTED" ]]; then
    die refused target_changed "origin/main is now ${OBSERVED:0:12}, but this update was authorized for ${REQUESTED:0:12}. Check for updates again and authorize the current tip."
fi

# ── apply ─────────────────────────────────────────────────────────────────────────────
# The installed build stamp is runtime identity, not source. Git therefore cannot restore it for
# us. Preserve its pre-operation state before the merge so checkout + identity remain one
# transaction, including the authorized same-head repair case.
STAMP="$SRC/corpusfm/_build.txt"
RELEASE_BUILD="$SRC/release-build.txt"
STAMP_BACKUP="$INSTALL_DIR/bin/.corpusfm-buildstamp-$OP_ID.backup"
STAMP_STAGE="$INSTALL_DIR/bin/.corpusfm-buildstamp-$OP_ID.stage"
STAMP_EXISTED=false
if [[ -L "$STAMP" || ( -e "$STAMP" && ! -f "$STAMP" ) ]]; then
    die refused invalid_build_stamp "the installed build stamp is not an ordinary file"
fi
if [[ -f "$STAMP" ]]; then
    cp -p -- "$STAMP" "$STAMP_BACKUP" >/dev/null 2>&1 \
        || die failed build_stamp_unreadable "the installed build stamp could not be preserved"
    STAMP_EXISTED=true
fi

read_release_build() {
    local value
    [[ -f "$RELEASE_BUILD" && ! -L "$RELEASE_BUILD" ]] || return 1
    value="$(cat -- "$RELEASE_BUILD" 2>/dev/null || true)"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
    printf '%s' "$value"
}

restore() {
    log "restoring $SRC to ${OLD_HEAD:0:12}"
    "$GIT" -C "$SRC" -c safe.directory='*' reset --hard "$OLD_HEAD" >/dev/null 2>&1 || true
    if [[ "$STAMP_EXISTED" == true ]]; then
        cp -p -- "$STAMP_BACKUP" "$STAMP_STAGE" >/dev/null 2>&1 \
            && mv -f -- "$STAMP_STAGE" "$STAMP" >/dev/null 2>&1 || true
    else
        rm -f -- "$STAMP" >/dev/null 2>&1 || true
    fi
    rm -f -- "$STAMP_BACKUP" "$STAMP_STAGE" >/dev/null 2>&1 || true
    for svc in "${SERVICES[@]}"; do systemctl restart "$svc" >/dev/null 2>&1 || true; done
}

log "advancing $SRC from ${OLD_HEAD:0:12} to ${OBSERVED:0:12}"
if ! "$GIT" -C "$SRC" -c safe.directory='*' merge --ff-only "$OBSERVED" >/dev/null 2>&1; then
    rm -f -- "$STAMP_BACKUP" "$STAMP_STAGE" >/dev/null 2>&1 || true
    die failed pull_failed "the fast-forward did not apply"
fi

# Stamp the declared build of the HEAD that was actually applied. Public history is intentionally
# short and its commit count is not the product build. A same-head invocation deliberately reaches
# this block: it is the bounded repair for a current checkout whose installed identity is stale.
if ! NEW_BUILD="$(read_release_build)"; then
    restore
    RESULT_HEAD="$OLD_HEAD"
    die failed build_stamp_failed "the applied checkout release-build.txt was not valid; rolled back" true
fi
rm -f -- "$STAMP_STAGE" >/dev/null 2>&1 || true
if [[ "$STAMP_EXISTED" == true ]]; then
    cp -p -- "$STAMP_BACKUP" "$STAMP_STAGE" >/dev/null 2>&1 || true
else
    install -m 0640 -o root -g root /dev/null "$STAMP_STAGE" >/dev/null 2>&1 || true
    chown --reference="$SRC" "$STAMP_STAGE" >/dev/null 2>&1 || true
fi
if [[ ! -f "$STAMP_STAGE" ]] \
        || ! printf '%s\n' "$NEW_BUILD" > "$STAMP_STAGE" \
        || [[ "$(tr -d '[:space:]' < "$STAMP_STAGE" 2>/dev/null || true)" != "$NEW_BUILD" ]] \
        || ! mv -f -- "$STAMP_STAGE" "$STAMP" >/dev/null 2>&1 \
        || [[ "$(tr -d '[:space:]' < "$STAMP" 2>/dev/null || true)" != "$NEW_BUILD" ]]; then
    restore
    RESULT_HEAD="$OLD_HEAD"
    die failed build_stamp_failed "the applied checkout build stamp could not be written and verified; rolled back" true
fi

# A fresh interpreter must be able to load the new code. A pull that added an import the runtime
# lacks passes every path gate above and would crash-loop the restarted service.
# The import probe DOES load the new code — that is its whole purpose — so it is the one place the
# checkout is on the path, after every gate above has passed and in a subshell of its own.
# The probe LOADS THE NEW CODE, so its output is the least trustworthy text in this script: an
# import error message is composed from the tree being tested. Exit status only.
if ! (cd "$SRC" && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SRC" "$VENV_PY" -c 'import corpusfm.app.web.app') >/dev/null 2>&1; then
    restore
    RESULT_HEAD="$OLD_HEAD"
    die refused import_probe_failed "the new code did not load in a fresh interpreter; rolled back" true
fi

for svc in "${SERVICES[@]}"; do
    systemctl restart "$svc" >/dev/null 2>&1 || true
done

sleep 3
FAILED_SVC=""
for svc in "${SERVICES[@]}"; do
    systemctl is-active --quiet "$svc" >/dev/null 2>&1 || FAILED_SVC="$svc"
done
if [[ -n "$FAILED_SVC" ]]; then
    restore
    RESULT_HEAD="$OLD_HEAD"
    die failed service_did_not_start "$FAILED_SVC did not come back; rolled back" true
fi

RESULT_HEAD="$("$GIT" -C "$SRC" -c safe.directory='*' rev-parse HEAD 2>/dev/null)"
[[ "$RESULT_HEAD" =~ ^[0-9a-f]{40,64}$ ]] || RESULT_HEAD=""
FINAL_BUILD="$(read_release_build || true)"
if [[ -z "$RESULT_HEAD" || ! "$FINAL_BUILD" =~ ^[1-9][0-9]*$ \
        || "$(tr -d '[:space:]' < "$STAMP" 2>/dev/null || true)" != "$FINAL_BUILD" ]]; then
    restore
    RESULT_HEAD="$OLD_HEAD"
    die failed build_stamp_mismatch "the resulting checkout and runtime build stamp disagree; rolled back" true
fi
rm -f -- "$STAMP_BACKUP" "$STAMP_STAGE" >/dev/null 2>&1 || true
log "completed at ${RESULT_HEAD:0:12}"
write_outcome completed ok "update applied and the services are running"
