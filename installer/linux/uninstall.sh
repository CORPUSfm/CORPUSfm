#!/usr/bin/env bash
# CORPUSfm Server — Uninstall LAUNCHER (packet 1246-09, stage 6)
#
# **This script removes nothing.** It elevates, builds one strict privileged request, calls
# `corpusfm-lifecycle uninstall start|resume`, reads exactly one JSON result, and prints it. Every
# decision about what may be deleted — and every deletion — belongs to the lifecycle component,
# which makes them from what this installation RECORDED about itself and re-proves each target
# immediately before acting.
#
# What this file deliberately does NOT contain, because each of them was a defect here:
#   * no deletion planning and no deletion. Not a path, not a service, not an account, not a file.
#   * no path or default authority. No `--install-root`, no `--config-home`, no `FM_DB_DIR`, no
#     hardcoded database location. A caller that supplies a target could supply any target.
#   * no database-name search and no `Removed_by_FMS` traversal. The retired uninstaller walked
#     FileMaker Server's own recovery folder by name and deleted what matched — capable of removing
#     an administrator's databases.
#   * no `--keep-data`. It left an installation the installer then refused to reinstall over.
#   * no direct FMS, proxy, service, account or file removal, and no `fmsadmin` call.
#   * no persisted credential. A known required FMS credential is validated before confirmation,
#     held by this launcher for this one run, framed afresh to each lifecycle call that needs it,
#     wiped when the run ends, and never written to the request or log.
#
# Usage:
#   sudo <install-dir>/uninstall.sh [OPTIONS]
#
# Options (the complete set; every other option is refused as unknown):
#   --yes       Consent pre-granted: no confirmation prompt, normal output.
#   --force     --yes, PLUS continue past work that cannot be completed now (the lifecycle
#               component still refuses anything it has no authority for).
#   --credential-stdin (with --silent) reads ONE credential frame from this launcher's standard
#               input: a 4-byte big-endian length and UTF-8 account, then the same for the password.
#               It is the only non-interactive route. The values never enter an environment
#               variable, an argument list, the request, the transcript or the output. A malformed,
#               truncated, empty or over-long frame, or trailing bytes, is refused before anything
#               is removed. Without it, a console run prompts and a --silent run stops
#               incomplete_safe with the credential-dependent work recorded and resumable.
#   --silent    --yes, PLUS decoration suppressed and detail routed to the transcript. NEVER prompts
#               for anything, including a credential.
#   --verbose   Stream detail to the console (it always reaches the transcript).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=installer/linux/_cfm_lib.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/_cfm_lib.sh"

# ── S1 Hello ──────────────────────────────────────────────────────────────────
cfm_section "Hello"
hello "CORPUSfm Uninstall"
info "Asks this installation's lifecycle component to remove exactly what it recorded."

# ── S2 Self-check ─────────────────────────────────────────────────────────────
cfm_section "Self-check"
# `id -u` rather than `$EUID`, and the difference is not style: a shell builtin cannot be observed
# from outside the process, so a launcher whose only elevation check was `$EUID` could be executed in
# a suite exactly once — as root — which is to say never. The probe is an ordinary command, so the
# whole protocol below can be driven through doubles.
#
# **This is not the security boundary and must never be mistaken for one.** The lifecycle CLI judges
# every request on the OPEN DESCRIPTOR and refuses one that is not root-owned, so a run that somehow
# got past here reaches exactly one step further and is refused there.
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

# Options — parsed on the root pass ("$@" survived the re-exec above). Consent and output only.
# **Every retired option is refused as unknown, and named**, because a flag that is silently ignored
# is worse than one that errors: `--keep-data` used to change what survived, and an operator who
# passes it to a build that dropped it must not be told the run succeeded on their terms.
SILENT=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)      export CFM_FORCE=true CFM_ASSUME_YES=true; shift ;;
        --yes)        export CFM_ASSUME_YES=true; shift ;;
        --silent)     SILENT=true; export CFM_SILENT=true CFM_ASSUME_YES=true; shift ;;
        # Reads ONE lifecycle credential frame from this launcher's own stdin - the same wire shape
        # the lifecycle component already consumes. Packet 1236 removed the environment route on
        # purpose: an exported credential is inherited by apt-get, git and pip, which is not
        # "transient" in the sense SPEC 4 promises. A frame on stdin is inherited by nothing,
        # appears in no argv, and is consumed once. --silent only.
        --credential-stdin) CREDENTIAL_STDIN=true; shift ;;
        --verbose|-v) export CFM_VERBOSE=true; shift ;;
        -h|--help)    sed -n '/^# Usage:/,/^[^#]/{ /^#/p }' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) die "Unknown option: $1  (use --help)

       If you are looking for --keep-data, --fm-admin-user, --fm-admin-pass, --install-root or
       --config-home: they are gone. Uninstall removes exactly what this installation recorded as
       its own, and an FMS administrator credential is requested by CORPUSfm itself, only if a
       recorded operation turns out to need one." ;;
    esac
done
FORCE="${CFM_FORCE:-false}"

# The transcript is a SIBLING of the installation's log directory, never inside it: `log_dir` is one
# of the trees the uninstall removes, and a log inside the tree being deleted is not a log. A
# transcript that cannot be opened is reported and the run continues — losing the log is not a reason
# to leave an installation half-removed, and every message still reaches the console.
cfm_log_init "${CFM_UNINSTALL_LOG:-/var/log/corpusfm-uninstall-$(date +%Y%m%d-%H%M%S).log}"
if [[ -n "${CFM_LOG:-}" ]]; then ok "Uninstall transcript: $CFM_LOG"; else warn "No transcript could be opened; detail goes to the console only."; fi

# THE PROGRAM TO RUN: the interpreter of the installation this launcher was installed into. The
# installer provisions the launcher directly in the installation directory, so its own directory IS
# that root, for a default or a non-default `--install-dir` alike (packet 1397 D1). There is no
# fallback to a default path: a guessed root would aim this uninstall at another installation, or at
# none.
CFM_ROOT="$SCRIPT_DIR"
PY="$CFM_ROOT/venv/bin/python"
[[ -x "$PY" ]] || die "This launcher runs the CORPUSfm installation it was installed into, and none is
       beside it: $PY does not exist.
       Run the uninstall.sh inside the CORPUSfm installation directory."
CFM_LIFECYCLE=("$PY" -m corpusfm.lifecycle)

# The lifecycle process may successfully remove the installed interpreter before this launcher
# validates its final JSON result. POSIX lets the RUNNING lifecycle process survive that unlink,
# but a SECOND invocation of the same path cannot start afterwards. Ubuntu's fixed system Python is
# therefore the result/request document reader. It holds no product code and no deletion authority;
# refuse before the uninstall boundary if the supported host does not provide its stdlib JSON
# reader. Never resolve it through PATH.
RESULT_PY="/usr/bin/python3"
[[ -x "$RESULT_PY" ]] && "$RESULT_PY" -I -c 'import json' </dev/null 2>/dev/null || die \
    "The fixed JSON result reader $RESULT_PY is unavailable. Nothing has been changed."

# ── S3 Settings ───────────────────────────────────────────────────────────────
cfm_section "Settings"
warn "This removes CORPUSfm from this machine: its services, its software, its data, and the"
warn "FileMaker Server registrations it made. Databases and folders it did not create are kept."
# **The storage database is named, not left inside the word "data".** It is the one thing removed
# here that a human would describe as their own — every snapshot, artifact, job and setting this
# installation holds lives in it — and an operator who reads "its data" has not been told that.
warn "Its data includes the CORPUSfm storage DB this installation created on FileMaker Server:"
warn "it is closed and removed with everything in it. Copy it first if you want to keep it."

# WHICH INSTALLATION — read from the shipped read-only verb, never from a path this script chose.
# The exit status is deliberately not fatal here: a status that reports an interrupted operation is
# still a status, and the uninstall verb has its own, better refusals for every one of those states.
LC_STATUS="$("${CFM_LIFECYCLE[@]}" status --json 2>>"${CFM_LOG:-/dev/null}" || true)"
INSTALLATION_ID="$(printf '%s' "$LC_STATUS" | "$RESULT_PY" -I -c \
    'import json,sys
try:
    print(json.load(sys.stdin).get("installation_id", ""))
except Exception:
    print("")' 2>/dev/null || true)"
[[ -n "$INSTALLATION_ID" ]] || die "No CORPUSfm installation record was found on this machine.
       \`corpusfm-lifecycle status --json\` reported no installation_id, so there is nothing to
       uninstall and nothing this launcher will guess at. Inspect it with:
         $PY -m corpusfm.lifecycle status --json"
info "Installation: $INSTALLATION_ID"

# The request directory: root-owned, 0700, umask 077, and removed when this invocation ends.
# `/run` is a root-only tmpfs on every supported Linux and is the right home for a privileged input;
# a box that does not offer one falls back to a private temporary directory with the same mode. What
# makes the request acceptable is its OWNERSHIP AND MODE, which the CLI re-judges on the open
# descriptor — the location is where we put it, never why it is trusted.
LC_REQ_DIR=""
# The held FMS credential is wiped here too, so every way out - completion, refusal, die, interrupt -
# ends with it cleared (bash runs the EXIT trap when a signal terminates the script).
lc_cleanup() {
    FM_ADMIN_PASS=""; FM_ADMIN_USER=""
    [[ -n "$LC_REQ_DIR" ]] && rm -rf "$LC_REQ_DIR" 2>/dev/null; return 0
}
trap lc_cleanup EXIT

lc_req_dir() {
    if [[ -z "$LC_REQ_DIR" ]]; then
        if [[ -d /run && -w /run ]]; then
            LC_REQ_DIR="/run/corpusfm-uninstall.$$"
            mkdir -p "$LC_REQ_DIR"
        else
            LC_REQ_DIR="$(mktemp -d "${TMPDIR:-/tmp}/corpusfm-uninstall.XXXXXX")"
        fi
        chmod 700 "$LC_REQ_DIR"
    fi
    printf '%s' "$LC_REQ_DIR"
}

lc_request() {          # lc_request <transport>  → prints the path
    local f="$LC_REQ_DIR/uninstall.json"
    # BUILT AS DATA and serialized — never pasted together as text. **No credential ever appears in
    # it**: the transport is a token saying HOW one would be read, never a value.
    ( umask 077; ACTOR="${SUDO_USER:-root}" ID="$INSTALLATION_ID" FORCE="$FORCE" T="$1" \
        "$PY" -c 'import json, os
print(json.dumps({"schema_version": 2,
                  "installation_id": os.environ["ID"],
                  "actor": os.environ["ACTOR"],
                  "force": os.environ["FORCE"] == "true",
                  "credential_transport": os.environ["T"]}))' > "$f" )
    chown root:root "$f" 2>/dev/null || true
    printf '%s' "$f"
}

# UNSET, not merely emptied: an inherited exported entry keeps its export attribute through a plain
# assignment, and a credential held for the whole run would then reach every child (packet 1236).
unset FM_ADMIN_USER FM_ADMIN_PASS
FM_ADMIN_USER=""
FM_ADMIN_PASS=""
: "${CREDENTIAL_STDIN:=false}"

# --credential-stdin is a NON-INTERACTIVE route; pairing it with a run that can prompt would leave
# two credential sources live at once and no rule for which wins. Refused before the plan is read.
if $CREDENTIAL_STDIN && ! $SILENT; then
    die "--credential-stdin requires --silent.
       A run that can prompt already has a credential route. Nothing has changed."
fi

# ONE FRAME, READ ONCE, FROM THIS LAUNCHER'S OWN STDIN:
#   [4-byte big-endian length][UTF-8 account][4-byte big-endian length][UTF-8 password]
# Every refusal happens before the plan is acted on. The reader is the interpreter the launcher
# already uses, so the parse is one implementation rather than a second shell transcription.
lc_read_framed_credential() {
    # THE TRANSFER FROM PYTHON TO BASH IS TEXTUAL, ON PURPOSE.
    #
    # The first version of this reader wrote `account\0password` and split it in bash. That cannot
    # work and was measured failing twice over: a Bash variable cannot hold a NUL at all, so command
    # substitution silently concatenated the two fields ("acct\0secret" arrived as "acctsecret"),
    # and the separator expressions were themselves a syntax error - bash reported
    # `bad substitution: no closing "}"` and left BOTH variables empty. An empty pair would then
    # have been handed to fmsadmin as a login attempt.
    #
    # So the parser emits TWO BASE64 RECORDS, one per line. Base64 contains no NUL, no newline and
    # nothing bash rewrites, so each record survives command substitution byte for byte. The record
    # count is proved BEFORE anything is decoded, and each record is decoded through stdin rather
    # than argv - base64 of a password is trivially reversible and argv is world-readable in ps.
    local parsed records=() b64
    parsed="$("$RESULT_PY" -I -c '
import base64, struct, sys
MAX = 4096
# THE REASON MUST REACH THE OPERATOR. `sys.exit(message)` writes to stderr, but this parser is read
# through command substitution, which captures stdout only - so every framing refusal arrived as a
# blank reason followed by "Nothing has changed.". The reason goes to stdout and the exit code
# carries the failure; nothing here ever names a credential VALUE, only a field and a fault.
def refuse(message):
    sys.stdout.write(message)
    raise SystemExit(1)
def take(n, what):
    buf = b""
    while len(buf) < n:
        chunk = sys.stdin.buffer.read(n - len(buf))
        if not chunk:
            refuse("the credential frame ended before its " + what)
        buf += chunk
    return buf
fields = []
for what in ("account", "password"):
    (size,) = struct.unpack(">I", take(4, what + " length"))
    if size == 0:
        refuse("the credential frame declares an empty " + what)
    if size > MAX:
        refuse("the credential frame declares an implausible " + what + " length")
    raw = take(size, what)
    try:
        fields.append(raw.decode("utf-8"))
    except UnicodeDecodeError:
        refuse("the credential frame " + what + " is not valid UTF-8")
if sys.stdin.buffer.read(1):
    refuse("the credential frame carries trailing bytes after the password")
if not fields[0] or not fields[1]:
    refuse("the credential frame carries an empty field")
# REFUSED RATHER THAN MANGLED. A NUL cannot exist in a Bash variable or in an argv string, and a
# newline or carriage return is stripped or altered by command substitution - so a credential
# containing one could not be carried faithfully to fmsadmin. Changing it silently would present
# the operator with an authentication failure instead of the representation problem that caused it.
for what, value in zip(("account", "password"), fields):
    for bad, name in ((chr(0), "NUL"), ("\n", "newline"), ("\r", "carriage return")):
        if bad in value:
            refuse("the credential " + what + " contains a " + name +
                     ", which cannot be carried to fmsadmin faithfully")
for value in fields:
    sys.stdout.write(base64.b64encode(value.encode("utf-8")).decode("ascii") + chr(10))
')" || die "$parsed
       Nothing has changed."

    # EXACTLY TWO RECORDS, PROVED BEFORE ANY DECODE. One record would decode as an account with no
    # password; three would mean the parser and this reader disagree about the wire.
    # A plain read loop rather than `mapfile`: mapfile is bash 4+, and a credential reader is the
    # last place to acquire a shell-version dependency. This works on 3.2 and on 5.
    local _line
    while IFS= read -r _line; do records+=("$_line"); done <<< "$parsed"
    parsed=""; _line=""
    if [[ ${#records[@]} -ne 2 || -z "${records[0]}" || -z "${records[1]}" ]]; then
        die "the credential transfer did not carry exactly two records. Nothing has changed."
    fi
    for b64 in "${records[0]}" "${records[1]}"; do
        [[ "$b64" =~ ^[A-Za-z0-9+/=]+$ ]] || \
            die "the credential transfer carried a record that is not base64. Nothing has changed."
    done
    # Decoded through STDIN, never argv.
    FM_ADMIN_USER="$(printf '%s' "${records[0]}" | "$RESULT_PY" -I -c \
        'import base64,sys; sys.stdout.write(base64.b64decode(sys.stdin.read()).decode("utf-8"))')"
    FM_ADMIN_PASS="$(printf '%s' "${records[1]}" | "$RESULT_PY" -I -c \
        'import base64,sys; sys.stdout.write(base64.b64decode(sys.stdin.read()).decode("utf-8"))')"
    records=()
    if [[ -z "$FM_ADMIN_USER" || -z "$FM_ADMIN_PASS" ]]; then
        FM_ADMIN_PASS=""; FM_ADMIN_USER=""
        die "the credential transfer decoded to an empty field. Nothing has changed."
    fi
    info "Read one FMS administrator credential frame from standard input."
    info "It is used for this run only and is never written down."
    [[ -x "$PLAN_FMSADMIN" ]] || { FM_ADMIN_PASS=""; FM_ADMIN_USER=""; die \
        "The recorded fmsadmin executable is unavailable at $PLAN_FMSADMIN. Nothing has changed."; }
    info "Verifying FM Server credentials..."
    # PRE-EXISTING, OWNED FINDING: this validation places the password in the fmsadmin child's argv.
    # The interactive path has always done so; unchanged here on purpose, recorded rather than newly
    # accepted. Closing it is a separate correction touching both credential routes.
    if ! "$PLAN_FMSADMIN" -u "$FM_ADMIN_USER" -p "$FM_ADMIN_PASS" list files &>/dev/null; then
        FM_ADMIN_PASS=""; FM_ADMIN_USER=""
        die "FM Server admin login failed. Nothing has changed."
    fi
    ok "FileMaker Server administrator '$FM_ADMIN_USER' authenticated."
}
lc_fms_frame() {
    printf '%s\0%s' "$FM_ADMIN_USER" "$FM_ADMIN_PASS" \
        | "$RESULT_PY" -I -c \
'import struct, sys
raw = sys.stdin.buffer.read()
account, sep, password = raw.partition(b"\0")
if not sep:
    raise SystemExit(1)
for field in (account, password):
    sys.stdout.buffer.write(struct.pack(">I", len(field)))
    sys.stdout.buffer.write(field)
sys.stdout.buffer.flush()'
}

# EXACTLY ONE JSON OBJECT, or this run stops. A second document, an array, a scalar or a truncated
# write is not a result, and reading it field-by-field is how a partial write becomes a false answer.
LC_OUT=""; LC_RC=0; LC_RESULT=""; LC_REASON=""; LC_DETAIL=""
lc_invoke() {           # lc_invoke <verb> <transport>
    # **The directory is created in THIS shell, never inside the command substitution below.** A
    # `$( )` runs in a subshell, so an assignment made in there does not reach the EXIT trap — and the
    # trap would then have nothing to clean up. Found by the cleanup test, which is why it exists.
    lc_req_dir > /dev/null
    local request; request="$(lc_request "$2")"
    LC_RC=0
    # **stdin is INHERITED for the prompt transport and closed for every other one.** The CLI reads
    # the console itself, so it needs the console this launcher was given; and a call that cannot need
    # a credential is given nothing to read, so a transport bug cannot turn into a silent wait.
    # `CredentialLease.read` refuses a prompt on a stream that is not a terminal, which is what makes
    # an unattended run stop with a reason instead of blocking for ever.
    if [[ "$2" == "stdin" ]]; then
        LC_OUT="$(lc_fms_frame | "${CFM_LIFECYCLE[@]}" uninstall "$1" --request "$request")" \
            || LC_RC=$?
    elif [[ "$2" == "prompt" ]]; then
        LC_OUT="$("${CFM_LIFECYCLE[@]}" uninstall "$1" --request "$request")" || LC_RC=$?
    else
        LC_OUT="$("${CFM_LIFECYCLE[@]}" uninstall "$1" --request "$request" < /dev/null)" || LC_RC=$?
    fi
    printf '%s\n' "$LC_OUT" >> "${CFM_LOG:-/dev/null}" 2>/dev/null || true
    local parsed
    parsed="$(printf '%s' "$LC_OUT" | "$RESULT_PY" -I -c 'import json, sys
raw = sys.stdin.read()
try:
    value = json.loads(raw)
except ValueError:
    raise SystemExit(1)
if not isinstance(value, dict):
    raise SystemExit(1)
for key in ("result", "reason", "detail"):
    print(value.get(key) or "")' 2>/dev/null)" || die \
        "The uninstall did not return one readable JSON result (exit $LC_RC). Nothing further was
       attempted. See $CFM_LOG."
    LC_RESULT="$(printf '%s' "$parsed" | sed -n 1p)"
    LC_REASON="$(printf '%s' "$parsed" | sed -n 2p)"
    LC_DETAIL="$(printf '%s' "$parsed" | sed -n 3p)"
    rm -f "$request" 2>/dev/null || true
}

# THE SIX RESULT WORDS AND THEIR CODES — the shipped contract, restated nowhere else. 4 means the
# REQUEST was refused, which is this launcher's defect and never the box's.
lc_report() {
    case "$LC_RC" in
        0) ok "Uninstall ${LC_RESULT}: ${LC_DETAIL}" ;;
        1) warn "Uninstall refused before changing anything (${LC_RESULT})."
           warn "  reason: ${LC_REASON}"; warn "  ${LC_DETAIL}" ;;
        2) warn "Uninstall was rolled back; this machine is unchanged (${LC_RESULT})."
           warn "  ${LC_DETAIL}" ;;
        3) warn "Uninstall needs an administrator action (${LC_RESULT})."
           warn "  reason: ${LC_REASON}"; warn "  ${LC_DETAIL}" ;;
        4) warn "This launcher built a request this build does not accept — a launcher defect."
           warn "  ${LC_DETAIL}" ;;
        5) warn "Uninstall stopped safely part-way (${LC_RESULT}). Re-run to continue."
           warn "  reason: ${LC_REASON}"; warn "  ${LC_DETAIL}" ;;
        *) warn "Uninstall returned an unrecognised exit status $LC_RC." ;;
    esac
    cfm_is_verbose && printf '%s\n' "$LC_OUT"
    return 0
}

# ── S4 Plan ───────────────────────────────────────────────────────────────────
cfm_section "Plan"
lc_invoke "plan" "none"
if [[ "$LC_RC" -ne 0 ]]; then
    warn "CORPUSfm could not derive a removal plan without changing the machine."
    lc_report
    exit "$LC_RC"
fi

PLAN_FIELDS="$(printf '%s' "$LC_OUT" | "$RESULT_PY" -I -c \
'import json, sys
p = json.load(sys.stdin)
print(p.get("mode", ""))
print("true" if p.get("fms_admin_login_required") else "false")
print((p.get("locations") or {}).get("fmsadmin") or "")
print(p.get("fms_state", "unknown"))' 2>/dev/null)" || die \
    "The read-only uninstall plan was not a readable plan object. Nothing has been changed."
PLAN_MODE="$(printf '%s\n' "$PLAN_FIELDS" | sed -n 1p)"
PLAN_NEEDS_CREDENTIAL="$(printf '%s\n' "$PLAN_FIELDS" | sed -n 2p)"
PLAN_FMSADMIN="$(printf '%s\n' "$PLAN_FIELDS" | sed -n 3p)"
PLAN_FMS_STATE="$(printf '%s\n' "$PLAN_FIELDS" | sed -n 4p)"

printf '%s' "$LC_OUT" | "$RESULT_PY" -I -c \
'import json, sys
p = json.load(sys.stdin)
print("Installation:", p["installation_id"])
print("Mode:", "resume the recorded uninstall" if p["mode"] == "resume" else "start a new uninstall")
print("FileMaker Server:", p.get("fms_state", "unknown"))
for key, value in (p.get("locations") or {}).items():
    if key != "fmsadmin" and value:
        print("  %s: %s" % (key.replace("_", " "), value))
print("Planned operations:")
for op in p.get("operations", ()):
    target = (op.get("path") or op.get("database_path") or op.get("registration_name") or
              op.get("hosting_dir") or op.get("name") or op.get("account") or "recorded resource")
    print("  - %s: %s" % (op.get("resource", op.get("operation", "operation")), target))
for item in p.get("retained", ()):
    print("  - retain %s: %s" % (item.get("resource", "resource"), item.get("because", "recorded plan")))
if p.get("fms_admin_login_reasons"):
    print("FMS administrator credential:")
    for reason in p["fms_admin_login_reasons"]:
        print("  - " + reason)
' | while IFS= read -r line; do info "$line"; done

# ONE VALIDATED CREDENTIAL SUPPLIES ONE APPROVED RUN (packet 1380-04 ruling, narrowing 1236). Once
# validated it is held in THIS process only and reused for every start or resume that answers
# credential_required; each lifecycle child still receives its own freshly framed copy on stdin. The
# lifecycle asks per operation - a live run asked for start and again for the PKI read-back - and
# the one frame on stdin cannot be read twice. Wiped by lc_cleanup on every exit.
START_TRANSPORT="none"
CREDENTIAL_FRAME_READ=false
if [[ "$PLAN_MODE" == "start" && "$PLAN_NEEDS_CREDENTIAL" == "true" ]]; then
    if $CREDENTIAL_STDIN; then
        lc_read_framed_credential
        CREDENTIAL_FRAME_READ=true
        START_TRANSPORT="stdin"
    elif $SILENT || [[ ! -t 0 ]]; then
        warn "The plan needs an FMS administrator credential, but this invocation cannot prompt."
        warn "Pass --credential-stdin with --silent and write one credential frame to this"
        warn "launcher's standard input to supply one without a console."
        warn "Independent safe removal may proceed; FMS-dependent work will remain resumable."
    else
        info "FileMaker Server administrator credentials are required by this removal plan."
        info "They are used for this run only and are never written down."
        read -rp "  FM Server admin account username [admin]: " FM_ADMIN_USER
        FM_ADMIN_USER="${FM_ADMIN_USER:-admin}"
        while [[ -z "$FM_ADMIN_PASS" ]]; do
            read -rsp "  FM Server admin account password: " FM_ADMIN_PASS; echo ""
            [[ -n "$FM_ADMIN_PASS" ]] || warn "The FM Server admin password cannot be blank."
        done
        [[ -x "$PLAN_FMSADMIN" ]] || die \
            "The recorded fmsadmin executable is unavailable at $PLAN_FMSADMIN. Nothing has changed."
        info "Verifying FM Server credentials..."
        if ! "$PLAN_FMSADMIN" -u "$FM_ADMIN_USER" -p "$FM_ADMIN_PASS" list files &>/dev/null; then
            unset FM_ADMIN_PASS
            die "FM Server admin login failed. Nothing has changed."
        fi
        ok "FileMaker Server administrator '$FM_ADMIN_USER' authenticated."
        START_TRANSPORT="stdin"
    fi
fi

if [[ "$PLAN_MODE" == "start" ]]; then
    cfm_section "Confirm"
    cfm_confirm "Continue with this plan?"
    echo ""
else
    info "This removal was already approved and recorded; confirmation is not repeated."
fi

# ── S5 Progress ───────────────────────────────────────────────────────────────
cfm_section "Progress"
info "Starting the uninstall..."
lc_invoke "start" "$START_TRANSPORT"

# **A pending record means this is a resume, not a fresh start** — and the component says so by name
# rather than this script inspecting any state of its own.
if [[ "$LC_REASON" == "pending_record_exists__resume_it_rather_than_starting_again" ]]; then
    info "An interrupted uninstall is already recorded — continuing it."
    lc_invoke "resume" "none"
fi

# Continue while the next recorded operation requires a credential. A held credential is reused; the
# frame is read at most once per run; a silent run with nothing held stops resumable, as before.
CONTINUATIONS=0
while [[ "$LC_REASON" == "credential_required" ]]; do
    if [[ -z "$FM_ADMIN_USER" || -z "$FM_ADMIN_PASS" ]]; then
        if $CREDENTIAL_STDIN && ! $CREDENTIAL_FRAME_READ; then
            info "A later operation now requires an FMS administrator credential."
            lc_read_framed_credential
            CREDENTIAL_FRAME_READ=true
        elif $SILENT; then
            warn "An FMS administrator credential is required to finish, and --silent never prompts."
            warn "Pass --credential-stdin with --silent and write one credential frame to standard"
            warn "input, or re-run without --silent. Nothing is lost: the uninstall is recorded and"
            warn "resumes where it stopped."
            break
        else
            info "A later operation now requires an FMS administrator credential."
            info "CORPUSfm will ask for it itself; it is used for this run only."
            lc_invoke "resume" "prompt"
            continue
        fi
    fi
    # A lifecycle that keeps asking with a validated credential in hand is not making progress; stop
    # resumable rather than resubmit it without end.
    CONTINUATIONS=$((CONTINUATIONS + 1))
    if (( CONTINUATIONS > 8 )); then
        warn "The uninstall still requires a credential after 8 continuations; stopping. It is"
        warn "recorded and resumes where it stopped."
        break
    fi
    lc_invoke "resume" "stdin"
done
FM_ADMIN_PASS=""; FM_ADMIN_USER=""
unset FM_ADMIN_PASS FM_ADMIN_USER

# ── S6 Summary ────────────────────────────────────────────────────────────────
cfm_section "Summary"
lc_report

# ── S7 Farewell ───────────────────────────────────────────────────────────────
cfm_section "Farewell"
if [[ "$LC_RC" -eq 0 ]]; then
    ok "CORPUSfm removed."
    echo "Goodbye!"
fi
exit "$LC_RC"
