#!/bin/bash
# cfm-proxy-exec - the Linux OS-native proxy executor (packet 1246-06).
#
# It owns ONE type's ENTIRE filesystem transaction and NOTHING else:
#
#   observe -> durable SAME-DIRECTORY backup + residue -> place the candidate -> publish
#           -> validate the PUBLISHED WHOLE config -> read back
#           -> on failure: restore exact bytes + metadata, VERIFY the restoration
#
# IT NEVER ACTIVATES. No `fmsadmin`, no restart, no reload, no service control of any kind - the
# activation for the Linux cohort is one shared restart planned once per run by the Python engine
# (1246-06 section 6.2/6.3), and it is the only thing in the component that touches a credential.
# A VALIDATION failure is not an ACTIVATION failure: the running server never consumed the
# candidate, so restoring the bytes is the whole of the recovery and nothing is restarted here.
#
# IT NEVER RENDERS. The marked block and the include body arrive as files (--block-file,
# --include-file), rendered once by corpusfm/lifecycle/proxy_render.py. That is ruling 4: planning
# cannot decide whether a change is needed without knowing what the DESIRED text is, and two
# independent renderers drift the moment either is edited.
#
# WHY THIS FILE EXISTS ALONGSIDE cfm-web-proxy.sh: 1246-06 is ADDITIVE. The old helper and its
# current installer/uninstaller callers are left untouched so `main` stays installable; 1246-04
# switches the installer, 1246-09 switches the uninstaller and then retires the old helper.
#
# Four defects in the old helper are fixed here rather than inherited:
#   1. BACKUPS WERE IN mktemp. A process killed between publish and validate left an edited FMS
#      config whose only backup was in /tmp - undiscoverable by a later run and gone at reboot.
#      Backups are now same-directory `.cfmbak` with a residue marker, which is what makes a
#      fail-closed residue check possible at all.
#   2. AN UNMATCHED MARKER DELETED TO END OF FILE. The `awk` skip-toggle flips on the first marker
#      and, with no closing marker, never flips back. Marker state is now zero-or-one-balanced-pair
#      or the operation REFUSES.
#   3. THE APACHE VALIDATOR COULD BE A SYSTEM BINARY. `command -v apachectl` finds /usr/sbin on a
#      box with a system Apache, so a malformed FMS block could validate against somebody else's
#      config. Validators are resolved from the VERIFIED FMS ROOT only.
#   4. THE nginx INCLUDE WAS PLACED BY TEXT ANCHOR. The include body contains `location` blocks,
#      which nginx accepts only inside a `server` block, so an anchor that is missing - or that
#      matches in main context - produces a configuration nginx refuses to start. Placement is now
#      BRACE-AWARE: the unique `server { ... listen ... 443 ... }` block, or a refusal.
#
# Usage:
#   cfm-proxy-exec <verb> <type> --fms-root DIR [--block-file F] [--include-file F]
#   verb  = prepare | classify | observe | publish | remove | restore | retire | digest
#   type  = fms-nginx | apache
# Emits ONE JSON object on stdout (except `digest`, which prints one hex line). Exit 0 = the verb's
# contract was met; 2 = refused; 1 = failed.

set -uo pipefail

MARK="CORPUSFM"
INCLUDE_NAME="corpusfm_https.conf"

# The two pure-filter verbs are dispatched BEFORE any argument is consumed: they take no type and
# no FMS root, and the positional `shift 2` below would eat their first `name=file` pair.
CFM_ARGV=("$@")
VERB="${1:-}"; TYPE="${2:-}"; shift 2 2>/dev/null || true
FMS_ROOT=""; BLOCK_FILE=""; INCLUDE_FILE=""; OPERATION_ID=""; EVIDENCE_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fms-root)     FMS_ROOT="$2";     shift 2 ;;
    --block-file)   BLOCK_FILE="$2";   shift 2 ;;
    --include-file) INCLUDE_FILE="$2"; shift 2 ;;
    --operation-id) OPERATION_ID="$2"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# JSON emission. Every field the Python engine reads is emitted by exactly one of these, so a new
# field cannot be half-added.
emit() { # ok restored restore_verified detail [fingerprint] [backup] [evidence] [unchanged]
  printf '{"ok":%s,"restored":%s,"restore_verified":%s,"detail":"%s","fingerprint":%s,"backup":%s,"evidence":%s,"unchanged":%s}\n' \
    "$1" "$2" "$3" "$(printf '%s' "$4" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "${5:-null}" "${6:-null}" "${7:-null}" "${8:-null}"
}
ok_json()   { emit true  false false "$1" "\"${2:-}\"" "\"${3:-}\"" "${4:-null}" "${5:-null}"; exit 0; }
# A successful restore must SAY it restored and verified. `ok_json` hardcodes both false, which is
# right for publish (nothing was put back) and silently wrong for restore - the dispatcher requires
# `ok AND restore_verified`, so an honest restore would have read as an unverified one.
ok_restored() { emit true true true "$1" null null null null; exit 0; }
refuse()    { emit false false false "$1"; exit 2; }
failed()    { emit false "$2" "$3" "$1"; exit 1; }

# ---------------------------------------------------------------------------------------------
# THE CANONICAL FINGERPRINT (ruling 4). SHA-256 of the block with LF newlines, NO terminal newline
# and NO BOM. Python, bash and PowerShell must agree byte-for-byte, and tests/test_proxy_render.py
# runs all three against the same input to prove it - because two implementations agreeing by
# inspection is exactly what was believed before and was false: this pipeline hashed WITH a trailing
# newline while Python hashed without, so drift fired on every correctly-configured box.
#
# Declared before the argument checks because `digest` is a pure filter that needs no FMS root.
# ---------------------------------------------------------------------------------------------
canonicalize() { # reads stdin -> canonical text on stdout, no terminal newline
  sed '1s/^\xEF\xBB\xBF//' | tr -d '\r' | awk '{ a[NR]=$0 } END { n=NR
    while (n > 1 && a[n] == "") n--
    for (i = 1; i <= n; i++) printf "%s%s", a[i], (i < n ? "\n" : "") }'
}

canonical_digest() { # reads stdin -> 64 hex chars
  canonicalize | sha256sum | cut -d' ' -f1
}

# THE FAMILY DIGEST (Codex ruling 3). One part digest is not an artifact digest: the nginx marked
# block is a single `include` directive, and the prefix, port and every MCP metadata route live in
# the include BODY - so hashing the block alone left the desired fingerprint unchanged when any of
# them changed. The whole owned family is hashed, LENGTH-PREFIXED per part so content cannot be
# moved between parts unnoticed, in sorted name order so the result does not depend on argument
# order.
#
#   <name>\n<byte length of canonical body>\n<canonical body>   joined by LF
family_digest() { # name=file [name=file ...] -> 64 hex chars
  local doc="" first=1 pair name file body len
  local -a sorted=()
  # Sorted by PART NAME, and read with a NUL-safe loop: an FMS path can contain a space, and
  # `for x in $(... | sort)` would split one argument into several.
  while IFS= read -r -d '' pair; do sorted+=("$pair"); done < <(
    printf '%s\0' "$@" | sort -z)
  for pair in "${sorted[@]}"; do
    name="${pair%%=*}"; file="${pair#*=}"
    body="$(canonicalize < "$file")"
    len=$(printf '%s' "$body" | wc -c | tr -d ' ')
    if [[ $first -eq 1 ]]; then first=0; else doc+=$'\n'; fi
    doc+="$name"$'\n'"$len"$'\n'"$body"
  done
  printf '%s' "$doc" | sha256sum | cut -d' ' -f1
}

if [[ "$VERB" == "digest" ]]; then canonical_digest; exit 0; fi

if [[ "$VERB" == "family-digest" ]]; then
  # The cross-language known-answer entry point for the composite (ruling 3). Either `name=file`
  # pairs on argv, or `--parts-file F` listing one `name=path` per line - the latter is what the
  # PowerShell side must use, because `-File` cannot bind a multi-value parameter at all.
  if [[ "${CFM_ARGV[1]:-}" == "--parts-file" ]]; then
    # A `while read` loop, not `mapfile`: bash 3.2 ships as /bin/bash on macOS and has no
    # `mapfile`, and this script must stay runnable wherever it is tested as well as on the Ubuntu
    # LTS floor it targets.
    _pairs=()
    while IFS= read -r _line; do
      [[ -n "$_line" ]] && _pairs+=("$_line")
    done < "${CFM_ARGV[2]}"
    family_digest "${_pairs[@]}"
  else
    family_digest "${CFM_ARGV[@]:1}"
  fi
  exit 0
fi

[[ -n "$VERB" && -n "$TYPE" ]] || refuse "usage: cfm-proxy-exec <verb> <type> --fms-root DIR ..."
[[ -n "$FMS_ROOT" ]] || refuse "--fms-root is required; detection is bounded to a verified FMS root"
[[ -d "$FMS_ROOT" ]] || refuse "the FMS root '$FMS_ROOT' is not a directory"

case "$TYPE" in
  fms-nginx) CONF="$FMS_ROOT/NginxServer/conf/fms_nginx.conf"
             INC="$FMS_ROOT/NginxServer/conf/$INCLUDE_NAME" ;;
  apache)    CONF="$FMS_ROOT/HTTPServer/conf/extra/httpd-proxy.conf"; INC="" ;;
  *) refuse "'$TYPE' is not a Linux proxy type (fms-nginx | apache)" ;;
esac
[[ -f "$CONF" ]] || refuse "no FMS-bundled configuration at $CONF"

# ---------------------------------------------------------------------------------------------
# Marker state: EXACTLY zero, or EXACTLY one balanced pair. Anything else refuses.
# Horizontal whitespace only, so the pattern can never consume a physical newline.
# ---------------------------------------------------------------------------------------------
marker_count() { grep -cE "^[[:space:]]*#+[[:space:]]*${MARK}[[:space:]]*$" "$1" 2>/dev/null || true; }

marker_state() {
  local n; n="$(marker_count "$1")"
  case "$n" in 0) echo none ;; 2) echo one ;; *) echo invalid ;; esac
}

# `strip_block` USED TO LIVE HERE and is gone (2026-08-08). It stripped from the FIRST `#+CORPUSFM`
# marker to the LAST, which is why a file carrying a retired block AND a current one could not be
# normalized: the span between them is not one block, and removing it would have taken whatever sat
# in between. Each front now has its own inverse — `nginx_strip_owned` retires exactly the attributed
# ranges, `apache_strip` is byte-exact — and leaving the old one defined-but-uncalled would only
# invite it back.

# ── NGINX'S TWO OWNED MARKER GENERATIONS, AND REMOVE-BEFORE-ADD ──────────────────────────────
#
# Measured on fms-server 2026-08-08. `fms_nginx.conf` ended up carrying BOTH an owned block in the
# retired form and one in the current form, each including the same file:
#
#     ###CORPUSFM                       # CORPUSFM
#         include ".../corpusfm_https.conf";       include ".../corpusfm_https.conf";
#     ###CORPUSFM                       # CORPUSFM
#
# The already-running nginx kept serving its loaded configuration, so nothing looked wrong. When FMS
# next stopped it, a fresh nginx could not load the DUPLICATE include and the web front stayed down
# until the retired block was removed by hand.
#
# `marker_count` cannot see this: its pattern is `#+`, which matches BOTH forms. A legacy-only file
# counts 2 and is mistaken for a current block; a mixed file counts 4 and lands in `invalid`. Neither
# answer is "one retired block and one current one, replace both with one".
#
# So the rule is stated once, here: publication is REMOVE-BEFORE-ADD at the CORPUSfm-owned block
# boundary, over both generations, and a block is only ours when its body is exactly the include we
# record. Anything else wearing those markers is ambiguous and refuses BEFORE backup or mutation —
# FMS and operator configuration is never rewritten to make room.
NGX_LEGACY_MARK="###${MARK}"

# Every CORPUSfm marker line, classified. `###CORPUSFM` is the retired form, `# CORPUSFM` the
# current one, and anything else wearing the name is UNKNOWN rather than assumed.
nginx_scan() { # file -> "<lineno> <legacy|current|unknown>" per marker line
  awk -v mark="$MARK" '
    {
      line = $0
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line !~ ("^#+[ \t]*" mark "$")) next
      if (line == "###" mark)            print NR, "legacy"
      else if (line ~ ("^#[ \t]+" mark "$")) print NR, "current"
      else                                print NR, "unknown"
    }' "$1"
}

# The one body an owned block may have: the include of the path this run recorded.
nginx_body_is_expected_include() { # file start end -> 0 when the body is exactly our include
  local f="$1" start="$2" end="$3" body n
  body="$(awk -v a="$start" -v b="$end" 'NR>a && NR<b' "$f" | grep -vE '^[[:space:]]*$')"
  n="$(printf '%s\n' "$body" | grep -c . || true)"
  [[ "$n" -eq 1 ]] || return 1
  printf '%s\n' "$body" | grep -qE "^[[:space:]]*include[[:space:]]+\"?${INC//\//\\/}\"?;[[:space:]]*$"
}

# The inventory rule 4 asks for: recognized blocks, and every reference to the expected include.
# Emits "<start> <end> <kind>" per attributable block; refuses (rc 1, reason on stderr) otherwise.
nginx_owned_blocks() { # file -> block lines on stdout
  local f="$1" scan i start end kind n_legacy=0 n_current=0 refs owned=0 _n _k
  local -a lines kinds
  scan="$(nginx_scan "$f")"
  if [[ -z "$scan" ]]; then
    refs="$(grep -cF "include \"$INC\"" "$f" 2>/dev/null || true)"
    [[ "${refs:-0}" -eq 0 ]] || { echo "an expected include exists outside any CORPUSfm block" >&2; return 1; }
    return 0
  fi
  if printf '%s\n' "$scan" | grep -q ' unknown$'; then
    echo "a marker line wearing ${MARK} is neither the retired '###${MARK}' nor the current '# ${MARK}' form" >&2
    return 1
  fi
  # A plain read loop, not `mapfile`: that is a bash-4 builtin and this script must not assume one.
  lines=(); kinds=()
  while read -r _n _k; do
    [[ -n "$_n" ]] || continue
    lines+=("$_n"); kinds+=("$_k")
  done < <(printf '%s\n' "$scan")
  if (( ${#lines[@]} % 2 != 0 )); then
    echo "the ${MARK} markers are unbalanced (${#lines[@]} found)" >&2; return 1
  fi
  for (( i=0; i<${#lines[@]}; i+=2 )); do
    start="${lines[i]}"; end="${lines[i+1]}"; kind="${kinds[i]}"
    [[ "$kind" == "${kinds[i+1]}" ]] || {
      echo "a ${MARK} marker pair mixes the retired and current forms" >&2; return 1; }
    nginx_body_is_expected_include "$f" "$start" "$end" || {
      echo "a ${MARK} block does not contain exactly the expected include of $INC" >&2; return 1; }
    [[ "$kind" == "legacy" ]] && n_legacy=$((n_legacy+1)) || n_current=$((n_current+1))
    owned=$((owned+1))
    printf '%s %s %s\n' "$start" "$end" "$kind"
  done
  (( n_legacy <= 1 )) || { echo "two retired ${MARK} blocks; refusing to guess which is current" >&2; return 1; }
  (( n_current <= 1 )) || { echo "two current ${MARK} blocks; refusing to guess which is current" >&2; return 1; }
  # Every reference to the include must live inside one of the blocks just accounted for.
  refs="$(grep -cF "include \"$INC\"" "$f" 2>/dev/null || true)"
  [[ "${refs:-0}" -eq "$owned" ]] || {
    echo "an expected include exists outside a CORPUSfm block ($refs reference(s), $owned owned block(s))" >&2
    return 1; }
  return 0
}

# THE POST-CONDITION (rule 7). Checked on the CANDIDATE, so a file carrying two includes can never
# reach a success verdict and therefore can never be handed to activation — which is exactly the
# state that took the FMS web front down: nginx kept serving its loaded config, and only the next
# start failed.
nginx_normalized_ok() { # file want=published|absent -> 0 when the candidate is exactly right
  local f="$1" want="$2" scan legacy current refs
  scan="$(nginx_scan "$f")"
  legacy="$(printf '%s\n' "$scan" | grep -c ' legacy$' || true)"
  current="$(printf '%s\n' "$scan" | grep -c ' current$' || true)"
  refs="$(grep -cF "include \"$INC\"" "$f" 2>/dev/null || true)"
  [[ "${legacy:-0}" -eq 0 ]] || return 1
  if [[ "$want" == "published" ]]; then
    [[ "${current:-0}" -eq 2 && "${refs:-0}" -eq 1 ]] || return 1
  else
    [[ "${current:-0}" -eq 0 && "${refs:-0}" -eq 0 ]] || return 1
  fi
  return 0
}

# Delete every recognized block's line range, and NOTHING else. Ranges are applied from the bottom
# up so earlier line numbers stay valid.
nginx_strip_owned() { # file blocks -> stdout
  local f="$1" blocks="$2" expr=""
  while read -r start end _kind; do
    [[ -n "$start" ]] || continue
    expr+="(NR>=$start && NR<=$end) ||"
  done < <(printf '%s\n' "$blocks")
  expr="${expr%||}"
  [[ -n "$expr" ]] || { cat -- "$f"; return 0; }
  awk "!( $expr )" "$f"
}

# ── APACHE'S OWNED APPEND GEOMETRY, IN BYTES ─────────────────────────────────────────────────
#
# The FMS-shipped `httpd-proxy.conf` ends WITHOUT a terminal newline — measured on fms-server
# 2026-08-08, its last bytes are `</Location>` with no `\n`. Appending the block therefore joined
# `</Location>` to `# CORPUSFM` on one line and Apache refused the whole configuration:
# `</Location>#> directive missing closing '>'`. A correct block was rolled back on every install.
#
# The retired `strip_block` could not be the inverse of that append: it was LINE-oriented and
# awk always emits a terminal newline, so removal could never restore a file that had none. Apache
# therefore gets a byte-exact pair of operations. **nginx keeps its brace-aware path untouched** —
# it inserts INSIDE the 443 server block rather than appending, and its config does end with a
# newline.
#
# The geometry this executor creates, and the ONLY one it will remove:
#
#   <original bytes, exactly><owned \n><opening marker line>…<closing marker at EOF>
#
# One deliberately owned separator, appended whether or not the original ended with a newline — so
# the original bytes are always an exact prefix, and removal is always "drop the last N bytes".
apache_marker_offsets() { # file -> "<first byte offset> <last byte offset>", or non-zero
  local f="$1" hits count
  hits="$(grep -abE "^[[:space:]]*#+[[:space:]]*${MARK}[[:space:]]*$" "$f" 2>/dev/null)" || return 1
  [[ -n "$hits" ]] || return 1
  count="$(printf '%s\n' "$hits" | grep -c .)"
  [[ "$count" -eq 2 ]] || return 1
  printf '%s %s' "$(printf '%s\n' "$hits" | head -1 | cut -d: -f1)" \
                 "$(printf '%s\n' "$hits" | tail -1 | cut -d: -f1)"
}

# REFUSES rather than guessing. A block this executor did not create — one not at EOF, or with
# something other than a single newline before it — cannot be removed byte-exactly, and removing it
# approximately is how an operator's own edit gets eaten.
apache_geometry_ok() { # file -> 0 when the marked block is exactly what publish creates
  local f="$1" offs first last size rest line sep
  offs="$(apache_marker_offsets "$f")" || return 1
  first="${offs%% *}"; last="${offs##* }"
  [[ "$first" -ge 1 ]] || return 1                    # no room for the owned separator
  # Belt and braces, and deliberately labelled as such: `marker_count` only matches a marker at a
  # LINE START, so the byte before it is a newline whenever the count is 2 — the reachable half of
  # this rule is the `first >= 1` check above, which is what refuses a file that BEGINS with the
  # block and therefore has no original prefix to restore.
  sep="$(dd if="$f" bs=1 skip=$((first - 1)) count=1 2>/dev/null | od -An -tu1 | tr -d ' ')"
  [[ "$sep" == "10" ]] || return 1
  size="$(wc -c < "$f" | tr -d ' ')"
  line="$(tail -c +$((last + 1)) "$f" | head -1)"
  rest=$(( size - last ))
  # The closing marker ends the file, with or without a terminal newline of its own.
  [[ "$rest" -eq "${#line}" || "$rest" -eq $(( ${#line} + 1 )) ]] || return 1
  return 0
}

apache_strip() { # file -> stdout: the ORIGINAL bytes, exactly, terminal newline state included
  local f="$1" offs first
  offs="$(apache_marker_offsets "$f")" || return 1
  first="${offs%% *}"
  head -c $(( first - 1 )) "$f"
}

extract_block() { # file -> stdout
  local f="$1" first last
  first="$(grep -nE "^[[:space:]]*#+[[:space:]]*${MARK}[[:space:]]*$" "$f" | head -1 | cut -d: -f1)"
  last="$(grep -nE "^[[:space:]]*#+[[:space:]]*${MARK}[[:space:]]*$" "$f" | tail -1 | cut -d: -f1)"
  awk -v a="$first" -v b="$last" 'NR>=a && NR<=b' "$f"
}

family_fingerprint() { # -> the digest of the WHOLE owned family for $TYPE, or empty
  [[ "$(marker_state "$CONF")" == "one" ]] || return 0
  local tmpb="$CONF.cfmpart-block"
  extract_block "$CONF" > "$tmpb"
  local rc
  if [[ -n "$INC" ]]; then
    # An nginx family is the block AND the include it names. A missing include is not "the block
    # alone" - it is an incomplete family, and reporting a digest for it would call a broken
    # installation current.
    if [[ -f "$INC" ]]; then
      family_digest "block=$tmpb" "include=$INC"; rc=0
    else
      rc=1
    fi
  else
    family_digest "block=$tmpb"; rc=0
  fi
  rm -f -- "$tmpb"
  return $rc
}

digest() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# ---------------------------------------------------------------------------------------------
# Durable SAME-DIRECTORY backup + residue. `.cfmbak` beside the file it protects, so a later run
# can FIND it - which is the whole difference from a /tmp backup nobody can discover.
# ---------------------------------------------------------------------------------------------
backup_of() { echo "$1.cfmbak"; }

residue_present() {
  local d; d="$(dirname "$1")"
  ls "$d"/*.cfmbak 2>/dev/null | head -1
}

make_backup() { # file
  local bak; bak="$(backup_of "$1")"
  cp -p -- "$1" "$bak" || return 1
  sync 2>/dev/null || true
  echo "$bak"
}

restore_backup() { # file -> 0 when restored AND verified
  local f="$1" bak; bak="$(backup_of "$f")"
  [[ -f "$bak" ]] || return 1
  cp -p -- "$bak" "$f" || return 1
  sync 2>/dev/null || true
  [[ "$(digest "$f")" == "$(digest "$bak")" ]] || return 1
  rm -f -- "$bak"
  return 0
}

# The nginx include is CORPUSfm's OWN file, so restoring the host config is only half of a restore:
# a leftover include is a live edit nobody agreed to keep. Its own backup answers the one question
# that matters - did it exist before this run - so a restore can either put it back or remove it.
backup_include() {
  [[ -n "$INC" ]] || return 0
  [[ -f "$INC" ]] && cp -p -- "$INC" "$INC.cfmbak"
  return 0
}

restore_include() {
  [[ -n "$INC" ]] || return 0
  if [[ -f "$INC.cfmbak" ]]; then
    cp -p -- "$INC.cfmbak" "$INC" && rm -f -- "$INC.cfmbak"
  else
    rm -f -- "$INC"
  fi
  return 0
}

retire_backups() {
  local conf_bak; conf_bak="$(backup_of "$CONF")"
  rm -f -- "$conf_bak" || return 1
  if [[ -n "$INC" ]]; then
    rm -f -- "$INC.cfmbak" || return 1
  fi
  [[ ! -e "$conf_bak" ]] || return 1
  [[ -z "$INC" || ! -e "$INC.cfmbak" ]] || return 1
  return 0
}

# ---------------------------------------------------------------------------------------------
# BRACE-AWARE placement (ruling 5). The include body contains `location` directives, which nginx
# accepts only inside a `server` block - so the include DIRECTIVE must go inside the unique 443
# server block, never in main context. The old helper anchored on text (`###OTTO`,
# `otto_https.conf`, `fms_fac.conf`); this resolves the STRUCTURE and refuses zero, multiple or
# unbalanced blocks rather than guessing. Braces inside `#` comments are ignored, so a commented
# brace cannot skew the depth count.
#
# The Otto fence is kept: OttoFMS re-injects its block if it sees its ###OTTO region modified, so
# where that region exists the insertion point is AFTER its closing marker - still inside the same
# server block, outside Otto's managed region.
# ---------------------------------------------------------------------------------------------
find_443_insert_line() { # file -> the 1-based line to insert BEFORE; a reason on stderr otherwise
  awk '
    {
      code = $0
      sub(/#.*/, "", code)                        # brace counting ignores comment text
      if (!in_server && code ~ /(^|[ \t;{}])server[ \t]*\{/) {
        in_server = 1; server_start = NR; depth = 0; has443 = 0; otto_end = 0
      }
      if (in_server) {
        n = gsub(/\{/, "{", code); depth += n
        n = gsub(/\}/, "}", code); depth -= n
        if ($0 ~ /^[ \t]*listen([ \t]|.*[^0-9])443([^0-9]|$)/) has443 = 1
        if ($0 ~ /^[ \t]*###[ \t]*OTTO[ \t]*$/) otto_end = NR
        if (depth <= 0) {
          if (has443) {
            found++
            close_line = NR
            anchor = (otto_end > server_start ? otto_end + 1 : NR)
          }
          in_server = 0
        }
      }
    }
    END {
      if (in_server) { print "unbalanced braces in a server block" > "/dev/stderr"; exit 3 }
      if (found == 0) { print "no server block listens on 443" > "/dev/stderr"; exit 4 }
      if (found > 1) { print "ambiguous: " found " server blocks listen on 443" > "/dev/stderr"; exit 5 }
      print anchor
    }
  ' "$1"
}

insert_at_line() { # file line block-file -> stdout
  awk -v at="$2" -v bf="$3" '
    NR == at { while ((getline l < bf) > 0) print l; close(bf) }
    { print }
  ' "$1"
}

# ---------------------------------------------------------------------------------------------
# Validators - honest per front, and BOUNDED TO THE FMS ROOT.
# ---------------------------------------------------------------------------------------------
# VALIDATORS. Measured on fms-server 2026-08-08 (E5), and the premise they used to hold is retired.
#
# They resolved `$FMS_ROOT/NginxServer/nginx` and `$FMS_ROOT/HTTPServer/bin/httpd`. **Neither
# exists on this deployment** — `find "<FMS root>" \( -name nginx -o -name httpd \) -type f`
# returns nothing. FileMaker Server drives the DISTRIBUTION's binaries:
#
#   nginx   /usr/sbin/nginx  -c "<FMS root>/NginxServer/conf/fms_nginx.conf"   (from /proc/<master>)
#   apache  /usr/sbin/apache2 -k <verb> -D FILEMAKER -f "<HTTP_ROOT>/conf/httpd.conf"
#                                                                     (from HTTPServer/bin/httpdctl)
#
# So every validator returned 2 — *cannot validate* — the caller treated the change as unproven, and
# a correct configuration was rolled back on every Linux install. Same false premise as the one
# `proxy_inventory.linux_active_front` carried, one layer down.
#
# WHAT REPLACES IT, and what does NOT change:
#   * The path is FIXED and absolute. Never PATH, never `command -v`, never cwd, never a caller
#     argument — defect 3 in the header is about exactly that and still stands. What changes is
#     WHICH fixed path, not that it is fixed.
#   * The binary must satisfy the privileged-command policy before it is run: a regular file,
#     executable, root-owned, and not writable by group or other. Anything else is `cannot validate`.
#   * VALIDATION IS NOT ACTIVATION. `httpdctl` exposes only start|stop|restart|graceful — it has no
#     validation verb at all, so it is NOT used here. Its value was telling us how FMS invokes
#     Apache; running it would restart the front, which this executor must never do.
# ---------------------------------------------------------------------------------------------

SYSTEM_NGINX="/usr/sbin/nginx"
SYSTEM_APACHE="/usr/sbin/apache2"

# THE BOUND IS PRIVILEGED AUTHORITY TOO, and it was the one command here that was not treated as
# such. It used to be `command -v timeout`, so PATH chose the program this process executes AS ROOT
# with a server as its argument - defect 3 in the header, one layer out from the validator it wraps.
# A caller who can prepend a directory to PATH did not need to touch the validator at all.
#
# The fallback was the second half of the same defect: with no `timeout` on the box, `bounded` ran
# the command UNBOUNDED. The nginx technique is a timed foreground start whose entire verdict is
# "still serving when the bound expired", so an unbounded run of a VALID configuration serves
# forever and the transaction never returns to restore or publish anything.
#
# So the bound is a fixed absolute path held to the same privileged-command policy as the
# validators, and there is no fallback of any kind: no usable bound is *cannot validate* (rc 2).
SYSTEM_TIMEOUT="/usr/bin/timeout"

# A validator is a privileged command: this process is about to run it as root. Every answer here is
# a REFUSAL to validate (rc 2), never a fallback to something else.
# THE FILE AND ITS CONTAINING DIRECTORY, both. A perfectly permissioned binary inside a directory
# somebody else can write is not protected: they need not edit it, they replace it. Same rule, and
# the same reason, as `proxy_transaction.executor_refusal` checking the executor's ancestry.
validator_usable() {   # validator_usable <path> -> 0 usable, 1 not
  local exe="$1" dir
  [[ -n "$exe" ]] || return 1
  [[ -f "$exe" && ! -L "$exe" ]] || return 1
  [[ -x "$exe" ]] || return 1
  [[ "$(stat -c '%U' "$exe" 2>/dev/null)" == "root" ]] || return 1
  [[ -z "$(find "$exe" -perm /022 -print -quit 2>/dev/null)" ]] || return 1
  dir="${exe%/*}"; [[ -n "$dir" ]] || dir="/"
  [[ -d "$dir" && ! -L "$dir" ]] || return 1
  [[ "$(stat -c '%U' "$dir" 2>/dev/null)" == "root" ]] || return 1
  [[ -z "$(find "$dir" -maxdepth 0 -perm /022 -print -quit 2>/dev/null)" ]] || return 1
  return 0
}

# The bound runs as root and takes the validator as ITS argument, so a substituted or writable
# `/usr/bin/timeout` runs anything it likes with the validator's privileges. Same policy, same
# predicate, no second implementation to drift.
timeout_usable() { validator_usable "$SYSTEM_TIMEOUT"; }

bounded() { # seconds cmd... -> the command's rc, 124 when cut short, or 2 when there is no bound
  timeout_usable || return 2
  local secs="$1"; shift
  "$SYSTEM_TIMEOUT" "$secs" "$@"
}

# Validator output crosses a JSON line boundary. Preserve the useful diagnostic while folding
# physical newlines and control whitespace so `emit` still produces exactly one valid JSON object.
validation_line() { tr '\r\n\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//'; }
VALIDATION_DETAIL=""

validate_nginx() {
  # The technique is UNCHANGED and still measured: `nginx -t` and `-T` HANG on this FMS
  # configuration, so a timed FOREGROUND START is used and its outcome read —
  #   rc 124 (ran to the bound)  -> :443 free, the config served fine       -> VALID
  #   "Address already in use"   -> the config PARSED; only the bind failed -> VALID
  #   any other [emerg]          -> a real configuration error              -> INVALID
  # The bound is REQUIRED: without one a valid configuration simply serves forever.
  if ! validator_usable "$SYSTEM_NGINX"; then
    VALIDATION_DETAIL="the nginx validator $SYSTEM_NGINX is absent or not protected for root execution"
    return 2
  fi
  if ! timeout_usable; then
    VALIDATION_DETAIL="the validation bound $SYSTEM_TIMEOUT is absent or not protected for root execution"
    return 2
  fi
  local out rc
  out="$(bounded 8 "$SYSTEM_NGINX" -c "$CONF" -g 'daemon off;' 2>&1)"; rc=$?
  if [[ "$rc" -eq 124 ]] || printf '%s' "$out" | grep -q 'Address already in use'; then return 0; fi
  VALIDATION_DETAIL="$(printf '%s' "$out" | validation_line)"
  [[ -n "$VALIDATION_DETAIL" ]] || VALIDATION_DETAIL="nginx rejected its existing configuration (exit $rc)"
  return 1
}

validate_apache() {
  # THE WHOLE CONFIGURATION, NEVER THE EDITED FRAGMENT. `$CONF` for apache is
  # `HTTPServer/conf/extra/httpd-proxy.conf`, which `httpd.conf` includes at line 493 and which is a
  # bare `ProxyPass`/`<Proxy>` set — it has no ServerRoot, no listener and no MPM, so `-f` on it
  # alone would fail for reasons that have nothing to do with our block. The main configuration is
  # the one FMS itself names.
  #
  # `HTTP_ROOT` and `SERVER_NAME` are exported because `httpd.conf` dereferences both
  # (`ServerRoot "${HTTP_ROOT}"`, `ServerName "${SERVER_NAME}"`); httpdctl exports the same two, and
  # without them the syntax check fails on an unset variable rather than on our edit.
  # `-D FILEMAKER` mirrors FMS's own invocation exactly. `-t` is the syntax check, and it neither
  # starts nor signals anything.
  if ! validator_usable "$SYSTEM_APACHE"; then
    VALIDATION_DETAIL="the Apache validator $SYSTEM_APACHE is absent or not protected for root execution"
    return 2
  fi
  # Apache's `-t` returns promptly, so this bound has never been the load-bearing one - but the
  # command that ENFORCES it is still run as root here, and it is checked on this path for that
  # reason, not for the timing.
  if ! timeout_usable; then
    VALIDATION_DETAIL="the validation bound $SYSTEM_TIMEOUT is absent or not protected for root execution"
    return 2
  fi
  local main="$FMS_ROOT/HTTPServer/conf/httpd.conf"
  if [[ ! -f "$main" ]]; then
    VALIDATION_DETAIL="the FileMaker Apache configuration $main does not exist"
    return 2
  fi
  local out rc
  out="$(HTTP_ROOT="$FMS_ROOT/HTTPServer" SERVER_NAME="$(hostname)" \
    bounded 30 "$SYSTEM_APACHE" -t -D FILEMAKER -f "$main" 2>&1)"; rc=$?
  if [[ "$rc" -eq 0 ]]; then return 0; fi
  VALIDATION_DETAIL="$(printf '%s' "$out" | validation_line)"
  [[ -n "$VALIDATION_DETAIL" ]] || VALIDATION_DETAIL="Apache rejected its existing configuration (exit $rc)"
  return "$rc"
}

validate_now() {
  case "$TYPE" in
    fms-nginx) validate_nginx ;;
    apache)    validate_apache ;;
  esac
}

# ---------------------------------------------------------------------------------------------
case "$VERB" in
  validate)
    VALIDATION_DETAIL=""
    if validate_now; then
      ok_json "the existing $TYPE configuration validates" "" ""
    fi
    failed "${VALIDATION_DETAIL:-the existing $TYPE configuration did not validate}" false false
    ;;

  observe)
    st="$(marker_state "$CONF")"
    case "$st" in
      invalid) refuse "the ###${MARK} markers in $CONF are neither absent nor one balanced pair" ;;
      none) ok_json "no CORPUSfm block present" "" "" ;;
      one)  ok_json "CORPUSfm block present" "$(family_fingerprint)" "" ;;
    esac
    ;;

  publish|remove)
    st="$(marker_state "$CONF")"
    # NGINX IS INVENTORIED BY GENERATION, not by the `#+` marker COUNT. The count cannot express the
    # state fms-server was actually in — one retired block beside one current one — because `#+`
    # matches both forms: legacy-only counts 2 and passes for current, and the mixed file counts 4
    # and lands in `invalid`. The inventory below refuses everything ambiguous BEFORE the backup and
    # returns the exact block ranges to retire, which is what makes publication remove-before-add.
    if [[ -n "$INC" ]]; then
      if ! NGX_BLOCKS="$(nginx_owned_blocks "$CONF" 2>"$CONF.cfmwhy")"; then
        why="$(cat "$CONF.cfmwhy" 2>/dev/null)"; rm -f -- "$CONF.cfmwhy"
        refuse "${why:-the CORPUSfm blocks in $CONF could not be attributed}; refusing to rewrite \
FileMaker Server or operator configuration to make room"
      fi
      rm -f -- "$CONF.cfmwhy"
    else
      [[ "$st" == "invalid" ]] && \
        refuse "the ###${MARK} markers in $CONF are neither absent nor one balanced pair"
    fi
    res="$(residue_present "$CONF")"
    [[ -n "$res" ]] && \
      refuse "an unresolved transaction residue is present ($res); resolve it before mutating"
    if [[ "$VERB" == "publish" ]]; then
      [[ -f "$BLOCK_FILE" ]] || \
        refuse "--block-file is required for publish; this executor never renders its own block"
      if [[ -n "$INC" ]]; then
        [[ -f "$INCLUDE_FILE" ]] || refuse "--include-file is required to publish an nginx front"
        # Resolve the STRUCTURE before touching anything: a refusal here must leave the box exactly
        # as it was, and that is only true if it happens before the first write.
        if ! at="$(find_443_insert_line "$CONF" 2>"$CONF.cfmwhy")"; then
          why="$(cat "$CONF.cfmwhy" 2>/dev/null)"; rm -f -- "$CONF.cfmwhy"
          refuse "cannot place the CORPUSfm include: ${why:-the 443 server block could not be resolved}"
        fi
        rm -f -- "$CONF.cfmwhy"
      fi
    fi

    # BEFORE the backup and before any mutation: an Apache block that is not the geometry this
    # executor creates cannot be removed byte-exactly, so it refuses rather than guessing.
    if [[ -z "$INC" && "$st" == "one" ]] && ! apache_geometry_ok "$CONF"; then
      refuse "the CORPUSfm block in $CONF is not the appended geometry this executor creates (one \
balanced pair, closing marker at end of file, a single owned newline before it); refusing to remove \
it byte-inexactly"
    fi

    bak="$(make_backup "$CONF")" || failed "could not create a durable backup beside $CONF" false false
    backup_include
    tmp="$CONF.cfmnew"
    if [[ -n "$INC" ]]; then
      # REMOVE-BEFORE-ADD over both generations. Only the attributed ranges go; every other byte —
      # FMS's own directives, an operator's edits, an unrelated vendor block — is carried through.
      if [[ -n "$NGX_BLOCKS" ]]; then nginx_strip_owned "$CONF" "$NGX_BLOCKS" > "$tmp"
      else cp -- "$CONF" "$tmp"; fi
    elif [[ "$st" == "one" ]]; then
      apache_strip "$CONF" > "$tmp"                 # byte-exact; its file has no terminal newline
    else
      cp -- "$CONF" "$tmp"
    fi

    if [[ "$VERB" == "publish" ]]; then
      if [[ -n "$INC" ]]; then
        # Re-resolve against the STRIPPED text: removing a prior block moves every line after it.
        at="$(find_443_insert_line "$tmp" 2>/dev/null)"
        cp -- "$INCLUDE_FILE" "$INC"
        insert_at_line "$tmp" "$at" "$BLOCK_FILE" > "$tmp.2" && mv -- "$tmp.2" "$tmp"
      else
        # THE OWNED SEPARATOR, appended unconditionally. The shipped fragment ends without a
        # newline, so without this the block's first line joins the file's last one.
        printf '\n' >> "$tmp"
        cat -- "$BLOCK_FILE" >> "$tmp"
      fi
    else
      [[ -n "$INC" ]] && rm -f -- "$INC"
    fi
    cat -- "$tmp" > "$CONF"; rm -f -- "$tmp"        # publish the candidate (in place, mode kept)

    # The candidate's OWN shape first, then the server's opinion of it. A duplicate include is a
    # configuration nginx will refuse the next time it starts, and the running process would not
    # have told us — so it is caught here rather than left for the next restart.
    if [[ -n "$INC" ]] \
       && ! nginx_normalized_ok "$CONF" "$([[ "$VERB" == "publish" ]] && echo published || echo absent)"; then
      vrc=1
    else
      VALIDATION_DETAIL=""
      validate_now; vrc=$?
    fi
    if [[ "$vrc" -eq 0 ]]; then
      fp=""
      [[ "$VERB" == "publish" ]] && fp="$(family_fingerprint)"
      # The backup STAYS. It is retired by the `retire` verb once the manifest and the
      # configuration agree; removing it here would leave the window between a live edit and a
      # published manifest with no restore point - which is the exact window a crash lands in.
      ok_json "published and validated" "$fp" "$bak"
    fi
    # PUBLICATION or VALIDATION failed. The running server never consumed this candidate, so put the
    # bytes back and RESTART NOTHING.
    if restore_backup "$CONF"; then
      restore_include
      failed "validation failed: ${VALIDATION_DETAIL:-the validator rejected the candidate}; exact bytes restored and verified (nothing was activated)" true true
    fi
    failed "validation failed: ${VALIDATION_DETAIL:-the validator rejected the candidate}; the restoration could not be verified; backup retained at $(backup_of "$CONF")" true false
    ;;

  restore)
    if restore_backup "$CONF"; then
      restore_include
      ok_restored "restored and verified"
    fi
    failed "restoration could not be verified; backup retained at $(backup_of "$CONF")" true false
    ;;

  prepare)
    # STAGE ONE (ruling 4). Capture the before-image; change NO routing. A crash here leaves
    # evidence and an untouched box - a state a later process can classify cleanly rather than
    # having to guess whether a mutation began.
    [[ -n "$OPERATION_ID" ]] || refuse "--operation-id is required to capture a before-image"
    [[ -n "$EVIDENCE_DIR" ]] || refuse "--evidence-dir is required to capture a before-image"
    st="$(marker_state "$CONF")"
    [[ "$st" == "invalid" ]] && \
      refuse "the ###${MARK} markers in $CONF are neither absent nor one balanced pair"
    mkdir -p -- "$EVIDENCE_DIR" || refuse "the evidence directory $EVIDENCE_DIR is not writable"
    ev="$EVIDENCE_DIR/cfm-${TYPE}-before-${OPERATION_ID}.json"
    inc_present=false; [[ -n "$INC" && -f "$INC" ]] && inc_present=true
    inc_digest=null
    [[ "$inc_present" == true ]] && inc_digest="\"$(canonicalize < "$INC" | sha256sum | cut -d' ' -f1)\""
    tmp_ev="$ev.new"
    printf '{"operation_id":"%s","proxy_type":"%s","config":"%s","config_digest":"%s","marker_state":"%s","include":"%s","include_present":%s,"include_digest":%s}\n' \
      "$OPERATION_ID" "$TYPE" "$CONF" "$(digest "$CONF")" "$st" "${INC:-}" "$inc_present" "$inc_digest" \
      > "$tmp_ev" || refuse "the before-image could not be written to $EVIDENCE_DIR"
    # ATOMIC and DURABLE: a half-written before-image is worse than none, because a later process
    # would read it as authority.
    sync 2>/dev/null || true
    mv -f -- "$tmp_ev" "$ev" || refuse "the before-image could not be published"
    sync 2>/dev/null || true
    ok_json "before-image captured; nothing was changed" "" "" "\"$ev\""
    ;;

  classify)
    # RECOVERY CLASSIFICATION (Codex final check). Does the artifact family STILL match the
    # before-image this operation captured?
    #
    # `prepare` changes no routing, so an interruption between it and the mutation leaves a durable
    # `prepared` record over a completely untouched box. The abort path used to restore blindly -
    # and `restore` needs a `.cfmbak` that publication never created, so it failed and left the
    # installation wedged with `manual_action_required` for an operation that had changed nothing.
    #
    # `unchanged` is the discriminator, and it is NEVER guessed: an unreadable before-image, a
    # missing one, or a state this cannot compare answers `null`, which the caller treats as
    # "may have changed" and restores through the ordinary path.
    [[ -n "$OPERATION_ID" && -n "$EVIDENCE_DIR" ]] || \
      refuse "--operation-id and --evidence-dir are required to classify a recovery"
    ev="$EVIDENCE_DIR/cfm-${TYPE}-before-${OPERATION_ID}.json"
    [[ -f "$ev" ]] || refuse "no before-image for this operation at $ev"
    # `sed -E`: basic sed has no `\|` alternation, and without it `include_present` parsed as the
    # EMPTY string - which never equals "true" or "false", so every classification came back
    # "differs" and the whole discrimination silently collapsed into the old blind-restore path.
    want_conf="$(sed -n -E 's/.*"config_digest":"([^"]*)".*/\1/p' "$ev")"
    want_inc_present="$(sed -n -E 's/.*"include_present":(true|false).*/\1/p' "$ev")"
    want_inc="$(sed -n -E 's/.*"include_digest":"([^"]*)".*/\1/p' "$ev")"
    [[ -n "$want_conf" ]] || refuse "the before-image at $ev does not record a configuration digest"

    now_conf="$(digest "$CONF")"
    same=true
    [[ "$now_conf" == "$want_conf" ]] || same=false
    if [[ -n "$INC" ]]; then
      now_present=false; [[ -f "$INC" ]] && now_present=true
      [[ "$now_present" == "$want_inc_present" ]] || same=false
      if [[ "$now_present" == true && "$want_inc_present" == true ]]; then
        [[ "$(canonicalize < "$INC" | sha256sum | cut -d' ' -f1)" == "$want_inc" ]] || same=false
      fi
    fi
    if [[ "$same" == true ]]; then
      ok_json "the artifact family still matches its before-image" "" "" "\"$ev\"" true
    fi
    ok_json "the artifact family differs from its before-image" "" "" "\"$ev\"" false
    ;;

  retire)
    # Called only after the configuration and the manifest agree. Afterwards the backup is inert;
    # before that it is the only restore point on the box.
    retire_backups || failed "one or more transaction backups could not be retired" false false
    [[ -n "$OPERATION_ID" && -n "$EVIDENCE_DIR" ]] && \
      rm -f -- "$EVIDENCE_DIR/cfm-${TYPE}-before-${OPERATION_ID}.json"
    ok_json "backups retired" "" ""
    ;;

  *) refuse "'$VERB' is not a verb (prepare | classify | observe | publish | remove | restore | retire)" ;;
esac
