#!/bin/bash
# cfm-db-helper — scoped, root-run broker for FileMaker Server Databases-dir file ops.
#
# The unprivileged corpusfm service invokes this via a narrow NOPASSWD sudoers rule
# (/etc/sudoers.d/corpusfm-db-helper). It is the ONLY elevation the service has, and
# it exists solely because the FMS Databases directory is writable by the fmserver
# user only. Every operation is:
#   - confined to the FMS Databases directory (no traversal, no symlink escape),
#   - restricted to .fmp12 files with a validated name,
#   - restricted to /tmp/cfm* for the external (caller-owned) side, symlink-safe
#     (the external path is canonicalized; a symlink leaf or symlinked parent is refused,
#     and root never cp/chowns the caller-named path directly — it writes a root-owned
#     mktemp file and mv's it into place, so a service-user symlink can't aim the chown
#     at /etc/*), and
#   - refused outright for the CORPUSfm storage DB.
#
# Hardening (defence-in-depth on the world-writable /tmp namespace): the external side must be a
# PRIVATE staging dir — its canonical parent is refused if group- or other-writable (the real
# callers stage in mkdtemp 0700 subdirs, so this only rejects a loose-perms / attacker-influenced
# dir), and the source leaf is re-checked for a symlink IMMEDIATELY before the privileged read to
# shrink the canon->use window.
#
# Full handoff TOCTOU close (mkhandoff/rmhandoff + handoff-source place): the /tmp-side residual
# was a tight race on the SERVICE-owned staging dir — a compromised service could swap the leaf
# for a symlink between the final ! -L re-check and the cp. The complete close is a ROOT-OWNED
# handoff dir the service cannot create/rename entries in: `mkhandoff` pre-creates a root-owned
# 0711 dir + a service-owned 0600 file inside; the service writes the payload INTO that file
# (file-write only) but can never swap the dir entry, so `place` reads a path whose directory
# entry is immutable from the service's side. `place` accepts BOTH a handoff path (preferred,
# race-free — validated root-owned) and a legacy /tmp/cfm* path (back-compat fallback for a box
# not yet re-provisioned, still symlink-hardened).
#
# It deliberately does NOT host/open/close databases (that goes through fmsadmin +
# the admin server, which the service can already do) — it only places, copies out,
# and removes files. Keep this script minimal and auditable.
#
# Ops:
#   cfm-db-helper copy-out  <db_name> <dest>  # DBDIR/<db_name>.fmp12 -> dest (chown corpusfm)
#   cfm-db-helper place     <src> <db_name>   # src -> DBDIR/<db_name>.fmp12 (chown fmserver)
#   cfm-db-helper remove    <db_name>         # rm DBDIR/<db_name>.fmp12
#   cfm-db-helper mkhandoff                   # mk root-owned dir + service-owned file; prints path
#   cfm-db-helper rmhandoff <file>            # rm the handoff dir created by mkhandoff
set -euo pipefail

DBDIR="/opt/FileMaker/FileMaker Server/Data/Databases"
DB_OWNER="fmserver:fmsadmin"
SERVICE_USER="corpusfm"
PROTECTED="CORPUSfm_DB"          # never place/remove the CORPUSfm storage DB
TMP_PREFIX="/tmp/cfm"            # caller-owned (external) paths must live here
# Root-owned handoff namespace (installer-provisioned, 0711 root:root). Env-overridable so the
# unit suite can exercise the path validation against a test dir. The TOCTOU-safe `place` source.
HANDOFF_ROOT="${CFM_HANDOFF_ROOT:-/var/lib/corpusfm/handoff}"
# Canonical real form (some platforms symlink the prefix, e.g. /tmp → /private/tmp under test) so
# the resolved-parent confinement accepts both forms. Falls back to the literal if it doesn't exist.
REAL_HANDOFF="$( (cd "$HANDOFF_ROOT" 2>/dev/null && pwd -P) || echo "$HANDOFF_ROOT")"
# Canonical real form of /tmp (some platforms symlink /tmp → e.g. /private/tmp); the resolved-
# parent confinement below accepts both so it doesn't false-reject where /tmp is itself a symlink.
# `cd … && pwd -P` is the portable symlink-resolver (GNU `realpath -e` isn't on every platform).
REAL_TMP="$( (cd /tmp 2>/dev/null && pwd -P) || echo /tmp)"

die() { echo "cfm-db-helper: $1" >&2; exit 2; }

assert_private_dir() {  # refuse a group/other-writable staging dir — handoff must be private (0700-style)
  local d="$1"
  # `find -perm -MODE` (all listed bits set) is portable (GNU + BSD); match group-write OR other-write.
  if find "$d" -maxdepth 0 \( -perm -0002 -o -perm -0020 \) 2>/dev/null | grep -q .; then
    die "staging dir is group/other-writable (refused — handoff must be private): '$d'"
  fi
}

assert_root_owned() {  # refuse a dir not owned by root — entry-immutability of the handoff depends on it
  local d="$1"
  # `find -user root` is portable (GNU + BSD). Root ownership + no group/other write (assert_private_dir)
  # means ONLY root can create/rename entries — the service cannot swap the source leaf for a symlink.
  find "$d" -maxdepth 0 -user root 2>/dev/null | grep -q . || \
    die "handoff dir is not root-owned (refused): '$d'"
}

valid_name() {
  local name="$1" re='^[A-Za-z0-9 ._-]+$'
  case "$name" in
    ""|*..*|*/*) die "invalid db name: '$name'" ;;
  esac
  [[ "$name" =~ $re ]] || die "invalid characters in db name: '$name'"
  [[ "$name" == "$PROTECTED" ]] && die "refusing to operate on the storage DB '$PROTECTED'"
  return 0
}

canon_external() {  # echo a symlink-safe, confined external path (resolved parent + literal leaf)
  local p="$1" parent leaf rp
  case "$p" in
    "$TMP_PREFIX"*) : ;;
    *) die "external path must be under '$TMP_PREFIX': '$p'" ;;
  esac
  case "$p" in *..*) die "path traversal in '$p'" ;; esac
  parent="$(dirname -- "$p")"
  leaf="$(basename -- "$p")"
  case "$leaf" in ""|.|..) die "invalid external leaf: '$p'" ;; esac
  # Resolve the parent's real path (follows + collapses symlinks); it must STILL be under the
  # /tmp/cfm prefix, so a symlinked parent that points outside is caught here. cd+pwd -P is the
  # portable resolver (requires the dir to exist, which it must).
  rp="$( (cd -- "$parent" 2>/dev/null && pwd -P) )" || true
  [ -n "$rp" ] || die "external parent dir not found: '$parent'"
  case "$rp/" in
    "$TMP_PREFIX"*|"$REAL_TMP"/cfm*) : ;;
    *) die "external path escapes '$TMP_PREFIX' after symlink resolution: '$p'" ;;
  esac
  # The staging dir must be private — a group/other-writable parent means a non-service local user
  # could plant or swap the leaf. The real callers use mkdtemp 0700 subdirs, so this only refuses a
  # loose-perms dir.
  assert_private_dir "$rp"
  # The leaf itself must not be a pre-planted symlink (would redirect a root cp/mv).
  [ -L "$rp/$leaf" ] && die "external path is a symlink (refused): '$p'"
  printf '%s/%s' "$rp" "$leaf"
}

canon_handoff() {  # echo a confined, race-free handoff source path (parent must be root-owned)
  local p="$1" parent leaf rp
  case "$p" in
    "$HANDOFF_ROOT"/*) : ;;
    *) die "handoff path must be under '$HANDOFF_ROOT': '$p'" ;;
  esac
  case "$p" in *..*) die "path traversal in '$p'" ;; esac
  parent="$(dirname -- "$p")"
  leaf="$(basename -- "$p")"
  case "$leaf" in ""|.|..) die "invalid handoff leaf: '$p'" ;; esac
  rp="$( (cd -- "$parent" 2>/dev/null && pwd -P) )" || true
  [ -n "$rp" ] || die "handoff parent dir not found: '$parent'"
  case "$rp/" in
    "$HANDOFF_ROOT"/*|"$REAL_HANDOFF"/*) : ;;
    *) die "handoff path escapes '$HANDOFF_ROOT' after symlink resolution: '$p'" ;;
  esac
  # SECURITY CRUX of the full close: the dir holding the source must be root-owned and not
  # group/other-writable, so the unprivileged service cannot create/rename/symlink-swap the entry
  # between this check and the privileged cp. With this, the source leaf is immutable from the
  # service's side — the /tmp handoff TOCTOU is gone (no race window to lose).
  assert_root_owned "$rp"
  assert_private_dir "$rp"
  [ -L "$rp/$leaf" ] && die "handoff path is a symlink (refused): '$p'"
  printf '%s/%s' "$rp" "$leaf"
}

canon_source() {  # dispatch: handoff (root-owned, race-free) vs legacy /tmp/cfm* (back-compat)
  case "$1" in
    "$HANDOFF_ROOT"/*) canon_handoff "$1" ;;
    *) canon_external "$1" ;;
  esac
}

db_path() {  # echo the confined absolute Databases path for a (validated) db name
  local p="$DBDIR/$1.fmp12"
  [[ "$(dirname "$p")" == "$DBDIR" ]] || die "path escapes the Databases directory"
  printf '%s' "$p"
}

op="${1:-}"; shift || true
case "$op" in
  copy-out)
    name="${1:-}"; valid_name "$name"
    dest="$(canon_external "${2:-}")"
    src="$(db_path "$name")"
    [[ -f "$src" ]] || die "no such database: '$name'"
    # Never cp/chown the caller-named path directly (a symlink there would aim root at it).
    # Write a root-owned mktemp (random name → not pre-placeable), set owner/mode on THAT,
    # then rename it over dest (rename replaces a symlink instead of following it).
    destdir="$(dirname -- "$dest")"
    tmp="$(mktemp "$destdir/.cfm-co.XXXXXX")" || die "mktemp failed in '$destdir'"
    trap 'rm -f "$tmp"' EXIT
    cp -f -- "$src" "$tmp"
    chown "$SERVICE_USER:$SERVICE_USER" -- "$tmp"
    chmod 600 -- "$tmp"
    mv -f -- "$tmp" "$dest"
    trap - EXIT
    echo "ok: copied '$name' -> $dest"
    ;;
  place)
    name="${2:-}"; valid_name "$name"
    src="$(canon_source "${1:-}")"
    [[ -f "$src" ]] || die "no such source file: '$src'"
    dest="$(db_path "$name")"
    # Atomic swap: write a sibling temp, set ownership/mode on it, then rename it over
    # the live file. A rename within one filesystem is atomic, so the live DB is always
    # either the complete OLD file or the complete NEW one — never a partial, even if
    # the copy is interrupted (crash, kill, disk-full). The temp is cleaned up on any
    # failure; it never ends in .fmp12 so FM Server's auto-scan ignores it. src is
    # canonicalized + symlink-checked above, so cp reads only the real caller file.
    tmp="$dest.cfmswap.$$"
    trap 'rm -f "$tmp"' EXIT
    # Re-assert the source isn't a symlink RIGHT BEFORE the privileged read (canon_external checked
    # at validation time; this shrinks the canon->use TOCTOU window to near-zero).
    [ -L "$src" ] && die "source became a symlink (refused): '$src'"
    cp -f -- "$src" "$tmp"
    chown "$DB_OWNER" -- "$tmp"
    chmod 660 -- "$tmp"
    mv -f -- "$tmp" "$dest"
    trap - EXIT
    echo "ok: placed '$name'"
    ;;
  remove)
    name="${1:-}"
    valid_name "$name"
    target="$(db_path "$name")"
    rm -f "$target"
    echo "ok: removed '$name'"
    ;;
  mkhandoff)
    # Pre-create a ROOT-OWNED handoff dir + a SERVICE-OWNED 0600 file inside it, and print the
    # file path (the only stdout line). The service writes its payload INTO that file in place
    # (file-write), then asks `place` to read from it — but it can never swap the dir entry
    # (the dir is root-owned, 0711, no group/other write). This is the race-free `place` source.
    [ -d "$HANDOFF_ROOT" ] || die "handoff root not provisioned: '$HANDOFF_ROOT' (re-run installer)"
    d="$(mktemp -d "$HANDOFF_ROOT/h.XXXXXX")" || die "mktemp -d failed under '$HANDOFF_ROOT'"
    chown root:root -- "$d"
    chmod 0711 -- "$d"          # service can traverse to the file, but cannot create/rename entries
    f="$d/payload.fmp12"
    : > "$f"
    chown "$SERVICE_USER:$SERVICE_USER" -- "$f"   # service owns the FILE → can write its content
    chmod 0600 -- "$f"
    printf '%s\n' "$f"
    ;;
  rmhandoff)
    # Tear down a handoff dir created by mkhandoff. Only a direct child dir of HANDOFF_ROOT is
    # removable (never the root itself, never anything outside it).
    f="${1:-}"
    case "$f" in
      "$HANDOFF_ROOT"/*) : ;;
      *) die "rmhandoff path must be under '$HANDOFF_ROOT': '$f'" ;;
    esac
    case "$f" in *..*) die "path traversal in '$f'" ;; esac
    d="$(dirname -- "$f")"
    [ "$d" = "$HANDOFF_ROOT" ] && die "refusing to remove the handoff root: '$d'"
    [ "$(dirname -- "$d")" = "$HANDOFF_ROOT" ] || die "refusing to remove non-handoff dir: '$d'"
    rm -rf -- "$d"
    echo "ok: removed handoff '$d'"
    ;;
  *)
    die "usage: cfm-db-helper {copy-out <db_name> <dest>|place <src> <db_name>|remove <db_name>|mkhandoff|rmhandoff <file>}"
    ;;
esac
