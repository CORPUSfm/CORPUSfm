#!/usr/bin/env bash
# Validate the one-use bootstrap handoff before install.sh enters its ordinary orchestration.
set -euo pipefail

HANDOFF="${1:-}"
BUNDLE_DIR="${2:-}"
refuse() { printf '  x Bootstrap handoff refused: %s\n' "$1" >&2; exit 2; }

[[ -n "$HANDOFF" && -n "$BUNDLE_DIR" ]] || refuse "handoff and bundle directory are required"
[[ "$HANDOFF" == "$BUNDLE_DIR/.bootstrap-handoff.json" ]] || \
    refuse "handoff is not the canonical file inside this bundle"
[[ -f "$HANDOFF" && ! -L "$HANDOFF" ]] || refuse "handoff is missing or is a symbolic link"
[[ "$(stat -c '%u' "$HANDOFF" 2>/dev/null || true)" == 0 ]] || refuse "handoff is not root-owned"
[[ "$(stat -c '%a' "$HANDOFF" 2>/dev/null || true)" == 600 ]] || refuse "handoff mode is not 0600"
expected_keys="application_version bootstrap_protocol bundle_protocol bundle_sha256 commit consent entry_point installer_series installer_version nonce platform schema_version transcript"
actual_keys="$(sed -nE 's/^[[:space:]]*"([a-z0-9_]+)":.*/\1/p' "$HANDOFF" | sort | tr '\n' ' ' | sed 's/ $//')"
[[ "$actual_keys" == "$expected_keys" ]] || refuse "fields do not match schema 1"

json_string() {
    local key="$1" count value
    count="$(grep -Ec "^[[:space:]]*\"${key}\": \"[^\"]*\",?$" "$HANDOFF" || true)"
    [[ "$count" == 1 ]] || refuse "field $key is absent, duplicated, or not a simple string"
    value="$(sed -nE "s/^[[:space:]]*\"${key}\": \"([^\"]*)\",?$/\\1/p" "$HANDOFF")"
    printf '%s' "$value"
}
json_integer() {
    local key="$1" count value
    count="$(grep -Ec "^[[:space:]]*\"${key}\": [0-9]+,?$" "$HANDOFF" || true)"
    [[ "$count" == 1 ]] || refuse "field $key is absent, duplicated, or not an integer"
    value="$(sed -nE "s/^[[:space:]]*\"${key}\": ([0-9]+),?$/\\1/p" "$HANDOFF")"
    printf '%s' "$value"
}

[[ "$(json_integer schema_version)" == 1 ]] || refuse "schema is not 1"
[[ "$(json_integer bootstrap_protocol)" == 1 ]] || refuse "bootstrap protocol is not 1"
[[ "$(json_integer bundle_protocol)" == 1 ]] || refuse "bundle protocol is not 1"
SERIES="$(json_string installer_series)"
VERSION="$(json_string installer_version)"
APP_VERSION="$(json_string application_version)"
COMMIT="$(json_string commit)"
PLATFORM="$(json_string platform)"
ENTRY="$(json_string entry_point)"
BUNDLE_SHA="$(json_string bundle_sha256)"
TRANSCRIPT="$(json_string transcript)"
CONSENT="$(json_string consent)"
NONCE="$(json_string nonce)"

[[ "$SERIES" =~ ^series-[1-9][0-9]*$ ]] || refuse "installer series is invalid"
[[ "$VERSION" =~ ^0\.[0-9]+$ && "$APP_VERSION" =~ ^0\.[0-9]+$ ]] || \
    refuse "installer or application version is invalid"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || refuse "commit is not exact"
[[ "$PLATFORM" == linux && "$ENTRY" == install.sh ]] || refuse "platform entry point disagrees"
[[ "$BUNDLE_SHA" =~ ^[0-9a-f]{64}$ ]] || refuse "bundle digest is invalid"
[[ "$TRANSCRIPT" == /var/log/corpusfm/bootstrap-install-*.log ]] || refuse "transcript is not canonical"
[[ "$CONSENT" == interactive || "$CONSENT" == yes || "$CONSENT" == silent ]] || \
    refuse "consent mode is invalid"
[[ "$NONCE" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || \
    refuse "nonce is not a version-4 UUID"

printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$SERIES" "$VERSION" "$APP_VERSION" "$COMMIT" "$TRANSCRIPT" "$CONSENT"
