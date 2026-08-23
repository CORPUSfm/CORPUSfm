#!/usr/bin/env bash
# Verify the flattened Linux installer package before the installer observes or changes a box.
set -euo pipefail

DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
MANIFEST="$DIR/installer-manifest.json"

refuse() { printf '  x Installer bundle refused: %s\n' "$1" >&2; exit 2; }

json_string() {
    local key="$1" count value
    count="$(grep -Ec "^[[:space:]]*\"${key}\": \"[^\"]*\",?$" "$MANIFEST" || true)"
    [[ "$count" == 1 ]] || refuse "descriptor field $key is absent, duplicated, or not a simple string"
    value="$(sed -nE "s/^[[:space:]]*\"${key}\": \"([^\"]*)\",?$/\\1/p" "$MANIFEST")"
    printf '%s' "$value"
}

json_integer() {
    local key="$1" count value
    count="$(grep -Ec "^[[:space:]]*\"${key}\": [0-9]+,?$" "$MANIFEST" || true)"
    [[ "$count" == 1 ]] || refuse "descriptor field $key is absent, duplicated, or not an integer"
    value="$(sed -nE "s/^[[:space:]]*\"${key}\": ([0-9]+),?$/\\1/p" "$MANIFEST")"
    printf '%s' "$value"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        refuse "neither sha256sum nor shasum is available"
    fi
}

[[ -f "$MANIFEST" ]] || refuse "installer-manifest.json is missing"
[[ "$(json_integer schema_version)" == 1 ]] || refuse "descriptor schema is not 1"
[[ "$(json_integer bundle_protocol)" == 1 ]] || refuse "bundle protocol is not 1"

SERIES="$(json_string installer_series)"
INSTALLER_VERSION="$(json_string installer_version)"
APPLICATION_VERSION="$(json_string application_version)"
COMMIT="$(json_string commit)"
PLATFORM="$(json_string platform)"
ENTRY_POINT="$(json_string entry_point)"
DIGEST_FILE="$(json_string payload_digest_file)"
DIGEST_SHA256="$(json_string payload_digest_sha256)"

[[ "$SERIES" =~ ^series-[1-9][0-9]*$ ]] || refuse "installer_series is invalid"
[[ "$INSTALLER_VERSION" =~ ^0\.[0-9]+$ ]] || refuse "installer_version is invalid"
[[ "$APPLICATION_VERSION" =~ ^0\.[0-9]+$ ]] || refuse "application_version is invalid"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || refuse "commit is not an exact SHA-1"
[[ "$PLATFORM" == linux ]] || refuse "descriptor platform is not linux"
[[ "$ENTRY_POINT" == install.sh ]] || refuse "descriptor entry point is not install.sh"
[[ "$DIGEST_FILE" == installer-files.sha256 ]] || refuse "payload digest file name is not canonical"
[[ "$DIGEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || refuse "payload digest-file hash is invalid"
[[ -f "$DIR/$DIGEST_FILE" ]] || refuse "$DIGEST_FILE is missing"
[[ "$(sha256_file "$DIR/$DIGEST_FILE")" == "$DIGEST_SHA256" ]] || \
    refuse "$DIGEST_FILE does not agree with installer-manifest.json"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$DIR" && sha256sum --check --strict --status "$DIGEST_FILE") || \
        refuse "one or more packaged payload files failed digest verification"
else
    (cd "$DIR" && shasum -a 256 --check "$DIGEST_FILE" >/dev/null) || \
        refuse "one or more packaged payload files failed digest verification"
fi

printf '%s\t%s\t%s\t%s\n' "$SERIES" "$INSTALLER_VERSION" "$APPLICATION_VERSION" "$COMMIT"
