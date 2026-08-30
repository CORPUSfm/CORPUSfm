#!/usr/bin/env bash
# package-installer.sh — package the self-sufficient installers as per-platform release zips.
#
# The distribution is a self-contained installer package. It carries an exact application Git
# bundle and a digest-covered installer runtime. The uninstaller is installed by the
# product; it is not exposed as a top-level distribution artifact.
#
# Produces one immutable release under outputs/server/<series>/releases/<version>/, containing TWO
# zips, each + a .sha256, and a release.json inventory. Each zip carries installer-manifest.json,
# the platform entrypoint, digest-covered runtime archive, and complete Git bundle at this exact main HEAD. A
# series-scoped latest.json is published only after both bundles and the release inventory agree.
# <rev> = the tracked public release-build identity (the same 0.{rev} version the app reports).
#
# Usage:  ./installer/package-installer.sh --application-checkout /path/to/CORPUSfm \
#           --application-commit <full-40-hex-commit>
#         # focused repo and application checkout must both be on clean main commits
# Then:   tag v0.<rev> + (optionally) attach the zips to a GitHub Release.
#
# Tier-3 build/release script (installer/SPEC.md "Script conformance") — NOT on the S1-S10 skeleton.
# A release directory is immutable: this script refuses rather than overwriting one.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# --application-commit is REQUIRED and must be a full 40-hex object id (packet 1257). The package is
# built from a clean materialization of exactly that commit, never from the caller's working tree:
# a builder that reads a working tree ships whatever happens to be checked out, which is the same
# hazard this project already forbids for the asset repositories.
[[ "${1:-}" == "--application-checkout" && -n "${2:-}" \
   && "${3:-}" == "--application-commit" && -n "${4:-}" && $# -eq 4 ]] || {
    echo "Usage: $0 --application-checkout /path/to/CORPUSfm \\" >&2
    echo "          --application-commit <full-40-hex-commit>" >&2
    exit 2
}
APP_ROOT="$(cd "$2" && pwd)"
APP_COMMIT_ARG="$4"
[[ "$APP_COMMIT_ARG" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Refusing: --application-commit must be a full 40-hex commit id, got $APP_COMMIT_ARG" >&2
    exit 1
}
# ── Application materialization (packet 1257) ────────────────────────────────────────────────
# The selected commit is resolved IN the caller's repository (which supplies the objects) and then
# CHECKED OUT CLEAN into a temporary clone. Everything downstream — the bundle, the inspected source,
# the version — reads that materialization. The caller's working tree is never read and never
# touched, so uncommitted work in it cannot reach a package and cannot block a build.
git -C "$APP_ROOT" cat-file -e "${APP_COMMIT_ARG}^{commit}" 2>/dev/null || {
    echo "Refusing: --application-commit $APP_COMMIT_ARG is not a commit in $APP_ROOT" >&2
    exit 1
}
COMMIT="$APP_COMMIT_ARG"
APP_MATERIALIZED="$(mktemp -d)"
git clone --quiet --no-hardlinks --no-checkout "$APP_ROOT" "$APP_MATERIALIZED" || {
    echo "Refusing: could not materialize the application repository" >&2; exit 1; }
git -C "$APP_MATERIALIZED" checkout --quiet -B main "$COMMIT" || {
    echo "Refusing: could not check out $COMMIT in the materialization" >&2; exit 1; }
[[ "$(git -C "$APP_MATERIALIZED" rev-parse HEAD)" == "$COMMIT" ]] || {
    echo "Refusing: materialized HEAD is not $COMMIT" >&2; exit 1; }
git -C "$APP_MATERIALIZED" diff --quiet && git -C "$APP_MATERIALIZED" diff --cached --quiet || {
    echo "Refusing: the materialization is not clean (this is a bug, not a caller condition)" >&2
    exit 1
}
REV="$(tr -d ' \t\r\n' < "$APP_MATERIALIZED/release-build.txt" 2>/dev/null || true)"
[[ "$REV" =~ ^[1-9][0-9]*$ ]] || {
    echo "Refusing: selected public commit has no valid release-build.txt" >&2; exit 1; }
VER="0.$REV"
INSTALLER_SOURCE_COMMIT="$(git rev-parse HEAD)"
SERIES="${CORPUSFM_INSTALLER_SERIES:-series-2}"
PACKAGE_KIND="${CORPUSFM_INSTALLER_PACKAGE_KIND:-ordinary}"
DISTRIBUTION_ROOT="outputs/server"
SERIES_DIR="$DISTRIBUTION_ROOT/$SERIES"
OUT_DIR="$SERIES_DIR/releases/$VER"
SRC="installer"
SOURCE_BUNDLE="$(mktemp)"
BUILD_DIR="$(mktemp -d)"
cleanup() { rm -f "$SOURCE_BUNDLE"; rm -rf "$BUILD_DIR" "${APP_MATERIALIZED:-}"; }
trap cleanup EXIT

[[ "$SERIES" =~ ^series-[1-9][0-9]*$ ]] || {
    echo "Refusing: installer series must match series-<positive integer>, got $SERIES" >&2
    exit 1
}
[[ "$PACKAGE_KIND" == ordinary || "$PACKAGE_KIND" == exercise || "$PACKAGE_KIND" == bridge ]] || {
    echo "Refusing: package kind must be ordinary, exercise or bridge" >&2
    exit 1
}
[[ ! -e "$SERIES_DIR/bridge.json" ]] || {
    echo "Refusing: $SERIES is permanently closed by $SERIES_DIR/bridge.json" >&2
    exit 1
}

[[ "$(git rev-parse HEAD)" == "$(git rev-parse refs/heads/main)" ]] || {
    echo "Refusing: focused installer HEAD is not refs/heads/main" >&2; exit 1;
}
# (The application selection is the explicit --application-commit above; the caller's branch state
# and working tree are deliberately irrelevant.)
[[ ! -e "$OUT_DIR" ]] || {
    echo "Refusing: immutable installer release already exists at $OUT_DIR" >&2
    exit 1
}
git diff --quiet -- \
    installer/linux/install.sh installer/linux/_cfm_lib.sh \
    installer/windows/install.ps1 installer/windows/_cfm_lib.ps1 \
    installer/windows/cfm-verify-installer-bundle.ps1 \
    installer/windows/cfm-verify-bootstrap-handoff.ps1 \
    installer/linux/cfm-verify-installer-bundle.sh \
    installer/linux/cfm-verify-bootstrap-handoff.sh \
    installer/bootstrap/linux/bootstrap.sh installer/bootstrap/windows/bootstrap.ps1 || {
    echo "Refusing: a shipped installer file differs from HEAD; commit it before packaging" >&2
    exit 1
}
# The bundle is produced from the MATERIALIZATION, and its `main` is then proved to resolve to the
# selected commit — a bundle is what the installed box actually gets, so "we asked for X" is not the
# same claim as "the shipped bundle contains X".
git -C "$APP_MATERIALIZED" bundle create "$SOURCE_BUNDLE" main >/dev/null
git -C "$APP_MATERIALIZED" bundle verify "$SOURCE_BUNDLE" >/dev/null
BUNDLED_MAIN="$(git -C "$APP_MATERIALIZED" bundle list-heads "$SOURCE_BUNDLE" \
                | awk '$2 == "refs/heads/main" {print $1}')"
[[ "$BUNDLED_MAIN" == "$COMMIT" ]] || {
    echo "Refusing: bundled refs/heads/main is $BUNDLED_MAIN, expected $COMMIT" >&2
    exit 1
}

mkdir -p "$BUILD_DIR/release"

# ── Series 2 asset payload (packet 1257) ─────────────────────────────────────────────────────
# A consolidated public tree carries reviewed runtime assets at installer/assets. Private development
# builds may nominate the two pinned source checkouts instead. Installed boxes receive bytes only.
ASSETS_ZIP="$BUILD_DIR/corpusfm-assets.zip"
if [[ -d "$APP_MATERIALIZED/installer/assets/db" && -d "$APP_MATERIALIZED/installer/assets/addon" ]]; then
    ASSET_DB_DIR="$APP_MATERIALIZED/installer/assets/db" \
    ASSET_ADDON_DIR="$APP_MATERIALIZED/installer/assets/addon" ASSET_TREE_REVISION="$COMMIT" \
    ASSETS_ZIP="$ASSETS_ZIP" BUILD_DIR="$BUILD_DIR" python3 "$ROOT/installer/build-asset-payload.py"
else
    : "${CORPUSFM_ASSET_DB_REPO:?set CORPUSFM_ASSET_DB_REPO to the reviewed stable DB asset checkout}"
    : "${CORPUSFM_ASSET_ADDON_REPO:?set CORPUSFM_ASSET_ADDON_REPO to the reviewed stable add-on asset checkout}"
    ASSET_DB_REPO="$CORPUSFM_ASSET_DB_REPO" \
    ASSET_DB_COMMIT="${CORPUSFM_ASSET_DB_COMMIT:-853339a}" \
    ASSET_ADDON_REPO="$CORPUSFM_ASSET_ADDON_REPO" \
    ASSET_ADDON_COMMIT="${CORPUSFM_ASSET_ADDON_COMMIT:-72d257c}" \
    ASSETS_ZIP="$ASSETS_ZIP" BUILD_DIR="$BUILD_DIR" python3 "$ROOT/installer/build-asset-payload.py"
fi

ASSET_MANIFEST="$BUILD_DIR/assets.json"
[[ -s "$ASSETS_ZIP" && -s "$ASSET_MANIFEST" ]] || {
    echo "Refusing: the Series 2 asset payload was not produced" >&2; exit 1; }


sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

write_installer_manifest() { # <stage> <platform> <entry-point>
    local stage="$1" platform="$2" entry="$3"
    local digest_file="$stage/installer-files.sha256"
    : > "$digest_file"
    local payload
    for payload in "$stage"/*; do
        [[ -f "$payload" && "$(basename "$payload")" != installer-files.sha256 ]] || continue
        printf '%s  %s\n' "$(sha256_file "$payload")" "$(basename "$payload")" >> "$digest_file"
    done
    local digest_sha256; digest_sha256="$(sha256_file "$digest_file")"
    STAGE="$stage" PLATFORM="$platform" ENTRY="$entry" SERIES="$SERIES" VER="$VER" COMMIT="$COMMIT" \
      INSTALLER_SOURCE_COMMIT="$INSTALLER_SOURCE_COMMIT" \
      PACKAGE_KIND="$PACKAGE_KIND" BRIDGE_TARGET_SERIES="${CORPUSFM_BRIDGE_TARGET_SERIES:-}" \
      DIGEST_SHA256="$digest_sha256" \
      python3 - <<'PY'
import json
import os
from pathlib import Path

stage = Path(os.environ["STAGE"])
manifest = {
    "schema_version": 1,
    "bundle_protocol": 1,
    "installer_series": os.environ["SERIES"],
    "installer_version": os.environ["VER"],
    "application_version": os.environ["VER"],
    "commit": os.environ["COMMIT"],
    "installer_source_commit": os.environ["INSTALLER_SOURCE_COMMIT"],
    "platform": os.environ["PLATFORM"],
    "entry_point": os.environ["ENTRY"],
    "minimum_bootstrap_protocol": 1,
    "accepted_installation_manifest_schemas": [1, 2],
    "bridge": {
        "is_bridge": os.environ["PACKAGE_KIND"] == "bridge",
        "target_series": os.environ["BRIDGE_TARGET_SERIES"] or None,
    },
    "payload_digest_file": "installer-files.sha256",
    "payload_digest_sha256": os.environ["DIGEST_SHA256"],
}
(stage / "installer-manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
}

# The verified package owns the files it later installs as privileged helpers. They live in one
# nested archive rather than in the application checkout; the outer manifest authenticates
# the archive as one payload file. The installed uninstaller therefore has no standalone public ZIP
# entry point, while installation still has local bytes from which to provision it.
build_runtime_payload() { # <output-zip> <installer-relative-file>...
    local output="$1"; shift
    ( cd "$ROOT" && zip -q -X "$output" "$@" )
}

# build_zip <platform> <entry> <zip> <readme> <runtime-zip> <file>...
build_zip() {
    local platform="$1" entry="$2" zip="$3" readme="$4" runtime="$5"; shift 5
    local stage; stage="$(mktemp -d)"
    local f
    for f in "$@"; do cp "$SRC/$f" "$stage/$(basename "$f")"; done
    cp "$runtime" "$stage/installer-runtime.zip"
    cp "$SOURCE_BUNDLE" "$stage/corpusfm.bundle"
    # One nested archive: the outer manifest authenticates
    # it as a single payload file, and `write_installer_manifest` picks it up with no special case.
    cp "$ASSETS_ZIP" "$stage/corpusfm-assets.zip"
    cp "$ASSET_MANIFEST" "$stage/assets.json"
    cp "$readme" "$stage/READ-ME-FIRST.txt"
    [[ "$PACKAGE_KIND" != bridge ]] || cp "$BRIDGE_JSON" "$stage/bridge.json"
    write_installer_manifest "$stage" "$platform" "$entry"
    ( cd "$stage" && zip -q -X "$zip" ./* && mv "$zip" "$BUILD_DIR/release/$zip" )
    local digest; digest="$(sha256_file "$BUILD_DIR/release/$zip")"
    printf '%s  %s\n' "$digest" "$zip" > "$BUILD_DIR/release/$zip.sha256"
    rm -rf "$stage"
    echo "Built $OUT_DIR/$zip"
    printf '%s  %s\n' "$digest" "$zip"
}

# A closing bridge names an already-published exact destination. Its metadata is included in each
# ZIP's digest inventory; the bootstrap never asks the destination series for `latest`.
if [[ "$PACKAGE_KIND" == bridge ]]; then
    TARGET_SERIES="${CORPUSFM_BRIDGE_TARGET_SERIES:-}"
    TARGET_VERSION="${CORPUSFM_BRIDGE_TARGET_VERSION:-}"
    [[ "$TARGET_SERIES" =~ ^series-[1-9][0-9]*$ && "$TARGET_SERIES" != "$SERIES" ]] || {
        echo "Refusing: bridge target series is invalid" >&2; exit 1;
    }
    [[ "$TARGET_VERSION" =~ ^0\.[0-9]+$ ]] || {
        echo "Refusing: bridge target version is invalid" >&2; exit 1;
    }
    TARGET_RELEASE="$DISTRIBUTION_ROOT/$TARGET_SERIES/releases/$TARGET_VERSION/release.json"
    [[ -f "$TARGET_RELEASE" ]] || { echo "Refusing: bridge destination release is absent" >&2; exit 1; }
    BRIDGE_JSON="$BUILD_DIR/bridge.json"
    SOURCE_SERIES="$SERIES" SOURCE_VERSION="$VER" SOURCE_COMMIT="$COMMIT" \
      TARGET_SERIES="$TARGET_SERIES" TARGET_VERSION="$TARGET_VERSION" TARGET_RELEASE="$TARGET_RELEASE" \
      BRIDGE_JSON="$BRIDGE_JSON" \
      python3 - <<'PY'
import json,os
from pathlib import Path
r=json.loads(Path(os.environ['TARGET_RELEASE']).read_text())
if r.get('installer_series') != os.environ['TARGET_SERIES'] or r.get('installer_version') != os.environ['TARGET_VERSION']:
    raise SystemExit('bridge destination release identity disagrees')
d={"schema_version":1,
   "source":{"series":os.environ['SOURCE_SERIES'],"version":os.environ['SOURCE_VERSION'],"commit":os.environ['SOURCE_COMMIT']},
   "target":{"series":r['installer_series'],"version":r['installer_version'],"commit":r['commit']},
   "platforms":r['platforms']}
Path(os.environ['BRIDGE_JSON']).write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
PY
fi

# A terminal uninstall can remove both the installed Python and Git immediately before retiring its
# lifecycle journal. corpusfm.bundle is not enough in that state on Windows because opening a Git
# bundle itself requires the MinGit that was just removed. Carry the exact verified application
# package a second time as a digest-covered recovery source archive. It is executable only
# with the temporary checksum-pinned interpreter prepared by the platform installer and is never
# deployed as application source.
RECOVERY_SOURCE_ARCHIVE="$BUILD_DIR/corpusfm-recovery-source.zip"
( cd "$APP_MATERIALIZED" && zip -q -r -X "$RECOVERY_SOURCE_ARCHIVE" corpusfm \
    -x '*/__pycache__/*' '*.pyc' '*.pyo' )

# ── Linux bundle ──────────────────────────────────────────────────────────────
LINUX_README="$(mktemp)"
cat > "$LINUX_README" <<TXT
CORPUSfm installer $VER  (Linux)

RECOMMENDATION: install on a DEVELOPMENT or STAGING FileMaker Server, not your production server.
Applying the reverse proxy RESTARTS the FMS web server — a few-second interruption of WebDirect, the
Data & OData APIs, and the Admin Console (FileMaker Pro clients on fmnet are unaffected). Uninstall
restarts it too. Plan a maintenance window if you must run it on a live box.

Run ON the co-located FileMaker Server box (Ubuntu, FM 21+), as a user with sudo:

    sudo bash install.sh

That is all. Series 2 installs and re-runs use only this verified package and install to
/opt/CORPUSfm/.
Non-interactive: set FM_ADMIN_USER, FM_ADMIN_PASS, CORPUSFM_ADMIN_USER and CORPUSFM_ADMIN_PASS,
then name all fresh-install locations explicitly:
    sudo -E bash install.sh --silent --yes \\
      --install-dir /opt/CORPUSfm \\
      --fms-root "/opt/FileMaker/FileMaker Server" \\
      --patch-hosting-dir /opt/CORPUSfm-Hosted
An existing published installation supplies its recorded locations, so those three path options may
be omitted when re-running the package on that installation.
Keep every extracted file together. The verified bundle carries both its application source and
its installer runtime. Public acquisition and updates are anonymous; no GitHub credential is used.
After a successful install, the installed bootstrap is the durable entry point.
TXT
LINUX_RUNTIME="$BUILD_DIR/linux-installer-runtime.zip"
build_runtime_payload "$LINUX_RUNTIME" \
    installer/requirements-server.txt installer/constraints-server-py313.txt \
    installer/linux/_cfm_lib.sh installer/linux/cfm-db-helper.sh \
    installer/linux/cfm-proxy-exec.sh installer/linux/cfm-web-proxy.sh \
    installer/linux/corpusfm-proxy.sh installer/linux/corpusfm-recovery.sh \
    installer/linux/corpusfm-update.sh installer/linux/uninstall.sh \
    installer/bootstrap/linux/bootstrap.sh
zip -q -j "$LINUX_RUNTIME" "$RECOVERY_SOURCE_ARCHIVE"
if [[ "$PACKAGE_KIND" == exercise ]]; then
    build_zip linux install.sh "corpusfm-installer-linux-$VER.zip" "$LINUX_README" "$LINUX_RUNTIME" bridge-exercise/linux/install.sh linux/cfm-verify-installer-bundle.sh linux/cfm-verify-bootstrap-handoff.sh
elif [[ "$PACKAGE_KIND" == bridge ]]; then
    build_zip linux install.sh "corpusfm-installer-linux-$VER.zip" "$LINUX_README" "$LINUX_RUNTIME" linux/install.sh linux/_cfm_lib.sh linux/cfm-verify-installer-bundle.sh linux/cfm-verify-bootstrap-handoff.sh
else
    build_zip linux install.sh "corpusfm-installer-linux-$VER.zip" "$LINUX_README" "$LINUX_RUNTIME" linux/install.sh linux/_cfm_lib.sh linux/cfm-verify-installer-bundle.sh linux/cfm-verify-bootstrap-handoff.sh
fi
rm -f "$LINUX_README"

echo
# ── Windows bundle ──────────────────────────────────────────────────────────────
WIN_README="$(mktemp)"
cat > "$WIN_README" <<TXT
CORPUSfm installer $VER  (Windows)

RECOMMENDATION: install on a DEVELOPMENT or STAGING FileMaker Server, not your production server.
Installation is invasive on the FMS box (deploys a database, registers services, mounts an IIS app).
The isolated IIS application avoids an FMS web-server restart, but install on a live production
server only with care and a maintenance window.

Run ON the co-located FileMaker Server box (Windows Server, FMS 2024/2025, FM 21+),
from an ELEVATED PowerShell (Run as Administrator):

    powershell -ExecutionPolicy Bypass -File install.ps1

That is all. Series 2 installs and re-runs use only this verified package and install to
C:\\Program Files\\CORPUSfm.
Non-interactive: set FM_ADMIN_USER, FM_ADMIN_PASS, CORPUSFM_ADMIN_USER and CORPUSFM_ADMIN_PASS,
then run: powershell -ExecutionPolicy Bypass -File install.ps1 -Silent -Yes
Keep every extracted file together. The verified bundle carries both its application source and
its installer runtime. Public acquisition and updates are anonymous; no GitHub credential is used.
After a successful install, the installed bootstrap is the durable entry point.
TXT
WINDOWS_RUNTIME="$BUILD_DIR/windows-installer-runtime.zip"
build_runtime_payload "$WINDOWS_RUNTIME" \
    installer/requirements-server.txt installer/constraints-server-win-py313.txt \
    installer/windows/_cfm_lib.ps1 installer/windows/cfm-proxy-exec.ps1 \
    installer/windows/corpusfm-proxy.ps1 \
    installer/windows/corpusfm-recovery.ps1 installer/windows/corpusfm-update.ps1 \
    installer/windows/uninstall.ps1 installer/bootstrap/windows/bootstrap.ps1
zip -q -j "$WINDOWS_RUNTIME" "$RECOVERY_SOURCE_ARCHIVE"
if [[ "$PACKAGE_KIND" == exercise ]]; then
    build_zip windows install.ps1 "corpusfm-installer-windows-$VER.zip" "$WIN_README" "$WINDOWS_RUNTIME" bridge-exercise/windows/install.ps1 windows/cfm-verify-installer-bundle.ps1 windows/cfm-verify-bootstrap-handoff.ps1
elif [[ "$PACKAGE_KIND" == bridge ]]; then
    build_zip windows install.ps1 "corpusfm-installer-windows-$VER.zip" "$WIN_README" "$WINDOWS_RUNTIME" windows/install.ps1 windows/_cfm_lib.ps1 windows/cfm-verify-installer-bundle.ps1 windows/cfm-verify-bootstrap-handoff.ps1
else
    build_zip windows install.ps1 "corpusfm-installer-windows-$VER.zip" "$WIN_README" "$WINDOWS_RUNTIME" windows/install.ps1 windows/_cfm_lib.ps1 windows/cfm-verify-installer-bundle.ps1 windows/cfm-verify-bootstrap-handoff.ps1
fi
rm -f "$WIN_README"

RELEASE_DIR="$BUILD_DIR/release" SERIES="$SERIES" VER="$VER" COMMIT="$COMMIT" \
  INSTALLER_SOURCE_COMMIT="$INSTALLER_SOURCE_COMMIT" \
  PACKAGE_KIND="$PACKAGE_KIND" BRIDGE_TARGET_SERIES="${CORPUSFM_BRIDGE_TARGET_SERIES:-}" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

release_dir = Path(os.environ["RELEASE_DIR"])
platforms = {}
for platform in ("linux", "windows"):
    name = f"corpusfm-installer-{platform}-{os.environ['VER']}.zip"
    path = release_dir / name
    platforms[platform] = {
        "file": name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
release = {
    "schema_version": 1,
    "installer_series": os.environ["SERIES"],
    "installer_version": os.environ["VER"],
    "application_version": os.environ["VER"],
    "commit": os.environ["COMMIT"],
    "installer_source_commit": os.environ["INSTALLER_SOURCE_COMMIT"],
    "bridge": {"is_bridge": os.environ["PACKAGE_KIND"] == "bridge",
               "target_series": os.environ["BRIDGE_TARGET_SERIES"] or None},
    "platforms": platforms,
}
(release_dir / "release.json").write_text(
    json.dumps(release, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

mkdir -p "$SERIES_DIR/releases"
mv "$BUILD_DIR/release" "$OUT_DIR"
SERIES_DIR="$SERIES_DIR" SERIES="$SERIES" VER="$VER" COMMIT="$COMMIT" \
  INSTALLER_SOURCE_COMMIT="$INSTALLER_SOURCE_COMMIT" python3 - <<'PY'
import json
import os
from pathlib import Path

latest = {
    "schema_version": 1,
    "installer_series": os.environ["SERIES"],
    "installer_version": os.environ["VER"],
    "commit": os.environ["COMMIT"],
    "installer_source_commit": os.environ["INSTALLER_SOURCE_COMMIT"],
    "release_manifest": f"releases/{os.environ['VER']}/release.json",
    "release_tag": f"installer-{os.environ['SERIES']}-{os.environ['VER']}",
}
series_dir = Path(os.environ["SERIES_DIR"])
temporary = series_dir / ".latest.json.tmp"
temporary.write_text(json.dumps(latest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
temporary.replace(series_dir / "latest.json")
PY

if [[ "$PACKAGE_KIND" == bridge ]]; then
    cp "$BRIDGE_JSON" "$SERIES_DIR/bridge.json"
fi

mkdir -p "$DISTRIBUTION_ROOT/bootstrap"
cp installer/bootstrap/linux/bootstrap.sh "$DISTRIBUTION_ROOT/bootstrap/bootstrap.sh"
cp installer/bootstrap/windows/bootstrap.ps1 "$DISTRIBUTION_ROOT/bootstrap/bootstrap.ps1"
chmod 755 "$DISTRIBUTION_ROOT/bootstrap/bootstrap.sh"
printf '%s  %s\n' "$(sha256_file "$DISTRIBUTION_ROOT/bootstrap/bootstrap.sh")" bootstrap.sh \
    > "$DISTRIBUTION_ROOT/bootstrap/bootstrap.sh.sha256"
printf '%s  %s\n' "$(sha256_file "$DISTRIBUTION_ROOT/bootstrap/bootstrap.ps1")" bootstrap.ps1 \
    > "$DISTRIBUTION_ROOT/bootstrap/bootstrap.ps1.sha256"

echo "Published $SERIES_DIR/latest.json -> releases/$VER/release.json"
