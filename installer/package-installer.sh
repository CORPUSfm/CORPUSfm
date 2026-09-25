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
#
# ── THE SIGNING SEAM (packet 1380-04) ────────────────────────────────────────────────────────────
# A signed release cannot be built in one pass, because the signer is an external, manually
# dispatched workflow and "sign an earlier representation, then rewrite it" is forbidden (1380-04
# §4). So the build has a seam in the middle, and BOTH halves are this script:
#
#   --stage-signing-candidate DIR   materialize every FINAL member into DIR, write the
#                                   11-occurrence signing inventory, and STOP. Nothing is
#                                   archived yet, so nothing exists that a later signature could go
#                                   stale against.
#   --finalize-signing-candidate DIR [--signed-members DIR]
#                                   adopt the signed streams (when supplied) and only THEN build the
#                                   nested runtime ZIP, payload digest file, manifest, outer ZIP,
#                                   sidecar, release.json and latest.json.
#
# With neither flag the script runs both halves back to back against a temporary candidate, which is
# the ordinary unsigned development build and is the behaviour it has always had. That is
# deliberate: the signed path and the local path run the SAME assembly code, so every local build
# rehearses the released one instead of being a second implementation of it.
#
# Finalization takes no application checkout. The candidate carries every final byte, so the job
# that assembles a signed release holds no credential at all. Public acquisition is anonymous: no
# step of either half reads, validates or embeds a repository credential.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
    echo "Usage: $0 --application-checkout /path/to/CORPUSfm \\" >&2
    echo "          --application-commit <full-40-hex-commit> [--stage-signing-candidate <dir>]" >&2
    echo "   or: $0 --finalize-signing-candidate <dir> [--signed-members <dir>]" >&2
    exit 2
}

PHASE=all
CANDIDATE=""
SIGNED_MEMBERS=""

if [[ "${1:-}" == "--finalize-signing-candidate" ]]; then
    [[ -n "${2:-}" && -d "$2" ]] || usage
    PHASE=finalize
    CANDIDATE="$(cd "$2" && pwd)"
    if [[ $# -eq 4 ]]; then
        [[ "${3:-}" == "--signed-members" && -n "${4:-}" && -d "$4" ]] || usage
        SIGNED_MEMBERS="$(cd "$4" && pwd)"
    elif [[ $# -ne 2 ]]; then
        usage
    fi
else
    # --application-commit is REQUIRED and must be a full 40-hex object id (packet 1257). The package
    # is built from a clean materialization of exactly that commit, never from the caller's working
    # tree: a builder that reads a working tree ships whatever happens to be checked out, which
    # would let uncommitted bytes - source or asset - reach a package.
    [[ "${1:-}" == "--application-checkout" && -n "${2:-}" \
       && "${3:-}" == "--application-commit" && -n "${4:-}" ]] || usage
    if [[ $# -eq 6 ]]; then
        [[ "${5:-}" == "--stage-signing-candidate" && -n "${6:-}" ]] || usage
        PHASE=stage
        mkdir -p "$6"
        CANDIDATE="$(cd "$6" && pwd)"
        [[ -z "$(ls -A "$CANDIDATE")" ]] || {
            echo "Refusing: the signing candidate directory $CANDIDATE is not empty" >&2; exit 1; }
    elif [[ $# -ne 4 ]]; then
        usage
    fi
    APP_ROOT="$(cd "$2" && pwd)"
    APP_COMMIT_ARG="$4"
    [[ "$APP_COMMIT_ARG" =~ ^[0-9a-f]{40}$ ]] || {
        echo "Refusing: --application-commit must be a full 40-hex commit id, got $APP_COMMIT_ARG" >&2
        exit 1
    }
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

BUILD_DIR="$(mktemp -d)"
SOURCE_BUNDLE=""
APP_MATERIALIZED=""
OWN_CANDIDATE=""
cleanup() {
    rm -rf "$BUILD_DIR" "${APP_MATERIALIZED:-}" "${OWN_CANDIDATE:-}"
    rm -f "${SOURCE_BUNDLE:-}"
}
trap cleanup EXIT

# The whole Windows outer/runtime layout the signing inventory addresses. Kept here, once, so the
# materializer and the finalizer cannot drift apart about where a member lives.
WINDOWS_RUNTIME_MEMBERS=(
    installer/requirements-server.txt
    installer/constraints-server-win-py313.txt
    installer/windows/_cfm_lib.ps1
    installer/windows/cfm-proxy-exec.ps1
    installer/windows/corpusfm-proxy.ps1
    installer/windows/corpusfm-recovery.ps1
    installer/windows/corpusfm-update.ps1
    installer/windows/uninstall.ps1
    installer/bootstrap/windows/bootstrap.ps1
)
LINUX_RUNTIME_MEMBERS=(
    installer/requirements-server.txt
    installer/constraints-server-py313.txt
    installer/linux/_cfm_lib.sh
    installer/linux/cfm-db-helper.sh
    installer/linux/cfm-proxy-exec.sh
    installer/linux/cfm-web-proxy.sh
    installer/linux/corpusfm-proxy.sh
    installer/linux/corpusfm-recovery.sh
    installer/linux/corpusfm-update.sh
    installer/linux/uninstall.sh
    installer/bootstrap/linux/bootstrap.sh
)

# ══ MATERIALIZE ════════════════════════════════════════════════════════════════════════════════
if [[ "$PHASE" != finalize ]]; then

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
BRIDGE_TARGET_SERIES="${CORPUSFM_BRIDGE_TARGET_SERIES:-}"
DISTRIBUTION_ROOT="outputs/server"
SERIES_DIR="$DISTRIBUTION_ROOT/$SERIES"
OUT_DIR="$SERIES_DIR/releases/$VER"
SRC="installer"
SOURCE_BUNDLE="$(mktemp)"

if [[ "$PHASE" == all ]]; then
    OWN_CANDIDATE="$(mktemp -d)"
    CANDIDATE="$OWN_CANDIDATE"
fi

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

# ── Series 2 asset payload ───────────────────────────────────────────────────────────────────
# THE ASSETS ARE APPLICATION CONTENT. They are tracked at `assets/` in the application repository,
# so they arrive with the SAME clean materialization of the SAME pinned commit that already supplies
# the source tree, the Git bundle and the version. One commit selects the whole product. There is no
# second repository, no second pin, no sibling checkout and no second credential — and because the
# caller's working tree is never read, an asset cannot be packaged that is not committed.
#
# The assets therefore travel TWICE, on purpose: inside the application Git bundle as tracked source
# (`src/assets/` on the installed box) and again as this separate digest-covered payload, which is
# the operational copy placed at `<install root>/assets`. The duplication is accepted for now; the
# installer runtime still clones nothing, so an installed box receives bytes, never a remote.
ASSET_SOURCE_DIR="$APP_MATERIALIZED/assets"
ASSETS_ZIP="$BUILD_DIR/corpusfm-assets.zip"

[[ -d "$ASSET_SOURCE_DIR" ]] || {
    echo "Refusing: the pinned application materialization $COMMIT carries no assets/ directory" >&2
    exit 1
}

ASSET_SOURCE_DIR="$ASSET_SOURCE_DIR" APPLICATION_COMMIT="$COMMIT" \
ASSETS_ZIP="$ASSETS_ZIP" BUILD_DIR="$BUILD_DIR" python3 "$ROOT/installer/build-asset-payload.py"

ASSET_MANIFEST="$BUILD_DIR/assets.json"
[[ -s "$ASSETS_ZIP" && -s "$ASSET_MANIFEST" ]] || {
    echo "Refusing: the Series 2 asset payload was not produced" >&2; exit 1; }

# A closing bridge names an already-published exact destination. Its metadata is included in each
# ZIP's digest inventory; the bootstrap never asks the destination series for `latest`.
if [[ "$PACKAGE_KIND" == bridge ]]; then
    TARGET_SERIES="$BRIDGE_TARGET_SERIES"
    TARGET_VERSION="${CORPUSFM_BRIDGE_TARGET_VERSION:-}"
    [[ "$TARGET_SERIES" =~ ^series-[1-9][0-9]*$ && "$TARGET_SERIES" != "$SERIES" ]] || {
        echo "Refusing: bridge target series is invalid" >&2; exit 1;
    }
    [[ "$TARGET_VERSION" =~ ^0\.[0-9]+$ ]] || {
        echo "Refusing: bridge target version is invalid" >&2; exit 1;
    }
    TARGET_RELEASE="$DISTRIBUTION_ROOT/$TARGET_SERIES/releases/$TARGET_VERSION/release.json"
    [[ -f "$TARGET_RELEASE" ]] || { echo "Refusing: bridge destination release is absent" >&2; exit 1; }
    BRIDGE_JSON="$CANDIDATE/bridge.json"
    mkdir -p "$CANDIDATE"
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
mkdir -p "$CANDIDATE/payload"
python3 "$ROOT/installer/zip_deterministic.py" "$CANDIDATE/payload/corpusfm-recovery-source.zip" \
    --base "$APP_MATERIALIZED" --tree corpusfm \
    --exclude-dir __pycache__ --exclude-suffix .pyc --exclude-suffix .pyo
cp "$SOURCE_BUNDLE" "$CANDIDATE/payload/corpusfm.bundle"
cp "$ASSETS_ZIP" "$CANDIDATE/payload/corpusfm-assets.zip"
cp "$ASSET_MANIFEST" "$CANDIDATE/payload/assets.json"

# stage_platform <platform> <entry-point> <readme-file> <outer-source-file>...
stage_platform() {
    local platform="$1" entry="$2" readme="$3"; shift 3
    local outer="$CANDIDATE/$platform/outer" runtime="$CANDIDATE/$platform/runtime"
    local f members=()
    mkdir -p "$outer" "$runtime"
    for f in "$@"; do cp -p "$SRC/$f" "$outer/$(basename "$f")"; done
    cp "$readme" "$outer/READ-ME-FIRST.txt"
    [[ "$PACKAGE_KIND" != bridge ]] || cp "$BRIDGE_JSON" "$outer/bridge.json"
    if [[ "$platform" == windows ]]; then members=("${WINDOWS_RUNTIME_MEMBERS[@]}")
    else members=("${LINUX_RUNTIME_MEMBERS[@]}"); fi
    for f in "${members[@]}"; do
        mkdir -p "$runtime/$(dirname "$f")"
        cp -p "$f" "$runtime/$f"
    done
}

LINUX_README="$BUILD_DIR/linux-readme.txt"
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

WIN_README="$BUILD_DIR/windows-readme.txt"
cat > "$WIN_README" <<TXT
CORPUSfm installer $VER  (Windows)

RECOMMENDATION: install on a DEVELOPMENT or STAGING FileMaker Server, not your production server.
Installation is invasive on the FMS box (deploys a database, registers services, mounts an IIS app).
The isolated IIS application avoids an FMS web-server restart, but install on a live production
server only with care and a maintenance window.

Run ON the co-located FileMaker Server box (Windows Server, FMS 2024/2025, FM 21+),
from an ELEVATED PowerShell (Run as Administrator):

    powershell -File install.ps1

That is all. Series 2 installs and re-runs use only this verified package and install to
C:\\Program Files\\CORPUSfm.
Non-interactive: set FM_ADMIN_USER, FM_ADMIN_PASS, CORPUSFM_ADMIN_USER and CORPUSFM_ADMIN_PASS,
then run: powershell -File install.ps1 -Silent -Yes
Keep every extracted file together. The verified bundle carries both its application source and
its installer runtime. Public acquisition and updates are anonymous; no GitHub credential is used.
After a successful install, the installed bootstrap is the durable entry point.
TXT

if [[ "$PACKAGE_KIND" == exercise ]]; then
    stage_platform linux install.sh "$LINUX_README" \
        bridge-exercise/linux/install.sh linux/cfm-verify-installer-bundle.sh \
        linux/cfm-verify-bootstrap-handoff.sh
    stage_platform windows install.ps1 "$WIN_README" \
        bridge-exercise/windows/install.ps1 windows/cfm-verify-installer-bundle.ps1 \
        windows/cfm-verify-bootstrap-handoff.ps1
else
    stage_platform linux install.sh "$LINUX_README" \
        linux/install.sh linux/_cfm_lib.sh linux/cfm-verify-installer-bundle.sh \
        linux/cfm-verify-bootstrap-handoff.sh
    stage_platform windows install.ps1 "$WIN_README" \
        windows/install.ps1 windows/_cfm_lib.ps1 windows/cfm-verify-installer-bundle.ps1 \
        windows/cfm-verify-bootstrap-handoff.ps1
fi

# NO STANDALONE BOOTSTRAP (public decision D14). The public release publishes no bootstrap outside
# its ZIPs, so none is materialized, signed or written beside the release. The bootstrap each package
# carries in its runtime archive - and the signed copy an installation keeps - is unaffected.

CANDIDATE="$CANDIDATE" SERIES="$SERIES" VER="$VER" COMMIT="$COMMIT" \
  INSTALLER_SOURCE_COMMIT="$INSTALLER_SOURCE_COMMIT" PACKAGE_KIND="$PACKAGE_KIND" \
  BRIDGE_TARGET_SERIES="$BRIDGE_TARGET_SERIES" \
  WINDOWS_RUNTIME_MEMBERS="$(printf '%s\n' "${WINDOWS_RUNTIME_MEMBERS[@]}")" \
  LINUX_RUNTIME_MEMBERS="$(printf '%s\n' "${LINUX_RUNTIME_MEMBERS[@]}")" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

def executables(root):
    """Relative paths under `root` that carry the executable bit RIGHT NOW.

    Read at staging time on purpose: the candidate is staged from a clean checkout, so these are
    the modes git records. By finalization the candidate may have crossed GitHub Actions artifact
    storage, which does not preserve the executable bit - so the mode has to be written down while
    it is still true, and restored from this record rather than inherited from the extraction.
    """
    base = Path(root)
    if not base.is_dir():
        return []
    return sorted(
        q.relative_to(base).as_posix()
        for q in base.rglob("*")
        if q.is_file() and os.access(q, os.X_OK)
    )


candidate = {
    "schema_version": 1,
    "installer_series": os.environ["SERIES"],
    "installer_version": os.environ["VER"],
    "commit": os.environ["COMMIT"],
    "installer_source_commit": os.environ["INSTALLER_SOURCE_COMMIT"],
    "package_kind": os.environ["PACKAGE_KIND"],
    "bridge_target_series": os.environ["BRIDGE_TARGET_SERIES"] or None,
    "platforms": {
        "linux": {
            "entry_point": "install.sh",
            "zip": f"corpusfm-installer-linux-{os.environ['VER']}.zip",
            "runtime_members": os.environ["LINUX_RUNTIME_MEMBERS"].split(),
            "executable_outer": executables(Path(os.environ["CANDIDATE"], "linux", "outer")),
            "executable_runtime": executables(Path(os.environ["CANDIDATE"], "linux", "runtime")),
        },
        "windows": {
            "entry_point": "install.ps1",
            "zip": f"corpusfm-installer-windows-{os.environ['VER']}.zip",
            "runtime_members": os.environ["WINDOWS_RUNTIME_MEMBERS"].split(),
            "executable_outer": executables(Path(os.environ["CANDIDATE"], "windows", "outer")),
            "executable_runtime": executables(Path(os.environ["CANDIDATE"], "windows", "runtime")),
        },
    },
}
Path(os.environ["CANDIDATE"], "candidate.json").write_text(
    json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

python3 "$ROOT/installer/windows_signing.py" stage --candidate "$CANDIDATE"

if [[ "$PHASE" == stage ]]; then
    echo "Staged signing candidate for $SERIES $VER at $CANDIDATE"
    exit 0
fi

fi  # ── end MATERIALIZE ──────────────────────────────────────────────────────────────────────────

# ══ FINALIZE ═══════════════════════════════════════════════════════════════════════════════════
if [[ "$PHASE" == finalize ]]; then
    CANDIDATE_ENV="$BUILD_DIR/candidate.env"
    CANDIDATE="$CANDIDATE" CANDIDATE_ENV="$CANDIDATE_ENV" python3 - <<'PY'
import json
import os
import shlex
from pathlib import Path

candidate = json.loads(Path(os.environ["CANDIDATE"], "candidate.json").read_text())
if candidate.get("schema_version") != 1:
    raise SystemExit("the signing candidate is not schema 1")
lines = []
for name, key in (("SERIES", "installer_series"), ("VER", "installer_version"),
                  ("COMMIT", "commit"), ("INSTALLER_SOURCE_COMMIT", "installer_source_commit"),
                  ("PACKAGE_KIND", "package_kind")):
    lines.append(f"{name}={shlex.quote(str(candidate[key]))}")
lines.append(f"BRIDGE_TARGET_SERIES={shlex.quote(candidate['bridge_target_series'] or '')}")
Path(os.environ["CANDIDATE_ENV"]).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    # shellcheck disable=SC1090
    . "$CANDIDATE_ENV"
    DISTRIBUTION_ROOT="outputs/server"
    SERIES_DIR="$DISTRIBUTION_ROOT/$SERIES"
    OUT_DIR="$SERIES_DIR/releases/$VER"
    BRIDGE_JSON="$CANDIDATE/bridge.json"
    [[ ! -e "$SERIES_DIR/bridge.json" ]] || {
        echo "Refusing: $SERIES is permanently closed by $SERIES_DIR/bridge.json" >&2; exit 1; }
    [[ ! -e "$OUT_DIR" ]] || {
        echo "Refusing: immutable installer release already exists at $OUT_DIR" >&2; exit 1; }
fi

# THE CANDIDATE'S OWN RECORDS ARE PROVED FIRST. `candidate.json` decides which shipped members get
# mode 0755, so it is an authority and is sealed by the staging digest like everything else the
# signer must not touch. This runs on BOTH paths, because the unsigned development build never calls
# `adopt` and would otherwise read an unverified record.
python3 "$ROOT/installer/windows_signing.py" assert-records-sealed --candidate "$CANDIDATE"

# The signed streams replace every occurrence of themselves BEFORE any archive exists. `adopt`
# refuses a body that changed outside its signature block and refuses any candidate content outside
# the inventory that moved, so "the immutable release assets are the exact bytes that were signed"
# is established here rather than asserted later.
if [[ -n "$SIGNED_MEMBERS" ]]; then
    python3 "$ROOT/installer/windows_signing.py" adopt \
        --candidate "$CANDIDATE" --signed "$SIGNED_MEMBERS"
fi

mkdir -p "$BUILD_DIR/release"

# The nested runtime's member list is the one the candidate RECORDED, read back here so that
# finalization cannot quietly ship a file the staging phase never saw or drop one it did.
CANDIDATE="$CANDIDATE" BUILD_DIR="$BUILD_DIR" python3 - <<'PY'
import json
import os
from pathlib import Path

candidate = Path(os.environ["CANDIDATE"])
build = Path(os.environ["BUILD_DIR"])
recorded = json.loads((candidate / "candidate.json").read_text())["platforms"]
for platform, facts in recorded.items():
    members = list(facts["runtime_members"])
    tree = candidate / platform / "runtime"
    present = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file())
    if sorted(members) != present:
        raise SystemExit(
            f"the {platform} runtime tree does not match the recorded member list "
            f"(missing: {sorted(set(members) - set(present))}; "
            f"unexpected: {sorted(set(present) - set(members))})"
        )
    (build / f"{platform}-runtime-members.txt").write_text(
        "\n".join(members) + "\n", encoding="utf-8"
    )
    # The executable bit, written down at staging and restored at assembly. GitHub Actions artifact
    # storage does not preserve it, so by the time finalization runs the candidate's modes are all
    # 0644 - inheriting them ships a package whose verifier the installed bootstrap refuses.
    #
    # Each entry is validated before it becomes a chmod target. The record is sealed, so this is not
    # a second integrity check: it is a shape check, so that a malformed or stale record fails here
    # rather than turning into a path operation outside the tree it names.
    for slot, sub in (("executable_outer", "outer"), ("executable_runtime", "runtime")):
        entries = list(facts.get(slot, []))
        if len(set(entries)) != len(entries):
            duplicates = sorted({e for e in entries if entries.count(e) > 1})
            raise SystemExit(f"Refusing: {platform}.{slot} repeats {duplicates}")
        tree = candidate / platform / sub
        for entry in entries:
            if not entry or entry.startswith("/") or "\\" in entry:
                raise SystemExit(f"Refusing: {platform}.{slot} entry {entry!r} is not a safe "
                                 "relative POSIX path")
            parts = entry.split("/")
            if any(part in ("", ".", "..") for part in parts):
                raise SystemExit(f"Refusing: {platform}.{slot} entry {entry!r} has an empty, "
                                 "'.' or '..' component")
            target = tree / entry
            if not target.is_file() or target.is_symlink():
                raise SystemExit(f"Refusing: {platform}.{slot} entry {entry!r} does not name a "
                                 f"present regular member of {platform}/{sub}")
        (build / f"{platform}-{slot.replace('_', '-')}.txt").write_text(
            "\n".join(entries) + "\n", encoding="utf-8"
        )
PY

# THE ASSET PAYLOAD IS THE ONE THE CANDIDATE RECORDED, and it belongs to the candidate's own
# application commit. Finalization does not re-read `assets/` — the materialization is long gone by
# then — so the only honest check available here is the one the staging phase wrote down: every
# recorded payload entry is present, the archive still hashes to its recorded digest, and the
# provenance names the same commit `candidate.json` names. A payload that was swapped, truncated or
# rebuilt from a different materialization between the two halves fails here instead of shipping.
CANDIDATE="$CANDIDATE" python3 - <<'PY'
import hashlib
import json
import os
import zipfile
from pathlib import Path

candidate = Path(os.environ["CANDIDATE"])
assets_zip = candidate / "payload" / "corpusfm-assets.zip"
manifest = json.loads((candidate / "payload" / "assets.json").read_text())
recorded_commit = json.loads((candidate / "candidate.json").read_text())["commit"]

if manifest.get("schema_version") != 2:
    raise SystemExit("Refusing: the asset manifest is not schema 2")

provenance = manifest["provenance"]
if provenance.get("application_commit") != recorded_commit:
    raise SystemExit(
        f"Refusing: the asset payload was built from application commit "
        f"{provenance.get('application_commit')}, but this candidate is {recorded_commit}"
    )

digest = hashlib.sha256(assets_zip.read_bytes()).hexdigest()
if digest != manifest["payload_sha256"]:
    raise SystemExit(
        f"Refusing: the asset payload changed after staging "
        f"(recorded {manifest['payload_sha256']}, found {digest})"
    )

with zipfile.ZipFile(assets_zip) as z:
    present = set(z.namelist())
missing = sorted(set(manifest["payload_digests"]) - present)
unexpected = sorted(present - set(manifest["payload_digests"]))
if missing or unexpected:
    raise SystemExit(
        f"Refusing: the asset payload does not match its manifest "
        f"(missing: {missing}; unexpected: {unexpected})"
    )
desktop = sorted(name for name in present if Path(name).name == ".DS_Store")
if desktop:
    raise SystemExit(f"Refusing: desktop state was packaged into the asset payload: {desktop}")
PY

write_installer_manifest() { # <stage> <platform> <entry-point>
    local stage="$1" platform="$2" entry="$3"
    local digest_file="$stage/installer-files.sha256"
    : > "$digest_file"
    local payload
    # C-ORDERED, so the digest file (and therefore the manifest that covers it) does not depend on
    # the builder's locale collation. Everything else about these archives is normalized too.
    while IFS= read -r payload; do
        [[ -f "$payload" && "$(basename "$payload")" != installer-files.sha256 ]] || continue
        printf '%s  %s\n' "$(sha256_file "$payload")" "$(basename "$payload")" >> "$digest_file"
    done < <(printf '%s\n' "$stage"/* | LC_ALL=C sort)
    local digest_sha256; digest_sha256="$(sha256_file "$digest_file")"
    STAGE="$stage" PLATFORM="$platform" ENTRY="$entry" SERIES="$SERIES" VER="$VER" COMMIT="$COMMIT" \
      INSTALLER_SOURCE_COMMIT="$INSTALLER_SOURCE_COMMIT" \
      PACKAGE_KIND="$PACKAGE_KIND" BRIDGE_TARGET_SERIES="${BRIDGE_TARGET_SERIES:-}" \
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
#
# THE MEMBER LIST COMES FROM THE CANDIDATE, not from the repository. Re-reading the repository here
# would let a working tree that moved between staging and finalization contribute bytes nobody
# signed — which is precisely the rewrite 1380-04 §4 forbids.
# restore_modes <tree> <list-file>  -- chmod 755 exactly the recorded relative paths.
# It refuses a recorded path that is missing rather than skipping it: a member that was executable
# at staging and is absent at assembly is a broken candidate, not a mode question.
restore_modes() {
    local tree="$1" list="$2" rel
    [[ -f "$list" ]] || { echo "Refusing: $list was not written by finalization" >&2; exit 1; }
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        [[ -f "$tree/$rel" ]] || {
            echo "Refusing: $rel was executable at staging but is absent from $tree" >&2; exit 1; }
        chmod 755 "$tree/$rel"
    done < "$list"
}

build_platform() { # <platform> <entry>
    local platform="$1" entry="$2"
    local outer="$CANDIDATE/$platform/outer" runtime_tree="$CANDIDATE/$platform/runtime"
    local zip_name; zip_name="corpusfm-installer-$platform-$VER.zip"
    local stage; stage="$(mktemp -d)"
    local runtime_zip="$BUILD_DIR/$platform-installer-runtime.zip"
    local members=() member

    while IFS= read -r member; do
        [[ -z "$member" ]] || members+=("$member")
    done < "$BUILD_DIR/$platform-runtime-members.txt"
    [[ ${#members[@]} -gt 0 ]] || { echo "Refusing: the candidate carries no $platform runtime" >&2; exit 1; }

    # THE EXECUTABLE BIT IS STATED HERE, NOT INHERITED. The candidate reached this job through
    # artifact storage, which flattens every mode to 0644. Restoring exactly the members that were
    # executable at staging keeps `uninstall.sh`, `cfm-proxy-exec.sh` and the rest runnable, and
    # leaves the deliberately non-executable ones (`_cfm_lib.sh`, `cfm-verify-installer-bundle.sh`,
    # both of which are invoked through `bash`) at 0644.
    restore_modes "$runtime_tree" "$BUILD_DIR/$platform-executable-runtime.txt"

    # DETERMINISTIC, because signing rewrites these members at finalization time and `zip` would
    # record that moment: see installer/zip_deterministic.py. One call writes the whole archive, so
    # member order is the rule's, not two appends'.
    python3 "$ROOT/installer/zip_deterministic.py" "$runtime_zip" --base "$runtime_tree" \
        "${members[@]/#/--member=}" --flat "$CANDIDATE/payload/corpusfm-recovery-source.zip"

    cp -p "$outer"/* "$stage/"
    cp "$runtime_zip" "$stage/installer-runtime.zip"
    cp "$CANDIDATE/payload/corpusfm.bundle" "$stage/corpusfm.bundle"
    cp "$CANDIDATE/payload/corpusfm-assets.zip" "$stage/corpusfm-assets.zip"
    cp "$CANDIDATE/payload/assets.json" "$stage/assets.json"
    # An artifact transport may not preserve a mode bit; every POSIX mode the package needs is
    # stated rather than inherited, so the shipped modes are a decision instead of a side effect.
    # The entry point keeps its own explicit line: it is the one member whose mode is a contract
    # with whoever unzips the package by hand, not only with the installed bootstrap.
    restore_modes "$stage" "$BUILD_DIR/$platform-executable-outer.txt"
    [[ "$platform" != linux ]] || chmod 755 "$stage/$entry"
    write_installer_manifest "$stage" "$platform" "$entry"
    python3 "$ROOT/installer/zip_deterministic.py" "$BUILD_DIR/release/$zip_name" --base "$stage" --all
    local digest; digest="$(sha256_file "$BUILD_DIR/release/$zip_name")"
    printf '%s  %s\n' "$digest" "$zip_name" > "$BUILD_DIR/release/$zip_name.sha256"
    rm -rf "$stage"
    echo "Built $OUT_DIR/$zip_name"
    printf '%s  %s\n' "$digest" "$zip_name"
}

build_platform linux install.sh
echo
build_platform windows install.ps1

RELEASE_DIR="$BUILD_DIR/release" SERIES="$SERIES" VER="$VER" COMMIT="$COMMIT" \
  INSTALLER_SOURCE_COMMIT="$INSTALLER_SOURCE_COMMIT" \
  PACKAGE_KIND="$PACKAGE_KIND" BRIDGE_TARGET_SERIES="${BRIDGE_TARGET_SERIES:-}" python3 - <<'PY'
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

# THE LAST WORD BELONGS TO THE FINISHED ARCHIVES. Everything above is a claim about what was built;
# this opens the outer ZIP and the nested runtime ZIP that will actually ship and proves each of the
# eleven occurrences carries the byte stream recorded in the inventory. A build that signed correctly
# and then rewrote a member during assembly passes every earlier check and fails here.
python3 "$ROOT/installer/windows_signing.py" verify \
    --candidate "$CANDIDATE" \
    --package "$OUT_DIR/corpusfm-installer-windows-$VER.zip" \
    --report "$OUT_DIR/windows-signature-map.json"

echo "Published $SERIES_DIR/latest.json -> releases/$VER/release.json"
