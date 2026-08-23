#!/usr/bin/env bash
# Stable CORPUSfm Linux bootstrap: acquire, verify, hand off. It performs no installation work.
set -euo pipefail

BOOTSTRAP_PROTOCOL=1
SERIES=series-2
BUNDLE=""
BRIDGE_BUNDLE=""
DISTRIBUTION_BASE="${CFM_DISTRIBUTION_BASE:-}"
GITHUB_REPOSITORY="CORPUSfm/CORPUSfm"
INSTALLER_ARGS=()
die() { printf 'Bootstrap refused: %s\n' "$1" >&2; exit 2; }
sha256_file() { if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

ORIGINAL_ARGS=("$@")
if [[ $EUID -ne 0 ]]; then exec sudo -E "$0" "${ORIGINAL_ARGS[@]}"; fi
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bundle) BUNDLE="$2"; shift 2 ;;
        --bridge-bundle) BRIDGE_BUNDLE="$2"; shift 2 ;;
        --distribution-base) DISTRIBUTION_BASE="$2"; shift 2 ;;
        --series) SERIES="$2"; shift 2 ;;
        --) shift; INSTALLER_ARGS=("$@"); break ;;
        -h|--help)
            printf 'Usage: sudo bootstrap.sh [--bundle ZIP | --distribution-base URL] [--bridge-bundle ZIP] [--series series-N] -- [installer options]\n'
            exit 0 ;;
        *) die "unknown bootstrap option $1 (put installer options after --)" ;;
    esac
done
[[ "$SERIES" =~ ^series-[1-9][0-9]*$ ]] || die "series must match series-N"
[[ "$SERIES" != series-1 ]] || die "series-1 is retired historical custody, not an installation channel"
command -v python3 >/dev/null || die "python3 is required for read-only release and installation records"
command -v unzip >/dev/null || die "unzip is required to open the installer bundle"

# Existing published identity selects its own series. Schema 1 predates the current installer
# identity and is deliberately unsupported; a future transition must arrive as new incoming code.
if [[ -f /etc/corpusfm/locator.json ]]; then
    published_series="$(python3 - <<'PY'
import json
from pathlib import Path
loc=json.loads(Path('/etc/corpusfm/locator.json').read_text())
root=Path(loc['install_dir'])
manifest=json.loads((root / loc['manifest_relative_path']).read_text())
if manifest.get('installation_id') != loc.get('installation_id'):
    raise SystemExit('locator and manifest installation identities disagree')
schema=manifest.get('schema_version')
if schema == 1:
    raise SystemExit('schema-1 installations are retired and have no bootstrap route')
elif schema == 2 and (manifest.get('installer') or {}).get('series'):
    print(manifest['installer']['series'])
else:
    raise SystemExit('published installation has no routable installer series')
PY
)" || die "published installation identity is unreadable or unroutable"
    [[ "$SERIES" == "$published_series" ]] || \
        die "requested $SERIES disagrees with published $published_series"
    SERIES="$published_series"
fi

WORK="$(mktemp -d /var/tmp/corpusfm-bootstrap.XXXXXX)"
chmod 700 "$WORK"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
ZIP="$WORK/installer.zip"

if [[ -n "$BUNDLE" ]]; then
    BUNDLE="$(realpath -- "$BUNDLE")"
    [[ -f "$BUNDLE" && -f "$BUNDLE.sha256" ]] || die "local bundle or its .sha256 sidecar is missing"
    expected="$(awk 'NR==1 {print $1}' "$BUNDLE.sha256")"
    cp "$BUNDLE" "$ZIP"
else
    command -v curl >/dev/null || die "curl is required to acquire a remote bundle"
    if [[ -n "$DISTRIBUTION_BASE" ]]; then
        [[ "$DISTRIBUTION_BASE" == https://* ]] || die "--distribution-base must use HTTPS"
        base="${DISTRIBUTION_BASE%/}/$SERIES"
        curl -fsSL "$base/latest.json" -o "$WORK/latest.json"
    else
        api="https://api.github.com/repos/$GITHUB_REPOSITORY"
        curl -fsSL -H 'Accept: application/vnd.github+json' \
          "$api/releases/latest" -o "$WORK/github-release.json"
    fi
    if [[ -n "$DISTRIBUTION_BASE" ]]; then
      release_rel="$(python3 - "$WORK/latest.json" "$SERIES" <<'PY'
import json,re,sys
d=json.load(open(sys.argv[1]))
if d.get('schema_version') != 1 or d.get('installer_series') != sys.argv[2]: raise SystemExit(1)
p=d.get('release_manifest','')
if not re.fullmatch(r'releases/0\.[0-9]+/release\.json',p): raise SystemExit(1)
print(p)
PY
)" || die "latest pointer is invalid for $SERIES"
    fi
    if [[ -n "$DISTRIBUTION_BASE" ]]; then
        curl -fsSL "$base/$release_rel" -o "$WORK/release.json"
    else
        release_asset="$(python3 - "$WORK/github-release.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); hits=[a.get('browser_download_url','') for a in d.get('assets',[]) if a.get('name')=='release.json']
if len(hits)!=1: raise SystemExit(1)
print(hits[0])
PY
)" || die "public release has no unique release.json asset"
        curl -fsSL "$release_asset" -o "$WORK/release.json"
    fi
    read -r file expected < <(python3 - "$WORK/release.json" "$SERIES" <<'PY'
import json,re,sys
d=json.load(open(sys.argv[1])); s=sys.argv[2]
if d.get('schema_version') != 1 or d.get('installer_series') != s: raise SystemExit(1)
p=(d.get('platforms') or {}).get('linux') or {}; f=p.get('file',''); h=p.get('sha256','')
if not re.fullmatch(r'corpusfm-installer-linux-0\.[0-9]+\.zip',f) or not re.fullmatch(r'[0-9a-f]{64}',h): raise SystemExit(1)
print(f,h)
PY
) || die "release inventory has no valid Linux bundle"
    if [[ -n "$DISTRIBUTION_BASE" ]]; then
        release_dir="${release_rel%/release.json}"
        curl -fsSL "$base/$release_dir/$file" -o "$ZIP"
    else
        zip_asset="$(python3 - "$WORK/github-release.json" "$file" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); hits=[a.get('browser_download_url','') for a in d.get('assets',[]) if a.get('name')==sys.argv[2]]
if len(hits)!=1: raise SystemExit(1)
print(hits[0])
PY
)" || die "public release has no unique $file asset"
        curl -fsSL "$zip_asset" -o "$ZIP"
    fi
fi
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$(sha256_file "$ZIP")" == "$expected" ]] || \
    die "installer ZIP digest does not agree with the selected release"

mkdir "$WORK/bundle"; chmod 700 "$WORK/bundle"
unzip -q "$ZIP" -d "$WORK/bundle"
identity="$(bash "$WORK/bundle/cfm-verify-installer-bundle.sh" "$WORK/bundle")" || exit $?
IFS=$'\t' read -r installer_series installer_version app_version commit <<<"$identity"
[[ "$installer_series" == "$SERIES" ]] || die "verified bundle belongs to $installer_series, not $SERIES"

# A designated closing release may route to one exact incoming-series bundle. The bridge metadata
# is itself in the verified source bundle's digest inventory. An ordinary release cannot use the
# caller's bridge bundle, and a bridge cannot select target `latest`.
bridge_identity="$(python3 - "$WORK/bundle/installer-manifest.json" "$WORK/bundle/bridge.json" <<'PY'
import json,re,sys
manifest=json.load(open(sys.argv[1])); bridge=manifest.get('bridge') or {}
if not bridge.get('is_bridge'):
    print('ordinary')
    raise SystemExit(0)
if set(bridge) != {'is_bridge','target_series'} or not re.fullmatch(r'series-[1-9][0-9]*', bridge.get('target_series','')):
    raise SystemExit('bridge descriptor is invalid')
d=json.load(open(sys.argv[2]))
if set(d) != {'schema_version','source','target','platforms'} or d.get('schema_version') != 1:
    raise SystemExit('bridge.json fields are invalid')
source=d.get('source') or {}; target=d.get('target') or {}; platform=(d.get('platforms') or {}).get('linux') or {}
if set(source) != {'series','version','commit'} or set(target) != {'series','version','commit'} or set(platform) != {'file','sha256'}:
    raise SystemExit('bridge.json identity fields are invalid')
if source != {'series':manifest['installer_series'],'version':manifest['installer_version'],'commit':manifest['commit']}:
    raise SystemExit('bridge source does not agree with its bundle')
if target.get('series') != bridge['target_series'] or target['series'] == source['series']:
    raise SystemExit('bridge target series is invalid')
if not re.fullmatch(r'0\.[0-9]+',target.get('version','')) or not re.fullmatch(r'[0-9a-f]{40}',target.get('commit','')):
    raise SystemExit('bridge target identity is invalid')
if not re.fullmatch(r'corpusfm-installer-linux-0\.[0-9]+\.zip',platform.get('file','')) or not re.fullmatch(r'[0-9a-f]{64}',platform.get('sha256','')):
    raise SystemExit('bridge target Linux bundle is invalid')
print('\t'.join(('bridge',target['series'],target['version'],target['commit'],platform['file'],platform['sha256'])))
PY
)" || die "verified closing release carries invalid bridge metadata"
IFS=$'\t' read -r bridge_kind target_series target_version target_commit target_file target_sha <<<"$bridge_identity"
if [[ "$bridge_kind" == bridge ]]; then
    source_series="$installer_series"
    source_version="$installer_version"
    TARGET_ZIP="$WORK/bridge-target.zip"
    if [[ -n "$BUNDLE" ]]; then
        [[ -n "$BRIDGE_BUNDLE" ]] || die "the exact local destination bundle is required for this bridge"
        BRIDGE_BUNDLE="$(realpath -- "$BRIDGE_BUNDLE")"
        [[ -f "$BRIDGE_BUNDLE" && -f "$BRIDGE_BUNDLE.sha256" ]] || \
            die "local bridge destination bundle or its .sha256 sidecar is missing"
        sidecar_sha="$(awk 'NR==1 {print $1}' "$BRIDGE_BUNDLE.sha256")"
        [[ "$sidecar_sha" == "$target_sha" ]] || die "bridge destination sidecar disagrees with bridge.json"
        cp "$BRIDGE_BUNDLE" "$TARGET_ZIP"
    else
        target_url="${DISTRIBUTION_BASE%/}/$target_series/releases/$target_version/$target_file"
        curl -fsSL "$target_url" -o "$TARGET_ZIP"
    fi
    [[ "$(sha256_file "$TARGET_ZIP")" == "$target_sha" ]] || die "bridge destination digest disagrees"
    rm -rf -- "$WORK/bundle"
    mkdir "$WORK/bundle"; chmod 700 "$WORK/bundle"
    unzip -q "$TARGET_ZIP" -d "$WORK/bundle"
    identity="$(bash "$WORK/bundle/cfm-verify-installer-bundle.sh" "$WORK/bundle")" || exit $?
    IFS=$'\t' read -r installer_series installer_version app_version commit <<<"$identity"
    [[ "$installer_series" == "$target_series" && "$installer_version" == "$target_version" && \
       "$commit" == "$target_commit" ]] || die "verified destination does not agree with bridge.json"
    expected="$target_sha"
    export CFM_BRIDGE_FROM_SERIES="$source_series"
    printf 'Bootstrap verified permanent bridge %s / %s -> %s / %s.\n' \
        "$source_series" "$source_version" "$installer_series" "$installer_version"
elif [[ -n "$BRIDGE_BUNDLE" ]]; then
    die "--bridge-bundle was supplied to an ordinary installer release"
fi

requested_yes=false
requested_silent=false
for arg in "${INSTALLER_ARGS[@]}"; do
    [[ "$arg" == --yes ]] && requested_yes=true
    [[ "$arg" == --silent ]] && requested_silent=true
done
consent=interactive
$requested_yes && consent=yes
$requested_silent && consent=silent
LOG="/var/log/corpusfm/bootstrap-install-$(date +%Y%m%d-%H%M%S).log"
mkdir -p /var/log/corpusfm; touch "$LOG"; chmod 640 "$LOG"
nonce="$(cat /proc/sys/kernel/random/uuid)"
HANDOFF="$WORK/bundle/.bootstrap-handoff.json"
python3 - "$HANDOFF" <<PY
import json,sys
json.dump({"schema_version":1,"bootstrap_protocol":$BOOTSTRAP_PROTOCOL,"bundle_protocol":1,
"installer_series":"$installer_series","installer_version":"$installer_version",
"application_version":"$app_version","commit":"$commit","platform":"linux",
"entry_point":"install.sh","bundle_sha256":"$expected","transcript":"$LOG",
"consent":"$consent","nonce":"$nonce"},open(sys.argv[1],'w'),indent=2,sort_keys=True)
open(sys.argv[1],'a').write('\n')
PY
chmod 600 "$HANDOFF"
printf 'Bootstrap verified %s / %s. Delegating to its installer.\n' "$installer_series" "$installer_version" | tee -a "$LOG"
export CFM_BOOTSTRAP_HANDOFF="$HANDOFF" CFM_LOG="$LOG"
set +e
bash "$WORK/bundle/install.sh" "${INSTALLER_ARGS[@]}"
rc=$?
set -e
exit "$rc"
