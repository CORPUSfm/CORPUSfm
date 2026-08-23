param([string]$Directory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) { throw "Installer bundle refused: $Message" }

$manifestPath = Join-Path $Directory 'installer-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
  Refuse 'installer-manifest.json is missing'
}
try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
catch { Refuse ('installer-manifest.json is not valid JSON: ' + $_.Exception.Message) }

$expectedFields = @(
  'accepted_installation_manifest_schemas', 'application_version', 'bridge', 'bundle_protocol',
  'commit', 'entry_point', 'installer_series', 'installer_source_commit', 'installer_version', 'minimum_bootstrap_protocol',
  'payload_digest_file', 'payload_digest_sha256', 'platform', 'schema_version'
)
$actualFields = @($manifest.PSObject.Properties.Name | Sort-Object)
if ((Compare-Object ($expectedFields | Sort-Object) $actualFields).Count -ne 0) {
  Refuse 'descriptor fields do not match schema 1'
}
if ($manifest.schema_version -ne 1) { Refuse 'descriptor schema is not 1' }
if ($manifest.bundle_protocol -ne 1) { Refuse 'bundle protocol is not 1' }
if ($manifest.installer_series -notmatch '^series-[1-9][0-9]*$') { Refuse 'installer_series is invalid' }
if ($manifest.installer_version -notmatch '^0\.[0-9]+$') { Refuse 'installer_version is invalid' }
if ($manifest.application_version -notmatch '^0\.[0-9]+$') { Refuse 'application_version is invalid' }
if ($manifest.commit -notmatch '^[0-9a-f]{40}$') { Refuse 'commit is not an exact SHA-1' }
if ($manifest.installer_source_commit -notmatch '^[0-9a-f]{40}$') {
  Refuse 'installer_source_commit is not an exact SHA-1'
}
if ($manifest.platform -ne 'windows') { Refuse 'descriptor platform is not windows' }
if ($manifest.entry_point -ne 'install.ps1') { Refuse 'descriptor entry point is not install.ps1' }
if ($manifest.payload_digest_file -ne 'installer-files.sha256') {
  Refuse 'payload digest file name is not canonical'
}
if ($manifest.payload_digest_sha256 -notmatch '^[0-9a-f]{64}$') {
  Refuse 'payload digest-file hash is invalid'
}

$digestPath = Join-Path $Directory $manifest.payload_digest_file
if (-not (Test-Path -LiteralPath $digestPath -PathType Leaf)) {
  Refuse ($manifest.payload_digest_file + ' is missing')
}
$digestHash = (Get-FileHash -LiteralPath $digestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($digestHash -ne $manifest.payload_digest_sha256) {
  Refuse ($manifest.payload_digest_file + ' does not agree with installer-manifest.json')
}

$seen = @{}
foreach ($line in Get-Content -LiteralPath $digestPath) {
  if ($line -notmatch '^([0-9a-f]{64})  ([^\\/]+)$') { Refuse 'payload digest inventory is malformed' }
  $expected, $name = $Matches[1], $Matches[2]
  if ($seen.ContainsKey($name)) { Refuse ('payload digest repeats ' + $name) }
  $seen[$name] = $true
  $path = Join-Path $Directory $name
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Refuse ($name + ' is missing') }
  $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { Refuse ($name + ' failed digest verification') }
}
if ($seen.Count -eq 0) { Refuse 'payload digest inventory is empty' }

[pscustomobject]@{
  InstallerSeries = [string]$manifest.installer_series
  InstallerVersion = [string]$manifest.installer_version
  ApplicationVersion = [string]$manifest.application_version
  Commit = [string]$manifest.commit
}
