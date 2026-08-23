param([Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$true)][string]$BundleDirectory)
$ErrorActionPreference = 'Stop'
function Refuse([string]$Message) { throw "Bootstrap handoff refused: $Message" }

$canonical = Join-Path ([IO.Path]::GetFullPath($BundleDirectory)) '.bootstrap-handoff.json'
if ([IO.Path]::GetFullPath($Path) -ne $canonical) { Refuse 'handoff is not canonical for this bundle' }
if (-not (Test-Path -LiteralPath $canonical -PathType Leaf)) { Refuse 'handoff is missing' }
$item = Get-Item -LiteralPath $canonical -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Refuse 'handoff is a reparse point' }
$acl = Get-Acl -LiteralPath $canonical
if (-not $acl.AreAccessRulesProtected) { Refuse 'handoff ACL still inherits' }
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowedSids = @('S-1-5-18','S-1-5-32-544',$currentSid)
foreach ($rule in $acl.Access) {
  $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if ($rule.AccessControlType -eq 'Allow' -and $sid -notin $allowedSids) {
    Refuse ('handoff grants access to ' + $sid)
  }
}
try { $handoff = Get-Content -LiteralPath $canonical -Raw | ConvertFrom-Json }
catch { Refuse ('handoff is not valid JSON: ' + $_.Exception.Message) }
$expected = @('application_version','bootstrap_protocol','bundle_protocol','bundle_sha256','commit',
  'consent','entry_point','installer_series','installer_version','nonce','platform','schema_version',
  'transcript')
$actual = @($handoff.PSObject.Properties.Name | Sort-Object)
if ((Compare-Object ($expected | Sort-Object) $actual).Count -ne 0) { Refuse 'fields do not match schema 1' }
if ($handoff.schema_version -ne 1 -or $handoff.bootstrap_protocol -ne 1 -or
    $handoff.bundle_protocol -ne 1) { Refuse 'protocol fields are unsupported' }
if ($handoff.installer_series -notmatch '^series-[1-9][0-9]*$' -or
    $handoff.installer_version -notmatch '^0\.[0-9]+$' -or
    $handoff.application_version -notmatch '^0\.[0-9]+$') { Refuse 'identity is invalid' }
if ($handoff.commit -notmatch '^[0-9a-f]{40}$' -or
    $handoff.bundle_sha256 -notmatch '^[0-9a-f]{64}$') { Refuse 'digest or commit is invalid' }
if ($handoff.platform -ne 'windows' -or $handoff.entry_point -ne 'install.ps1') {
  Refuse 'platform entry point disagrees'
}
if ($handoff.consent -notin @('interactive','yes','silent')) { Refuse 'consent mode is invalid' }
if ($handoff.nonce -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') {
  Refuse 'nonce is not a version-4 UUID'
}
$expectedLogRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'CORPUSfm\logs'))
$actualLog = [IO.Path]::GetFullPath([string]$handoff.transcript)
if (-not $actualLog.StartsWith($expectedLogRoot + [IO.Path]::DirectorySeparatorChar,
                              [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($actualLog) -notmatch '^bootstrap-install-[0-9]{8}-[0-9]{6}\.log$') {
  Refuse 'transcript is not canonical'
}
[pscustomobject]@{
  InstallerSeries=[string]$handoff.installer_series
  InstallerVersion=[string]$handoff.installer_version
  ApplicationVersion=[string]$handoff.application_version
  Commit=[string]$handoff.commit
  Transcript=$actualLog
  Consent=[string]$handoff.consent
}
