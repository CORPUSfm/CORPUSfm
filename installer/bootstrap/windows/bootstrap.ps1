<# Stable CORPUSfm Windows bootstrap: acquire, verify, hand off. It does no installation work. #>
[CmdletBinding()]
param(
  [string]$Bundle = '',
  [string]$BridgeBundle = '',
  [string]$DistributionBase = $env:CFM_DISTRIBUTION_BASE,
  [string]$Series = 'series-2',
  [switch]$Yes,
  [switch]$Silent,
  [string[]]$InstallerArguments = @()
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$GitHubRepository = 'CORPUSfm/CORPUSfm'
function Refuse([string]$Message) {
  [Console]::Error.WriteLine('Bootstrap refused: ' + $Message)
  exit 2
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { Refuse 'run from an elevated PowerShell' }
if ($Series -notmatch '^series-[1-9][0-9]*$') { Refuse 'series must match series-N' }
if ($Series -eq 'series-1') { Refuse 'series-1 is retired historical custody, not an installation channel' }

# The Windows locator is a two-slot HKLM publication. Read only its committed slot, then require the
# manifest to agree. Schema 1 predates the current installer identity and is deliberately
# unsupported; a future transition must arrive as new incoming code.
$locatorRoot = 'HKLM:\SOFTWARE\CORPUSfm\Installation'
if (Test-Path -LiteralPath $locatorRoot) {
  $slot = (Get-ItemProperty -LiteralPath $locatorRoot -Name committed_slot -ErrorAction Stop).committed_slot
  if ($slot -notin @(0,1)) { Refuse 'published locator has no committed slot' }
  $loc = Get-ItemProperty -LiteralPath (Join-Path $locatorRoot ([string]$slot))
  $manifestPath = Join-Path ([string]$loc.install_dir) ([string]$loc.manifest_relative_path)
  try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
  catch { Refuse 'published installation manifest is unreadable' }
  if ([string]$manifest.installation_id -ne [string]$loc.installation_id) {
    Refuse 'locator and manifest installation identities disagree'
  }
  if ($manifest.schema_version -eq 1) { Refuse 'schema-1 installations are retired and have no bootstrap route' }
  elseif ($manifest.schema_version -eq 2 -and $manifest.installer.series) {
    $publishedSeries = [string]$manifest.installer.series
  } else { Refuse 'published installation has no routable installer series' }
  if ($Series -ne $publishedSeries) {
    Refuse ("requested $Series disagrees with published $publishedSeries")
  }
  $Series = $publishedSeries
}

$work = Join-Path $env:TEMP ('corpusfm-bootstrap-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$full = [Security.AccessControl.FileSystemRights]::FullControl
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$prop = [Security.AccessControl.PropagationFlags]::None
$allow = [Security.AccessControl.AccessControlType]::Allow
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins,$full,$inherit,$prop,$allow)))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,$full,$inherit,$prop,$allow)))
Set-Acl -LiteralPath $work -AclObject $acl
try {
  $zip = Join-Path $work 'installer.zip'
  if ($Bundle) {
    $Bundle = [IO.Path]::GetFullPath($Bundle)
    if (-not (Test-Path -LiteralPath $Bundle -PathType Leaf) -or
        -not (Test-Path -LiteralPath ($Bundle + '.sha256') -PathType Leaf)) {
      Refuse 'local bundle or its .sha256 sidecar is missing'
    }
    $expected = ((Get-Content -LiteralPath ($Bundle + '.sha256') -TotalCount 1) -split '\s+')[0]
    Copy-Item -LiteralPath $Bundle -Destination $zip
  } else {
    $latestPath = Join-Path $work 'latest.json'
    if ($DistributionBase) {
      if ($DistributionBase -notmatch '^https://') { Refuse 'DistributionBase must use HTTPS' }
      $base = $DistributionBase.TrimEnd('/') + '/' + $Series
      Invoke-WebRequest -UseBasicParsing -Uri ($base + '/latest.json') -OutFile $latestPath
    } else {
      $api = 'https://api.github.com/repos/' + $GitHubRepository
      $githubRelease = Invoke-RestMethod -UseBasicParsing `
        -Headers @{ Accept = 'application/vnd.github+json' } -Uri ($api + '/releases/latest')
    }
    if ($DistributionBase) {
      $latest = Get-Content -LiteralPath $latestPath -Raw | ConvertFrom-Json
      if ($latest.schema_version -ne 1 -or $latest.installer_series -ne $Series -or
          $latest.release_manifest -notmatch '^releases/0\.[0-9]+/release\.json$') {
        Refuse 'latest pointer is invalid for this series'
      }
    }
    $releasePath = Join-Path $work 'release.json'
    if ($DistributionBase) {
      Invoke-WebRequest -UseBasicParsing -Uri ($base + '/' + $latest.release_manifest) -OutFile $releasePath
    } else {
      $releaseAssets = @($githubRelease.assets | Where-Object { $_.name -eq 'release.json' })
      if ($releaseAssets.Count -ne 1) { Refuse 'public release has no unique release.json asset' }
      Invoke-WebRequest -UseBasicParsing -Uri $releaseAssets[0].browser_download_url -OutFile $releasePath
    }
    $release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
    $platform = $release.platforms.windows
    if ($release.schema_version -ne 1 -or $release.installer_series -ne $Series -or
        $platform.file -notmatch '^corpusfm-installer-windows-0\.[0-9]+\.zip$' -or
        $platform.sha256 -notmatch '^[0-9a-f]{64}$') { Refuse 'release has no valid Windows bundle' }
    $expected = [string]$platform.sha256
    if ($DistributionBase) {
      $releaseDir = ([string]$latest.release_manifest) -replace '/release\.json$',''
      Invoke-WebRequest -UseBasicParsing -Uri ($base + '/' + $releaseDir + '/' + $platform.file) -OutFile $zip
    } else {
      $zipAssets = @($githubRelease.assets | Where-Object { $_.name -eq $platform.file })
      if ($zipAssets.Count -ne 1) { Refuse ('public release has no unique ' + $platform.file + ' asset') }
      Invoke-WebRequest -UseBasicParsing -Uri $zipAssets[0].browser_download_url -OutFile $zip
    }
  }
  $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($expected -notmatch '^[0-9a-f]{64}$' -or $actual -ne $expected) {
    Refuse 'installer ZIP digest does not agree with the selected release'
  }
  $bundleDir = Join-Path $work 'bundle'; New-Item -ItemType Directory -Path $bundleDir | Out-Null
  Expand-Archive -LiteralPath $zip -DestinationPath $bundleDir
  $identity = & (Join-Path $bundleDir 'cfm-verify-installer-bundle.ps1') -Directory $bundleDir
  if ($identity.InstallerSeries -ne $Series) { Refuse 'verified bundle belongs to another series' }
  $bundleManifest = Get-Content -LiteralPath (Join-Path $bundleDir 'installer-manifest.json') -Raw | ConvertFrom-Json
  if ($bundleManifest.bridge.is_bridge -eq $true) {
    if ($bundleManifest.bridge.PSObject.Properties.Name.Count -ne 2 -or
        $bundleManifest.bridge.target_series -notmatch '^series-[1-9][0-9]*$' -or
        $bundleManifest.bridge.target_series -eq $identity.InstallerSeries) {
      Refuse 'bridge descriptor is invalid'
    }
    try { $bridge = Get-Content -LiteralPath (Join-Path $bundleDir 'bridge.json') -Raw | ConvertFrom-Json }
    catch { Refuse ('verified closing release carries invalid bridge metadata: ' + $_.Exception.Message) }
    $bridgeFields = @($bridge.PSObject.Properties.Name | Sort-Object)
    if ((Compare-Object @('platforms','schema_version','source','target') $bridgeFields).Count -ne 0 -or
        $bridge.schema_version -ne 1) { Refuse 'bridge.json fields are invalid' }
    if ($bridge.source.series -ne $identity.InstallerSeries -or
        $bridge.source.version -ne $identity.InstallerVersion -or
        $bridge.source.commit -ne $identity.Commit) { Refuse 'bridge source does not agree with its bundle' }
    if ($bridge.target.series -ne $bundleManifest.bridge.target_series -or
        $bridge.target.version -notmatch '^0\.[0-9]+$' -or
        $bridge.target.commit -notmatch '^[0-9a-f]{40}$') { Refuse 'bridge target identity is invalid' }
    $targetPlatform = $bridge.platforms.windows
    if ($targetPlatform.file -notmatch '^corpusfm-installer-windows-0\.[0-9]+\.zip$' -or
        $targetPlatform.sha256 -notmatch '^[0-9a-f]{64}$') { Refuse 'bridge target Windows bundle is invalid' }
    $sourceSeries = $identity.InstallerSeries
    $sourceVersion = $identity.InstallerVersion
    $targetZip = Join-Path $work 'bridge-target.zip'
    if ($Bundle) {
      if (-not $BridgeBundle) { Refuse 'the exact local destination bundle is required for this bridge' }
      $BridgeBundle = [IO.Path]::GetFullPath($BridgeBundle)
      if (-not (Test-Path -LiteralPath $BridgeBundle -PathType Leaf) -or
          -not (Test-Path -LiteralPath ($BridgeBundle + '.sha256') -PathType Leaf)) {
        Refuse 'local bridge destination bundle or its .sha256 sidecar is missing'
      }
      $sidecarSha = ((Get-Content -LiteralPath ($BridgeBundle + '.sha256') -TotalCount 1) -split '\s+')[0]
      if ($sidecarSha -ne $targetPlatform.sha256) {
        Refuse 'bridge destination sidecar disagrees with bridge.json'
      }
      Copy-Item -LiteralPath $BridgeBundle -Destination $targetZip
    } else {
      $targetUrl = $DistributionBase.TrimEnd('/') + '/' + $bridge.target.series + '/releases/' +
        $bridge.target.version + '/' + $targetPlatform.file
      Invoke-WebRequest -UseBasicParsing -Uri $targetUrl -OutFile $targetZip
    }
    $targetActual = (Get-FileHash -LiteralPath $targetZip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($targetActual -ne $targetPlatform.sha256) { Refuse 'bridge destination digest disagrees' }
    Remove-Item -LiteralPath $bundleDir -Recurse -Force
    New-Item -ItemType Directory -Path $bundleDir | Out-Null
    Expand-Archive -LiteralPath $targetZip -DestinationPath $bundleDir
    $identity = & (Join-Path $bundleDir 'cfm-verify-installer-bundle.ps1') -Directory $bundleDir
    if ($identity.InstallerSeries -ne $bridge.target.series -or
        $identity.InstallerVersion -ne $bridge.target.version -or
        $identity.Commit -ne $bridge.target.commit) {
      Refuse 'verified destination does not agree with bridge.json'
    }
    $expected = [string]$targetPlatform.sha256
    $env:CFM_BRIDGE_FROM_SERIES = $sourceSeries
    Write-Output ("Bootstrap verified permanent bridge $sourceSeries / $sourceVersion -> " +
      $identity.InstallerSeries + ' / ' + $identity.InstallerVersion + '.')
  } elseif ($BridgeBundle) {
    Refuse '-BridgeBundle was supplied to an ordinary installer release'
  }
  if ($InstallerArguments -contains '-Yes' -or $InstallerArguments -contains '-Silent') {
    Refuse 'pass consent as the typed bootstrap -Yes or -Silent switch, not InstallerArguments'
  }
  $consent = if ($Silent) { 'silent' } elseif ($Yes) { 'yes' } else { 'interactive' }
  $logDir = Join-Path $env:ProgramData 'CORPUSfm\logs'; New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $log = Join-Path $logDir ('bootstrap-install-' + (Get-Date).ToString('yyyyMMdd-HHmmss') + '.log')
  New-Item -ItemType File -Force -Path $log | Out-Null
  $handoffPath = Join-Path $bundleDir '.bootstrap-handoff.json'
  [ordered]@{ schema_version=1; bootstrap_protocol=1; bundle_protocol=1
    installer_series=$identity.InstallerSeries; installer_version=$identity.InstallerVersion
    application_version=$identity.ApplicationVersion; commit=$identity.Commit; platform='windows'
    entry_point='install.ps1'; bundle_sha256=$expected; transcript=$log; consent=$consent
    nonce=[guid]::NewGuid().ToString() } | ConvertTo-Json | Set-Content -LiteralPath $handoffPath -Encoding UTF8
  $fileAcl = New-Object Security.AccessControl.FileSecurity
  $fileAcl.SetAccessRuleProtection($true,$false)
  $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins,$full,$allow)))
  $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,$full,$allow)))
  Set-Acl -LiteralPath $handoffPath -AclObject $fileAcl
  Add-Content -LiteralPath $log -Value ("Bootstrap verified " + $identity.InstallerSeries + ' / ' + $identity.InstallerVersion)
  $env:CFM_BOOTSTRAP_HANDOFF = $handoffPath; $env:CFM_LOG = $log
  # PowerShell array splatting is positional: strings such as '-InstallDir' inside
  # InstallerArguments are NOT rebound as named parameters when a script is invoked in-process.
  # Delegate through the fixed Windows PowerShell executable so each verified argument remains a
  # real argv token for install.ps1's own parameter binder.  No credential is present here; the
  # four credential values stay in the inherited process environment and the installer clears them.
  # NO -ExecutionPolicy Bypass (packet 1380-02 D20). Measured in parent 3.5: Invoke-WebRequest
  # -OutFile plus Expand-Archive apply no Mark of the Web, so the extracted install.ps1 is an
  # ordinary local file that RemoteSigned already permits. Under AllSigned the incoming package's
  # own verifier has already run IN THIS PROCESS above, so that policy decides the outcome before
  # this line either way - the flag never made the delegation reachable, it only hid which
  # authority was doing the work.
  $delegate = @('-NoProfile', '-File',
                (Join-Path $bundleDir 'install.ps1'))
  if ($Yes) { $delegate += '-Yes' }
  if ($Silent) { $delegate += '-Silent' }
  $delegate += $InstallerArguments
  & (Join-Path $PSHOME 'powershell.exe') @delegate
  $result = $LASTEXITCODE
} finally {
  Remove-Item Env:CFM_BOOTSTRAP_HANDOFF -ErrorAction SilentlyContinue
  Remove-Item Env:CFM_BRIDGE_FROM_SERIES -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit $result
