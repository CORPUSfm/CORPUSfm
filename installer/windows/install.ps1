<#
  CORPUSfm Server - Windows Install / Upgrade Script
  Supported: Windows Server 2019 / 2022 / 2025 (Desktop Experience) with FileMaker Server.

  Self-contained distribution: run install.ps1 from its complete verified Series 2 package.
  It downloads Python + git, materializes the exact bundled application source, installs dependencies, publishes the
  installation record, composes the four providers, installs the service definitions and fronts
  the app at <FMS-host>/corpusfm/ behind FileMaker Server's active web front.
  DUAL-FRONT: the default IIS front uses an isolated /corpusfm IIS application (ARR). For the optional
  Claris nginx front (FMS 2025+), the lifecycle provider owns one marked include family. While inactive,
  publication is a byte-safe write + parse transaction. While active, the executor stages exact bytes
  and the lifecycle provider activates them through the already-validated fmsadmin credential; failure
  restores exact bytes and performs one restorative HTTP-server restart. No general process control or
  caller-selected executable is exposed. Uninstall uses the same bounded transaction to remove what the
  installation published. See installer/SPEC.md.

  Run from an ELEVATED PowerShell:
      powershell -File install.ps1 [options]

  Options (parent 1246-04 section 4H.1 - ten switches, nine declared; the same set on Linux):
      -InstallDir <str>         Installation directory (default C:\Program Files\CORPUSfm)
      -PatchHostingDir <str>    CORPUSfm patch hosting folder (default <FMS drive>\CORPUSfm-Hosted)
      -FmsRoot <str>            FileMaker Server 'Database Server' directory (default: auto-detect);
                                the storage DB directory is derived from it
      -ProxyPolicyAdd <str[]>   Manage this reverse-proxy front (comma-separated; TYPE or 'all').
                                Linux spells the repetition as a repeated flag; PowerShell binds an
                                array from one comma list. Same obligation, native spelling.
      -ProxyPolicyIgnore <str[]> Leave this reverse-proxy front alone (comma-separated; TYPE or 'all')
      -RepairStorageAccess      Repair automation access to an existing storage database
      -ReplaceExistingInstall   Authorize moving an existing, non-empty install directory that
                                carries no CORPUSfm installation trace
      -DiscardIncompleteAttempt When an earlier fresh install stopped part-way, discard what that
                                attempt recorded creating, without the Inspect/Discard/Quit menu
                                (required for -Silent), then exit. Packet 1398 adds this one
                                switch on both platforms.
      -Yes                      Consent pre-granted; skip the confirmation wait (normal output)
      -Silent                   Non-interactive: inputs from the environment, fail loud on a missing
                                required input
      -Verbose                  Stream full command output to the console. Concise by default - the
                                detail always goes to the install transcript, and a failure prints
                                the transcript path.

  THE -Verbose ASYMMETRY, AND IT IS THE ONLY ONE (section 4H.1). Windows does NOT declare -Verbose
  in its parameter block: the CmdletBinding attribute below already supplies it as a common
  parameter, and a second declaration of the same name is a binding error. It is supported,
  documented here, and read through $VerbosePreference below. The divergence is in the DECLARATION,
  never in the surface an administrator meets. (Neither the attribute nor the block keyword is
  spelled out in this comment on purpose: more than one guard bounds the parameter block by
  searching for the FIRST occurrence of its spelling, and a mention up here sends them into the
  documentation instead.)

  CREDENTIALS ARE NEVER PASSED AS OPTIONS. Supply them in the environment:
    FM_ADMIN_USER / FM_ADMIN_PASS              FileMaker Server administrator
    CORPUSFM_ADMIN_USER / CORPUSFM_ADMIN_PASS  first CORPUSfm web administrator (fresh install)
  A password on a command line is visible in the process table and in shell history; the installer
  reads these from the environment, copies them into script variables, and clears the environment
  entries before any child process runs.

  RETIRED, and REFUSED as unknown parameters - not aliased, not ignored. An undeclared parameter is
  a PowerShell binding error, which is this platform's native form of "refused as unknown", so there
  is no catch-all arm to write:
    -WebPort  -Prefix  -ConfigHome  -Site  -GitPat  -FmAdminUser  -FmAdminPass  -AdminUser
    -AdminPass  -Ref  -NoMcp  -NoPull  -AllowDirty  -NoPki  -NoBootstrap
  The loopback port and the /corpusfm mount are implementation constants published by the
  installation manifest; the config home is the platform layout, not a choice; the IIS site is
  detected; MCP, the scheduler, PKI and the storage bootstrap always run; there is no version,
  branch or rollback choice; and no credential travels in argv. (-InstallRoot was RENAMED to
  -InstallDir; -HostingDir to -PatchHostingDir.)

  Upgrade: re-run this script. An existing installation is detected automatically. The installer
  installs the checkout it finds at <InstallDir>\src; it does NOT fetch code or advance the tree.
  The supply-chain rails on that path are unconditional: the checkout's origin must be the expected
  CORPUSfm repository and its tracked files must be unmodified. New code arrives through the in-app
  Updates button, which runs the privileged one-shot updater installed at phase 13.

  NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so any
  non-ASCII char (em dash, arrows, box-drawing) corrupts the parser.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = 'C:\Program Files\CORPUSfm',
  [string]$PatchHostingDir = '',
  [string]$FmsRoot = '',
  [string[]]$ProxyPolicyAdd = @(),
  [string[]]$ProxyPolicyIgnore = @(),
  [switch]$RepairStorageAccess,
  [switch]$ReplaceExistingInstall,
  [switch]$DiscardIncompleteAttempt,
  [switch]$Silent,
  [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$env:PYTHONDONTWRITEBYTECODE = '1'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallerSeries = ''
$InstallerVersion = ''
$PackageApplicationVersion = ''
$PackageCommit = ''
$BootstrapHandoffConsent = ''
$BundleManifest = Join-Path $PSScriptRoot 'installer-manifest.json'
if (Test-Path -LiteralPath $BundleManifest -PathType Leaf) {
  $BundleVerifier = Join-Path $PSScriptRoot 'cfm-verify-installer-bundle.ps1'
  if (-not (Test-Path -LiteralPath $BundleVerifier -PathType Leaf)) {
    Write-Host '  x Installer bundle refused: cfm-verify-installer-bundle.ps1 is missing' -ForegroundColor Red
    exit 2
  }
  try { $BundleIdentity = & $BundleVerifier -Directory $PSScriptRoot }
  catch {
    Write-Host ('  x ' + $_.Exception.Message) -ForegroundColor Red
    exit 2
  }
  $InstallerSeries = $BundleIdentity.InstallerSeries
  $InstallerVersion = $BundleIdentity.InstallerVersion
  $PackageApplicationVersion = $BundleIdentity.ApplicationVersion
  $PackageCommit = $BundleIdentity.Commit
  Write-Host ('  + Installer bundle verified: ' + $InstallerSeries + ' / ' +
              $InstallerVersion + ' / ' + $PackageCommit.Substring(0, 12)) -ForegroundColor Green
}
$RuntimeRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$RuntimeTemp = ''
# The installer-owned asset tree, a fixed SIBLING of the Git checkout inside the install root:
# <install root>\assets\{db,addon}. The application derives the same location from the published
# install root (app_paths.ASSETS_DIRNAME); this name and that constant must agree. Not selectable --
# a second configurable path is a second place for an installation to disagree with itself.
$script:CfmAssetsDirName = 'assets'
$script:CfmAssetsPayloadSha256 = ''
if ($InstallerSeries) {
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host '  x Run this installer package from an elevated (Administrator) PowerShell.' -ForegroundColor Red
    exit 2
  }
  $runtimeArchive = Join-Path $PSScriptRoot 'installer-runtime.zip'
  if (-not (Test-Path -LiteralPath $runtimeArchive -PathType Leaf)) {
    Write-Host '  x Installer bundle refused: installer-runtime.zip is missing' -ForegroundColor Red
    exit 2
  }
  $RuntimeTemp = Join-Path ([IO.Path]::GetTempPath()) ('corpusfm-installer-runtime.' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $RuntimeTemp | Out-Null
  & icacls $RuntimeTemp /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -Recurse -Force $RuntimeTemp -ErrorAction SilentlyContinue
    Write-Host '  x Installer bundle refused: runtime directory could not be protected' -ForegroundColor Red
    exit 2
  }
  try { Expand-Archive -LiteralPath $runtimeArchive -DestinationPath $RuntimeTemp -ErrorAction Stop }
  catch {
    Remove-Item -Recurse -Force $RuntimeTemp -ErrorAction SilentlyContinue
    Write-Host ('  x Installer bundle refused: runtime extraction failed: ' + $_.Exception.Message) -ForegroundColor Red
    exit 2
  }
  $RuntimeRoot = $RuntimeTemp
  Register-EngineEvent PowerShell.Exiting -SupportEvent -Action ([scriptblock]::Create(
    "Remove-Item -Recurse -Force '" + ($RuntimeTemp -replace "'", "''") + "' -ErrorAction SilentlyContinue")) | Out-Null
}
# Where an administrator obtains the release AND the publisher trust material that goes with it
# (packet 1380 section 4.2A.1: the trust record and the DER leaf ship as release assets, because a
# leaf carried INSIDE the package is unreachable in the one case that needs it - AllSigned with the
# leaf absent, where nothing in the package executes). The SYSTEM updater task's AllSigned refusal
# names it.
$ReleaseLocation = 'https://github.com/CORPUSfm/CORPUSfm/releases'

if ($env:CFM_BOOTSTRAP_HANDOFF) {
  if (-not $InstallerSeries) {
    Write-Host '  x Bootstrap handoff refused: delegated execution requires a packaged installer' -ForegroundColor Red
    exit 2
  }
  $HandoffVerifier = Join-Path $PSScriptRoot 'cfm-verify-bootstrap-handoff.ps1'
  if (-not (Test-Path -LiteralPath $HandoffVerifier -PathType Leaf)) {
    Write-Host '  x Bootstrap handoff refused: verifier is missing' -ForegroundColor Red
    exit 2
  }
  try { $HandoffIdentity = & $HandoffVerifier -Path $env:CFM_BOOTSTRAP_HANDOFF -BundleDirectory $PSScriptRoot }
  catch { Write-Host ('  x ' + $_.Exception.Message) -ForegroundColor Red; exit 2 }
  if ($HandoffIdentity.InstallerSeries -ne $InstallerSeries -or
      $HandoffIdentity.InstallerVersion -ne $InstallerVersion -or
      $HandoffIdentity.ApplicationVersion -ne $PackageApplicationVersion -or
      $HandoffIdentity.Commit -ne $PackageCommit) {
    Write-Host '  x Bootstrap handoff refused: handoff and verified bundle identities disagree' -ForegroundColor Red
    exit 2
  }
  if ($env:CFM_LOG -ne $HandoffIdentity.Transcript) {
    Write-Host '  x Bootstrap handoff refused: transcript continuity disagrees' -ForegroundColor Red
    exit 2
  }
  $BootstrapHandoffConsent = $HandoffIdentity.Consent
  $actualConsent = if ($Silent) { 'silent' } elseif ($Yes) { 'yes' } else { 'interactive' }
  if ($BootstrapHandoffConsent -ne $actualConsent) {
    Write-Host ('  x Bootstrap handoff refused: consent ' + $BootstrapHandoffConsent +
                ' disagrees with invocation ' + $actualConsent) -ForegroundColor Red
    exit 2
  }
  if ((Test-Path -LiteralPath 'C:\ProgramData\CORPUSfm\.corpusfm\install.yaml' -PathType Leaf) -and
      -not (Test-Path -LiteralPath (Join-Path $InstallDir 'manifest\installation.json') -PathType Leaf)) {
    Write-Host '  x Bootstrap handoff refused: Series 1 is retired and has no installation route' -ForegroundColor Red
    exit 2
  }
  Remove-Item -LiteralPath $env:CFM_BOOTSTRAP_HANDOFF -Force
  Remove-Item Env:CFM_BOOTSTRAP_HANDOFF
  Write-Host '  + Bootstrap handoff consumed; continuing with the verified installer bundle' -ForegroundColor Green
}

# Canonicalize the selected software root before any manifest path or dependent directory is
# derived. GetFullPath is lexical for a missing final path. Preserve a volume root's separator, but
# remove trailing separators everywhere else so the lifecycle canonicality check sees what Windows
# will actually address.
try {
  $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
  $volumeRoot = [System.IO.Path]::GetPathRoot($InstallDir)
  if ($InstallDir.Length -gt $volumeRoot.Length) {
    $InstallDir = $InstallDir.TrimEnd([char[]]@('\','/'))
  }
} catch {
  Write-Host ('  x -InstallDir could not be normalized: ' + $_.Exception.Message) -ForegroundColor Red
  exit 2
}

# Series 1 is retired. Its final platform payloads remain under retired/series-1 as historical
# custody only; a Series 2 package does not carry or execute the old takeover adapter.
$Legacy1246Marker = 'C:\ProgramData\CORPUSfm\.corpusfm\install.yaml'
$CurrentManifest = Join-Path $InstallDir 'manifest\installation.json'
if ((Test-Path -LiteralPath $Legacy1246Marker -PathType Leaf) -and
    -not (Test-Path -LiteralPath $CurrentManifest -PathType Leaf)) {
  Write-Host '  x Series 1 installation detected. Series 2 has no in-place legacy takeover; uninstall the old installation before running this package.' -ForegroundColor Red
  exit 2
}

# A final Series 1 installation carries the current schema-2 manifest, so the legacy-marker check
# above does not identify it. Read both the selected root and the fixed registry locator before
# source materialization or deployment; a Series 2 package must not first overwrite the old runtime
# and only then discover the installer-series mismatch in composition.
$SeriesOneCandidates = @($CurrentManifest)
$PublishedLocatorRoot = 'HKLM:\SOFTWARE\CORPUSfm\Installation'
if (Test-Path -LiteralPath $PublishedLocatorRoot) {
  try {
    $locatorRoot = Get-ItemProperty -LiteralPath $PublishedLocatorRoot
    $slotName = '' + $locatorRoot.committed_slot
    if ($slotName -eq '0' -or $slotName -eq '1') {
      $slot = Get-ItemProperty -LiteralPath (Join-Path $PublishedLocatorRoot $slotName)
      $locatedRoot = '' + $slot.install_dir
      $locatedRelative = '' + $slot.manifest_relative_path
      if ($locatedRoot -and $locatedRelative -and -not [IO.Path]::IsPathRooted($locatedRelative) -and
          -not ($locatedRelative -split '[\\/]' | Where-Object { $_ -eq '..' })) {
        $SeriesOneCandidates += (Join-Path $locatedRoot $locatedRelative)
      }
    }
  } catch {
    # The ordinary lifecycle authority reader below owns malformed-locator diagnostics. This early
    # gate answers one narrower question and never turns unreadable authority into fresh state.
  }
}
foreach ($candidate in ($SeriesOneCandidates | Select-Object -Unique)) {
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
  try { $published = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json }
  catch { continue }
  if ($published.installer -and ('' + $published.installer.series) -eq 'series-1') {
    $publishedRoot = if ($published.paths -and $published.paths.install_dir) {
      '' + $published.paths.install_dir
    } else { Split-Path (Split-Path $candidate -Parent) -Parent }
    Write-Host ('  x Series 1 installation detected at ' + $publishedRoot +
                '. Series 2 will not overwrite, upgrade, adopt or convert it. Run the installed' +
                ' Series 1 uninstaller, then run this Series 2 package again. No Series 2' +
                ' mutation phase began.') -ForegroundColor Red
    exit 2
  }
}

# Dot-source the shared S1-S10 library. CRITICAL ORDERING: this installer self-clones the repo
# mid-run (phase 10), so _cfm_lib.ps1 is NOT guaranteed beside install.ps1 unless shipped
# together. The Windows release ZIP ships install.ps1 + _cfm_lib.ps1 together, so
# when run from the bundle the library IS beside it. Use raw Write-Host for THIS one error since the
# library isn't loaded yet.
$LibPath = Join-Path $PSScriptRoot '_cfm_lib.ps1'
if (-not (Test-Path $LibPath)) { Write-Host "  x Missing _cfm_lib.ps1 beside install.ps1 - run install.ps1 from the installer bundle (it ships the library)." -ForegroundColor Red; exit 1 }
. $LibPath
# -Verbose (the built-in CmdletBinding switch) streams full command output (pip/git/download) to the
# console too; concise by default (that detail always goes to the install transcript regardless).
if ($VerbosePreference -ne 'SilentlyContinue') { $script:CfmVerbose = $true }
# -Silent must reach the library's silence gear BEFORE the first primitive call, or it grants consent
# and suppresses prompts while every Hello/Section/Info still prints - which is exactly what it did
# until packet 1230. Linux has exported CFM_SILENT since the library landed; this is Windows catching
# up. -Yes is consent only (normal output), so it sets the consent state, never the silence one.
if ($Silent) { $script:CfmSilent = $true; $script:CfmAssumeYes = $true }
if ($Yes) { $script:CfmAssumeYes = $true }

$Repo = 'CORPUSfm/CORPUSfm'

# -- Implementation constants, not administrator inputs (section 4H R3) --------------------------
# The loopback port and the URL prefix are published by `composition foundation` as facts about the
# installation. Their flags are retired; these remain because the blocks below still read them.
$WebPrefix = '/corpusfm'
$WebPort   = 8533
# MCP ALWAYS installs (section 4H.2). It stays a CONSTANT because the blocks below still read it;
# what is gone is every parameter that could set it. There is no opt-out to express.
#
# THE SCHEDULER IS NOT A SERVICE (application packet 1361-01, round 3), so it has no switch at all.
# Scheduling is a background component of the ONE web process: it starts when the database becomes
# readable and stops with the service. A second process could not honour the process-wide
# database-readiness gate - it kept reading and writing FileMaker while CORPUSfm was PAUSED - and
# `python -m corpusfm.server.scheduler` now exits 2 with that reason, so an obsolete service under
# WinSW's restart policy would fail repeatedly. The name below survives ONLY as a removal target.
$EnableMcp = $true
# The tracked branch is `main` and forward-only; there is no channel, tag or SHA to choose, so this
# is a CONSTANT the git blocks read, not an input.
$GitTrackedBranch = 'main'
# The config home is the PLATFORM LAYOUT, never a second selectable root. It must stay identical to
# `corpusfm.lifecycle.os_layout.windows_os_layout()`, whose directories the canonical service
# definitions rendered at phase 20 are derived from; a literal that drifts from it renders a
# definition naming a directory the application does not use.
$ConfigHome = 'C:\ProgramData\CORPUSfm'

$Service = @{ web = 'corpusfm-web' }
$WebService   = $Service.web
# The retired standalone scheduler service. Named here so an upgrade can STOP, remove its ACL
# entries, prove the one-service policy and only then DELETE it; nothing renders, registers, grants
# to or starts it. See THE SCHEDULER RETIREMENT ADAPTER above for why that order is load-bearing.
$SchedServiceRetired = 'corpusfm-scheduler'
$SchedRetiredAccount = 'NT SERVICE\' + $SchedServiceRetired
$SchedRetiredService = $SchedServiceRetired
# The two accounts the patch-compartment request names. Ours is the WinSW virtual service account -
# the same `NT SERVICE\<id>` spelling `service_identity.windows_virtual_account` produces, so the
# compartment is asked about the identity phase 20 actually registers. FMS's own service runs as
# LocalSystem on a stock Windows FileMaker Server; it is stated here because the compartment decides
# who may host FROM the compartment, and an account nobody runs as would answer that wrongly.
$WebServiceAccount = 'NT SERVICE\' + $Service.web
$FmsServiceAccount = 'NT AUTHORITY\SYSTEM'
# CO-LOCATED IS THE ONLY SHIPPED DEPLOYMENT, so the FileMaker host the provider verbs reach is this
# machine. It is not an option: an install that had to be told where its own FileMaker Server is
# would not be co-located.
$CfmFmsHost = 'localhost'
# The proxy fronts a WINDOWS box can present, from `proxy_inventory.inventory()`: `fms-nginx` and
# `apache` are answered `Linux-only front` there, so naming them here would ask this box about
# fronts it structurally cannot have.
$CfmProxyTypes = @('iis', 'claris-nginx')

# -- Derived paths -------------------------------------------------------------------------------
# PowerShell binds param() BEFORE the script body runs, so every path below already reflects
# -InstallDir. (Linux needed an explicit re-derivation block because its assignments precede its
# argument parser; that hazard does not exist here, and inventing a re-derivation would be cargo.)
$PyDir    = Join-Path $InstallDir 'python'
$Py       = Join-Path $PyDir 'python.exe'
$script:RecoveryRuntimeKind = 'installed'
$script:PythonRuntimeVersion = '3.13.14'
$script:PythonRuntimeSha256 = '90b4e5b9898b72d744650524bff92377c367f44bd5fbd09e3148656c080ad907'
# The bundled MinGit, by ABSOLUTE path. It used to also be added to the SERVICE PATH through the
# hand-written definition's <env name="PATH">, and that entry is gone: the canonical renderer allows
# a short, exact environment allowlist and PATH is not on it. Nothing regressed - the running app
# reads its version from corpusfm\_build.txt rather than shelling out to git, and the privileged
# updater is rendered with this absolute path so the installation's own record says which binary
# runs. install.sh's canonical unit carries no PATH either.
$Git      = Join-Path $InstallDir 'git\cmd\git.exe'
$Src      = Join-Path $InstallDir 'src'
$script:RecoverySource = $Src
# A complete checkout may carry this installer at installer\windows\install.ps1. A flattened
# ordinary release ZIP has no .git two levels above this file and keeps the established acquisition
# path. This is discovered from the executing file, never from a caller-selected path or environment
# value.
$SourceSeed = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$SvcDir   = Join-Path $InstallDir 'services'
$BinDir   = Join-Path $InstallDir 'bin'
$LibDir   = Join-Path $InstallDir 'lib'
$ProxyDir = Join-Path $InstallDir 'proxy'
$MetaProxyDir = Join-Path $InstallDir 'proxy-mcp'
$Dl       = Join-Path $InstallDir 'downloads'
# The fixed OS locations (packet 1246-03). These are `windows_os_layout()`, restated here because
# PowerShell cannot import it and re-stated NOWHERE ELSE in this file.
$LogDir       = Join-Path $ConfigHome 'logs'
$FixedConfig  = Join-Path $ConfigHome 'config'
$FixedState   = Join-Path $ConfigHome 'state'
$FixedSecrets = Join-Path $ConfigHome 'secrets'
$FixedRun     = Join-Path $ConfigHome 'run'
$InboxDir     = Join-Path $FixedState 'update-inbox'
$OutcomeDir   = Join-Path $FixedState 'update-outcome'
# TRANSITIONAL. An unpublished box still resolves its keys and marker from HOME, so this legacy
# directory is still created and still holds them. Packet 1246-10 removes it with the conversion
# that makes the published layout authoritative; install.sh carries the identical transitional
# directory for the identical reason.
$LegacyHome   = Join-Path $ConfigHome '.corpusfm'
# The definitions phase 20 installed and READ BACK. Phase 21 starts exactly this set - it is the
# mechanism behind "identity, not merely order".
$VerifiedServices = @()

# Version is resolved at phase 10; pre-declare so Hello can reference it.
$Version = ''
$FmAdminUser = ''
$FmAdminPass = ''
$AdminUser = ''
$AdminPass = ''
$StorageOk = $false

function NeedExit($code, $what) { if ($code -ne 0) { Die "$what failed (exit $code)" } }

# -- Supply-chain trust guards for the in-place update path (mirror install.sh) -------------------
# Re-running the installer installs the checkout at <InstallDir>\src, and this elevated process then
# runs that code, so the checkout must point at the expected CORPUSfm repo (not a redirected or
# tampered remote) and must carry no modified tracked file. Form-independent origin compare: strip
# scheme, embedded PAT userinfo, scp-style colon, and a trailing .git.
#
# SCOPE, stated exactly. These rails run on the SUPPORTED IN-PLACE UPDATE PATH and no other. They do
# NOT adjudicate the provenance of a fresh install or of an external checkout an administrator chose
# to install from, and they are NOT a defence against a malicious installer or a general
# supply-chain attack. An administrator who installs from an unusual checkout owns that choice.
# -AllowDirty is retired, so no parameter waives either rail.
$ExpectedRemote = $null
$ExternalSourceAdvance = $false
$ExternalSourceHead = ''
function Normalize-Remote([string]$u) {
  if (-not $u) { return '' }
  $u = $u.Trim()
  if ($u.EndsWith('.git')) { $u = $u.Substring(0, $u.Length - 4) }
  $u = $u.TrimEnd('/')
  foreach ($s in @('https://','http://','ssh://','git://')) { if ($u.StartsWith($s)) { $u = $u.Substring($s.Length); break } }
  if ($u.StartsWith('git@')) { $u = $u.Substring(4) }
  $u = $u.Replace('github.com:', 'github.com/')   # scp-style host:path -> host/path
  if ($u.Contains('@')) { $u = $u.Substring($u.IndexOf('@') + 1) }   # strip any userinfo
  return $u.ToLower()
}
function Assert-Origin($src) {
  $got = (& $Git -C $src remote get-url origin 2>$null)
  $norm = Normalize-Remote $got
  if ($norm -ne $ExpectedRemote) {
    Die ("Update refused - the checkout origin is not the expected CORPUSfm repository.`n" +
         "       expected: $ExpectedRemote`n       found:    $norm`n" +
         "     A privileged update runs this code; an unexpected remote is a supply-chain risk.`n" +
         "     Fix it: git remote set-url origin https://github.com/$Repo.git`n" +
         "     This rail is unconditional - there is no parameter that installs from an unexpected origin.")
  }
  Ok "origin verified: $norm"
}
function Assert-CleanTree($src) {
  $dirty = (& $Git -C $src status --porcelain --untracked-files=no)
  if ($dirty) {
    Die ("Update refused - the deployed checkout has local modifications to tracked files:`n" +
         ($dirty -join "`n") + "`n" +
         "     Commit or stash them, then re-run. This rail is unconditional: there is no`n" +
         "     parameter that installs over a modified checkout.")
  }
  Ok "deployed checkout is clean"
}

# THE EXECUTING INSTALLER AND THE DEPLOYED PRODUCT MUST BE ONE REVISION before the first lifecycle
# status call. The 1246-10 Windows tail proved why: a corrected external install.ps1 drove an older
# lifecycle package and reproduced the defect the correction had removed. Comparing after status is
# too late; the mixed pair has already executed by then.
#
# Windows Git may materialize the tracked checkout with CRLF while a release bundle carries LF. Git
# blob identity was measured with exactly that difference, so line-ending spelling is normalized and
# nothing else is. Both executable files are required: checking install.ps1 while dot-sourcing a
# different _cfm_lib.ps1 is still skew.
function Get-NormalizedPowerShellDigest([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
  $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n").Replace("`r", "`n")
  $bytes = [Text.Encoding]::UTF8.GetBytes($text)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}
function Test-InstallerSourceAgreement([string]$SourceRoot) {
  $pairs = @(
    @((Join-Path $PSScriptRoot 'install.ps1'), (Join-Path $SourceRoot 'installer\windows\install.ps1')),
    @($LibPath, (Join-Path $SourceRoot 'installer\windows\_cfm_lib.ps1'))
  )
  foreach ($pair in $pairs) {
    $running = Get-NormalizedPowerShellDigest $pair[0]
    $deployed = Get-NormalizedPowerShellDigest $pair[1]
    if (-not $running -or -not $deployed -or $running -ne $deployed) {
      return $false
    }
  }
  return $true
}
function Assert-InstallerSourceAgreement([string]$SourceRoot) {
  # A verified distribution intentionally has two repositories: this focused package owns the
  # installer, while corpusfm.bundle owns the application source. Their agreement is the exact app
  # commit recorded by the digested installer manifest; comparing same-named files across those
  # repositories would incorrectly recreate the retired application-repo installer authority.
  if ($InstallerSeries) {
    $sourceHead = ("" + (& $Git -C $SourceRoot rev-parse HEAD 2>$null)).Trim()
    if ($PackageCommit -notmatch '^[0-9a-f]{40}$' -or $sourceHead -ne $PackageCommit) {
      Die ("Installer/source identity refused before lifecycle work or mutation.`n" +
           "     The verified installer selects application commit " + $PackageCommit +
           ", but the source at " + $SourceRoot + " is " + $sourceHead + ".")
    }
    Ok "verified installer and application source identities agree"
    return
  }
  if (-not (Test-InstallerSourceAgreement $SourceRoot)) {
    Die ("Installer/source skew refused before lifecycle work or mutation.`n" +
         "     The executing installer does not match the deployed checkout at " + $SourceRoot + ".`n" +
         "     Run install.ps1 and _cfm_lib.ps1 together from either that checkout or a complete,`n" +
         "     clean current CORPUSfm checkout; no loose scripts or partial payload may advance it.")
  }
  Ok "executing installer and deployed source agree"
}
function Prepare-ExternalSourceAdvance([string]$DeployedRoot) {
  # A complete checkout carrying this installer is the Windows equivalent of Linux's external
  # payload.  It may advance an older installed checkout, but it may nominate no ref or path: the
  # source is derived from PSScriptRoot, both trees are clean expected-origin checkouts, the payload
  # is exactly its own origin/main, and the deployed head must be its ancestor.  No byte moves here;
  # phase 10 performs the reset only after phase 9 has quiesced both services.
  $seedGit = Join-Path $SourceSeed '.git'
  # A flattened release ZIP carries an exact Git bundle, not an exposed checkout. On an
  # upgrade the installed MinGit can materialize that bundle into installer-owned temporary state
  # before the skew check. Without this bridge every newer public package compares itself to the
  # older deployed installer and refuses before it can advance it. The bundle chooses no target or
  # ref from caller input: it is fixed beside this executing installer and must carry main.
  $packageBundle = Join-Path $PSScriptRoot 'corpusfm.bundle'
  if (-not (Test-Path -LiteralPath $seedGit) -and
      (Test-Path -LiteralPath $packageBundle -PathType Leaf)) {
    $bundleSeed = Join-Path $env:TEMP ("corpusfm-package-seed." + $PID)
    Remove-Item -Recurse -Force $bundleSeed -ErrorAction SilentlyContinue
    # PowerShell 5.1 promotes git's ordinary stderr progress ("Cloning into ...") to a terminating
    # NativeCommandError while the installer runs with ErrorActionPreference=Stop. Judge this
    # native operation by its exit code and keep its combined output in the transcript.
    $bundleEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
      & $Git clone --no-hardlinks --branch $GitTrackedBranch $packageBundle $bundleSeed 2>&1 |
        ForEach-Object { Cfm-Logline ("[bundle seed] " + $_) }
      $bundleCloneRc = $LASTEXITCODE
    } finally { $ErrorActionPreference = $bundleEap }
    if ($bundleCloneRc -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $bundleSeed '.git'))) {
      Remove-Item -Recurse -Force $bundleSeed -ErrorAction SilentlyContinue
      Die "Package source advance refused: corpusfm.bundle could not materialize its main checkout."
    }
    $bundleEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
      & $Git -C $bundleSeed remote set-url origin "https://github.com/$Repo.git" 2>&1 |
        ForEach-Object { Cfm-Logline ("[bundle seed] " + $_) }
      $bundleOriginRc = $LASTEXITCODE
    } finally { $ErrorActionPreference = $bundleEap }
    if ($bundleOriginRc -ne 0) {
      Remove-Item -Recurse -Force $bundleSeed -ErrorAction SilentlyContinue
      Die "Package source advance refused: the temporary checkout origin could not be normalized."
    }
    $script:SourceSeed = $bundleSeed
    $script:PackageSourceSeed = $bundleSeed
    Register-EngineEvent PowerShell.Exiting -SupportEvent -Action ([scriptblock]::Create(
      "Remove-Item -Recurse -Force '" + ($bundleSeed -replace "'", "''") + "' -ErrorAction SilentlyContinue")) | Out-Null
    $seedGit = Join-Path $SourceSeed '.git'
  }
  if (-not (Test-Path -LiteralPath $seedGit) -or
      -not (Test-Path -LiteralPath (Join-Path $SourceSeed 'corpusfm') -PathType Container)) {
    if (Test-Path -LiteralPath (Join-Path $DeployedRoot '.git')) {
      Assert-InstallerSourceAgreement $DeployedRoot
    }
    return
  }
  # Fresh packaged installation has no deployed checkout to compare or advance. Materializing the
  # exact adjacent corpusfm.bundle above is still required: phase 10 will clone this SourceSeed
  # instead of downloading whichever commit remote main names at that later moment.
  if (-not (Test-Path -LiteralPath (Join-Path $DeployedRoot '.git'))) {
    return
  }
  if ([IO.Path]::GetFullPath($SourceSeed).TrimEnd('\') -eq
      [IO.Path]::GetFullPath($DeployedRoot).TrimEnd('\')) {
    Assert-InstallerSourceAgreement $DeployedRoot
    return
  }
  Assert-InstallerSourceAgreement $SourceSeed
  Assert-Origin $SourceSeed
  Assert-Origin $DeployedRoot
  Assert-CleanTree $SourceSeed
  Assert-CleanTree $DeployedRoot
  $seedHead = ("" + (& $Git -C $SourceSeed rev-parse HEAD 2>$null)).Trim()
  $seedMain = ("" + (& $Git -C $SourceSeed rev-parse origin/main 2>$null)).Trim()
  $deployedHead = ("" + (& $Git -C $DeployedRoot rev-parse HEAD 2>$null)).Trim()
  if ($seedHead -notmatch '^[0-9a-f]{40}$' -or $seedHead -ne $seedMain -or
      $deployedHead -notmatch '^[0-9a-f]{40}$') {
    Die "External source advance refused: the payload or deployed commit could not be resolved exactly."
  }
  if ($seedHead -eq $deployedHead) {
    Assert-InstallerSourceAgreement $DeployedRoot
    return
  }
  & $Git -C $SourceSeed merge-base --is-ancestor $deployedHead $seedHead 2>$null
  if ($LASTEXITCODE -ne 0) {
    Die "External source advance refused: the payload is not a fast-forward of the deployed checkout."
  }
  $script:ExternalSourceHead = $seedHead
  $script:ExternalSourceAdvance = $true
  Ok ("external source payload proven for post-quiesce advance to " + $seedHead.Substring(0, 12))
}
$ExpectedRemote = Normalize-Remote "https://github.com/$Repo.git"

# Locate the FMS 'Database Server' bin dir on ANY drive: the "FileMaker Server" service's
# binary path points at ...\Database Server\fmshelper.exe. Falls back to the default location.
# -FmsRoot overrides (custom installs). This makes a non-C: FMS install just work.
function Find-FmsBin($override) {
  if ($override) { return $override.TrimEnd('\') }
  $svc = Get-CimInstance Win32_Service -Filter "Name='FileMaker Server'" -ErrorAction SilentlyContinue
  if ($svc -and $svc.PathName) {
    $bin = Split-Path ($svc.PathName.Trim('"')) -Parent
    if (Test-Path (Join-Path $bin 'fmsadmin.exe')) { return $bin }
  }
  $def = 'C:\Program Files\FileMaker\FileMaker Server\Database Server'
  if (Test-Path (Join-Path $def 'fmsadmin.exe')) { return $def }
  return $null
}

# Download with retry/backoff + a clean failure message. Prefer curl.exe (built into Server 2019+):
# it uses Schannel, not the .NET HTTP stack, which on some networks drops python.org's CDN mid-
# transfer ("connection closed on send") even though Invoke-WebRequest HEAD succeeds. Falls back to
# Invoke-WebRequest if curl is somehow absent. Generous retries past a transient blip.
$script:CurlExe = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
function Get-File($url, $out) {
  for ($i=1; $i -le 5; $i++) {
    try {
      if ($script:CurlExe) {
        $log = & $script:CurlExe -L -sS --fail --connect-timeout 30 --max-time 600 -o $out $url 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-Path $out) -and (Get-Item $out).Length -gt 0) { return }
        throw ("curl exit " + $LASTEXITCODE + " " + ($log -join ' '))
      } else {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out -TimeoutSec 300; return
      }
    } catch { if ($i -eq 5) { Die ("Download failed after 5 tries: " + $url + "`n      " + $_.Exception.Message) } ; Start-Sleep -Seconds (5*$i) }
  }
}

function Initialize-PackagedRecoveryRuntime {
  if ($script:RecoveryRuntimeKind -eq 'package') { return }
  if (-not $InstallerSeries -or -not $RuntimeTemp) {
    Die "A lifecycle journal survives without the installed runtime. Re-run from a complete verified Series 2 package; loose scripts cannot supply recovery authority."
  }
  $root = Join-Path $RuntimeTemp 'lifecycle-recovery-runtime'
  $source = Join-Path $root 'source'
  $sourceArchive = Join-Path $RuntimeRoot 'corpusfm-recovery-source.zip'
  $zip = Join-Path $RuntimeTemp ('python-' + $script:PythonRuntimeVersion + '-embed-amd64.zip')
  $py = Join-Path $root 'python.exe'
  Info "Preparing a temporary verified-package lifecycle recovery runtime"
  if (-not (Test-Path -LiteralPath $sourceArchive -PathType Leaf)) {
    Die "The verified package lacks its private lifecycle recovery source."
  }
  New-Item -ItemType Directory -Force -Path $source | Out-Null
  Expand-Archive -LiteralPath $sourceArchive -DestinationPath $source -Force
  if (-not (Test-Path -LiteralPath (Join-Path $source 'corpusfm\lifecycle\__main__.py') -PathType Leaf)) {
    Die "The lifecycle recovery source archive has an unexpected layout."
  }
  Get-File ('https://www.python.org/ftp/python/' + $script:PythonRuntimeVersion + '/python-' +
            $script:PythonRuntimeVersion + '-embed-amd64.zip') $zip
  $got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $script:PythonRuntimeSha256) {
    Die ("Recovery Python checksum mismatch (expected " + $script:PythonRuntimeSha256 +
         ", got " + $got + "). The lifecycle journal remains untouched.")
  }
  New-Item -ItemType Directory -Force -Path $root | Out-Null
  Expand-Archive -LiteralPath $zip -DestinationPath $root -Force
  if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    Die "The pinned recovery Python archive has an unexpected layout; the journal remains untouched."
  }
  $pth = Get-ChildItem -LiteralPath $root -Filter 'python*._pth' | Select-Object -First 1
  if (-not $pth) { Die "The recovery Python path policy file is missing; the journal remains untouched." }
  @("python$($script:PythonRuntimeVersion.Split('.')[0])$($script:PythonRuntimeVersion.Split('.')[1]).zip",
    ".", "Lib\site-packages", $source, "import site") |
    Set-Content -LiteralPath $pth.FullName -Encoding ascii
  $getpip = Join-Path $RuntimeTemp 'recovery-get-pip.py'
  Get-File 'https://bootstrap.pypa.io/get-pip.py' $getpip
  & $py $getpip --no-warn-script-location >> $script:CfmLog 2>&1
  if ($LASTEXITCODE -ne 0) { Die "Recovery pip bootstrap failed; the journal remains untouched." }
  $req = Join-Path $RuntimeRoot 'installer\requirements-server.txt'
  $constraints = Join-Path $RuntimeRoot 'installer\constraints-server-win-py313.txt'
  if (-not (Test-Path -LiteralPath $req) -or -not (Test-Path -LiteralPath $constraints)) {
    Die "The verified package lacks its locked recovery dependency set."
  }
  & $py -m pip install -r $req -c $constraints --no-warn-script-location >> $script:CfmLog 2>&1
  if ($LASTEXITCODE -ne 0) { Die "Recovery dependencies could not be installed; the journal remains untouched." }
  $script:Py = $py
  $script:RecoverySource = $source
  $script:RecoveryRuntimeKind = 'package'
  Ok "Verified package recovery runtime ready; the installed root is still untouched"
}
function Get-Json($url) {
  for ($i=1; $i -le 5; $i++) {
    try {
      if ($script:CurlExe) {
        $raw = & $script:CurlExe -L -sS --fail --connect-timeout 30 --max-time 120 -H "User-Agent: corpusfm-installer" $url 2>&1
        if ($LASTEXITCODE -eq 0 -and $raw) { return (($raw | Out-String) | ConvertFrom-Json) }
        throw ("curl exit " + $LASTEXITCODE + " " + ($raw -join ' '))
      } else {
        return Invoke-RestMethod -UseBasicParsing -Uri $url -Headers @{ 'User-Agent'='corpusfm-installer' } -TimeoutSec 60
      }
    } catch { if ($i -eq 5) { Die ("API request failed after 5 tries: " + $url + "`n      " + $_.Exception.Message) } ; Start-Sleep -Seconds (5*$i) }
  }
}
# HTTP status without following redirects (PS 5.1's Invoke-WebRequest -MaximumRedirection 0 throws on
# a 302 and loses the status). Used by the storage phase (OData polling) and by phase 21's readiness.
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
function Code($url) {
  try {
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.AllowAutoRedirect = $false; $req.Timeout = 15000; $req.UserAgent = 'corpusfm-installer'
    $resp = $req.GetResponse(); $c = [int]$resp.StatusCode; $resp.Close(); return $c
  } catch [System.Net.WebException] {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode } else { return -1 }
  }
}
# Same, but an unauthenticated POST {} - used by phase 21's MCP fail-closed smoke test (the
# folded-in MCP must reject an unauthenticated request with 401; a GET could 405 before the auth gate).
function CodePost($url) {
  try {
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = 'POST'; $req.AllowAutoRedirect = $false; $req.Timeout = 15000
    $req.UserAgent = 'corpusfm-installer'; $req.ContentType = 'application/json'
    $body = [Text.Encoding]::UTF8.GetBytes('{}'); $req.ContentLength = $body.Length
    $s = $req.GetRequestStream(); $s.Write($body, 0, $body.Length); $s.Close()
    $resp = $req.GetResponse(); $c = [int]$resp.StatusCode; $resp.Close(); return $c
  } catch [System.Net.WebException] {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode } else { return -1 }
  }
}

# Doubling the apostrophe is the single-quoted-literal escape. Used when rendering an installation
# path into an artifact that runs elevated: raw substitution of a path containing an apostrophe
# would close the literal early - a syntax error, or with a crafted directory name, injected code
# inside a script that runs as SYSTEM.
function Esc-PsLiteral($value) { return ([string]$value).Replace("'", "''") }

# -- Lifecycle composition helpers (packet 1246-04-04) -------------------------------------------
# Every lifecycle verb reads an administrator-owned request file. Requests live in a directory
# granted to SYSTEM + Administrators only and are REMOVED when the invocation ends: a request may
# name an installation and an operation, and it must never name a credential (section 6). The
# provider CLIs read secrets from their own authorities, not from what the installer hands them.
$LcReqDir = Join-Path $env:TEMP ("corpusfm-lifecycle." + $PID)
$SystemSid = '*S-1-5-18'          # NT AUTHORITY\SYSTEM
$AdminsSid = '*S-1-5-32-544'      # BUILTIN\Administrators
$InstallationId = ''
$CfmGeneration = 0

function Lc-Cleanup {
  if (Test-Path $script:LcReqDir) { Remove-Item -Recurse -Force $script:LcReqDir -ErrorAction SilentlyContinue }
}
# PowerShell has no EXIT trap. `PowerShell.Exiting` fires on a normal end and on `exit`, which is
# how Die terminates, so the ordinary and the failing path both clean up; phase 21 calls Lc-Cleanup
# explicitly as well, so the removal does not depend on the event alone. The path is BAKED into the
# handler rather than read from a variable: the event action runs in its own scope, where this
# script's variables are not reliably visible, so a handler that dereferenced $LcReqDir would
# silently remove nothing.
Register-EngineEvent PowerShell.Exiting -SupportEvent -Action ([scriptblock]::Create(
  "Remove-Item -Recurse -Force '" + (Esc-PsLiteral $LcReqDir) + "' -ErrorAction SilentlyContinue")) | Out-Null

# A request object is BUILT AS DATA and serialized, never pasted together as text. An installation
# path on Windows is full of backslashes and may contain spaces or an apostrophe; hand-escaping it
# into a JSON string literal is the kind of thing that works until the first customer whose FMS
# lives on D:\Program Files.
function Lc-Json($obj) { return ($obj | ConvertTo-Json -Depth 20 -Compress) }

# The OS locations, read from `lifecycle.os_layout` rather than restated here. `storage_dirs` and
# `protected_dirs` are the compartment's FORBIDDEN neighbours - a sandbox must not overlap the
# directories CORPUSfm keeps its own state and its own lifecycle records in - so a literal that
# drifts from the layout silently stops protecting the directory it names.
$script:CfmConfigDir = ''; $script:CfmStateDir = ''; $script:CfmSecretsDir = ''
$script:CfmLogDir = '';    $script:CfmRunDir = ''
function Lc-LoadOsLayout {
  $lines = (& $script:Py -c "from corpusfm.lifecycle.os_layout import platform_os_layout as p`nl = p()`nprint(l.config_dir)`nprint(l.state_dir)`nprint(l.secrets_dir)`nprint(l.log_dir)`nprint(l.run_dir)" 2>&1)
  if ($LASTEXITCODE -ne 0 -or $lines.Count -lt 5) { Die "could not read this platform's OS layout." }
  $script:CfmConfigDir  = ("" + $lines[0]).Trim()
  $script:CfmStateDir   = ("" + $lines[1]).Trim()
  $script:CfmSecretsDir = ("" + $lines[2]).Trim()
  $script:CfmLogDir     = ("" + $lines[3]).Trim()
  $script:CfmRunDir     = ("" + $lines[4]).Trim()
  if (-not $script:CfmSecretsDir -or -not $script:CfmStateDir) {
    Die "the OS layout reported no secrets or state directory."
  }
}

# THE FIVE REQUEST AUTHORITIES (packet 1246-04-04, correction B). Each builder produces EXACTLY its
# verb's key set, measured from the shipped parsers - `_REQUEST_KEYS`, `_PX_`, `_AI_`, `_ST_` and
# `_CO_REQUEST_KEYS`. An unknown key and a missing key both refuse, so these are not "close enough":
# every one of the seven requests this installer used to build was rejected outright.
#
# `credential_input` is a TRANSPORT TOKEN - 'absent', 'prompt', 'stdin' or 'fd:<n>' - and NEVER a
# value. No request object below carries a secret (section 6).
function Lc-AdminIdentityRequest($credentialInput) {
  return ([ordered]@{
    schema_version      = 1
    actor               = 'installer'
    installation_id     = $script:InstallationId
    install_dir         = $script:InstallDir
    fms_root            = $script:FmsBin
    secrets_dir         = $script:CfmSecretsDir
    host                = $script:CfmFmsHost
    mode                = $script:CfmMode
    expected_generation = [int]$script:CfmGeneration
    credential_input    = $credentialInput
  })
}
function Lc-StorageRequest($mode) {
  return ([ordered]@{
    schema_version      = 1
    actor               = 'installer'
    installation_id     = $script:InstallationId
    install_dir         = $script:InstallDir
    fms_root            = $script:FmsBin
    fms_database_dir    = $script:FmDbDir
    secrets_dir         = $script:CfmSecretsDir
    host                = $script:CfmFmsHost
    mode                = $mode
    expected_generation = [int]$script:CfmGeneration
  })
}
# `disposition` and `credential_input` are the only difference between status and reconcile, and both
# are structural: `composed_candidate` says this is the INTEGRATOR surface. `mcp_metadata` must be
# exactly true - MCP always installs - and 'all' is a PUBLIC selector, never a request value.
function Lc-ProxyRequest($verb) {
  $o = [ordered]@{
    schema_version      = 1
    actor               = 'installer'
    installation_id     = $script:InstallationId
    install_dir         = $script:InstallDir
    fms_root            = $script:FmsBin
    expected_generation = [int]$script:CfmGeneration
    mcp_metadata        = $true
    port                = [int]$script:WebPort
    prefix              = $script:WebPrefix
    types               = @($script:CfmProxyTypes)
  }
  if ($verb -eq 'reconcile') {
    $o['disposition']      = 'composed_candidate'
    $o['credential_input'] = (Lc-FmsTransport)
  }
  return $o
}
# The compartment request names no installation, no generation and no operation: it RETURNS candidate
# facts rather than writing them, so its key set is these ten facts and nothing else.
function Lc-PatchRequest {
  return ([ordered]@{
    requested        = $script:PatchHostingDir
    install_dir      = $script:InstallDir
    fms_root         = $script:FmsBin
    fms_database_dir = $script:FmDbDir
    storage_dirs     = @($script:CfmStateDir, $script:CfmSecretsDir)
    protected_dirs   = @($script:CfmConfigDir, $script:CfmLogDir, $script:CfmRunDir)
    service_identity = [ordered]@{ flavour = 'windows'; account = $script:WebServiceAccount; role = 'web' }
    fms_identity     = [ordered]@{ flavour = 'windows'; account = $script:FmsServiceAccount; role = 'fms' }
    flavour          = 'windows'
    # ONE Join-Path, as before. A NESTED Join-Path makes PowerShell resolve the drive of the inner
    # result, which fails off-Windows ("A drive with the name 'C' does not exist") and takes the
    # cross-platform request-builder walk down with it -- this builder is exercised on a POSIX host.
    seed             = (Join-Path $script:InstallDir ($script:CfmAssetsDirName + '\db\CORPUSfm_DB.fmp12'))
  })
}

function Lc-Request($name, $json) {
  if (-not (Test-Path $script:LcReqDir)) {
    New-Item -ItemType Directory -Force -Path $script:LcReqDir | Out-Null
    & icacls $script:LcReqDir /inheritance:r /grant:r ($script:SystemSid + ':(OI)(CI)F') ($script:AdminsSid + ':(OI)(CI)F') 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "Could not protect the lifecycle request directory $script:LcReqDir" }
  }
  $f = Join-Path $script:LcReqDir ($name + '.json')
  [IO.File]::WriteAllText($f, $json)
  # THE FILE ITSELF MUST BE PROTECTED (packet 1246-10-04). The directory grants SYSTEM and
  # Administrators with (OI)(CI), so a new child INHERITS the right identities - but an inherited
  # DACL is not a PROTECTED one, and `_open_privileged_request` asks the platform's own question:
  # `authority.protected`. It refused every request with "does not carry a protected DACL", which
  # the installer's exit-4 mapping reported as a key-set defect it was not. Measured on winfms2026,
  # 2026-08-08, at the foundation publication.
  & icacls $f /inheritance:r /grant:r ($script:SystemSid + ':F') ($script:AdminsSid + ':F') 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Die ("Could not protect the lifecycle request file " + $f) }
  return $f
}

# Map a lifecycle exit code onto this installer's behaviour. The six result words and the codes are
# the shipped contract; 4 means the REQUEST was refused, which is our defect, never the box's.
function Lc-Dispatch($code, $what) {
  switch ($code) {
    0 { return }
    1 { Die "$what refused before changing anything (failed_before_change)." }
    2 { Die ("$what contains rolled-back work (rolled_back). The failed front was restored, but " +
             "recorded recovery may still contain independently completed work; re-run the " +
             "installer to recover and continue.") }
    3 { Die "$what needs an administrator action before the install can continue (manual_action_required)." }
    4 { Die "${what}: the installer built a request this build does not accept - this is an installer defect." }
    5 { Die "$what stopped safely part-way (incomplete_safe). The services stay STOPPED. Re-run the installer to resume; do not start anything by hand." }
    default { Die "$what returned an unrecognised exit status $code." }
  }
}

# The SAME run, WITHOUT the dispatcher. Exactly one caller: phase 18, which must inspect a storage
# result before deciding whether its exit code is the ordinary stop or the one composable fresh
# success. Everything else goes through Lc-Run, so exit 5 stays a stop everywhere else.
#: Set by phase 18 when storage composed `first_administrator_owed`. Declared here so phase 19 can
#: read it on every path, including one that never reaches phase 18's fresh branch.
$script:CfmFirstAdminOwed = $false
$script:LcAwaiting = $null
$script:LcProviderOut = ''
$script:LcFrameAccount = $null; $script:LcFramePassword = $null
$script:CfmStorageObservation = ''
$script:LcRawOut = ''; $script:LcRawRc = 0
function Lc-RunRaw([string[]]$LcArgs) {
  # STDOUT AND STDERR SEPARATELY (correction F4). Merging them put diagnostics into the text that
  # `Lc-Field` parses; `Lc-Field` answers $null on a parse failure, so a real awaiting-composition
  # result became "no candidate" and the disposition helper answered `skip` - leaving an open
  # journal uncommitted while the installer reported success. A parse failure must STOP.
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $script:LcRawOut = (& $script:Py -m corpusfm.lifecycle @LcArgs 2>$errFile | Out-String)
    $script:LcRawRc = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $eap
    if (Test-Path $errFile) { Cfm-Logline (Get-Content $errFile -Raw); Remove-Item -Force $errFile -ErrorAction SilentlyContinue }
  }
  Cfm-Logline $script:LcRawOut
  # EXACTLY ONE JSON OBJECT. A second document, an array, a scalar or a truncated write refuses here
  # rather than being read field-by-field into a false answer.
  if (-not (Lc-IsOneJsonObject $script:LcRawOut)) {
    Die ("a lifecycle verb returned output this installer cannot read as one JSON result (exit " + $script:LcRawRc + "). See the log. Nothing further was changed.")
  }
}

function Lc-IsOneJsonObject($text) {
  if (-not ("" + $text).Trim()) { return $false }
  try { $value = ("" + $text) | ConvertFrom-Json -ErrorAction Stop } catch { return $false }
  if ($null -eq $value) { return $false }
  # ConvertFrom-Json returns an ARRAY for two concatenated documents and for a JSON array; either is
  # not one object. A scalar has no properties.
  if ($value -is [System.Array]) { return $false }
  # `-is [PSCustomObject]` is TRUE for a bare string or number, because PowerShell wraps every value
  # in a PSObject - so a scalar JSON document passed a type test that looks like it excludes one.
  # The concrete type is what distinguishes an object from a scalar.
  return ($value.GetType().FullName -eq 'System.Management.Automation.PSCustomObject')
}

# THE ONE EXIT-5 EXCEPTION, decided by the SHIPPED predicate and not by this script.
# `cli.storage_fresh_success_is_composable` is the single boundary BOTH installers ask; a script
# that re-implemented the conjunction would be a second opinion about a protocol it cannot see. It
# takes only data - no path, no installation selection - so handing it a result buys no authority.
# WHICH STORAGE VERB THIS INVOCATION MAY RUN, decided by the SHIPPED boundary from the phase-14
# OBSERVATION (correction C1). Choosing the verb from the repair flag alone ran `bootstrap` with
# `mode=forward_update` on every update - which `proven_fresh` rejects - and died at phase 18 with
# every service already stopped by phase 9.
function Lc-StorageRoute($observationJson) {
  $probe = @'
import json, sys
from corpusfm.lifecycle.cli import storage_route_for_observation as route
try:
    payload = json.load(sys.stdin)
except ValueError as exc:
    sys.stderr.write("the storage observation is not readable JSON: %s\n" % exc)
    raise SystemExit(1)
verb, reason = route(payload, mode=sys.argv[1], repair_requested=(sys.argv[2] == "true"))
sys.stderr.write(reason + "\n")
if verb is None:
    raise SystemExit(1)
sys.stdout.write(verb)
'@
  # STDOUT IS THE VALUE; STDERR IS DIAGNOSTIC ONLY (correction F2). This captured with `2>&1`, and
  # the probe writes its REASON to stderr before the verb to stdout - so the returned string was
  # "<reason>`n<verb>" and never equalled a route word. `$stVerb` became the reason text and
  # `storage <garbage>` exited 2: every Windows install and update died at phase 18, after
  # generations 2-4 were already committed. Merging streams into a value used for CONTROL FLOW is
  # the defect; the two are captured separately and only the diagnostic half is logged.
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $repair = $(if ($script:RepairStorageAccess) { 'true' } else { 'false' })
  $errFile = [System.IO.Path]::GetTempFileName()
  $probeFile = New-CfmProbeFile $probe
  try {
    $out = ($observationJson | & $script:Py $probeFile $script:CfmStorageMode $repair 2>$errFile | Out-String)
    $rc = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $eap
    Remove-Item $probeFile -Force -ErrorAction SilentlyContinue
    if (Test-Path $errFile) { Cfm-Logline (Get-Content $errFile -Raw); Remove-Item -Force $errFile -ErrorAction SilentlyContinue }
  }
  if ($rc -ne 0) {
    Die ("storage cannot be routed from this machine's own observation - see the log for the state it reported. Nothing was changed.")
  }
  # EXACTLY ONE ALLOWED ROUTE WORD. Empty, multiline, whitespace-plus-extra and anything unknown all
  # refuse rather than becoming a verb.
  $route = ($out -replace '\s+$', '') -replace '^\s+', ''
  if ($route -notin @('skip','repair','bootstrap','adopt')) {
    Die ("the storage routing boundary returned '" + $route + "', which is not a route this installer recognises. Nothing was changed.")
  }
  return $route
}

# THE FMS CREDENTIAL FRAME (correction C3). `CredentialLease.from_frame` reads two length-prefixed
# UTF-8 fields - four-byte big-endian length, then bytes - and refuses a short read, a trailing byte
# or an empty field. This installer already acquired and VERIFIED the account at phase 7, so asking
# the lifecycle layer to prompt again asks twice for something we hold, and `prompt` cannot be
# answered at all by a -Silent run.
#
# WRITTEN AS BYTES, through StandardInput.BaseStream. The ordinary PowerShell pipeline re-encodes to
# text and appends a line terminator, which would give `from_frame` a trailing byte and a refusal.
# The two values never reach argv (a process list is readable) and never the environment (inherited
# by every child).
# WINDOWS ARGV ENCODING (correction F3). `ProcessStartInfo.ArgumentList` is .NET Core 2.1+; the
# target host is Windows PowerShell 5.1 on .NET Framework, where the property does not exist - so
# the framed launch could not run on the only platform it is for. The repo already knew: the shipped
# `corpusfm-update.ps1` throws rather than assume it. Every token therefore starts life as an argv
# ELEMENT and is encoded exactly once, here, at the single launch boundary.
#
# These are CommandLineToArgvW / CreateProcess rules, not shell rules: backslashes are literal
# EXCEPT immediately before a quote, where each doubles; a closing quote must not be escaped by a
# trailing backslash run. There is no shell, no Invoke-Expression and no cmd.exe anywhere in this.
function Encode-WindowsArgv([string]$value) {
  if ($value -eq '') { return '""' }
  if ($value -notmatch '[ \t"]') { return $value }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  $slashes = 0
  foreach ($ch in $value.ToCharArray()) {
    if ($ch -eq '\') { $slashes++; continue }
    if ($ch -eq '"') {
      [void]$sb.Append('\' * ($slashes * 2 + 1)); [void]$sb.Append('"'); $slashes = 0; continue
    }
    if ($slashes -gt 0) { [void]$sb.Append('\' * $slashes); $slashes = 0 }
    [void]$sb.Append($ch)
  }
  # A trailing backslash run sits immediately before the CLOSING quote, so it doubles too.
  if ($slashes -gt 0) { [void]$sb.Append('\' * ($slashes * 2)) }
  [void]$sb.Append('"')
  return $sb.ToString()
}

function Encode-WindowsCommandLine([string[]]$argv) {
  return (($argv | ForEach-Object { Encode-WindowsArgv $_ }) -join ' ')
}

function Lc-RunFramedRaw($what, [string[]]$LcArgs, $account, $password) {
  # REFUSE A HOST THAT CANNOT DO THIS, rather than discovering it mid-install.
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  foreach ($needed in @('RedirectStandardInput','RedirectStandardOutput','RedirectStandardError')) {
    if ($null -eq $psi.PSObject.Properties[$needed]) {
      Die ("this PowerShell host does not provide ProcessStartInfo." + $needed + "; the credential frame cannot be delivered and no operation was attempted.")
    }
  }
  $psi.FileName = $script:Py                     # the authoritative absolute interpreter
  $psi.Arguments = Encode-WindowsCommandLine (@('-m','corpusfm.lifecycle') + $LcArgs)
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $bytes = $null; $out = ''; $errText = ''
  $proc = [System.Diagnostics.Process]::Start($psi)
  try {
    # READS BEGIN BEFORE THE WAIT (correction F5). Reading stdout to the end and only then stderr
    # deadlocks the moment a child fills the stderr pipe while we are blocked on stdout - and a
    # child that writes diagnostics before reading its stdin deadlocks the other way. Both streams
    # are drained concurrently, and the frame is written while they drain.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $stream = $proc.StandardInput.BaseStream
    foreach ($value in @($account, $password)) {
      $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$value)
      $len = [System.BitConverter]::GetBytes([int]$bytes.Length)
      if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }
      $stream.Write($len, 0, 4)
      if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
      [Array]::Clear($bytes, 0, $bytes.Length)          # the frame material does not linger
    }
    $stream.Flush()
    $proc.StandardInput.Close()
    if (-not $proc.WaitForExit($script:LcFramedTimeoutMs)) {
      try { $proc.Kill() } catch {}
      $proc.WaitForExit(5000) | Out-Null
      Die ("$what did not complete within " + [int]($script:LcFramedTimeoutMs / 1000) + " seconds and was terminated. The services stay STOPPED and nothing further was attempted.")
    }
    $out = $outTask.Result
    $errText = $errTask.Result
  } finally {
    # WIPED ON EVERY PATH - success, refusal, exception and timeout.
    if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    $bytes = $null; $account = $null; $password = $null
    try { $proc.StandardInput.Dispose() } catch {}
  }
  Cfm-Logline ($out + $errText)      # both are provider output; neither carries the frame
  $script:LcRawOut = $out
  $script:LcRawRc = $proc.ExitCode
  if (-not (Lc-IsOneJsonObject $out)) {
    Die ("a lifecycle provider returned output this installer cannot read as one JSON result (exit " +
         $script:LcRawRc + "). See the log. Nothing further was changed.")
  }
  return $out
}

#: Bounded, and generous: a provider call may legitimately talk to FileMaker Server.
$script:LcFramedTimeoutMs = 600000

# `stdin` when we hold a verified FMS administrator, `absent` when we do not. Never `prompt`.
function Lc-FmsTransport {
  if ($script:FmAdminUser -and $script:FmAdminPass) { return 'stdin' }
  return 'absent'
}

function Lc-Run($what, [string[]]$LcArgs) {
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $out = (& $script:Py -m corpusfm.lifecycle @LcArgs 2>&1 | Out-String)
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eap
  Cfm-Logline $out
  Lc-Dispatch $rc $what
  return $out
}

# The named field of a lifecycle result, AS AN OBJECT. A candidate block is nested straight into the
# next request by Lc-CommitProvider, so re-serializing it to a string here would make the commit
# request carry a JSON-encoded string where the schema expects an object.
# EVERY MULTILINE PROBE IS A FILE, NEVER `-c` (packet 1246-10-04). Passing probe source as a native
# argument let Windows PowerShell strip its embedded double quotes on the way into python.exe, and
# the probe died with `SyntaxError: '(' was never closed` while the document it was judging was
# perfectly well-formed. Measured twice on winfms2026 (2026-08-08): the strict status probe, then
# the admin-identity result probe, which turned a readable `no_change` into "could not be
# published". Same text, same arguments, same stdin - written ASCII, executed directly, removed
# either way.
function New-CfmProbeFile($text) {
  $p = Join-Path ([IO.Path]::GetTempPath()) ("corpusfm-probe." + $PID + "." + ([guid]::NewGuid().ToString('N').Substring(0,8)) + ".py")
  # `-c` PUT THE WORKING DIRECTORY ON sys.path AND A SCRIPT FILE DOES NOT - it puts its own
  # directory there instead, which here is the temp directory. Three of these probes import
  # `corpusfm.lifecycle.cli`, so without this line the change of invocation would trade a quoting
  # failure for `ModuleNotFoundError: No module named 'corpusfm'` wherever the interpreter does not
  # already bind the source (the box's `._pth` does; a bare interpreter does not). Restoring the
  # exact import semantics `-c` gave is part of preserving each probe unchanged.
  $prelude = "import os, sys" + "`n" + "sys.path.insert(0, os.getcwd())" + "`n"
  Set-Content -Path $p -Value ($prelude + $text) -Encoding ascii
  return $p
}

function Lc-Field($text, $field) {
  $t = ("" + $text).Trim()
  if (-not $t) { return $null }
  try { $o = ($t | ConvertFrom-Json) } catch { return $null }
  if ($null -eq $o) { return $null }
  return $o.$field
}

# ONE lifecycle observation per invocation (packet 1246-10-04). Phase 2 CLASSIFIES from it and
# phase 3 ROUTES from it. Two invocations could disagree; worse, a second detection path is exactly
# what let the transitional `install.yaml` marker outrank published authority and call a published
# generation-1 installation a fresh install. The observation is made once, validated once here, and
# read by both.
#
# An empty return means "there is no interpreter to ask", which is not the same as "settled" - the
# caller decides what that means for it. Every OTHER unreadable answer refuses inside this function,
# before anything has been changed.
# THE ONE QUESTION THAT SEPARATES AN INSTALLATION FROM DEBRIS: is there an installation AUTHORITY?
# Files on disk are not authority. A locator, a manifest or the legacy marker are. Everything below
# routes on this, so "is this box installed" has exactly one answer and cannot drift between the two
# places that ask it.
function Test-CfmInstallationAuthority {
  $publishedLocator = Test-Path 'HKLM:\SOFTWARE\CORPUSfm\Installation'
  $legacyMarker = Join-Path $LegacyHome 'install.yaml'
  return [bool]($publishedLocator -or (Test-Path $CurrentManifest -PathType Leaf) -or
                (Test-Path $legacyMarker -PathType Leaf))
}

# === packet 1380-02: the SYSTEM updater task's AllSigned check ====================================
#
# The updater task runs as NT AUTHORITY\SYSTEM, non-interactively. SYSTEM is governed by the
# machine-wide execution policy (MachinePolicy, then LocalMachine) and reads only LocalMachine
# certificate stores; the administrator's Process, UserPolicy and CurrentUser scopes, and the fact that
# this script is running at all, say nothing about it. Measured: under AllSigned with the signing leaf
# absent from LocalMachine\TrustedPublisher, a correctly signed script exits 1 (UnauthorizedAccess) and
# no prompt can be answered. So when that machine-wide policy is AllSigned, or cannot be determined, the
# running installer's valid signer leaf must be in LocalMachine\TrustedPublisher. One release is signed
# by one leaf, so the installer's leaf is the updater's leaf.
function Get-CfmSystemTaskTrustVerdict {
  param(
    [string]$MachinePolicy = '',
    [string]$LocalMachine = '',
    [string]$SignatureStatus = '',
    [string]$SignerThumbprint = '',
    [string[]]$LocalMachineThumbprints = @()
  )
  $known = @('AllSigned', 'Bypass', 'Default', 'RemoteSigned', 'Restricted', 'Unrestricted', 'Undefined')
  $policy = 'Undefined'
  foreach ($value in @($MachinePolicy, $LocalMachine)) {
    if ($known -notcontains $value) { $policy = 'Indeterminate'; break }
    if ($value -ne 'Undefined') { $policy = $value; break }
  }
  $result = { param($allow, $reason, $detail)
    [pscustomobject]@{ Allow = $allow; Reason = $reason; Policy = $policy; Detail = $detail } }
  if ($policy -ne 'AllSigned' -and $policy -ne 'Indeterminate') { return (& $result $true 'not_applicable' '') }
  if ($SignatureStatus -ne 'Valid') {
    $observed = if ($SignatureStatus) { $SignatureStatus } else { 'Unreadable' }
    return (& $result $false 'signature_not_valid' $observed)
  }
  if (-not $SignerThumbprint) { return (& $result $false 'no_signer_certificate' '') }
  $want = $SignerThumbprint.Trim().ToUpperInvariant()
  $have = @(foreach ($t in @($LocalMachineThumbprints)) { ([string]$t).Trim().ToUpperInvariant() })
  if ($have -notcontains $want) { return (& $result $false 'leaf_not_in_localmachine_trustedpublisher' $want) }
  return (& $result $true 'trusted' $want)
}

function Assert-CfmSystemTaskTrust {
  param([Parameter(Mandatory=$true)][string]$EntryPoint)
  $machinePolicy = ''; $localMachine = ''
  try { $machinePolicy = [string](Get-ExecutionPolicy -Scope MachinePolicy -ErrorAction Stop) } catch { $machinePolicy = '' }
  try { $localMachine = [string](Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop) } catch { $localMachine = '' }
  $status = ''; $thumb = ''; $subject = ''
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $EntryPoint
    $status = [string]$sig.Status
    if ($sig.SignerCertificate) {
      $thumb = [string]$sig.SignerCertificate.Thumbprint
      $subject = [string]$sig.SignerCertificate.Subject
    }
  } catch { $status = 'Unreadable' }
  $trusted = @()
  try {
    $trusted = @(Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction Stop |
                 ForEach-Object { [string]$_.Thumbprint })
  } catch { $trusted = @() }
  $verdict = Get-CfmSystemTaskTrustVerdict -MachinePolicy $machinePolicy -LocalMachine $localMachine `
               -SignatureStatus $status -SignerThumbprint $thumb -LocalMachineThumbprints $trusted
  if ($verdict.Allow) {
    if ($verdict.Reason -eq 'trusted') {
      Ok ("Updater task trust: signing leaf " + $verdict.Detail + " is in LocalMachine\TrustedPublisher")
    } else {
      Info ("Updater task trust: machine-wide execution policy is " + $verdict.Policy + "; AllSigned does not apply")
    }
    return
  }
  $who = if ($subject) { $subject } else { '(no signer certificate on the running installer)' }
  $what = if ($thumb) { $thumb } else { '(none)' }
  Die ("Refused before any installation change: the CORPUSfm updater task runs as NT AUTHORITY\SYSTEM," +
       " and the machine-wide execution policy (MachinePolicy/LocalMachine) is " + $verdict.Policy + "." + "`n" +
       "     Under that policy SYSTEM runs only scripts whose signing certificate is in LocalMachine\TrustedPublisher." + "`n" +
       "     Reason: " + $verdict.Reason + " (" + $verdict.Detail + ")" + "`n" +
       "     Publisher: " + $who + "`n" +
       "     Certificate thumbprint: " + $what + "`n" +
       "     Your organization deploys that exact certificate to LocalMachine\TrustedPublisher with its own tooling." +
       " The certificate and its details ship with the release: " + $ReleaseLocation + "`n" +
       "     Nothing was installed or changed. Re-run this installer once the certificate is deployed.")
}

# === Windows lifecycle recovery (packet 1380-02, reduced) =========================================
#
# Recovery is the lifecycle CLI run directly by this installer with the runtime this invocation already
# selected: the installed interpreter, or the verified package runtime when Get-LcState or phase 2
# selected it. Execution policy governs script FILES, not python.exe, so recovery needs no staged or
# signed script and takes no publisher-trust dependency. The disposition boundary proposes the family,
# verb and request; the closed table below decides whether that pair may run at all.
function Test-CfmLifecycleRecoverySucceeded([int]$Code) {
  # 0 completed and 2 rolled back are both a recovered journal; everything else is not.
  return ($Code -eq 0 -or $Code -eq 2)
}

function Invoke-CfmLifecycleRecovery {
  $family = "" + $script:LcRecoveryFamily
  $verb = "" + $script:LcRecoveryVerb
  $expectedVerb = switch -CaseSensitive ($family) {
    'patch-compartment' { 'rollback' }
    'proxy' { 'abort' }
    'admin-identity' { 'abort' }
    'storage' { 'abort' }
    default { '' }
  }
  if (-not $expectedVerb -or $verb -cne $expectedVerb) {
    Die "The installer-disposition boundary returned a recovery verb this installer does not run; the journal remains untouched."
  }
  if ($family -ceq 'patch-compartment') {
    $childArgs = @($family, $verb, '--operation-id', ("" + $script:LcOp))
  } else {
    if (-not (Lc-IsOneJsonObject $script:LcRecoveryRequest)) {
      Die "The installer-disposition boundary returned no recovery request document; the journal remains untouched."
    }
    $request = Lc-Request 'installer-recovery' $script:LcRecoveryRequest
    $childArgs = @($family, $verb, '--request', $request)
  }
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    & $script:Py -m corpusfm.lifecycle @childArgs | Out-Host
    $rc = $LASTEXITCODE
  } finally { $ErrorActionPreference = $eap }
  return $rc
}

function Complete-CfmOwedLifecycleRecovery {
  # An owed recovery OWNS this invocation: both outcomes end it, so no new mutation can follow it.
  Info ("Recovering the prior lifecycle operation with the " + $script:RecoveryRuntimeKind + " runtime")
  $recoveryRc = Invoke-CfmLifecycleRecovery
  if (Test-CfmLifecycleRecoverySucceeded $recoveryRc) {
    Die "The prior lifecycle recovery completed. Re-run this Series 2 package to begin a separate installation invocation."
  }
  Die ("The prior lifecycle recovery did not complete (exit " + $recoveryRc +
       "). Its journal and recovery evidence remain in place. Re-run this same verified" +
       " Series 2 package to try recovery again.")
}

$script:LcStateRaw = $null
function Get-LcState {
  # ONE OBSERVATION BY DEFAULT, and that default is load-bearing: phases 2 and 3 classify from the
  # SAME status object, so a second read between them could route on a box that had changed under
  # the classification. Ordinary callers must keep getting the memoized value.
  #
  # `-Refresh` IS THE EXPLICIT EXCEPTION, and it exists because the default silently defeated a
  # verification. A001's post-recovery check called this expecting current state and received the
  # phase-3 observation - taken when the journal was still `open` - so a recovery that had actually
  # succeeded reported "a lifecycle journal is still retained" and aborted the invocation. Measured
  # on w-test-private, 2026-09-03, at generation 9 with the journal already gone.
  #
  # A refresh runs the authoritative status command again, applies EVERY validation below, and
  # stores the successful result back as the new shared observation. It never falls back to the
  # cached value: each failure path here either dies or replaces the cache, so a failed refresh
  # cannot hand a caller the pre-recovery answer it was asking to look past.
  param([switch]$Refresh)
  if (-not $Refresh -and $null -ne $script:LcStateRaw) { return $script:LcStateRaw }
  $lifecyclePackage = Join-Path $script:RecoverySource 'corpusfm\lifecycle\__main__.py'
  $orphanJournal = Join-Path $FixedState 'lifecycle-journal.json'
  if ((Test-Path -LiteralPath $orphanJournal -PathType Leaf) -and
      $script:RecoveryRuntimeKind -ne 'package' -and $InstallerSeries -and $RuntimeTemp) {
    # Always recover retained evidence through the verified package's code.  A runnable installed
    # interpreter can still be the old build whose parser defect made the operation unrecoverable.
    Initialize-PackagedRecoveryRuntime
    $lifecyclePackage = Join-Path $script:RecoverySource 'corpusfm\lifecycle\__main__.py'
  }
  if ((-not (Test-Path $script:Py) -or
       -not (Test-Path $lifecyclePackage -PathType Leaf)) -and
      (Test-Path -LiteralPath $orphanJournal -PathType Leaf)) {
    Initialize-PackagedRecoveryRuntime
    $lifecyclePackage = Join-Path $script:RecoverySource 'corpusfm\lifecycle\__main__.py'
  }
  if (-not (Test-Path $script:Py) -or -not (Test-Path $lifecyclePackage -PathType Leaf)) {
    # Dependency preparation is deliberately resumable. An interrupted fresh run may have created
    # Python/MinGit and the fixed empty support directories without ever installing application
    # source or publishing an installation. Those files are not an installation authority and
    # cannot make a later detection invoke a package that does not exist.
    if (Test-CfmInstallationAuthority) {
      Die ("An installation record exists but its lifecycle application source is unavailable at " +
           $lifecyclePackage + ". This installer will not classify that box as fresh.")
    }
    $script:LcStateRaw = ''
    return $script:LcStateRaw
  }
  # stdout SEPARATE from stderr, and the exit status kept. An unresolved or invalid status
  # legitimately exits non-zero AND carries valid JSON, so the parsed STATE is what routes - never
  # the exit code alone, and never "non-zero means nothing to see".
  $eapS = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $raw = (& $Py -m corpusfm.lifecycle status --json 2>$null | Out-String)
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eapS
  if (-not ($raw.Trim())) {
    # AN UNANSWERABLE INTERPRETER IS NOT AN INSTALLATION (packet 1257). The guard above already
    # treats a MISSING interpreter as resumable preparation; an interpreter that is present but
    # cannot answer is the same situation one step later, and it was refusing outright.
    #
    # Measured on winfms2026: a run interrupted at the asset step left `python\` and `src\` but no
    # venv, so this call exited 1 with a traceback and no stdout - while the box carried no locator,
    # no manifest and no install.yaml. The installer refused here, at phase 2, and so never reached
    # the `-ReplaceExistingInstall` decision that exists for exactly that debris. The box could not
    # be recovered by its own installer.
    #
    # With NO authority present there is nothing to be in flight, so this is traceless debris and
    # classification continues; the replacement decision downstream is what refuses or proceeds, and
    # it still refuses without the flag. With ANY authority present this stays fatal: an
    # installation whose status cannot be read must never be classified as absent.
    if (-not (Test-CfmInstallationAuthority)) {
      Warn ("The lifecycle status could not be read (exit " + $rc + ") and this box carries no" +
            " locator, manifest or install marker - treating " + $InstallDir + " as traceless" +
            " installation debris, not as an installation.")
      $script:LcStateRaw = ''
      return $script:LcStateRaw
    }
    Die ("``corpusfm-lifecycle status --json`` produced no output (exit " + $rc + "). This installer cannot establish whether an operation is in flight and will not guess. Nothing has been changed.")
  }
  # EXACTLY ONE PARSEABLE JSON OBJECT. A second document, a diagnostic that reached stdout, or a
  # truncated write all refuse here rather than being read field-by-field into a false "settled".
  $strict = @'
import json, sys
raw = sys.stdin.read()
try:
    value = json.loads(raw)
except ValueError as exc:
    sys.stderr.write("status --json is not one parseable JSON object: %s\n" % exc)
    raise SystemExit(1)
if not isinstance(value, dict):
    sys.stderr.write("status --json is not a JSON object\n")
    raise SystemExit(1)
if "journal" not in value or "locator" not in value:
    sys.stderr.write("status --json is missing a required field\n")
    raise SystemExit(1)
'@
  # THE PROBE IS A FILE, NEVER `-c` (packet 1246-10-04). Passing this text as a native argument
  # let Windows PowerShell strip its embedded double quotes on the way into python.exe, and the
  # probe died with `SyntaxError: '(' was never closed` while the status output it was meant to
  # judge was perfectly well-formed - a validator that refuses everything is indistinguishable
  # from one that works until the day the thing it guards is actually good. It had never run:
  # every previous Windows invocation began with no interpreter, so the gate above was false.
  # Measured on winfms2026, 2026-08-08, on the first update over a published installation.
  # Same probe text, same contract, executed as a file and removed either way.
  $probeFile = New-CfmProbeFile $strict
  $strictRc = 1
  try {
    $eapS = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    Cfm-Logline (($raw | & $Py $probeFile 2>&1 | Out-String))
    $strictRc = $LASTEXITCODE
    $ErrorActionPreference = $eapS
  } finally {
    Remove-Item $probeFile -Force -ErrorAction SilentlyContinue
  }
  if ($strictRc -ne 0) {
    Die ("``corpusfm-lifecycle status --json`` did not return one well-formed status object (exit " + $rc + "). This installer will not route an operation from output it cannot read, and it has changed nothing.")
  }
  $script:LcStateRaw = $raw
  return $script:LcStateRaw
}

# Commit one provider and verify the generation it produced. The DISCARD is a separate boundary and
# is performed by `Lc-DiscardProvider`: `commit_provider` does not retire a journal record, and this
# comment used to say it did (finding B4). The discard is REQUIRED, not tidy-up - storage answers
# foreign_open on the PRESENCE of any journal record, so a leftover one stops the NEXT provider.
# THE OPERATION ID AND THE CANDIDATE BOTH COME FROM THE PROVIDER (packet 1246-04-04, correction B).
# The installer used to mint a GUID, put it in the provider's request and then commit against it. No
# provider request schema accepts `operation_id` - the provider mints its own and returns it - so
# every one of those requests was refused, and the id the commit named was one nothing had ever used.
# `Lc-ProviderRun` is the only place either value is obtained.
$script:LcCondition = ''; $script:LcCompose = $false; $script:LcRetireProvider = ''
$script:LcRecoveryFamily = ''; $script:LcRecoveryVerb = ''; $script:LcRecoveryRequest = ''
$script:LcDispositionReason = ''
$script:LcFirstAdminOwedByDisposition = $false

function Lc-PreflightDisposition {
  $probe = @'
import json, sys
sys.path.insert(0, sys.argv[1])
from corpusfm.lifecycle.installer_disposition import classify
with open(sys.argv[2], encoding="utf-8") as handle:
    journal = json.load(handle)
request = {
    "schema_version": 1, "phase": "preflight", "provider": None, "exit_code": None,
    "installation_id": None, "expected_generation": None, "mode": None,
    "install_dir": sys.argv[3], "platform": "windows", "provider_result": None,
    "journal": journal,
}
print(json.dumps(classify(request), separators=(",", ":"), sort_keys=True))
'@
  $probeFile = New-CfmProbeFile $probe
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $disp = (& $script:Py $probeFile $script:RecoverySource $script:CfmJournalFile `
      $script:InstallDir 2>$errFile | Out-String)
    $rc = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $eap
    Remove-Item $probeFile -Force -ErrorAction SilentlyContinue
    if (Test-Path $errFile) {
      Cfm-Logline (Get-Content $errFile -Raw)
      Remove-Item -Force $errFile -ErrorAction SilentlyContinue
    }
  }
  if ($rc -ne 0 -or -not (Lc-IsOneJsonObject $disp)) {
    Die "The shared installer-disposition boundary could not classify the prior lifecycle journal. It remains untouched; see the log."
  }
  Cfm-Logline $disp
  $script:LcCondition = "" + (Lc-Field $disp 'condition')
  $script:LcRetireProvider = "" + (Lc-Field $disp 'retire_provider')
  $script:LcOp = "" + (Lc-Field $disp 'operation_id')
  $script:LcRecoveryFamily = "" + (Lc-Field $disp 'recovery_family')
  $script:LcRecoveryVerb = "" + (Lc-Field $disp 'recovery_verb')
  $script:LcRecoveryRequest = "" + (Lc-Field $disp 'recovery_request')
  $script:LcDispositionReason = "" + (Lc-Field $disp 'reason')
}

function Resume-PackagedInterruptedUninstall([string]$InstallationId) {
  $transport = 'prompt'
  if ($Silent) {
    $transport = if ($script:FmAdminUser -and $script:FmAdminPass) { 'stdin' } else { 'none' }
  }
  $request = Lc-Request 'resume-interrupted-uninstall' (Lc-Json ([ordered]@{
    schema_version = 2
    installation_id = $InstallationId
    actor = 'installer-package-recovery'
    force = $false
    credential_transport = $transport
  }))
  $args = @('uninstall','resume','--request',$request)
  if ($transport -eq 'stdin') {
    $out = Lc-RunFramedRaw 'interrupted uninstall recovery' $args `
      $script:FmAdminUser $script:FmAdminPass
    $rc = $script:LcRawRc
  } else {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
      $out = (& $script:Py -m corpusfm.lifecycle @args 2>&1 | Out-String)
      $rc = $LASTEXITCODE
    } finally { $ErrorActionPreference = $eap }
    Cfm-Logline $out
  }
  try { $result = $out | ConvertFrom-Json } catch {
    Die ("Interrupted uninstall recovery returned no readable result (exit " + $rc +
         "); its journal remains untouched.")
  }
  switch ($rc) {
    0 { Die ("The interrupted uninstall recovery completed (" + $result.result +
             "). Re-run this Series 2 package to begin a separate fresh installation invocation.") }
    3 { Die ("The interrupted uninstall still needs administrator action (" + $result.reason +
             "). " + $result.detail + " Re-run this same verified Series 2 package afterward.") }
    5 { Die ("The interrupted uninstall remains safely resumable (" + $result.reason +
             "). " + $result.detail + " Re-run this same verified Series 2 package to continue.") }
    default { Die ("Interrupted uninstall recovery failed or refused (exit " + $rc + ", " +
                   $result.reason + "). " + $result.detail +
                   " Its journal and recovery evidence remain untouched.") }
  }
}

# -- The fresh-install attempt (packet 1398) ------------------------------------------------------
# A fresh install that fails part-way leaves resources nothing else owns. From consent onward, a
# no-authority fresh run records every durable mutation in a protected attempt record BEFORE it
# happens: observe the exact target, publish the intent with that prior, mutate, then publish the
# result - a failed command publishes its post-observation too. The record is the only ownership
# evidence a later Discard may use (corpusfm.lifecycle.install_attempt reads and validates it).
#
# EVERY WRAPPER BELOW IS A PASS-THROUGH WHEN NO ATTEMPT IS ACTIVE: an update, and every run that is
# not a no-authority fresh start, executes exactly the command it always did.
#
# Native PowerShell writes the record (packet 1398 section 2.4). The whole document is serialized
# from this process's own data, staged inside the protected container, flushed, replaced,
# re-protected and read back. Nothing here reads a record back in order to re-serialize it.
$script:CfmAttempt = $false
$script:AttemptDir = Join-Path (Split-Path $ConfigHome -Parent) 'CORPUSfm-Attempt'
$script:AttemptRecord = $null
$script:AttemptId = ''
$script:LaSeqs = @()
$script:LaLeftoverEmpty = $false
$script:LaRouteDeferred = $false
$script:LaProviderIntent = ''
$script:LaProviderPrior = $null
$script:LaProviderSeqs = @()
$script:LaProviderTargetSeqs = @()
$script:LaLifecycleRc = 0
# The closed WINDOWS vocabulary this installer writes (rulings 5 and 6). `journal` is written by the
# application's discard and never here; `set_owner_mode`, `account`, `unit`, `package_set` and
# `firewall_rule` are POSIX.
$script:LaKinds = [ordered]@{
  'dir'              = @('create', 'set_acl', 'move_aside')
  'file'             = @('create', 'overwrite', 'append', 'delete')
  'service'          = @('create')
  'task'             = @('create')
  'git_config_entry' = @('append', 'unset')
  'iis_setting'      = @('enable_arr_proxy')
  'provider_op'      = @('foundation', 'provision_keys', 'admin_identity_reconcile', 'patch_apply',
                         'proxy_reconcile', 'storage_bootstrap', 'storage_adopt', 'create_first_admin',
                         'retire_scheduler_authority', 'backfill_storage_projections')
}
$script:LaFsKinds = @('dir', 'file')
$script:LaAllowedSids = @('S-1-5-18', 'S-1-5-32-544')

function La-RefuseFirst {
  # Packet 1398 section 4.2, Windows: the install root, install.yaml, the web service, the task.
  return @(
    @{ kind = 'dir';     target = $script:InstallDir },
    @{ kind = 'file';    target = (Join-Path $script:FixedConfig 'install.yaml') },
    @{ kind = 'service'; target = $script:WebService },
    @{ kind = 'task';    target = '\CORPUSfm Update' }
  )
}

function La-Now { return (Get-Date).ToUniversalTime().ToString('o') }
function La-PathItem([string]$Path) { return (Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue) }
function La-Parent([string]$Path) { return (Split-Path $Path -Parent) }
function La-Sddl([string]$Path) { return ("" + (Get-Acl -LiteralPath $Path).Sddl) }
function La-Sha256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function La-Canon([string]$Path) {
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
  return $full
}

function La-Inside([string]$Child, [string]$Parent) {
  $c = (La-Canon $Child).ToLowerInvariant()
  $p = (La-Canon $Parent).ToLowerInvariant().TrimEnd('\')
  return (($c -ne $p) -and $c.StartsWith($p + '\'))
}

function La-ProtectedSecurity([bool]$Directory) {
  if ($Directory) { $sec = New-Object System.Security.AccessControl.DirectorySecurity }
  else { $sec = New-Object System.Security.AccessControl.FileSecurity }
  $sec.SetAccessRuleProtection($true, $false)
  $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $sec.SetOwner($admins)
  $inherit = [System.Security.AccessControl.InheritanceFlags]::None
  if ($Directory) { $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
  foreach ($sid in @($system, $admins)) {
    $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
      $sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
      [System.Security.AccessControl.PropagationFlags]::None,
      [System.Security.AccessControl.AccessControlType]::Allow)))
  }
  return $sec
}

function La-SetProtected([string]$Path, [bool]$Directory) {
  Set-Acl -LiteralPath $Path -AclObject (La-ProtectedSecurity $Directory)
}

function La-AuthorityProblem([string]$Path) {
  # The application's rule, in the same terms: a protected DACL, nothing inherited, owned by
  # Administrators or SYSTEM, and nobody else named.
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) { return ($Path + ' does not carry a protected DACL') }
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($script:LaAllowedSids -notcontains $owner) { return ($Path + ' is owned by ' + $owner) }
  foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.IsInherited) { return ($Path + ' inherits access from its parent') }
    if ($script:LaAllowedSids -notcontains $rule.IdentityReference.Value) {
      return ($Path + ' grants access to ' + $rule.IdentityReference.Value)
    }
  }
  return ''
}

function La-ContainerProblem {
  $item = La-PathItem $script:AttemptDir
  if (-not $item) { return ($script:AttemptDir + ' does not exist') }
  if (-not $item.PSIsContainer) { return ($script:AttemptDir + ' is not a directory') }
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return ($script:AttemptDir + ' is a reparse point') }
  return (La-AuthorityProblem $script:AttemptDir)
}

function La-ContainerIsEmpty {
  $item = La-PathItem $script:AttemptDir
  if (-not $item -or -not $item.PSIsContainer) { return $false }
  $foreign = @(Get-ChildItem -LiteralPath $script:AttemptDir -Force |
               Where-Object { $_.Name -notmatch '^\.(attempt|pending|journal)\.json\..+\.tmp$' })
  return ($foreign.Count -eq 0)
}

function La-Write {
  $problem = La-ContainerProblem
  if ($problem) {
    Die ("The fresh-install attempt container is not protected: " + $problem + ". Nothing further was changed.")
  }
  $json = ConvertTo-Json -InputObject $script:AttemptRecord -Depth 20
  $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json + "`n")
  $record = Join-Path $script:AttemptDir 'attempt.json'
  $staged = Join-Path $script:AttemptDir ('.attempt.json.' + [guid]::NewGuid().ToString('N') + '.tmp')
  $stream = [IO.File]::Open($staged, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  try {
    La-SetProtected $staged $false
    # [NullString]::Value, never $null: PowerShell converts $null to '' for a .NET string argument,
    # and File.Replace refuses an empty backup path (measured under pwsh).
    if (Test-Path -LiteralPath $record) { [IO.File]::Replace($staged, $record, [NullString]::Value) }
    else { [IO.File]::Move($staged, $record) }
  } catch {
    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    Die ("The fresh-install attempt record could not be published: " + $_.Exception.Message)
  }
  La-SetProtected $record $false
  $sha = [Security.Cryptography.SHA256]::Create()
  if ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($record))) -ne
      [BitConverter]::ToString($sha.ComputeHash($bytes))) {
    Die "The fresh-install attempt record did not read back as written."
  }
  $problem = La-AuthorityProblem $record
  if ($problem) { Die ("The fresh-install attempt record is not protected: " + $problem) }
}

function La-ServiceState([string]$Name) {
  $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $Name + "'") -ErrorAction SilentlyContinue
  if (-not $svc) { return [ordered]@{ exists = $false } }
  $path = "" + $svc.PathName
  if (-not $path) { $path = '<unreadable>' }
  return [ordered]@{ exists = $true; binary_path = $path }
}

function La-TaskState([string]$Target) {
  $task = Get-ScheduledTask -TaskName $Target.TrimStart('\') -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $task) { return [ordered]@{ exists = $false } }
  return [ordered]@{ exists = $true; task_path = ("" + $task.TaskPath + $task.TaskName) }
}

function La-Observe([string]$Kind, [string]$Intent, [string]$Target, $Extra) {
  # The exact current facts for one target, in the ledger shape for its kind.
  if ($script:LaFsKinds -contains $Kind) {
    $item = La-PathItem $Target
    if (-not $item) { return [ordered]@{ exists = $false } }
    $isDir = [bool]$item.PSIsContainer
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($isDir -ne ($Kind -eq 'dir'))) {
      Die ("An unexpected object stands at " + $Target + "; the fresh-install attempt refuses before any change.")
    }
    if ($isDir) { return [ordered]@{ exists = $true; type = 'dir'; sddl = (La-Sddl $Target) } }
    return [ordered]@{ exists = $true; type = 'file'; size = [long]$item.Length
                       sha256 = (La-Sha256 $Target); sddl = (La-Sddl $Target) }
  }
  if ($Kind -eq 'service') { return (La-ServiceState $Target) }
  if ($Kind -eq 'task') { return (La-TaskState $Target) }
  if ($Kind -eq 'git_config_entry') {
    $exists = [bool](Test-Path -LiteralPath $Target -PathType Leaf)
    $sha = $null
    if ($exists) { $sha = La-Sha256 $Target }
    return [ordered]@{ file = $Target; exists = $exists; sha256 = $sha; values = @($Extra.values) }
  }
  return $Extra
}

function La-EntriesFor($Ledger, [string]$Kind, [string]$Target) {
  $found = @()
  foreach ($e in $Ledger) {
    if ($e.kind -ne $Kind) { continue }
    if ($script:LaFsKinds -contains $Kind) { $same = ((La-Canon $e.target) -ieq (La-Canon $Target)) }
    else { $same = ($e.target -eq $Target) }
    if ($same) { $found += ,$e }
  }
  $moved = -1
  for ($i = 0; $i -lt $found.Count; $i++) {
    if ($found[$i].intent -eq 'move_aside' -and $found[$i].state -eq 'done') { $moved = $i }
  }
  # Returned UNROLLED: every caller wraps the answer in @(...). A unary-comma return would arrive as
  # one element holding the array, and an empty answer would count as one entry (measured under pwsh).
  if ($moved -ge 0) { return @($found | Select-Object -Skip ($moved + 1)) }
  return $found
}

function La-Contained($Ledger, [string]$Target) {
  foreach ($e in $Ledger) {
    if ($e.kind -eq 'dir' -and $e.intent -eq 'create' -and $e.prior.Count -eq 1 -and
        $e.prior.exists -eq $false -and (La-Inside $Target $e.target)) { return $true }
  }
  return $false
}

function La-Created([string]$Kind, [string]$Target) {
  $found = @(La-EntriesFor $script:AttemptRecord.ledger $Kind $Target)
  return ($found.Count -gt 0 -and $found[0].intent -eq 'create' -and $found[0].prior.exists -eq $false -and
          ($found[0].state -eq 'done' -or $found[0].state -eq 'intended'))
}

function La-SeqOf([string]$Kind, [string]$Target) {
  $found = @(La-EntriesFor $script:AttemptRecord.ledger $Kind $Target)
  if ($found.Count) { return [int]$found[$found.Count - 1].seq }
  return 0
}

function La-Step([string]$Kind, [string]$Intent, $Extra, [string[]]$Targets) {
  $script:LaSeqs = @()
  if (-not $script:LaKinds.Contains($Kind)) { Die ("Unknown fresh-install ledger kind " + $Kind) }
  $ledger = $script:AttemptRecord.ledger
  $before = @($ledger.ToArray())
  $planned = New-Object System.Collections.ArrayList
  $fs = $script:LaFsKinds -contains $Kind
  if ($fs -and ($Intent -eq 'ensure' -or $Intent -eq 'create')) {
    foreach ($t in $Targets) {
      $chain = @()
      $parent = La-Parent (La-Canon $t)
      while ($parent -and -not (La-PathItem $parent)) { $chain = @($parent) + $chain; $parent = La-Parent $parent }
      foreach ($a in $chain) { [void]$planned.Add(@('dir', $a)) }
    }
  }
  foreach ($t in $Targets) {
    if ($fs) { [void]$planned.Add(@($Kind, (La-Canon $t))) } else { [void]$planned.Add(@($Kind, $t)) }
  }
  $refuse = La-RefuseFirst
  $seqs = @()
  foreach ($p in $planned) {
    $entryKind = $p[0]; $target = $p[1]
    $entryFs = $script:LaFsKinds -contains $entryKind
    if ($entryFs -and (La-Contained $before $target)) { continue }
    if (@($ledger | Where-Object { $_.intent -eq 'create' -and $_.state -eq 'intended' -and $_.kind -eq $entryKind -and
          $_.target -ieq $target -and $_.seq -gt $before.Count }).Count) { continue }
    $word = $Intent
    if ($entryKind -ne $Kind) { $word = 'create' }
    $present = $false
    if ($entryFs) { $present = [bool](La-PathItem $target) }
    elseif ($entryKind -eq 'service') { $present = [bool](La-ServiceState $target).exists }
    elseif ($entryKind -eq 'task') { $present = [bool](La-TaskState $target).exists }
    if ($word -eq 'ensure') {
      if ($entryKind -eq 'dir') { if ($present) { $word = 'set_acl' } else { $word = 'create' } }
      elseif ($entryKind -eq 'file') { if ($present) { $word = 'overwrite' } else { $word = 'create' } }
      else { $word = 'create' }
    }
    if ($script:LaKinds[$entryKind] -notcontains $word) {
      Die ("Intent " + $word + " is not allowed for the fresh-install ledger kind " + $entryKind)
    }
    if ($word -eq 'delete' -and $entryFs -and -not $present) { continue }
    if ($present -and @('create', 'set_acl', 'overwrite') -contains $word) {
      foreach ($r in $refuse) {
        if ($r.kind -ne $entryKind) { continue }
        if ($entryFs) { $match = ((La-Canon $r.target) -ieq $target) } else { $match = ($r.target -eq $target) }
        if ($match -and @(La-EntriesFor $before $entryKind $target).Count -eq 0) {
          Die ("REFUSE-FIRST: " + $target + " already exists and no ledger entry of this attempt created it." +
               " A fresh install does not take over a CORPUSfm resource it cannot account for. Re-run the" +
               " installer to inspect or discard the incomplete attempt.")
        }
      }
    }
    $entry = [ordered]@{
      seq        = [int]($ledger.Count + 1)
      target     = $target
      kind       = $entryKind
      intent     = $word
      prior      = (La-Observe $entryKind $word $target $Extra)
      state      = 'intended'
      post       = $null
      intent_utc = (La-Now)
      result_utc = $null
    }
    [void]$ledger.Add($entry)
    $seqs += [int]$entry.seq
  }
  if ($seqs.Count) { La-Write }
  $script:LaSeqs = $seqs
}

function La-Result($Seqs, [string]$State, $Extra) {
  $list = @($Seqs | Where-Object { $_ })
  if ($list.Count -eq 0) { return }
  foreach ($seq in $list) {
    $entry = $script:AttemptRecord.ledger[[int]$seq - 1]
    if ($entry.state -ne 'intended') { Die ("Fresh-install ledger entry " + $seq + " is not awaiting a result.") }
    if ($entry.kind -eq 'dir' -and $entry.intent -eq 'move_aside' -and -not (La-PathItem $entry.target)) {
      $post = [ordered]@{ exists = $false; moved_to = $Extra.moved_to }
    } else {
      $post = La-Observe $entry.kind $entry.intent $entry.target $Extra
    }
    $entry.state = $State
    $entry.post = $post
    $entry.result_utc = (La-Now)
  }
  La-Write
}

function La-Do([string]$Kind, [string]$Intent, $Extra, [string[]]$Targets, [scriptblock]$Action) {
  if (-not $script:CfmAttempt) { return (& $Action) }
  La-Step $Kind $Intent $Extra $Targets
  $seqs = $script:LaSeqs
  $ok = $false
  try {
    $global:LASTEXITCODE = 0
    $out = & $Action
    $ok = ($LASTEXITCODE -eq 0)
    return $out
  } finally {
    if ($ok) { La-Result $seqs 'done' $Extra } else { La-Result $seqs 'failed' $Extra }
  }
}

function La-KeysPrior {
  return [ordered]@{
    corpus_key     = [bool](Test-Path -LiteralPath (Join-Path $script:FixedSecrets 'corpus.key'))
    machine_key    = [bool](Test-Path -LiteralPath (Join-Path $script:FixedSecrets 'machine.key'))
    session_secret = [bool](Test-Path -LiteralPath (Join-Path $script:FixedSecrets 'session_secret'))
  }
}

function La-ProviderBegin([string]$Intent, $Prior, [string]$Target) {
  $script:LaProviderSeqs = @()
  if (-not $script:CfmAttempt) { return }
  if (-not $Intent -or $null -eq $Prior) {
    Die "A provider call reached the fresh-install attempt with no recorded observation."
  }
  La-Step 'provider_op' $Intent $Prior @($Target)
  $script:LaProviderSeqs = $script:LaSeqs
}

function La-JsonObject([string]$Text) {
  $t = ("" + $Text).Trim()
  foreach ($candidate in @($t, $(if ($t.IndexOf('{') -ge 0) { $t.Substring($t.IndexOf('{')) } else { '' }))) {
    if (-not $candidate) { continue }
    try {
      $o = $candidate | ConvertFrom-Json -ErrorAction Stop
      if ($o -is [System.Management.Automation.PSCustomObject]) { return $o }
    } catch {}
  }
  return (New-Object PSObject)
}

function La-ProviderPost([string]$Intent, [int]$Rc, [string]$Text) {
  $words = @('completed', 'no_change', 'rolled_back', 'incomplete_safe', 'manual_action_required',
             'failed_before_change')
  $out = La-JsonObject $Text
  $word = "" + $out.result
  if ($words -notcontains $word) {
    switch ($Rc) {
      0 { $word = 'completed' }
      1 { $word = 'failed_before_change' }
      2 { $word = 'rolled_back' }
      3 { $word = 'manual_action_required' }
      5 { $word = 'incomplete_safe' }
      default { $word = 'manual_action_required' }
    }
  }
  if ($Intent -eq 'backfill_storage_projections') {
    if ($Rc -eq 0) { $word = 'completed' } else { $word = 'incomplete_safe' }
  }
  $post = [ordered]@{ result = $word }
  $facts = $out.attempt_facts
  switch ($Intent) {
    'foundation' {
      $g = $out.generation
      if (($g -is [int] -or $g -is [long]) -and $g -ge 1) { $post.generation = [int]$g } else { $post.generation = $null }
    }
    'provision_keys' {
      $generated = @(); $reused = @()
      foreach ($k in @($out.keys)) {
        if (-not $k -or -not $k.name) { continue }
        if ($k.action -eq 'generated') { $generated += ("" + $k.name) }
        elseif ($k.action -eq 'reused') { $reused += ("" + $k.name) }
      }
      $post.generated = $generated
      $post.reused = $reused
    }
    'admin_identity_reconcile' { $post.committed = $false }
    'patch_apply' {
      $shaped = $facts -and ($facts.settled -is [bool]) -and ($facts.slot_touched -is [bool]) -and
                ($facts.directory_created_by_this_run -is [bool]) -and ($facts.sandbox_existed -is [bool]) -and
                (@($facts.PSObject.Properties.Name) -contains 'slot_before')
      if ($shaped) {
        $post.settled = $facts.settled
        $post.slot_touched = $facts.slot_touched
        $before = $null
        if ($null -ne $facts.slot_before) {
          $before = [ordered]@{ fms_path = $facts.slot_before.fms_path; enabled = [bool]$facts.slot_before.enabled }
        }
        $post.slot_before = $before
        $post.directory_created_by_this_run = $facts.directory_created_by_this_run
        $post.sandbox_existed = $facts.sandbox_existed
      } else {
        # Unreadable facts never authorize removal: report the adoption as settled.
        $post.settled = $true; $post.slot_touched = $false; $post.slot_before = $null
        $post.directory_created_by_this_run = $false; $post.sandbox_existed = $true
      }
    }
    'proxy_reconcile' {
      $family = [ordered]@{}
      if ($facts -and $null -ne $facts.prior_family) {
        foreach ($prop in $facts.prior_family.PSObject.Properties) {
          $f = $prop.Value
          $marker = "" + $f.marker_state
          if (-not $marker) { $marker = 'unknown' }
          $family[$prop.Name] = [ordered]@{ pool_existed = [bool]$f.pool_existed; app_existed = [bool]$f.app_existed
                                            marker_state = $marker; include_present = [bool]$f.include_present }
        }
      } else {
        foreach ($t in @($script:CfmProxyTypes)) {
          $family[$t] = [ordered]@{ pool_existed = $true; app_existed = $true; marker_state = 'unknown'
                                    include_present = $true }
        }
      }
      $post.prior_family = $family
    }
    'create_first_admin' { $post.created = ($Rc -eq 0 -and $word -eq 'completed') }
  }
  return $post
}

function La-ProviderEnd([string]$Intent, [int]$Rc, [string]$Text) {
  if (-not $script:CfmAttempt) { return }
  $post = La-ProviderPost $Intent $Rc $Text
  $state = 'failed'
  if ($Rc -eq 0) { $state = 'done' }
  La-Result $script:LaProviderSeqs $state $post
  $script:LaProviderSeqs = @()
  if (@($script:LaProviderTargetSeqs).Count) {
    La-Result $script:LaProviderTargetSeqs $state $null
    $script:LaProviderTargetSeqs = @()
  }
}

# `Lc-Run`, write-ahead. The ordinary path IS `Lc-Run`; an attempt publishes the intent, runs the verb,
# publishes the result, and only then dispatches the exit code.
function La-LcRun([string]$Intent, $Prior, [string]$What, [string[]]$LcArgs) {
  if (-not $script:CfmAttempt) { return (Lc-Run $What $LcArgs) }
  La-ProviderBegin $Intent $Prior $Intent
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $out = (& $script:Py -m corpusfm.lifecycle @LcArgs 2>&1 | Out-String)
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eap
  Cfm-Logline $out
  La-ProviderEnd $Intent $rc $out
  Lc-Dispatch $rc $What
  return $out
}

# -- Rerun routing: Inspect / Discard / Quit (packet 1398 section 7) ------------------------------
function La-Field($Text, [string[]]$Keys) {
  $v = La-JsonObject $Text
  foreach ($k in $Keys) { if ($null -eq $v) { return '' }; $v = $v.$k }
  if ($null -eq $v) { return '' }
  return $v
}

function La-Lifecycle([string[]]$LcArgs) {
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $out = (& $script:Py -m corpusfm.lifecycle @LcArgs 2>$null | Out-String)
    $script:LaLifecycleRc = $LASTEXITCODE
  } finally { $ErrorActionPreference = $eap }
  Cfm-Logline $out
  return $out
}

function La-AttemptInspect([string]$InstallationId, [switch]$WithCommands) {
  $req = Lc-Request 'attempt-inspect' (Lc-Json ([ordered]@{
    schema_version = 1; installation_id = $InstallationId; actor = 'installer' }))
  $report = La-JsonObject (La-Lifecycle @('attempt', 'inspect', '--request', $req))
  $planReq = Lc-Request 'attempt-plan' (Lc-Json ([ordered]@{
    schema_version = 2; installation_id = $InstallationId; actor = 'installer'; force = $false
    credential_transport = 'none' }))
  $plan = La-JsonObject (La-Lifecycle @('uninstall', 'plan', '--request', $planReq))
  $observed = $null
  if ($report.package) { $observed = $report.package.observed }
  $recorded = 'development'
  if ($observed) { $recorded = ("" + $observed.installer_series + " / " + $observed.installer_version + " @ " + $observed.application_commit) }
  $running = 'development'
  if ($InstallerSeries) { $running = ($InstallerSeries + " / " + $InstallerVersion + " @ " + $PackageCommit) }
  Info ("Attempt:       " + $report.attempt_id)
  Info ("Installation:  " + $report.installation_id)
  Info ("State:         " + $report.state + " (phase " + $report.phase + ")")
  Info ("Recorded by:   " + $recorded)
  Info ("Running now:   " + $running)
  if ($report.reason) { Info ("Finding:       " + $report.reason + ": " + $report.detail) }
  Info "Recorded changes (seq, kind, intent, state, class, target):"
  foreach ($row in @($report.ledger)) {
    if (-not $row) { continue }
    $class = "" + $row.class
    if (-not $class) { $class = 'reported' }
    Info ("  " + $row.seq + "  " + $row.kind + "  " + $row.intent + "  " + $row.state + "  " + $class + "  " + $row.target)
  }
  $removes = @($plan.operations | Where-Object { $_ } | ForEach-Object { "" + $_.resource })
  if ($removes.Count) { Info ("Discard would remove or restore: " + ($removes -join ', ')) }
  foreach ($kept in @($plan.retained)) {
    if ($kept) { Info ("Discard would keep " + $kept.resource + " (" + $kept.because + ")") }
  }
  Info "Kept and reported: every row above whose class is not 'created' (logs are always kept)."
  if ($WithCommands -and @($report.manual_commands).Count) {
    Warn "Verified cleanup cannot run here. These commands remove only what this attempt recorded creating, newest first; read them before running any:"
    foreach ($command in @($report.manual_commands)) { Write-Host ("    " + $command) }
  }
}

function La-AttemptDiscard([string]$InstallationId) {
  if ($script:RecoveryRuntimeKind -ne 'package') {
    La-AttemptInspect $InstallationId -WithCommands
    # The protected attempt record and its frozen plan are the deletion authority; no package identity
    # grants any, and "verified" here is not an Authenticode claim. A complete package runtime is an
    # EXECUTION requirement: cleanup may remove the installed runtime that would otherwise be running it.
    Die ("Executable Discard needs a complete private CORPUSfm Series 2 package, whose own runtime keeps" +
         " running while cleanup removes the installed one. Deletion authority is the protected attempt" +
         " record and its frozen plan, not the package. The commands above are the bounded filesystem" +
         " fallback; to discard through verified cleanup, rerun a complete private package. Nothing has" +
         " been changed.")
  }
  $account = $env:FM_ADMIN_USER; $password = $env:FM_ADMIN_PASS
  $transport = 'prompt'
  if ($Silent) { if ($account -and $password) { $transport = 'stdin' } else { $transport = 'none' } }
  La-AttemptInspect $InstallationId
  $request = Lc-Request 'attempt-discard' (Lc-Json ([ordered]@{
    schema_version = 2; installation_id = $InstallationId; actor = 'installer'; force = $false
    credential_transport = $transport }))
  $discardArgs = @('uninstall', 'start', '--request', $request)
  Info "Discarding the incomplete fresh-install attempt with the verified package runtime"
  if ($transport -eq 'stdin') {
    $out = Lc-RunFramedRaw 'the incomplete attempt discard' $discardArgs $account $password
    $rc = $script:LcRawRc
  } else {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
      $out = (& $script:Py -m corpusfm.lifecycle @discardArgs 2>&1 | Out-String)
      $rc = $LASTEXITCODE
    } finally { $ErrorActionPreference = $eap }
    Cfm-Logline $out
  }
  $account = $null; $password = $null
  $result = La-JsonObject $out
  if ($rc -eq 0) {
    Ok ("The incomplete fresh-install attempt was discarded (" + $result.result + ").")
    Write-Host "  Everything listed above as kept or reported remains in place; logs were preserved."
    Write-Host "  Run the installer again to start a fresh installation."
    Lc-Cleanup
    exit 0
  }
  if ($rc -eq 3 -or $rc -eq 5) {
    Die ("The discard stopped safely part-way (" + $result.result + "; " + $result.reason + "). " +
         $result.detail + " Re-run this same verified package and choose Discard again.")
  }
  if (("" + $result.reason) -eq 'lock_unavailable') { La-AttemptInspect $InstallationId -WithCommands }
  Die ("The discard refused (" + $result.result + "; " + $result.reason + "). " + $result.detail +
       " The attempt record is unchanged.")
}

function La-AttemptMenu([string]$State, [string]$InstallationId) {
  Warn ("An earlier CORPUSfm fresh installation stopped part-way (" + $State + "). It must be discarded" +
        " before a new installation can start; nothing it recorded is continued or published.")
  if ($DiscardIncompleteAttempt) { La-AttemptDiscard $InstallationId }
  if ($Silent) {
    La-AttemptInspect $InstallationId
    Die ("failed_before_change: an incomplete fresh-install attempt owns this machine. Review the summary" +
         " above, then re-run with -DiscardIncompleteAttempt to discard it. Nothing has been changed.")
  }
  while ($true) {
    $reply = Read-Host "  [I] Inspect  [D] Discard  [Q] Quit"
    if ($reply -match '^[Ii]$') { La-AttemptInspect $InstallationId }
    elseif ($reply -match '^[Dd]$') { La-AttemptDiscard $InstallationId }
    elseif ($reply -match '^[Qq]$') { Write-Host "  Quit - nothing changed."; Lc-Cleanup; exit 0 }
    else { Write-Host "  Choose I, D or Q." }
  }
}

function La-RouteExistingAttempt([string]$Pass) {
  $savedPy = $script:Py; $savedSource = $script:RecoverySource; $savedKind = $script:RecoveryRuntimeKind
  if ($InstallerSeries -and $RuntimeTemp -and
      (Test-Path -LiteralPath (Join-Path $RuntimeRoot 'corpusfm-recovery-source.zip') -PathType Leaf)) {
    Initialize-PackagedRecoveryRuntime
  } elseif (-not ((Test-Path -LiteralPath $script:Py) -and
                  (Test-Path -LiteralPath (Join-Path $Src 'corpusfm\lifecycle\__main__.py')))) {
    Die ("This machine holds an incomplete CORPUSfm fresh-install attempt at " + $script:AttemptDir +
         ", and this installer carries no verified lifecycle runtime to read it. Re-run from a complete" +
         " verified Series 2 package. Nothing has been changed.")
  }
  $state = La-Lifecycle @('status', '--json')
  if (-not ("" + $state).Trim()) {
    Die ("corpusfm-lifecycle status --json produced no output beside the attempt container " +
         $script:AttemptDir + ". Nothing has been changed.")
  }
  $st = "" + (La-Field $state @('fresh_attempt', 'state'))
  $inst = "" + (La-Field $state @('fresh_attempt', 'installation_id'))
  $attempt = "" + (La-Field $state @('fresh_attempt', 'attempt_id'))
  if (-not $st -or $st -eq 'none') { return }
  if ($st -eq 'leftover_empty_container') { $script:LaLeftoverEmpty = $true; return }
  if ($st -eq 'complete_stale_record') {
    $req = Lc-Request 'attempt-complete-stale' (Lc-Json ([ordered]@{
      schema_version = 1; installation_id = $inst; attempt_id = $attempt; actor = 'installer' }))
    $out = La-Lifecycle @('attempt', 'complete', '--request', $req)
    if ($script:LaLifecycleRc -ne 0) {
      Die ("A completed installation still carries its attempt record, and it could not be retired (" +
           (La-Field $out @('reason')) + ": " + (La-Field $out @('detail')) + "). Nothing else changed.")
    }
    Ok "Retired the completed installation's leftover attempt record"
    # This invocation continues as the ordinary run it would have been: the recovery runtime prepared
    # to read the record does not become its lifecycle runtime.
    $script:Py = $savedPy; $script:RecoverySource = $savedSource; $script:RecoveryRuntimeKind = $savedKind
    return
  }
  if ($st -eq 'undecidable') {
    Die ("The fresh-install attempt at " + $script:AttemptDir + " cannot be trusted: " +
         (La-Field $state @('fresh_attempt', 'reason')) + ": " + (La-Field $state @('fresh_attempt', 'detail')) +
         ". Nothing has been changed, and no cleanup command is offered for a record that cannot be verified.")
  }
  if ($st -eq 'post_foundation' -and $Pass -eq 'first') {
    $journal = "" + (La-Field $state @('journal'))
    if ($journal -and $journal -ne 'none') { $script:LaRouteDeferred = $true; return }
  }
  if (@('pre_foundation', 'foundation_window', 'post_foundation', 'discarding', 'terminal_pending',
        'terminal_done', 'bookkeeping_only') -contains $st) {
    La-AttemptMenu $st $inst
  }
  Die ("The fresh-install attempt reports state '" + $st + "', which this installer cannot route. Nothing has been changed.")
}

# A no-authority fresh start becomes a recorded attempt, after consent and before the first mutation.
function La-NestedHostingDir {
  # A patch hosting folder AT or INSIDE the install root is contained by the root's own ledger entry,
  # so the patch compartment could never be recorded against an entry of its own.
  $root = La-Canon $script:InstallDir
  $hosting = La-Canon $script:PatchHostingDir
  return (($hosting -ieq $root) -or (La-Inside $hosting $root))
}

function La-BeginAttempt {
  # The normalized path relationship is known now: refuse before the container or any attempt mutation.
  if (La-NestedHostingDir) {
    Die ("-PatchHostingDir " + $PatchHostingDir + " is the install directory or lies inside it (" + $InstallDir +
         "). A fresh install records its patch hosting folder as its own resource, which a folder inside the" +
         " install root cannot be. Choose a patch hosting folder outside " + $InstallDir + ". Nothing has been changed.")
  }
  if ([bool]$SchedRetiredPresent) {
    # The closed ledger vocabulary has no service deletion, so this removal could not be recorded.
    Die ("The retired " + $SchedServiceRetired + " service is registered on a box that has no CORPUSfm" +
         " installation record. A fresh install records every change it makes and cannot record that" +
         " removal, so it refuses before any change. Remove that service deliberately, then re-run.")
  }
  $refused = @()
  foreach ($r in (La-RefuseFirst)) {
    if ($r.kind -eq 'dir') { if ((La-PathItem $r.target) -and -not $ReplaceAside) { $refused += $r.target } }
    elseif ($r.kind -eq 'file') { if (La-PathItem $r.target) { $refused += $r.target } }
    elseif ($r.kind -eq 'service') { if ((La-ServiceState $r.target).exists) { $refused += ('service ' + $r.target) } }
    elseif ($r.kind -eq 'task') { if ((La-TaskState $r.target).exists) { $refused += ('scheduled task ' + $r.target) } }
  }
  if ($refused.Count) {
    Die ("REFUSE-FIRST: this fresh install found CORPUSfm resources that no installation record accounts" +
         " for: " + ($refused -join '; ') + ". They may belong to an earlier installation. Resolve them" +
         " deliberately, then re-run. Nothing has been changed.")
  }
  if (-not (La-PathItem $script:AttemptDir)) {
    try { [IO.Directory]::CreateDirectory($script:AttemptDir, (La-ProtectedSecurity $true)) | Out-Null }
    catch {
      New-Item -ItemType Directory -Path $script:AttemptDir | Out-Null
      La-SetProtected $script:AttemptDir $true
    }
  }
  $problem = La-ContainerProblem
  if ($problem) { Die ("The fresh-install attempt container cannot be used: " + $problem + ". Nothing has been changed.") }
  if (-not (La-ContainerIsEmpty)) {
    Die ($script:AttemptDir + " is not empty; it is not adopted. Nothing has been changed.")
  }
  Get-ChildItem -LiteralPath $script:AttemptDir -Force | Remove-Item -Force
  $script:AttemptId = [guid]::NewGuid().ToString()
  $script:InstallationId = [guid]::NewGuid().ToString()
  $package = $null
  if ($InstallerSeries) {
    $commit = $null
    if ($PackageCommit) { $commit = $PackageCommit }
    $package = [ordered]@{
      observed   = [ordered]@{ installer_series = $InstallerSeries; installer_version = $InstallerVersion
                               application_commit = $commit; installer_source_commit = $null
                               payload_digest_sha256 = $null }
      provenance = @('self_consistent')
    }
  }
  $databases = Join-Path $FmDbDir 'CORPUSfm'
  $script:AttemptRecord = [ordered]@{
    schema_version  = 1
    attempt_id      = $script:AttemptId
    installation_id = $script:InstallationId
    platform        = 'windows'
    created_utc     = (La-Now)
    paths           = [ordered]@{
      install_dir = $InstallDir; patch_hosting_dir = $PatchHostingDir; fms_root = $FmsBin
      fms_database_dir = $FmDbDir; config_dir = $FixedConfig; state_dir = $FixedState
      secrets_dir = $FixedSecrets; log_dir = $LogDir; run_dir = $FixedRun
      storage_target = (Join-Path $databases 'CORPUSfm_DB.fmp12'); support_dir = $SupportDir
    }
    package         = $package
    ledger          = (New-Object System.Collections.ArrayList)
    discard         = $null
    phase           = 'installing'
  }
  La-Write
  $script:CfmAttempt = $true
  $script:LaLeftoverEmpty = $false
  # No package cache outside the recorded roots: pip otherwise writes the administrator's profile.
  $env:PIP_NO_CACHE_DIR = '1'
  Ok ("Fresh-install attempt " + $script:AttemptId + " recorded at " + $script:AttemptDir)
}

function Lc-ProviderDisposition($provider, $exitCode, $resultJson) {
  $probe = @'
import json, os, sys
sys.path.insert(0, sys.argv[1])
from corpusfm.lifecycle.installer_disposition import classify
payload = json.load(sys.stdin)
journal = None
try:
    with open(sys.argv[8], encoding="utf-8") as handle:
        journal = json.load(handle)
except FileNotFoundError:
    pass
request = {
    "schema_version": 1, "phase": "provider", "provider": sys.argv[2],
    "exit_code": int(sys.argv[3]), "installation_id": sys.argv[4],
    "expected_generation": int(sys.argv[5]), "mode": sys.argv[6],
    "install_dir": sys.argv[7], "platform": "windows",
    "provider_result": payload, "journal": journal,
}
print(json.dumps(classify(request), separators=(",", ":"), sort_keys=True))
'@
  $probeFile = New-CfmProbeFile $probe
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $disp = ($resultJson | & $script:Py $probeFile $script:Src $provider $exitCode `
      $script:InstallationId $script:CfmGeneration $script:CfmStorageMode $script:InstallDir `
      $script:CfmJournalFile 2>$errFile | Out-String)
    $rc = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $eap
    Remove-Item $probeFile -Force -ErrorAction SilentlyContinue
    if (Test-Path $errFile) {
      Cfm-Logline (Get-Content $errFile -Raw)
      Remove-Item -Force $errFile -ErrorAction SilentlyContinue
    }
  }
  if ($rc -ne 0 -or -not (Lc-IsOneJsonObject $disp)) {
    Die ("$provider returned a lifecycle result the shared installer-disposition boundary refused. " +
         "The journal remains untouched; see the log.")
  }
  Cfm-Logline $disp
  $script:LcCondition = "" + (Lc-Field $disp 'condition')
  $script:LcCompose = [bool](Lc-Field $disp 'compose')
  $script:LcRetireProvider = "" + (Lc-Field $disp 'retire_provider')
  $script:LcOp = "" + (Lc-Field $disp 'operation_id')
  $script:LcRecoveryFamily = "" + (Lc-Field $disp 'recovery_family')
  $script:LcRecoveryVerb = "" + (Lc-Field $disp 'recovery_verb')
  $script:LcRecoveryRequest = "" + (Lc-Field $disp 'recovery_request')
  $script:LcDispositionReason = "" + (Lc-Field $disp 'reason')
  $script:LcFirstAdminOwedByDisposition = [bool](Lc-Field $disp 'first_administrator_owed')
}

function Lc-ApplyProviderDisposition($what) {
  if ($script:LcRetireProvider) {
    Lc-DiscardProvider $script:LcRetireProvider $script:LcOp
  }
  switch ($script:LcCondition) {
    'continue' { return }
    'correct_and_rerun' {
      Die ("$what stopped without leaving recovery owed: " + $script:LcDispositionReason +
           " Correct the reported condition, then re-run the installer.")
    }
    'recover_first' {
      Warn $script:LcDispositionReason
      Die ("$what left an operation that must be recovered before installation continues.`n" +
           "     Re-run this same verified installer from an elevated Windows PowerShell. Before any" +
           " new work it recovers this operation automatically; nothing needs to be run by hand first.")
    }
    default { Die "$what received unknown installer condition '$script:LcCondition'; the journal remains untouched." }
  }
}

function Lc-ProviderRun($what, $candidateField, [string[]]$LcArgs) {
  # Packet 1398: inside a fresh-install attempt the call is intended before it runs and its result -
  # a refusal or an unreadable answer included - is published before anything is dispatched. With
  # no attempt both La- calls return immediately.
  La-ProviderBegin $script:LaProviderIntent $script:LaProviderPrior $script:LaProviderIntent
  if ($script:CfmAttempt) { $script:LcRawRc = -1; $script:LcRawOut = '' }
  try {
    if ($script:LcFrameAccount) {
      $out = Lc-RunFramedRaw $what $LcArgs $script:LcFrameAccount $script:LcFramePassword
    } else {
      Lc-RunRaw $LcArgs
      $out = $script:LcRawOut
    }
  } finally {
    La-ProviderEnd $script:LaProviderIntent $script:LcRawRc $script:LcRawOut
    $script:LaProviderIntent = ''; $script:LaProviderPrior = $null
  }
  $script:LcProviderOut = $out
  $script:LcAwaiting = (Lc-Field $out 'awaiting_composition')
  if ($candidateField -eq '-') { $script:LcCandidate = $null }
  else { $script:LcCandidate = (Lc-Field $out $candidateField) }
  if ($what -eq 'admin_identity reconcile') { $provider = 'admin_identity' }
  elseif ($what -eq 'patch compartment apply') { $provider = 'patch' }
  elseif ($what -eq 'proxy reconcile') { $provider = 'proxy' }
  elseif ($what -like 'storage *') { $provider = 'storage' }
  else { Die "no provider identity is registered for '$what'." }
  Lc-ProviderDisposition $provider $script:LcRawRc $out
  Lc-ApplyProviderDisposition $what
}

# Retire one provider's journal record through the shipped boundary. Section 4H.5 requires the
# discard and the installers CLAIMED it; until correction A there was no verb that performed one, so
# the claim was false and the next provider met a record its predecessor had left behind.
function Lc-DiscardProvider($provider, $operationId, $installationId = $script:InstallationId) {
  if (-not $operationId) { Die "$provider returned no operation_id; its journal cannot be discarded." }
  if (-not $installationId) { Die "$provider journal names no installation identity; refusing to guess." }
  if ($provider -eq 'proxy') {
    $retireReq = Lc-Request ("retire-" + $provider) (Lc-Json ([ordered]@{
      schema_version  = 1
      operation_id    = $operationId
      installation_id = $installationId
      actor           = 'installer'
    }))
    Lc-Run "$provider artifact retirement" @('proxy','retire','--request',$retireReq) | Out-Null
    Ok "$provider artifacts retired"
  }
  $req = Lc-Request ("discard-" + $provider) (Lc-Json ([ordered]@{
    schema_version  = 1
    provider        = $provider
    operation_id    = $operationId
    installation_id = $installationId
    actor           = 'installer'
  }))
  Lc-Run "$provider journal discard" @('composition','discard-provider','--request',$req) | Out-Null
  Ok "$provider journal discarded"
}

function Lc-RecoverA001Authority {
  # A001's ACCUMULATED RECOVERY ROUTE - and it is A001's alone, not a framework.
  #
  # THE PROBLEM IT SOLVES. Phase 3 routes every retained journal through the shared provider
  # disposition, and `a001_scheduler_authority` is not a provider - `_provider_for_journal` answers
  # None, `_preflight` raises "the unresolved lifecycle journal does not identify its provider", and
  # the installer dies before it can ever reach A001 step 5. The composition operation is resumable;
  # until now the installers could not reach it. So this recognizes the EXACT A001 journal ahead of
  # generic disposition. A001 is still not a provider and the provider vocabulary is untouched.
  #
  # WHAT IT DOES NOT DO. It does not continue the installation. Recovery and new work are never
  # combined - a run that repairs and then installs cannot say which half a later failure belongs
  # to - so a successful recovery ENDS this invocation and the operator re-runs.
  param($Record, $State)
  $op     = "" + $Record.operation_id
  $inst   = "" + $Record.installation_id
  $st     = "" + $Record.state
  $sub    = "" + $Record.current_subsystem
  $result = "" + $Record.result

  # -- the accepted interruption shapes --------------------------------------------
  #
  # A CHEAP EARLY SUBSET, NOT THE AUTHORITY. The full rule is a MATRIX pairing the journal state
  # with whether the manifest still records the scheduler, and only the application operation can
  # see both halves - this script has no manifest reader and must not grow one. So these refuse the
  # shapes visible from the journal alone; the operation refuses the pairs, and because `Lc-Run`
  # dies on a refusal, a pair rejected there ends this invocation with the journal untouched. A
  # refusal is never reinterpreted as recoverable and nothing here discards a record.
  switch ($st) {
    'open' {
      if ($sub -and $sub -ne 'None') {
        Die ("The retained A001 journal is open yet names subsystem '" + $sub + "'; it contradicts itself and remains untouched.")
      }
    }
    'checkpointed' {
      if ($sub -ne 'a001_scheduler_authority') {
        Die ("The retained A001 journal is checkpointed under subsystem '" + $sub + "', not a001_scheduler_authority; it remains untouched.")
      }
    }
    'resolved' {
      if ($sub -ne 'a001_scheduler_authority') {
        Die ("The retained A001 journal is resolved under subsystem '" + $sub + "'; it remains untouched.")
      }
      if ($result -ne 'completed') {
        Die ("The retained A001 journal is resolved '" + $result + "'; only a completed retirement may be finished. It remains untouched.")
      }
    }
    default {
      Die ("The retained A001 journal reads state '" + $st + "', which is not a resumable retirement. It remains untouched.")
    }
  }
  # THE EXACT CANONICAL UUID, lowercase, as `schema._UUID_RE` spells it. The previous shape test
  # was '^[0-9a-fA-F-]{36}$', which accepts thirty-six dashes and any hex/dash soup of the right
  # length - a length check wearing an identity check's clothes. There is deliberately no second
  # normalization rule here: a record whose identity is not already canonical is not one to tidy
  # up, it is one to refuse.
  if ($inst -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
    Die ("The retained A001 journal's installation identity '" + $inst + "' is not a canonical lowercase UUID; it remains untouched.")
  }
  if (-not $op) { Die "The retained A001 journal names no operation; it remains untouched." }

  # -- bound to the PUBLISHED identity, not to what the interrupted run believed ----
  $locator   = "" + (Lc-Field $State 'locator')
  $manifest  = "" + (Lc-Field $State 'manifest')
  $recordDir = "" + (Lc-Field $State 'install_dir')
  if ($locator -ne 'present') {
    Die "A retained A001 journal is present but this installation publishes no locator; refusing to recover against unpublished authority."
  }
  if ($manifest -ne 'valid') {
    Die ("A retained A001 journal is present but the manifest reads '" + $manifest + "'; refusing to recover against a record that cannot be read.")
  }
  # TWO SOURCES, COMPARED. `installation_id` is read from the published LOCATOR and
  # `journal_operation` from the journal state block; $inst and $op come from reading the journal
  # file directly. So these compare the retained record against published authority rather than
  # against itself.
  $statusInst = "" + (Lc-Field $State 'installation_id')
  if ($inst -ne $statusInst) {
    Die ("The retained A001 journal names installation '" + $inst + "' but the published locator names '" +
         $statusInst + "'; refusing to recover a journal that belongs elsewhere. Nothing has been changed.")
  }
  if (("" + (Lc-Field $State 'journal_operation')) -ne $op) {
    Die "The retained A001 journal and the status disagree about the operation; nothing has been changed."
  }
  if (-not $recordDir) {
    Die "The published installation record names no software root; refusing to recover."
  }

  # -- the platform's physical postconditions, RE-PROVED ---------------------------
  if (Get-Service $script:SchedServiceRetired -ErrorAction SilentlyContinue) {
    Die ("A retained A001 journal is present but the " + $script:SchedServiceRetired +
         " service is still registered. The physical retirement did not complete; re-run the" +
         " installer, which will finish it. The journal remains untouched.")
  }
  foreach ($a in (Get-CfmRetiredSchedulerArtifacts)) {
    if (Test-Path -LiteralPath $a) {
      Die ("A retained A001 journal is present but " + $a + " still exists. The physical retirement" +
           " did not complete; re-run the installer. The journal remains untouched.")
    }
  }

  # -- THE CURRENT generation, never one the interrupted process remembered ---------
  $gen = "" + (Lc-Field $State 'generation')
  if ($gen -notmatch '^[0-9]+$' -or [int]$gen -lt 1) {
    Die ("The published manifest reports generation '" + $gen + "'; refusing to recover A001 against it.")
  }

  Info ("Finishing the interrupted A001 authority retirement (operation " + $op + ", generation " + $gen + ")")
  $req = Lc-Request 'retire-scheduler-authority' (Lc-Json ([ordered]@{
    schema_version      = 1
    installation_id     = $inst
    expected_generation = [int]$gen
    install_dir         = $recordDir
    actor               = 'installer'
  }))
  # THE SAME OPERATION, through the runtime phase 3 already selected. No second mutation path.
  $out = Lc-Run "A001 authority recovery" @('composition','retire-scheduler-authority','--request',$req)
  $committed = "" + (Lc-Field $out 'committed_generation')
  # THE OPERATION MUST HAVE FINISHED **THIS** OPERATION. A result naming another one means the
  # composition joined a different record than the one phase 3 routed here.
  $returnedOp = "" + (Lc-Field $out 'operation_id')
  if ($returnedOp -ne $op) {
    Die ("A001 recovery finished operation '" + $returnedOp + "', not the retained '" + $op +
         "'; nothing further will be attempted.")
  }

  # -- read the STATE back; the call returning is not the proof --------------------
  # -Refresh, NOT the default. The default is memoized and would return the phase-3 observation,
  # which is the state BEFORE this recovery ran - the exact defect this call now avoids.
  $after = Get-LcState -Refresh
  if (("" + (Lc-Field $after 'journal')) -ne 'none') {
    Die "A001 recovery ran but a lifecycle journal is still retained; nothing further will be attempted."
  }
  if (("" + (Lc-Field $after 'manifest')) -ne 'valid') {
    Die "A001 recovery ran but the manifest no longer reads valid; nothing further will be attempted."
  }
  if (("" + (Lc-Field $after 'install_dir')) -ne $recordDir) {
    Die "A001 recovery ran but the published software root changed; nothing further will be attempted."
  }
  if (("" + (Lc-Field $after 'installation_id')) -ne $statusInst) {
    Die "A001 recovery ran but the published installation identity changed; nothing further will be attempted."
  }
  if (("" + (Lc-Field $after 'generation')) -ne $committed) {
    Die ("A001 recovery reported generation '" + $committed + "' but the record reads '" +
         (Lc-Field $after 'generation') + "'; nothing further will be attempted.")
  }

  Ok ("A001 authority retirement completed at generation " + $committed)
  # RECOVERY IS THE WHOLE INVOCATION. It is never combined with the remaining phases.
  Die "The interrupted A001 authority retirement is complete. Re-run this Series 2 package to begin a separate installation invocation."
}

function Lc-RetireSchedulerAuthority {
  # A001 STEP 5 - AUTHORITY RETIREMENT, and it is a different thing from the physical retirement
  # above. Steps 2-4b prove the OS no longer carries the service; this proves the published
  # installation record no longer claims it.
  #
  # CALLED ONLY AFTER THE PHYSICAL POSTCONDITIONS HOLD, and it re-proves them here rather than
  # trusting the order of two call sites: the service must be unregistered and both artifacts gone.
  # Retiring the authority while the service still exists would publish a record that is wrong in
  # the other direction.
  #
  # THE PREDICATE INCLUDES THE LEGACY MANIFEST ENTRY, not just OS residue. An installation
  # interrupted after the OS retirement but before this write has no service and no artifacts, so an
  # OS-only predicate would skip it forever and leave the record stale. The operation itself is what
  # decides: it is a true no-op when the entry is already gone and no journal of its own exists.
  if (Get-Service $script:SchedServiceRetired -ErrorAction SilentlyContinue) {
    Die ("Refusing to retire scheduler authority while the " + $script:SchedServiceRetired +
         " service is still registered; the physical retirement must complete first.")
  }
  foreach ($a in (Get-CfmRetiredSchedulerArtifacts)) {
    if (Test-Path -LiteralPath $a) {
      Die ("Refusing to retire scheduler authority while " + $a + " is still present; the physical" +
           " retirement must complete first.")
    }
  }
  $req = Lc-Request 'retire-scheduler-authority' (Lc-Json ([ordered]@{
    schema_version      = 1
    installation_id     = $script:InstallationId
    expected_generation = [int]$script:CfmGeneration
    install_dir         = $script:InstallDir
    actor               = 'installer'
  }))
  # Lc-Run DIES on a refusal, which is the required behaviour: authority retirement that cannot be
  # written or verified fails the installer rather than reporting A001 complete over a stale record.
  $out = La-LcRun 'retire_scheduler_authority' ([ordered]@{}) "scheduler authority retirement" @('composition','retire-scheduler-authority','--request',$req)
  $committed = Lc-Field $out 'committed_generation'
  if (-not ($committed -match '^[0-9]+$') -or [int]$committed -lt [int]$script:CfmGeneration) {
    Die ("scheduler authority retirement returned generation '" + $committed + "'; expected at least " +
         $script:CfmGeneration)
  }
  $script:CfmGeneration = [int]$committed
  if ((Lc-Field $out 'removed') -eq 'True') {
    Ok ("Retired scheduler authority: the installation record no longer names it (generation " + $committed + ")")
  } else {
    Ok ("Installation record already names no scheduler (generation " + $committed + ")")
  }
}

function Lc-CommitProvider($provider, $operationId, $inspectedGeneration, $candidate) {
  if (-not $operationId) { Die "$provider returned no operation_id; refusing to invent one." }
  if ($null -eq $candidate) { Die "$provider composed no candidate; there is nothing to commit." }
  $req = Lc-Request ("commit-" + $provider) (Lc-Json ([ordered]@{
    schema_version       = 1
    provider             = $provider
    operation_id         = $operationId
    installation_id      = $script:InstallationId
    inspected_generation = [int]$inspectedGeneration
    candidate            = $candidate
    install_dir          = $script:InstallDir
    actor                = 'installer'
  }))
  $out = Lc-Run "$provider composition" @('composition','commit-provider','--request',$req)
  $committed = Lc-Field $out 'committed_generation'
  $expected = [int]$inspectedGeneration + 1
  if ("$committed" -ne "$expected") {
    Die "$provider committed generation '$committed', expected $expected - refusing to continue."
  }
  $script:CfmGeneration = $expected
  Ok "$provider composed at generation $expected"
}

# Install (or re-install) one WinSW-wrapped service from a definition that is ALREADY on disk.
# IT NEVER STARTS ANYTHING. The start belongs to phase 21 and to nothing else, so the capability is
# absent from this function rather than defaulted off in a parameter a later edit could flip.
# ACL FAILURE IS FATAL. A warning here leaves a service running with permissions nobody established,
# which is the same class of silent defect as an omitted service account.
function Grant-OrDie($path, $spec, $what) {
  & icacls $path /grant $spec 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Die ("Could not establish ACLs on " + $path + " (" + $what + ")") }
}

# == THE SCHEDULER RETIREMENT ADAPTER (Series 2) ==================================================
#
# ACCUMULATED ADAPTERS - developer ruling, 2026-09-03. The compatibility epoch begins with the first
# genuinely public installer release, and from that epoch forward architectural migration adapters
# ACCUMULATE. A later installer runs the accumulated set in dependency order, and each one is
# governed by OBSERVED STATE.
#
# THE RECORDED INSTALLER VERSION IS CONTEXT, NEVER AUTHORITY. This adapter must never become a
# `0.2791 -> 0.2792` branch, or key on anything a manifest claims about where the box has been: it
# asks Windows whether the service is there. A version-keyed adapter is wrong for every box whose
# history is not what its record says, and those are exactly the boxes that need it.
#
# It is PERMANENT and IDEMPOTENT. It is not retired or consolidated with its neighbours except at an
# explicitly approved compatibility-epoch or installer-series boundary. Deleting it because no box
# in front of you has a scheduler is the mistake its tests exist to catch.
# =================================================================================================
# DURABLE UPGRADE KNOWLEDGE. Keep this in every future installer. The standalone `corpusfm-scheduler`
# service is retired (application packet 1361-01) and nothing renders one any more - but boxes that
# carry it will keep arriving at this installer for as long as any of them exist, and each one needs
# the same four steps in the same order.
#
# THE ORDER IS THE WHOLE POINT, and getting it wrong is what release 0.2792 did. A Windows virtual
# service account exists only while its service is registered: unregister first and
# `NT SERVICE\corpusfm-scheduler` stops resolving, `icacls /remove:g` answers 1332, and - measured on
# w-test-private, 2026-09-03 - it then removes NOTHING AT ALL, including for the trustee that still
# resolves. The install aborts, and every rerun aborts at the same line, because the orphaned SID it
# failed to remove is still sitting in the DACL.
#
#   1. stop it, but leave it REGISTERED while its account is still needed   (phase 9 quiesce)
#   2. remove its ACL entries while that account still resolves             (Remove-CfmRetiredSchedulerGrants)
#   3. establish and read back the one-service ACL policy                   (Assert-CfmOneServiceAclPolicy)
#   4a. only THEN unregister it, and require authoritative absence          (Remove-CfmRetiredSchedulerService)
#   4b. remove its exact installer-owned artifacts and read back absence    (Remove-CfmRetiredSchedulerArtifacts)
#
# A001 RECOGNISES THREE SOURCE STATES, and they are not the same predicate:
#
#   (a) A REGISTERED SERVICE       -> full identity and service retirement: steps 1-4a, then 4b.
#       The account resolves, so ACL work is possible and required.
#
#   (b) EXACT RETIRED ARTIFACTS, NO SERVICE -> bounded artifact cleanup only: step 4b alone.
#       This is the box interrupted between 4a and 4b. There is no account to resolve and no ACL
#       work to attempt; two named files are removed and proven gone. Guarding 4b on the captured
#       SID - which is what an earlier version did - meant this box could never heal, because the
#       next run correctly observes no service and captures no SID.
#
#   (c) AN UNEXPLAINED ORPHAN ACL WITH NO SERVICE -> UNSUPPORTED CORRUPTION. Not repaired, not
#       silently normalised, and no code here looks for it. Removing an ACE for a principal this
#       installer cannot account for is the blanket deletion the rules forbid, and inventing the
#       SID to match is forbidden outright. Such a box is a developer matter.
#
# EVERY INTERRUPTION POINT IS RERUNNABLE. Before step 3 completes the service is still registered, so
# a rerun repeats from step 1 with the identity available. Between steps 3 and 4 the grants are
# already gone and the removal is idempotent, so a rerun re-proves the policy and proceeds to delete.
# After step 4 the observation above is `$false`, nothing names the account, and no later phase wants
# it.

function Resolve-CfmServiceSid($account, $what) {
  # ONE translation helper, so every SID in this adapter is obtained the same way and a failure is
  # always a refusal. Nothing here computes, guesses or parses a SID: it asks LSA for a live one.
  try {
    $sid = (New-Object System.Security.Principal.NTAccount($account)
           ).Translate([System.Security.Principal.SecurityIdentifier]).Value
  } catch {
    Die ("Could not resolve " + $account + " (" + $what + "): " + $_.Exception.Message)
  }
  if (-not $sid) { Die ("Resolving " + $account + " (" + $what + ") produced an empty SID.") }
  return $sid
}

function Remove-CfmGrantBySid($path, $sidOperand, $who) {
  # ONE PATH, ONE TRUSTEE, ONE CALL, ONE EXIT CODE.
  #
  # NEVER BATCHED. `icacls <path> /remove:g <a> <b>` is all-or-nothing: measured on w-test-private,
  # 2026-09-03, a pair in which ONE operand failed to resolve returned 1332 and removed neither -
  # "Successfully processed 0 files" - so the trustee that was perfectly valid kept its grant while
  # the exit code blamed the other one. Separate calls make each removal's outcome its own fact.
  #
  # The operand is `*<numerical SID>`, never a friendly name, so icacls performs no name lookup and
  # there is no lookup left to fail.
  & icacls $path '/remove:g' $sidOperand 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Die ("Could not remove the " + $who + " grant (" + $sidOperand + ") from " + $path +
         "; icacls exited " + $LASTEXITCODE + ".")
  }
}

function Remove-CfmRetiredSchedulerGrants($paths) {
  # STEP 2. Remove exactly one trustee, by the SID captured at the preflight, and only where this
  # installer's own two-service layout granted it. Nothing else is touched: an unexplained trustee
  # is the proxy provider's refusal to raise, not this script's to normalise away.
  if (-not $script:SchedRetiredIcaclsOperand) { return }
  foreach ($path in $paths) {
    if (-not (Test-Path $path)) { continue }
    Remove-CfmGrantBySid $path $script:SchedRetiredIcaclsOperand "retired scheduler's"
  }
}

function Assert-CfmOneServiceAclPolicy($paths) {
  # STEP 3. READ THE STATE BACK AND COMPARE NUMERICAL SIDs. An icacls call that exits zero is an
  # intent; a DACL that does not contain the SID is the fact, and only the second one can contradict
  # the first. Both halves are asserted: the web identity HOLDS its grant everywhere, and the retired
  # identity holds NOTHING anywhere.
  #
  # The retired SID is the EXACT value captured before phase 9 - not re-resolved here, because by
  # design this runs while the service still exists but the whole point of capturing it early was to
  # stop depending on that.
  $retiredSid = $script:SchedRetiredSid
  $webSidValue = $script:WebSidValue
  foreach ($path in $paths) {
    if (-not (Test-Path $path)) { continue }
    $acl = Get-Acl $path
    $sids = @($acl.Access | ForEach-Object {
      try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
      catch { "" + $_.IdentityReference.Value }
    })
    if ($retiredSid -and ($sids -contains $retiredSid)) {
      Die ("The retired scheduler (" + $retiredSid + ") still holds a grant on " + $path +
           " after its removal; the one-service ACL policy is not established.")
    }
    if (-not ($sids -contains $webSidValue)) {
      Die ("The web service (" + $webSidValue + ") holds no grant on " + $path +
           "; the one-service ACL policy is not established.")
    }
  }
  Ok ("One-service ACL policy read back across " + $paths.Count + " protected locations" +
      $(if ($retiredSid) { " (the retired scheduler holds nothing)" } else { "" }))
}

function Get-CfmRetiredSchedulerArtifacts {
  # THE EXACT installer-owned artifacts of the retired service. Named, never globbed: this list is
  # what "bounded artifact cleanup" is bounded BY, and a wildcard here would be the blanket deletion
  # the adapter's rules forbid.
  return @(
    (Join-Path $script:SvcDir ($script:SchedServiceRetired + '.xml')),
    (Join-Path $script:SvcDir ($script:SchedServiceRetired + '.exe'))
  )
}

function Remove-CfmRetiredSchedulerService {
  # STEP 4a - SERVICE AND IDENTITY RETIREMENT, and only after step 3. Now the account may stop
  # resolving: nothing left needs it.
  #
  # NOT OPTIONAL on a box that has one. `python -m corpusfm.server.scheduler` exits 2 under this
  # build, so a surviving WinSW service fails every start attempt and fills its error log with a
  # refusal an operator cannot act on from the service alone.
  #
  # THIS STEP DELETES NO FILES. Artifact cleanup is 4b, deliberately separate and separately
  # guarded - see there for why.
  if (-not $script:SchedRetiredSid) { return }
  Info ("Retiring the standalone " + $script:SchedServiceRetired + " service (scheduling is inside the web app)...")
  $schedExe = Join-Path $script:SvcDir ($script:SchedServiceRetired + '.exe')
  if (Test-Path $schedExe) {
    & $schedExe stop      2>&1 | Out-Null
    & $schedExe uninstall 2>&1 | Out-Null
  } else {
    Stop-Service $script:SchedServiceRetired -Force -ErrorAction SilentlyContinue
    & sc.exe delete $script:SchedServiceRetired 2>&1 | Out-Null
  }
  for ($i=0; $i -lt 20 -and (Get-Service $script:SchedServiceRetired -ErrorAction SilentlyContinue); $i++) {
    Start-Sleep -Seconds 1
  }
  # AUTHORITATIVE ABSENCE, required before anything proceeds. `-ErrorAction SilentlyContinue` on the
  # probe is how "is it gone" is asked; it is not how "it is gone" is proven.
  if (Get-Service $script:SchedServiceRetired -ErrorAction SilentlyContinue) {
    Die ("The retired " + $script:SchedServiceRetired + " service could not be removed. It cannot start" +
         " under this build and must not be left registered; remove it and re-run the installer.")
  }
  Ok ("Standalone " + $script:SchedServiceRetired + " service unregistered; the web service schedules.")
}

function Remove-CfmRetiredSchedulerArtifacts {
  # STEP 4b - BOUNDED ARTIFACT CLEANUP, and it runs WHETHER OR NOT this invocation captured a SID.
  #
  # THIS IS WHAT MAKES THE RERUNNABILITY CLAIM TRUE. An interruption between 4a and here leaves a
  # box with no service and two orphaned installer-owned files. On the next invocation
  # `$SchedRetiredPresent` is false and no SID is captured - correctly, there is no service to
  # observe - so a cleanup guarded by the SID would never run again and the definition XML would
  # survive forever. That XML is precisely what the canonical service read-back enumerates, so
  # leaving it is not cosmetic.
  #
  # Guarded by ARTIFACT PRESENCE instead. No ACL work is attempted here and no SID is invented: this
  # step removes two named files and proves they are gone. That is the whole of it.
  $artifacts = Get-CfmRetiredSchedulerArtifacts
  $present = @($artifacts | Where-Object { Test-Path -LiteralPath $_ })
  if (-not $present) { return }
  Info ("Removing " + $present.Count + " retired " + $script:SchedRetiredService + " artifact(s)...")
  foreach ($path in $present) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  }
  # READ BACK. `-ErrorAction SilentlyContinue` above hides a locked or in-use file, so the removal's
  # silence proves nothing and the absence test is the proof.
  $remaining = @($artifacts | Where-Object { Test-Path -LiteralPath $_ })
  if ($remaining) {
    Die ("The retired scheduler's installer-owned artifacts could not be removed: " +
         ($remaining -join ', ') + ". A held file lock is the usual cause; release it and re-run" +
         " the installer.")
  }
  Ok "Retired scheduler artifacts removed and read back absent."
}

function Register-CfmService($id) {
  $exe = Join-Path $script:SvcDir ($id + '.exe')
  # Stop + uninstall any existing service FIRST so the running wrapper releases the .exe lock
  # (else Copy-Item over the in-use exe fails on an idempotent re-run).
  if (Get-Service $id -ErrorAction SilentlyContinue) {
    if (Test-Path $exe) { & $exe stop 2>$null | Out-Null; & $exe uninstall 2>$null | Out-Null }
    else { & sc.exe stop $id 2>$null | Out-Null; & sc.exe delete $id 2>$null | Out-Null }
    for ($i=0; $i -lt 10 -and (Get-Service $id -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
    # The WinSW wrapper process can outlive 'uninstall' by a beat, keeping the .exe locked. Kill any
    # process still holding this exe (the wrapper) before overwriting it.
    for ($k=0; $k -lt 10; $k++) {
      $busy = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe }
      if (-not $busy) { break }
      $busy | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
      Start-Sleep -Seconds 1
    }
    Start-Sleep -Seconds 2
  }
  # Copy with retry - the lock can release a moment after the process exits.
  for ($k=0; $k -lt 6; $k++) {
    try { Copy-Item $script:Winsw $exe -Force -ErrorAction Stop; break }
    catch { if ($k -eq 5) { Die ("Could not replace " + $exe + " (locked): " + $_.Exception.Message) }; Start-Sleep -Seconds 2 }
  }
  & $exe install | Out-Null
  if (-not (Get-Service $id -ErrorAction SilentlyContinue)) { Die ($id + " did not register") }
}

Section "Hello"
Hello "CORPUSfm Windows Installer"
Info ("Installs to " + $InstallDir + ", publishes the installation record, composes patch, proxy, admin identity and storage, then fronts the app at <FMS-host>" + $WebPrefix + "/ behind FileMaker Server's active web front (IIS by default via an isolated ARR application; the optional Claris nginx front is maintained via a narrow CORPUSfm include - FMS owns the nginx lifecycle).")


# === PHASE 1 - Research - inspect and classify without mutation =================================
Section "Self-check"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Die "Run this from an elevated (Administrator) PowerShell."
}
Ok ("Administrator: " + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Ok "Shared library present: _cfm_lib.ps1"
# Open the always-on install transcript now that we're elevated. The heavy pip/download detail is
# captured here even though the console stays concise; a failure (Die) points the operator at this
# path. Re-run with -Verbose to also stream that detail to the console.
Cfm-LogInit (Join-Path $LogDir ("install-" + (Get-Date).ToString('yyyyMMdd-HHmmss') + ".log"))
if ($script:CfmLog) { Ok ("Install transcript: " + $script:CfmLog) } else { Warn "Could not open an install transcript (continuing; output stays on the console)." }

Section "Detection"
# READ-ONLY ORIENTATION ONLY. Every mutation this phase used to perform - the directory creation,
# the ACL lock and the ARR toggle - now runs in its own later phase, where mutation belongs
# (packet 1228 moved them out of Detection; this packet gives each of them a numbered phase).
$os = (Get-CimInstance Win32_OperatingSystem).Caption
if ($os -notmatch 'Server (2019|2022|2025)') { Warn "Untested OS: $os (supported: Windows Server 2019/2022/2025)" } else { Ok "OS: $os" }

# FMS detection (drive-agnostic via the service path; -FmsRoot overrides).
$FmsBin = Find-FmsBin $FmsRoot
if (-not $FmsBin) { Die "FileMaker Server not found. Is FMS installed + the 'FileMaker Server' service present? Pass -FmsRoot '<...\Database Server>' for a custom location." }
Ok "FileMaker Server present: $FmsBin"
$FmsHome = Split-Path $FmsBin -Parent   # ...\FileMaker Server (parent of Database Server + NginxServer)
$FmDbDir = Join-Path $FmsHome 'Data\Databases'
$ClarisNginxExe = Join-Path $FmsHome 'Nginx\nginx.exe'
$ClarisNginxActive = @(
  Get-CimInstance Win32_Process -Filter "Name='nginx.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -and
      ([IO.Path]::GetFullPath($_.ExecutablePath) -eq [IO.Path]::GetFullPath($ClarisNginxExe)) }
).Count -gt 0
if ($ClarisNginxActive) {
  Ok "Claris nginx is the active FMS web front; proxy reconciliation requires one authenticated HTTP-server restart"
}
if (Test-Path (Join-Path $FmsBin 'FMUpgradeTool.exe')) { Ok "FMUpgradeTool.exe present (apply/generative features available)" } else { Warn "FMUpgradeTool.exe not found - analysis features only." }
if ((Get-Service 'FileMaker Server' -ErrorAction SilentlyContinue).Status -ne 'Running') { Warn "The 'FileMaker Server' service is not Running - start it before using CORPUSfm." }

# OData PREFLIGHT (pre-mutation): CORPUSfm's storage/backend path REQUIRES the FM OData API. Check it
# HERE - before Python/deps/services/proxy - so an OData-disabled box fails EARLY with actionable
# guidance instead of after the install. 200/401 = enabled (401 = up + unauthenticated, expected).
# The installer REQUIRES the administrator to enable OData; it does NOT auto-toggle FMS settings, and
# -NoBootstrap is retired, so there is no longer a parameter that defers this question.
$odataPre = Code 'https://localhost/fmi/odata/v4/'
if ($odataPre -eq 200 -or $odataPre -eq 401) { Ok "OData API enabled (HTTP $odataPre)" }
else { Die ("OData API is required but not responding (HTTP " + $odataPre + "). Enable it in the FileMaker Server Admin Console (Connectors -> FileMaker OData API), then re-run.") }

# Port: the loopback web port is an implementation constant, so it must be free unless it is our own
# service re-binding on an update. There is no -WebPort to move it to.
$portOwner = Get-NetTCPConnection -LocalPort $WebPort -State Listen -ErrorAction SilentlyContinue
if ($portOwner) {
  $ownerPid = $portOwner.OwningProcess | Select-Object -First 1
  $ownerName = (Get-Process -Id $ownerPid -ErrorAction SilentlyContinue).ProcessName
  if (-not (Get-Service $WebService -ErrorAction SilentlyContinue) -and $ownerName -ne 'python') {
    Die "Port $WebPort is already in use by '$ownerName' (PID $ownerPid). The loopback port is an implementation constant published by the installation manifest, so it cannot be moved by a parameter - free the port, then re-run."
  }
}

try { Import-Module WebAdministration -ErrorAction Stop }
catch { Die "IIS is not available (the WebAdministration module could not load). Install the IIS role (Web-Server) plus the URL Rewrite 2.1 and ARR 3.0 modules, then re-run. (We never auto-install IIS components.)" }
try { Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/rewrite' -ErrorAction Stop | Out-Null; Ok "IIS URL Rewrite module present" }
catch { Die "IIS URL Rewrite module missing. Install 'URL Rewrite 2.1' (rewrite_amd64_en-US.msi) then re-run." }
try {
  $arr = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'enabled' -ErrorAction Stop).Value
} catch { Die "IIS Application Request Routing (ARR) missing. Install 'ARR 3.0' (requestRouter_amd64.msi) then re-run." }
if ($arr) { Ok "ARR reverse-proxy enabled" } else { Warn "ARR reverse-proxy is OFF - it is enabled with the proxy at phase 16 (a global IIS toggle FMS itself relies on)" }
# -Site is retired: the FMS IIS site is DETECTED, never named. An installation that could be pointed
# at an arbitrary site by a parameter is a choice the product can make for itself.
$Site = ''
if (Get-Website -Name 'FMWebSite' -ErrorAction SilentlyContinue) { $Site = 'FMWebSite' }
else { $Site = (Get-Website | Where-Object { $_.Name -ne 'Default Web Site' -and $_.State -eq 'Started' } | Select-Object -First 1).Name }
if (-not $Site -or -not (Get-Website -Name $Site -ErrorAction SilentlyContinue)) { Die "Could not find the FMS IIS site (no 'FMWebSite' and no other started site). Start the FileMaker Server web site, then re-run." }
Ok "FMS IIS site: $Site (detected)"


# === PHASE 2 - Classify - fresh or valid new-format update ======================================
# Auto-detection only. There is no force parameter - re-running the installer IS the update command
# on both platforms.
#
# THE MARKER IS THIS INSTALLER'S OWN RECORD PLUS ITS OWN CHECKOUT, never the presence of a Python.
# `Test-Path $Py` was tried and is a DATA-LOSS PATH: `python\python.exe` is the ordinary layout of a
# real Windows Python installation, so `-InstallDir` aimed at one would classify it as an update,
# skip the replace-existing guard below (whose condition is "not an update"), and reach the
# unconditional `Remove-Item $PyDir -Recurse -Force` at phase 10. Linux's `$INSTALL_DIR/venv` is the
# same class of marker but a far less collision-prone name; on Windows the name is not safe to use.
#
# PUBLISHED AUTHORITY OUTRANKS THE MARKER (packet 1246-10-04). The marker is transitional and this
# installer no longer writes route facts into its home; an installation can be published, at a
# generation, with providers composed, and carry no `install.yaml` at all. Classifying that as a
# FRESH install is how a live box came within one phase of fresh-install cleanup over its own
# published record. So: a locator that is PRESENT with a VALID manifest, whose recorded install
# root is the root this run is installing to, IS an update - marker or no marker. It is read from
# the single lifecycle observation, never from a second detection path of this installer's own.
$MarkerPath = Join-Path $LegacyHome 'install.yaml'
# Do not ask the deployed lifecycle package to classify the box until the executing installer has
# proved it is the package's own installer. A real checkout is enough to make the check applicable;
# marker/manifest classification itself is the next read and cannot safely precede this boundary.
# PACKET 1398: AN INCOMPLETE FRESH-INSTALL ATTEMPT IS ROUTED FIRST - before any other classification
# and before phase-4+ work. An EMPTY container needs no interpreter to recognise. The one exception to
# "first" is an ordinary provider journal left inside a published attempt: its existing recover-first
# route at phase 3 runs first, and the attempt is routed immediately after it.
if (Test-Path -LiteralPath $script:AttemptDir) {
  if (La-ContainerIsEmpty) { $script:LaLeftoverEmpty = $true }
  else { La-RouteExistingAttempt 'first' }
}
if (Test-Path (Join-Path $Src '.git')) { Prepare-ExternalSourceAdvance $Src }
$lcStateEarly = Get-LcState
$PublishedHere = $false
if ($lcStateEarly) {
  $lcRoot = ("" + (Lc-Field $lcStateEarly 'install_dir')).TrimEnd('\')
  $PublishedHere = ((("" + (Lc-Field $lcStateEarly 'locator')) -eq 'present') -and
                    (("" + (Lc-Field $lcStateEarly 'manifest')) -eq 'valid') -and
                    ($lcRoot) -and ($lcRoot -eq $InstallDir.TrimEnd('\')))
}
$IsUpgrade = ((Test-Path $MarkerPath) -and (Test-Path $Src)) -or $PublishedHere
# An EMPTY protected attempt container is adopted by a fresh run and removed by any other (1398 2.1).
if ($script:LaLeftoverEmpty -and ($IsUpgrade -or $PublishedHere)) {
  $laProblem = La-ContainerProblem
  if ($laProblem) { Warn ("The empty attempt container is not in its protected shape and is left in place: " + $laProblem) }
  else {
    try { [IO.Directory]::Delete($script:AttemptDir, $false); Ok ("Removed an empty leftover fresh-install attempt container (" + $script:AttemptDir + ")") }
    catch { Warn ("Could not remove the empty leftover attempt container " + $script:AttemptDir + ": " + $_.Exception.Message) }
  }
  $script:LaLeftoverEmpty = $false
}
# THE SCHEDULER RETIREMENT ADAPTER'S SID PREFLIGHT (application packet 1361-01).
#
# Taken HERE, before phase 9 quiesces anything, before phase 8 creates or re-permissions a
# directory, and long before any installed byte is replaced - so a refusal costs nothing.
#
# PRESENCE IS THE TRIGGER, NOT THE FACT. An earlier version of this adapter reasoned that a
# registered service implies a resolvable account and stopped there. That is an assumption about
# LSA state, and the whole defect being corrected here was an assumption about exactly that. So
# presence REQUIRES a translation, and the successful translation is what establishes the fact:
# from here on the adapter carries a numerical SID it captured, never a name it hopes still
# resolves. If the translation fails we refuse now, while the box is untouched.
#
# A box that never had the service and a box a previous run already retired it from are the SAME
# case - no SID captured - and on that path nothing about the retired identity is resolved,
# named, or removed.
$SchedRetiredPresent = [bool](Get-Service $SchedServiceRetired -ErrorAction SilentlyContinue)
$SchedRetiredSid = ''
$SchedRetiredIcaclsOperand = ''
if ($SchedRetiredPresent) {
  try {
    $SchedRetiredSid = (New-Object System.Security.Principal.NTAccount($SchedRetiredAccount)
                       ).Translate([System.Security.Principal.SecurityIdentifier]).Value
  } catch {
    Die ("The retired " + $SchedServiceRetired + " service is registered but its account " +
         $SchedRetiredAccount + " does not resolve to a SID, so its grants could not be removed" +
         " or proven removed: " + $_.Exception.Message +
         " Nothing has been stopped or replaced. Resolve the account, or remove the service, then" +
         " re-run the installer.")
  }
  if (-not $SchedRetiredSid) {
    Die ("The retired " + $SchedServiceRetired + " service resolved to an empty SID. Nothing has" +
         " been stopped or replaced.")
  }
  # THE ICACLS OPERAND IS THE SID, ALWAYS. `*S-1-...` is icacls's own spelling for "this is a SID,
  # do not look up a name" - and a name lookup is the single thing that must never happen again on
  # this path, because it is what answers 1332 once the service is unregistered.
  $SchedRetiredIcaclsOperand = '*' + $SchedRetiredSid
  Info ("Retired " + $SchedServiceRetired + " service observed; its account resolved to " +
        $SchedRetiredSid + " and that SID is what will be removed and proven gone.")
}
if ($PublishedHere) {
  Info ("Published installation record at generation " + (Lc-Field $lcStateEarly 'generation') + " for " + $InstallDir + " - update mode")
} elseif ($IsUpgrade) { Info "Existing install found - update mode" } else { Info "Fresh install" }

# Hoisted deliberately: the phase 6 announcement reads $appMounted, and a variable left UNDEFINED by
# an untaken branch is falsy in PowerShell exactly as it is in Alpine - it would read as "not
# mounted" and quietly print the wrong plan. Compute it once, unconditionally, as a strict boolean.
$appMounted = [bool](Get-WebApplication -Site $Site -Name $WebPrefix.Trim('/') -ErrorAction SilentlyContinue)

# THE SELF-PULL IS RETIRED (parent section 4H.2). -NoPull, -Ref and -AllowDirty are gone, and with
# them the installer's habit of fetching new code mid-run. There is no version, branch, channel or
# rollback CHOICE to express, so there is nothing for the installer to decide here: it installs the
# checkout it finds. New code reaches a box through the in-app Updates button, which runs the
# privileged one-shot updater installed at phase 13.
#
# The TRUST RAILS those parameters waived are NOT retired, and nothing can waive them any more.
if ($IsUpgrade -and (Test-Path (Join-Path $Src '.git'))) {
  Info "Verifying installation source (origin + working tree)..."
  Assert-Origin $Src        # expected remote only - mandatory, no parameter can waive it
  Assert-CleanTree $Src     # no local modifications - mandatory, no parameter can waive it
}


# === PHASE 3 - Prior-operation routing ==========================================================
# An operation already in flight OWNS this box. Resuming, finalizing or aborting it is the whole of
# this invocation - cleanup is never combined with new work, because a run that repairs and then
# installs cannot say which half a later failure belongs to. Every branch ENDS the invocation; the
# administrator reruns.
#
# ROUTED ON THE FIELDS `status --json` ACTUALLY EMITS (packet 1246-04-04, correction C). This block
# used to match `"requires_recovery": true`. **There is no such key and there never was** -
# `requires_recovery()` is an internal Journal predicate - so the guard matched nothing, on every
# box, and the installer walked straight over an unresolved operation. The emitted vocabulary is
# journal in none|invalid|open|checkpointed|needs_recovery|resolved, with `journal_operation`,
# `journal_mode` and `journal_subsystem` beside it.
#
# On a fresh box there is no interpreter yet, so `status` cannot run at all. That is NOT unresolved
# evidence: an installation that does not exist has no operation in flight.
# THE GATE IS THE STATE, NOT THE INTERPRETER (correction R7). This block ran only when the bundled
# interpreter existed - so a box with an OPEN JOURNAL and a broken or missing Python walked straight
# past its own unresolved operation. And stderr was merged into stdout, so ONE diagnostic line made
# `Lc-Field` answer $null for every field, and every branch was skipped: "settled" inferred from an
# inability to look. Both directions failed OPEN. They now fail closed.
#
# The journal path is a FIXED platform location (`lifecycle/layout.py::windows_layout`), so its
# presence is established without running anything.
$CfmJournalFile = Join-Path $ConfigHome 'state\lifecycle-journal.json'
if (-not (Test-Path $script:Py)) {
  if (Test-Path $CfmJournalFile) {
    Die ("This machine holds a CORPUSfm lifecycle journal at " + $CfmJournalFile + " and no usable CORPUSfm interpreter to read it with. Refusing to begin new work over an operation this installer cannot inspect. Restore the bundled Python (re-running this installer rebuilds it) or resolve the operation with a working installation, then re-run. Nothing has been changed.")
  }
  Info "No prior CORPUSfm installation detected - nothing to recover."
} else {
  # THE SAME observation phase 2 classified from - taken once, validated once, read twice.
  $lcState = Get-LcState
  $lcJournal  = "" + (Lc-Field $lcState 'journal')
  $lcJOp      = "" + (Lc-Field $lcState 'journal_operation')
  $lcJMode    = "" + (Lc-Field $lcState 'journal_mode')
  $lcJSub     = "" + (Lc-Field $lcState 'journal_subsystem')
  $lcLocator  = "" + (Lc-Field $lcState 'locator')
  $lcManifest = "" + (Lc-Field $lcState 'manifest')
  if ($lcJournal -eq 'invalid') {
    # `invalid`, or a word this build does not know. Neither is routed and neither is assumed
    # harmless.
    Die ("This installation's lifecycle journal reads '" + $lcJournal + "', which this installer" +
         " cannot route. Inspect it with corpusfm-lifecycle status --json. Nothing has been changed.")
  }
  elseif ($lcJournal -eq 'open' -or $lcJournal -eq 'checkpointed' -or
          $lcJournal -eq 'needs_recovery' -or $lcJournal -eq 'resolved') {
    if ($script:RecoveryRuntimeKind -eq 'package' -and $lcJMode -eq 'uninstall') {
      try { $uninstallJournal = Get-Content -LiteralPath $CfmJournalFile -Raw | ConvertFrom-Json }
      catch { Die "The interrupted uninstall journal is unreadable and remains untouched." }
      $uninstallId = '' + $uninstallJournal.installation_id
      if (-not $uninstallId) { Die "The interrupted uninstall journal names no installation identity." }
      Info "Resuming the interrupted uninstall with the verified package runtime"
      Resume-PackagedInterruptedUninstall $uninstallId
    }
    # A001 FIRST, and only for its exact mode. Generic provider disposition cannot route this
    # journal at all - A001 is not a provider and is not being made one.
    if ($lcJMode -eq 'a001_scheduler_authority') {
      try { $a001Record = Get-Content -LiteralPath $CfmJournalFile -Raw | ConvertFrom-Json }
      catch { Die "The retained A001 lifecycle journal is unreadable and remains untouched." }
      Lc-RecoverA001Authority $a001Record $lcState
    }
    # One application-owned boundary maps both preflight journal state and provider results to the
    # same three operator conditions. Platform code neither guesses a recovery verb nor emits a
    # placeholder request.
    Lc-PreflightDisposition
    if ($LcCondition -eq 'recover_first') {
      Warn $LcDispositionReason
      Complete-CfmOwedLifecycleRecovery
    }
    elseif ($LcCondition -eq 'continue' -and $LcRetireProvider) {
      $journalRaw = Get-Content -LiteralPath $CfmJournalFile -Raw | ConvertFrom-Json
      $script:InstallationId = "" + $journalRaw.installation_id
      Lc-DiscardProvider $LcRetireProvider $LcOp
      Ok ("Retired resolved " + $LcRetireProvider + " lifecycle record")
      $lcJournal = 'none'
    }
    elseif ($LcCondition -ne 'continue') {
      Die ("The prior lifecycle journal was classified as '" + $LcCondition +
           "', which preflight cannot apply. It remains untouched.")
    }
  }
  elseif ($lcJournal -and $lcJournal -ne 'none') {
    Die ("This installation's lifecycle journal reads '" + $lcJournal + "', which this installer" +
         " cannot route. Inspect it with corpusfm-lifecycle status --json. Nothing has been changed.")
  }
  # Foreign or contradictory IDENTITY evidence refuses too, for the same reason.
  if ($lcLocator -and $lcLocator -ne 'missing' -and $lcLocator -ne 'present') {
    Die ("This installation's locator reads '" + $lcLocator + "'; refusing to work over evidence" +
         " that cannot be read. Nothing has been changed.")
  }
  if ($lcLocator -eq 'present' -and $lcManifest -ne 'valid') {
    Die ("This installation publishes a locator but its manifest reads '" + $lcManifest + "';" +
         " refusing to work over a record that disagrees with itself. Nothing has been changed.")
  }
}
if ($script:LaRouteDeferred) { La-RouteExistingAttempt 'final' }


# === PHASE 4 - Accept and validate the authoritative inputs =====================================
Section "Settings"
# The patch hosting folder defaults to a top-level, clearly-named folder on the FMS DATA DRIVE -
# deliberately OUTSIDE InstallDir so removing the install directory never touches user-generated
# databases (the preserve rule). It is derived here, after -FmsRoot has been resolved, because a
# hard-coded C: would be wrong on a box whose FMS lives on another volume.
if (-not $PatchHostingDir) {
  $fmsDrive = Split-Path $FmsBin -Qualifier              # 'C:' / 'D:' - the FMS data drive
  $PatchHostingDir = Join-Path ($fmsDrive + '\') 'CORPUSfm-Hosted'
}
$SupportDir = Join-Path $FmDbDir 'CORPUSfm-Support'
Info ("InstallDir:      " + $InstallDir)
if ($InstallerSeries) {
  Info ("Installer:       " + $InstallerSeries + " / " + $InstallerVersion)
  Info ("Package source:  " + $PackageApplicationVersion + " @ " + $PackageCommit.Substring(0, 12))
} else {
  Info "Installer:       direct checkout (no release descriptor)"
}
Info ("PatchHostingDir: " + $PatchHostingDir)
Info ("FmsRoot:         " + $FmsBin)
Info ("Config/state:    " + $ConfigHome + "  (platform layout; not a choice)")
Info ("Web:             loopback " + $WebPort + " behind " + $WebPrefix + "/  (implementation constants published by the installation record)")
Info ("MCP:             folded into the web app at " + $WebPrefix + "/mcp/ (user-authenticated)")
$declared = @()
if ($ProxyPolicyAdd.Count)    { $declared += ('-ProxyPolicyAdd ' + ($ProxyPolicyAdd -join ',')) }
if ($ProxyPolicyIgnore.Count) { $declared += ('-ProxyPolicyIgnore ' + ($ProxyPolicyIgnore -join ',')) }
if ($RepairStorageAccess)     { $declared += '-RepairStorageAccess' }
if ($ReplaceExistingInstall)  { $declared += '-ReplaceExistingInstall' }
if ($DiscardIncompleteAttempt) { $declared += '-DiscardIncompleteAttempt' }
if ($Silent)                  { $declared += '-Silent' }
if ($Yes)                     { $declared += '-Yes' }
Info ("Options:         " + $(if ($declared.Count) { ($declared -join ' ') } else { "(none)" }))

# -ReplaceExistingInstall authorizes moving an existing, non-empty install directory that carries NO
# CORPUSfm installation trace. It is deliberately narrow: it is NOT a way to convert, replace or
# discard a CORPUSfm installation of any format. A directory holding a trace is never touched here.
# The guard is NOT gated on "this is a fresh install". Gating it that way is what turned a
# mis-classification into a deletion: whatever decides the classification, a directory this
# installer did not create must never be wiped by phase 10.
$ReplaceAside = ''
$ReplaceAsideWasDebris = $false
if (Test-Path $InstallDir) {
  $existing = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue)
  # A failed/interrupted phase 10 can leave only the installer-owned dependency cache/runtime and
  # the empty product directories phase 8 prepared. With no locator, manifest, marker, source or
  # service definition this is resumable preparation, not an unknown CORPUSfm installation. Keep
  # the recognition narrow at the root: arbitrary files, extra directories, product source, or a
  # populated immutable-product directory still take the refusal paths below.
  $residueRootNames = @('bin','downloads','git','lib','proxy','python','services')
  $unexpectedResidue = @($existing | Where-Object {
    -not $_.PSIsContainer -or $_.Name -notin $residueRootNames
  })
  $populatedProductDirs = @($BinDir,$LibDir,$ProxyDir,$SvcDir | Where-Object {
    (Test-Path $_) -and @(Get-ChildItem -LiteralPath $_ -Force -ErrorAction SilentlyContinue).Count
  })
  $dependencyResidue = [bool]($InstallerSeries -and -not $IsUpgrade -and
    -not (Test-Path $Src) -and $unexpectedResidue.Count -eq 0 -and
    $populatedProductDirs.Count -eq 0)
  # Evidence about THIS directory, so the check is about what is in front of us. The state
  # directory lives elsewhere and says nothing about which software root was chosen.
  $ours = (Test-Path $Src) -or (Test-Path $SvcDir)
  # ...but PRODUCT FILES ARE NOT AUTHORITY (packet 1257). A run interrupted after the source clone
  # leaves `src\` behind, which made `$ours` true and sent the box to the refusal below - the one no
  # parameter overrides. That refusal is right for an installation whose record is missing or
  # mismatched; it is wrong for debris that never had a record at all, and it left the box
  # unrecoverable by its own installer. The authority check is what separates the two.
  $tracelessDebris = [bool]($ours -and -not $IsUpgrade -and -not (Test-CfmInstallationAuthority))
  if ($dependencyResidue) {
    Info "Resuming installer-owned dependency preparation; no installation record or product payload exists yet."
  } elseif ($existing.Count -gt 0 -and (-not $ours -or $tracelessDebris)) {
    if (-not $ReplaceExistingInstall) {
      if ($tracelessDebris) {
        Die ("$InstallDir holds files from an interrupted CORPUSfm installation - product source" +
             " or service definitions are present, but there is no locator, manifest or install" +
             " marker, so no installation was ever published. Re-run with -ReplaceExistingInstall" +
             " to have the installer move that debris aside, or choose another -InstallDir." +
             " Nothing has been changed.")
      }
      Die ("$InstallDir exists, is not empty, and carries no CORPUSfm installation. Re-run with" +
           " -ReplaceExistingInstall to have the installer move it aside, or choose another" +
           " -InstallDir. Nothing has been changed.")
    }
    $ReplaceAside = $InstallDir + '.replaced-' + (Get-Date).ToString('yyyyMMdd-HHmmss')
    # WHY the move was authorized, carried to the pre-mutation re-check so it re-observes this
    # basis rather than a shape that may legitimately differ.
    $ReplaceAsideWasDebris = $tracelessDebris
    Warn ("Plan: move the existing directory aside to " + $ReplaceAside +
          " after final consent (-ReplaceExistingInstall)" +
          $(if ($tracelessDebris) { " - authorized as traceless installation debris" } else { "" }))
  } elseif ($ours -and -not $IsUpgrade) {
    Die ("$InstallDir carries a CORPUSfm installation this installer cannot account for - its" +
         " record is missing or does not match. This is an incomplete or old-format installation," +
         " and no parameter converts, replaces or discards one. Resolve it deliberately, then" +
         " re-run. Nothing has been changed.")
  }
}


# === PHASE 5 - Preflight and prepare required inputs =============================================
# First determine credential need from read-only configuration. Then acquire and validate the
# credentials required by that measured plan. Phase 6 consumes only the prepared result, so every
# required fresh-install question is answered before the final consent boundary.
#
# ASK ONLY WHEN THE MEASURED MODE WILL USE IT. IIS publication takes effect without fmsadmin, while
# an independently observed active Claris nginx front needs one authenticated HTTP-server restart
# after its exact CORPUSfm family is staged. A normal IIS update preserves storage and needs no FMS
# password. Fresh bootstrap, an explicitly requested storage-access repair, and active-Claris proxy
# reconciliation consume one. `server_configs.yaml` is deliberately not consulted; it is a retired projection
# and caused a healthy published installation to be misreported as needing bootstrap on 0.2380.
$NeedFmsCreds = (-not $IsUpgrade) -or [bool]$RepairStorageAccess -or $ClarisNginxActive
if (-not $IsUpgrade) { Info "Fresh storage bootstrap requires FileMaker Server administrator credentials." }
elseif ($RepairStorageAccess) { Info "The requested storage-access repair requires FileMaker Server administrator credentials." }
elseif ($ClarisNginxActive) { Info "Active Claris nginx proxy reconciliation requires FileMaker Server administrator credentials." }
else { Info "Published-install update preserves storage - no FM admin credentials needed for this plan." }

# Acquire and authenticate every credential the measured plan requires before final consent. The
# values are means, not consent, and are removed from the inherited environment immediately.
$FmAdminUser = $env:FM_ADMIN_USER
$FmAdminPass = $env:FM_ADMIN_PASS
$env:FM_ADMIN_PASS = $null; $env:FM_ADMIN_USER = $null
if (-not $FmAdminUser) { $FmAdminUser = 'admin' }
if ($NeedFmsCreds -and -not $FmAdminPass) {
  if ($Silent) { Die "-Silent requires FM_ADMIN_USER and FM_ADMIN_PASS before installation." }
  Info "FileMaker Server admin credentials are required for this plan and are never stored."
  $u = Read-Host "  FM Server admin account username:"
  if ($u) { $FmAdminUser = $u }
  do { $sec = Read-Host "  FM Server admin account password:" -AsSecureString } while ($sec.Length -eq 0)
  $FmAdminPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
if ($NeedFmsCreds) {
  Info "Verifying FM Server credentials..."
  $eapV = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & (Join-Path $FmsBin 'fmsadmin.exe') -u $FmAdminUser -p $FmAdminPass list files *> $null
  $vrc = $LASTEXITCODE; $ErrorActionPreference = $eapV
  if ($vrc -ne 0) { $FmAdminPass = ''; Die "FM Server admin login failed; no installation mutation began." }
  Ok ("FileMaker Server is active and reachable; administrator '" + $FmAdminUser + "' authenticated")
}

$AdminUser = $env:CORPUSFM_ADMIN_USER
$AdminPass = $env:CORPUSFM_ADMIN_PASS
$env:CORPUSFM_ADMIN_PASS = $null; $env:CORPUSFM_ADMIN_USER = $null
if (-not $IsUpgrade) {
  if (-not $AdminPass) {
    if ($Silent) { Die "-Silent fresh install requires CORPUSFM_ADMIN_USER and CORPUSFM_ADMIN_PASS." }
    $auIn = Read-Host "  First CORPUSfm admin username [admin]"
    if ($auIn) { $AdminUser = $auIn }
    $sec1 = Read-Host "  First CORPUSfm admin password (min 8 chars)" -AsSecureString
    $sec2 = Read-Host "  Confirm CORPUSfm admin password" -AsSecureString
    $p1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec1))
    $p2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec2))
    if ($p1 -ne $p2) { Die "CORPUSfm admin passwords did not match; no installation mutation began." }
    $AdminPass = $p1
  }
  if (-not $AdminUser) { $AdminUser = 'admin' }
  if (-not $AdminPass -or $AdminPass.Length -lt 8) {
    $AdminPass = ''; Die "The first CORPUSfm admin password must be at least 8 characters."
  }
}


# === PHASE 6 - Complete plan ====================================================================
# Every interactive install and update crosses the same explicit final-consent boundary. Re-running
# an installer selects the update operation; it does not silently consent to the measured changes.
# Only -Yes/-Silent or the verified bootstrap handoff may pre-grant that consent.

Section "Confirm"
# ANNOUNCE ALWAYS (SPEC S6): "Don't display an action that won't be performed under the given
# settings." Only the WAIT is conditional; a silent run still records what it was about to do.
Info ("This " + $(if ($IsUpgrade) { "UPDATE" } else { "INSTALL" }) + " will:")
Info ("    - install the code + Python runtime in " + $InstallDir + ", stop the CORPUSfm services first, and start them again once their definitions are verified")
if (-not $IsUpgrade) {
  Info ("    - create " + $InstallDir + " and " + $ConfigHome + ", and lock the config/data tree to SYSTEM+Administrators")
  Info ("    - publish this installation's record, compose patch, proxy, admin identity and storage")
  Info ("    - register the " + $WebService + " service")
}
if (-not $appMounted) { Info ("    - mount the isolated IIS application " + $WebPrefix + " under " + $Site) }
else { Info ("    - IIS application " + $WebPrefix + " is already mounted under " + $Site + " - no FMS web-site change") }
if (-not $arr) { Info "    - enable the global ARR reverse-proxy toggle (currently OFF; FMS relies on it too)" }
if (-not $IsUpgrade) { Info "    - deploy + bootstrap the CORPUSfm storage DB" }
else { Info "    - leave the hosted CORPUSfm_DB and its bootstrap untouched" }
if ($ClarisNginxActive) {
  Info "    - stage the bounded CORPUSfm nginx include and restart the FMS HTTP server once to activate it"
} else {
  Info "  No FMS web-server restart is needed for the IIS application."
}
if ($NeedFmsCreds) { Info ("  FMS administrator:    " + $FmAdminUser + " (authenticated)") }
if (-not $IsUpgrade) { Info ("  First CORPUSfm admin: " + $AdminUser + " (input validated)") }
Cfm-Confirm -Prompt 'Proceed?'


# === PHASE 7 - Report credential disposition ====================================================
Section "Permissions"
if (-not $NeedFmsCreds) { Info "No FM admin credential required; existing storage is preserved." }


# === PHASE 8 - Establish or verify the layout and preconditions =================================
Section "Progress"
# packet 1380-02: the SYSTEM updater task's AllSigned prerequisite, immediately before phase 8's first
# installation mutation, so a refusal leaves phases 8-12 unstarted and nothing installed or changed.
Assert-CfmSystemTaskTrust -EntryPoint $PSCommandPath
# PACKET 1398: the protected attempt container and its record are the first durable change of a
# no-authority fresh start. An update, and any run with published authority, never creates one.
if (-not $IsUpgrade -and -not $PublishedHere) { La-BeginAttempt }
Info "Fixed OS state locations"
if ($ReplaceAside) {
  # The facts used to authorize replacement were observed before consent. Re-observe the exact
  # target immediately before the first mutation so a path changed during the prompt is refused,
  # not silently treated as the directory the administrator approved moving.
  #
  # RE-OBSERVE THE BASIS THE PLAN WAS AUTHORIZED ON, not a fixed shape (packet 1257). This used to
  # refuse whenever `src\` or `services\` existed, which re-derived "-not $ours" and so contradicted
  # a plan that was deliberately authorized FOR traceless debris - and debris from an interrupted
  # run is exactly what contains `src\`. The box then refused here, after consent, having planned
  # the move it would not perform.
  #
  # What must still be true is the property that authorized the move: no installation AUTHORITY.
  # An installation that appeared during the prompt is refused on either basis; product FILES are
  # re-checked only when the plan was authorized on their absence.
  $basisChanged = if ($ReplaceAsideWasDebris) { Test-CfmInstallationAuthority }
                  else { (Test-Path -LiteralPath $Src) -or (Test-Path -LiteralPath $SvcDir) -or
                         (Test-CfmInstallationAuthority) }
  if (-not (Test-Path -LiteralPath $InstallDir) -or $basisChanged -or
      (Test-Path -LiteralPath $ReplaceAside)) {
    Die "The existing-install replacement facts changed after confirmation; nothing was moved. Re-run to review the new plan."
  }
  $replaceNow = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue)
  if ($replaceNow.Count -eq 0) {
    Die "The directory approved for replacement is now empty; nothing was moved. Re-run to review the new plan."
  }
  La-Do 'dir' 'move_aside' ([ordered]@{ moved_to = $ReplaceAside }) @($InstallDir) {
    Move-Item -LiteralPath $InstallDir -Destination $ReplaceAside
  }
  Warn ("Moved the approved existing directory aside to " + $ReplaceAside)
}
La-Do 'dir' 'ensure' $null @($InstallDir,$ConfigHome,$SvcDir,$BinDir,$LibDir,$LogDir,$ProxyDir,$Dl) {
  New-Item -ItemType Directory -Force -Path $InstallDir,$ConfigHome,$SvcDir,$BinDir,$LibDir,$LogDir,$ProxyDir,$Dl | Out-Null
}
# ConfigHome is HOME for the services' at-rest state, so the app writes secrets there at runtime -
# corpus.key (the portable Corpus Key), machine.key (the Machine Key, which belongs to this
# installation and never leaves it), install.yaml, server_configs.yaml. On Windows POSIX chmod is a
# no-op, so lock the whole tree to SYSTEM+Administrators with inheritance BEFORE anything is
# written, so those runtime files inherit a safe ACL instead of C:\ProgramData's default Users:(RX).
# ConfigHome is CORPUSfm-only (never IIS-read), so a tree lock is safe here; InstallDir is NOT
# tree-locked (its proxy\web.config must stay IIS-readable). Installed secrets remain under the
# provider-owned ConfigHome tree and are read-only to both runtime services.
La-Do 'dir' 'set_acl' $null @($ConfigHome) { Lock-DirTreeAcl $ConfigHome }
# The separated fixed locations. State, logs and run become service-writable at phase 20, once the
# service identities exist; SECRETS never does, and neither service may create, delete or rename
# anything in it - which is what makes the per-file protection at phase 20 mean something.
La-Do 'dir' 'ensure' $null @($FixedConfig,$FixedState,$FixedSecrets,$FixedRun,$InboxDir,$OutcomeDir,$LegacyHome) {
  New-Item -ItemType Directory -Force -Path $FixedConfig,$FixedState,$FixedSecrets,$FixedRun,$InboxDir,$OutcomeDir,$LegacyHome | Out-Null
}
# THE OUTCOME DIRECTORY IS SYSTEM'S. The service writes the update REQUEST, so the inbox is
# service-writable; the OUTCOME is SYSTEM's word about what the elevated operation did, and a
# directory the service could create, delete or rename entries in would let it forge one naming its
# own trigger id - correlation is not authentication. Their PROTECTIVE DACLs are written at phase
# 20, in one call each naming all four principals, because `NT SERVICE\<id>` has no SID until the
# service is registered. Between here and there they inherit the ConfigHome tree lock above, which
# is already SYSTEM+Administrators only - so there is no window in which either is loose.
Ok ("State locations ready (" + $FixedConfig + ", " + $FixedState + ", " + $FixedSecrets + ", " + $LogDir + ", " + $FixedRun + ")")
Ok "Update inbox (service-writable at phase 20) and outcome (SYSTEM-owned) separated"


# === PHASE 9 - QUIESCE UPDATE - stop every existing CORPUSfm service ============================
# THE ONLY PLACE A SERVICE IS STOPPED, AND IT RUNS BEFORE PHASE 10 REPLACES A BYTE. Windows installs
# the interpreter in place - it has no staging directory to build a replacement runtime in while the
# old one keeps serving - so a running service holds python.exe and its native extension DLLs
# (onnxruntime / pydantic-core / numpy .pyd) memory-mapped, and Windows refuses to overwrite a loaded
# binary. Before this packet the stops were scattered: one inside the interpreter-version branch and
# another before pip, so the same-version path replaced dependencies under a service that had been
# stopped by a branch that had not been taken. One quiesce, here, covers both.
if ($IsUpgrade) {
  Info "Stopping services"
  # The retired scheduler service is quiesced here too: an upgrade of a box that still carries it
  # must stop it before the new code lands, or it keeps reading FileMaker under the old runtime.
  # Phase 20 then deletes it.
  foreach ($svc in @($WebService, $SchedServiceRetired)) {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Stopped') {
      Info "Stopping $svc ..."
      Stop-Service $svc -Force -ErrorAction SilentlyContinue
      try { $s.WaitForStatus('Stopped','00:00:30') } catch {}
    }
  }
}
# A WinSW child python can linger a beat after the service reports Stopped, and on a fresh install
# a stray python from an interrupted earlier run can hold the same directory. Unconditional, and
# scoped to interpreters under THIS installation's python directory.
Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.ExecutablePath -and $_.ExecutablePath.ToLower().StartsWith($PyDir.ToLower()) } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 750
Ok "No CORPUSfm service is running; nothing has been replaced yet"


# === PHASE 10 - Install code and immutable helpers - FIRST byte replacement =====================
Info "Dependency bootstrap"
# Egress preflight: ANY HTTP response means the network is up (a 429/redirect/error still proves
# egress); only a real connection failure (Code -1) counts as down. Retry past a transient blip.
$egress = $false
for ($i=0; $i -lt 3 -and -not $egress; $i++) { if ((Code 'https://github.com') -ge 0) { $egress = $true } else { Start-Sleep -Seconds 3 } }
if ($egress) { Ok "Internet egress OK" } else { Die "No internet egress (need https to python.org + github.com to fetch Python/git/deps). Check the proxy/firewall." }
# EMBEDDABLE Python: a plain ZIP, no MSI, no machine-wide registration. This is deliberate - the MSI
# installer leaves global state that a file-delete can't undo (a stuck registration makes a
# same-version reinstall no-op to an empty dir). Extract-and-delete is always clean.
#
# ALIGNED to the same CPython the Linux installer bundles (python-build-standalone 3.13.14) - so one
# validated interpreter version runs on both platforms and a bump is one re-pin per OS. The download
# is SHA256-PINNED: a mismatch Dies before extract, so a tampered/wrong artifact can never become the
# runtime. To bump: change $pyVer + $pySha256 together (SHA256 of the python.org embeddable zip),
# then regenerate constraints-server-win-py<MAJ><MIN>.txt on a Windows box.
$pyVer = $script:PythonRuntimeVersion
$pySha256 = $script:PythonRuntimeSha256  # python-3.13.14-embed-amd64.zip
# Reinstall when Python is absent/broken OR a DIFFERENT version than $pyVer (a version bump must take
# effect - a working older interpreter is NOT left in place). Wiping $PyDir also clears the old
# site-packages, so the deps stage rebuilds the graph against the new interpreter's ABI.
$pyOk = $false
$cur = ''
if (Test-Path $Py) {
  $cur = (& $Py -c "import platform;print(platform.python_version())" 2>$null)
  if ($LASTEXITCODE -eq 0) { & $Py -c "import encodings, ssl" 2>$null; $pyOk = ($LASTEXITCODE -eq 0) -and ("$cur".Trim() -eq $pyVer) }
}
if (-not $pyOk) {
  # DOWNLOAD AND VERIFY BEFORE WIPING. The services are already stopped (phase 9), so the wipe is
  # safe; verifying first means a failed or garbage download Dies with the old runtime still on
  # disk, never stranding the box with no interpreter at all.
  $zip = Join-Path $Dl "python-$pyVer-embed-amd64.zip"
  Info "Downloading embeddable Python $pyVer ..."
  Get-File "https://www.python.org/ftp/python/$pyVer/python-$pyVer-embed-amd64.zip" $zip
  $got = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $pySha256) { Die "Embeddable Python checksum mismatch (expected $pySha256, got $got) - refusing to extract a tampered/wrong artifact." }
  Ok "Embeddable Python SHA256 verified"
  if (Test-Path $PyDir) {
    if ($cur -and "$cur".Trim() -ne $pyVer) { Info ("Replacing bundled Python " + "$cur".Trim() + " -> $pyVer (aligned to the Linux CPython).") }
    else { Warn "Existing Python is broken/partial - reinstalling." }
    Remove-Item $PyDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  Expand-Archive -Path $zip -DestinationPath $PyDir -Force
  if (-not (Test-Path $Py)) { Die "Embeddable Python extract failed (no python.exe at $Py)." }
  # The ._pth controls sys.path AND disables env (PYTHONPATH is ignored under a ._pth) - so we
  # enable site (for pip), add Lib\site-packages (where pip installs), and put the app source
  # ($Src) directly on the path (since PYTHONPATH won't be honored). This is also why the canonical
  # service definitions rendered at phase 20 need no PYTHONPATH entry: the interpreter carries it.
  $pth = Get-ChildItem $PyDir -Filter 'python*._pth' | Select-Object -First 1
  @("python$($pyVer.Split('.')[0])$($pyVer.Split('.')[1]).zip", ".", "Lib\site-packages", $Src, "import site") |
    Set-Content -Path $pth.FullName -Encoding ascii
  # Bootstrap pip (embeddable omits ensurepip) via get-pip.py.
  Info "Bootstrapping pip ..."
  $getpip = Join-Path $Dl 'get-pip.py'
  Get-File 'https://bootstrap.pypa.io/get-pip.py' $getpip
  Cfm-Run "pip bootstrap" $Py $getpip --no-warn-script-location
  & $Py -m pip --version 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "pip bootstrap failed in embeddable Python." }
}
Ok ("Python: " + (& $Py --version) + " (embeddable)")

# The environment every INSTALLER-RUN Python child inherits. It is not, and must not be confused
# with, the service definition's environment: the definitions rendered at phase 20 are built by
# `lifecycle/service_identity`, which allows a short, exact list and no HOME at all.
$env:USERPROFILE = $ConfigHome
$env:HOME = $ConfigHome
$env:PYTHONPATH = $Src
$env:CORPUSFM_MODE = 'server'

if (-not (Test-Path $Git)) {
  Info "Resolving + downloading MinGit ..."
  $rel = Get-Json 'https://api.github.com/repos/git-for-windows/git/releases/latest'
  $asset = $rel.assets | Where-Object { $_.name -like 'MinGit-*-64-bit.zip' -and $_.name -notlike '*busybox*' } | Select-Object -First 1
  if (-not $asset) { Die "No MinGit asset found in the latest git-for-windows release." }
  $zip = Join-Path $Dl $asset.name
  Get-File $asset.browser_download_url $zip
  Expand-Archive -Path $zip -DestinationPath (Join-Path $InstallDir 'git') -Force
}
if (-not (Test-Path $Git)) { Die "git.exe missing after MinGit extract ($Git)." }
Ok ("git: " + (& $Git --version))

Info "Source"
# A fresh packaged install has no deployed checkout during the early skew boundary, and MinGit does
# not exist until this phase. Materialize the adjacent exact bundle now, after MinGit is verified but
# before any canonical source directory is created. Existing installations already did this during
# the early read-only comparison and reuse that proven SourceSeed here.
if (-not (Test-Path (Join-Path $Src '.git')) -and $InstallerSeries) {
  Prepare-ExternalSourceAdvance $Src
}
# credential.helper= (empty) disables MinGit's wincredman store so the in-URL token isn't cached
# (and doesn't error trying to persist). GIT_TERMINAL_PROMPT=0 keeps a bad token from hanging.
$env:GIT_TERMINAL_PROMPT = '0'
$GitNoCred = @('-c','credential.helper=')
if (Test-Path (Join-Path $Src '.git')) {
  if ($ExternalSourceAdvance) {
    # Recheck the deployed tree at the mutation boundary.  Phase 2 proved both checkouts, but an
    # administrator or interrupted process could have changed this one before quiescence completed.
    Assert-CleanTree $Src
    Info ("Existing checkout - advancing it to the exact external payload " +
          $ExternalSourceHead.Substring(0, 12))
    & $Git -C $Src fetch $SourceSeed refs/heads/main
    if ($LASTEXITCODE -ne 0) { Die "could not import the exact external payload" }
    $fetched = ("" + (& $Git -C $Src rev-parse FETCH_HEAD 2>$null)).Trim()
    if ($fetched -ne $ExternalSourceHead) {
      Die "the imported payload does not match the commit proven before quiescence"
    }
    & $Git -C $Src reset --hard $ExternalSourceHead
    if ($LASTEXITCODE -ne 0) { Die "could not advance the deployed checkout to the external payload" }
    $advanced = ("" + (& $Git -C $Src rev-parse HEAD 2>$null)).Trim()
    if ($advanced -ne $ExternalSourceHead) {
      Die "the deployed checkout did not read back at the exact external payload"
    }
    # `fetch $SourceSeed refs/heads/main` writes FETCH_HEAD only. Preserve the package's exact
    # identity in the deployed remote-tracking ref too; otherwise a successful upgrade can leave
    # new HEAD beside stale origin/main, and the Settings update classifier calls that divergence.
    # This value is not caller authority: ExternalSourceHead was independently proven against the
    # digested package before quiescence and read back again above.
    & $Git -C $Src update-ref ("refs/remotes/origin/" + $GitTrackedBranch) $ExternalSourceHead
    if ($LASTEXITCODE -ne 0) {
      Die "could not align origin/main with the verified deployed payload"
    }
    $tracked = ("" + (& $Git -C $Src rev-parse ("origin/" + $GitTrackedBranch) 2>$null)).Trim()
    if ($tracked -ne $ExternalSourceHead) {
      Die "origin/main did not read back at the verified deployed payload"
    }
    Assert-InstallerSourceAgreement $Src
  } else {
    # The in-app updater remains the ordinary code-only advancer.  A matching installer rerun
    # installs the checkout as it stands and moves no ref.
    Info "Existing checkout - installing it as it stands (new code arrives through the Updates button)."
  }
} else {
  # Blobless partial clone (--filter=blob:none): fetch the FULL commit graph (so the rev-list version
  # stamp stays exact - it walks commits, not blobs) but DEFER the historical blob pack; only HEAD's
  # blobs are fetched at checkout. This is a blobless partial clone, NOT the technically treeless
  # --filter=tree:0, which would also drop the tree objects rev-list needs. Lazy blobs a later pull
  # needs come from origin via the credential store wired below. --progress so a slow/proxied link
  # is VISIBLY moving.
  #
  # STAGE-THEN-PROMOTE (interruption safety): clone into an installer-owned SIBLING staging dir
  # (same volume as $Src, so promotion is a rename, never a cross-volume copy), and promote it to
  # canonical $Src only AFTER git reports success and origin is normalized. Cloning straight into
  # $Src used to mean a Ctrl-C left a partial $Src\.git that the next run's presence check mistook
  # for an installed checkout. A failed, exhausted or interrupted attempt never creates a canonical
  # $Src\.git.
  #
  # We NEVER auto-delete a canonical $Src here. If $Src exists in this branch it has no .git, so it
  # is unrecognized content - not our checkout. Fail closed and let the administrator resolve it.
  if (Test-Path $Src) {
    Die ("Source directory exists but is not a recognized CORPUSfm Git checkout (no .git): $Src`n" +
         "     Refusing to delete or overwrite it automatically. If it is leftover from an interrupted`n" +
         "     install, remove it yourself and re-run; otherwise move your content aside first.")
  }
  $cloneStage = "$Src.clone-partial"
  $cloneUrl = "https://github.com/$Repo.git"
  $hasSourceSeed = (
    (Test-Path -LiteralPath (Join-Path $SourceSeed '.git')) -and
    (Test-Path -LiteralPath (Join-Path $SourceSeed 'corpusfm') -PathType Container)
  )
  $cloned = $false
  $promoted = $false
  try {
    # Remove stale staging before either source is consulted. A prior hard interruption may have
    # left it, but neither path ever deletes or overwrites canonical $Src.
    if (Test-Path $cloneStage) { Remove-Item -Recurse -Force $cloneStage -ErrorAction SilentlyContinue }
    if ($hasSourceSeed) {
      # The seed is authoritative as the exact application checkout selected by this installer.
      # A focused distribution proves it through the digested manifest's application commit; a
      # development checkout still proves same-repository script agreement. Its tracked tree must
      # be clean and HEAD must be the bundled origin/main. Clone with no hardlinks so the installed
      # tree is independent of disposable adapter staging. The canonical checkout's origin is
      # normalized below before promotion.
      Assert-InstallerSourceAgreement $SourceSeed
      Assert-CleanTree $SourceSeed
      $seedHead = (& $Git -C $SourceSeed rev-parse HEAD).Trim()
      $seedMain = (& $Git -C $SourceSeed rev-parse origin/main).Trim()
      if (-not $seedHead -or $seedHead -ne $seedMain) {
        Die ("Bundled source checkout is not at its recorded origin/main; refusing to seed the " +
             "installation from an ambiguous revision.")
      }
      Info ("Seeding the installed source from the complete checkout that carries this installer (" +
            $seedHead.Substring(0, 8) + ")")
      & $Git clone --no-hardlinks --branch $GitTrackedBranch $SourceSeed $cloneStage
      if ($LASTEXITCODE -eq 0) {
        $stageHead = (& $Git -C $cloneStage rev-parse HEAD).Trim()
        $cloned = ($stageHead -eq $seedHead)
      }
      if (-not $cloned) {
        if (Test-Path $cloneStage) { Remove-Item -Recurse -Force $cloneStage -ErrorAction SilentlyContinue }
        Die "The exact bundled source could not be cloned and read back; nothing was promoted."
      }
    } else {
      for ($attempt = 1; $attempt -le 4; $attempt++) {
        # Remove partial network staging before EVERY attempt. Attempt 1 was already cleaned above;
        # retaining this inside the loop also cleans a failed preceding attempt in this run.
        if (Test-Path $cloneStage) { Remove-Item -Recurse -Force $cloneStage -ErrorAction SilentlyContinue }
        if ($attempt -gt 1) {
          Warn ("Source clone attempt " + $attempt + " of 4 (previous did not complete)")
          Start-Sleep -Seconds (5 * ($attempt - 1))
        }
        & $Git $GitNoCred -c http.postBuffer=524288000 -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 clone '--filter=blob:none' --branch $GitTrackedBranch --progress $cloneUrl $cloneStage
        if ($LASTEXITCODE -eq 0) { $cloned = $true; break }
      }
    }
    if (-not $cloned) {
      # Truthful cleanup BEFORE the terminal error: remove the partial staging checkout, then report.
      if (Test-Path $cloneStage) { Remove-Item -Recurse -Force $cloneStage -ErrorAction SilentlyContinue }
      if (Test-Path $cloneStage) { Die "git clone failed after 4 attempts (network/proxy, or interrupted), and the partial staging checkout ($cloneStage) could not be removed - delete it manually, then re-run the installer." }
      Die "git clone failed after 4 attempts (network/proxy, or interrupted). The partial staging checkout was cleaned up - re-run the installer."
    }
    # Inexpensive sanity check: a valid HEAD + real work tree must exist before we go further.
    & $Git -C $cloneStage rev-parse --verify --quiet HEAD *> $null
    if ($LASTEXITCODE -ne 0) { Die "Staged clone has no valid HEAD - refusing to promote an incomplete checkout. Re-run the installer." }
    # Normalize origin to the tokenless URL in STAGING as the LAST step before promotion, so the
    # PROMOTED checkout never persists the authenticated clone URL. set-url is a native command: a
    # FAILED normalize must NOT reach promotion (else the token URL would persist) - NeedExit Dies,
    # and the finally cleans staging.
    & $Git -C $cloneStage remote set-url origin "https://github.com/$Repo.git"; NeedExit $LASTEXITCODE "normalize staged origin (tokenless)"
    Move-Item -LiteralPath $cloneStage -Destination $Src
    $promoted = $true
  } finally {
    # Best-effort interruption cleanup: on ordinary failure (Die -> exit runs finally), Ctrl-C, or
    # any non-promoting exit, remove staging so it never lingers and never becomes a canonical $Src.
    if (-not $promoted -and (Test-Path $cloneStage)) {
      Remove-Item -Recurse -Force $cloneStage -ErrorAction SilentlyContinue
    }
  }
}
# Older Windows installer runs imported the deployed package without suppressing bytecode writes.
# The updater correctly refuses ignored importable content, so retire only that installer-created
# cache shape before this run imports the advanced source. The standalone helper refuses links,
# reparse points, nested directories and every non-.pyc entry before deleting anything.
$BytecodeCleanup = Join-Path $Src 'corpusfm\lifecycle\bytecode_cleanup.py'
if (-not (Test-Path -LiteralPath $BytecodeCleanup -PathType Leaf)) {
  Die "The deployed source carries no bounded bytecode cleanup helper."
}
$bytecodeResult = (& $Py -B $BytecodeCleanup $Src 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
  Die ("The deployed Python cache set could not be retired safely: " + $bytecodeResult)
}
Ok "Installer-created Python bytecode caches retired; future writes suppressed"
& $Git -C $Src remote set-url origin "https://github.com/$Repo.git"
# Public source access is anonymous. Remove every inherited/private-era credential mechanism so a
# public installation neither needs nor retains a repository secret.
$eapC = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& $Git config --system --unset-all credential.helper 2>$null
# PACKET 1398: HOME is the product root, so `--global` is ProgramData\CORPUSfm\.gitconfig. It is
# recorded only when present; `--unset-all` over an absent file writes nothing.
$laGitGlobal = Join-Path $ConfigHome '.gitconfig'
if ($script:CfmAttempt -and (Test-Path -LiteralPath $laGitGlobal -PathType Leaf)) {
  La-Do 'git_config_entry' 'unset' ([ordered]@{ values = @(& $Git config --global --get-all credential.helper 2>$null) }) @($laGitGlobal) {
    & $Git config --global --unset-all credential.helper 2>$null
  } | Out-Null
} else {
  & $Git config --global --unset-all credential.helper 2>$null
}
# PUBLIC PROJECTION: no credential store is configured, because the public tree carries no embedded
# credential to put in one. The deployed checkout's own helper and any ssh command are cleared too.
& $Git -C $Src config --unset-all credential.helper 2>$null
& $Git -C $Src config --unset core.sshCommand 2>$null
$ErrorActionPreference = $eapC
Remove-Item -LiteralPath (Join-Path $InstallDir '.git-pat'), (Join-Path $InstallDir '.git-credentials') `
  -Force -ErrorAction SilentlyContinue
Ok "Anonymous public update source wired; no repository credential is installed"
$ReleaseBuild = Join-Path $Src 'release-build.txt'
if (-not (Test-Path -LiteralPath $ReleaseBuild -PathType Leaf)) {
  Die "the published source has no release-build.txt identity"
}
$Rev = ([IO.File]::ReadAllText($ReleaseBuild)).Trim()
if ($Rev -notmatch '^[1-9][0-9]*$') { Die "the published release build identity is invalid" }
$Version = "0.$Rev"
$BuildCommit = ("" + (& $Git -C $Src rev-parse HEAD)).Trim()
$Short = (& $Git -C $Src rev-parse --short HEAD).Trim()
if ($InstallerSeries) {
  if ($PackageApplicationVersion -ne $Version -or $PackageCommit -ne $BuildCommit) {
    Die ("the verified installer bundle describes " + $PackageApplicationVersion + " @ " +
         $PackageCommit + ", but the deployed source is " + $Version + " @ " + $BuildCommit +
         "; refusing to publish a mixed installation.")
  }
  $InstallerSource = 'package'
} else {
  $InstallerSeries = 'series-1'
  $InstallerVersion = $Version
  $InstallerSource = 'development'
}
$InstallerBundleProtocol = 1

# -- Series 2 runtime assets -------------------------------------------------------
# TWO COPIES EXIST, DELIBERATELY, AND THEY ARE NOT THE SAME THING.
#
#   1. src\assets\ -- TRACKED application source. The assets are application content now, so they
#      are committed on application main, they travel inside the application Git bundle like the
#      rest of the source, and they land in the deployed checkout as ordinary tracked files.
#   2. <install root>\assets -- the OPERATIONAL copy placed below, unpacked from the package's
#      separate digest-covered corpusfm-assets.zip. This is what the service reads.
#
# THE OLD FAILURE WAS ABOUT UNTRACKED BYTES, NOT ABOUT LOCATION. Placing the operational copy under
# src\ put UNTRACKED content into a Git working tree, and tree_inspection refuses ANY untracked path
# so a privileged update never builds on something git cannot account for. Measured on fms-dev at
# 0.2438: every provider composed, then the eligibility gate refused with 33 untracked-content
# problems and the services were never started. Widening that allowlist was considered and rejected
# - the checkout is on the service's import path, so the fix is to keep UNACCOUNTED bytes out of it.
#
# Tracked src\assets\ does not reopen that: git accounts for it exactly as it accounts for
# src\corpusfm\, so the gate has nothing to object to. The operational copy stays a sibling of the
# checkout because it is placed by the installer rather than committed, which is the property that
# mattered all along.
if ($InstallerSeries) {
  # $PSScriptRoot, like every other package-relative file here (installer-manifest.json,
  # installer-runtime.zip). $ScriptDir was never defined anywhere in this script, so this line
  # bound $null and PowerShell refused: "Cannot bind argument to parameter 'Path' because it is
  # null." It never fired before because no Windows box had yet installed an asset payload.
  $assetsZip = Join-Path $PSScriptRoot 'corpusfm-assets.zip'
  if (-not (Test-Path -LiteralPath $assetsZip -PathType Leaf)) {
    throw 'the verified installer package carries no Series 2 asset payload.'
  }
  $assetsRoot = Join-Path $InstallDir $script:CfmAssetsDirName
  $assetsTmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $assetsTmp -Force | Out-Null
  try {
    Expand-Archive -LiteralPath $assetsZip -DestinationPath $assetsTmp -Force
    foreach ($leaf in @('db', 'addon')) {
      $from = Join-Path $assetsTmp $leaf
      if (-not (Test-Path -LiteralPath $from -PathType Container)) {
        throw "asset payload is missing its $leaf content."
      }
      $to = Join-Path $assetsRoot $leaf
      if (Test-Path -LiteralPath $to) { Remove-Item -LiteralPath $to -Recurse -Force }
      New-Item -ItemType Directory -Path $to -Force | Out-Null
      Copy-Item -Path (Join-Path $from '*') -Destination $to -Recurse -Force
    }
  } finally {
    Remove-Item -LiteralPath $assetsTmp -Recurse -Force -ErrorAction SilentlyContinue
  }
  foreach ($required in @(
      (Join-Path $assetsRoot 'db\CORPUSfm_DB.fmp12'),
      (Join-Path $assetsRoot 'addon\CORPUSfm_ADDON.fmaddon'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
      throw 'Series 2 runtime assets are not present after placement.'
    }
  }
  if (-not (Test-Path -LiteralPath (Join-Path $assetsRoot 'addon\CORPUSfm_ADDON') -PathType Container)) {
    throw 'Series 2 runtime assets are not present after placement.'
  }
  # The checkout must carry NO asset content. Asserted rather than trusted, because the whole 0.2438
  # failure was assets sitting where the eligibility gate would later find them.
  $srcRoot = Join-Path $InstallDir 'src'
  foreach ($forbidden in @((Join-Path $srcRoot 'db'), (Join-Path $srcRoot 'addon'))) {
    if (Test-Path -LiteralPath $forbidden) {
      throw 'asset content is present inside the deployed checkout; refusing to publish an installation a privileged update would reject.'
    }
  }
  # Administrator-owned, application-READABLE, application-NOT-writable. The install root's ACL
  # already grants SYSTEM/Administrators full control and denies the service write; assets inherit
  # it, and the readback after publication proves the service can read but not write.
  $script:CfmAssetsPayloadSha256 =
    (Get-FileHash -LiteralPath $assetsZip -Algorithm SHA256).Hash.ToLowerInvariant()
  Write-Host ("  + Series 2 runtime assets placed (" + $script:CfmAssetsDirName +
              "\db, " + $script:CfmAssetsDirName + "\addon; payload " +
              $script:CfmAssetsPayloadSha256.Substring(0, 12) + ")") -ForegroundColor Green
}
# Version stamp: the running service reads corpusfm\_build.txt for its version instead of shelling
# out to git at runtime - git here is the bundled MinGit, not on the service PATH (the 0.0 class of
# bug). git stays the dev fallback. (gitignored; an untracked runtime file.)
if ($Rev -match '^[0-9]+$') { Set-Content -Path (Join-Path $Src 'corpusfm\_build.txt') -Value $Rev -Encoding ascii }
Ok ("installing " + $GitTrackedBranch + " @ " + $Short + "   version " + $Version)

# THE BINDING BELONGS HERE, NOT BESIDE THE INTERPRETER (packet 1246-10-04). It was placed
# immediately after the Python step, mirroring the Linux phase order - but on Windows the
# interpreter is installed BEFORE the source is deployed, so the proof ran against a $Src that
# did not exist yet and the install died at S7 with `import corpusfm` raising. Measured on
# winfms2026, 2026-08-08. The block is unchanged; only its position is. It must follow a
# successful source deployment and precede every lifecycle CLI call, service rendering,
# registration and start - all of which need an interpreter that can import the application.
# -- The interpreter's binding to the deployed source, re-asserted on EVERY run (packet 1246-10-04)
# The `._pth` above is written only when the interpreter is downloaded, so an update over an
# existing interpreter never re-asserted it - and the canonical service definitions carry no
# PYTHONPATH by design (the embeddable interpreter ignores it under a `._pth` anyway). A binding
# that exists only on the run that installed Python is a binding an update can silently lose, and
# the service then cannot import the application at all: measured on Linux, where the same gap left
# both services failing ModuleNotFoundError with correct definitions.
#
# The required entries are PRESERVED - the stdlib zip, `.`, `Lib\site-packages` and `import site` -
# and `$Src` is added exactly once. No PYTHONPATH is introduced anywhere.
$pthFile = Get-ChildItem $PyDir -Filter 'python*._pth' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pthFile) { Die "The embeddable interpreter has no python*._pth at $PyDir; refusing to leave the source unbound." }
$pthLines = @(Get-Content $pthFile.FullName | ForEach-Object { $_.TrimEnd() })
if ($pthLines -notcontains $Src) {
  Info "Binding the embeddable interpreter to $Src ..."
  $insertAt = [Array]::IndexOf($pthLines, 'import site')
  if ($insertAt -lt 0) { $pthLines = @($pthLines + $Src + 'import site') }
  else { $pthLines = @($pthLines[0..($insertAt-1)] + $Src + $pthLines[$insertAt..($pthLines.Count-1)]) }
  Set-Content -Path $pthFile.FullName -Value $pthLines -Encoding ascii
}
$pthAfter = @(Get-Content $pthFile.FullName | ForEach-Object { $_.TrimEnd() })
if ($pthAfter -notcontains $Src) { Die ("The source binding did not take in " + $pthFile.FullName) }
if ($pthAfter -notcontains 'import site') { Die ("The embeddable interpreter's import-site entry was lost from " + $pthFile.FullName) }
if ($pthAfter -notcontains 'Lib\site-packages') { Die ("The embeddable interpreter's site-packages entry was lost from " + $pthFile.FullName) }
if (@($pthAfter | Where-Object { $_ -eq $Src }).Count -ne 1) { Die ("The source path is bound more than once in " + $pthFile.FullName) }

# PROVEN WITH PYTHONPATH ABSENT AND cwd OUTSIDE THE SOURCE TREE. The service definitions carry no
# PYTHONPATH, so a proof that inherited one would prove nothing about what actually starts.
$probe = Join-Path $Dl '_bind_probe.py'
# NOTHING ON STDERR (packet 1246-10-04). The probe used to write a `cwd=` diagnostic there, and
# PowerShell converts native stderr into a NativeCommandError - terminating under this script's
# ErrorActionPreference, even with `2>$null` on the call. The install died here on winfms2026,
# 2026-08-08, with the binding itself perfectly correct. A successful probe now emits stdout only.
@'
import corpusfm
print(corpusfm.__file__)
'@ | Set-Content -Path $probe -Encoding ascii
$savedPP = $env:PYTHONPATH
$env:PYTHONPATH = $null
try {
  $bound = (& $Py $probe 2>$null | Select-Object -First 1)
  if (-not $bound) { Die "The installed interpreter cannot import corpusfm without PYTHONPATH; the source binding did not take." }
  if (-not $bound.StartsWith((Join-Path $Src 'corpusfm'), [StringComparison]::OrdinalIgnoreCase)) {
    Die ("The installed interpreter imports corpusfm from " + $bound + ", which is not beneath " + $Src)
  }
  # RESOLUTION WITHOUT IMPORTING ANYTHING (packet 1246-10-04). The dependencies are installed AFTER
  # this point, and `find_spec` on a SUBMODULE imports its parent packages - so both
  # `import_module` and `find_spec` raise here on uvicorn, and the traceback becomes a terminating
  # NativeCommandError. What is provable before the dependency install is that the bound
  # interpreter locates the deployed package and that each service module's file is inside it. The
  # modules are imported for real at phase 20, by the read-back that renders their definitions.
  $spec = @'
import importlib.util, os, sys
spec = importlib.util.find_spec("corpusfm")
root = os.path.dirname(spec.origin) if spec and spec.origin else ""
missing = [] if root else ["corpusfm"]
for rel in (os.path.join("app", "web", "__init__.py"), os.path.join("server", "scheduler.py")):
    if root and not os.path.isfile(os.path.join(root, rel)):
        missing.append(rel)
print("MISSING " + ";".join(missing) if missing else "RESOLVED " + root)
'@
  $specFile = Join-Path $Dl '_bind_spec.py'
  $spec | Set-Content -Path $specFile -Encoding ascii
  $resolved = (& $Py $specFile 2>$null | Select-Object -Last 1)
  Remove-Item -Force $specFile -ErrorAction SilentlyContinue
  if ("$resolved".Trim() -notlike 'RESOLVED *') { Die ("A canonical service module does not resolve from the bound interpreter: " + $resolved) }
} finally {
  $env:PYTHONPATH = $savedPP
  Remove-Item -Force $probe -ErrorAction SilentlyContinue
}
Ok ("Source binding established and proven (" + $pthFile.FullName + " -> " + $Src + ")")


Info "Python environment"
# Box-validated dependency lock, keyed to the bundled interpreter AND platform
# (constraints-server-win-py<MAJ><MIN>.txt). It is a SEPARATE file from the Linux
# constraints-server-py3XX.txt locks ON PURPOSE: the graphs diverge by platform (Windows pins
# pywin32 / pywin32-ctypes; Linux pins uvloop / jeepney / SecretStorage), so reusing the Linux lock
# here would fail to resolve. Apply only the lock that MATCHES the bundled Python; with no match,
# resolve UNPINNED (the pre-lock behavior) rather than force a mismatched lock.
Cfm-Run "pip upgrade" $Py -m pip install --upgrade pip; NeedExit $LASTEXITCODE "pip upgrade"
$reqFile = Join-Path $RuntimeRoot 'installer\requirements-server.txt'
$pyTag = (& $Py -c "import sys;print('py%d%d'%sys.version_info[:2])").Trim()
$lockFile = Join-Path $RuntimeRoot ("installer\constraints-server-win-" + $pyTag + ".txt")
if (Test-Path $lockFile) {
  Info ("Installing requirements-server.txt with lock constraints-server-win-$pyTag.txt (several minutes; full pip output in the install transcript, -Verbose to watch) ...")
  Cfm-Run "pip install (locked)" $Py -m pip install -r $reqFile -c $lockFile; NeedExit $LASTEXITCODE "pip install (locked)"
} else {
  Info ("Installing requirements-server.txt unpinned (no Windows lock for $pyTag; several minutes; full pip output in the install transcript, -Verbose to watch) ...")
  Cfm-Run "pip install (unpinned)" $Py -m pip install -r $reqFile; NeedExit $LASTEXITCODE "pip install"
}
# Sanity: the heavy native dep (chromadb->onnxruntime) must import (needs the VC++ runtime present).
& $Py -c "import fastapi, uvicorn, chromadb" 2>$null
if ($LASTEXITCODE -ne 0) { Die "Dependencies installed but a core import failed (likely the Visual C++ runtime is missing - install the VC++ 2015-2022 x64 redistributable)." }
Ok "Dependencies installed + import-verified"

# -- Installed uninstaller ----------------------------------------------------------------------
# The public installer package exposes no standalone uninstaller. Its private source payload
# carries the launcher input, and installation turns that input into this installation's one
# canonical local entry point. The lifecycle runtime is the installed Python/source tree above;
# uninstallation does not acquire code, a PAT or a package.
$UninstallerPath = Join-Path $InstallDir 'uninstall.ps1'
$UninstallerLib = Join-Path $InstallDir '_cfm_lib.ps1'
$UninstallerSource = Join-Path $RuntimeRoot 'installer\windows\uninstall.ps1'
$UninstallerLibSource = Join-Path $RuntimeRoot 'installer\windows\_cfm_lib.ps1'
Copy-Item -LiteralPath $UninstallerSource -Destination $UninstallerPath -Force
Copy-Item -LiteralPath $UninstallerLibSource -Destination $UninstallerLib -Force
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $UninstallerSource).Hash -ne
    (Get-FileHash -Algorithm SHA256 -LiteralPath $UninstallerPath).Hash) {
  Die ("the installed uninstaller did not read back as the payload launcher: " + $UninstallerPath)
}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $UninstallerLibSource).Hash -ne
    (Get-FileHash -Algorithm SHA256 -LiteralPath $UninstallerLib).Hash) {
  Die ("the installed uninstaller support library did not read back as the payload library: " + $UninstallerLib)
}
Ok ("Installed uninstaller provisioned and read back (" + $UninstallerPath + ")")

# -- Installed installer bootstrap ---------------------------------------------------------------
# The downloaded package is caller-owned and may be removed after this run. Preserve the stable
# Series 2 acquisition/verification launcher inside the installation. Public acquisition is
# anonymous; the verified source is installed byte-for-byte and remains administrator-only because
# it is a privileged operational entry point, not because it contains a secret.
$InstallerEntryPoint = Join-Path $BinDir 'corpusfm-installer.ps1'
$InstallerBootstrapSource = Join-Path $RuntimeRoot 'installer\bootstrap\windows\bootstrap.ps1'
$InstallerBootstrapStage = Join-Path $BinDir ('.corpusfm-installer.' + $PID + '.ps1')
if (-not (Test-Path -LiteralPath $InstallerBootstrapSource -PathType Leaf)) {
  Die "the verified installer runtime carries no Windows bootstrap source."
}

function Assert-InstallerBootstrapAclOnly($Path) {
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) {
    Die "the durable installer bootstrap still inherits access from its parent directory."
  }
  $allowed = @('S-1-5-18','S-1-5-32-544')
  $seen = @{}
  foreach ($rule in $acl.Access) {
    try {
      $sidValue = $rule.IdentityReference.Translate(
        [Security.Principal.SecurityIdentifier]).Value
    } catch {
      Die ("the durable installer bootstrap has an unreadable ACL identity: " +
           $rule.IdentityReference.Value)
    }
    if ($sidValue -notin $allowed -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
      Die ("the durable installer bootstrap grants an unexpected identity: " + $sidValue)
    }
    $seen[$sidValue] = $true
  }
  foreach ($requiredSid in $allowed) {
    if (-not $seen.ContainsKey($requiredSid)) {
      Die ("the durable installer bootstrap omits required ACL identity " + $requiredSid)
    }
  }
}

# Stage, protect, prove, then publish by rename - the same discipline as before. What changed is
# WHAT is written: an exact copy of the verified runtime source rather than a rendered variant. The
# staged file still receives and proves its protected ACL before publication, so no interval leaves
# the installed entry point readable under inherited BinDir access.
Copy-Item -LiteralPath $InstallerBootstrapSource -Destination $InstallerBootstrapStage -Force
Lock-FileAcl $InstallerBootstrapStage
Assert-InstallerBootstrapAclOnly $InstallerBootstrapStage
Move-Item -LiteralPath $InstallerBootstrapStage -Destination $InstallerEntryPoint -Force
Lock-FileAcl $InstallerEntryPoint

function Assert-InstallerBootstrapAcl {
  if (-not (Test-Path -LiteralPath $InstallerEntryPoint -PathType Leaf)) {
    Die ("the durable installer bootstrap is missing: " + $InstallerEntryPoint)
  }
  # BYTE EQUALITY with the verified package source, proved by one SHA-256 comparison of the two files:
  # nothing was substituted into the installed entry point.
  $sourceHash = (Get-FileHash -LiteralPath $InstallerBootstrapSource -Algorithm SHA256).Hash
  $installedHash = (Get-FileHash -LiteralPath $InstallerEntryPoint -Algorithm SHA256).Hash
  if ($sourceHash -ne $installedHash) {
    Die ("the installed durable bootstrap is not byte-identical to its verified package source " +
         "(source " + $sourceHash + ", installed " + $installedHash + ").")
  }
  Assert-InstallerBootstrapAclOnly $InstallerEntryPoint
}
Assert-InstallerBootstrapAcl
Ok ("Durable installer provisioned and protected (" + $InstallerEntryPoint + ")")

# -- CORPUSfm database folders (FRESH AND UPDATE) ------------------------------------------------
# The hosting folder (packet 1061) + the support folder (packet 1066, the other half of the apply
# COMPARTMENT). Both are provisioned on every run so an already-bootstrapped update provisions and
# records them too. Both are SYSTEM/Administrator-writable; recorded in install.yaml so
# generate_db_file hosts in place and the compartment gate can locate targets. Idempotent. NOT
# deleted on uninstall when non-empty (user work product / hosted files).
Info "CORPUSfm database folders"
try {
  La-Do 'dir' 'ensure' $null @($PatchHostingDir) { New-Item -ItemType Directory -Force -Path $PatchHostingDir | Out-Null }
  # NOT recorded in install.yaml, and the call that tried to is GONE. `corpusfm set-hosting-dir` was
  # retired with the `hosting_dir` marker key by packet 1246-05-02 - the compartment has to be PROVEN,
  # not claimed. The subcommand no longer exists; the path is published by `composition foundation` as
  # paths.patch_hosting_dir and proven at phase 16.
  Ok ("Hosting folder provisioned (" + $PatchHostingDir + ") - recorded in the installation manifest as patch_hosting_dir")
} catch {
  Warn ("Could not provision the hosting folder at " + $PatchHostingDir + " - generated files fall back to the _generated/ quarantine + promote.")
}
try {
  La-Do 'dir' 'ensure' $null @($SupportDir) { New-Item -ItemType Directory -Force -Path $SupportDir | Out-Null }
  # Same retirement (packet 1246-05-02): the `support_dir` marker key and its setter are both gone.
  Ok ("Support folder provisioned (" + $SupportDir + ") - the apply compartment is proven at phase 16, not recorded here")
} catch {
  Warn ("Could not provision the support folder - the apply compartment will have only the hosting folder.")
}


# === PHASE 11 - Foundation publication - generation 1 ===========================================
# The FIRST write of this installation. Publishes the manifest at generation 1 - the seven
# PathsBlock fields and the fixed web facts - reads it back, then publishes the locator. The
# installer supplies only the three paths it classified; the five OS locations come from the
# platform layout and the web facts are implementation constants, so neither appears in this request.
# FRESH vs UPDATE IS DECIDED BY THE PUBLISHED RECORD (packet 1246-04-04, correction D). `$IsUpgrade`
# classifies the CODE installation - it is what decides that an upgrade never touches FileMaker - and
# it answers from this installer's own marker. A marker is not a published installation: a box whose
# record was never published, or was removed, still has one. So the foundation runs for a genuinely
# UNPUBLISHED installation and for nothing else, and an update reads the generation the manifest
# actually holds.
#
# The old update branch set `$CfmGeneration = 1` unconditionally. On a box at generation 5 every
# provider then committed against `inspected_generation=1` and the manifest's own compare-and-swap
# refused - an update that could not complete on any installation that had ever been updated.
Lc-LoadOsLayout
$eapS = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$st = (& $Py -m corpusfm.lifecycle status --json 2>&1 | Out-String)
$ErrorActionPreference = $eapS
$lcLocator  = "" + (Lc-Field $st 'locator')
$lcManifest = "" + (Lc-Field $st 'manifest')
if ($lcLocator -ne 'present') {
  if ($lcLocator -and $lcLocator -ne 'missing') {
    Die ("the installation locator reads '" + $lcLocator + "'; refusing to publish a foundation over it.")
  }
  # A recorded attempt minted its installation identity with the record and reuses it (packet 1398).
  if ($script:CfmAttempt) {
    if (Test-Path -LiteralPath (Join-Path $InstallDir 'manifest\installation.json')) {
      Die "an unpublished manifest already stands in the install directory; this attempt cannot record a foundation over it."
    }
  } else {
    $InstallationId = [guid]::NewGuid().ToString()
  }
  $req = Lc-Request 'foundation' (Lc-Json ([ordered]@{
    schema_version    = 1
    installation_id   = $InstallationId
    install_dir       = $InstallDir
    patch_hosting_dir = $PatchHostingDir
    fms_root          = $FmsBin
    support_dir       = $SupportDir
    uninstaller_path  = $UninstallerPath
    version                    = $Version
    commit                     = $BuildCommit
    installer_series           = $InstallerSeries
    installer_version          = $InstallerVersion
    installer_bundle_protocol  = $InstallerBundleProtocol
    installer_source           = $InstallerSource
    installer_entry_point      = $InstallerEntryPoint
    actor             = 'installer'
  }))
  $out = La-LcRun 'foundation' ([ordered]@{ locator = $false; manifest = $false }) "foundation publication" @('composition','foundation','--request',$req)
  $CfmGeneration = Lc-Field $out 'generation'
  if ("$CfmGeneration" -ne "1") { Die "foundation published generation '$CfmGeneration', expected 1." }
  if (("" + (Lc-Field $out 'uninstaller_path')) -ne $UninstallerPath) {
    Die "foundation did not read back the canonical installed uninstaller."
  }
  if (("" + (Lc-Field $out 'installer_entry_point')) -ne $InstallerEntryPoint) {
    Die "foundation did not read back the canonical installed installer."
  }
  Ok ("Installation record published at generation 1 (" + $InstallationId + ")")
} else {
  # UPDATE. The record must agree with THIS invocation before a single provider runs: an installation
  # record naming another directory is not this installation, and composing into it would move
  # another installation's manifest.
  if ($lcManifest -ne 'valid') {
    Die ("this installation's manifest reads '" + $lcManifest + "'; refusing to update over it.")
  }
  $InstallationId = "" + (Lc-Field $st 'installation_id')
  $recordedDir    = "" + (Lc-Field $st 'install_dir')
  $genRaw = "" + (Lc-Field $st 'generation')
  if (-not $InstallationId) { Die "this installation publishes no identity; refusing to update it." }
  if ($genRaw -notmatch '^\d+$') {
    Die ("the published manifest reports generation '" + $genRaw + "'; refusing to update it.")
  }
  $CfmGeneration = [int]$genRaw
  if ($recordedDir -ne $InstallDir) {
    Die ("the published installation is at '" + $recordedDir + "', this invocation installs to '" +
         $InstallDir + "'. Refusing to compose into another installation's record.")
  }
  if ($CfmGeneration -lt 1) {
    Die ("the published manifest reports generation '" + $CfmGeneration + "'; refusing to update it.")
  }
  $req = Lc-Request 'publish-installer' (Lc-Json ([ordered]@{
    schema_version             = 1
    installation_id            = $InstallationId
    expected_generation        = [int]$CfmGeneration
    install_dir                = $InstallDir
    version                    = $Version
    commit                     = $BuildCommit
    installer_series           = $InstallerSeries
    installer_version          = $InstallerVersion
    installer_bundle_protocol  = $InstallerBundleProtocol
    installer_source           = $InstallerSource
    installer_entry_point      = $InstallerEntryPoint
    actor                       = 'installer'
  }))
  $out = Lc-Run "installer identity publication" @('composition','publish-installer','--request',$req)
  $genRaw = "" + (Lc-Field $out 'generation')
  if ($genRaw -notmatch '^\d+$' -or [int]$genRaw -lt 1) {
    Die ("installer identity publication returned invalid generation '" + $genRaw + "'.")
  }
  $CfmGeneration = [int]$genRaw
  if (("" + (Lc-Field $out 'installer_entry_point')) -ne $InstallerEntryPoint) {
    Die "installer identity publication did not read back the canonical installed installer."
  }
  Ok ("Existing installation record verified and installer identity published (" +
      $InstallationId + " at generation " + $CfmGeneration + ")")
}


# === PHASE 12 - Machine and Corpus keys - through published authority ===========================
# TWO keys, never crossed (split packet 1007; named packet 1246-02):
#   corpus.key  - the Corpus Key. Encrypts everything the CORPUS owns. It is PORTABLE: a Recovery
#                 File carries it, and only it, to another machine.
#   machine.key - the Machine Key. Encrypts what belongs to THIS installation (the FMS PKI private
#                 key). Never exported, never carried by a Recovery File, never replaced by an
#                 adoption - which is what keeps a box's own PKI working after its corpus moves.
# THE PRIVILEGED INSTALLER PROVISIONS THESE, and the two guards this replaced could not. They tested
# $LegacyHome - the RETIRED home - so on a published 1246-03 installation they read a directory the
# resolver no longer uses, and a failure to create either key downgraded to a warning that promised a
# "first use" the runtime never performs. Its Linux twin was measured on fms-server (2026-08-08):
# machine.key was never created and phase 15 refused with prerequisite_required. Same defect, same
# fix - one privileged operation, FATAL, through published authority, with the rules
# (Corpus Key irreplaceable and never generated beside an existing corpus; Machine Key replaceable;
# neither retired filename consulted) in corpusfm.lifecycle.key_provisioning rather than in a script.
# PRE-SERVICE PROTECTION, EXPLICITLY (packet 1246-10-04). This request used to name
# `NT SERVICE\<web>` and `NT SERVICE\<scheduler>`. A virtual service account has NO SID until its
# service is registered, and registration is phase 20 - so `LookupAccountName` refused with error
# 1332 ("No mapping between account names and security IDs was done") and key provisioning failed
# on every Windows box, with the keys already written and unprotected. Measured on winfms2026,
# 2026-08-08. The keys are protected HERE to SYSTEM + Administrators, inheritance disabled, read
# back before this reports success; the final service ACL pass at phase 20 - after both services
# are registered and before either starts - resolves the two accounts and applies the runtime
# grants. No placeholder service, no early SID.
Info "Encryption keys"
$req = Lc-Request 'provision-keys' (Lc-Json ([ordered]@{
  schema_version       = 1
  actor                = 'installer'
  flavour              = 'windows'
  database_name        = 'CORPUSfm_DB'
  database_search_dirs = @($FmDbDir, $PatchHostingDir)
  pre_service          = $true
}))
$laPrior = $null
if ($script:CfmAttempt) { $laPrior = La-KeysPrior }
La-LcRun 'provision_keys' $laPrior "key provisioning" @('provision-keys','--request',$req) | Out-Null
Ok ("Corpus and Machine keys established at " + $FixedSecrets + " and proven through the published resolvers")

Info "Install marker"
# `write_web_deployment` IS RETIRED HERE (packet 1246-10-04), as it was on Linux: it copied the
# prefix and port into the transitional home, making a SECOND publisher of route facts the
# published installation record already owns - the class of defect that cost the Linux tail several
# rounds. `write_install_marker` STAYS: it still participates in installer compatibility and
# classification. Two different writes, not one habit.
& $Py -c "from corpusfm.install import write_install_marker; write_install_marker('server','$Version')"
NeedExit $LASTEXITCODE "write install marker"
Ok ("install.yaml -> " + (Join-Path $LegacyHome 'install.yaml'))

# -- Asset root readback (packet 1257) ---------------------------------------------
# Read the asset root back through the APPLICATION's own resolver rather than restating the path
# this script used: the installer places bytes, the application derives their location from the
# published install root, and a readback that recomputed the path locally would agree with itself
# and prove nothing. It runs here because it needs the published record.
if ($InstallerSeries) {
  $seenAssets = (& $Py -c "from corpusfm.lifecycle import app_paths; print(app_paths.assets_dir())" 2>$null)
  NeedExit $LASTEXITCODE "resolve the application asset root"
  $seenAssets = ($seenAssets | Select-Object -Last 1)
  $expectedAssets = Join-Path $InstallDir $script:CfmAssetsDirName
  if ($seenAssets -ne $expectedAssets) {
    Die ("the application resolves its asset root to '" + $seenAssets + "', not " + $expectedAssets)
  }
  foreach ($required in @(
      (Join-Path $seenAssets 'db\CORPUSfm_DB.fmp12'),
      (Join-Path $seenAssets 'addon\CORPUSfm_ADDON.fmaddon'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
      Die ("the placed asset is missing at " + $required)
    }
  }
  Ok ("Asset root read back by the application at " + $seenAssets +
      " (payload sha256 " + $script:CfmAssetsPayloadSha256 + ")")
}


# === PHASE 13 - Render and install the privileged updater =======================================
# The in-app Updates button no longer pulls into the checkout the service is running from. It writes
# a request and triggers ONE fixed scheduled task; everything else is decided by SYSTEM. The
# service's whole grant is "may run and read that task" - no path, no ref, no command, no
# environment. The task runs as SYSTEM.
Info "Privileged one-shot updater"
$UpdaterSrc  = Join-Path $RuntimeRoot 'installer\windows\corpusfm-update.ps1'
$UpdaterDst  = Join-Path $BinDir 'corpusfm-update.ps1'
$UpdaterTask = 'CORPUSfm Update'
# THE ADMINISTRATOR-OWNED LIBRARY AND ENTRY POINTS, INSTALLED BEFORE THE UPDATER IS RENDERED.
# The updater loads its tree inspector and its outcome publisher from OUTSIDE the checkout - loading
# the judge from the tree being judged is how a modified helper inside a modified checkout declares
# itself clean (packet 1246-03, R7b/N2). `outcome_publisher` resolves its library as
# <its own dir>\..\lib, so bin/ and lib/ are siblings under InstallDir and neither may be $Src.
# Nothing rendered these before, so every placeholder below had no value and the render check
# refused the install; installing them is what makes the rendering complete.
$LibPkg = Join-Path $LibDir 'corpusfm'
if (Test-Path $LibPkg) { Remove-Item -Recurse -Force $LibPkg -ErrorAction SilentlyContinue }
Copy-Item -Recurse -Force (Join-Path $Src 'corpusfm') $LibPkg
if (-not (Test-Path (Join-Path $LibPkg 'lifecycle'))) { Die "the administrator-owned library at $LibDir does not hold corpusfm\lifecycle - refusing to install an updater that would load its own judge from the checkout." }
$Helper    = Join-Path $BinDir 'tree_inspection.py'
$Publisher = Join-Path $BinDir 'publish_outcome.py'
$Cleaner   = Join-Path $BinDir 'bytecode_cleanup.py'
Copy-Item -Force (Join-Path $Src 'corpusfm\lifecycle\tree_inspection.py') $Helper
Copy-Item -Force (Join-Path $Src 'corpusfm\lifecycle\outcome_publisher.py') $Publisher
Copy-Item -Force (Join-Path $Src 'corpusfm\lifecycle\bytecode_cleanup.py') $Cleaner
foreach ($entry in @($Helper, $Publisher, $Cleaner)) {
  if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
    Die ("the privileged updater entry point was not installed at " + $entry)
  }
}
# Administrator-owned, SYSTEM-readable, and NOT writable by a service identity. The service grants
# are added at phase 20, once the identities exist.
foreach ($p in @($LibDir, $BinDir)) {
  & icacls $p /inheritance:r /grant:r ($SystemSid + ':(OI)(CI)(RX)') ($AdminsSid + ':(OI)(CI)(F)') 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Die ("Could not protect " + $p) }
}
Ok ("Administrator-owned library + entry points installed (" + $LibDir + ", " + $BinDir + ")")

# THE PROXY EXECUTOR (ruling 2026-08-08). Deliberately here, ABOVE the updater branch: a missing
# updater may disable updates, and it may never suppress this. `cfm-proxy-exec` appeared nowhere in
# either installer and never had - measured on the Linux twin 2026-08-08, where a fresh install
# reached generation 3 and phase 17 refused with "cfm-proxy-exec.sh does not exist".
# `proxy_transaction.executor_script` resolves <InstallDir>\bin\cfm-proxy-exec.ps1 and NOTHING else -
# no source tree, no PATH, no cwd - because this file is handed root authority over FileMaker
# Server's own web configuration. The installer's job is to put the shipped bytes exactly there,
# prove they are the shipped bytes, and refuse otherwise.
Info "Proxy executor"
$ProxyExecSrc = Join-Path $RuntimeRoot 'installer\windows\cfm-proxy-exec.ps1'
$ProxyExecDst = Join-Path $BinDir 'cfm-proxy-exec.ps1'
if (-not (Test-Path $ProxyExecSrc)) {
  Die ("the proxy executor is not in this payload at " + $ProxyExecSrc + " - the proxy provider would refuse at phase 17 and no install can complete without it")
}
# STAGED BESIDE THE DESTINATION, then moved: no reader ever sees a half-copied file at the path a
# root-authority resolver reads.
$ProxyExecTmp = $ProxyExecDst + '.tmp'
try {
  Copy-Item -Force $ProxyExecSrc $ProxyExecTmp
  Move-Item -Force $ProxyExecTmp $ProxyExecDst
} catch {
  Remove-Item -Force $ProxyExecTmp -ErrorAction SilentlyContinue
  Die ("could not install the proxy executor at " + $ProxyExecDst + ": " + $_.Exception.Message)
}
# PROTECTED, SYSTEM and Administrators only. No service identity is named at all - not even read -
# and phase 20 adds none, because nothing but an elevated caller ever runs this.
& icacls $ProxyExecDst /reset 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die ("Could not reset the ACL on " + $ProxyExecDst) }
& icacls $ProxyExecDst /inheritance:r /grant:r ($SystemSid + ':(RX)') ($AdminsSid + ':(F)') 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die ("Could not protect the proxy executor " + $ProxyExecDst) }
# READ BACK THE STATE, never the command's exit status.
if (-not (Test-Path $ProxyExecDst -PathType Leaf)) { Die ($ProxyExecDst + " is not a file") }
$peAcl = Get-Acl $ProxyExecDst
if (-not $peAcl.AreAccessRulesProtected) { Die ($ProxyExecDst + " does not carry a protected DACL") }
foreach ($rule in $peAcl.Access) {
  $who = $rule.IdentityReference.Value
  if ($who -notmatch 'SYSTEM' -and $who -notmatch 'Administrators') {
    Die ("the proxy executor grants " + $who + "; only SYSTEM and Administrators may appear on it")
  }
}
$peSrcHash = (Get-FileHash -Algorithm SHA256 $ProxyExecSrc).Hash
$peDstHash = (Get-FileHash -Algorithm SHA256 $ProxyExecDst).Hash
if ($peSrcHash -ne $peDstHash) {
  Die ("the installed proxy executor does not match the shipped source (" + $peSrcHash + " vs " + $peDstHash + ")")
}
Ok ("Proxy executor installed (" + $ProxyExecDst + "; SYSTEM/Administrators only, digest verified against the payload)")

# A missing updater source disables the in-app update path and does NOT fail the install - the same
# disposition install.sh takes for the same case. The rest of the installation is unaffected, and an
# administrator can always update by re-running this script.
$UpdaterInstalled = $false
if (-not (Test-Path $UpdaterSrc)) {
  Warn ("corpusfm-update.ps1 not found at " + $UpdaterSrc + " - in-app updates disabled")
} else {
  # NOT RENDERED AT ALL ANY MORE (packet 1380-02 D-A). There is no Windows renderer to call.
  #
  # The history is worth keeping because it explains the shape. This was once nine hand-written
  # `.Replace()` calls over values this script derived for itself - a second opinion about paths the
  # installation record already stated, and the two duly diverged. That was corrected by rendering
  # through the shipped renderer instead. D-A removes the remaining problem with rendering: a
  # per-installation artifact cannot be signed, because the bytes on the box are not the bytes that
  # were signed.
  #
  # So the updater is now STATIC and installed byte-for-byte, and it derives the installation root
  # itself from the fixed machine locator phase 11 published, corroborated by the manifest. The quoting
  # hazard rendering carried - a path containing an apostrophe closing a single-quoted literal early,
  # which on a crafted directory name is code injection into a script that runs as SYSTEM - is gone
  # with it: no path is ever spliced into PowerShell source.
  #
  # The bundled interpreter's `._pth` carries $Src on sys.path (PYTHONPATH is ignored under a ._pth),
  # while $UpdaterSrc is authenticated as part of the package runtime.

  # STAGED, VALIDATED AND PROTECTED BEFORE IT IS PUBLISHED (packet 1000-10, R10).
  #
  # The render used to write STRAIGHT TO $UpdaterDst, which spends an existing good updater before
  # anything has judged the new bytes. Three failures, all landing on the exact path the elevated
  # task executes as SYSTEM: a renderer that dies part-way leaves a truncated script where a working
  # one was; the placeholder guard's own remedy was to REMOVE $UpdaterDst, i.e. delete the previous
  # installation's updater to punish a template this run could not render; and between the render
  # and the icacls below the file sat at that path with whatever DACL $BinDir handed it. A re-run
  # that failed for any of those reasons left the box worse than it started.
  #
  # UNIQUE, and in the SAME DIRECTORY. Unique so residue from an earlier interrupted run can never
  # be adopted as this run's output; same-directory so publication is a rename on one volume, which
  # carries the protected DACL established below with the file and never exposes a half-written or
  # unprotected script at the path SYSTEM runs. Until that rename, $UpdaterDst is untouched: every
  # refusal below removes only what this run created.
  # -- THE UPDATER IS COPIED, NOT RENDERED -------------------------------------------------------
  #
  # It is static and signed, so the installed bytes must be the bytes that were signed. Rendering
  # is what made every installed copy unique and therefore unsignable; a copy is what makes the
  # signature mean anything on the box.
  $UpdaterStage = $UpdaterDst + '.' + ([guid]::NewGuid().ToString('N')) + '.new'
  Copy-Item -LiteralPath $UpdaterSrc -Destination $UpdaterStage -Force
  if (-not (Test-Path $UpdaterStage -PathType Leaf)) {
    Die "the one-shot updater could not be staged from the verified package runtime"
  }
  # A PLACEHOLDER-SHAPED token must not survive anywhere in a static artifact. The pattern is the
  # rendered SEAM shape, not a bare '@@': prose may legitimately discuss the mechanism, and a guard
  # a comment can trip is a guard that gets weakened rather than obeyed.
  if ((Get-Content $UpdaterStage -Raw) -match '@@\w+@@') {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die "the shipped updater still carries a rendered placeholder - refusing to install it"
  }
  # BYTE-IDENTICAL to its verified source, proved rather than assumed.
  $usSourceHash = (Get-FileHash -LiteralPath $UpdaterSrc -Algorithm SHA256).Hash
  $usStageHash = (Get-FileHash -LiteralPath $UpdaterStage -Algorithm SHA256).Hash
  if ($usSourceHash -ne $usStageHash) {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die ("the staged updater is not byte-identical to its verified package source (source " +
         $usSourceHash + ", staged " + $usStageHash + ")")
  }
  # The script IS the action, so write access to it would be write access to what the elevated task
  # executes. Established on the STAGED file and READ BACK there - an ACL that cannot be applied now
  # refuses while the previously installed updater is still the one the task runs. The web identity's
  # read+execute is granted at phase 20 with the other identity grants.
  & icacls $UpdaterStage /reset 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die ("Could not reset the ACL on the staged updater " + $UpdaterStage)
  }
  & icacls $UpdaterStage /inheritance:r /grant:r ($SystemSid + ':(RX)') ($AdminsSid + ':(F)') 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die ("Could not protect the updater script " + $UpdaterDst)
  }
  # READ BACK THE STATE, never the command's exit status - the rule the proxy executor above follows.
  # Caught, because $ErrorActionPreference is Stop: an uncaught throw here would abort the install
  # with the staging file still in bin\, and this block's whole claim is that a failure removes what
  # this run created and nothing else.
  try {
    $upAcl = Get-Acl $UpdaterStage
  } catch {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die ("could not read back the staged updater's DACL: " + $_.Exception.Message)
  }
  if (-not $upAcl.AreAccessRulesProtected) {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die ("the staged updater does not carry a protected DACL; " + $UpdaterDst + " is unchanged")
  }
  $upSystemOk = $false
  $upAdminsOk = $false
  # icacls requires a leading `*` to say "this trustee is a SID".  Translation returns the SID
  # itself, without that command-line sigil; compare like with like rather than treating both
  # correctly-applied trustees as foreign.
  $systemSidText = $SystemSid.TrimStart('*')
  $adminsSidText = $AdminsSid.TrimStart('*')
  foreach ($rule in $upAcl.Access) {
    try {
      $whoSid = $rule.IdentityReference.Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    } catch {
      Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
      Die ("the staged updater names an unreadable trustee; " + $UpdaterDst + " is unchanged")
    }
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
      Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
      Die ("the staged updater carries a non-allow rule; " + $UpdaterDst + " is unchanged")
    }
    $rights = [int]$rule.FileSystemRights
    if ($whoSid -eq $systemSidText) {
      $required = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute
      $upSystemOk = (($rights -band $required) -eq $required)
    } elseif ($whoSid -eq $adminsSidText) {
      $required = [int][System.Security.AccessControl.FileSystemRights]::FullControl
      $upAdminsOk = (($rights -band $required) -eq $required)
    } else {
      Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
      Die ("the staged updater grants an unexpected trustee; only SYSTEM and Administrators may appear on it")
    }
  }
  if (-not $upSystemOk -or -not $upAdminsOk) {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die ("the staged updater does not grant the required SYSTEM and Administrators rights; " +
         $UpdaterDst + " is unchanged")
  }
  # PUBLISH. One rename in one directory: the path holds either the previous updater or this one,
  # never a partial file and never nothing.
  try {
    Move-Item -Force $UpdaterStage $UpdaterDst
  } catch {
    Remove-Item -Force $UpdaterStage -ErrorAction SilentlyContinue
    Die ("could not publish the one-shot updater at " + $UpdaterDst + ": " + $_.Exception.Message)
  }
  if (-not (Test-Path $UpdaterDst -PathType Leaf)) {
    Die ($UpdaterDst + " is not a file after the updater was published")
  }

  # A FIXED action with FIXED arguments. The script itself takes no parameters (see its param()).
  #
  # NO -ExecutionPolicy Bypass (packet 1380-02 D20). CORPUSfm does not override execution policy,
  # including for its own elevated task. Under RemoteSigned the updater is a local file in bin\ with
  # no Mark of the Web, which the policy already permits. Under a machine-wide AllSigned policy the
  # check before phase 8's first mutation has already required this release's signing leaf in
  # LocalMachine\TrustedPublisher, which is the authority that admits it - a policy override would not
  # have supplied one.
  $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
      -Argument ('-NonInteractive -NoProfile -File "' + $UpdaterDst + '"')
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
      -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
  try {
    # REGISTERING A TASK DOES NOT RUN IT. It has no trigger; the only thing that starts it is the
    # web service asking, and the web service does not exist yet and does not start before phase 21.
    La-Do 'task' 'create' $null @('\CORPUSfm Update') {
      Register-ScheduledTask -TaskName $UpdaterTask -Action $taskAction -Principal $principal `
          -Settings $settings -Description 'CORPUSfm one-shot code update' -Force | Out-Null
    }
  } catch {
    try { Unregister-ScheduledTask -TaskName $UpdaterTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Die ("Could not register the one-shot updater task: " + $_.Exception.Message)
  }
  # SYSTEM and Administrators only, for now. The web identity's run+read is added at phase 20, because
  # `NT SERVICE\<id>` has no SID until the service is registered and phase 20 is where that happens.
  # There is no exposure window: the grant lands before phase 21 starts anything, and until then no
  # service identity exists to hold it.
  try {
    $ts = New-Object -ComObject 'Schedule.Service'; $ts.Connect()
    $ts.GetFolder('\').GetTask($UpdaterTask).SetSecurityDescriptor('D:P(A;;GA;;;BA)(A;;GA;;;SY)', 0)
    Ok ("One-shot updater task registered (" + $UpdaterTask + "; SYSTEM and Administrators only until phase 20)")
  } catch {
    # A runnable task with default permissions is worse than no task. Remove the staged task and abort
    # rather than leave that installed.
    Warn ("Could not tighten the update task's security descriptor - removing it: " + $_.Exception.Message)
    try { Unregister-ScheduledTask -TaskName $UpdaterTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Die "The privileged update task could not be secured; it has been removed and the install is aborting."
  }
  $UpdaterInstalled = $true
}


# === PHASE 14 - Provider prerequisites and observation ==========================================
# Read-only observation. Only now is it known which providers need FileMaker authority this run;
# nothing here mutates and nothing here holds a credential.
#
# EVERY ONE OF THESE TAKES `--request` (packet 1246-04-04, correction B). They were invoked with no
# request at all, and `--request` is required on all four - so argparse refused before any
# observation happened, and nothing read the refusal. The requests are built with EXACTLY their
# verb's key set; a key this build does not accept is a refusal, not a warning.
#
# THE MODE. `fresh_install` when this invocation published the foundation, `forward_update`
# otherwise - the same classification phase 11 made, from the same published record, not a second
# opinion. -RepairStorageAccess overrides it for storage alone (see phase 18).
if ("$CfmGeneration" -eq "1") { $CfmMode = 'fresh_install' } else { $CfmMode = 'forward_update' }
$CfmStorageMode = $CfmMode
if ($RepairStorageAccess) { $CfmStorageMode = 'repair_storage_access' }

$eapO = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
# NO patch-compartment inspection here (ruling, 2026-08-08). It authenticates to the FMS Admin API
# with THIS installation's PKI identity, which phase 15 creates - so on a fresh box it can only
# report `api_required_unavailable`, and recording that as an observed prerequisite states a
# conclusion about an identity that does not exist yet. Phase 16 inspects, after phase 15 publishes.
foreach ($obs in @(
    @('proxy','status','proxy-status',                      (Lc-ProxyRequest 'status')),
    @('admin-identity','observe','admin_identity-observe',  (Lc-AdminIdentityRequest 'absent')),
    @('storage','observe','storage-observe',                (Lc-StorageRequest $CfmStorageMode)))) {
  $obsReq = Lc-Request $obs[2] (Lc-Json $obs[3])
  # THE STORAGE OBSERVATION HERE IS A PREREQUISITE RECORD, NOT THE ROUTING AUTHORITY. Phase 18 takes
  # its own (packet 1246-10-04): this one runs BEFORE phase 15 publishes the Admin-API machine
  # identity, so `list_databases()` cannot answer and the database-known and hosted axes are UNKNOWN
  # by construction - which classifies every box, fresh or not, as `indeterminate`.
  Cfm-Logline ((& $Py -m corpusfm.lifecycle $obs[0] $obs[1] '--request' $obsReq 2>&1 | Out-String))
}
$ErrorActionPreference = $eapO
Ok "Provider prerequisites observed"


# === PROVIDER ORDER - RULED 2026-08-08, and the order IS the dependency =========================
#
# admin_identity(2) -> patch_compartment(3) -> proxy(4) -> storage(5). Identical to Linux, and it
# has to be: the patch compartment authenticates to the FMS Admin API with THIS installation's PKI
# identity, so the provider that creates that identity must run first. Measured on fms-server
# 2026-08-08 under the old order - patch refused `api_required_unavailable` on a fresh box.
#
# The canonical Admin API identity is UNCONDITIONAL maintained infrastructure on a supported
# co-located installation. On update the same provider takes the already-published no-change path:
# no rotation, no second identity, no generation consumed.
#
# Generations follow POSITION, not the label - the commit helper advances the counter.

# === PHASE 15 - ADMIN IDENTITY - Protocol F - generation 2 ======================================
# PROTOCOL F - admin_identity leaves its entry UNRESOLVED for the commit, then finalizes against the
# generation the commit produced, and the boundary discards the journal.
# A WORKING MACHINE IDENTITY THE MANIFEST ALREADY CARRIES COMPOSES NOTHING (correction R6). It
# consumes no generation and opens no journal, so there is nothing here to commit, finalize or
# discard - and calling `commit-provider` anyway is exactly the `ProviderMismatch` that killed every
# update of a box whose identity was already working.
$req = Lc-Request 'admin_identity-reconcile' (Lc-Json (Lc-AdminIdentityRequest (Lc-FmsTransport)))
if ($script:CfmAttempt) {
  # Observed IMMEDIATELY before the mutation, and refuse-first on a foreign same-name identity.
  $laObs = Lc-Request 'admin_identity-observe-attempt' (Lc-Json (Lc-AdminIdentityRequest 'absent'))
  $laState = "" + (La-Field (La-Lifecycle @('admin-identity','observe','--request',$laObs)) @('state'))
  if (@('remote_only','mismatched') -contains $laState) {
    Die ("REFUSE-FIRST: FileMaker Server already trusts a same-name Admin API identity this installation" +
         " does not hold (" + $laState + "). A fresh install does not overwrite it. Remove that" +
         " registration deliberately, then re-run.")
  }
  if (@('not_installed','local_only','working') -notcontains $laState) {
    Die ("The Admin API identity reads '" + $laState + "' and cannot be recorded for a fresh attempt. Resolve the reported condition, then re-run.")
  }
  $script:LaProviderIntent = 'admin_identity_reconcile'
  $script:LaProviderPrior = [ordered]@{ observe = $laState.ToUpperInvariant() }
}
$script:LcFrameAccount = $FmAdminUser; $script:LcFramePassword = $FmAdminPass
Lc-ProviderRun "admin_identity reconcile" 'candidate' @('admin-identity','reconcile','--request',$req)
$script:LcFrameAccount = $null; $script:LcFramePassword = $null
$aiOp = $LcOp
if ($LcCompose) {
  Lc-CommitProvider 'admin_identity' $aiOp $CfmGeneration $LcCandidate
  $fin = Lc-Request 'admin_identity-finalize' (Lc-Json ([ordered]@{
    schema_version       = 1
    operation_id         = $aiOp
    installation_id      = $InstallationId
    committed_generation = [int]$CfmGeneration
    actor                = 'installer'
  }))
  Lc-Run "admin_identity finalize" @('admin-identity','finalize','--request',$fin) | Out-Null
  Ok "admin_identity finalized"
  Lc-DiscardProvider 'admin_identity' $aiOp
} else {
  Ok "admin_identity already published - no generation consumed and no journal opened"
}


# === PHASE 15B - Final service definitions and registration, BEFORE the compartment =============
# WHY HERE AND NOT AT PHASE 20 (packet 1246-10-04). The patch compartment proves EFFECTIVE ACCESS
# for both identities before it will touch anything - `NT SERVICE\<web>` and the FMS identity - and
# a virtual service account does not exist until its service is REGISTERED. Registering at phase 20
# put that after the compartment, so phase 16 refused `permissions_incomplete` with "could not read
# effective rights for 'NT SERVICE\corpusfm-web'", and asked an administrator to grant access to a
# principal the box could not yet name. Measured on winfms2026, 2026-08-09, at generation 2.
#
# The definitions are UNCHANGED - same canonical rendering, same read-back, same registration, same
# refusal to start anything. Only their position moved, and with them the one grant the compartment
# depends on. Phase 20 still owns every other ACL and its read-back; phase 21 is still the only
# place a service starts.
Section "Service identities"
Info "Final service definitions"
$Winsw = Join-Path $SvcDir 'WinSW.exe'
if (-not (Test-Path $Winsw)) {
  $rel = Get-Json 'https://api.github.com/repos/winsw/winsw/releases/latest'
  $a = $rel.assets | Where-Object { $_.name -eq 'WinSW.NET461.exe' } | Select-Object -First 1
  if (-not $a) { $a = $rel.assets | Where-Object { $_.name -like 'WinSW-x64.exe' } | Select-Object -First 1 }
  if (-not $a) { Die "No WinSW asset found in the latest release." }
  Get-File $a.browser_download_url $Winsw
}

# MCP access is user-account-centric. The endpoint mounts by deployment mode and every credential
# resolves through storage, so neither a fresh install nor an update provisions a file-backed token.
# Remove both locations used by earlier installers before either runtime service starts.
foreach ($staleMcpEnv in @((Join-Path $FixedSecrets '.mcp_env'), (Join-Path $InstallDir '.mcp_env'))) {
  if (Test-Path -LiteralPath $staleMcpEnv) {
    try {
      La-Do 'file' 'delete' $null @($staleMcpEnv) { Remove-Item -LiteralPath $staleMcpEnv -Force -ErrorAction Stop }
      Ok ("Retired the previous global MCP token at " + $staleMcpEnv)
    } catch {
      Die ("Could not retire the previous global MCP token at " + $staleMcpEnv + ": " + $_.Exception.Message)
    }
  }
}

$RenderPy = Join-Path $Dl '_render_service.py'
@'
import sys
from corpusfm.lifecycle import os_layout, service_identity as si
role, service_id, display, target, install_dir = sys.argv[1:6]
layout = os_layout.windows_os_layout()
common = (("PYTHONDONTWRITEBYTECODE", "1"),)
spec = si.winsw_service_spec(role, layout, install_dir=install_dir, service_id=service_id,
                             display_name=display, description="CORPUSfm " + role,
                             environment=common)
with open(target, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(si.render_winsw_service(spec))
print(spec.command.executable)
print(str(layout.log_dir))
'@ | Set-Content -Path $RenderPy -Encoding ascii
$VerifyPy = Join-Path $Dl '_verify_service.py'
@'
import sys
from corpusfm.lifecycle import os_layout, service_identity as si
role, service_id, display, target, install_dir = sys.argv[1:6]
layout = os_layout.windows_os_layout()
common = (("PYTHONDONTWRITEBYTECODE", "1"),)
spec = si.winsw_service_spec(role, layout, install_dir=install_dir,
                             service_id=service_id, display_name=display,
                             description="CORPUSfm " + role, environment=common)
want = si.render_winsw_service(spec)
with open(target, encoding="utf-8", newline="\n") as fh:
    got = fh.read()
assert got == want, target + " differs from the canonical rendering"
assert si.service_definition_names_an_identity(got), target + " names no unprivileged identity"
'@ | Set-Content -Path $VerifyPy -Encoding ascii

# ONE ROLE (application packet 1361-01, round 3). The `scheduler` role is retired: scheduling is a
# background component of the web process, so there is no second definition to render, verify,
# register or start.
foreach ($role in @('web')) {
  $id = $Service[$role]
  $display = 'CORPUSfm Web'
  $xml = Join-Path $SvcDir ($id + '.xml')
  $renderOut = (& $Py $RenderPy $role $id $display $xml $InstallDir 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { Die ("Could not render the " + $role + " service definition: " + $renderOut) }
  $lines = @($renderOut -split "`r?`n" | Where-Object { $_.Trim() })
  $canonicalLogDir = ("" + $lines[1]).Trim()
  # The same agreement, one level out: the log directory this script writes to and the one the
  # canonical layout publishes must be the same directory, or the transcript and the service logs
  # part company silently.
  if ($canonicalLogDir -ne $LogDir) {
    Die ("The published layout logs to '" + $canonicalLogDir + "' but this installer used '" + $LogDir + "'.")
  }
  # READ BACK: what is on disk must be what the canonical renderer produced, and it must name an
  # unprivileged identity. A definition that failed to write, or wrote partially, must not reach
  # phase 21 - which starts exactly this set.
  $verifyOut = (& $Py $VerifyPy $role $id $display $xml $InstallDir 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { Die ("The installed " + $role + " definition does not match the canonical rendering: " + $verifyOut) }
  # REGISTER, NEVER START. The virtual service account's SID does not exist until the service is
  # registered, so the ACLs below cannot be granted before this; and the services cannot start before
  # those grants, because ConfigHome is locked to SYSTEM+Administrators and they are neither.
  # Register-all, grant, then start at phase 21 - and Register-CfmService has no start path at all.
  La-Do 'service' 'create' $null @($id) { Register-CfmService $id }
  Ok ($id + " definition installed, read back (canonical) and registered - not started")
  $VerifiedServices += $id
}
Remove-Item $RenderPy,$VerifyPy -ErrorAction SilentlyContinue

# THE RETIRED SCHEDULER STAYS REGISTERED THROUGH PHASE 20 (application packet 1361-01). It was
# stopped at phase 9 and it is deleted at the END of phase 20 - after its ACL entries are removed and
# the one-service policy is read back - because its virtual account exists only while it does. See
# THE SCHEDULER RETIREMENT ADAPTER above.

# The identity now EXISTS, which is the whole point of moving this. Name it once; phase 20's
# least-privilege pass uses the same variable.
$WebSid   = 'NT SERVICE\' + $WebService
# CAPTURED ONCE, the moment the account exists (registration is what creates it). Every removal
# operand and every read-back comparison below uses this one numerical value, so an ACL is never
# proven against a different spelling of the trustee than the one that was removed.
$WebSidValue = Resolve-CfmServiceSid $WebSid 'the web service identity'
$WebIcaclsOperand = '*' + $WebSidValue
# ONE service identity (application packet 1361-01, round 3). The retired scheduler service is not
# registered, so `NT SERVICE\corpusfm-scheduler` has no SID at all - naming it in any grant or
# read-back below would make `LookupAccountName` refuse with error 1332.

# THE ONE GRANT PHASE 16 DEPENDS ON. The compartment lives under the recorded hosting folder, and on
# Windows `apply_compartment_permissions` deliberately does nothing - the folder inherits from its
# parent and the effective-rights proof decides whether that inheritance was enough. It was not:
# phase 8 granted SYSTEM + Administrators only. The web service needs MODIFY to create, write and
# remove the compartment's own files; SYSTEM and Administrators keep the authority they already
# hold, and the scheduler is not named here at all.
# `M,DC`, NOT `M` AND NOT `F` (packet 1246-10-04). NTFS Modify is 0x1301BF and does NOT carry
# FILE_DELETE_CHILD (0x40) - that bit lives only in Full Control - and the compartment requires it,
# because it must remove entries it created. Measured on winfms2026, 2026-08-09: the grant landed
# and phase 16 refused "missing 0x40 of the create/read/write/rename/delete set", one bit short.
# Full Control would also pass and would hand the service WRITE_DAC and WRITE_OWNER, which the
# component's own constant deliberately excludes - re-permissioning is far past what it claims.
La-Do 'dir' 'set_acl' $null @($PatchHostingDir) { Grant-OrDie $PatchHostingDir ($WebSid + ':(OI)(CI)(M,DC)') 'the patch compartment' }

# READ BACK AGAINST THE PRODUCT'S OWN CONSTANT, never a mask this script chose. The previous version
# verified 0x116 - a number invented here - so it passed while the compartment's requirement went
# unmet, which is the whole failure mode this read-back exists to prevent: a grant that was issued
# is not a grant that took effect, and a check against the wrong requirement is not a check.
# `patch_compartment.WIN_REQUIRED_RIGHTS` is the one definition; asking it means the installer and
# the provider cannot drift apart.
$rightsProbe = New-CfmProbeFile @'
import sys
from corpusfm.lifecycle.patch_compartment import WIN_REQUIRED_RIGHTS, _win_rights_satisfied
held = int(sys.argv[1])
if _win_rights_satisfied(held):
    print("SATISFIED")
else:
    print("MISSING 0x%x" % (WIN_REQUIRED_RIGHTS & ~held))
'@
try {
  $hostAcl = (Get-Acl $PatchHostingDir).Access
  $webRights = $hostAcl | Where-Object { $_.IdentityReference.Value -eq $WebSid -and $_.AccessControlType -eq 'Allow' }
  if (-not $webRights) {
    Die ("The patch hosting folder " + $PatchHostingDir + " names no grant for " + $WebSid +
         " after one was issued; the patch compartment would refuse. Nothing has been composed.")
  }
  $webMask = 0
  foreach ($ace in $webRights) { $webMask = $webMask -bor [int]$ace.FileSystemRights }
  $verdict = (& $Py $rightsProbe $webMask 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $verdict) {
    Die ("Could not read the compartment's required rights from the installed product: " + $verdict)
  }
  if ($verdict -ne 'SATISFIED') {
    Die ("The patch hosting folder " + $PatchHostingDir + " grants " + $WebSid + " 0x" +
         ('{0:x}' -f $webMask) + ", which the patch compartment refuses (" + $verdict + "). Nothing" +
         " has been composed.")
  }
} finally {
  Remove-Item $rightsProbe -Force -ErrorAction SilentlyContinue
}
Ok ($WebService + " registered (not started); " + $WebSid +
    " granted Modify+DeleteChild on " + $PatchHostingDir + ", read back against the compartment's" +
    " own required-rights constant")


# === PHASE 16 - PATCH - Protocol P - generation 3 ===============================================
# PROTOCOL P - patch-compartment alone. Its `apply` RESOLVES its own journal before returning, so the
# commit requires a RESOLVED entry and there is no finalize verb: the sequence ends at the read-back,
# and the boundary discards the journal.
# The request is the compartment's own ten-key schema - no operation id, no installation id, no
# generation. It RETURNS `operation_id` and a `candidate` already shaped as
# `{patch, patch_hosting_dir}`, which is exactly what `commit-provider` parses, so the candidate is
# passed through rather than rebuilt from a field the result does not carry.
$req = Lc-Request 'patch-apply' (Lc-Json (Lc-PatchRequest))
if ($script:CfmAttempt) {
  $laSeq = La-SeqOf 'dir' $PatchHostingDir
  if (-not $laSeq) {
    Die ("the patch hosting folder " + $PatchHostingDir + " has no entry in this attempt's record, so the patch compartment cannot be recorded against it. Nothing was changed by this step.")
  }
  $script:LaProviderIntent = 'patch_apply'
  $script:LaProviderPrior = [ordered]@{ hosting_dir_seq = [int]$laSeq }
}
Lc-ProviderRun "patch compartment apply" 'candidate' @(
  'patch-compartment','apply','--request',$req,'--mode',$CfmMode
)
$patchOp = $LcOp
if ($LcCompose) {
  Lc-CommitProvider 'patch' $patchOp $CfmGeneration $LcCandidate
  Lc-DiscardProvider 'patch' $patchOp
} else {
  Ok "patch compartment already satisfied - no generation consumed and no journal opened"
}


# === PHASE 16B - The proxy executor's replacement-authority boundary ============================
# WHAT THE PRODUCT ACTUALLY REQUIRES (packet 1246-10-04). `proxy_transaction.executor_refusal`
# checks REPLACEMENT authority, not file authority: a perfectly protected script inside a directory
# somebody else can write is not protected at all - they need not edit it, they delete it and put
# their own there. So it walks executor -> bin -> install root and demands each carry a PROTECTED,
# non-inherited DACL owned by SYSTEM or the invoking administrator, naming nobody else.
#
# The Windows installer never established that. `C:\Program Files\CORPUSfm` inherited everything
# from `C:\Program Files` - `CREATOR OWNER:(F)`, `BUILTIN\Users:(RX)`, the application packages,
# TrustedInstaller - so phase 17 refused "does not carry a protected DACL" at generation 3.
# Measured on winfms2026, 2026-08-09. CREATOR OWNER is the substantive one: it means whoever
# creates a file there owns it outright.
#
# EXACTLY THESE THREE SUBJECTS, and no `/t`. The requirement is a chain, not a tree policy: the
# source checkout, the bundled Python, the venv and the library keep their own ACLs. What they do
# receive is what inheritance from a protected parent gives them, which is the same two principals.
#
# THIS RUNS ON EVERY INVOCATION, and it must. Phase 20 grants both service identities read and
# traverse here so they can start at phase 21, and `executor_refusal` counts EVERY named trustee -
# so a box that has completed once carries explicit service ACEs the next proxy check rejects.
# `/grant:r` replaces grants only for the trustees it names; it does not clear those service ACEs.
# Remove exactly the two current service grants first. Any other explicit trustee survives and the
# provider refuses it rather than this installer silently normalising unexplained authority.
Section "Executor authority"
$AuthorityChain = @(
  @{ Path = $InstallDir;    Kind = 'dir'  },
  @{ Path = $BinDir;        Kind = 'dir'  },
  @{ Path = $ProxyExecDst;  Kind = 'file' }
)
foreach ($subject in $AuthorityChain) {
  if (-not (Test-Path $subject.Path)) {
    Die ("The proxy executor's authority chain is incomplete: " + $subject.Path + " does not exist." +
         " Nothing has been composed.")
  }
  # WELL-KNOWN SIDs, not localised names: `BUILTIN\Administrators` is spelled differently on a
  # non-English Windows and this must not depend on the box's language.
  & icacls $subject.Path /setowner '*S-1-5-32-544' 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Die ("Could not take ownership of " + $subject.Path) }
  if ($subject.Kind -eq 'dir') {
    # TWO SEPARATE SINGLE-TRUSTEE REMOVALS, each by numerical SID and each checked on its own.
    # These used to be one batched call naming both accounts, which is what failed: a batch is
    # all-or-nothing, so one unresolvable operand removed neither grant and reported 1332.
    # The retired half runs only on a box whose preflight captured a SID for it.
    Remove-CfmGrantBySid $subject.Path $WebIcaclsOperand 'prior web service read'
    if ($SchedRetiredIcaclsOperand) {
      Remove-CfmGrantBySid $subject.Path $SchedRetiredIcaclsOperand "retired scheduler's"
    }
  }
  $grants = if ($subject.Kind -eq 'dir') { @('*S-1-5-18:(OI)(CI)(F)', '*S-1-5-32-544:(OI)(CI)(F)') }
            else                         { @('*S-1-5-18:(F)',         '*S-1-5-32-544:(F)') }
  # `/inheritance:r` REMOVES the inherited ACEs (it is `/inheritance:d` that copies them down first)
  # and `/grant:r` replaces rather than adds for SYSTEM and Administrators. The known service ACEs
  # were retired above. Any other explicit principal remains visible to the provider and refuses.
  & icacls $subject.Path /inheritance:r /grant:r @grants 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Die ("Could not protect " + $subject.Path) }
}

# READ BACK THROUGH THE PRODUCT'S OWN PREDICATE. Asking `executor_refusal` rather than re-deriving
# its rule here is what keeps the installer and the provider from drifting - the same reason the
# compartment's required rights are read from `patch_compartment` rather than restated.
$authProbe = New-CfmProbeFile @'
import sys
from pathlib import Path
from corpusfm.lifecycle.proxy_transaction import executor_refusal
why = executor_refusal(Path(sys.argv[1]), is_windows=True, install_dir=sys.argv[2])
print("ACCEPTED" if why is None else "REFUSED " + why)
'@
try {
  # Python may emit a warning on stderr while still completing this read-only probe. Windows
  # PowerShell promotes native stderr to a terminating NativeCommandError under EAP=Stop, so judge
  # the child by its exit code and exact stdout verdict, as the other native probes do.
  $authEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $verdict = (& $Py $authProbe $ProxyExecDst $InstallDir 2>&1 | Out-String).Trim()
    $authRc = $LASTEXITCODE
  } finally { $ErrorActionPreference = $authEap }
  if ($authRc -ne 0 -or -not $verdict) {
    Die ("Could not read the proxy executor's authority from the installed product: " + $verdict)
  }
  if ($verdict -ne 'ACCEPTED') {
    Die ("The proxy executor's authority chain is not acceptable to the provider (" + $verdict +
         "). Nothing has been composed.")
  }
} finally {
  Remove-Item $authProbe -Force -ErrorAction SilentlyContinue
}
Ok ("Executor authority established over " + $ProxyExecDst + " -> " + $BinDir + " -> " + $InstallDir +
    " (SYSTEM + Administrators only, inheritance disabled) and accepted by the provider's own check")


# THE GLOBAL ARR TOGGLE IS A PREREQUISITE, NOT A PUBLICATION (developer ruling, 2026-08-09). The
# provider's IIS family is an ARR reverse-proxy application, so the switch must already be on when
# phase 17 composes it; it is a safe global toggle FMS itself relies on, and the shared REWRITE
# configuration is never touched. Read back rather than assumed: a `Set` that did not take would
# leave the provider publishing a family that cannot forward.
if (-not $arr) {
  # RULING 6: the one fixed IIS fact, recorded before and after. No rollback, deletion or command.
  $laArrSeqs = @()
  if ($script:CfmAttempt) {
    $laArrBefore = [bool](Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'enabled' -ErrorAction SilentlyContinue).Value
    La-Step 'iis_setting' 'enable_arr_proxy' ([ordered]@{ enabled = $laArrBefore }) @('system.webServer/proxy')
    $laArrSeqs = $script:LaSeqs
  }
  try {
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'enabled' -Value $true
  } finally {
    if ($script:CfmAttempt) {
      $laArrAfter = [bool](Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'enabled' -ErrorAction SilentlyContinue).Value
      if ($laArrAfter) { La-Result $laArrSeqs 'done' ([ordered]@{ enabled = $laArrAfter }) }
      else { La-Result $laArrSeqs 'failed' ([ordered]@{ enabled = $laArrAfter }) }
    }
  }
  $arrNow = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'enabled' -ErrorAction SilentlyContinue).Value
  if (-not $arrNow) {
    Die "The global ARR reverse-proxy toggle could not be enabled; the proxy family would publish but never forward. Nothing has been composed."
  }
  $arr = $true
  Ok "Enabled ARR reverse-proxy (was off) and read it back"
}

# === PHASE 17 - PROXY - Protocol F - generation 4 ===============================================
# PROTOCOL F - proxy leaves its entry UNRESOLVED for the commit, then finalizes against the
# generation the commit produced, and the boundary discards the journal.
# `candidates` (plural) is the one place the four providers' result shapes differ: proxy composes ONE
# ENTRY PER FRONT, so its result is a mapping of proxy type to entry and `commit-provider` reads it
# under the key `proxy_policy`. The other three return a `candidate` object already in the shape the
# commit parses.
#
# FINALIZE takes `committed_generation` and `operation_id` - never `generation`, never `install_dir`.
# The generation it names is the one the COMMIT produced.
$req = Lc-Request 'proxy-reconcile' (Lc-Json (Lc-ProxyRequest 'reconcile'))
$ProxyProbeProcess = $null
$ProxyProbeScript = ''
try {
  if ($ClarisNginxActive) {
    # Phase 21 intentionally owns the real service start, but an active nginx publication must be
    # proven after its FMS restart. A closed loopback port yields a 502 whose socket-side meaning is
    # not observable reliably on Windows. Give the route one bounded, loopback-only upstream now;
    # a 2xx proves nginx loaded the staged include and reached the exact internal port. This process
    # is never the application and is always retired before composition continues.
    $ProxyProbeScript = Join-Path $Dl '_proxy_activation_probe.py'
    @'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()
    def log_message(self, *_args):
        pass
ThreadingHTTPServer(('127.0.0.1', 8533), Handler).serve_forever()
'@ | Set-Content -LiteralPath $ProxyProbeScript -Encoding ascii
    # Start-Process flattens ArgumentList before creating the process. Preserve the script path as
    # one quoted argv entry: both the Python and download roots normally contain "Program Files".
    $ProxyProbeArgument = '"' + $ProxyProbeScript + '"'
    $ProxyProbeProcess = Start-Process -FilePath $Py -ArgumentList $ProxyProbeArgument `
      -WindowStyle Hidden -PassThru
    $probeCode = -1
    for ($i=0; $i -lt 20 -and $probeCode -ne 204; $i++) {
      Start-Sleep -Milliseconds 250
      $probeCode = Code "http://127.0.0.1:$WebPort/"
    }
    if ($probeCode -ne 204) {
      Die ("The bounded proxy activation responder could not bind loopback port " + $WebPort +
           "; no proxy change was attempted.")
    }
    Ok ("Loopback-only proxy activation responder ready on port " + $WebPort)
  }
  if ($script:CfmAttempt) {
    # Each front's owned-block state, observed now. A block that differs from this installation's
    # rendering is REFUSE-FIRST; only an absent or current block proceeds.
    $laObs = Lc-Request 'proxy-status-attempt' (Lc-Json (Lc-ProxyRequest 'status'))
    $laStatus = La-JsonObject (La-Lifecycle @('proxy','status','--request',$laObs))
    $laBlocks = [ordered]@{}
    foreach ($laRow in @($laStatus.per_type)) {
      if (-not $laRow) { continue }
      $laBlock = "" + $laRow.owned_block
      if (@('absent','current') -notcontains $laBlock) {
        Die ("REFUSE-FIRST: the " + $laRow.proxy_type + " front carries a " + $laBlock + " CORPUSfm block that" +
             " differs from this installation's rendering. A fresh install does not publish over it.")
      }
      $laBlocks[("" + $laRow.proxy_type)] = ('BLOCK_' + $laBlock.ToUpperInvariant())
    }
    if ($laBlocks.Count -eq 0) { Die "the proxy status observation carries no per-front block state; nothing was changed by this step." }
    $script:LaProviderIntent = 'proxy_reconcile'
    $script:LaProviderPrior = [ordered]@{ blocks = $laBlocks }
  }
  $script:LcFrameAccount = $FmAdminUser; $script:LcFramePassword = $FmAdminPass
  Lc-ProviderRun "proxy reconcile" 'candidates' @('proxy','reconcile','--request',$req)
} finally {
  $script:LcFrameAccount = $null; $script:LcFramePassword = $null
  if ($ProxyProbeProcess) {
    Stop-Process -Id $ProxyProbeProcess.Id -Force -ErrorAction SilentlyContinue
    try { Wait-Process -Id $ProxyProbeProcess.Id -Timeout 5 -ErrorAction SilentlyContinue } catch {}
  }
  if ($ProxyProbeScript) { Remove-Item -LiteralPath $ProxyProbeScript -Force -ErrorAction SilentlyContinue }
}
$proxyOp = $LcOp
if ($LcCompose) {
  Lc-CommitProvider 'proxy' $proxyOp $CfmGeneration ([ordered]@{ proxy_policy = $LcCandidate })
  $fin = Lc-Request 'proxy-finalize' (Lc-Json ([ordered]@{
    schema_version       = 1
    operation_id         = $proxyOp
    installation_id      = $InstallationId
    committed_generation = [int]$CfmGeneration
    actor                = 'installer'
  }))
  Lc-Run "proxy finalize" @('proxy','finalize','--request',$fin) | Out-Null
  Ok "proxy finalized"
  Lc-DiscardProvider 'proxy' $proxyOp
} else {
  Ok "proxy already satisfied - no generation consumed and no journal opened"
}

# -- Declared proxy POLICY (parent section 4H.1) -------------------------------------------------
# -ProxyPolicyAdd and -ProxyPolicyIgnore were echoed into the plan and consumed NOWHERE (finding
# F4/B9): two supported options that changed nothing. They move POLICY, which is a different act from
# reconciling routing - `managed` means CORPUSfm owns that front, `ignored` means it does not - so
# they run through `proxy-public`, the surface that owns policy, after the reconcile they would otherwise
# contradict.
# THE VERB GROUP IS `proxy-public`, NOT `proxy`. `proxy` is the INTEGRATOR surface and declares only
# status/reconcile/finalize/abort; `add` and `ignore` live on the public surface, which takes a
# selector and no `--request`. Sending them to `proxy` exits 2 from argparse - which would have
# aborted the run at phase 16, AFTER generation 3 was committed and the proxy journal discarded.
# $ErrorActionPreference is 'Stop' globally, and under Stop a native command that merely PRINTS to
# stderr while succeeding escalates to a terminating NativeCommandError once `2>&1` merges the
# streams - aborting the install with a raw PowerShell error instead of the Die message below. Every
# other native lifecycle call in this file saves and restores the preference for exactly this
# reason; these two must as well. $LASTEXITCODE is read BEFORE the restore, because restoring is
# itself a statement.
$eapP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
try {
  foreach ($pt in $ProxyPolicyAdd) {
    Cfm-Logline ((& $Py -m corpusfm.lifecycle proxy-public add $pt 2>&1 | Out-String))
    $rcP = $LASTEXITCODE
    if ($rcP -ne 0) { $ErrorActionPreference = $eapP; Die ("could not record proxy policy 'managed' for '" + $pt + "'.") }
    Ok ("proxy policy: " + $pt + " managed")
  }
  foreach ($pt in $ProxyPolicyIgnore) {
    Cfm-Logline ((& $Py -m corpusfm.lifecycle proxy-public ignore $pt 2>&1 | Out-String))
    $rcP = $LASTEXITCODE
    if ($rcP -ne 0) { $ErrorActionPreference = $eapP; Die ("could not record proxy policy 'ignored' for '" + $pt + "'.") }
    Ok ("proxy policy: " + $pt + " ignored")
  }
} finally { $ErrorActionPreference = $eapP }

# -- Reverse proxy: THE LIFECYCLE PROVIDER PUBLISHES IT, and nothing here does --------------------
# THE ENTIRE INLINE PUBLICATION PATH IS DELETED (developer ruling, 2026-08-09). This block used to
# render a web.config, create the pool and the application, mount the metadata children, and apply
# the nginx include through a second publisher - all AFTER
# phase 17 had already composed exactly that family and stored its fingerprint in the manifest. So
# the installer published over the provider's own work, and the next run observed a family whose
# fingerprint no longer matched what the manifest recorded and refused with "the CORPUSfm-owned
# routing was edited outside CORPUSfm". Nobody had edited it: the installer was the second
# publisher. Measured on winfms2026, 2026-08-09, generation 10.
#
# One publisher now: `composition proxy reconcile` at phase 17. It owns the IIS application family,
# the metadata children and the optional Claris-nginx front alike - the `claris-nginx` proxy type is
# UNCHANGED and still supported; what is gone is this installer's second, unrecorded path to it.
# The global ARR toggle stays, because it is a PREREQUISITE rather than a publication, and it has
# moved ahead of phase 17 where the provider needs it.
Info "Reverse proxy"
Ok ("the proxy family is published and owned by the lifecycle provider (composed at phase 17); this installer publishes no routing of its own")


# === PHASE 18 - STORAGE - Protocol F - generation 5 =============================================
# PROTOCOL F - storage leaves its entry UNRESOLVED for the commit, then finalizes against the
# generation the commit produced, and the boundary discards the journal.
#
# STORAGE composition-ready: a fresh success may report `incomplete_safe` with a
# first_administrator_owed candidate. That exact predicate - and only it - is composable; any other
# incomplete_safe stops the run through Lc-Dispatch.
# THE VERB FOLLOWS THE MODE (parent section 4H.1; finding F4/B9). -RepairStorageAccess set a
# variable nothing read. `repair_storage_access` is a real member of `storage_identity.MODES` and
# `repair` is a real shipped verb, so the option now selects both - one bounded repair, never a
# second bootstrap of an installation that already has one.
# ROUTED FROM THE OBSERVATION, never from the flag alone (correction C1). `bootstrap` is reachable
# from exactly one state - `proven_fresh` on a fresh install - so there is no path from a failed
# anything to a bootstrap, and "never reinterpret a failed bootstrap as an update plan" is
# structural rather than a promise. Every unroutable state refused above, before any mutation.
# OBSERVED HERE, WHERE THE AUTHORITY EXISTS (packet 1246-10-04). The phase-14 observation ran before
# phase 15 published the Admin-API machine identity, so its database-known and hosted axes were
# UNKNOWN and its state was `indeterminate` on every box - measured on fms-server 2026-08-08, where a
# fresh install stopped here with "storage cannot be routed". Routing reads THIS observation. stdout
# is captured SEPARATELY from stderr: a diagnostic merged into the JSON would make it unparseable.
$obsReq = Lc-Request 'storage-observe' (Lc-Json (Lc-StorageRequest $CfmStorageMode))
$eapS = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$CfmStorageObservation = (& $Py -m corpusfm.lifecycle storage observe --request $obsReq 2>$null | Out-String)
$ErrorActionPreference = $eapS
Cfm-Logline $CfmStorageObservation
$stRoute = Lc-StorageRoute $CfmStorageObservation
if ($stRoute -eq 'skip') {
  Ok "storage: the published corpus is reachable - no verb, no journal, no generation consumed"
} else {
$stVerb = $stRoute
$req = Lc-Request ('storage-' + $stVerb) (Lc-Json (Lc-StorageRequest $CfmStorageMode))
if ($script:CfmAttempt) {
  # The storage target is observed and intended IMMEDIATELY before the provider call (section 6.5):
  # a bootstrap must find it absent, an adoption must find it present, and a contradiction refuses.
  $laTarget = "" + $script:AttemptRecord.paths.storage_target
  $laPresent = Test-Path -LiteralPath $laTarget -PathType Leaf
  if ($stRoute -eq 'bootstrap' -and (Test-Path -LiteralPath $laTarget)) { Die ("storage routed to bootstrap, but " + $laTarget + " already exists. Nothing was changed by this step.") }
  if ($stRoute -eq 'adopt' -and -not $laPresent) { Die ("storage routed to adoption, but " + $laTarget + " is not present. Nothing was changed by this step.") }
  if (@('bootstrap','adopt') -notcontains $stRoute) { Die ("storage routed to '" + $stRoute + "', which a fresh attempt cannot record. Nothing was changed by this step.") }
  La-Step 'file' 'ensure' $null @($laTarget)
  $script:LaProviderTargetSeqs = $script:LaSeqs
  $script:LaProviderIntent = 'storage_' + $stRoute
  $script:LaProviderPrior = [ordered]@{ observe = ("" + (Lc-Field $CfmStorageObservation 'state')); route = $stRoute
                                        target_seq = [int](La-SeqOf 'file' $laTarget) }
}
Lc-ProviderRun ("storage " + $stVerb) 'candidate' @('storage',$stVerb,'--request',$req)
if ($LcFirstAdminOwedByDisposition) {
  $CfmFirstAdminOwed = $true
  Info "storage composed a candidate and owes only its first administrator (phase 19)"
} else {
  $CfmFirstAdminOwed = $false
}
$stOp = $LcOp
# A repair that composed nothing is terminal and consumes no generation; one that composed a
# candidate follows the same commit/finalize/discard every Protocol F provider does.
if (-not $LcCompose) {
  Ok "storage $stVerb completed with nothing to compose - no generation consumed"
} else {
Lc-CommitProvider 'storage' $stOp $CfmGeneration $LcCandidate
$fin = Lc-Request 'storage-finalize' (Lc-Json ([ordered]@{
  schema_version       = 1
  operation_id         = $stOp
  installation_id      = $InstallationId
  committed_generation = [int]$CfmGeneration
  actor                = 'installer'
}))
Lc-Run "storage finalize" @('storage','finalize','--request',$fin) | Out-Null
# The journal must be RESOLVED before it is discarded - `Journal.discard` refuses an unresolved
# record, so this is a read-back of what finalize claims rather than a second opinion about it.
$eapJ = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$stState = (& $Py -m corpusfm.lifecycle status --json 2>&1 | Out-String)
$ErrorActionPreference = $eapJ
if (("" + (Lc-Field $stState 'journal')) -ne 'resolved') {
  Die ("storage finalized but its journal reads '" + (Lc-Field $stState 'journal') + "', not resolved; refusing to discard it.")
}
Ok "storage finalized"
Lc-DiscardProvider 'storage' $stOp
$eapJ = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$stState = (& $Py -m corpusfm.lifecycle status --json 2>&1 | Out-String)
$ErrorActionPreference = $eapJ
if (("" + (Lc-Field $stState 'journal')) -ne 'none') {
  Die ("storage's journal reads '" + (Lc-Field $stState 'journal') + "' after the discard; refusing to continue over it.")
}
}          # end: the repair/bootstrap composed a candidate
}          # end: storage was not routed to `skip`

# -- FileMaker Server storage: THE PROVIDER COMPOSED IT, and nothing here republishes it ---------
# THE ENTIRE INLINE STORAGE PUBLISHER IS DELETED (developer ruling, 2026-08-09), mirroring the same
# deletion on Linux and the proxy one above it. This tail deployed the database, registered PKI, ran
# `run_bootstrap` to rotate the automation password, called `activate_fm_backend`, and wrote a
# legacy `server_configs` record - all AFTER phase 18 had composed exactly that storage and stored
# its credential. Two publishers of one authority is what produced a rotated credential the manifest
# did not describe, and it is the same shape as the proxy defect measured on winfms2026 the same day.
#
# The lifecycle storage provider owns the corpus, its credential and its rotation. What remains
# below CONSUMES that composition: the projection backfill reads the composed backend, and phase 19
# handles the first administrator. Neither publishes storage authority.
#
# THE FMS ADMINISTRATOR CREDENTIAL HAS NO CONSUMER LEFT. Phase 5 verified it, phase 16 and 18 pass
# it to the provider through the credential frame; nothing after this point needs it, so it is
# cleared here rather than left in the process for the remaining phases to inherit. Cleared, never
# logged: no branch prints, tests or reports its value.
$FmAdminUser = $null
$FmAdminPass = $null
Remove-Item Env:\FM_ADMIN_USER -ErrorAction SilentlyContinue
Remove-Item Env:\FM_ADMIN_PASS -ErrorAction SilentlyContinue
Ok "storage is composed and owned by the lifecycle provider; the FM administrator credential is cleared"

# -- Indexed-slot projection backfill (idempotent; OData-only, no DB swap) ------------------------
# Fills newly-added query slots on historical records; slots fill only on commit, so pre-existing
# rows need a one-time re-projection. Marker-gated: a no-op once current (and trivial on a fresh
# install). Best-effort - the picker uses its scan fallback until it completes.
Info "Projection backfill"
# Capture native stdout+stderr WITHOUT terminating: under $ErrorActionPreference='Stop', a benign
# line on the child's stderr (e.g. a urllib3 InsecureRequestWarning from the verify_ssl=False OData
# call) is otherwise raised as a fatal NativeCommandError - which once killed the whole install at
# this step. Relax EAP around the call; judge success by $LASTEXITCODE only.
if ($script:CfmAttempt) {
  # RULING 6: bound to this attempt's storage-target entry and storage route. It only reports that
  # projection writes may have occurred; an adopted database is always preserved.
  La-ProviderBegin 'backfill_storage_projections' ([ordered]@{
    target_seq = [int](La-SeqOf 'file' ("" + $script:AttemptRecord.paths.storage_target)); route = $stRoute }) 'storage'
}
$eapB = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$pbOut = (& $Py -m corpusfm.server.cli backfill-storage-projections 2>&1 | Out-String).Trim()
$pbrc = $LASTEXITCODE
$ErrorActionPreference = $eapB
La-ProviderEnd 'backfill_storage_projections' $pbrc $pbOut
$pbLast = if ($pbOut) { ($pbOut -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim() } else { "" }
if ($pbrc -eq 0) { Ok ("Projections current" + $(if ($pbLast) { " - $pbLast" } else { "" })) }
else { Warn ("Projection backfill did not complete - picker uses the scan fallback until it does. " + $pbOut) }


# === PHASE 19 - Post-composition installation work ==============================================
# First CORPUSfm admin (a named-user web login). The browser no longer creates the first account
# (anti-race), so a FRESH install creates it here; existing users are PRESERVED. The password
# reaches the child through the environment ONLY - never on the command line (process list) and
# never logged or echoed. -AdminUser and -AdminPass are retired: the approved environment secrets
# replace them (section 6).
Info "First CORPUSfm admin"
# raise_on_error=True is load-bearing (packet 1201): the default form SWALLOWS a storage failure and
# answers "no users", so an outage read as a FRESH box. Raising leaves $hasUsers empty = UNKNOWN,
# which is a third state - not "no admin". Knowing there is no admin is FATAL (a box nobody can sign
# in to is not a completed install); not knowing is reported and continues, so a transient read never
# aborts an update re-run.
$hasUsers = ("$(& $Py -c "from corpusfm.app.web import users; print('1' if users.users_exist(raise_on_error=True) else '0')" 2>$null | Select-Object -Last 1)").Trim()
if ($hasUsers -eq '1') {
  Ok "CORPUSfm admin already configured - preserving existing users"
} elseif ($hasUsers -ne '0') {
  # ...UNLESS phase 18 already told us. When storage composed `first_administrator_owed` it read the
  # user table and found it EMPTY, so "we cannot tell" is not a tie - it is a later, worse read of a
  # question already answered, and continuing would report a box nobody can sign in to as done.
  if ($CfmFirstAdminOwed) {
    Die ("storage reported that this installation owes its first administrator, and whether one exists can no longer be determined. The services stay STOPPED. Restore storage and re-run the installer.")
  }
  Warn ("Could not determine whether a CORPUSfm admin exists - storage was unreachable. If the login page reports no users once storage is back, create one: " + $Py + " -m corpusfm.server.cli users create <name> --admin")
} else {
  # Fresh-install input was acquired and validated before final consent. There is deliberately no
  # post-mutation prompt here: reaching this branch without it is an internal installer failure.
  if (-not $AdminUser) { $AdminUser = 'admin' }
  if (-not $AdminPass) {
    Die "No CORPUSfm admin exists and none was supplied - a box nobody can sign in to is not a completed install. Provide CORPUSFM_ADMIN_USER/CORPUSFM_ADMIN_PASS and re-run."
  } elseif ($AdminPass.Length -lt 8) {
    $AdminPass = ''
    Die "The CORPUSfm admin password must be at least 8 characters - no admin was created. Re-run with a longer CORPUSFM_ADMIN_PASS."
  } else {
    # THROUGH THE SHIPPED STORAGE VERB (packet 1246-04-04, correction R5 step 8). This used to call
    # `users.create_user` directly, bypassing the provider that owns the user store - so the one act
    # that decides whether anybody can sign in had no lock, no journal, no read-back and no result
    # word. `storage create-first-admin` has all four, and it PROVES the account read back before
    # reporting `completed`.
    #
    # ORDER IS THE CONTRACT: this runs at phase 19, after phase 18 committed, finalized and
    # discarded the storage candidate. Creating the administrator first would put a row in a store
    # whose composition the installation record does not yet acknowledge.
    #
    # THE PASSWORD TRAVELS ON STDIN, never in the request. `admin_credential_input` is the TRANSPORT
    # TOKEN `stdin`; the request JSON is written to an administrator-owned file and carries no
    # secret (section 6).
    $faReq = Lc-Request 'storage-create-first-admin' (Lc-Json ([ordered]@{
      schema_version         = 1
      actor                  = 'installer'
      installation_id        = $InstallationId
      install_dir            = $InstallDir
      fms_root               = $FmsBin
      fms_database_dir       = $FmDbDir
      secrets_dir            = $CfmSecretsDir
      host                   = $CfmFmsHost
      mode                   = $CfmMode
      expected_generation    = [int]$CfmGeneration
      admin_username         = $AdminUser
      admin_credential_input = 'stdin'
    }))
    La-ProviderBegin 'create_first_admin' ([ordered]@{ users_exist = $false }) 'first_admin'
    $eapA = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $mkOut = ($AdminPass | & $Py -m corpusfm.lifecycle storage create-first-admin --request $faReq 2>&1 | Out-String)
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $eapA
    La-ProviderEnd 'create_first_admin' $rc $mkOut
    $AdminPass = ''
    Cfm-Logline $mkOut
    $faResult = "" + (Lc-Field $mkOut 'result')
    if ($rc -eq 0 -and $faResult -eq 'completed') {
      Ok ("First CORPUSfm admin '" + $AdminUser + "' created (full admin)")
    } elseif ($rc -eq 0 -and $faResult -eq 'no_change') {
      # `no_change` is returned ONLY after `users_exist` proved True on a real backend read - an
      # outage answers `manual_action_required`, not "already there". So this word IS the proof.
      Ok "A CORPUSfm administrator already exists - existing users preserved"
    } else {
      Lc-Dispatch $rc "creating the first CORPUSfm administrator"
      Die ("creating the first CORPUSfm administrator returned '" + $faResult + "'; this box has no way in. The services stay STOPPED. Fix the reported error and re-run the installer.")
    }
  }
  $AdminPass = ''
}


# === PHASE 20 - Final ACLs over the definitions registered at phase 15B =========================
# THE DEFINITIONS ARE ALREADY INSTALLED, READ BACK AND REGISTERED (packet 1246-10-04). That half of
# this phase moved to 15B, ahead of the patch compartment, because the compartment REQUIRES both
# service identities to hold effective access to the hosting folder and a virtual service account
# has no SID until its service is registered. Measured on winfms2026, 2026-08-09: phase 16 refused
# `permissions_incomplete` - "could not read effective rights for 'NT SERVICE\corpusfm-web'" - and
# its own next_action asked for something that could not yet exist. Nothing is registered again
# here: this phase completes the least-privilege ACLs over the identities 15B created, reads them
# back, and phase 21 remains the only place a service starts.

# -- Service ACLs ---------------------------------------------------------------------------------
# The services do not run as LocalSystem, so they do not inherit its access to everything.
# Lock-DirTreeAcl at phase 8 granted SYSTEM + Administrators only; each virtual service account now
# needs exactly what it uses and nothing more. The SIDs exist only after registration, which is why
# this runs after 15B and not with the directory creation.
#
# EFFECTIVE RIGHTS, NOT SPELLING. An earlier version granted Modify on a mixed tree and then "pulled
# back" each key with `/grant (R)`. That is not how NTFS works: ACL grants are ADDITIVE and an
# inherited Modify ACE survives an added Read ACE. The fix is per-file PROTECTION: `/inheritance:r`
# REMOVES the inherited ACEs (it is `/inheritance:d` that copies them down before severing), and
# `/grant:r` then replaces rather than adds, so the explicit set that follows is the whole DACL.
#
# PER-FILE PROTECTION IS NOT SUFFICIENT ON ITS OWN: a parent directory the service can create, delete
# and rename entries in lets it delete a protected file and put its own there. That is why the
# secrets directory withholds those rights.
#
# Only the WEB identity may run the update task. Installed secrets are uniformly read-only to both
# service identities; neither receives a per-file exception.
Info "Service ACLs"

# THE SECRETS ARE THE PROVIDER'S, NOT THIS SCRIPT'S (developer ruling, 2026-08-09). This used to
# `/reset` the secrets directory and then `/grant` the four principals - two calls, and the first
# one removes the caller's own authority before the second can run. On a box where SYSTEM already
# owned the directory that is unrecoverable in place: measured on winfms2026, 2026-08-09, at
# generation 20, `icacls C:\ProgramData\CORPUSfm\secrets: Access is denied`, because the
# pre-service protection had made it SYSTEM's alone and the elevated installer is Administrators.
#
# `WindowsLayoutProtector` is the single final authority for that policy, and it is reached the way
# the two-stage design always intended: a SECOND `provision-keys`, now with `pre_service=false` and
# the two registered service SIDs, after registration and before any service starts. It writes each
# whole DACL in one operation and reads the result back, so there is no window in which the caller
# has surrendered its authority.
$req = Lc-Request 'provision-keys-final' (Lc-Json ([ordered]@{
  schema_version       = 1
  actor                = 'installer'
  flavour              = 'windows'
  database_name        = 'CORPUSfm_DB'
  database_search_dirs = @($FmDbDir, $PatchHostingDir)
  pre_service          = $false
  web_sid              = $WebSid
}))
$laPrior = $null
if ($script:CfmAttempt) { $laPrior = La-KeysPrior }
La-LcRun 'provision_keys' $laPrior "final secret protection" @('provision-keys','--request',$req) | Out-Null
Ok ("Secrets protected for the registered service (SYSTEM owner, Administrators full, " +
    $WebService + " read-only)")

& icacls $OutcomeDir /reset 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die ("Could not reset the ACL on " + $OutcomeDir) }
& icacls $OutcomeDir /inheritance:r /grant:r ($SystemSid + ':(OI)(CI)(F)') ($AdminsSid + ':(OI)(CI)(F)') `
    ($WebSid + ':(OI)(CI)(RX)') 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die ("Could not protect the update outcome directory " + $OutcomeDir) }

# THE ONE-SERVICE ACL POLICY, and the retirement adapter's steps 2-3 wrapped around it.
#
# These eight locations are exactly where this installer's OWN two-service layout granted a service
# identity, so they are exactly where a retired scheduler's grant can still be sitting. The list is
# the grant loop's own list - it cannot drift from what is granted, because it is what is granted.
# (`$OutcomeDir` above and the secrets below are not here on purpose: both are rewritten WHOLE each
# run - `/reset` + `/grant:r`, and the provider's protected DACLs - so neither can carry a stale
# trustee forward.)
$OneServiceAclPolicyPaths = @($LogDir, $FixedState, $FixedRun, $InboxDir,
                              $InstallDir, $BinDir, $FixedConfig, $LegacyHome)

# STEP 2 - remove the retired grants FIRST, while the account still resolves, so the grants below
# author a fresh DACL rather than adding a second service to a two-service one.
Remove-CfmRetiredSchedulerGrants $OneServiceAclPolicyPaths

foreach ($sid in @($WebSid)) {
  La-Do 'dir' 'set_acl' $null @($LogDir) { Grant-OrDie $LogDir ($sid + ':(OI)(CI)(M)') 'logs' }
  Grant-OrDie $FixedState  ($sid + ':(OI)(CI)(M)')  'service state'
  Grant-OrDie $FixedRun    ($sid + ':(OI)(CI)(M)')  'service run directory'
  Grant-OrDie $InboxDir    ($sid + ':(OI)(CI)(M)')  'update inbox'
  Grant-OrDie $InstallDir  ($sid + ':(OI)(CI)(RX)') 'read the install tree'
  # BIN TOO, EXPLICITLY. Phase 16B protects it to SYSTEM + Administrators only, so a service that
  # must reach what lives there gets an explicit read+traverse ACE rather than an inherited one it
  # no longer has. READ AND TRAVERSE ONLY: no write, no delete, no ownership, no DACL authority -
  # the executor inside it stays administrator/SYSTEM-only, and phase 16B of the NEXT run resets
  # this chain before the provider inspects it again.
  Grant-OrDie $BinDir      ($sid + ':(OI)(CI)(RX)') 'read the entry points'
  Grant-OrDie $FixedConfig ($sid + ':(OI)(CI)(RX)') 'read the published configuration'
  # TRANSITIONAL, and deliberately bounded. Until the published layout is authoritative for the
  # running application (packet 1246-10), this legacy directory holds state the app must write.
  # install.sh carries the identical transitional grant for the identical reason.
  Grant-OrDie $LegacyHome  ($sid + ':(OI)(CI)(M)')  'transitional mixed state'
}

# THE INSTALLED SECRETS ARE THE PROVIDER'S TOO. This loop reset and re-granted each file, the same
# two-call shape as the directory above and with the same hazard. `READ_ONLY_SECRETS` in
# `lifecycle/protection.py` is the one list - it now includes `storage_access.json`, which this
# hard-coded loop never named - and the final `provision-keys` above applies and verifies it.

# The ONE writable secret, protected the same way and granted to the WEB identity only.
# (R,W) rather than (M): NTFS Modify carries DELETE on the file, the exact authority the ruling
# withholds. The scheduler is absent from this DACL entirely.
# The one writable secret is the provider's bounded exception, applied and verified with the rest.

# The updater's artifacts: the WEB identity may READ and EXECUTE the script and the administrator-
# owned library, and may write neither. The script IS the action, so write access to it would be
# write access to what SYSTEM executes. The scheduler gets nothing here at all.
if ($UpdaterInstalled) {
  foreach ($p in @($UpdaterDst, $LibDir, $BinDir)) {
    Grant-OrDie $p ($WebSid + ':(OI)(CI)(RX)') 'run the update path'
  }
  # The task's own DACL, completed now that the SID exists: SYSTEM and Administrators full, the web
  # identity read+execute. It may START the task and may not change its action, arguments, identity,
  # environment or definition - that separation is what makes "the caller passes nothing" true.
  try {
    $webSidValue = (New-Object System.Security.Principal.NTAccount($WebSid)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $sddl = 'D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGX;;;' + $webSidValue + ')'
    $ts = New-Object -ComObject 'Schedule.Service'; $ts.Connect()
    $folder = $ts.GetFolder('\')
    $regTask = $folder.GetTask($UpdaterTask)
    $regTask.SetSecurityDescriptor($sddl, 0)
    Ok ("Update task granted to " + $WebSid + " (run and read; not modify)")
  } catch {
    # The task exists and is currently SYSTEM/Administrators-only, so nothing unsafe is installed -
    # but the in-app update path would be silently dead, and a silently dead privileged boundary is
    # exactly what packet 1246-03 removed. Refuse rather than ship it.
    try { Unregister-ScheduledTask -TaskName $UpdaterTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Die ("Could not grant the web service the right to run the update task; the task has been removed and the install is aborting: " + $_.Exception.Message)
  }
} else {
  Warn "In-app updates are disabled (no updater was installed at phase 13); this installer does not advance an existing source checkout."
}

# Report the EFFECTIVE rights just established, so an administrator (and the live gate) can see them
# rather than infer them from the commands that were issued.
foreach ($proof in @($FixedSecrets, $OutcomeDir) + @('corpus.key','machine.key' | ForEach-Object { Join-Path $FixedSecrets $_ })) {
  if (Test-Path $proof) {
    $acl = Get-Acl $proof
    Info ("  ACL " + $proof + " protected=" + $acl.AreAccessRulesProtected + " [" +
          (($acl.Access | ForEach-Object { $_.IdentityReference.Value + '=' + $_.FileSystemRights }) -join '; ') + "]")
  }
}
# The BinDir grants above are intentionally recursive so services can reach their entry points.
# This credential-bearing launcher is the exception: sever inheritance again after those grants and
# prove that only SYSTEM and Administrators remain before either service starts.
Lock-FileAcl $InstallerEntryPoint
Assert-InstallerBootstrapAcl
Ok "Service ACLs granted (installed secrets protected read-only to the web service)"

# STEP 3 - PROVE the one-service policy, against the state rather than against the calls that were
# issued. The retired scheduler is still registered here, which is what makes "it holds nothing"
# provable rather than merely unresolvable.
Assert-CfmOneServiceAclPolicy $OneServiceAclPolicyPaths

# STEP 4a - only now. Nothing after this line needs the retired identity, and phase 21 starts exactly
# the definitions phase 20 verified, which is the web service alone.
Remove-CfmRetiredSchedulerService

# STEP 4b - UNCONDITIONAL on this invocation's SID. It heals a box interrupted between 4a and here,
# whose next run sees no service and captures no SID but still carries the definition XML.
Remove-CfmRetiredSchedulerArtifacts

# STEP 5 - AUTHORITY RETIREMENT, after every physical postcondition above holds.
Lc-RetireSchedulerAuthority


# === PHASE 21 - Start exactly the definitions phase 20 verified, then readiness =================
# START, on BOTH paths. Phase 9 quiesced every service and nothing has started one since - the
# installer has no pre-phase-21 start path at all. So this phase starts exactly the definitions
# phase 20 installed, read back and registered, and it does so identically whether this run was a
# fresh install or an update. There is deliberately no $IsUpgrade branch here: an earlier design
# left the update path alone "because the layout cutover owns the restart", and every update
# finished with the product stopped.
foreach ($id in $VerifiedServices) {
  $exe = Join-Path $SvcDir ($id + '.exe')
  & $exe start | Out-Null
  for ($i=0; $i -lt 30 -and (Get-Service $id -ErrorAction SilentlyContinue).Status -ne 'Running'; $i++) { Start-Sleep -Seconds 1 }
  if ((Get-Service $id -ErrorAction SilentlyContinue).Status -ne 'Running') {
    Warn ($id + " did not reach Running - last error log:")
    Get-Content (Join-Path $LogDir ($id + '.err.log')) -Tail 20 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ("      " + $_) }
    Die ($id + " failed to start after its definition was verified. Full logs: " + $LogDir)
  }
  Ok ($id + " started (definition verified at phase 20)")
}
Lc-Cleanup

Section "Summary"
Info "Verify"
# POST-START VERIFICATION (parent section 4H item 9; the 1246-04-04 post-closure correction).
#
# **This stage REPORTED and never REFUSED.** Every gate below used to be `Ok`/`Warn`, and
# `$installOk` - derived from the loopback code alone - selected only WHICH completion message was
# printed. So a box whose MCP answered 200 to an unauthenticated request, or whose storage was
# unreachable, still finished with a success line under a green banner. Linux had the same defect
# from the other direction (it lost its whole self-test) and 1246-04-03 corrected it; this is the
# Windows half of the same obligation.
#
# The MECHANISMS are Windows's; the OBLIGATIONS and the CRITICALITY are the parent's, matched to
# Linux fact for fact and NOT by weakening Linux. FMS's own /fmi/ health is observed and warns -
# that is the administrator's layer, not ours - and every other gate is critical.
$CfmSelfTestCrit = 0

# 1. EVERY PHASE-20-VERIFIED SERVICE IS RUNNING. Not a hard-coded pair: exactly the set phase 20
#    read back and registered, so a service added later cannot be silently unverified.
foreach ($id in $VerifiedServices) {
  $svc = Get-Service -Name $id -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -eq 'Running') { Ok ($id + " running") }
  else {
    Warn ($id + " is NOT running - check " + (Join-Path $LogDir ($id + '.wrapper.log')))
    $CfmSelfTestCrit = 1
  }
}

# 2. THE APP ANSWERS ON LOOPBACK. Settle + retry: uvicorn can take a beat past service-Running to
#    bind the socket, so a single probe races startup.
$loop = -1
for ($i=0; $i -lt 6 -and $loop -lt 0; $i++) { Start-Sleep -Seconds 2; $loop = Code "http://127.0.0.1:$WebPort/login" }
if ($loop -ge 200 -and $loop -lt 400) { Ok ("Loopback login responds: HTTP " + $loop) }
else { Warn ("The app did NOT answer on loopback (HTTP " + $loop + ") - check the " + $WebService + " logs in " + $LogDir); $CfmSelfTestCrit = 1 }

# 3. THE PROXIED ROUTE ANSWERS, AND FMS STILL COEXISTS. A proxy edit that works for CORPUSfm and
#    breaks FMS's own :443 is not a successful install - it is an outage we caused.
$prox = Code ("https://127.0.0.1" + $WebPrefix + "/")
if ($prox -ge 200 -and $prox -lt 500) { Ok ("proxied " + $WebPrefix + "/: HTTP " + $prox) }
else { Warn ("The proxied route " + $WebPrefix + "/ did not respond (HTTP " + $prox + ")"); $CfmSelfTestCrit = 1 }
$fms = Code "https://127.0.0.1/fmi/mwpew/wpe/info"
if ($fms -eq 200) { Ok "FMS /fmi/ still healthy: HTTP 200 (coexistence verified)" }
else { Warn ("FMS /fmi/ returned HTTP " + $fms + " (check the FMS web server)") }

# 4. UNAUTHENTICATED MCP IS REFUSED. The folded-in MCP is reachable on a public HTTPS URL, so a 200
#    here is a security regression - and exactly the kind a unit suite cannot see, because it
#    depends on the token, the environment and the proxy all being right on THIS box.
$mcp = CodePost "http://127.0.0.1:$WebPort/mcp/"
if ($mcp -eq 401) { Ok "MCP fail-closed (rejects unauthenticated access: HTTP 401)" }
else { Warn ("MCP did NOT reject unauthenticated access (got HTTP " + $mcp + ", expected 401) - check user authentication before exposing this box."); $CfmSelfTestCrit = 1 }

# 5. STORAGE IS GENUINELY USABLE AND THE SHIPPED DEFAULT SET IS PRESENT. Startup seeds a fresh
#    catalog asynchronously, so one early count is not a completion predicate: direct Windows
#    installs have observed one or two records at this gate before all four appeared. Poll the SAME
#    backend the app uses for at most 60 seconds and require the four exact name/type pairs.
#    Additional user artifacts are allowed; this readback never invokes a second seeder.
$hPy = Join-Path $Dl '_health.py'
@'
import urllib3
# CATEGORY-SCOPED. The loopback OData call runs with verify_ssl=False, so InsecureRequestWarning is
# expected and must not pollute this line's output - but a bare disable_warnings() silences every
# urllib3 warning class, and this snippet is the one place that decides whether storage is usable.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from corpusfm.storage import get_backend
    rows = list(get_backend().iter_artifact_metas())
    present = {(str(m.name), str(m.artifact_type)) for m in rows}
    required = (
        ('CORPUSfm_DB', 'SaveAsXML'),
        ('CORPUSfm_ADDON', 'SaveAsXML'),
        ('CORPUSfm_ADDON', 'AddonXML'),
        ('CORPUSfm_ADDON', 'MergedXML'),
    )
    missing = ['%s/%s' % pair for pair in required if pair not in present]
    print(('MISSING:' + ', '.join(missing)) if missing else 'OK:%d' % len(rows))
except Exception as e:
    print("FAIL:" + type(e).__name__)
'@ | Set-Content -Path $hPy -Encoding ascii
Info "Waiting for the four required default artifacts..."
$h = ''
$lastMissing = ''
for ($seedTry = 0; $seedTry -lt 31; $seedTry++) {
  $h = ("" + (& $Py $hPy 2>$null | Select-Object -Last 1)).Trim()
  if ($h -like 'OK:*') { break }
  if ($h -like 'MISSING:*') {
    $missing = $h.Substring(8)
    if ($missing -ne $lastMissing) {
      Info ("Default artifacts not complete yet - missing: " + $missing)
      $lastMissing = $missing
    }
    if ($seedTry -lt 30) { Start-Sleep -Seconds 2 }
    continue
  }
  break
}
Remove-Item $hPy -ErrorAction SilentlyContinue
if ($h -like 'OK:*') {
  Ok ("Storage reachable; all four required default artifacts installed (" + $h.Substring(3) + " total)")
  $StorageOk = $true
} elseif ($h -like 'MISSING:*') {
  Warn ("Required default artifacts did not complete within 60 seconds - missing: " + $h.Substring(8))
  $CfmSelfTestCrit = 1
} else {
  Warn ("Storage is NOT reachable (" + $h + ") - check the connection in Settings -> Connections.")
  $CfmSelfTestCrit = 1
}

# 6. THE NAMED-USER STATE, CHECKED AFTER THE INSTALL. Phase 19's detection ran before the services
#    existed; this asks the running installation. Three outcomes, not two: a storage outage is
#    UNKNOWN, never a claim that no user exists (packet 1201).
$luPy = Join-Path $Dl '_loginstate.py'
@'
from corpusfm.app.web import users
try:
    print("1" if users.users_exist(raise_on_error=True) else "0")
except Exception:
    print("?")
'@ | Set-Content -Path $luPy -Encoding ascii
$lu = ("" + (& $Py $luPy 2>$null | Select-Object -Last 1)).Trim()
Remove-Item $luPy -ErrorAction SilentlyContinue
if ($lu -eq '1') { Ok "Login user configured" }
elseif ($lu -eq '0') { Warn "No login user yet - create the first admin: corpusfm users create <name> --admin"; $CfmSelfTestCrit = 1 }
else { Warn "Could not verify the login user - storage was unreachable. This does NOT mean there is none." }

# ANY CRITICAL FAILURE REFUSES SUCCESS. `$installOk` is GONE as the authority for whether the
# installation worked: it read one HTTP code and then chose an adjective, so a warning was always
# followed by a completion claim. The banner and Next steps below are unreachable from here on a
# degraded install, which is the whole point.
if ($CfmSelfTestCrit -ne 0) {
  Die "Post-install verification FAILED - the installation is degraded (see above). Fix the reported condition and re-run the installer; refusing to report success."
}
Ok ("Post-install verification passed - CORPUSfm installed (version " + $Version + ")")

# -- PACKET 1398: the completion boundary - the last lifecycle mutation of a fresh install -----------
# Stamps last_result.operation_id = attempt_id through the application, then retires the attempt record
# and its container. Until this succeeds the attempt is incomplete, and a rerun offers
# Inspect / Discard / Quit rather than reporting an installation.
if ($script:CfmAttempt) {
  $laReq = Lc-Request 'attempt-complete' (Lc-Json ([ordered]@{
    schema_version = 1; installation_id = $InstallationId; attempt_id = $script:AttemptId; actor = 'installer' }))
  $laOut = La-Lifecycle @('attempt','complete','--request',$laReq)
  $laResult = "" + (La-Field $laOut @('result'))
  if ($script:LaLifecycleRc -eq 0 -and ($laResult -eq 'completed' -or $laResult -eq 'no_change')) {
    $script:CfmAttempt = $false
    Ok ("Fresh installation complete: attempt " + $script:AttemptId + " stamped and its record retired")
  } else {
    Die ("The installation verified, but its completion could not be stamped (" + (La-Field $laOut @('reason')) +
         ": " + (La-Field $laOut @('detail')) + "). The attempt record is kept; re-run the installer to inspect or discard it.")
  }
}

Section "Next steps"
# SAY THE ADDRESS THE BOX ACTUALLY ASSERTED, not "<your-fms-host>". The app detects and persists its
# own address at startup, so telling the administrator to work out what the machine already knows is
# consequence 1 of the Unknowable-Install Principle violated in our own output.
#
# READ what the app decided; do NOT re-derive it here. A second address-detection implementation in
# the installer could disagree with the one the app advertises as its OAuth audience, and then this
# summary would confidently print an address no client can use. The services are started and probed
# by this point, so the startup assertion has happened.
#
# Falls back to the placeholder when the app asserted nothing - a box with no non-loopback address
# really does not know where it can be reached, and inventing a guess here would be worse.
$Base = ''
$iy = Join-Path $LegacyHome 'install.yaml'
if (Test-Path $iy) {
  $m = Select-String -LiteralPath $iy -Pattern '^\s*public_base_url:\s*(\S.*)$' -ErrorAction SilentlyContinue |
       Select-Object -First 1
  if ($m) { $Base = $m.Matches[0].Groups[1].Value.Trim().Trim('"').Trim("'") }
}
if (-not $Base) { $Base = "https://<your-fms-host>" + $WebPrefix }

Write-Host "  Next steps:"
if ($StorageOk) { Write-Host ("    - Open " + $Base + "/ and log in - storage is live.") }
else { Write-Host ("    - Open " + $Base + "/ -> Settings -> Connections to finish storage (it was not reachable above).") }
Write-Host ("    - Installer: powershell -File '" + $InstallerEntryPoint + "'")
Write-Host "    - Cleanup: You may delete the original extracted installer package and ZIP; the installed launcher is the durable entry point."
Write-Host "    - If a PKI 'did not complete' warning appeared above, register the Admin key via Settings -> FileMaker Server (apply features need it)."
# THE TOKEN IS NEVER PRINTED (developer, 2026-07-29). A line ending in the real bearer token puts a
# working all-gates credential on the console and into terminal scrollback for the life of the
# window. install.sh had already refused to do this, so Windows was the divergence, not the policy.
# The ENDPOINT stays: the Unknowable-Install Principle's consequence 5 requires the exact MCP address
# to exist where no working connection is needed, and installer output is that place.
Write-Host ("    - MCP endpoint: " + $Base + "/mcp/  (connect a client from Library -> MCP; browser sign-in needs no token)")
Write-Host ("    - Service: " + $WebService + " (scheduling runs inside it).   Logs: " + $LogDir)
if ($script:CfmLog) { Write-Host ("    - Install transcript: " + $script:CfmLog + "  (full detail; re-run with -Verbose to watch live)") }
Write-Host ("    - Update later: use the in-app Updates button for code-only changes. When it asks for installer authority, run the Installer command above.")

# Post-update refresh notice - the SAME notice the web first-load banner shows. Idempotent (the
# just-started service runs the flow on boot); never fails the install.
try {
  $updNotice = (& $Py -m corpusfm.server.cli update-notice 2>$null | Out-String).Trim()
  if ($updNotice) { Write-Host ("    - " + $updNotice) }
} catch {}

Section "Farewell"
# Reached ONLY on full success - the phase-21 post-install verification Die()s on any critical
# failure, so arriving here IS the success condition. `$installOk` was the last consumer of a
# variable that no longer decides anything.
Hello "Thank you for installing CORPUSfm."
