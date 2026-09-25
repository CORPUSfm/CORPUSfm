<#
  CORPUSfm Server - Uninstall LAUNCHER (packet 1246-09, stage 6)

  **This script removes nothing.** It elevates, builds one strict privileged request, calls
  `corpusfm-lifecycle uninstall start|resume`, reads exactly one JSON result, and prints it. Every
  decision about what may be deleted - and every deletion - belongs to the lifecycle component,
  which makes them from what this installation RECORDED about itself and re-proves each target
  immediately before acting.

  What this file deliberately does NOT contain, because each of them was a defect here:
    * no deletion planning and no deletion. Not a path, not a service, not an IIS application,
      not a file.
    * no path or default authority. No -InstallRoot, no -ConfigHome, no -Site, no -FmsRoot. Both of
      the first two reached a recursive Remove-Item from free-form argv.
    * no database-name search and no Removed_by_FMS traversal. The retired uninstaller walked
      FileMaker Server's own recovery folder by name and deleted what matched - capable of removing
      an administrator's databases.
    * no -KeepData. It left an installation the installer then refused to reinstall over.
    * no direct FMS, proxy, service, account or file removal, and no fmsadmin call.
    * no persisted credential. A known required FMS credential is validated before confirmation,
      held by this launcher for this one run, framed afresh to each lifecycle call that needs it,
      wiped when the run ends, and never written to the request/log.

  Run from an ELEVATED PowerShell:
      powershell -File uninstall.ps1 [options]

  Options (the complete set; every other option is refused as unknown):
      -Yes        Consent pre-granted: no confirmation prompt, normal output.
      -Force      -Yes, PLUS continue past work that cannot be completed now (the lifecycle
                  component still refuses anything it has no authority for).
      -Silent     -Yes, PLUS decoration suppressed and detail routed to the transcript. NEVER
                  prompts for anything, including a credential.
      -Verbose    Stream detail to the console (it always reaches the transcript).

  FMS administrator credential, when a recorded operation needs one:
      -CredentialStdin (with -Silent) reads ONE credential frame from this launcher's standard
      input: a 4-byte big-endian length and UTF-8 account, then the same for the password. It is
      the only non-interactive route. The values never enter an environment variable, an argument
      list, the request, the transcript or the output. A malformed, truncated, empty or
      over-long frame, or trailing bytes, is refused before anything is removed.
      Without the option: a console run prompts as before, and a -Silent run stops
      incomplete_safe with the credential-dependent work recorded and resumable - it is never
      skipped.

  NOTE: keep this file ASCII-only (Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI).
#>
[CmdletBinding()]
param(
  [switch]$Force,
  [switch]$Yes,
  [switch]$Silent,
  # Reads ONE lifecycle credential frame from this launcher's own stdin - the same wire shape the
  # lifecycle component already consumes. Packet 1236 removed the environment route on purpose: an
  # exported credential is inherited by pip, git and apt-get, which is not "transient" in the sense
  # SPEC 4 promises. A frame on stdin is inherited by nothing, appears in no argv, and is consumed
  # once. -Silent only: a console run prompts, which is the behaviour that route exists for.
  [switch]$CredentialStdin,
  # **THE RETIRED OPTIONS, DECLARED SO THEY CAN BE REFUSED.** PowerShell would otherwise answer an
  # unknown parameter with its own error, and a positional value would bind silently to the first
  # free parameter. Naming them here means an operator who passes -KeepData is TOLD it is gone
  # rather than watching a run succeed on terms it never honoured.
  [string]$InstallRoot = '',
  [string]$ConfigHome = '',
  [string]$Prefix = '',
  [string]$Site = '',
  [string]$FmsRoot = '',
  [string]$FmAdminUser = '',
  [string]$FmAdminPass = '',
  [switch]$KeepData
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot '_cfm_lib.ps1')
if ($Force)  { $script:CfmForce = $true; $script:CfmAssumeYes = $true }
if ($Yes)    { $script:CfmAssumeYes = $true }
if ($Silent) { $script:CfmSilent = $true; $script:CfmAssumeYes = $true }
if ($VerbosePreference -ne 'SilentlyContinue') { $script:CfmVerbose = $true }

Section "Hello"
Hello "CORPUSfm Uninstall"
Info "Asks this installation's lifecycle component to remove exactly what it recorded."

Section "Self-check"
$retired = @()
foreach ($pair in @(@('-InstallRoot', $InstallRoot), @('-ConfigHome', $ConfigHome),
                    @('-Prefix', $Prefix), @('-Site', $Site), @('-FmsRoot', $FmsRoot),
                    @('-FmAdminUser', $FmAdminUser), @('-FmAdminPass', $FmAdminPass))) {
  if ($pair[1]) { $retired += $pair[0] }
}
if ($KeepData) { $retired += '-KeepData' }
# -CredentialStdin is a NON-INTERACTIVE route; pairing it with a run that can prompt would leave two
# credential sources live at once and no rule for which wins. Refused here, before the plan is read.
if ($CredentialStdin -and -not $Silent) {
  Die ("-CredentialStdin requires -Silent.`n" +
       "       A run that can prompt already has a credential route. Nothing has changed.")
}
if ($retired.Count -gt 0) {
  Die ("Unknown option(s): " + ($retired -join ', ') + "`n" +
       "       They are gone. Uninstall removes exactly what this installation recorded as its own,`n" +
       "       and an FMS administrator credential is requested by CORPUSfm itself, only if a`n" +
       "       recorded operation turns out to need one.")
}

# The integrity level, from `whoami /groups`, rather than the .NET principal API - and the
# difference is not style: an in-process API cannot be observed from outside the process, so a
# launcher whose only elevation check was `IsInRole` could be executed in a suite exactly once, on an
# elevated Windows box, which is to say never. The probe is an ordinary command, so the whole
# protocol below can be driven through doubles. S-1-16-12288 is High Mandatory Level: the group an
# elevated token carries and a filtered one does not.
#
# **This is not the security boundary and must never be mistaken for one.** The lifecycle CLI judges
# every request on the OPEN DESCRIPTOR - a protected DACL, owned by the invoking administrator or
# SYSTEM, with nobody else named - so a run that somehow got past here reaches exactly one step
# further and is refused there. It FAILS CLOSED: a probe that cannot be read is not elevation.
$groups = ''
try { $groups = (& whoami /groups 2>&1 | Out-String) } catch { $groups = '' }
if ($LASTEXITCODE -ne 0 -or $groups -notmatch 'S-1-16-12288') {
  Die "This uninstaller must run from an ELEVATED PowerShell (Run as Administrator)."
}

# The transcript is a SIBLING of the installation's log directory, never inside it: the log tree is
# one of the trees the uninstall removes, and a log inside the tree being deleted is not a log.
Cfm-LogInit (Join-Path $env:ProgramData ("CORPUSfm-uninstall-" + (Get-Date).ToString('yyyyMMdd-HHmmss') + ".log"))
if ($script:CfmLog) { Ok ("Uninstall transcript: " + $script:CfmLog) }

# THE PROGRAM TO RUN: the interpreter of the installation this launcher was installed into. The
# installer provisions the launcher directly in the installation directory, so its own directory IS
# that root, for a default or a non-default -InstallDir alike (packet 1397 D1). There is no fallback
# to a default path: a guessed root would aim this uninstall at another installation, or at none.
$CfmRoot = $PSScriptRoot
$Py = Join-Path $CfmRoot 'python\python.exe'
if (-not (Test-Path -LiteralPath $Py -PathType Leaf)) {
  Die ("This launcher runs the CORPUSfm installation it was installed into, and none is beside it:`n" +
       "       " + $Py + " does not exist.`n" +
       "       Run the uninstall.ps1 inside the CORPUSfm installation directory.")
}

Section "Settings"
Warn "This removes CORPUSfm from this machine: its services, its software, its data, and the"
Warn "FileMaker Server registrations it made. Databases and folders it did not create are kept."
# **The storage database is named, not left inside the word "data".** It is the one thing removed
# here that a human would describe as their own - every snapshot, artifact, job and setting this
# installation holds lives in it - and an operator who reads "its data" has not been told that.
Warn "Its data includes the CORPUSfm storage DB this installation created on FileMaker Server:"
Warn "it is closed and removed with everything in it. Copy it first if you want to keep it."

# WHICH INSTALLATION - read from the shipped read-only verb, never from a path this script chose.
# The exit status is deliberately not fatal here: a status that reports an interrupted operation is
# still a status, and the uninstall verb has its own, better refusals for every one of those states.
$statusJson = (& $Py -m corpusfm.lifecycle status --json 2>&1 | Out-String)
Cfm-Logline $statusJson
$InstallationId = ''
try {
  $parsed = $statusJson | ConvertFrom-Json -ErrorAction Stop
  if ($parsed -and $parsed.PSObject.Properties.Name -contains 'installation_id') {
    $InstallationId = "" + $parsed.installation_id
  }
} catch { $InstallationId = '' }
if (-not $InstallationId) {
  Die ("No CORPUSfm installation record was found on this machine.`n" +
       "       ``corpusfm-lifecycle status --json`` reported no installation_id, so there is nothing`n" +
       "       to uninstall and nothing this launcher will guess at.")
}
Info ("Installation: " + $InstallationId)

# The request directory: SYSTEM and Administrators only, and removed when this invocation ends. The
# CLI judges the DACL on the OPEN DESCRIPTOR, so a directory anyone else can write is refused there
# too - the protection here is what makes the request acceptable, not a substitute for that check.
#
# **It now holds the short-lived uninstall RUNTIME as well** (packet 1000-14), which is why it is
# created up front rather than on the first request. One temporary directory, one protection, one
# cleanup: a second one would be a second thing to get wrong and a second thing to leave behind.
$script:LcOriginalLocation = (Get-Location).Path
$LcReqDir = Join-Path $env:TEMP ("corpusfm-uninstall." + $PID)
$SystemSid = '*S-1-5-18'
$AdminsSid = '*S-1-5-32-544'
function Lc-Cleanup {
  # The caller may interrupt after this launcher steps out of the installation. Always leave its
  # shell somewhere deliberate: back where it began when that directory survived, otherwise in the
  # invoking user's profile (the install directory may have been removed successfully).
  if (Test-Path $script:LcReqDir) {
    # OUT OF IT FIRST. This process cannot remove a directory it is standing in, which is the same
    # platform fact the staged runtime exists for - one process further out.
    Set-Location $env:TEMP
    Remove-Item -Recurse -Force $script:LcReqDir -ErrorAction SilentlyContinue
  }
  $returnTo = $script:LcOriginalLocation
  if (-not $returnTo -or -not (Test-Path -LiteralPath $returnTo -PathType Container)) {
    $returnTo = $env:USERPROFILE
  }
  if ($returnTo -and (Test-Path -LiteralPath $returnTo -PathType Container)) {
    Set-Location -LiteralPath $returnTo -ErrorAction SilentlyContinue
    Cfm-Logline ("restored working directory: " + (Get-Location).Path)
  }
}
Register-EngineEvent PowerShell.Exiting -SupportEvent -Action ([scriptblock]::Create(
  "Remove-Item -Recurse -Force '" + ($LcReqDir -replace "'", "''") + "' -ErrorAction SilentlyContinue")) | Out-Null

function Lc-ProtectedDir {
  if (-not (Test-Path $script:LcReqDir)) {
    New-Item -ItemType Directory -Force -Path $script:LcReqDir | Out-Null
    & icacls $script:LcReqDir /inheritance:r /grant:r ($script:SystemSid + ':(OI)(CI)F') ($script:AdminsSid + ':(OI)(CI)F') 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "Could not protect the request directory $script:LcReqDir" }
  }
}

function Lc-Request($transport) {
  Lc-ProtectedDir
  # BUILT AS DATA and serialized - never pasted together as text. **No credential ever appears in
  # it**: the transport is a token saying HOW one would be read, never a value.
  $obj = ([ordered]@{
    schema_version       = 2
    installation_id      = $script:InstallationId
    actor                = $env:USERNAME
    force                = [bool]$script:CfmForce
    credential_transport = $transport
  })
  $f = Join-Path $script:LcReqDir 'uninstall.json'
  [IO.File]::WriteAllText($f, ($obj | ConvertTo-Json -Depth 5 -Compress))
  # A child inherits the right trustees from the protected parent, but the privileged request
  # reader requires the FILE'S DACL itself to be protected. This is the same boundary as every
  # installer lifecycle request: inherited SYSTEM/Administrators is not a protected descriptor.
  & icacls $f /inheritance:r /grant:r ($script:SystemSid + ':F') ($script:AdminsSid + ':F') 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Die ("Could not protect the uninstall request file " + $f) }
  return $f
}

# THE SHORT-LIVED RUNTIME (packet 1000-14). **This is the whole of the Windows difference, and it is
# not an optimisation.** The interpreter found beside this script lives inside the installation, and
# Windows will not unlink a running image or remove a directory a live process is standing in - so an
# uninstall driven from there refuses its own install directory, every time, and the box is left one
# manual deletion short of clean. Linux has neither restriction and stages nothing.
#
# The component copies ITS OWN interpreter and product code - never a path named here - into the
# protected directory this script already created, RUNS the copy to prove it reads nothing from the
# installation, and reports what to run instead. This script keeps no authority it did not have: it
# supplies a destination for a copy, which is not a deletion target and names nothing to remove.
#
# A refusal stops the run BEFORE the first request. Nothing has been touched at that point, and
# beginning an uninstall that is now known to be unable to finish is the one thing worth avoiding.
$script:LcPy = $Py
Lc-ProtectedDir
# THE STAGED LIFETIME: every exit and interruption after this point runs the one exact cleanup.
try {
$runtimeDir = Join-Path $script:LcReqDir 'runtime'
$runtimeOut = (& $Py -m corpusfm.lifecycle uninstall runtime --destination $runtimeDir 2>&1 | Out-String)
Cfm-Logline $runtimeOut
$runtime = $null
try { $runtime = $runtimeOut | ConvertFrom-Json -ErrorAction Stop } catch { $runtime = $null }
if ($null -eq $runtime -or $runtime -isnot [PSCustomObject] -or
    -not ($runtime.PSObject.Properties.Name -contains 'executable') -or -not $runtime.executable) {
  Die ("CORPUSfm could not stage a runtime outside its own installation, so the uninstall would`n" +
       "       stop at the install directory and leave it behind. Nothing has been changed.`n" +
       "       " + ($runtimeOut.Trim()))
}
$script:LcPy = $runtime.executable
Ok ("Running the uninstall from " + $script:LcPy)

# OUT OF THE INSTALLATION, for THIS process. The component steps its own working directory out of a
# tree it is about to remove, and it cannot do that for the shell that launched it - a launcher left
# standing inside the install directory blocks the very removal it asked for.
Set-Location $env:TEMP

# EXACTLY ONE JSON OBJECT, or this run stops. A second document, an array, a scalar or a truncated
# write is not a result, and reading it field-by-field is how a partial write becomes a false answer.
$script:LcOut = ''; $script:LcRc = 0
$script:LcResult = ''; $script:LcReason = ''; $script:LcDetail = ''
function Lc-Invoke($verb, $transport) {
  $request = Lc-Request $transport
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $script:LcOut = (& $script:LcPy -m corpusfm.lifecycle uninstall $verb --request $request 2>$errFile | Out-String)
    $script:LcRc = $LASTEXITCODE
  } finally {
    if (Test-Path $errFile) {
      Cfm-Logline (Get-Content $errFile -Raw); Remove-Item -Force $errFile -ErrorAction SilentlyContinue
    }
    Remove-Item -Force $request -ErrorAction SilentlyContinue
  }
  Cfm-Logline $script:LcOut
  $value = $null
  try { $value = $script:LcOut | ConvertFrom-Json -ErrorAction Stop } catch { $value = $null }
  # ONE OBJECT, and one that is actually a result. `ConvertFrom-Json` answers an ARRAY for two
  # concatenated documents and for a JSON array, and a bare STRING or NUMBER for a scalar - and a
  # string has PSObject properties of its own, so "does it have properties" reads a scalar as an
  # object. The result contract always carries `result`, so that is what is required.
  if ($null -eq $value -or $value -is [array] -or $value -isnot [PSCustomObject] -or
      -not ($value.PSObject.Properties.Name -contains 'result')) {
    Die ("The uninstall did not return one readable JSON result (exit " + $script:LcRc + ").`n" +
         "       Nothing further was attempted. See " + $script:CfmLog + ".")
  }
  $script:LcResult = "" + $value.result
  $script:LcReason = "" + $value.reason
  $script:LcDetail = "" + $value.detail
}

function Encode-UninstallArg([string]$value) {
  if ($value -eq '') { return '""' }
  if ($value -notmatch '[ \t"]') { return $value }
  $sb = New-Object Text.StringBuilder
  [void]$sb.Append('"'); $slashes = 0
  foreach ($ch in $value.ToCharArray()) {
    if ($ch -eq '\') { $slashes++; continue }
    if ($ch -eq '"') {
      [void]$sb.Append('\' * ($slashes * 2 + 1)); [void]$sb.Append('"'); $slashes = 0
      continue
    }
    if ($slashes) { [void]$sb.Append('\' * $slashes); $slashes = 0 }
    [void]$sb.Append($ch)
  }
  if ($slashes) { [void]$sb.Append('\' * ($slashes * 2)) }
  [void]$sb.Append('"')
  return $sb.ToString()
}

function Lc-InvokeFramed($verb, $account, $password) {
  $request = Lc-Request 'stdin'
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:LcPy
  $psi.Arguments = (@('-m','corpusfm.lifecycle','uninstall',$verb,'--request',$request) |
                    ForEach-Object { Encode-UninstallArg $_ }) -join ' '
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $bytes = $null; $proc = [System.Diagnostics.Process]::Start($psi)
  try {
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $stream = $proc.StandardInput.BaseStream
    foreach ($value in @($account, $password)) {
      $bytes = [Text.Encoding]::UTF8.GetBytes([string]$value)
      $len = [BitConverter]::GetBytes([int]$bytes.Length)
      if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }
      $stream.Write($len, 0, 4)
      if ($bytes.Length) { $stream.Write($bytes, 0, $bytes.Length) }
      [Array]::Clear($bytes, 0, $bytes.Length)
    }
    $stream.Flush(); $proc.StandardInput.Close(); $proc.WaitForExit()
    $script:LcOut = $outTask.Result
    $script:LcRc = $proc.ExitCode
    Cfm-Logline ($script:LcOut + $errTask.Result)
  } finally {
    if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    Remove-Item -Force $request -ErrorAction SilentlyContinue
  }
  $parsed = $null
  try { $parsed = $script:LcOut | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }
  if ($null -eq $parsed -or $parsed -is [array] -or $parsed -isnot [PSCustomObject] -or
      -not ($parsed.PSObject.Properties.Name -contains 'result')) {
    Die ("The uninstall did not return one readable JSON result (exit " + $script:LcRc + ").")
  }
  $script:LcResult = "" + $parsed.result
  $script:LcReason = "" + $parsed.reason
  $script:LcDetail = "" + $parsed.detail
}

function Lc-ReadFmsCredential($plan) {
  Info "FileMaker Server administrator credentials are required by this removal plan."
  Info "They are used for this run only and are never written down."
  $script:LcCredentialUser = Read-Host "  FM Server admin account username [admin]"
  if (-not $script:LcCredentialUser) { $script:LcCredentialUser = 'admin' }
  do { $sec = Read-Host "  FM Server admin account password" -AsSecureString } while ($sec.Length -eq 0)
  $script:LcCredentialPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
  $fmsadmin = "" + $plan.locations.fmsadmin
  if (-not $fmsadmin -or -not (Test-Path $fmsadmin)) {
    $script:LcCredentialPass = ''
    Die ("The recorded fmsadmin executable is unavailable at " + $fmsadmin + ". Nothing has changed.")
  }
  Info "Verifying FM Server credentials..."
  & $fmsadmin -u $script:LcCredentialUser -p $script:LcCredentialPass list files *> $null
  if ($LASTEXITCODE -ne 0) {
    $script:LcCredentialPass = ''; Die "FM Server admin login failed. Nothing has changed."
  }
  Ok ("FileMaker Server administrator '" + $script:LcCredentialUser + "' authenticated.")
}

# ONE FRAME, READ ONCE, FROM THIS LAUNCHER'S OWN STDIN.
#
#   [4-byte big-endian length][UTF-8 account][4-byte big-endian length][UTF-8 password]
#
# Every refusal below happens BEFORE the plan is acted on, and each one clears whatever it had read.
# The frame is read only when the read-only plan says a credential is required, so an invocation
# that does not need one never consumes the caller's stdin at all.
function Lc-ReadFramedCredential($plan) {
  $MaxField = 4096                      # far above any real account or password; bounds a hostile length
  $stdin = [Console]::OpenStandardInput()
  $account = $null; $password = $null
  try {
    $fields = @()
    foreach ($which in @('account', 'password')) {
      $lenBuf = New-Object byte[] 4
      $got = 0
      while ($got -lt 4) {
        $n = $stdin.Read($lenBuf, $got, 4 - $got)
        if ($n -le 0) { Die ("The credential frame ended before its $which length. Nothing has changed.") }
        $got += $n
      }
      $be = $lenBuf.Clone()
      if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($be) }
      $len = [BitConverter]::ToInt32($be, 0)
      if ($len -le 0) { Die ("The credential frame declares an empty $which. Nothing has changed.") }
      if ($len -gt $MaxField) {
        Die ("The credential frame declares an implausible $which length ($len). Nothing has changed.")
      }
      $buf = New-Object byte[] $len
      $got = 0
      while ($got -lt $len) {
        $n = $stdin.Read($buf, $got, $len - $got)
        if ($n -le 0) { Die ("The credential frame is truncated in its $which. Nothing has changed.") }
        $got += $n
      }
      # STRICT UTF-8. A replacement character would silently turn a wrong byte string into a
      # plausible-looking credential, and the operator would see an authentication failure instead
      # of the framing error that actually happened.
      $strict = New-Object Text.UTF8Encoding($false, $true)
      try { $fields += $strict.GetString($buf) }
      catch { [Array]::Clear($buf, 0, $buf.Length)
              Die ("The credential frame's $which is not valid UTF-8. Nothing has changed.") }
      [Array]::Clear($buf, 0, $buf.Length)
    }
    # EXACTLY TWO FIELDS. Trailing bytes mean the caller framed something this launcher does not
    # understand; consuming two and ignoring the rest would accept a frame nobody agreed on.
    $extra = New-Object byte[] 1
    if ($stdin.Read($extra, 0, 1) -gt 0) {
      Die ("The credential frame carries trailing bytes after the password. Nothing has changed.")
    }
    $account = $fields[0]; $password = $fields[1]
    if (-not $account -or -not $password) {
      Die ("The credential frame carries an empty field. Nothing has changed.")
    }
  } finally { $stdin.Dispose() }

  $script:LcCredentialUser = $account
  $script:LcCredentialPass = $password
  $account = $null; $password = $null
  Info "Read one FMS administrator credential frame from standard input."
  Info "It is used for this run only and is never written down."
  $fmsadmin = "" + $plan.locations.fmsadmin
  if (-not $fmsadmin -or -not (Test-Path $fmsadmin)) {
    $script:LcCredentialPass = ''; $script:LcCredentialUser = ''
    Die ("The recorded fmsadmin executable is unavailable at " + $fmsadmin + ". Nothing has changed.")
  }
  Info "Verifying FM Server credentials..."
  # PRE-EXISTING, OWNED FINDING: this validation places the password in the FMSADMIN child's argv.
  # The interactive path has always done so; it is unchanged here on purpose, and recorded rather
  # than newly accepted. Closing it is a separate correction that touches both credential routes.
  & $fmsadmin -u $script:LcCredentialUser -p $script:LcCredentialPass list files *> $null
  if ($LASTEXITCODE -ne 0) {
    $script:LcCredentialPass = ''; $script:LcCredentialUser = ''
    Die "FM Server admin login failed. Nothing has changed."
  }
  Ok ("FileMaker Server administrator '" + $script:LcCredentialUser + "' authenticated.")
}

# THE SIX RESULT WORDS AND THEIR CODES - the shipped contract, restated nowhere else. 4 means the
# REQUEST was refused, which is this launcher's defect and never the box's.
function Lc-Report {
  switch ($script:LcRc) {
    0 { Ok ("Uninstall " + $script:LcResult + ": " + $script:LcDetail) }
    1 { Warn ("Uninstall refused before changing anything (" + $script:LcResult + ").")
        Warn ("  reason: " + $script:LcReason); Warn ("  " + $script:LcDetail) }
    2 { Warn ("Uninstall was rolled back; this machine is unchanged (" + $script:LcResult + ").")
        Warn ("  " + $script:LcDetail) }
    3 { Warn ("Uninstall needs an administrator action (" + $script:LcResult + ").")
        Warn ("  reason: " + $script:LcReason); Warn ("  " + $script:LcDetail) }
    4 { Warn "This launcher built a request this build does not accept - a launcher defect."
        Warn ("  " + $script:LcDetail) }
    5 { Warn ("Uninstall stopped safely part-way (" + $script:LcResult + "). Re-run to continue.")
        Warn ("  reason: " + $script:LcReason); Warn ("  " + $script:LcDetail) }
    default { Warn ("Uninstall returned an unrecognised exit status " + $script:LcRc + ".") }
  }
  if (Cfm-IsVerbose) { Write-Host $script:LcOut }
}

# The same read-only lifecycle projection used on Linux. It owns the plan; PowerShell only renders
# the returned typed operations and acquires a credential when the plan says one is already known.
Section "Plan"
Lc-Invoke 'plan' 'none'
if ($script:LcRc -ne 0) {
  Warn "CORPUSfm could not derive a removal plan without changing the machine."
  Lc-Report
  Lc-Cleanup
  exit $script:LcRc
}
$plan = $null
try { $plan = $script:LcOut | ConvertFrom-Json -ErrorAction Stop } catch { $plan = $null }
if ($null -eq $plan -or -not ($plan.PSObject.Properties.Name -contains 'mode')) {
  Die "The read-only uninstall plan was not a readable plan object. Nothing has been changed."
}
Info ("Installation: " + $plan.installation_id)
Info ("Mode: " + $(if ($plan.mode -eq 'resume') { 'resume the recorded uninstall' } else { 'start a new uninstall' }))
Info ("FileMaker Server: " + $plan.fms_state)
if ($plan.locations) {
  foreach ($name in @('fms_root','install_dir','patch_hosting_dir')) {
    if ($plan.locations.$name) { Info ("  " + ($name -replace '_',' ') + ': ' + $plan.locations.$name) }
  }
}
Info "Planned operations:"
foreach ($op in @($plan.operations)) {
  $target = $op.path
  if (-not $target) { $target = $op.database_path }
  if (-not $target) { $target = $op.registration_name }
  if (-not $target) { $target = $op.hosting_dir }
  if (-not $target) { $target = $op.name }
  if (-not $target) { $target = $op.account }
  if (-not $target) { $target = 'recorded resource' }
  Info ("  - " + $op.resource + ': ' + $target)
}
foreach ($item in @($plan.retained)) {
  Info ("  - retain " + $item.resource + ': ' + $item.because)
}
if (@($plan.fms_admin_login_reasons).Count) {
  Info "FMS administrator credential:"
  foreach ($reason in @($plan.fms_admin_login_reasons)) { Info ("  - " + $reason) }
}

# ONE VALIDATED CREDENTIAL SUPPLIES ONE APPROVED RUN (packet 1380-04 ruling, narrowing 1236). Once
# validated it is held in THIS process only and reused for every start or resume that answers
# credential_required; each lifecycle child still receives its own freshly framed copy on stdin. The
# lifecycle asks per operation - a live Linux run asked for start and again for the PKI read-back -
# so a credential spent on the first call would strand the second. Wiped in the outer finally.
$startTransport = 'none'; $script:LcCredentialUser = ''; $script:LcCredentialPass = ''
$script:CredentialFrameRead = $false
if ($plan.mode -eq 'start' -and $plan.fms_admin_login_required) {
  # UserInteractive is false in a real interactive OpenSSH console on Windows Server. The stream is
  # the relevant fact: Read-Host works there when console input is not redirected.
  if ($CredentialStdin) {
    Lc-ReadFramedCredential $plan
    $script:CredentialFrameRead = $true
    $startTransport = 'stdin'
  } elseif ($script:CfmSilent -or [Console]::IsInputRedirected) {
    Warn "The plan needs an FMS administrator credential, but this invocation cannot prompt."
    Warn "Pass -CredentialStdin with -Silent and write one credential frame to this launcher's"
    Warn "standard input to supply one without a console."
    Warn "Independent safe removal may proceed; FMS-dependent work will remain resumable."
  } else {
    Lc-ReadFmsCredential $plan
    $startTransport = 'stdin'
  }
}

if ($plan.mode -eq 'start') {
  Section "Confirm"
  Cfm-Confirm "Continue with this plan?"
  Write-Host ""
} else {
  Info "This removal was already approved and recorded; confirmation is not repeated."
}

Section "Progress"
Info "Starting the uninstall..."
if ($startTransport -eq 'stdin') { Lc-InvokeFramed 'start' $script:LcCredentialUser $script:LcCredentialPass }
else { Lc-Invoke 'start' 'none' }

# **A pending record means this is a resume, not a fresh start** - and the component says so by name
# rather than this script inspecting any state of its own.
if ($script:LcReason -eq 'pending_record_exists__resume_it_rather_than_starting_again') {
  Info "An interrupted uninstall is already recorded - continuing it."
  Lc-Invoke 'resume' 'none'
}

# Continue while the next recorded operation requires a credential. A held credential is reused; the
# frame is read at most once per run; a silent run with nothing held stops resumable, as before.
$continuations = 0
while ($script:LcReason -eq 'credential_required') {
  if (-not ($script:LcCredentialUser -and $script:LcCredentialPass)) {
    if ($CredentialStdin -and -not $script:CredentialFrameRead) {
      Info "A later operation now requires an FMS administrator credential."
      Lc-ReadFramedCredential $plan
      $script:CredentialFrameRead = $true
    } elseif ($script:CfmSilent) {
      Warn "An FMS administrator credential is required to finish, and -Silent never prompts."
      Warn "Pass -CredentialStdin with -Silent and write one credential frame to standard input,"
      Warn "or re-run without -Silent. Nothing is lost: the uninstall is recorded and resumes"
      Warn "where it stopped."
      break
    } else {
      Info "A later operation now requires an FMS administrator credential."
      Lc-ReadFmsCredential $plan
    }
  }
  # A lifecycle that keeps asking with a validated credential in hand is not making progress; stop
  # resumable rather than resubmit it without end.
  if (++$continuations -gt 8) {
    Warn "The uninstall still requires a credential after 8 continuations; stopping. It is recorded"
    Warn "and resumes where it stopped."
    break
  }
  Lc-InvokeFramed 'resume' $script:LcCredentialUser $script:LcCredentialPass
}
$script:LcCredentialPass = ''; $script:LcCredentialUser = ''

Section "Summary"
Lc-Report

Section "Farewell"
if ($script:LcRc -eq 0) {
  Ok "CORPUSfm removed."
  Write-Host "Goodbye!"
}
} finally {
  $script:LcCredentialPass = ''; $script:LcCredentialUser = ''
  Lc-Cleanup
}
exit $script:LcRc
