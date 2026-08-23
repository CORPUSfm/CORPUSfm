# corpusfm-update.ps1  -  the fixed, administrator-owned, one-shot code update (packet 1246-03, E4).
#
# Windows counterpart of installer/linux/corpusfm-update.sh. It is invoked by a fixed scheduled task
# that the service SID may RUN but not MODIFY (the task's ACL grants the SID read+execute and
# withholds write), so the service can trigger this operation and can change nothing about it  -
# not the script, not the arguments, not the environment.
#
# It takes NO parameters. Everything it needs comes from fixed paths under ProgramData; the one value
# the administrator supplies, `expected_head`, arrives in the request file and can only cause a
# refusal. This script resolves origin/main itself and never checks out the supplied value.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# -- SILENCE IS STRUCTURAL, FOR THE WHOLE OPERATIONAL BODY ---------------------------------------
#
# The boundary begins before path construction or service-list construction. Join-Path and array
# expressions are executable PowerShell too; putting them above this block made the earlier claim
# that the whole operational body was enclosed false.
& {

# FIXED LOCATIONS, rendered into this artifact by the installer. No environment override: this
# script runs elevated and rewrites the code the box executes, so anything that could set
# CFM_SRC_DIR could choose the tree it advances. Tests render their own copy - a seam, not an input.
$InstallDir = '@@INSTALL_DIR@@'
$StateDir   = '@@STATE_DIR@@'
$LogDir     = '@@LOG_DIR@@'
# TWO AUTHORITIES, TWO DIRECTORIES (ruling 2026-08-03). The inbox is service-writable; the outcome
# directory is SYSTEM-owned and merely readable by the services, so a service cannot forge a result
# naming its own trigger id. These must be the SAME paths update_boundary defines - they were not,
# and the boundary was decorative on Windows as a result.
$InboxDir    = Join-Path $StateDir 'update-inbox'
$OutcomeDir  = Join-Path $StateDir 'update-outcome'
$RequestFile = Join-Path $InboxDir 'update_request.json'
$LogFile     = Join-Path $LogDir 'update.log'
$Src = '@@SRC_DIR@@'
$Py  = '@@VENV_PY@@'
# The tree inspector as an ADMINISTRATOR-OWNED FILE outside the checkout (R7b). This used to be
# `$env:PYTHONPATH = $Src; & $Py -m corpusfm.lifecycle.tree_inspection` - loading the judge from the
# tree being judged, so a modified helper inside a modified checkout declared it clean. Proven on
# BOTH platforms deliberately: a provenance property established on one says nothing about the other.
$Helper = '@@HELPER@@'
# The outcome publisher, same location and same reason (N2). This script COLLECTS fields; that
# boundary validates them against the record schema and the structural secret fence and performs the
# atomic write. Nothing here composes an outcome document any more.
$Publisher = '@@PUBLISHER@@'
# The administrator-owned Python library the publisher and the classifier load from - deliberately
# not $Src, because both are judgments about the checkout.
$LibDir = '@@LIB_DIR@@'
# An ABSOLUTE git, rendered rather than composed, so it is the installation's own record that says
# which binary runs.
$Git = '@@GIT@@'
# The scheduler is restarted and verified here. The web process waiting for the root-owned outcome
# schedules its own supervised restart after the success response flushes.
$Services = @('corpusfm-scheduler')
$Cleaner = Join-Path $InstallDir 'bin\bytecode_cleanup.py'

# -- WHY THE SILENCE BOUNDARY ENCLOSES THIS WHOLE BODY -------------------------------------------
#
# Everything below runs inside ONE script block whose every PowerShell stream - success, error,
# warning, verbose, debug, information - is redirected to $null, and native child output inherits
# that too. No command, cmdlet or error path in the body can put a byte on a stream this script does
# not control, whether or not any test names it.
#
# The Linux artifact does the same thing with `exec 1>/dev/null 2>/dev/null`. Both replace three
# rounds of redirecting invocations one at a time and then enumerating them: each round the claim
# was refuted by an invocation nobody had listed, because a list of commands is wrong the moment
# somebody adds one.
#
# ADMINISTRATOR-VISIBLE INFORMATION HAS TWO HOMES, BOTH VALIDATED: the outcome record, written by
# the installed publisher through UpdateOutcome plus the structural secret fence, and Write-Log,
# which appends fixed sentences and validated values to the log FILE. Neither is a process stream.
#
# Invoke-Fixed still builds each child's environment from empty and still captures its output; this
# boundary is what catches everything that is not a child of Invoke-Fixed.

# -- CHILD ENVIRONMENTS ARE BUILT FROM EMPTY (F1) -------------------------------------------------
#
# The previous version removed a list of variables from THIS process and pinned a few more, then let
# every child inherit what was left. That is a denylist, and the ones it did not name were the point:
# PSModulePath loads modules into a child PowerShell, PYTHONUSERBASE relocates site-packages,
# APPDATA/LOCALAPPDATA lead back to a user profile, and the proxy variables steer git's network
# calls. Enumerating them is the list that is wrong the moment it is written - the same finding the
# Linux artifact was corrected on, one platform over.
#
# So no child inherits anything. Every process this script starts goes through ONE launch boundary
# with an environment constructed from nothing, an absolute executable and an argument ARRAY - never
# a command line something downstream re-parses.
# THE SYSTEM DIRECTORY COMES FROM THE OPERATING SYSTEM, NOT FROM A VARIABLE.
#
# The first version of this block read `$env:SystemRoot` with a `C:\Windows` fallback, which put the
# location of system32 - and therefore the child's DLL search path - under the control of whoever
# could set one environment variable on this elevated process. Reading it and then handing it to a
# child is not a smaller version of the denylist; it is the denylist with one entry.
#
# `[Environment]::SystemDirectory` is the GetSystemDirectory Win32 API, not an environment lookup.
# It is validated as absolute and present, and there is NO fallback: an operating system that cannot
# say where its own system directory is has not given us enough to build a child environment from.
$SystemDirectory = [System.Environment]::SystemDirectory
if ([string]::IsNullOrWhiteSpace($SystemDirectory) -or
    -not [System.IO.Path]::IsPathRooted($SystemDirectory) -or
    -not (Test-Path -LiteralPath $SystemDirectory -PathType Container)) {
    Write-Error "corpusfm-update: the operating system did not report a usable system directory; refusing to build a child environment from an environment variable"
    exit 1
}
$SystemRoot = Split-Path -Parent $SystemDirectory
$ChildTemp  = Join-Path $LogDir 'tmp'

function New-ChildEnvironment {
    param([ValidateSet('git', 'python')][string]$Kind, [hashtable]$Extra = @{})
    # Only what the executable genuinely needs. SystemRoot/windir are required by the Windows loader
    # and by anything that opens a system DLL; TEMP/TMP point at a directory this installation owns
    # rather than a user profile's.
    # Every value here is either OS-derived (above) or a fixed literal. None is read from the
    # environment this process was handed.
    $e = @{
        'PATH'       = ($SystemDirectory + [System.IO.Path]::PathSeparator + $SystemRoot)
        'SystemRoot' = $SystemRoot
        'windir'     = $SystemRoot
        'TEMP'       = $ChildTemp
        'TMP'        = $ChildTemp
        'LC_ALL'     = 'C'
        'LANG'       = 'C'
    }
    if ($Kind -eq 'git') {
        # HOME, USERPROFILE and XDG_CONFIG_HOME each lead to a user gitconfig by a different route,
        # so all three are pointed at the installation rather than left absent - git invents a HOME
        # on Windows when it finds none.
        $e['HOME'] = $InstallDir
        $e['USERPROFILE'] = $InstallDir
        $e['XDG_CONFIG_HOME'] = (Join-Path $InstallDir '.no-config')
        $e['GIT_TERMINAL_PROMPT'] = '0'
        $e['GIT_CONFIG_NOSYSTEM'] = '1'
        $e['GIT_CONFIG_GLOBAL'] = 'NUL'
        $e['GIT_CONFIG_SYSTEM'] = 'NUL'
    }
    foreach ($k in $Extra.Keys) { $e[$k] = $Extra[$k] }
    return $e
}

# Windows PowerShell 5.1 runs on .NET Framework and has no ProcessStartInfo.ArgumentList.  The
# installer already crosses the same boundary with these CommandLineToArgvW/CreateProcess rules.
# Keep this copy byte-equivalent (guarded) because the updater is a standalone SYSTEM artifact and
# cannot source a mutable helper beside the checkout it is judging.
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
    if ($slashes -gt 0) { [void]$sb.Append('\' * ($slashes * 2)) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Encode-WindowsCommandLine([string[]]$argv) {
    return (($argv | ForEach-Object { Encode-WindowsArgv $_ }) -join ' ')
}

function Invoke-Fixed {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory)][hashtable]$Environment,
        [string]$StdIn = ''
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # Stdin is redirected ALWAYS and closed immediately below, whether or not there is input. A
    # `[string]` parameter coerces $null to '', so a conditional here would have read as optional
    # while being unconditional - and closing stdin is the behaviour we want regardless: no child
    # of this script may inherit and block on the elevated process's own input.
    $psi.RedirectStandardInput = $true
    # Every value begins as an argv element and is encoded exactly once at this one launch boundary.
    # `.ArgumentList` would be preferable but does not exist on the shipped Windows PowerShell 5.1
    # host; a per-call string or Start-Process -ArgumentList would silently reintroduce the quoting
    # defect this boundary removed.
    $psi.Arguments = Encode-WindowsCommandLine $Arguments
    $psi.EnvironmentVariables.Clear()
    foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[[string]$k] = [string]$Environment[$k] }

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $p.StandardInput.Write($StdIn)
    $p.StandardInput.Close()
    # Read both pipes concurrently: a child that fills one while we block on the other deadlocks,
    # and `git fetch` is perfectly capable of filling stderr.
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        StdOut   = $outTask.Result
        StdErr   = $errTask.Result
    }
}

$GitEnv = New-ChildEnvironment -Kind git
$PyEnv  = New-ChildEnvironment -Kind python
# Every git invocation disables accumulated credential helpers. Public acquisition is anonymous;
# no replacement store or token is installed.
$GitCommon = @(
    '-c', 'safe.directory=*',
    '-c', 'credential.helper='
)

function Invoke-Git {
    param([string[]]$Arguments)
    return Invoke-Fixed -FilePath $Git -Arguments ($GitCommon + $Arguments) -Environment $GitEnv
}

if (-not (Test-Path $Git))       { Write-Error "corpusfm-update: $Git is missing"; exit 1 }
if (-not (Test-Path $Helper))    { Write-Error "corpusfm-update: $Helper is missing"; exit 1 }
if (-not (Test-Path $Publisher)) { Write-Error "corpusfm-update: $Publisher is missing"; exit 1 }

New-Item -ItemType Directory -Force -Path $InboxDir, $OutcomeDir, $LogDir, $ChildTemp | Out-Null

$script:OpId = (Get-Date -Format 'yyyyMMddHHmmss') + '-' + $PID
$script:Started = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$script:TriggerId = ''
$script:Requested = ''
$script:Observed = ''
$script:ResultHead = ''

function Write-Log($msg) {
    Add-Content -Path $LogFile -Value ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') + ' ' + $msg)
}

# Root writes it; the service reads it. Carries SHAs, states and the log LOCATION  -  never a secret.
# THIS FUNCTION WRITES NOTHING: it hands named fields to the installed publisher, which validates
# them against UpdateOutcome and the structural secret fence and performs the atomic write. A
# refusal there leaves NO outcome, which the service reads as "no result" - correct, and better
# than a record we could not vouch for.
function Write-Outcome($state, $reason, $detail, $rolledBack) {
    $rb = if ($rolledBack) { 'true' } else { 'false' }
    $fields = @(
        $StateDir,
        ("operation_id=" + $script:OpId),
        ("trigger_id=" + $script:TriggerId),
        ("state=" + $state),
        ("requested_head=" + $script:Requested),
        ("observed_head=" + $script:Observed),
        ("resulting_head=" + $script:ResultHead),
        ("started_utc=" + $script:Started),
        ("ended_utc=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
        ("reason_code=" + $reason),
        ("detail=" + $detail),
        ("log_path=" + $LogFile),
        ("rolled_back=" + $rb)
    )
    $r = Invoke-Fixed -FilePath $Py -Arguments (@('-I', $Publisher) + $fields) -Environment $PyEnv
    # Exit status only. The publisher redacts its own message, but it is still child output and
    # "prefer not retaining it" applies to the trusted component too.
    if ($r.ExitCode -ne 0) { Write-Log ("NO OUTCOME PUBLISHED (publisher exit " + $r.ExitCode + ")") }
}

# THE REASON CODE ONLY. `$detail` is built from real filesystem pathnames out of the checkout, and a
# pathname is attacker-supplied content: a planted file called `CORPUSFM_MCP_TOKEN=<hex>.py` puts a
# credential-shaped string into it. The publisher refuses to write such a record - but this line ran
# BEFORE the publisher and wrote the raw value to update.log, so the fence held and the log leaked.
# Linux never had it: its `die()` logs `$2`, the code, and always did. A fence proven on one platform
# says nothing about the other.
#
# The complete record goes to ONE place: the trusted publisher, which validates it and either writes
# it or writes nothing.
function Stop-With($state, $reason, $detail, $rolledBack = $false) {
    Write-Log ("REFUSED/FAILED: " + $reason)
    Write-Outcome $state $reason $detail $rolledBack
    exit 1
}

# -- the request ---------------------------------------------------------------------------------
if (-not (Test-Path $RequestFile)) { Stop-With 'refused' 'no_request' 'no update request was recorded' }
# THE REQUEST IS SERVICE-WRITABLE, so parsing it is handling untrusted input. With
# $ErrorActionPreference = 'Stop' a malformed document raises a TERMINATING error whose message
# quotes the offending content to the console - the service choosing what appears in the journal.
# Caught, and answered with a fixed reason code.
try {
    $request = Get-Content $RequestFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Stop-With 'refused' 'bad_request' 'the update request could not be read'
}
$script:TriggerId = [string]$request.trigger_id
$script:Requested = [string]$request.expected_head
if ($script:TriggerId -notmatch '^[A-Za-z0-9_-]{1,64}$') { Stop-With 'refused' 'bad_trigger_id' 'the trigger id is not a plain identifier' }
if ($script:Requested -notmatch '^[0-9a-f]{40,64}$')     { Stop-With 'refused' 'bad_expected_head' 'expected_head is not a full commit SHA' }

Write-Log ("operation " + $script:OpId + " for trigger " + $script:TriggerId)

# -- preconditions, all evaluated on what THIS script resolves ------------------------------------
if (-not (Test-Path (Join-Path $Src '.git'))) { Stop-With 'failed' 'not_git_deployment' "$Src is not a git checkout" }

# Retire only structurally ordinary generated bytecode before the whole-tree judgment. The fixed,
# administrator-owned cleaner refuses links, reparse points, nested directories and non-.pyc files.
$clean = Invoke-Fixed -FilePath $Py -Arguments @('-I', $Cleaner, $Src) -Environment (New-ChildEnvironment -Kind python)
if ($clean.ExitCode -ne 0) {
    Stop-With 'refused' 'unclean_tree' 'runtime bytecode residue could not be safely retired'
}

# CANONICAL comparison, never a substring: a lookalike host is a different server entirely.
$originResult = Invoke-Git @('-C', $Src, 'remote', 'get-url', 'origin')
$canon = ([string]$originResult.StdOut).Trim() -replace '\.git$','' -replace '/$',''
$canon = $canon -replace '^git@github\.com:','' -replace '^https://github\.com/','' -replace '^ssh://git@github\.com/',''
if ($canon -ne 'CORPUSfm/CORPUSfm') {
    Stop-With 'refused' 'origin_mismatch' 'the checkout origin is not the expected CORPUSfm repository'
}

# THE WHOLE TREE, through the same bounded Python helper as Linux - one implementation of "what may
# be in a deployed checkout", not two that drift. It includes ignored files, allows only exact
# installer artifacts, and returns JSON so no pathname is ever parsed here.
# STDOUT ONLY. The helper's stdout is a bounded JSON document; its stderr is raw child output and is
# discarded rather than folded into the thing we parse (N2). The parsed problems are the ONE piece of
# child-derived text retained, and they go to exactly one place: the trusted publisher, which fences
# the whole record before writing it.
$tree = Invoke-Fixed -FilePath $Py -Arguments @($Helper, $Src) -Environment $PyEnv
if ($tree.ExitCode -ne 0) {
    $detail = 'the deployed checkout could not be inspected'
    try { $detail = (($tree.StdOut | ConvertFrom-Json).problems -join '; ') } catch {}
    Stop-With 'refused' 'unclean_tree' $detail
}

$fetch = Invoke-Git @('-C', $Src, 'fetch', '--quiet', 'origin', 'main')
if ($fetch.ExitCode -ne 0) { Stop-With 'failed' 'fetch_failed' 'could not fetch origin/main' }

# CAPTURED IS NOT VALIDATED (the Linux side gained the same check). These two decide what gets
# merged and what the outcome says landed; a value that is not a commit id means the child did
# something other than what was asked.
$oldHead = (Invoke-Git @('-C', $Src, 'rev-parse', 'HEAD')).StdOut.Trim()
$script:Observed = (Invoke-Git @('-C', $Src, 'rev-parse', 'origin/main')).StdOut.Trim()
if ($oldHead -notmatch '^[0-9a-f]{40,64}$')         { Stop-With 'failed' 'head_unreadable' 'the deployed head could not be read as a commit' }
if ($script:Observed -notmatch '^[0-9a-f]{40,64}$') { Stop-With 'failed' 'head_unreadable' 'origin/main could not be resolved to a commit' }

if ($oldHead -ne $script:Observed) {
    $ff = Invoke-Git @('-C', $Src, 'merge-base', '--is-ancestor', $oldHead, $script:Observed)
    if ($ff.ExitCode -ne 0) { Stop-With 'refused' 'not_fast_forward' 'origin/main is not a fast-forward of the deployed head' }
}

# CLASSIFY. Privileged change classes refuse the in-app path and name the elevated installer.
$changed = (Invoke-Git @('-C', $Src, 'diff', '--name-only', ($oldHead + '..' + $script:Observed))).StdOut
if ($changed.Trim()) {
    $classifier = @'
import sys
from corpusfm.lifecycle import update_boundary as ub
paths = [p.strip() for p in sys.stdin if p.strip()]
result = ub.classify(paths)
if result.requires_installer:
    sys.stdout.write(result.reason())
    raise SystemExit(1)
'@
    $classifyEnv = New-ChildEnvironment -Kind python -Extra @{ 'PYTHONPATH' = $LibDir }
    $verdict = Invoke-Fixed -FilePath $Py -Arguments @('-c', $classifier) -Environment $classifyEnv -StdIn $changed
    if ($verdict.ExitCode -ne 0) { Stop-With 'refused' 'needs_installer' ([string]$verdict.StdOut) }
}

# CONSENT, EVALUATED LAST. Exact equality (ruling O2) - a prefix match would let an abbreviation
# authorize every commit sharing it - and deliberately AFTER the fast-forward and classification
# gates above. Each of those is decided on the tip THIS script resolved, so the administrator's
# value can only ever REFUSE. Comparing it first put it in FRONT of those gates, which is the shape
# of a value that selects rather than consents.
if ($script:Observed -ne $script:Requested) {
    Stop-With 'refused' 'target_changed' ("origin/main is now " + $script:Observed.Substring(0,12) +
        ", but this update was authorized for " + $script:Requested.Substring(0,12) +
        ". Check for updates again and authorize the current tip.")
}

# -- apply ----------------------------------------------------------------------------------------
# The installed build stamp is runtime identity, not source, so Git cannot restore it. Preserve its
# exact pre-operation state before the merge. The same transaction can then repair an authorized
# same-head checkout whose stamp is stale.
$Stamp = Join-Path $Src 'corpusfm\_build.txt'
$ReleaseBuild = Join-Path $Src 'release-build.txt'
$stampExisted = Test-Path $Stamp -PathType Leaf
if ((Test-Path $Stamp) -and -not $stampExisted) {
    Stop-With 'refused' 'invalid_build_stamp' 'the installed build stamp is not an ordinary file'
}
$oldStampBytes = $null
if ($stampExisted) {
    try { $oldStampBytes = [System.IO.File]::ReadAllBytes($Stamp) }
    catch { Stop-With 'failed' 'build_stamp_unreadable' 'the installed build stamp could not be preserved' }
}

function Get-DeclaredReleaseBuild {
    if (-not (Test-Path $ReleaseBuild -PathType Leaf)) { return '' }
    try { $value = ([System.IO.File]::ReadAllText($ReleaseBuild)).Trim() }
    catch { return '' }
    if ($value -notmatch '^[1-9][0-9]*$') { return '' }
    return $value
}

function Restore-Previous {
    Write-Log ("restoring to " + $oldHead.Substring(0,12))
    [void](Invoke-Git @('-C', $Src, 'reset', '--hard', $oldHead))
    try {
        if ($stampExisted) { [System.IO.File]::WriteAllBytes($Stamp, $oldStampBytes) }
        else { Remove-Item -Force $Stamp -ErrorAction SilentlyContinue }
    } catch {
        Write-Log 'build stamp rollback failed'
    }
    foreach ($svc in $Services) { Restart-Service $svc -ErrorAction SilentlyContinue }
}

Write-Log ("advancing to " + $script:Observed.Substring(0,12))
# Exit status only from here on (N2): merge, reset and the import probe all produce text composed
# from the tree being changed or from a remote, and none of it passes a fence on its way to a log.
$merge = Invoke-Git @('-C', $Src, 'merge', '--ff-only', $script:Observed)
if ($merge.ExitCode -ne 0) { Stop-With 'failed' 'pull_failed' 'the fast-forward did not apply' }

# Stamp the declared build of the HEAD that was actually applied, then read it back before any new
# code is loaded. Public Git history is intentionally short and is not the product build identity.
$newBuild = Get-DeclaredReleaseBuild
if ($newBuild -notmatch '^[1-9][0-9]*$') {
    Restore-Previous
    $script:ResultHead = $oldHead
    Stop-With 'failed' 'build_stamp_failed' 'the applied checkout release-build.txt was not valid; rolled back' $true
}
try {
    Set-Content -Path $Stamp -Value $newBuild -Encoding ascii -ErrorAction Stop
    $writtenBuild = (Get-Content $Stamp -Raw -ErrorAction Stop).Trim()
} catch {
    $writtenBuild = ''
}
if ($writtenBuild -ne $newBuild) {
    Restore-Previous
    $script:ResultHead = $oldHead
    Stop-With 'failed' 'build_stamp_failed' 'the applied checkout build stamp could not be written and verified; rolled back' $true
}

# The import probe DOES load the new code - its whole purpose - so it is the one place the checkout
# is on the path, after every gate above has passed. PYTHONPATH is added to THIS child's built
# environment rather than to the process, so it reaches the probe and nothing else.
$probeEnv = New-ChildEnvironment -Kind python -Extra @{
    'PYTHONPATH' = $Src
    'PYTHONDONTWRITEBYTECODE' = '1'
}
$probe = Invoke-Fixed -FilePath $Py -Arguments @('-c', 'import corpusfm.app.web.app') -Environment $probeEnv
if ($probe.ExitCode -ne 0) {
    Restore-Previous
    $script:ResultHead = $oldHead
    Stop-With 'refused' 'import_probe_failed' 'the new code did not load in a fresh interpreter; rolled back' $true
}

foreach ($svc in $Services) { Restart-Service $svc -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 3
# The Windows boolean/status equivalents of `systemctl is-active`. `-ErrorAction SilentlyContinue`
# is what contains their error stream; without it a missing service writes to the console.
$failed = @($Services | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -ne 'Running' })
if ($failed.Count -gt 0) {
    Restore-Previous
    $script:ResultHead = $oldHead
    Stop-With 'failed' 'service_did_not_start' (($failed -join ', ') + ' did not come back; rolled back') $true
}

$script:ResultHead = (Invoke-Git @('-C', $Src, 'rev-parse', 'HEAD')).StdOut.Trim()
if ($script:ResultHead -notmatch '^[0-9a-f]{40,64}$') { $script:ResultHead = '' }
$finalBuild = Get-DeclaredReleaseBuild
try { $finalStamp = (Get-Content $Stamp -Raw -ErrorAction Stop).Trim() } catch { $finalStamp = '' }
if (-not $script:ResultHead -or $finalBuild -notmatch '^[1-9][0-9]*$' -or
    $finalStamp -ne $finalBuild) {
    Restore-Previous
    $script:ResultHead = $oldHead
    Stop-With 'failed' 'build_stamp_mismatch' 'the resulting checkout and runtime build stamp disagree; rolled back' $true
}
Write-Log ("completed at " + $(if ($script:ResultHead) { $script:ResultHead.Substring(0,12) } else { 'an unreadable head' }))
Write-Outcome 'completed' 'ok' 'update applied and the services are running' $false

} *> $null
