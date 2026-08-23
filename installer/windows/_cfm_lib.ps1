<#
  _cfm_lib.ps1 - CORPUSfm shared script library (the S1-S10 contract skeleton).

  The PowerShell twin of _cfm_lib.sh - keep the two APIs identical in name + behavior.
  Dot-sourced by every Tier-1/Tier-2 PowerShell script (installer SPEC.md, "Script conformance").
  It is the enforcement mechanism: scripts use these primitives + the section/step runners and
  MUST NOT define their own (Info/Ok/Warn/Die live HERE only).

  Provides:
    - five canonical output primitives: Hello Info Ok Warn Die   (-silent muting baked in)
    - Section <title>           : the section runner (labels the log even for a no-op body)
    - Cfm-StepReset / Cfm-Step    : register ordered steps
    - Cfm-RunSteps              : the S7 step-runner (retry/recover, hard-fail -> jump to S8)
    - Cfm-Summary             : the S8 tally ("N/N completed" | "k/N: failed on <step>")

  A step scriptblock signals FAILURE by THROWING (or returning $false); anything else is success.
  KEEP THIS FILE ASCII-ONLY (Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI).
#>

# Idempotent guard - safe to dot-source more than once.
if ($script:CfmLibSourced) { return }
$script:CfmLibSourced = $true

# -- Silence -----------------------------------------------------------------------------------
# Set $script:CfmSilent = $true (from a -Silent/-Yes switch or for a non-interactive helper)
# BEFORE the first primitive call. Suppresses decoration (Hello / Section banners / Info), keeps
# Ok+Warn (state), always keeps Die. Ceremony and silence are the same gear.
if ($null -eq $script:CfmSilent) { $script:CfmSilent = $false }

function Cfm-IsSilent { return [bool]$script:CfmSilent }

# -- Transcript log + verbosity (the PowerShell twin of _cfm_lib.sh's CFM_LOG / CFM_VERBOSE) ----
# Two orthogonal output controls layered over the primitives:
#   $script:CfmLog     - path to an always-on transcript. When set (via Cfm-LogInit) EVERY primitive
#                        + section is ALSO appended as a plain, timestamped line, and Cfm-Run captures
#                        a command's full output to it. Console output is UNCHANGED, so this is
#                        invisible to the operator until something fails (Die points them at it).
#   $script:CfmVerbose - $true shows Cfm-Run command output on the CONSOLE too (concise by default:
#                        that detail goes only to the log). Set from the caller's -Verbose.
# Both default off, so a script that never calls Cfm-LogInit behaves exactly as before.
if ($null -eq $script:CfmLog)     { $script:CfmLog = if ($env:CFM_LOG) { $env:CFM_LOG } else { '' } }
if ($null -eq $script:CfmVerbose) { $script:CfmVerbose = $false }
function Cfm-IsVerbose { return [bool]$script:CfmVerbose }
function Cfm-Ts { return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
# Append one plain, timestamped line to the transcript (no-op when no log / unwritable).
function Cfm-Logline($m) {
    if ($script:CfmLog) {
        try { Add-Content -LiteralPath $script:CfmLog -Value ((Cfm-Ts) + '  ' + $m) -ErrorAction SilentlyContinue } catch { }
    }
}

# Cfm-LogInit <path> - begin the always-on transcript. Reuses $env:CFM_LOG when already set (a
# nested/re-invoked script continues ONE transcript). An unwritable path disables the transcript
# rather than failing the install. Exports CFM_LOG for any child process.
function Cfm-LogInit($path) {
    if (-not $script:CfmLog) { $script:CfmLog = $path }
    try {
        $dir = Split-Path -Parent $script:CfmLog
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -LiteralPath $script:CfmLog -Value '' -ErrorAction Stop
    } catch { $script:CfmLog = ''; return }
    $env:CFM_LOG = $script:CfmLog
    Cfm-Logline ("=== transcript opened (verbose=" + $script:CfmVerbose + ", pid=" + $PID + ") ===")
}

# Cfm-Run <label> <exe> [args...] - run an external command as part of the install. Its combined
# output is ALWAYS captured to the transcript; it reaches the console only under -Verbose (concise
# default). The native exit code lands in $LASTEXITCODE, so callers keep the existing
# `Cfm-Run ...; NeedExit $LASTEXITCODE "..."` pattern. With neither a log nor verbose it just runs
# the command (pre-Batch-1 console passthrough).
#
# DELIBERATELY a SIMPLE function using $args (no param()/ValueFromRemainingArguments): a declared
# parameter would let a command flag like `-c` bind by prefix to a `-Cmd` parameter. With $args
# there is no binding at all, so any dash-leading command flag passes through untouched.
function Cfm-Run {
    if ($args.Count -lt 2) { return }
    $Label = $args[0]
    $exe = $args[1]
    $rest = @(); if ($args.Count -gt 2) { $rest = $args[2..($args.Count - 1)] }
    Cfm-Logline ('$ [' + $Label + '] ' + ((@($exe) + $rest) -join ' '))
    if (-not $script:CfmLog -and -not (Cfm-IsVerbose)) { & $exe @rest; return }
    # Capture combined output WITHOUT letting a native stderr write escalate to a terminating error
    # under $ErrorActionPreference='Stop' (the documented stderr-as-terminating-error pitfall that
    # bit the first Windows install attempt) - force Continue locally around the call only.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $exe @rest 2>&1 | ForEach-Object { $_.ToString() } }
    finally { $ErrorActionPreference = $prev }
    if ($script:CfmLog -and $out) { $out | Add-Content -LiteralPath $script:CfmLog -ErrorAction SilentlyContinue }
    if ((Cfm-IsVerbose) -and $out) { foreach ($line in $out) { Write-Host $line } }
}

# -- The five canonical primitives -------------------------------------------------------------
# Each also records a plain timestamped line to the transcript (when active) - the console form is
# unchanged, so the transcript is a complete, greppable history without altering operator output.
function Hello($m) { Cfm-Logline ("==> " + $m); if (-not (Cfm-IsSilent)) { Write-Host ""; Write-Host ("==> " + $m) -ForegroundColor Cyan } }
function Info($m)  { Cfm-Logline ("  > " + $m); if (-not (Cfm-IsSilent)) { Write-Host ("  > " + $m) -ForegroundColor Cyan } }
function Ok($m)    { Cfm-Logline ("  + " + $m); Write-Host ("  + " + $m) -ForegroundColor Green }
function Warn($m)  { Cfm-Logline ("  ! " + $m); Write-Host ("  ! " + $m) -ForegroundColor Yellow }
function Die($m)   {
    Cfm-Logline ("  x " + $m)
    Write-Host ("  x " + $m) -ForegroundColor Red
    if ($script:CfmLog) {
        Cfm-Logline "(install aborted - see this transcript)"
        Write-Host ("    full install log: " + $script:CfmLog) -ForegroundColor DarkGray
    }
    exit 1
}

# -- Secret-file ACL ---------------------------------------------------------------------------
# Lock a box-local secret file down to SYSTEM + Administrators only. icacls /inheritance:r
# strips inherited ACEs (so a permissive parent dir can't widen access) then /grant:r re-grants
# ONLY the two trusted SIDs (S-1-5-18 = LocalSystem, the account the services run as; S-1-5-32-544
# = the Administrators group). Idempotent: re-running just re-asserts the same ACL. Best-effort -
# a failure Warns rather than aborting the install.
function Lock-FileAcl($path) {
    if (-not (Test-Path $path)) { return }
    & icacls $path /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Warn ("Could not lock ACL on " + $path + " (icacls exit " + $LASTEXITCODE + ")") }
}

# Lock-DirTreeAcl - strip inheritance on a DIRECTORY and grant ONLY the two trusted SIDs with the
# (OI)(CI) object/container-inherit flags, so every child (present AND future, incl. files the app
# writes at runtime - corpus.key, .ai_env, install.yaml) inherits SYSTEM+Administrators-only. This is
# the Windows equivalent of the Linux 0700 service-owned config dir: on Windows POSIX chmod is a
# no-op (core.secure_fs can't enforce it), so a runtime-written secret would otherwise inherit
# C:\ProgramData's default Users:(RX). Use for CORPUSfm-only trees (ConfigHome) - NOT for a tree IIS
# must read (e.g. the proxy web.config under InstallRoot). Idempotent; best-effort.
function Lock-DirTreeAcl($path) {
    if (-not (Test-Path $path)) { return }
    & icacls $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Warn ("Could not lock ACL on dir " + $path + " (icacls exit " + $LASTEXITCODE + ")") }
}

# -- Section runner ----------------------------------------------------------------------------
# Section "<title>" - opens one of the ten contract sections with a uniform, numbered boundary so
# every script's transcript has the SAME shape, even when the body is a ceremonial no-op. Under
# silent the banner collapses to a single dim line (still present, for the record).
$script:CfmSectionNo = 0
function Section($title) {
    $script:CfmSectionNo++
    Cfm-Logline ("=== S" + $script:CfmSectionNo + "  " + $title + " ===")
    if (Cfm-IsSilent) {
        Write-Host ("-- S" + $script:CfmSectionNo + " " + $title + " --") -ForegroundColor DarkGray
    } else {
        Write-Host ""
        Write-Host ("=== S" + $script:CfmSectionNo + "  " + $title + " ===") -ForegroundColor Cyan
    }
}

# -- Consent (S6) ------------------------------------------------------------------------------
# Cfm-Confirm -Prompt <str> [-SkipReason <str>] - the ONE consent gate (packet 1228), twin of bash
# cfm_confirm. Every Tier-1 script calls this; none hand-rolls a prompt. The prompt STRING lives here
# and nowhere else, so the four scripts cannot disagree about what the operator types - which is
# exactly how they came to disagree ("Type 'yes' to continue" on Windows vs "[y/N]" on Linux, split
# by OS rather than by consequence).
#
# Proceeds without waiting when EITHER a consent flag is set ($script:CfmSilent / CfmAssumeYes /
# CfmForce - which IS a pre-given confirmation) or -SkipReason is non-empty (the caller's SCOPE
# answer, computed before S6).
#
# The scope answer arrives as ONE value the caller computes, never as logic in here: the library
# cannot know what "outside this install's footprint" means for a given script. That keeps the S6
# body greppable - one name plus the consent flags - which is what lets the conformance guard still
# prove "credentials are never consent" after the SPEC's absolute form was relaxed.
#
# NEVER reference a credential variable here or in a caller's S6 body. A supplied password is the
# MEANS to mutate; it is not permission (packet 020).
if ($null -eq $script:CfmAssumeYes) { $script:CfmAssumeYes = $false }
if ($null -eq $script:CfmForce)     { $script:CfmForce = $false }
function Cfm-Confirm {
    param([string]$Prompt = 'Proceed?', [string]$SkipReason = '')
    if ($script:CfmSilent -or $script:CfmAssumeYes -or $script:CfmForce) {
        Info "Proceeding (consent pre-granted by flag)."
        return
    }
    if ($SkipReason) {
        Info ("Proceeding - " + $SkipReason + ".")
        return
    }
    $reply = Read-Host ("  " + $Prompt + " [y/N]")
    # TEST POSITIVELY FOR CONSENT, never negatively for its absence.
    #
    # MEASURED on a live box 2026-07-31: with stdin closed (ssh, a pipe, a scheduled task) Read-Host
    # returns $null, and `$null -notmatch '<pattern>'` evaluates to EMPTY rather than $true - so
    # `if ($reply -notmatch ...)` was falsy, the abort never ran, and the function returned as though
    # consent had been given. A non-interactive uninstall with NO consent flag proceeded and removed a
    # real install. This is CLAUDE.md's Alpine boolean-coercion rule in another language: never branch
    # on an expression that can be null when the null case is the dangerous one.
    #
    # "$reply" coerces null to the empty string, and '' -match '^[Yy]$' is a definite $false, so an
    # absent answer aborts. The bash twin was already correct: `case "$reply" in [Yy]) ... ;; *) abort`
    # is a positive match, which is why only this side was wrong.
    if ("$reply" -match '^[Yy]$') { return }
    Write-Host "  Aborted - nothing changed."
    exit 0
}

# -- Step runner (S7) + tally (S8) -------------------------------------------------------------
# Register ordered, named steps; run them in order; on a step failure attempt retry then an
# optional recover block; if it still fails, STOP (no silent continuation past a fatal step) and
# leave the failure recorded for Cfm-Summary.
$script:CfmSteps = @()
$script:CfmStepDone = 0
$script:CfmFailedStep = ''
$script:CfmFailedSteps = @()

function Cfm-StepReset {
    $script:CfmSteps = @()
    $script:CfmStepDone = 0
    $script:CfmFailedStep = ''
    $script:CfmFailedSteps = @()
}

# Cfm-Step -Name <str> -Action <scriptblock> [-Recover <scriptblock>] [-Retries <int>]
function Cfm-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [scriptblock]$Recover = $null,
        [int]$Retries = 0
    )
    $script:CfmSteps += [pscustomobject]@{ Name = $Name; Action = $Action; Recover = $Recover; Retries = $Retries }
}

# A step succeeds unless its scriptblock throws OR returns [bool]$false.
function Cfm-RunOne($step) {
    $attempt = 0
    while ($true) {
        try {
            $r = & $step.Action
            if ($r -is [bool] -and -not $r) { throw "step returned false" }
            return $true
        } catch {
            if ($attempt -lt $step.Retries) {
                $attempt++
                Warn ("step '" + $step.Name + "' failed (" + $_.Exception.Message + ") - retry " + $attempt + "/" + $step.Retries)
                continue
            }
            break
        }
    }
    if ($step.Recover) {
        Warn ("step '" + $step.Name + "' failed - attempting recovery")
        try { & $step.Recover; Ok ("recovered after '" + $step.Name + "'"); return $true } catch { }
    }
    return $false
}

# Cfm-RunSteps - run all registered steps in order. On the first ultimate failure, record it and
# STOP (jump straight to S8). Returns $true iff all completed.
# On the first ultimate failure, record it and STOP -- UNLESS $script:CfmForce is set, in which case
# record it and CONTINUE (packet 1235). Until now the force state reached Cfm-Confirm and nothing
# else, so -Force granted consent only while the SPEC advertised "continue past a failed step".
#
# EVERY failure is recorded, not just the first, so S8 cannot report N/N after a forced run walked
# past two of them. A best-effort mode that ends in a clean verdict is worse than none.
function Cfm-RunSteps {
    foreach ($step in $script:CfmSteps) {
        Info ($step.Name + " ...")
        if (Cfm-RunOne $step) {
            $script:CfmStepDone++
            Ok $step.Name
        } else {
            $script:CfmFailedSteps += $step.Name
            if (-not $script:CfmFailedStep) { $script:CfmFailedStep = $step.Name }
            if ($script:CfmForce) {
                Warn ("step '" + $step.Name + "' failed - continuing (-Force)")
                continue
            }
            return $false
        }
    }
    return ($script:CfmFailedSteps.Count -eq 0)
}

# Cfm-Summary - S8 verdict. Returns $true iff everything completed.
function Cfm-Summary {
    $total = $script:CfmSteps.Count
    if (-not $script:CfmFailedStep -and $script:CfmFailedSteps.Count -eq 0) {
        Ok ($script:CfmStepDone.ToString() + "/" + $total + " steps completed")
        return $true
    }
    if ($script:CfmFailedSteps.Count -gt 1) {
        Warn ($script:CfmStepDone.ToString() + "/" + $total + ": failed on " +
              $script:CfmFailedSteps.Count + " steps - " + ($script:CfmFailedSteps -join ', '))
    } else {
        Warn ($script:CfmStepDone.ToString() + "/" + $total + ": failed on '" + $script:CfmFailedStep + "'")
    }
    return $false
}
