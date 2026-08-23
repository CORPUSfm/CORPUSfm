# corpusfm-recovery - create or adopt a CORPUSfm Recovery File (packet 1246-02).
#
# Installed to $InstallRoot\bin\corpusfm-recovery.ps1, under the same ACLs as the other privileged
# helpers. The PLACEMENT and its ACLs are the installer's (1246-03/04).
#
# It finds the runtime RELATIVE TO ITSELF - bin\.. - and nowhere else. An earlier version hard-coded
# C:\Program Files\CORPUSfm and honoured a CORPUSFM_INSTALL_DIR variable; both were installation
# LAYOUT policy, which belongs to 1246-03, and the variable was an environment override of exactly
# the kind this family is removing.
#
# No SUPPORTED passphrase option exists anywhere in this chain: this wrapper defines none and
# does not prompt, and the module's parser defines none either - an unrecognised argument is
# rejected, not consumed. It DOES forward whatever arguments it is given - a pass-through
# must - so "never forwarded" was a stronger claim than the truth.
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Rest)

$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallRoot = Split-Path -Parent $Here
$PyBin = Join-Path $InstallRoot 'venv\Scripts\python.exe'

if (-not (Test-Path $PyBin)) {
    Write-Error "corpusfm-recovery: no CORPUSfm runtime beside this command (looked for $PyBin)"
    exit 2
}

$env:PYTHONPATH = Join-Path $InstallRoot 'src'
& $PyBin -m corpusfm.lifecycle.recovery_cli @Rest
exit $LASTEXITCODE
