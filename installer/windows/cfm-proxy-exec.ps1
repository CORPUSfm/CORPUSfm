<#
  cfm-proxy-exec - the Windows OS-native proxy executor and IIS provider (packet 1246-06).

  TWO TYPES, TWO MECHANISMS - and this is the correction that matters most on Windows:

    * iis          CORPUSfm's OWN application pool, primary /corpusfm application, its physical
                   directory and isolated web.config, and one exact-path metadata child application
                   per MCP well-known route. PUBLICATION IS ACTIVATION - the isolated applications
                   apply without restarting FMS (installer/SPEC.md:667), so the engine health-checks
                   the route DIRECTLY and no FMS restart exists on this path at all.
    * claris-nginx a marked include in the UNIQUE 443 server block. An ACTIVE front uses the
                   explicit publish-active/remove-active verbs to stage the bounded family and
                   retain its exact before-image. The lifecycle provider then activates it through
                   its authenticated fmsadmin restart cohort. Ordinary publish/remove still refuse
                   while the front is active.

  IT NEVER RENDERS. The marked block, the include body and every web.config arrive as files, all
  rendered once by corpusfm/lifecycle/proxy_render.py. Two independent renderers drift the moment
  either is edited, and planning cannot decide whether a change is needed without knowing what the
  DESIRED text is.

  BEFORE-IMAGE AND ROLLBACK. Ruling 1: rollback removes only what THIS RUN created and restores
  every pre-existing definition and byte. So `publish` records, per artifact, whether it existed
  beforehand and - for the pool and each application - its prior physical path and pool assignment.
  `restore` consults that record; it never deletes an object it cannot prove this run created.

  NEVER: fmsadmin, nginx lifecycle commands, Start/Stop/Restart-Service, taskkill, iisreset, or
  broad FMS lifecycle control. Never an FMS SITE-LEVEL rewrite rule.

  CURRENT AUTHORITY: this executor contains the required appcmd behaviour and byte-exact primitives
  directly. The retired inline publisher is not a dependency and is no longer shipped.

  ASCII-ONLY. Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so one non-ASCII byte corrupts
  the parser. Avoid PS7-only syntax so it parses on 5.1.

  Usage:
    cfm-proxy-exec -Verb <observe|publish|publish-active|remove|remove-active|restore|retire|digest|probe>
                   -Type <iis|claris-nginx> -FmsRoot DIR [-BlockFile F] [-IncludeFile F]
                   [-WebConfigFile F] [-MetadataDir D] [-IisAppDir D] [-Prefix P]
                   [-ClarisNginxActive]
  Emits ONE JSON object on stdout. Exit 0 = the verb's contract was met; 2 = refused; 1 = failed.
#>

param(
  [Parameter(Mandatory)][ValidateSet('prepare','classify','observe','publish','publish-active','remove','remove-active','restore','retire','digest','family-digest','probe')][string]$Verb,
  [ValidateSet('iis','claris-nginx')][string]$Type = 'iis',
  [string]$FmsRoot = '',
  [string]$Prefix = '/corpusfm',
  [string]$BlockFile = '',
  [string]$IncludeFile = '',
  [string]$WebConfigFile = '',
  [string]$MetadataDir = '',
  [string]$IisAppDir = '',
  [string]$Site = 'FMWebSite',
  # SWITCHES, not [bool]. PowerShell cannot bind a [bool] parameter through `-File` at all - it
  # refuses "$true" and "1" alike - and `-File` is exactly how the Python dispatcher invokes this
  # script. A [bool] here is an interface that only works from inside PowerShell.
  [switch]$ClarisNginxActive,
  [string]$OperationId = '',
  # A FILE of `name=path` lines, not an array. PowerShell's `-File` invocation binds each argument
  # as one string and never splits one into an array, so a multi-value parameter is unreachable
  # through the very channel the dispatcher uses - the same class of defect as the [bool] switches.
  [string]$PartsFile = ''
)

$ErrorActionPreference = 'Stop'
$script:CfmMark = 'CORPUSFM'
$script:CfmIncludeName = 'corpusfm_https.conf'
$script:CfmPool = 'CORPUSfmProxy'
# The normalized prefix, available to the evidence reader before the iis branch computes its own.
$pfxForEvidence = $Prefix
if (-not $pfxForEvidence.StartsWith('/')) { $pfxForEvidence = '/' + $pfxForEvidence }
$pfxForEvidence = $pfxForEvidence.TrimEnd('/')
if ($pfxForEvidence -eq '') { $pfxForEvidence = '/' }

function Write-CfmResult {
  param([bool]$Ok, [bool]$Restored = $false, [bool]$RestoreVerified = $false,
        [string]$Detail = '', [string]$Fingerprint = '', [string]$Backup = '',
        [object]$Evidence = $null, [object]$Unchanged = $null,
        [string]$ConfigLocation = '')
  $o = [ordered]@{ ok = $Ok; restored = $Restored; restore_verified = $RestoreVerified;
                   detail = $Detail; fingerprint = $Fingerprint; backup = $Backup;
                   evidence = $Evidence; unchanged = $Unchanged;
                   config_location = $ConfigLocation }
  $o | ConvertTo-Json -Compress -Depth 8
}
function Deny([string]$m) { Write-CfmResult -Ok $false -Detail $m; exit 2 }
function Fail([string]$m, [bool]$r = $false, [bool]$v = $false) {
  Write-CfmResult -Ok $false -Restored $r -RestoreVerified $v -Detail $m; exit 1
}
function Pass([string]$m, [string]$fp = '', [string]$bak = '', [object]$ev = $null,
              [object]$unchanged = $null, [string]$location = '') {
  Write-CfmResult -Ok $true -Detail $m -Fingerprint $fp -Backup $bak -Evidence $ev `
                  -Unchanged $unchanged -ConfigLocation $location; exit 0
}
# A successful restore must SAY it restored and verified. `Pass` reports both false, which is right
# for publish (nothing was put back) and silently wrong for restore - the dispatcher requires
# `ok AND restore_verified`, so an honest restore would have read as an unverified one.
function PassRestored([string]$m, [object]$ev = $null) {
  Write-CfmResult -Ok $true -Restored $true -RestoreVerified $true -Detail $m -Evidence $ev; exit 0
}

# ---------------------------------------------------------------------------------------------
# Byte-exact primitives preserve BOM, newline style, and every byte outside the marked block. They
# live here because this installed executor is the publication authority.
# ---------------------------------------------------------------------------------------------
function Get-CfmTextFile {
  param([Parameter(Mandatory)][string]$Path)
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
  $start = if ($hasBom) { 3 } else { 0 }
  $text = [System.Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start)
  $newline = if ($text -match "`r`n") { "`r`n" } else { "`n" }
  return @{ Text = $text; HasBom = $hasBom; Newline = $newline }
}

# Encode as UTF-8, EXPLICITLY prepending the BOM when the original had one. `UTF8Encoding($true)`
# does NOT emit the preamble from `GetBytes()` - only `GetPreamble()` does - so relying on the
# constructor flag silently drops the BOM. An earlier version of this executor lost it and dropped
# the BOM.
function Get-CfmUtf8Bytes {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [bool]$HasBom = $false)
  $enc = New-Object System.Text.UTF8Encoding($false)
  $body = $enc.GetBytes($Text)
  if (-not $HasBom) { return $body }
  $bom = [byte[]](0xEF, 0xBB, 0xBF)
  $out = New-Object 'byte[]' ($bom.Length + $body.Length)
  [System.Array]::Copy($bom, 0, $out, 0, $bom.Length)
  [System.Array]::Copy($body, 0, $out, $bom.Length, $body.Length)
  return $out
}

function Write-CfmBytesAtomic {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [bool]$HasBom = $false)
  $tmp = "$Path.cfmnew"
  [System.IO.File]::WriteAllBytes($tmp, (Get-CfmUtf8Bytes -Text $Text -HasBom $HasBom))
  # Copy-onto-existing rather than a replace: the destination keeps its own ACL, which on a real box
  # is FileMaker Server's, and this executor has no business rewriting it.
  [System.IO.File]::Copy($tmp, $Path, $true)
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

# THE CANONICAL FINGERPRINT (ruling 4). SHA-256 of the block with LF newlines, NO terminal newline
# and NO BOM. Python, bash and PowerShell must agree byte-for-byte, and tests/test_proxy_render.py
# runs all three against the same input to prove it - two implementations agreeing by inspection is
# exactly what was believed before, and it was false.
function Get-CfmCanonicalText {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
  $t = $Text
  if ($t.Length -ge 1 -and [int][char]$t[0] -eq 0xFEFF) { $t = $t.Substring(1) }
  $t = $t -replace "`r`n", "`n"
  $t = $t -replace "`r", "`n"
  return $t.TrimEnd("`n")
}

function Get-CfmDigest {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
  $canonical = Get-CfmCanonicalText $Text
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $enc = New-Object System.Text.UTF8Encoding($false)
  $h = $sha.ComputeHash($enc.GetBytes($canonical))
  return (($h | ForEach-Object { $_.ToString('x2') }) -join '')
}

# THE FAMILY DIGEST (Codex ruling 3). One part digest is not an artifact digest: hashing the primary
# web.config ignored the pool, every application definition, their physical paths and pool
# assignments, and every metadata child - so an operator could repoint an application and nothing
# would register it. The whole owned family is hashed, LENGTH-PREFIXED per part so content cannot be
# moved between parts unnoticed, in sorted name order so the result does not depend on build order.
#
#   <name>`n<byte length of canonical body>`n<canonical body>   joined by LF
function Get-CfmFamilyDocument {
  param([Parameter(Mandatory)][hashtable]$Parts)
  $enc = New-Object System.Text.UTF8Encoding($false)
  $chunks = @()
  foreach ($name in ($Parts.Keys | Sort-Object -CaseSensitive)) {
    $body = Get-CfmCanonicalText ([string]$Parts[$name])
    $len = $enc.GetByteCount($body)
    $chunks += ("$name`n$len`n$body")
  }
  return ($chunks -join "`n")
}

function Get-CfmFamilyDigest {
  param([Parameter(Mandatory)][hashtable]$Parts)
  return (Get-CfmDigest (Get-CfmFamilyDocument $Parts))
}

# Marker-pair policy: EXACTLY zero, or EXACTLY one balanced pair. Anything else is invalid and the
# caller fails closed. Horizontal whitespace only - it can never consume a physical newline.
function Get-CfmMarkerState {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
  # Normalize CRLF before applying a line-anchored expression. In .NET regex `$` matches before
  # LF but not before the preceding CR, so the old expression treated a block we had just written
  # into a CRLF FMS config as absent and silently omitted it from the family fingerprint.
  $normalized = $Text -replace "`r`n", "`n"
  $n = ([regex]::Matches($normalized, "(?m)^[ `t]*#+[ `t]*$($script:CfmMark)[ `t]*$")).Count
  if ($n -eq 0) { return 'none' }
  if ($n -eq 2) { return 'one' }
  return 'invalid'
}

function Get-CfmMarkedBlock {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
  if ((Get-CfmMarkerState $Text) -ne 'one') { return $null }
  $lines = $Text -split "`r?`n"
  $re = [regex]"^[ `t]*#+[ `t]*$($script:CfmMark)[ `t]*$"
  $idx = @()
  for ($i = 0; $i -lt $lines.Count; $i++) { if ($re.IsMatch($lines[$i])) { $idx += $i } }
  return ($lines[$idx[0]..$idx[1]] -join "`n")
}

function Get-CfmBackupPath { param([string]$Path) return "$Path.cfmbak" }

function Test-CfmResidue {
  param([string]$Path)
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $dir)) { return $false }
  $found = @(Get-ChildItem -LiteralPath $dir -Filter '*.cfmbak' -ErrorAction SilentlyContinue)
  return ($found.Count -gt 0)
}

function New-CfmBackup {
  param([string]$Path)
  $bak = Get-CfmBackupPath $Path
  Copy-Item -LiteralPath $Path -Destination $bak -Force
  return $bak
}

# Retire the durable backups. Called ONLY once the configuration and the manifest agree - before
# that the backup is the only restore point on the box, which is why a successful publish keeps it.
function Remove-CfmBackup {
  param([string]$Path)
  Remove-Item -LiteralPath (Get-CfmBackupPath $Path) -Force -ErrorAction SilentlyContinue
}

function Restore-CfmBackup {
  param([string]$Path)
  $bak = Get-CfmBackupPath $Path
  if (-not (Test-Path -LiteralPath $bak)) { return $false }
  Copy-Item -LiteralPath $bak -Destination $Path -Force
  $a = Get-CfmDigest ((Get-CfmTextFile $Path).Text)
  $b = Get-CfmDigest ((Get-CfmTextFile $bak).Text)
  if ($a -ne $b) { return $false }
  Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
  return $true
}

# Exact-byte comparison for the active-front rollback contract. The canonical text digest above is
# the publication identity; it intentionally ignores BOM/newline differences and therefore cannot
# prove that a host-owned file was restored byte-for-byte.
function Get-CfmByteDigest {
  param([Parameter(Mandatory)][string]$Path)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $h = $sha.ComputeHash([System.IO.File]::ReadAllBytes($Path)) }
  finally { $sha.Dispose() }
  return (($h | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Resolve-CfmFmsNginx {
  param([Parameter(Mandatory)][string]$Root)
  $checked = @(
    (Join-Path $Root 'Nginx\nginx.exe'),
    (Join-Path $Root 'NginxServer\nginx.exe')
  )
  foreach ($candidate in $checked) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return @{ Exe = $candidate; Checked = $checked }
    }
  }
  return @{ Exe = ''; Checked = $checked }
}

# Inactive-front parser only. An active Claris server removes CStore/.passphrase after startup, so
# its unchanged live configuration cannot be parsed by a later standalone nginx -t. That front is
# validated by the lifecycle provider's authenticated HTTP-server restart instead.
function Invoke-CfmFmsNginx {
  param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][ValidateSet('test')][string]$Mode)
  $resolved = Resolve-CfmFmsNginx $Root
  if (-not $resolved.Exe) {
    return @{ Ok = $false; ExitCode = -1; Output = ('nginx.exe not found. Checked: ' + ($resolved.Checked -join '; ')) }
  }
  $argv = @('-p', (Join-Path $Root 'NginxServer'), '-c',
            (Join-Path $Root 'NginxServer\conf\fms_nginx.conf'), '-t')
  $out = ''; $code = -1
  $savedEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $out = & $resolved.Exe @argv 2>&1 | Out-String
    $code = $LASTEXITCODE
  } catch {
    $out = "$_"
    $code = -1
  } finally {
    $ErrorActionPreference = $savedEap
  }
  $text = "$out"
  $syntaxOk = [bool]($text -match 'syntax is ok')
  $bindRe = 'bind\(\) to (0\.0\.0\.0|\[::\]):(80|443)'
  $bindConflict = [bool]($text -match $bindRe -or $text -match '\b10013\b')
  $otherError = $false
  foreach ($line in ($text -split "`n")) {
    $item = $line.Trim()
    if ($item -eq '') { continue }
    $isSignal = ($item -match '\[emerg\]' -or $item -match '\[alert\]' -or
      $item -match '\[error\]' -or $item -match 'unknown directive' -or
      $item -match 'unexpected "' -or $item -match 'is not allowed' -or
      $item -match 'permission denied' -or $item -match 'failed')
    if (-not $isSignal) { continue }
    if ($item -match $bindRe -or $item -match '\b10013\b') { continue }
    if ($item -match 'test (failed|is successful)') { continue }
    $otherError = $true
    break
  }
  if ($code -ne 0 -and -not $bindConflict) { $otherError = $true }
  if ($code -eq 0 -and -not $syntaxOk) { $otherError = $true }
  # A dormant Claris nginx parses while IIS owns 80/443. Its expected bind conflict is not a
  # configuration defect when (and only when) nginx reached an explicit syntax-ok verdict and no
  # unrelated error was present. This is read-only validation; no listener is stopped or started.
  return @{
    Ok = ($syntaxOk -and -not $otherError)
    SyntaxOk = $syntaxOk
    BindConflict = $bindConflict
    OtherError = $otherError
    ExitCode = $code
    Output = $text
  }
}

function Restore-CfmClarisFamily {
  param([Parameter(Mandatory)][string]$Conf, [Parameter(Mandatory)][string]$Include)
  $confBak = Get-CfmBackupPath $Conf
  $incBak = Get-CfmBackupPath $Include
  if (-not (Test-Path -LiteralPath $confBak -PathType Leaf)) {
    return @{ Ok = $false; Detail = "main backup is absent at $confBak" }
  }
  try {
    [System.IO.File]::Copy($confBak, $Conf, $true)
    if (Test-Path -LiteralPath $incBak -PathType Leaf) {
      [System.IO.File]::Copy($incBak, $Include, $true)
    } else {
      Remove-Item -LiteralPath $Include -Force -ErrorAction SilentlyContinue
    }
    if ((Get-CfmByteDigest $Conf) -ne (Get-CfmByteDigest $confBak)) {
      return @{ Ok = $false; Detail = 'main configuration did not restore byte-exactly' }
    }
    if (Test-Path -LiteralPath $incBak -PathType Leaf) {
      if (-not (Test-Path -LiteralPath $Include -PathType Leaf) -or
          (Get-CfmByteDigest $Include) -ne (Get-CfmByteDigest $incBak)) {
        return @{ Ok = $false; Detail = 'include did not restore byte-exactly' }
      }
    } elseif (Test-Path -LiteralPath $Include) {
      return @{ Ok = $false; Detail = 'new include remained after rollback' }
    }
    return @{ Ok = $true; Detail = 'prior family restored byte-exactly' }
  } catch {
    return @{ Ok = $false; Detail = "restore raised: $_" }
  }
}

# ---------------------------------------------------------------------------------------------
# The metadata vpaths, prefix-derived and EXACT. Kept explicit because the installed executor runs
# independently of the application checkout. Must equal proxy_render.metadata_routes.
# ---------------------------------------------------------------------------------------------
function Get-CfmNormalizedPrefix {
  param([Parameter(Mandatory)][string]$Prefix)
  $p = $Prefix
  if (-not $p.StartsWith('/')) { $p = '/' + $p }
  $p = $p.TrimEnd('/')
  if ($p -eq '') { $p = '/' }
  return $p
}

function Get-CfmMetadataVpaths {
  param([Parameter(Mandatory)][string]$NormalizedPrefix)
  return @(
    "/.well-known/oauth-protected-resource$NormalizedPrefix/mcp",
    "/.well-known/oauth-authorization-server$NormalizedPrefix/mcp",
    "/.well-known/openid-configuration$NormalizedPrefix/mcp"
  )
}

# ---------------------------------------------------------------------------------------------
# appcmd. Absolute Windows system tool path (ruling 2) - never a PATH lookup. Injectable so the
# semantic suite can drive every branch without IIS.
# ---------------------------------------------------------------------------------------------
$script:CfmAppCmdScript = $env:CFM_APPCMD_STUB          # tests only; absent in production

function Invoke-CfmAppCmd {
  param([Parameter(Mandatory)][string[]]$Argv)
  if ($script:CfmAppCmdScript) {
    $o = (& $script:CfmAppCmdScript @Argv 2>&1 | Out-String)
    return @{ ExitCode = $LASTEXITCODE; Output = $o }
  }
  $appcmd = Get-CfmAppCmdPath
  if (-not $appcmd -or -not (Test-Path -LiteralPath $appcmd)) {
    return @{ ExitCode = 9009; Output = 'appcmd.exe not found' }
  }
  $o = (& $appcmd @Argv 2>&1 | Out-String)
  return @{ ExitCode = $LASTEXITCODE; Output = $o }
}

function Get-CfmAppCmdPath {
  # `$env:windir` is empty off Windows, and `Join-Path` rejects a null root - so the absence of the
  # variable is itself the answer, not an error to propagate.
  if (-not $env:windir) { return '' }
  return (Join-Path $env:windir 'system32\inetsrv\appcmd.exe')
}

function Test-CfmIisAvailable {
  if ($script:CfmAppCmdScript) { return $true }
  $p = Get-CfmAppCmdPath
  if (-not $p) { return $false }
  return (Test-Path -LiteralPath $p)
}

# TRI-STATE (ruling 6): $true present, $false absent, $null COULD NOT BE READ. Collapsing the third
# into "absent" is how a mutation comes to recreate an application that is already there, or to
# report an installation unconfigured because appcmd happened to fail.
function Get-CfmAppState {
  param([Parameter(Mandatory)][string]$AppName)
  $r = Invoke-CfmAppCmd @('list', 'app', "/app.name:$AppName")
  if ($r.ExitCode -ne 0) { return $null }
  return ($r.Output -match [regex]::Escape('APP "' + $AppName + '"'))
}

function Test-CfmAppExists {
  param([Parameter(Mandatory)][string]$AppName)
  $state = Get-CfmAppState $AppName
  if ($null -eq $state) {
    Fail "the registration of $AppName could not be read; refusing to act on an unknown state"
  }
  return $state
}

function Get-CfmAppPhysicalPath {
  param([Parameter(Mandatory)][string]$AppName)
  $r = Invoke-CfmAppCmd @('list', 'vdir', "/app.name:$AppName", '/text:physicalPath')
  if ($r.ExitCode -ne 0) { return $null }      # UNREAD, not empty
  return ("$($r.Output)".Trim())
}

function Get-CfmPoolState {
  $r = Invoke-CfmAppCmd @('list', 'apppool', "/apppool.name:$($script:CfmPool)")
  # REAL IIS answers a missing named app pool with exit 1 and NO output (measured on
  # winfms2026, 2026-08-10). That is absence, not an unreadable registration. Other failures keep
  # their output or another exit code and remain the third, unknown state.
  if ($r.ExitCode -eq 1 -and [string]::IsNullOrWhiteSpace("$($r.Output)")) { return $false }
  if ($r.ExitCode -ne 0) { return $null }
  return ($r.Output -match [regex]::Escape('APPPOOL "' + $script:CfmPool + '"'))
}

function Test-CfmPoolExists {
  $state = Get-CfmPoolState
  if ($null -eq $state) {
    Fail "the registration of $($script:CfmPool) could not be read; refusing to act on an unknown state"
  }
  return $state
}

function Get-CfmPoolRuntime {
  # The pool's relevant setting, read back rather than assumed. An operator can change it, and a
  # family fingerprint that ignored it would call a repointed installation current.
  $r = Invoke-CfmAppCmd @('list', 'apppool', "/apppool.name:$($script:CfmPool)",
                          '/text:managedRuntimeVersion')
  if ($r.ExitCode -ne 0) { return $null }      # UNREAD, not empty
  return ("$($r.Output)".Trim())
}

function Get-CfmAppPool {
  param([Parameter(Mandatory)][string]$AppName)
  $r = Invoke-CfmAppCmd @('list', 'app', "/app.name:$AppName", '/text:applicationPool')
  if ($r.ExitCode -ne 0) { return $null }      # UNREAD, not empty
  return ("$($r.Output)".Trim())
}

# IIS reads each application's web.config as the pool identity before it can execute a rewrite.
# The installation root is deliberately closed to SYSTEM, Administrators and the two CORPUSfm
# services, so merely registering an IIS application is not enough: without this narrow grant IIS
# returns 500.19 / 0x80070005 while the loopback application remains healthy.  The grant belongs to
# the owned IIS family and is therefore captured and restored with that family, not applied by the
# general installer permissions phase.
function Get-CfmDirectorySddl {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return '' }
  # The portable PowerShell composition tests replace appcmd and have no Windows ACL provider.
  # They exercise the transaction shape; the real executor must always read the Windows DACL.
  if ($env:CFM_APPCMD_STUB) { return '' }
  try { return (Get-Acl -LiteralPath $Path -ErrorAction Stop).Sddl }
  catch { Fail "the DACL on $Path could not be read: $($_.Exception.Message)" }
}

function Set-CfmDirectorySddl {
  param([Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Sddl)
  if ($env:CFM_APPCMD_STUB) { return }
  try {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $acl.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
  } catch { Fail "the prior DACL on $Path could not be restored: $($_.Exception.Message)" $true $false }
}

function Grant-CfmPoolReadAccess {
  param([Parameter(Mandatory)][string]$Path)
  if ($env:CFM_APPCMD_STUB) { return }
  $identity = "IIS AppPool\$($script:CfmPool)"
  try {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
      $identity,
      [Security.AccessControl.FileSystemRights]::ReadAndExecute,
      [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
      [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow)
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    $seen = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $required = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
    $ok = $false
    foreach ($ace in $seen.Access) {
      if ($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
          "$($ace.IdentityReference.Value)" -ieq $identity -and
          (([int]$ace.FileSystemRights -band $required) -eq $required)) { $ok = $true; break }
    }
    if (-not $ok) { Fail "the read grant for $identity on $Path was not effective" }
  } catch { Fail "IIS cannot be granted read access to ${Path}: $($_.Exception.Message)" }
}

# The OWNED FAMILY, read back from what is actually registered (ruling 3). Every part an operator
# can change is a part: the pool and its runtime setting, each application's path and pool
# assignment, and each application's web.config bytes.
function Get-CfmIisFamilyParts {
  param([Parameter(Mandatory)][string]$NormalizedPrefix)
  $parts = @{}
  $parts['pool'] = "$($script:CfmPool)`n" + 'managedRuntimeVersion=' + (Get-CfmPoolRuntime)
  foreach ($a in (Get-CfmOwnedApps $NormalizedPrefix)) {
    $physical = Get-CfmAppPhysicalPath $a.AppName
    $pool = Get-CfmAppPool $a.AppName
    $parts["app:$($a.VPath)"] = "path=$($a.VPath)`nphysicalPath=$physical`npool=$pool"
    $cfg = Join-Path $a.Dir 'web.config'
    $body = ''
    if (Test-Path -LiteralPath $cfg) { $body = (Get-CfmTextFile $cfg).Text }
    $parts["config:$($a.VPath)"] = $body
  }
  return $parts
}

# ---------------------------------------------------------------------------------------------
# The owned IIS artifact family, as ONE list. Observation, creation, removal and rollback all walk
# it, so an artifact cannot be created by one path and forgotten by another.
# ---------------------------------------------------------------------------------------------
function Get-CfmOwnedApps {
  param([Parameter(Mandatory)][string]$NormalizedPrefix)
  $apps = @()
  $apps += @{ Kind = 'primary'; VPath = $NormalizedPrefix; AppName = "$Site$NormalizedPrefix";
              Dir = $IisAppDir }
  foreach ($v in (Get-CfmMetadataVpaths $NormalizedPrefix)) {
    $sub = Join-Path $MetadataDir (($v -replace '[^A-Za-z0-9]', '_').Trim('_'))
    $apps += @{ Kind = 'metadata'; VPath = $v; AppName = "$Site$v"; Dir = $sub }
  }
  return $apps
}

function Get-CfmIisBeforeImage {
  param([Parameter(Mandatory)][string]$NormalizedPrefix)
  $ev = [ordered]@{
    operation_id = $OperationId
    proxy_type = 'iis'
    prefix = $NormalizedPrefix
    pool_existed = (Test-CfmPoolExists)
    prior_pool_runtime = $(if (Test-CfmPoolExists) { Get-CfmPoolRuntime } else { '' })
    apps = @()
  }
  foreach ($a in (Get-CfmOwnedApps $NormalizedPrefix)) {
    $existed = Test-CfmAppExists $a.AppName
    $cfg = Join-Path $a.Dir 'web.config'
    $ev.apps += [ordered]@{
      kind = $a.Kind; vpath = $a.VPath; app_name = $a.AppName; dir = $a.Dir;
      app_existed = $existed
      prior_physical_path = $(if ($existed) { Get-CfmAppPhysicalPath $a.AppName } else { '' })
      # The PRIOR POOL, captured because restore must put an existing application back in the pool
      # it was in - not in ours. Omitting it meant a rollback silently re-homed somebody else's
      # application into CORPUSfmProxy.
      prior_pool = $(if ($existed) { Get-CfmAppPool $a.AppName } else { '' })
      dir_existed = (Test-Path -LiteralPath $a.Dir)
      dir_sddl = $(if (Test-Path -LiteralPath $a.Dir) { Get-CfmDirectorySddl $a.Dir } else { '' })
      config_existed = (Test-Path -LiteralPath $cfg)
      config_digest = $(if (Test-Path -LiteralPath $cfg) { Get-CfmDigest ((Get-CfmTextFile $cfg).Text) } else { '' })
      # THE BYTES, not just their digest. A `.cfmbak` beside the file cannot survive the directory
      # removal that `remove` now performs, so the restore authority for IIS lives in this one
      # operation-bound, digest-bound record instead of in a sibling file.
      config_body = $(if (Test-Path -LiteralPath $cfg) { (Get-CfmTextFile $cfg).Text } else { '' })
    }
  }
  return $ev
}

# Evidence is OPERATION-BOUND (ruling 6). A fixed `cfm-iis-before.json` cannot say WHICH operation
# it describes, so a later abort could restore one operation's before-image over another's work.
# The name carries the operation id, and the Python recovery record binds this path and its digest.
function Get-CfmEvidencePath {
  param([string]$Operation = '')
  if (-not $IisAppDir) { return '' }
  $id = $Operation
  if (-not $id) { $id = $OperationId }
  if (-not $id) { return '' }
  return (Join-Path (Split-Path -Parent $IisAppDir) "cfm-iis-before-$id.json")
}

function Save-CfmEvidence {
  param([Parameter(Mandatory)][object]$Evidence)
  $path = Get-CfmEvidencePath
  if (-not $path) { return '' }
  $parent = Split-Path -Parent $path
  if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  # ATOMIC and DURABLE (ruling 6): a half-written before-image is worse than none, because a later
  # process would read it as authority. Write beside, flush, then replace in one step.
  $tmp = "$path.new"
  $stream = [System.IO.File]::Create($tmp)
  try {
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(($Evidence | ConvertTo-Json -Depth 8))
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  } finally { $stream.Dispose() }
  [System.IO.File]::Copy($tmp, $path, $true)
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  return $path
}

function Read-CfmEvidence {
  $path = Get-CfmEvidencePath
  if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $null }
  try { $ev = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } catch { return $null }

  # STRICT, INSIDE POWERSHELL, BEFORE ACTING (ruling 6). This record decides what a restoration
  # writes and what it deletes; a shape it cannot fully read is not one to act on partially.
  foreach ($k in @('operation_id', 'proxy_type', 'prefix', 'pool_existed', 'prior_pool_runtime', 'apps')) {
    if ($null -eq $ev.PSObject.Properties[$k]) { return $null }
  }
  if ($OperationId -and $ev.operation_id -ne $OperationId) { return $null }
  if ($ev.proxy_type -ne 'iis') { return $null }
  if ($ev.prefix -ne $pfxForEvidence) { return $null }
  if (-not ($ev.pool_existed -is [bool])) { return $null }
  foreach ($a in @($ev.apps)) {
    foreach ($k in @('kind', 'vpath', 'app_name', 'dir', 'app_existed', 'prior_physical_path',
                     'prior_pool', 'dir_existed', 'dir_sddl', 'config_existed', 'config_digest',
                     'config_body')) {
      if ($null -eq $a.PSObject.Properties[$k]) { return $null }
    }
    if (-not ($a.app_existed -is [bool])) { return $null }
    if (-not ($a.dir_existed -is [bool])) { return $null }
    if (-not ($a.config_existed -is [bool])) { return $null }
    # Bounded to the owned roots, and canonical. A path outside them is not ours to restore or
    # remove, whatever the record says.
    if (-not (Test-CfmBoundedPath $a.dir)) { return $null }
    if ($a.config_digest -and ($a.config_digest -notmatch '^[0-9a-f]{64}$')) { return $null }
  }
  return $ev
}

function Test-CfmBoundedPath {
  param([string]$Candidate)
  if (-not $Candidate) { return $false }
  $full = $null
  try { $full = [System.IO.Path]::GetFullPath($Candidate) } catch { return $false }
  if ($full -ne $Candidate.TrimEnd('\','/')) {
    if ($full -ne $Candidate) { return $false }
  }
  foreach ($root in @($IisAppDir, $MetadataDir)) {
    if (-not $root) { continue }
    $r = $null
    try { $r = [System.IO.Path]::GetFullPath($root) } catch { continue }
    if ($full -eq $r) { return $true }
    if ($full.StartsWith($r.TrimEnd('\','/') + [System.IO.Path]::DirectorySeparatorChar)) { return $true }
    if ($full.StartsWith($r.TrimEnd('\','/') + '/')) { return $true }
  }
  return $false
}

function Clear-CfmEvidence {
  $path = Get-CfmEvidencePath
  if ($path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------------------------------------
if ($Verb -eq 'digest') {
  # The cross-language known-answer entry point (ruling 4). Reads a block on stdin.
  $stdin = [Console]::In.ReadToEnd()
  Write-Output (Get-CfmDigest $stdin)
  exit 0
}

if ($Verb -eq 'family-digest') {
  # The composite known-answer entry point (ruling 3). `-PartsFile` lists `name=path` per line.
  $h = @{}
  foreach ($line in ([System.IO.File]::ReadAllLines($PartsFile))) {
    if (-not $line.Trim()) { continue }
    $i = $line.IndexOf('=')
    $h[$line.Substring(0, $i)] = [System.IO.File]::ReadAllText($line.Substring($i + 1))
  }
  Write-Output (Get-CfmFamilyDigest $h)
  exit 0
}

if ($Verb -eq 'probe') {
  # READ-ONLY Windows observation (ruling 2). Every field is UNKNOWN ($null) until established;
  # an unreadable state is NEVER converted to absent or inactive, because "we could not tell" and
  # "it is not there" lead to opposite decisions and only one of them is safe.
  $pfx = Get-CfmNormalizedPrefix $Prefix
  $iisAvailable = Test-CfmIisAvailable
  $appsPresent = $null
  if ($iisAvailable -and $IisAppDir -and $MetadataDir) {
    $all = @(Get-CfmOwnedApps $pfx)
    $present = @($all | Where-Object { Test-CfmAppExists $_.AppName })
    # COMPLETE presence or COMPLETE absence. A partial family is neither, and reporting it as
    # present would let a reconcile skip the missing members.
    if ($present.Count -eq $all.Count) { $appsPresent = $true }
    elseif ($present.Count -eq 0) { $appsPresent = $false }
    else { $appsPresent = $null }
  }

  # THE OBSERVED FAMILY DIGEST, WHICH THIS VERB ALWAYS KNEW HOW TO COMPUTE (packet 1246-10-04).
  # `proxy_inventory._observe_iis` reads `iis_fingerprint` out of this report and
  # `proxy_policy.decide` compares it against the manifest's stored value to decide drift - and no
  # verb ever emitted the key. Two consumers, zero producers, so `obs.fingerprint` was always $null
  # for IIS. That is harmless until a fingerprint is STORED: the comparison then reads
  # `<digest> == None`, and a byte-identical family is refused as "edited outside CORPUSfm". It
  # appeared the moment generation 12 became the first successful Windows IIS publication.
  # Measured on winfms2026, 2026-08-09: desired == stored == the `observe` verb's answer, all three
  # 8c39ec37..., while the probe emitted no key at all.
  #
  # The SAME renderer and the SAME digest as every other caller - `Get-CfmIisFamilyParts` and
  # `Get-CfmFamilyDigest`, which `observe` also uses. A second algorithm here would be a second
  # opinion about the question drift detection exists to ask.
  #
  # COMPLETE PRESENCE ONLY. Absence has no family and reports no digest; a partial or unreadable
  # family stays UNKNOWN, because a digest computed over some of the parts is not this family's
  # fingerprint and would read as drift against the whole one.
  $iisFingerprint = $null
  $iisAppPath = $null
  if ($appsPresent -eq $true) {
    try {
      $iisFingerprint = Get-CfmFamilyDigest (Get-CfmIisFamilyParts $pfx)
      # The manifest records WHERE the family was published as well as WHAT was published. The
      # inventory consumer has always read `iis_app_path`, but this probe never emitted it; the
      # first successful IIS publication therefore carried a digest beside a null location and an
      # ordinary uninstall had no recorded front it could safely remove.
      $iisAppPath = [IO.Path]::GetFullPath($IisAppDir)
    } catch {
      # A partial observation is no authority. Keep both fields unknown rather than pairing a
      # digest with a location that was not established by the same read.
      $iisFingerprint = $null
      $iisAppPath = $null
    }
  }

  # Claris nginx: installed = FMS ships the front on this box; active = it is the SELECTED front.
  $clarisInstalled = $null
  $clarisActive = $null
  $selectedFront = $null
  if ($FmsRoot -and (Test-Path -LiteralPath $FmsRoot)) {
    $conf = Join-Path $FmsRoot 'NginxServer\conf\fms_nginx.conf'
    $clarisInstalled = (Test-Path -LiteralPath $conf)
    if ($clarisInstalled) {
      # LISTENER OWNERSHIP, strengthened (ruling 2): an nginx listener counts only when its
      # executable resolves INSIDE the verified FMS root. A system nginx on :443 is somebody
      # else's web server and must never make CORPUSfm believe the Claris front is selected.
      try {
        # IIS normally listens through the kernel HTTP service. Its owning process is `System`,
        # and Windows deliberately exposes no executable Path for that protected process. Keep
        # process NAMES for the bounded IIS attribution and executable PATHS for the stronger
        # Claris-nginx attribution. Filtering on Path before reading ProcessName made a settled
        # IIS front unobservable whenever the dormant Claris nginx files were also installed.
        $ownerPaths = @()
        $ownerNames = @()
        $conns = Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction Stop
        foreach ($c in $conns) {
          $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
          if ($proc) {
            if ($proc.ProcessName) { $ownerNames += $proc.ProcessName }
            if ($proc.Path) { $ownerPaths += $proc.Path }
          }
        }
        $fmsOwned = @($ownerPaths | Where-Object { $_ -like (Join-Path $FmsRoot '*') -and $_ -match 'nginx' })
        $iisOwned = @($ownerNames | Where-Object { $_ -in @('System','svchost','w3wp','inetinfo') })
        if ($fmsOwned.Count -gt 0 -and $iisOwned.Count -eq 0) {
          $clarisActive = $true; $selectedFront = 'claris-nginx'
        }
        elseif ($fmsOwned.Count -eq 0 -and $iisOwned.Count -gt 0) {
          $clarisActive = $false; $selectedFront = 'iis'
        }
        else { $clarisActive = $null; $selectedFront = $null }
      } catch {
        # Unreadable listener state stays UNKNOWN. Never inactive.
        $clarisActive = $null; $selectedFront = $null
      }
    } else {
      $clarisActive = $false; $selectedFront = $(if ($iisAvailable) { 'iis' } else { $null })
    }
  }

  $probe = [ordered]@{
    iis_available = $iisAvailable
    iis_apps_present = $appsPresent
    claris_installed = $clarisInstalled
    claris_active = $clarisActive
    selected_front = $selectedFront
    iis_fingerprint = $iisFingerprint
    iis_app_path = $iisAppPath
  }
  Write-Output ($probe | ConvertTo-Json -Compress -Depth 5)
  exit 0
}

if (-not $FmsRoot) { Deny 'a verified FMS root is required; detection is bounded to it' }
if (-not (Test-Path -LiteralPath $FmsRoot)) { Deny "the FMS root '$FmsRoot' is not a directory" }

# ---------------------------------------------------------------------------------------------
if ($Type -eq 'claris-nginx') {
  $activeVerb = ($Verb -in @('publish-active','remove-active'))
  # Ordinary verbs retain their old contract. Only the explicit active verbs can stage a change
  # for the provider's fmsadmin activation cohort, and only when the caller independently observed
  # this as the selected front.
  if ($ClarisNginxActive -and $Verb -in @('publish','remove')) {
    Deny ("Claris nginx is the ACTIVE front; ordinary $Verb cannot activate a live edit. " +
          "Use the bounded $Verb-active operation so staging, activation and rollback remain one transaction.")
  }
  if ($activeVerb -and -not $ClarisNginxActive) {
    Deny "$Verb requires an independently observed active Claris nginx front"
  }
  $conf = Join-Path $FmsRoot 'NginxServer\conf\fms_nginx.conf'
  if (-not (Test-Path -LiteralPath $conf)) { Deny "no FMS nginx configuration at $conf" }
  $inc = Join-Path $FmsRoot "NginxServer\conf\$($script:CfmIncludeName)"

  $info = Get-CfmTextFile $conf
  $state = Get-CfmMarkerState $info.Text
  if ($state -eq 'invalid') {
    Deny "the ###$($script:CfmMark) markers in $conf are neither absent nor one balanced pair"
  }
  if ($Verb -eq 'observe') {
    if ($state -eq 'none') { Pass 'no CORPUSfm block present' }
    Pass 'CORPUSfm block present' (Get-CfmDigest (Get-CfmMarkedBlock $info.Text))
  }
  if ($Verb -eq 'prepare') {
    # Stage one changes NOTHING. The actual publish/remove creates the exact sibling backups; their
    # absence is therefore the clean classification for a crash after prepare and before mutation.
    if (Test-CfmResidue $conf) {
      Deny 'an unresolved Claris transaction residue is present; resolve it before preparing'
    }
    Pass 'Claris before-image is readable and no transaction residue exists; nothing was changed'
  }
  if ($Verb -eq 'classify') {
    # A backup can only be created by the mutating verb after prepare's residue refusal. Its
    # presence means the family may differ and must go through restore; absence means prepare was
    # interrupted before any byte changed.
    $changed = Test-CfmResidue $conf
    Pass $(if ($changed) { 'the Claris family may differ from its before-image' }
           else { 'the Claris family is unchanged since prepare' }) '' '' $null (-not $changed)
  }
  if ($Verb -eq 'restore') {
    $restored = Restore-CfmClarisFamily -Conf $conf -Include $inc
    if (-not $restored.Ok) {
      Fail "restoration could not be verified: $($restored.Detail); backups retained" $true $false
    }
    Remove-CfmBackup $conf
    Remove-Item -LiteralPath (Get-CfmBackupPath $inc) -Force -ErrorAction SilentlyContinue
    PassRestored 'restored byte-exactly; the lifecycle provider owns any required activation restart'
  }
  if ($Verb -eq 'retire') {
    Remove-CfmBackup $conf
    Remove-Item -LiteralPath "$inc.cfmbak" -Force -ErrorAction SilentlyContinue
    Pass 'backups retired'
  }
  if (Test-CfmResidue $conf) { Deny 'an unresolved transaction residue is present; resolve it first' }
  $isPublish = ($Verb -in @('publish','publish-active'))
  if ($isPublish) {
    if (-not (Test-Path -LiteralPath $BlockFile)) { Deny '-BlockFile is required for publish; this executor never renders its own block' }
    if (-not (Test-Path -LiteralPath $IncludeFile)) { Deny '-IncludeFile is required to publish an nginx front' }
  }

  # BRACE-AWARE placement (ruling 5). The include body contains `location` directives, which nginx
  # accepts only inside a `server` block, so the include DIRECTIVE must land inside the unique 443
  # server block and never in main context. Braces inside `#` comments are ignored, and zero /
  # multiple / unbalanced blocks REFUSE rather than guess.
  function Find-Cfm443ServerBlock {
    param([Parameter(Mandatory)][string]$Text)
    $serverRe = [regex]'(?m)^[ \t]*server[ \t]*\{'
    $listen443Re = [regex]'(?m)^[ \t]*listen[^;#]*\b443\b'
    $found = @()
    foreach ($m in $serverRe.Matches($Text)) {
      $open = $Text.IndexOf('{', $m.Index)
      if ($open -lt 0) { continue }
      $depth = 0; $i = $open; $close = -1
      while ($i -lt $Text.Length) {
        $ch = $Text[$i]
        if ($ch -eq '#') {
          $nl = $Text.IndexOf("`n", $i)
          if ($nl -lt 0) { break }
          $i = $nl + 1; continue
        }
        if ($ch -eq '{') { $depth++ }
        elseif ($ch -eq '}') { $depth--; if ($depth -eq 0) { $close = $i; break } }
        $i++
      }
      if ($close -lt 0) { return @{ Ok = $false; Reason = 'unbalanced braces in a server block' } }
      $body = $Text.Substring($open, $close - $open + 1)
      if ($listen443Re.IsMatch($body)) { $found += @{ Start = $m.Index; Open = $open; Close = $close } }
    }
    if ($found.Count -eq 0) { return @{ Ok = $false; Reason = 'no server block listens on 443' } }
    if ($found.Count -gt 1) { return @{ Ok = $false; Reason = "ambiguous: $($found.Count) server blocks listen on 443" } }
    $b = $found[0]
    $lineStart = $Text.LastIndexOf("`n", $b.Close)
    return @{ Ok = $true; Reason = 'unique 443 server block'; InsertAt = ($lineStart + 1) }
  }

  # Strip a prior block by LINE INDEX (never a stateful toggle), then insert the new one.
  $lines = $info.Text -split "`r?`n"
  $re = [regex]"^[ `t]*#+[ `t]*$($script:CfmMark)[ `t]*$"
  $idx = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($re.IsMatch($lines[$i])) { $idx += $i } }
  if ($idx.Count -eq 2) {
    $keep = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($i -lt $idx[0] -or $i -gt $idx[1]) { $keep += $lines[$i] } }
  } else { $keep = $lines }
  $stripped = ($keep -join $info.Newline)

  if ($isPublish) {
    $where = Find-Cfm443ServerBlock $stripped
    if (-not $where.Ok) { Deny "cannot place the CORPUSfm include: $($where.Reason)" }
  }

  $bak = New-CfmBackup $conf
  # The include is CORPUSfm's OWN file, so restoring the host config is only half of a restore: a
  # leftover include is a live edit nobody agreed to keep. Its backup answers the one question that
  # matters - did it exist before this run.
  if (Test-Path -LiteralPath $inc) { Copy-Item -LiteralPath $inc -Destination "$inc.cfmbak" -Force }

  if ($isPublish) {
    $blockText = Get-CfmCanonicalText ([System.IO.File]::ReadAllText($BlockFile))
    $incText = Get-CfmCanonicalText ([System.IO.File]::ReadAllText($IncludeFile))
    Write-CfmBytesAtomic -Path $inc -Text ($incText + $info.Newline) -HasBom $false
    $where = Find-Cfm443ServerBlock $stripped
    $indented = (($blockText -split "`n") -join $info.Newline) + $info.Newline
    $final = $stripped.Substring(0, $where.InsertAt) + $indented + $stripped.Substring($where.InsertAt)
    Write-CfmBytesAtomic -Path $conf -Text $final -HasBom $info.HasBom
  } else {
    Remove-Item -LiteralPath $inc -Force -ErrorAction SilentlyContinue
    Write-CfmBytesAtomic -Path $conf -Text $stripped -HasBom $info.HasBom
  }

  $resolvedNginx = Resolve-CfmFmsNginx $FmsRoot
  $validation = $null
  if (-not $activeVerb -and $resolvedNginx.Exe) {
    $validation = Invoke-CfmFmsNginx -Root $FmsRoot -Mode test
  }
  if ($null -ne $validation -and -not $validation.Ok) {
    $why = "validation failed (exit $($validation.ExitCode)): $($validation.Output)"
    $restored = Restore-CfmClarisFamily -Conf $conf -Include $inc
    if ($restored.Ok) {
      Remove-CfmBackup $conf
      Remove-Item -LiteralPath (Get-CfmBackupPath $inc) -Force -ErrorAction SilentlyContinue
      Fail "$why; exact bytes restored and verified (nothing was activated)" $true $true
    }
    Fail "$why AND restoration could not be verified: $($restored.Detail); backups retained" $true $false
  }
  # The backup STAYS until `retire`: removing it here would leave the window between a live edit and
  # a published manifest with no restore point - the exact window a crash lands in.
  $fp = ''
  if ($isPublish) {
    # Planning compares the WHOLE owned family: the marked include directive plus the include
    # body. Returning only the marked-block digest makes every honest publication disagree with
    # the rendering that produced it and forces the lifecycle layer to restore correct bytes.
    $fp = Get-CfmFamilyDigest @{
      block = (Get-CfmMarkedBlock ((Get-CfmTextFile $conf).Text))
      include = [System.IO.File]::ReadAllText($inc)
    }
  }
  $activation = $(if ($activeVerb) { 'staged for authenticated fmsadmin activation' } else { 'validated while inactive' })
  Pass "$Verb $activation" $fp $bak
}

if ($Verb -in @('publish-active','remove-active')) {
  Deny "$Verb is valid only for the claris-nginx proxy type"
}

# ---------------------------------------------------------------------------------------------
# iis: CORPUSfm's OWN pool, primary application, physical dir, web.config, and one exact-path
# metadata child application per MCP route. Publication IS activation.
# ---------------------------------------------------------------------------------------------
if (-not $IisAppDir) { Deny '-IisAppDir is required for the iis type' }
if (-not $MetadataDir) { Deny '-MetadataDir is required for the iis type' }
if (-not (Test-CfmIisAvailable)) { Deny 'IIS is not available on this machine (appcmd.exe was not found)' }

$pfx = Get-CfmNormalizedPrefix $Prefix
$owned = @(Get-CfmOwnedApps $pfx)

switch ($Verb) {
  'observe' {
    $present = @($owned | Where-Object { Test-CfmAppExists $_.AppName })
    if ($present.Count -eq 0) { Pass 'the CORPUSfm IIS application family is not mounted' }
    if ($present.Count -lt $owned.Count) {
      # PARTIAL IS DRIFT, not present (ruling 5). Returning a fingerprint for a half-mounted family
      # would let planning compare it against a complete desired family and call the difference an
      # ordinary mutation, when what is actually true is that the installation is in a state nobody
      # published.
      Deny ("the CORPUSfm IIS application family is INCOMPLETE ($($present.Count)/$($owned.Count) " +
            'mounted); this is drift, not an absence. Inspect the site, then re-run.')
    }
    # The WHOLE family, read back - pool, every application definition, every web.config.
    Pass 'the CORPUSfm IIS application family is present' (Get-CfmFamilyDigest (Get-CfmIisFamilyParts $pfx))
  }

  'publish' {
    if (-not (Test-Path -LiteralPath $WebConfigFile)) { Deny '-WebConfigFile is required for an iis publish' }
    if (Test-CfmResidue (Join-Path $IisAppDir 'web.config')) {
      Deny 'an unresolved transaction residue is present; resolve it first'
    }
    # BEFORE-IMAGE FIRST (ruling 1). Rollback may remove only what this run created, and that is
    # unanswerable after the fact - so it is recorded before the first change.
    $before = Get-CfmIisBeforeImage $pfx
    Save-CfmEvidence $before

    if (-not $before.pool_existed) {
      $r = Invoke-CfmAppCmd @('add', 'apppool', "/name:$($script:CfmPool)", '/managedRuntimeVersion:')
      if ($r.ExitCode -ne 0) { Fail "'appcmd add apppool' failed (exit $($r.ExitCode)): $("$($r.Output)".Trim())" }
    }

    $webText = Get-CfmCanonicalText ([System.IO.File]::ReadAllText($WebConfigFile))
    foreach ($a in $owned) {
      New-Item -ItemType Directory -Force -Path $a.Dir | Out-Null
      Grant-CfmPoolReadAccess $a.Dir
      $cfg = Join-Path $a.Dir 'web.config'
      if (Test-Path -LiteralPath $cfg) { $null = New-CfmBackup $cfg }
      if ($a.Kind -eq 'primary') {
        Write-CfmBytesAtomic -Path $cfg -Text $webText -HasBom $false
      } else {
        $mf = Join-Path $MetadataDir ((($a.VPath) -replace '[^A-Za-z0-9]', '_').Trim('_') + '.webconfig')
        if (-not (Test-Path -LiteralPath $mf)) { Fail "the rendered metadata web.config for $($a.VPath) was not supplied at $mf" }
        Write-CfmBytesAtomic -Path $cfg -Text (Get-CfmCanonicalText ([System.IO.File]::ReadAllText($mf))) -HasBom $false
      }
      if (-not (Test-CfmAppExists $a.AppName)) {
        # CREATE with the pool in ONE operation - a follow-up `set app` on a leading-dot vpath is
        # the failure mode where appcmd exits zero without persisting the application.
        $r = Invoke-CfmAppCmd @('add', 'app', "/site.name:$Site", "/path:$($a.VPath)",
                                "/physicalPath:$($a.Dir)", "/applicationPool:$($script:CfmPool)")
        if ($r.ExitCode -ne 0) { Fail "'appcmd add app' failed (exit $($r.ExitCode)) for $($a.AppName): $("$($r.Output)".Trim())" }
      } else {
        # RECONCILE BOTH (ruling 5). An existing application may be in the wrong pool AND pointed at
        # the wrong directory; setting only the pool left a live application serving somebody else's
        # physical path while everything reported success.
        $r = Invoke-CfmAppCmd @('set', 'app', "/app.name:$($a.AppName)", "/applicationPool:$($script:CfmPool)")
        if ($r.ExitCode -ne 0) { Fail "'appcmd set app' (pool) failed (exit $($r.ExitCode)) for $($a.AppName): $("$($r.Output)".Trim())" }
        $r = Invoke-CfmAppCmd @('set', 'vdir', "/vdir.name:$($a.AppName)/", "/physicalPath:$($a.Dir)")
        if ($r.ExitCode -ne 0) { Fail "'appcmd set vdir' (physicalPath) failed (exit $($r.ExitCode)) for $($a.AppName): $("$($r.Output)".Trim())" }
      }
      # EFFECTIVE READBACK. An exit-0 that did not persist is still failure, so registration is
      # re-read rather than inferred from the exit code - and so are the two settings this run just
      # reconciled.
      if (-not (Test-CfmAppExists $a.AppName)) {
        Fail "the application $($a.AppName) is NOT registered after create/repair"
      }
      # EXACT equality (ruling 6). `if ($seen -and $seen -ne ...)` passed on an EMPTY answer, so an
      # unreadable setting read as a correct one - the readback rule defeating itself.
      $seenPath = Get-CfmAppPhysicalPath $a.AppName
      if ($seenPath -ne $a.Dir) {
        Fail "the application $($a.AppName) points at '$seenPath', not '$($a.Dir)', after reconciliation"
      }
      $seenPool = Get-CfmAppPool $a.AppName
      if ($seenPool -ne $script:CfmPool) {
        Fail "the application $($a.AppName) is in pool '$seenPool', not '$($script:CfmPool)', after reconciliation"
      }
    }
    if (-not (Test-CfmPoolExists)) { Fail "the application pool $($script:CfmPool) is NOT registered after publish" }
    $seenRuntime = Get-CfmPoolRuntime
    if ($null -eq $seenRuntime) { Fail "the pool runtime setting could not be read back after publish" }
    $cfg = Join-Path $IisAppDir 'web.config'
    Pass 'published (the isolated IIS applications are live without an FMS restart)' `
         (Get-CfmFamilyDigest (Get-CfmIisFamilyParts $pfx)) (Get-CfmBackupPath $cfg) $before `
         $null ([IO.Path]::GetFullPath($IisAppDir))
  }

  'prepare' {
    # STAGE ONE (ruling 4). Capture the before-image; change NOTHING. A crash here leaves evidence
    # and an untouched box - cleanly classifiable, which "did a mutation begin?" is not.
    if (-not $OperationId) { Deny '-OperationId is required to capture a before-image' }
    $before = Get-CfmIisBeforeImage $pfx
    $path = Save-CfmEvidence $before
    if (-not $path) { Fail 'the before-image could not be published' }
    # THE PATH, NOT THE IMAGE (packet 1246-10-04). This returned `$before` - the before-image
    # object - where the lifecycle layer requires the path the line above just wrote it to, so
    # `proxy_transaction.bind_evidence` crashed with `TypeError: expected str, bytes or
    # os.PathLike object, not dict` inside the transaction rather than refusing outside it.
    # Measured on winfms2026, 2026-08-09, at generation 4. `bind_evidence` needs the path because
    # it digest-binds the BYTES ON DISK: a path alone binds nothing, and an image alone names no
    # file to re-read before a restoration. The POSIX executor has always returned a path here,
    # which is why this was Windows-only.
    Pass 'before-image captured; nothing was changed' '' '' $path
  }

  'classify' {
    # RECOVERY CLASSIFICATION (Codex final check). Does the owned family still match the
    # before-image this operation captured? `prepare` changes nothing, so an interruption between
    # it and the mutation leaves a durable `prepared` record over an untouched box - and restoring
    # blindly there fails for the absence of a backup publication never created.
    #
    # `unchanged` is never guessed: unreadable or absent evidence answers `null`, which the caller
    # treats as "may have changed".
    $ev = Read-CfmEvidence
    if ($null -eq $ev) { Deny 'no readable before-image for this operation' }
    $same = $true
    if ((Get-CfmPoolState) -ne $ev.pool_existed) { $same = $false }
    foreach ($a in $ev.apps) {
      $state = Get-CfmAppState $a.app_name
      if ($null -eq $state) { $same = $false; break }        # unread is not unchanged
      if ($state -ne $a.app_existed) { $same = $false; break }
      $cfg = Join-Path $a.dir 'web.config'
      $present = Test-Path -LiteralPath $cfg
      if ($present -ne $a.config_existed) { $same = $false; break }
      if ($present) {
        if ((Get-CfmDigest ((Get-CfmTextFile $cfg).Text)) -ne $a.config_digest) { $same = $false; break }
      }
      if ($state) {
        if ((Get-CfmAppPhysicalPath $a.app_name) -ne $a.prior_physical_path) { $same = $false; break }
        if ((Get-CfmAppPool $a.app_name) -ne $a.prior_pool) { $same = $false; break }
      }
    }
    if ($same) { Pass 'the artifact family still matches its before-image' '' '' (Get-CfmEvidencePath) $true }
    Pass 'the artifact family differs from its before-image' '' '' (Get-CfmEvidencePath) $false
  }

  'remove' {
    $before = Get-CfmIisBeforeImage $pfx
    Save-CfmEvidence $before
    foreach ($a in $owned) {
      $cfg = Join-Path $a.Dir 'web.config'
      # The before-image captured above already holds these bytes and their digest, which is what
      # makes an abort of a `remove` possible now that the directory itself is removed - a sibling
      # `.cfmbak` would go with it.
      if (Test-CfmAppExists $a.AppName) {
        $r = Invoke-CfmAppCmd @('delete', 'app', "/app.name:$($a.AppName)")
        if ($r.ExitCode -ne 0) { Fail "'appcmd delete app' failed (exit $($r.ExitCode)) for $($a.AppName): $("$($r.Output)".Trim())" }
      }
      Remove-Item -LiteralPath $cfg -Force -ErrorAction SilentlyContinue
      # EFFECTIVE READBACK of ABSENCE.
      if (Test-CfmAppExists $a.AppName) { Fail "the application $($a.AppName) is still registered after delete" }
      # THE OWNED PHYSICAL DIRECTORY GOES TOO (ruling 6) - but only when it holds nothing but what
      # we put there. Unexpected content is somebody else's, and deleting it because it sits in a
      # directory we created is not a removal, it is data loss.
      if (Test-Path -LiteralPath $a.Dir) {
        $left = @(Get-ChildItem -LiteralPath $a.Dir -Force -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -ne 'web.config' -and $_.Name -notlike '*.cfmbak' })
        if ($left.Count -gt 0) {
          Fail ("$($a.Dir) holds content this installation did not put there " +
                "($($left[0].Name)); refusing to remove it")
        }
        Remove-Item -LiteralPath $a.Dir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $a.Dir) { Fail "$($a.Dir) is still present after removal" }
      }
    }
    # `CORPUSfmProxy` is EXCLUSIVELY CORPUSfm-owned (ruling 5), so `remove` deletes the complete
    # family INCLUDING the pool. An earlier version kept a pool that existed before the remove
    # operation, reasoning it might be shared - but a pool this packet declares exclusive ownership
    # of cannot be shared, and keeping it left an uninstall visibly incomplete.
    #
    # `restore` is the different question: there, "existed before" means before THIS OPERATION
    # created it, and a pool the operation did not create is put back.
    if (Test-CfmPoolExists) {
      $r = Invoke-CfmAppCmd @('delete', 'apppool', "/apppool.name:$($script:CfmPool)")
      if ($r.ExitCode -ne 0) { Fail "'appcmd delete apppool' failed (exit $($r.ExitCode)): $("$($r.Output)".Trim())" }
    }
    if (Test-CfmPoolExists) { Fail "the application pool $($script:CfmPool) is still registered after delete" }
    Pass 'the CORPUSfm IIS artifacts were removed' '' '' $before
  }

  'restore' {
    # Rollback removes ONLY run-created objects and restores every pre-existing definition and byte.
    $ev = Read-CfmEvidence
    if ($null -eq $ev) {
      Fail 'no before-image evidence for this operation; refusing to guess what this run created' $true $false
    }
    foreach ($a in $ev.apps) {
      $cfg = Join-Path $a.dir 'web.config'
      if ($a.config_existed) {
        # Restored FROM THE RECORD, then verified against the digest the record bound. The bytes
        # travel with the evidence precisely so a removed directory cannot take them with it.
        if (-not (Test-Path -LiteralPath $a.dir)) { New-Item -ItemType Directory -Force -Path $a.dir | Out-Null }
        Write-CfmBytesAtomic -Path $cfg -Text $a.config_body -HasBom $false
        if ((Get-CfmDigest ((Get-CfmTextFile $cfg).Text)) -ne $a.config_digest) {
          Fail "the restored web.config for $($a.app_name) does not match its before-image digest" $true $false
        }
      } else {
        Remove-Item -LiteralPath $cfg -Force -ErrorAction SilentlyContinue
      }
      if ($a.app_existed) {
        # Restore the application AND its prior path and pool. Recreating it in OUR pool, or at OUR
        # physical path, would silently re-home somebody else's application - a rollback that leaves
        # the box changed is not a rollback.
        $priorPool = $a.prior_pool
        if (-not $priorPool) { $priorPool = $script:CfmPool }
        if (-not (Test-CfmAppExists $a.app_name)) {
          $r = Invoke-CfmAppCmd @('add', 'app', "/site.name:$Site", "/path:$($a.vpath)",
                                  "/physicalPath:$($a.prior_physical_path)", "/applicationPool:$priorPool")
          if ($r.ExitCode -ne 0) { Fail "could not restore the pre-existing application $($a.app_name)" $true $false }
        } else {
          $r = Invoke-CfmAppCmd @('set', 'app', "/app.name:$($a.app_name)", "/applicationPool:$priorPool")
          if ($r.ExitCode -ne 0) { Fail "could not restore the prior pool of $($a.app_name)" $true $false }
          $r = Invoke-CfmAppCmd @('set', 'vdir', "/vdir.name:$($a.app_name)/",
                                  "/physicalPath:$($a.prior_physical_path)")
          if ($r.ExitCode -ne 0) { Fail "could not restore the prior physical path of $($a.app_name)" $true $false }
        }
        if (-not (Test-CfmAppExists $a.app_name)) { Fail "the pre-existing application $($a.app_name) is still absent" $true $false }
        $seenPath = Get-CfmAppPhysicalPath $a.app_name
        if ($seenPath -ne $a.prior_physical_path) {
          Fail "the restored $($a.app_name) points at '$seenPath', not its prior '$($a.prior_physical_path)'" $true $false
        }
        $seenPool = Get-CfmAppPool $a.app_name
        if ($seenPool -ne $priorPool) {
          Fail "the restored $($a.app_name) is in pool '$seenPool', not its prior '$priorPool'" $true $false
        }
      } else {
        if (Test-CfmAppExists $a.app_name) {
          $r = Invoke-CfmAppCmd @('delete', 'app', "/app.name:$($a.app_name)")
          if ($r.ExitCode -ne 0) { Fail "could not remove the run-created application $($a.app_name)" $true $false }
        }
        if (Test-CfmAppExists $a.app_name) { Fail "the run-created application $($a.app_name) is still registered" $true $false }
        if (-not $a.dir_existed) { Remove-Item -LiteralPath $a.dir -Recurse -Force -ErrorAction SilentlyContinue }
      }
      if ($a.dir_existed) {
        Set-CfmDirectorySddl -Path $a.dir -Sddl $a.dir_sddl
        if ((Get-CfmDirectorySddl $a.dir) -ne $a.dir_sddl) {
          Fail "the restored DACL on $($a.dir) does not match its before-image" $true $false
        }
      }
    }
    if (-not $ev.pool_existed -and (Test-CfmPoolExists)) {
      $r = Invoke-CfmAppCmd @('delete', 'apppool', "/apppool.name:$($script:CfmPool)")
      if ($r.ExitCode -ne 0) { Fail 'could not remove the run-created application pool' $true $false }
    }
    if ($ev.pool_existed) {
      if (-not (Test-CfmPoolExists)) {
        # A `remove` deleted it; restoring the operation must put it back with its prior setting.
        $r = Invoke-CfmAppCmd @('add', 'apppool', "/name:$($script:CfmPool)",
                                "/managedRuntimeVersion:$($ev.prior_pool_runtime)")
        if ($r.ExitCode -ne 0) { Fail 'could not restore the pre-existing application pool' $true $false }
      }
      if (-not (Test-CfmPoolExists)) { Fail 'the pre-existing application pool is missing after restoration' $true $false }
      $seenRuntime = Get-CfmPoolRuntime
      if ($seenRuntime -ne $ev.prior_pool_runtime) {
        Fail "the restored pool runtime is '$seenRuntime', not its prior '$($ev.prior_pool_runtime)'" $true $false
      }
    }
    # RESTORE DOES NOT CLEAR THE EVIDENCE (packet 1246-10-04). It did, and the lifecycle layer had
    # not resolved yet: the run rolled back, this line deleted the before-image the recovery record
    # binds by digest, and the journal was left `needs_recovery` over an operation whose evidence no
    # longer existed - so `proxy abort` refused ("could not be read") and `discard-provider` refused
    # a record that was not resolved. Measured on winfms2026, 2026-08-09, operation 515b6d84.
    # `retire` is the sole verb that deletes a before-image, and it runs AFTER the lifecycle layer
    # has resolved. Restoration and its verification are unchanged.
    PassRestored 'restored and verified (only run-created objects were removed)'
  }

  'retire' {
    foreach ($a in $owned) { Remove-CfmBackup (Join-Path $a.Dir 'web.config') }
    Clear-CfmEvidence
    Pass 'backups and before-image evidence retired'
  }
}
