<#
  Semantic tests for installer/windows/cfm-proxy-exec.ps1 (packet 1246-06 section 6.5, 14).

  The packet requires EXECUTED semantic tests for both executors - static source-string assertions
  are insufficient. So this runs the real script, as a process, against a real fixture FMS root and
  a STUBBED appcmd, and reads the real JSON it emits. Nothing here touches a real FileMaker Server
  or a real IIS, which is also what proves the executor is bounded to what it is handed.

  The appcmd stub is a real program with real state (a JSON file of pools and apps), not a mock
  returning canned strings: the behaviour under test is a sequence of create/read-back/delete
  operations whose whole point is that the read-back can DISAGREE with the exit code. A stub that
  simply echoed success would prove nothing about the readback rule.

  Real Windows execution - a real IIS, a real appcmd, a real Get-NetTCPConnection - remains a
  1246-10 gate. This suite proves policy and structure, not that IIS accepts these calls.

  Runs on PowerShell 7+ (macOS/Linux) and Windows PowerShell 5.1. Exits non-zero on any failure.
#>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exec = Join-Path $here '..\..\installer\windows\cfm-proxy-exec.ps1'
$exec = [System.IO.Path]::GetFullPath($exec.Replace('\', [System.IO.Path]::DirectorySeparatorChar))

$script:fails = 0
$script:count = 0
function Assert($cond, $name) {
  $script:count++
  if ($cond) { Write-Output "  PASS $name" } else { Write-Output "  FAIL $name"; $script:fails++ }
}
function AssertEq($a, $b, $name) { Assert ($a -eq $b) ("$name (got '$a' want '$b')") }

$MARK = 'CORPUSFM'
$NGINX_BODY = @"
http {
    server {
        listen 80;
        server_name _;
    }
    server {
        listen 443 ssl;
        include "fms_fac.conf";
        ###OTTO
        include "otto_https.conf";
        ###OTTO
    }
}
"@

# ---------------------------------------------------------------------------------------------
# A stateful appcmd stub. Pools and apps live in a JSON file the stub reads and writes, so a create
# followed by a read-back sees what the create actually did - which is the whole point of the
# post-condition rule: an exit-zero appcmd call must still read back at the requested state.
# ---------------------------------------------------------------------------------------------
$STUB = @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Argv)
$state = $env:CFM_APPCMD_STATE
if (-not (Test-Path -LiteralPath $state)) {
  '{"pools":[],"apps":{}}' | Set-Content -LiteralPath $state -Encoding utf8
}
$s = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
function Save($obj) { $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $env:CFM_APPCMD_STATE -Encoding utf8 }
function Pools($obj) { if ($null -eq $obj.pools) { return @() } else { return @($obj.pools) } }
function AppNames($obj) { if ($null -eq $obj.apps) { return @() } else { return @($obj.apps.PSObject.Properties.Name) } }
$verb = $Argv[0]; $kind = $Argv[1]
$named = @{}
foreach ($a in $Argv) { if ($a -match '^/([A-Za-z.]+):(.*)$') { $named[$Matches[1]] = $Matches[2] } }

if ($env:CFM_APPCMD_FAIL -and (($Argv -join ' ') -match [regex]::Escape($env:CFM_APPCMD_FAIL))) {
  Write-Output 'simulated appcmd failure'; exit 7
}
# A create that reports success but does NOT persist - the exact failure the readback rule exists
# to catch. Behind its own variable so only the test that wants it sees it.
$phantom = ($env:CFM_APPCMD_PHANTOM -and ($named['path'] -eq $env:CFM_APPCMD_PHANTOM))

switch ("$verb $kind") {
  'list apppool' {
    if ((Pools $s) -contains $named['apppool.name']) {
      if ($Argv -contains '/text:managedRuntimeVersion') { Write-Output ([string]$s.poolRuntime) }
      else { Write-Output ('APPPOOL "' + $named['apppool.name'] + '"') }
      exit 0
    }
    # Match the real appcmd contract: a missing named pool is exit 1 with empty output.
    exit 1
  }
  'add apppool'  {
    $p = @(Pools $s); $p += $named['name']; $s.pools = $p
    $s | Add-Member -NotePropertyName 'poolRuntime' -NotePropertyValue $named['managedRuntimeVersion'] -Force
    Save $s; exit 0
  }
  'delete apppool' { $s.pools = @(Pools $s | Where-Object { $_ -ne $named['apppool.name'] }); Save $s; exit 0 }
  'list app' {
    $n = $named['app.name']
    if ((AppNames $s) -contains $n) {
      if ($Argv -contains '/text:applicationPool') { Write-Output ([string]$s.apps.$n.pool) }
      else { Write-Output ('APP "' + $n + '"') }
    }
    exit 0
  }
  'list vdir' {
    $n = $named['app.name']
    if ((AppNames $s) -contains $n) { Write-Output $s.apps.$n.physicalPath }
    exit 0
  }
  'add app' {
    if (-not $phantom) {
      $name = $named['site.name'] + $named['path']
      $s.apps | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{
        physicalPath = $named['physicalPath']; pool = $named['applicationPool'] }) -Force
      Save $s
    }
    exit 0
  }
  'set app' {
    $n = $named['app.name']
    if (((AppNames $s) -contains $n) -and $named['applicationPool']) {
      $s.apps.$n.pool = $named['applicationPool']; Save $s
    }
    exit 0
  }
  'set vdir' {
    $n = ($named['vdir.name'] -replace '/$', '')
    if (((AppNames $s) -contains $n) -and $named['physicalPath']) {
      $s.apps.$n.physicalPath = $named['physicalPath']; Save $s
    }
    exit 0
  }
  'delete app' {
    $n = $named['app.name']
    $keep = [pscustomobject]@{}
    foreach ($p in $s.apps.PSObject.Properties) { if ($p.Name -ne $n) { $keep | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value } }
    $s.apps = $keep; Save $s; exit 0
  }
}
exit 0
'@

function NewFmsRoot([string]$NginxText = $NGINX_BODY) {
  $root = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  $conf = Join-Path (Join-Path $root 'NginxServer') 'conf'
  New-Item -ItemType Directory -Force -Path $conf | Out-Null
  [IO.File]::WriteAllText((Join-Path $conf 'fms_nginx.conf'), $NginxText,
                          (New-Object System.Text.UTF8Encoding($false)))
  return $root
}

function ConfOf([string]$Root) {
  return (Join-Path (Join-Path (Join-Path $Root 'NginxServer') 'conf') 'fms_nginx.conf')
}
function IncludeOf([string]$Root) {
  return (Join-Path (Join-Path (Join-Path $Root 'NginxServer') 'conf') 'corpusfm_https.conf')
}
function Digest([string]$Path) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $h = $sha.ComputeHash([IO.File]::ReadAllBytes($Path))
  return (($h | ForEach-Object { $_.ToString('x2') }) -join '')
}

function InstallNginxStub([string]$Root) {
  if ($env:OS -eq 'Windows_NT') { return $false }
  $dir = Join-Path $Root 'Nginx'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $stub = Join-Path $dir 'nginx.exe'
  $body = @'
#!/bin/sh
printf '%s\n' "$*" >> "$CFM_NGINX_LOG"
case " $* " in
  *" -t "*) mode=test ;;
  *" -s reload "*) mode=reload ;;
  *) mode=unknown ;;
esac
if [ "$CFM_NGINX_FAIL_MODE" = "$mode" ]; then exit 7; fi
if [ "$CFM_NGINX_FAIL_MODE" = "reload-once" ] && [ "$mode" = "reload" ]; then
  count=0
  if [ -f "$CFM_NGINX_COUNT" ]; then count=$(cat "$CFM_NGINX_COUNT"); fi
  count=$((count + 1)); printf '%s' "$count" > "$CFM_NGINX_COUNT"
  if [ "$count" -eq 1 ]; then exit 8; fi
fi
exit 0
'@
  [IO.File]::WriteAllText($stub, $body, (New-Object System.Text.UTF8Encoding($false)))
  & chmod '+x' $stub
  return $true
}

# The ONE renderer's output, written where the executor expects it. These tests do not compose
# their own text either - that is the point of ruling 4.
function NewRendered([string]$Root, [string]$Prefix = '/corpusfm', [int]$Port = 8533) {
  $dir = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $inc = IncludeOf $Root
  $block = "# $MARK`n    include `"$inc`";`n# $MARK"
  [IO.File]::WriteAllText((Join-Path $dir 'block.txt'), $block, (New-Object System.Text.UTF8Encoding($false)))
  $body = "location $Prefix/ {`n    proxy_pass http://127.0.0.1:$Port$Prefix/;`n}"
  [IO.File]::WriteAllText((Join-Path $dir 'include.txt'), $body, (New-Object System.Text.UTF8Encoding($false)))
  $web = "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n<configuration><system.webServer><rewrite><rules>" +
         "<rule name=`"corpusfm-proxy`" stopProcessing=`"true`"><match url=`"(.*)`" />" +
         "<action type=`"Rewrite`" url=`"http://127.0.0.1:$Port$Prefix/{R:1}`" /></rule></rules></rewrite></system.webServer></configuration>"
  [IO.File]::WriteAllText((Join-Path $dir 'web.config'), $web, (New-Object System.Text.UTF8Encoding($false)))
  return @{ Dir = $dir; Block = (Join-Path $dir 'block.txt'); Include = (Join-Path $dir 'include.txt');
            Web = (Join-Path $dir 'web.config') }
}

function FamilyDigestOfRendered($Rendered) {
  $parts = Join-Path $Rendered.Dir 'parts.txt'
  [IO.File]::WriteAllLines($parts, @("block=$($Rendered.Block)", "include=$($Rendered.Include)"),
                           (New-Object System.Text.UTF8Encoding($false)))
  $out = & (Get-PsExe) -NoProfile -File $exec -Verb family-digest -PartsFile $parts
  return (($out | Out-String).Trim())
}

function MetadataVpaths([string]$Prefix = '/corpusfm') {
  return @(
    "/.well-known/oauth-protected-resource$Prefix/mcp",
    "/.well-known/oauth-authorization-server$Prefix/mcp",
    "/.well-known/openid-configuration$Prefix/mcp"
  )
}

# Each metadata child application's own rendered web.config, named as the executor derives it.
function NewMetadataRendered([string]$MetadataDir, [int]$Port = 8533, [string]$Prefix = '/corpusfm') {
  New-Item -ItemType Directory -Force -Path $MetadataDir | Out-Null
  foreach ($v in (MetadataVpaths $Prefix)) {
    $slug = ($v -replace '[^A-Za-z0-9]', '_').Trim('_')
    $xml = "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n<configuration><system.webServer><rewrite><rules>" +
           "<rule name=`"corpusfm-mcp-metadata-exact`" stopProcessing=`"true`"><match url=`"^/?`$`" />" +
           "<action type=`"Rewrite`" url=`"http://127.0.0.1:$Port$v`" /></rule></rules></rewrite></system.webServer></configuration>"
    [IO.File]::WriteAllText((Join-Path $MetadataDir "$slug.webconfig"), $xml,
                            (New-Object System.Text.UTF8Encoding($false)))
  }
}

$script:stubPath = Join-Path ([IO.Path]::GetTempPath()) (([IO.Path]::GetRandomFileName()) + '.ps1')
[IO.File]::WriteAllText($script:stubPath, $STUB, (New-Object System.Text.UTF8Encoding($false)))

function Get-PsExe() {
  $p = (Get-Process -Id $PID).Path
  if (-not $p) { $p = 'pwsh' }
  return $p
}

function Invoke-Exec {
  param([string]$Verb, [string]$Type = 'iis', [string]$Root = '', [switch]$ClarisActive,
        [string]$IisAppDir = '', [string]$MetadataDir = '', [object]$Rendered = $null,
        [string]$StatePath = '', [string]$FailOn = '', [string]$Phantom = '',
        [string]$Operation = '11111111-2222-3333-4444-555555555555', [switch]$NoStub)
  $a = @('-NoProfile', '-File', $exec, '-Verb', $Verb, '-Type', $Type, '-Prefix', '/corpusfm')
  if ($Operation) { $a += @('-OperationId', $Operation) }
  if ($Root) { $a += @('-FmsRoot', $Root) }
  if ($ClarisActive) { $a += '-ClarisNginxActive' }
  if ($IisAppDir) { $a += @('-IisAppDir', $IisAppDir) }
  if ($MetadataDir) { $a += @('-MetadataDir', $MetadataDir) }
  if ($Rendered) {
    $a += @('-BlockFile', $Rendered.Block, '-IncludeFile', $Rendered.Include,
            '-WebConfigFile', $Rendered.Web)
  }
  $old = @{ Stub = $env:CFM_APPCMD_STUB; State = $env:CFM_APPCMD_STATE;
            Fail = $env:CFM_APPCMD_FAIL; Phantom = $env:CFM_APPCMD_PHANTOM }
  if (-not $NoStub) { $env:CFM_APPCMD_STUB = $script:stubPath }
  if ($StatePath) { $env:CFM_APPCMD_STATE = $StatePath }
  $env:CFM_APPCMD_FAIL = $FailOn
  $env:CFM_APPCMD_PHANTOM = $Phantom
  try {
    $out = & (Get-PsExe) @a 2>&1
    $text = ($out | Out-String)
    $line = ($text -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
    $json = $null
    if ($line) { $json = ($line | ConvertFrom-Json) }
    return @{ Json = $json; Raw = $text; Code = $LASTEXITCODE }
  } finally {
    $env:CFM_APPCMD_STUB = $old.Stub; $env:CFM_APPCMD_STATE = $old.State
    $env:CFM_APPCMD_FAIL = $old.Fail; $env:CFM_APPCMD_PHANTOM = $old.Phantom
  }
}

function NewIisFixture() {
  $base = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Force -Path $base | Out-Null
  $state = Join-Path $base 'appcmd-state.json'
  '{"pools":[],"apps":{}}' | Set-Content -LiteralPath $state -Encoding utf8
  $meta = Join-Path $base 'proxy-mcp'
  NewMetadataRendered $meta
  return @{ Base = $base; State = $state; App = (Join-Path $base 'proxy'); Meta = $meta }
}

function ReadState([string]$Path) { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) }
function StateApps($st) { if ($null -eq $st.apps) { return @() } else { return @($st.apps.PSObject.Properties.Name) } }
function StatePools($st) { if ($null -eq $st.pools) { return @() } else { return @($st.pools) } }

# ---------------------------------------------------------------------------------------------
Write-Output '== the script is ASCII-only and bounds lifecycle control =='

$raw = [IO.File]::ReadAllBytes($exec)
$nonAscii = @($raw | Where-Object { $_ -gt 0x7F })
AssertEq $nonAscii.Count 0 'ASCII-only (PS 5.1 reads a BOM-less .ps1 as ANSI)'

# The `<# ... #>` header is stripped as well as `#` lines: the header has to NAME what it forbids,
# and a scan that included it would report the rationale as the violation.
$srcText = [IO.File]::ReadAllText($exec)
$srcText = [regex]::Replace($srcText, '(?s)<\#.*?\#>', '')
$srcLines = ($srcText -split "`r?`n") | Where-Object { -not ($_.TrimStart().StartsWith('#')) }
$code = ($srcLines -join "`n")
foreach ($forbidden in @('fmsadmin.exe', 'Restart-Service', 'Stop-Service', 'Start-Service',
                         'taskkill', 'iisreset')) {
  Assert (-not ($code -match [regex]::Escape($forbidden))) "no lifecycle control: $forbidden"
}
Assert (-not ($code -match "'-s'\s*,\s*'reload'")) 'the executor carries no nginx reload construction'
Assert ($code -match "@\('publish-active','remove-active'\)") 'only explicit active verbs stage a live-front change'
Assert ($code -match 'system32.inetsrv.appcmd\.exe') 'appcmd is resolved by ABSOLUTE path'
Assert (-not ($code -match 'Get-Command\s+appcmd')) 'appcmd is never resolved through PATH'

# ---------------------------------------------------------------------------------------------
Write-Output '== the canonical digest (ruling 4) =='

$block = "# $MARK`n    include `"/x/corpusfm_https.conf`";`n# $MARK"
$noisy = [string][char]0xFEFF + ($block -replace "`n", "`r`n") + "`r`n"
$d1 = ($block | & (Get-PsExe) -NoProfile -File $exec -Verb digest) | Out-String
$d2 = ($noisy | & (Get-PsExe) -NoProfile -File $exec -Verb digest) | Out-String
AssertEq $d1.Trim() $d2.Trim() 'a BOM, CRLF and a trailing newline normalize to the same digest'
AssertEq $d1.Trim().Length 64 'the digest is a SHA-256 hex string'

# ---------------------------------------------------------------------------------------------
Write-Output '== the marker-pair policy fails closed and touches nothing =='

foreach ($verb in @('observe', 'publish', 'remove')) {
  $root = NewFmsRoot ($NGINX_BODY + "`n# $MARK`n    include `"x`";`n")   # one UNMATCHED marker
  $conf = ConfOf $root
  $before = Digest $conf
  $r = Invoke-Exec -Verb $verb -Type 'claris-nginx' -Root $root -Rendered (NewRendered $root)
  Assert ($r.Json.ok -eq $false) "$verb refuses an unmatched marker"
  Assert ("$($r.Json.detail)" -match 'balanced pair') "$verb explains the marker refusal"
  AssertEq (Digest $conf) $before "$verb left the file byte-identical while refusing"
}

$root = NewFmsRoot ($NGINX_BODY + "`n# $MARK`na`n# $MARK`nb`n# $MARK`n")
$r = Invoke-Exec -Verb 'observe' -Type 'claris-nginx' -Root $root
Assert ($r.Json.ok -eq $false) 'three markers refuse too'

# The discriminating half - otherwise the refusals above could pass by refusing everything.
$root = NewFmsRoot
$r = Invoke-Exec -Verb 'observe' -Type 'claris-nginx' -Root $root
Assert ($r.Json.ok -eq $true) 'an absent block observes cleanly'
Assert ("$($r.Json.detail)" -match 'no CORPUSfm block') 'absent is reported as absent'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 5: the include lands INSIDE the unique 443 server block =='

$root = NewFmsRoot
$conf = ConfOf $root
$r = Invoke-Exec -Verb 'publish' -Type 'claris-nginx' -Root $root -Rendered (NewRendered $root)
Assert ($r.Json.ok -eq $true) 'a real nginx publish succeeds'
$lines = ([IO.File]::ReadAllText($conf) -split "`r?`n")
$marks = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -eq "# $MARK") { $marks += $i } }
AssertEq $marks.Count 2 'exactly one marked pair is written'
$open443 = -1; for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'listen 443') { $open443 = $i; break } }
$depth = 0; $close443 = -1
for ($i = $open443; $i -lt $lines.Count; $i++) {
  $c = ($lines[$i] -split '#')[0]
  $depth += ([regex]::Matches($c, '\{')).Count - ([regex]::Matches($c, '\}')).Count
  if ($i -gt $open443 -and $depth -lt 0) { $close443 = $i; break }
}
Assert (($open443 -lt $marks[0]) -and ($marks[1] -lt $close443)) `
  'the block is INSIDE the 443 server block, not in nginx main context'
$otto = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -eq '###OTTO') { $otto += $i } }
Assert ($marks[0] -gt $otto[1]) 'the block is OUTSIDE the Otto-managed region'
Assert (Test-Path -LiteralPath (IncludeOf $root)) 'the CORPUSfm include is written'
Assert (Test-Path -LiteralPath "$conf.cfmbak") 'the backup is RETAINED until retire'

# Poisoned: zero, multiple and unbalanced 443 blocks refuse without touching a byte.
foreach ($case in @(
    @{ Body = "http {`n    server {`n        listen 80;`n    }`n}`n"; Reason = 'no server block listens on 443' },
    @{ Body = "http {`n    server {`n        listen 443;`n    }`n    server {`n        listen 443;`n    }`n}`n"; Reason = 'ambiguous' },
    @{ Body = "http {`n    server {`n        listen 443;`n"; Reason = 'unbalanced' })) {
  $r2 = NewFmsRoot $case.Body
  $c2 = ConfOf $r2
  $b2 = Digest $c2
  $res = Invoke-Exec -Verb 'publish' -Type 'claris-nginx' -Root $r2 -Rendered (NewRendered $r2)
  Assert ($res.Json.ok -eq $false) "publish refuses: $($case.Reason)"
  Assert ("$($res.Json.detail)" -match [regex]::Escape($case.Reason)) "the refusal names it: $($case.Reason)"
  AssertEq (Digest $c2) $b2 "the file is byte-identical after refusing: $($case.Reason)"
  Assert (-not (Test-Path -LiteralPath (IncludeOf $r2))) "no include was written: $($case.Reason)"
}

# A brace inside a comment is not a brace - the discriminating half of the unbalanced case.
$r3 = NewFmsRoot "http {`n    server {`n        # a stray } and { in a comment`n        listen 443 ssl;`n    }`n}`n"
$res = Invoke-Exec -Verb 'publish' -Type 'claris-nginx' -Root $r3 -Rendered (NewRendered $r3)
Assert ($res.Json.ok -eq $true) 'a commented brace does not skew the resolver'

# ---------------------------------------------------------------------------------------------
Write-Output '== ordinary verbs still refuse an ACTIVE Claris nginx front before publication =='

foreach ($verb in @('publish', 'remove')) {
  $root = NewFmsRoot
  $conf = ConfOf $root
  $before = Digest $conf
  $r = Invoke-Exec -Verb $verb -Type 'claris-nginx' -Root $root -ClarisActive -Rendered (NewRendered $root)
  Assert ($r.Json.ok -eq $false) "$verb refuses while the front is ACTIVE"
  Assert ("$($r.Json.detail)" -match "bounded $verb-active") "$verb names the bounded active operation"
  AssertEq (Digest $conf) $before "$verb published nothing at all"
  Assert (-not (Test-Path -LiteralPath (IncludeOf $root))) "$verb wrote no include"
}

Write-Output '== active Claris verbs stage exact bytes for provider-owned activation =='
$root = NewFmsRoot
$conf = ConfOf $root; $before = Digest $conf
$prepared = Invoke-Exec -Verb 'prepare' -Type 'claris-nginx' -Root $root -ClarisActive
Assert ($prepared.Json.ok -eq $true) 'Claris prepare succeeds'
AssertEq (Digest $conf) $before 'Claris prepare changes no routing bytes'
$classified = Invoke-Exec -Verb 'classify' -Type 'claris-nginx' -Root $root -ClarisActive
Assert ($classified.Json.unchanged -eq $true) 'an interruption after prepare classifies unchanged'
$rendered = NewRendered $root
$r = Invoke-Exec -Verb 'publish-active' -Type 'claris-nginx' -Root $root -ClarisActive -Rendered $rendered
Assert ($r.Json.ok -eq $true) 'publish-active stages successfully'
AssertEq $r.Json.fingerprint (FamilyDigestOfRendered $rendered) `
  'publish-active reports the complete block-plus-include family fingerprint'
$partDigest = ((Get-Content -LiteralPath $rendered.Block -Raw) |
  & (Get-PsExe) -NoProfile -File $exec -Verb digest | Out-String).Trim()
Assert ($r.Json.fingerprint -ne $partDigest) `
  'the complete family fingerprint is not silently reduced to the marked block'
Assert (Test-Path -LiteralPath "$conf.cfmbak") 'staging retains its recovery backup'
Assert (Test-Path -LiteralPath (IncludeOf $root)) 'staging writes the owned include'
$classified = Invoke-Exec -Verb 'classify' -Type 'claris-nginx' -Root $root -ClarisActive
Assert ($classified.Json.unchanged -eq $false) 'a staged family classifies as changed'
$restore = Invoke-Exec -Verb 'restore' -Type 'claris-nginx' -Root $root -ClarisActive
Assert ($restore.Json.ok -and $restore.Json.restored -and $restore.Json.restore_verified) 'restore verifies the prior family'
AssertEq (Digest $conf) $before 'restore returns the main config byte-exactly'
Assert (-not (Test-Path -LiteralPath (IncludeOf $root))) 'restore removes a newly-created include'

$root = NewFmsRoot
$conf = ConfOf $root; $before = Digest $conf
$r = Invoke-Exec -Verb 'publish-active' -Type 'claris-nginx' -Root $root -Rendered (NewRendered $root)
Assert ($r.Json.ok -eq $false) 'publish-active refuses without active-front evidence'
AssertEq (Digest $conf) $before 'the missing-active-evidence refusal changes no bytes'

# ---------------------------------------------------------------------------------------------
Write-Output '== byte fidelity: CRLF and BOM survive a publish =='

$crlfBody = ($NGINX_BODY -replace "`r?`n", "`r`n")
$root = NewFmsRoot $crlfBody
$conf = ConfOf $root
[IO.File]::WriteAllText($conf, $crlfBody, (New-Object System.Text.UTF8Encoding($true)))   # with BOM
Invoke-Exec -Verb 'publish' -Type 'claris-nginx' -Root $root -Rendered (NewRendered $root) | Out-Null
$bytes = [IO.File]::ReadAllBytes($conf)
Assert ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'the BOM survived'
$after = [IO.File]::ReadAllText($conf)
Assert ($after -match "`r`n") 'CRLF survived'
Assert (-not ($after -match "(?<!`r)`n")) 'no LF-only line was introduced'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 1: the IIS provider owns pool, primary app and every metadata child app =='

$fx = NewIisFixture
$root = NewFmsRoot

$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fx.App -MetadataDir $fx.Meta -StatePath $fx.State
Assert ($r.Json.ok -eq $true) 'observe answers for an unmounted family'
Assert ("$($r.Json.detail)" -match 'not mounted') 'an unmounted family says so'

$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fx.App -MetadataDir $fx.Meta `
                 -Rendered (NewRendered $root) -StatePath $fx.State
Assert ($r.Json.ok -eq $true) 'publish mounts the family'
$st = ReadState $fx.State
Assert ((StatePools $st) -contains 'CORPUSfmProxy') 'the CORPUSfmProxy application pool was created'
$apps = StateApps $st
Assert ($apps -contains 'FMWebSite/corpusfm') 'the primary /corpusfm application was created'
foreach ($v in (MetadataVpaths)) {
  Assert ($apps -contains ('FMWebSite' + $v)) "the metadata child application $v was created"
}
AssertEq $apps.Count 4 'exactly four applications - one primary, three metadata'
Assert (Test-Path -LiteralPath (Join-Path $fx.App 'web.config')) 'the primary web.config exists'
foreach ($v in (MetadataVpaths)) {
  $slug = ($v -replace '[^A-Za-z0-9]', '_').Trim('_')
  $cfg = Join-Path (Join-Path $fx.Meta $slug) 'web.config'
  Assert (Test-Path -LiteralPath $cfg) `
    "the metadata web.config for $v exists"
  Assert (([IO.File]::ReadAllText($cfg)) -match '<match url="\^/\?\$" />') `
    "the metadata web.config for $v preserves the renderer exact-root rule"
}
$primary = [IO.File]::ReadAllText((Join-Path $fx.App 'web.config'))
Assert ($primary -match 'http://127\.0\.0\.1:8533/corpusfm/') 'the primary route points at the internal port'
Assert (-not ($primary -match '<sites>|applicationHost')) 'no FMS site-level rewrite rule is touched'

$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fx.App -MetadataDir $fx.Meta -StatePath $fx.State
Assert ("$($r.Json.detail)" -match 'family is present') 'observe sees the whole family'

# An INCOMPLETE family is neither present nor absent - reporting it present would let a reconcile
# skip the missing members.
$st = ReadState $fx.State
$keep = [pscustomobject]@{}
foreach ($p in $st.apps.PSObject.Properties) { if ($p.Name -ne 'FMWebSite/corpusfm') { $keep | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value } }
$st.apps = $keep; $st | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fx.State -Encoding utf8
$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fx.App -MetadataDir $fx.Meta -StatePath $fx.State
Assert ("$($r.Json.detail)" -match 'INCOMPLETE') 'a partial family is reported INCOMPLETE'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 1: effective readback, not an exit code =='

$fx2 = NewIisFixture
$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fx2.App -MetadataDir $fx2.Meta `
                 -Rendered (NewRendered $root) -StatePath $fx2.State -Phantom '/corpusfm'
Assert ($r.Json.ok -eq $false) 'a create that reports success but does NOT persist is caught'
Assert ("$($r.Json.detail)" -match 'NOT registered') 'the readback names the failure'

$fx3 = NewIisFixture
$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fx3.App -MetadataDir $fx3.Meta `
                 -Rendered (NewRendered $root) -StatePath $fx3.State -FailOn 'add apppool'
Assert ($r.Json.ok -eq $false) 'a nonzero appcmd exit fails the publish'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 1: rollback removes ONLY run-created objects =='

# Case A: nothing pre-existed. Restore removes the whole family and the pool.
$fxA = NewIisFixture
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxA.App -MetadataDir $fxA.Meta `
            -Rendered (NewRendered $root) -StatePath $fxA.State | Out-Null
$r = Invoke-Exec -Verb 'restore' -Root $root -IisAppDir $fxA.App -MetadataDir $fxA.Meta -StatePath $fxA.State
Assert ($r.Json.restore_verified -eq $true) 'restore of a wholly run-created family verifies'
$st = ReadState $fxA.State
AssertEq (StateApps $st).Count 0 'every run-created application was removed'
AssertEq (StatePools $st).Count 0 'the run-created pool was removed'

# Case B: the pool and the primary app PRE-EXIST. Restore must keep them, and keep their bytes.
$fxB = NewIisFixture
$stB = ReadState $fxB.State
$stB.pools = @('CORPUSfmProxy')
$stB.apps | Add-Member -NotePropertyName 'FMWebSite/corpusfm' -NotePropertyValue ([pscustomobject]@{
  physicalPath = $fxB.App; pool = 'CORPUSfmProxy' }) -Force
$stB | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fxB.State -Encoding utf8
New-Item -ItemType Directory -Force -Path $fxB.App | Out-Null
$priorText = '<configuration><!-- somebody else was here --></configuration>'
[IO.File]::WriteAllText((Join-Path $fxB.App 'web.config'), $priorText, (New-Object System.Text.UTF8Encoding($false)))

Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxB.App -MetadataDir $fxB.Meta `
            -Rendered (NewRendered $root) -StatePath $fxB.State | Out-Null
Assert (([IO.File]::ReadAllText((Join-Path $fxB.App 'web.config'))) -notmatch 'somebody else') `
  'publish replaced the pre-existing web.config'

$r = Invoke-Exec -Verb 'restore' -Root $root -IisAppDir $fxB.App -MetadataDir $fxB.Meta -StatePath $fxB.State
Assert ($r.Json.restore_verified -eq $true) 'restore verifies with pre-existing artifacts'
$st = ReadState $fxB.State
Assert ((StatePools $st) -contains 'CORPUSfmProxy') 'the PRE-EXISTING pool was kept'
Assert ((StateApps $st) -contains 'FMWebSite/corpusfm') 'the PRE-EXISTING primary application was kept'
foreach ($v in (MetadataVpaths)) {
  Assert (-not ((StateApps $st) -contains ('FMWebSite' + $v))) "the run-created $v was removed"
}
AssertEq ([IO.File]::ReadAllText((Join-Path $fxB.App 'web.config'))) $priorText `
  'the pre-existing web.config bytes were restored exactly'

# A restore with no before-image refuses rather than guessing what this run created.
$fxC = NewIisFixture
$r = Invoke-Exec -Verb 'restore' -Root $root -IisAppDir $fxC.App -MetadataDir $fxC.Meta -StatePath $fxC.State
Assert ($r.Json.ok -eq $false) 'a restore with no before-image REFUSES'
Assert ("$($r.Json.detail)" -match 'refusing to guess') 'and says why'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 1: remove backs up first, and removes a run-created pool only =='

$fxD = NewIisFixture
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxD.App -MetadataDir $fxD.Meta `
            -Rendered (NewRendered $root) -StatePath $fxD.State | Out-Null
Invoke-Exec -Verb 'retire' -Root $root -IisAppDir $fxD.App -MetadataDir $fxD.Meta -StatePath $fxD.State | Out-Null
$mounted = [IO.File]::ReadAllText((Join-Path $fxD.App 'web.config'))

$r = Invoke-Exec -Verb 'remove' -Root $root -IisAppDir $fxD.App -MetadataDir $fxD.Meta -StatePath $fxD.State
Assert ($r.Json.ok -eq $true) 'remove succeeds'
$st = ReadState $fxD.State
AssertEq (StateApps $st).Count 0 'every owned application was deleted'
Assert (-not (Test-Path -LiteralPath $fxD.App)) 'the owned physical directory was removed'
# The restore authority is the operation-bound before-image, not a sibling `.cfmbak`: a backup
# inside the directory would have been deleted along with it.
$evD = Join-Path (Split-Path -Parent $fxD.App) 'cfm-iis-before-11111111-2222-3333-4444-555555555555.json'
Assert (Test-Path -LiteralPath $evD) 'the before-image survives the directory removal'
Assert ((Get-Content -LiteralPath $evD -Raw) -match 'config_body') 'and carries the bytes'

$r = Invoke-Exec -Verb 'restore' -Root $root -IisAppDir $fxD.App -MetadataDir $fxD.Meta -StatePath $fxD.State
Assert ($r.Json.restore_verified -eq $true) 'an abort of a remove restores and verifies'
AssertEq ([IO.File]::ReadAllText((Join-Path $fxD.App 'web.config'))) $mounted `
  'the removed routing is byte-identical again'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 5: publish reconciles BOTH pool and physical path =='

$fxR = NewIisFixture
$stR = ReadState $fxR.State
$stR.pools = @('CORPUSfmProxy')
$stR.apps | Add-Member -NotePropertyName 'FMWebSite/corpusfm' -NotePropertyValue ([pscustomobject]@{
  physicalPath = '/somewhere/else'; pool = 'SomeoneElsesPool' }) -Force
$stR | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fxR.State -Encoding utf8

$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxR.App -MetadataDir $fxR.Meta `
                 -Rendered (NewRendered $root) -StatePath $fxR.State
Assert ($r.Json.ok -eq $true) 'publish over a mis-pointed existing application succeeds'
$st = ReadState $fxR.State
AssertEq $st.apps.'FMWebSite/corpusfm'.pool 'CORPUSfmProxy' 'the pool was reconciled'
AssertEq $st.apps.'FMWebSite/corpusfm'.physicalPath $fxR.App 'the PHYSICAL PATH was reconciled'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 5: restore puts back the prior pool AND the prior path =='

$r = Invoke-Exec -Verb 'restore' -Root $root -IisAppDir $fxR.App -MetadataDir $fxR.Meta -StatePath $fxR.State
Assert ($r.Json.restore_verified -eq $true) 'restore verifies'
$st = ReadState $fxR.State
AssertEq $st.apps.'FMWebSite/corpusfm'.pool 'SomeoneElsesPool' 'the PRIOR pool was restored'
AssertEq $st.apps.'FMWebSite/corpusfm'.physicalPath '/somewhere/else' 'the PRIOR path was restored'
Assert ((StatePools $st) -contains 'CORPUSfmProxy') 'the pre-existing pool was kept'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 5: remove deletes the COMPLETE owned family, pool included =='

$fxX = NewIisFixture
$stX = ReadState $fxX.State
$stX.pools = @('CORPUSfmProxy')          # the pool pre-dates this operation
$stX | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fxX.State -Encoding utf8
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxX.App -MetadataDir $fxX.Meta `
            -Rendered (NewRendered $root) -StatePath $fxX.State | Out-Null
Invoke-Exec -Verb 'retire' -Root $root -IisAppDir $fxX.App -MetadataDir $fxX.Meta -StatePath $fxX.State | Out-Null

$r = Invoke-Exec -Verb 'remove' -Root $root -IisAppDir $fxX.App -MetadataDir $fxX.Meta -StatePath $fxX.State
Assert ($r.Json.ok -eq $true) 'remove succeeds'
$st = ReadState $fxX.State
AssertEq (StateApps $st).Count 0 'every owned application is gone'
# CORPUSfmProxy is EXCLUSIVELY ours, so `remove` takes it even though it pre-dated this operation.
# The earlier version kept it and left an uninstall visibly incomplete.
AssertEq (StatePools $st).Count 0 'the exclusively-owned pool is gone too'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 5: a PARTIAL family is drift, not presence =='

$fxP2 = NewIisFixture
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxP2.App -MetadataDir $fxP2.Meta `
            -Rendered (NewRendered $root) -StatePath $fxP2.State | Out-Null
$st = ReadState $fxP2.State
$keep2 = [pscustomobject]@{}
foreach ($pr in $st.apps.PSObject.Properties) {
  if ($pr.Name -ne 'FMWebSite/.well-known/openid-configuration/corpusfm/mcp') {
    $keep2 | Add-Member -NotePropertyName $pr.Name -NotePropertyValue $pr.Value
  }
}
$st.apps = $keep2; $st | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fxP2.State -Encoding utf8
$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fxP2.App -MetadataDir $fxP2.Meta -StatePath $fxP2.State
Assert ($r.Json.ok -eq $false) 'a partial family REFUSES rather than reporting presence'
Assert ("$($r.Json.detail)" -match 'INCOMPLETE') 'and names it'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 3: the IIS fingerprint covers the whole family =='

$fxF = NewIisFixture
$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxF.App -MetadataDir $fxF.Meta `
                 -Rendered (NewRendered $root) -StatePath $fxF.State
$fp1 = $r.Json.fingerprint
Assert ($fp1.Length -eq 64) 'publish returns a family fingerprint'
$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fxF.App -MetadataDir $fxF.Meta -StatePath $fxF.State
AssertEq $r.Json.fingerprint $fp1 'observe reads back the SAME family fingerprint'

# An operator repoints one application: the family digest must move.
$st = ReadState $fxF.State
$st.apps.'FMWebSite/corpusfm'.physicalPath = '/operator/moved/it'
$st | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fxF.State -Encoding utf8
$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fxF.App -MetadataDir $fxF.Meta -StatePath $fxF.State
Assert ($r.Json.fingerprint -ne $fp1) 'a repointed physical path MOVES the family fingerprint'

# An operator edits a metadata child's web.config: likewise.
$fxG = NewIisFixture
$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxG.App -MetadataDir $fxG.Meta `
                 -Rendered (NewRendered $root) -StatePath $fxG.State
$fp2 = $r.Json.fingerprint
$slug = ('/.well-known/openid-configuration/corpusfm/mcp' -replace '[^A-Za-z0-9]', '_').Trim('_')
$victim = Join-Path (Join-Path $fxG.Meta $slug) 'web.config'
[IO.File]::AppendAllText($victim, "`n<!-- an operator was here -->")
$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fxG.App -MetadataDir $fxG.Meta -StatePath $fxG.State
Assert ($r.Json.fingerprint -ne $fp2) 'an edited metadata web.config MOVES the family fingerprint'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 6: evidence is operation-bound =='

$fxE2 = NewIisFixture
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxE2.App -MetadataDir $fxE2.Meta `
            -Rendered (NewRendered $root) -StatePath $fxE2.State `
            -Operation '11111111-2222-3333-4444-555555555555' | Out-Null
$evPath = Join-Path (Split-Path -Parent $fxE2.App) 'cfm-iis-before-11111111-2222-3333-4444-555555555555.json'
Assert (Test-Path -LiteralPath $evPath) 'the before-image is named for its operation'

# A DIFFERENT operation must not restore through it.
$r = Invoke-Exec -Verb 'restore' -Root $root -IisAppDir $fxE2.App -MetadataDir $fxE2.Meta `
                 -StatePath $fxE2.State -Operation '99999999-8888-7777-6666-555555555555'
Assert ($r.Json.ok -eq $false) 'another operation cannot restore through this evidence'
Assert ("$($r.Json.detail)" -match 'refusing to guess') 'and says why'
$st = ReadState $fxE2.State
AssertEq (StateApps $st).Count 4 'and nothing was restored'

# ---------------------------------------------------------------------------------------------
Write-Output '== the crash boundary: prepare changes nothing, so recovery must SEE that =='

$fxC2 = NewIisFixture
$r = Invoke-Exec -Verb 'prepare' -Root $root -IisAppDir $fxC2.App -MetadataDir $fxC2.Meta -StatePath $fxC2.State
Assert ($r.Json.ok -eq $true) 'prepare captures a before-image'
$st = ReadState $fxC2.State
AssertEq (StateApps $st).Count 0 'prepare mounted nothing'
AssertEq (StatePools $st).Count 0 'prepare created no pool'

$r = Invoke-Exec -Verb 'classify' -Root $root -IisAppDir $fxC2.App -MetadataDir $fxC2.Meta -StatePath $fxC2.State
Assert ($r.Json.unchanged -eq $true) 'an untouched family classifies as UNCHANGED'

# ...and once a publish has happened, the same comparison says otherwise.
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxC2.App -MetadataDir $fxC2.Meta `
            -Rendered (NewRendered $root) -StatePath $fxC2.State | Out-Null
$r = Invoke-Exec -Verb 'classify' -Root $root -IisAppDir $fxC2.App -MetadataDir $fxC2.Meta -StatePath $fxC2.State
Assert ($r.Json.unchanged -eq $false) 'a published family classifies as CHANGED'

# An operator edit to one metadata web.config alone is enough to move it.
$fxC3 = NewIisFixture
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxC3.App -MetadataDir $fxC3.Meta `
            -Rendered (NewRendered $root) -StatePath $fxC3.State | Out-Null
Invoke-Exec -Verb 'retire' -Root $root -IisAppDir $fxC3.App -MetadataDir $fxC3.Meta -StatePath $fxC3.State | Out-Null
Invoke-Exec -Verb 'prepare' -Root $root -IisAppDir $fxC3.App -MetadataDir $fxC3.Meta -StatePath $fxC3.State | Out-Null
$r = Invoke-Exec -Verb 'classify' -Root $root -IisAppDir $fxC3.App -MetadataDir $fxC3.Meta -StatePath $fxC3.State
Assert ($r.Json.unchanged -eq $true) 'a settled family classifies as unchanged'
$slug3 = ('/.well-known/openid-configuration/corpusfm/mcp' -replace '[^A-Za-z0-9]', '_').Trim('_')
[IO.File]::AppendAllText((Join-Path (Join-Path $fxC3.Meta $slug3) 'web.config'), "`n<!-- edited -->")
$r = Invoke-Exec -Verb 'classify' -Root $root -IisAppDir $fxC3.App -MetadataDir $fxC3.Meta -StatePath $fxC3.State
Assert ($r.Json.unchanged -eq $false) 'an edited metadata web.config classifies as CHANGED'

# A repointed application likewise - the classification covers registrations, not only files.
$fxC4 = NewIisFixture
Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxC4.App -MetadataDir $fxC4.Meta `
            -Rendered (NewRendered $root) -StatePath $fxC4.State | Out-Null
Invoke-Exec -Verb 'retire' -Root $root -IisAppDir $fxC4.App -MetadataDir $fxC4.Meta -StatePath $fxC4.State | Out-Null
Invoke-Exec -Verb 'prepare' -Root $root -IisAppDir $fxC4.App -MetadataDir $fxC4.Meta -StatePath $fxC4.State | Out-Null
$st = ReadState $fxC4.State
$st.apps.'FMWebSite/corpusfm'.physicalPath = '/operator/moved/it'
$st | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fxC4.State -Encoding utf8
$r = Invoke-Exec -Verb 'classify' -Root $root -IisAppDir $fxC4.App -MetadataDir $fxC4.Meta -StatePath $fxC4.State
Assert ($r.Json.unchanged -eq $false) 'a repointed application classifies as CHANGED'

# Unreadable evidence is UNKNOWN, never 'unchanged'.
$r = Invoke-Exec -Verb 'classify' -Root $root -IisAppDir $fxC4.App -MetadataDir $fxC4.Meta `
                 -StatePath $fxC4.State -Operation '99999999-8888-7777-6666-555555555555'
Assert ($r.Json.ok -eq $false) 'a foreign operation cannot classify through this evidence'

# ---------------------------------------------------------------------------------------------
Write-Output '== ruling 2: read-only observation, and UNKNOWN stays UNKNOWN =='

$fxP = NewIisFixture
$env:CFM_APPCMD_STUB = $script:stubPath; $env:CFM_APPCMD_STATE = $fxP.State
$probeRaw = & (Get-PsExe) -NoProfile -File $exec -Verb probe -Type iis -FmsRoot $root `
  -Prefix '/corpusfm' -IisAppDir $fxP.App -MetadataDir $fxP.Meta 2>&1 | Out-String
$env:CFM_APPCMD_STUB = $null; $env:CFM_APPCMD_STATE = $null
$probe = ($probeRaw -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
Assert ($null -ne $probe) 'the probe emits a JSON report'
Assert ($probe.iis_available -eq $true) 'IIS availability is established'
Assert ($probe.iis_apps_present -eq $false) 'a complete absence is reported as absent'
Assert ($probe.claris_installed -eq $true) 'the Claris front is detected from the FMS root'
# On this machine Get-NetTCPConnection does not exist, so the active state CANNOT be established -
# and that must come back as UNKNOWN rather than as inactive.
Assert ($null -eq $probe.claris_active) 'an undeterminable active state stays UNKNOWN, never false'

$probeRaw2 = & (Get-PsExe) -NoProfile -File $exec -Verb probe -Type iis `
  -FmsRoot (Join-Path ([IO.Path]::GetTempPath()) 'no-such-root') -Prefix '/corpusfm' 2>&1 | Out-String
$probe2 = ($probeRaw2 -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
Assert ($null -eq $probe2.claris_installed) 'an unreachable FMS root leaves claris_installed UNKNOWN'
Assert ($null -eq $probe2.claris_active) 'and claris_active UNKNOWN'

$probeState = (Get-Content -LiteralPath $fxP.State -Raw).Trim()
AssertEq $probeState '{"pools":[],"apps":{}}' 'the probe mutated no IIS state'

# ---------------------------------------------------------------------------------------------
Write-Output '== refusals =='

$r = Invoke-Exec -Verb 'observe' -Type 'claris-nginx' -Root (Join-Path ([IO.Path]::GetTempPath()) 'no-such-fms-root')
Assert ($r.Json.ok -eq $false) 'an absent FMS root refuses rather than searching the machine'

$root2 = NewFmsRoot
Remove-Item -LiteralPath (ConfOf $root2) -Force
$r = Invoke-Exec -Verb 'observe' -Type 'claris-nginx' -Root $root2
Assert ($r.Json.ok -eq $false) 'a config absent from the root refuses'

$fxE = NewIisFixture
$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxE.App -MetadataDir $fxE.Meta -StatePath $fxE.State
Assert ($r.Json.ok -eq $false) 'an iis publish without a rendered web.config refuses'

$r = Invoke-Exec -Verb 'publish' -Root $root -MetadataDir $fxE.Meta -Rendered (NewRendered $root) -StatePath $fxE.State
Assert ($r.Json.ok -eq $false) 'the iis type requires an application directory'

$r = Invoke-Exec -Verb 'publish' -Root $root -IisAppDir $fxE.App -Rendered (NewRendered $root) -StatePath $fxE.State
Assert ($r.Json.ok -eq $false) 'the iis type requires a metadata directory'

$r = Invoke-Exec -Verb 'observe' -Root $root -IisAppDir $fxE.App -MetadataDir $fxE.Meta -NoStub
Assert ($r.Json.ok -eq $false) 'no IIS on the machine refuses rather than reporting absence'
Assert ("$($r.Json.detail)" -match 'IIS is not available') 'and says so'

# ---------------------------------------------------------------------------------------------
Write-Output ''
Write-Output "$($script:count) assertions, $($script:fails) failure(s)"
if ($script:fails -gt 0) { exit 1 }
exit 0
