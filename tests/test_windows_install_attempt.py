"""Packet 1398 — the Windows installer's fresh-install attempt: writer, wrappers, routing.

**Authoritative here:** the static contract — the closed vocabulary equals the application's Windows
vocabulary, the refuse-first set is the packet's, the switch parses, the attempt is routed before any
other classification and begun after consent, every named mutation site goes through a wrapper, and
the completion stamp is the last lifecycle mutation.

**Supplementary, under local pwsh:** the `La-` functions themselves, executed. The Windows-only
observations (DACLs, services, tasks, reparse points, path canonicalisation) are replaced by doubles,
because macOS pwsh cannot answer them; the record serialization, the write-ahead ordering, the
pass-through and the provider result shapes are the real text. Each record the executed writer
produces is read back by the APPLICATION's own validator. Windows PowerShell 5.1 itself is not run
here; that is the deferred live gate.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from corpusfm.lifecycle import install_attempt as ia

REPO = Path(__file__).resolve().parents[1]
PS1 = REPO / "installer" / "windows" / "install.ps1"
TEXT = PS1.read_text(encoding="ascii")
PWSH = shutil.which("pwsh")
supplementary = pytest.mark.skipif(PWSH is None, reason="no pwsh; these checks are supplementary")


def code(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def ps_function(name: str) -> str:
    start = re.search(rf"^function {re.escape(name)}\b", TEXT, re.M)
    assert start, f"{name} is not defined in install.ps1"
    # Braces inside quoted strings and line comments are not structure (`$t.IndexOf('{')`).
    i, depth, quote, comment = TEXT.index("{", start.start()), 0, None, False
    for j in range(i, len(TEXT)):
        ch = TEXT[j]
        if comment:
            comment = ch != "\n"
            continue
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            comment = True
        elif ch in "{}":
            depth += 1 if ch == "{" else -1
            if depth == 0:
                return TEXT[start.start():j + 1]
    raise AssertionError(f"{name} is never closed")


# ── the static contract ───────────────────────────────────────────────────────────


def _kinds() -> dict:
    block = TEXT[TEXT.index("$script:LaKinds = [ordered]@{"):]
    block = block[:block.index("\n}\n")]
    kinds = {}
    for name, body in re.findall(r"'(\w+)'\s*=\s*@\(([^)]*)\)", block, re.S):
        kinds[name] = set(re.findall(r"'(\w+)'", body))
    return kinds


def test_the_windows_vocabulary_is_exactly_the_applications_windows_vocabulary():
    app = {kind: set(intents) for kind, intents in ia.LEDGER_VOCABULARY.items()}
    posix_or_application_only = {"account", "unit", "package_set", "firewall_rule", "journal"}
    expected = {kind: intents - {"set_owner_mode"} for kind, intents in app.items()
                if kind not in posix_or_application_only}
    assert _kinds() == expected


def test_the_refuse_first_set_is_the_packet_list():
    body = ps_function("La-RefuseFirst")
    assert re.findall(r"kind = '(\w+)';\s+target = ([^}]+?) }", body) == [
        ("dir", "$script:InstallDir"),
        ("file", "(Join-Path $script:FixedConfig 'install.yaml')"),
        ("service", "$script:WebService"),
        ("task", "'\\CORPUSfm Update'"),
    ]


def test_the_discard_switch_is_declared_documented_and_reported():
    params = TEXT[TEXT.index("[CmdletBinding()]"):TEXT.index("$ErrorActionPreference = 'Stop'")]
    assert "[switch]$DiscardIncompleteAttempt" in params
    assert "-DiscardIncompleteAttempt When an earlier fresh install stopped part-way" in TEXT
    assert "$declared += '-DiscardIncompleteAttempt'" in TEXT


def test_the_file_stays_ascii_for_windows_powershell_5_1():
    PS1.read_bytes().decode("ascii")


def test_the_attempt_is_routed_first_and_begun_after_consent_before_any_mutation():
    body = code(TEXT)
    route = body.index("else { La-RouteExistingAttempt 'first' }")
    assert route < body.index("Prepare-ExternalSourceAdvance $Src }") < body.index("$lcStateEarly = Get-LcState")
    assert body.index("if ($script:LaRouteDeferred) { La-RouteExistingAttempt 'final' }") < body.index(
        "# === PHASE 4") if "# === PHASE 4" in body else True
    begin = body.index("if (-not $IsUpgrade -and -not $PublishedHere) { La-BeginAttempt }")
    assert body.index("Cfm-Confirm -Prompt 'Proceed?'") < body.index("Assert-CfmSystemTaskTrust -EntryPoint") < begin
    assert begin < body.index("Move-Item -LiteralPath $InstallDir -Destination $ReplaceAside")
    assert begin < body.index("New-Item -ItemType Directory -Force -Path $InstallDir,$ConfigHome")
    complete = body.index("La-Lifecycle @('attempt','complete','--request',$laReq)")
    assert body.index('Ok ("Post-install verification passed') < complete < body.index('Section "Next steps"')


#: The Windows mutation sites section 5.1 names, spelled as they are executed.
MUTATIONS = [
    r"Move-Item -LiteralPath \$InstallDir", r"New-Item -ItemType Directory -Force -Path \$InstallDir,",
    r"Lock-DirTreeAcl \$ConfigHome", r"New-Item -ItemType Directory -Force -Path \$FixedConfig,",
    r"config --global --unset-all credential\.helper", r"-Path \$PatchHostingDir \|",
    r"-Path \$SupportDir \|", r"composition','foundation'", r"'provision-keys','--request'",
    r"Register-ScheduledTask -TaskName", r"Remove-Item -LiteralPath \$staleMcpEnv",
    r"Register-CfmService \$id$", r"Grant-OrDie \$PatchHostingDir", r"Grant-OrDie \$LogDir",
    r"Set-WebConfigurationProperty .*system\.webServer/proxy", r"'retire-scheduler-authority','--request',\$req\)$",
    r"backfill-storage-projections", r"storage create-first-admin",
]


def test_every_named_windows_mutation_site_is_wrapped():
    lines = code(TEXT).splitlines()
    unwrapped = []
    for index, line in enumerate(lines):
        for pattern in MUTATIONS:
            if not re.search(pattern, line.rstrip()):
                continue
            if line.lstrip().startswith(("Die ", "Warn ", "Info ", "Ok ")) or "function " in line:
                continue
            window = "\n".join(lines[max(0, index - 14):index + 3])
            if re.search(r"La-(Do|Step|LcRun|ProviderBegin)\b", window) or \
                    "Lc-Run \"A001 authority recovery\"" in line:
                continue
            unwrapped.append(line.strip())
    assert not unwrapped, "\n".join(unwrapped)


def test_every_provider_run_publishes_its_result_before_dispatch():
    body = ps_function("Lc-ProviderRun")
    begin, end = body.index("La-ProviderBegin"), body.index("La-ProviderEnd")
    assert begin < body.index("Lc-RunRaw $LcArgs") < end < body.index("Lc-ProviderDisposition")
    assert "finally" in body[:end], "a refusal or an unreadable answer would leave no post-observation"


def test_the_discard_ends_the_invocation_and_starts_nothing_new():
    discard = ps_function("La-AttemptDiscard")
    assert discard.count("exit 0") == 1 and "Die " in discard
    assert "La-BeginAttempt" not in discard and "La-Step" not in discard
    menu = ps_function("La-AttemptMenu")
    assert "-DiscardIncompleteAttempt" in menu and "failed_before_change" in menu


# ── supplementary: the writer and wrappers, executed under pwsh ─────────────────────

FUNCTIONS = ("La-RefuseFirst", "La-Now", "La-Inside", "La-ContainerIsEmpty", "La-Write", "La-Observe",
             "La-EntriesFor", "La-Contained", "La-Created", "La-SeqOf", "La-Step", "La-Result",
             "La-Do", "La-KeysPrior", "La-ProviderBegin", "La-JsonObject", "La-ProviderPost",
             "La-ProviderEnd", "La-LcRun")

INSTALL = r"C:\Program Files\CORPUSfm"
PD = r"C:\ProgramData\CORPUSfm"
DB = r"C:\Program Files\FileMaker\FileMaker Server\Data\Databases"


def run_ps(tmp_path: Path, body: str, *, attempt=True, present=()):
    container = tmp_path / "attempt"
    container.mkdir(exist_ok=True)
    functions = "\n".join(ps_function(name) for name in FUNCTIONS)
    present_list = ",".join("'" + p.replace("'", "''") + "'" for p in present) or ""
    script = f"""
$ErrorActionPreference = 'Stop'
function Die($m) {{ throw ('DIE: ' + $m) }}
function Ok($m) {{ }}
function Cfm-Logline($m) {{ }}
function Lc-Dispatch($code, $what) {{ if ($code -ne 0) {{ throw ('DISPATCH ' + $code) }} }}
$script:InstallDir = '{INSTALL}'
$script:FixedConfig = '{PD}\\config'
$script:FixedSecrets = '{PD}\\secrets'
$script:WebService = 'corpusfm-web'
$script:CfmProxyTypes = @('iis', 'claris-nginx')
$script:AttemptDir = '{container}'
$script:CfmAttempt = ${'true' if attempt else 'false'}
$script:LaFsKinds = @('dir', 'file')
$script:LaSeqs = @(); $script:LaProviderSeqs = @(); $script:LaProviderTargetSeqs = @()
{TEXT[TEXT.index("$script:LaKinds = [ordered]@{"):TEXT.index("$script:LaFsKinds = @('dir', 'file')")]}
$script:Present = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
foreach ($p in @({present_list})) {{ [void]$script:Present.Add($p) }}
{functions}
# Doubles for what only Windows can answer. `Join-Path` cannot name a C: path on macOS, so the
# refuse-first list is restated by concatenation; its real text is pinned by the static test.
function La-RefuseFirst {{ return @(@{{ kind = 'dir'; target = $script:InstallDir }},
  @{{ kind = 'file'; target = ($script:FixedConfig + '\\install.yaml') }},
  @{{ kind = 'service'; target = $script:WebService }}, @{{ kind = 'task'; target = '\\CORPUSfm Update' }}) }}
function La-Canon([string]$Path) {{ return $Path.TrimEnd('\\') }}
function La-Parent([string]$Path) {{ $i = $Path.LastIndexOf('\\'); if ($i -le 2) {{ return '' }}; return $Path.Substring(0, $i) }}
function La-PathItem([string]$Path) {{
  if ($Path -eq $script:AttemptDir) {{ return (Get-Item -LiteralPath $Path -Force) }}
  if (-not $script:Present.Contains($Path)) {{ return $null }}
  $isDir = -not $Path.EndsWith('.fmp12') -and -not $Path.EndsWith('.yaml')
  return [pscustomobject]@{{ PSIsContainer = $isDir; Attributes = [IO.FileAttributes]::Normal; Length = 5 }}
}}
function La-Sddl([string]$Path) {{ return 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)' }}
function La-Sha256([string]$Path) {{ return ('0' * 64) }}
function La-SetProtected([string]$Path, [bool]$Directory) {{ }}
function La-AuthorityProblem([string]$Path) {{ return '' }}
function La-ContainerProblem {{ return '' }}
function La-ServiceState([string]$Name) {{ if ($script:Present.Contains('service:' + $Name)) {{ return [ordered]@{{ exists = $true; binary_path = 'C:\\x.exe' }} }}; return [ordered]@{{ exists = $false }} }}
function La-TaskState([string]$Target) {{ if ($script:Present.Contains('task:' + $Target)) {{ return [ordered]@{{ exists = $true; task_path = $Target }} }}; return [ordered]@{{ exists = $false }} }}
$script:AttemptRecord = [ordered]@{{
  schema_version = 1; attempt_id = '11111111-2222-4333-8444-555555555555'
  installation_id = '6f1d0d2a-2f1e-4c3b-9a77-1b2c3d4e5f60'; platform = 'windows'; created_utc = (La-Now)
  paths = [ordered]@{{ install_dir = '{INSTALL}'; patch_hosting_dir = 'C:\\CORPUSfm-Hosted'
    fms_root = 'C:\\Program Files\\FileMaker\\FileMaker Server'; fms_database_dir = '{DB}'
    config_dir = '{PD}\\config'; state_dir = '{PD}\\state'; secrets_dir = '{PD}\\secrets'
    log_dir = '{PD}\\logs'; run_dir = '{PD}\\run'; storage_target = '{DB}\\CORPUSfm\\CORPUSfm_DB.fmp12'
    support_dir = '{DB}\\CORPUSfm-Support' }}
  package = $null; ledger = (New-Object System.Collections.ArrayList); discard = $null; phase = 'installing'
}}
{body}
"""
    path = tmp_path / "walk.ps1"
    path.write_text(script, encoding="utf-8")
    proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                          capture_output=True, text=True)
    record = container / "attempt.json"
    return proc, (json.loads(record.read_text(encoding="utf-8-sig")) if record.exists() else None)


@supplementary
def test_a_walk_over_every_windows_entry_validates_and_classifies_in_the_application(tmp_path):
    body = rf"""
La-Write
$script:Present.Add('{PD}') | Out-Null; $script:Present.Add('{PD}\logs') | Out-Null
$script:Present.Add('C:\Program Files') | Out-Null; $script:Present.Add('C:\ProgramData') | Out-Null
$script:Present.Add('{DB}') | Out-Null; $script:Present.Add('C:\CORPUSfm-Hosted') | Out-Null
La-Do 'dir' 'ensure' $null @('{INSTALL}', '{PD}', '{INSTALL}\bin', '{PD}\logs') {{ $script:Present.Add('{INSTALL}') | Out-Null; $script:Present.Add('{INSTALL}\bin') | Out-Null }} | Out-Null
La-Do 'dir' 'set_acl' $null @('{PD}') {{ }} | Out-Null
La-Do 'dir' 'ensure' $null @('{PD}\config', '{PD}\state', '{PD}\state\update-inbox') {{ foreach ($d in @('{PD}\config','{PD}\state','{PD}\state\update-inbox')) {{ $script:Present.Add($d) | Out-Null }} }} | Out-Null
La-Do 'git_config_entry' 'unset' ([ordered]@{{ values = @('manager') }}) @('{PD}\.gitconfig') {{ }} | Out-Null
La-Do 'task' 'create' $null @('\CORPUSfm Update') {{ $script:Present.Add('task:\CORPUSfm Update') | Out-Null }} | Out-Null
La-Do 'service' 'create' $null @('corpusfm-web') {{ $script:Present.Add('service:corpusfm-web') | Out-Null }} | Out-Null
La-Do 'dir' 'set_acl' $null @('C:\CORPUSfm-Hosted') {{ }} | Out-Null
La-Step 'iis_setting' 'enable_arr_proxy' ([ordered]@{{ enabled = $false }}) @('system.webServer/proxy')
La-Result $script:LaSeqs 'done' ([ordered]@{{ enabled = $true }})
foreach ($pair in @(
    @('foundation', ([ordered]@{{ locator = $false; manifest = $false }}), '{{"generation": 1}}'),
    @('provision_keys', ([ordered]@{{ corpus_key = $false; machine_key = $false; session_secret = $false }}), '{{"result":"completed","keys":[{{"name":"corpus.key","action":"generated"}}]}}'),
    @('admin_identity_reconcile', ([ordered]@{{ observe = 'NOT_INSTALLED' }}), 'not json'),
    @('patch_apply', ([ordered]@{{ hosting_dir_seq = [int](La-SeqOf 'dir' 'C:\CORPUSfm-Hosted') }}), '{{"result":"completed"}}'),
    @('proxy_reconcile', ([ordered]@{{ blocks = [ordered]@{{ iis = 'BLOCK_ABSENT' }} }}), '{{"result":"completed","attempt_facts":{{"prior_family":{{"iis":{{"pool_existed":false,"app_existed":false,"marker_state":"none","include_present":false}}}}}}}}'))) {{
  La-ProviderBegin $pair[0] $pair[1] $pair[0]
  La-ProviderEnd $pair[0] 0 $pair[2]
}}
$target = '{DB}\CORPUSfm\CORPUSfm_DB.fmp12'
La-Step 'file' 'ensure' $null @($target)
$script:LaProviderTargetSeqs = $script:LaSeqs
$seq = [int](La-SeqOf 'file' $target)
La-ProviderBegin 'storage_bootstrap' ([ordered]@{{ observe = 'proven_fresh'; route = 'bootstrap'; target_seq = $seq }}) 'storage'
$script:Present.Add($target) | Out-Null; $script:Present.Add('{DB}\CORPUSfm') | Out-Null
La-ProviderEnd 'storage_bootstrap' 0 '{{"result":"completed"}}'
La-ProviderBegin 'backfill_storage_projections' ([ordered]@{{ target_seq = $seq; route = 'bootstrap' }}) 'storage'
La-ProviderEnd 'backfill_storage_projections' 1 'Traceback'
La-ProviderBegin 'create_first_admin' ([ordered]@{{ users_exist = $false }}) 'first_admin'
La-ProviderEnd 'create_first_admin' 0 'warning line\n{{"result":"completed"}}'
La-ProviderBegin 'retire_scheduler_authority' ([ordered]@{{}}) 'a001'
La-ProviderEnd 'retire_scheduler_authority' 0 '{{"result":"no_change"}}'
"""
    proc, raw = run_ps(tmp_path, body)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    record = ia.AttemptRecord.from_dict(raw)
    classify = lambda target, kind: ia.classify_target(record, target, kind,
                                                       observer=lambda t, k: "match")[0]
    assert classify(INSTALL, "dir") == ia.CLASS_CREATED
    assert classify(PD, "dir") == ia.CLASS_MODIFIED, "the transcript's product root is never removable"
    assert classify(PD + r"\logs", "dir") == ia.CLASS_MODIFIED
    assert classify(PD + r"\config", "dir") == ia.CLASS_CREATED
    assert classify("corpusfm-web", "service") == ia.CLASS_CREATED
    assert classify(r"\CORPUSfm Update", "task") == ia.CLASS_CREATED
    assert classify(DB + r"\CORPUSfm\CORPUSfm_DB.fmp12", "file") == ia.CLASS_CREATED
    by_intent = {e.intent: e for e in record.ledger}
    assert by_intent["enable_arr_proxy"].post == {"enabled": True}
    assert by_intent["patch_apply"].post["settled"] is True, "unreadable patch facts never authorize removal"
    assert by_intent["backfill_storage_projections"].post == {"result": "incomplete_safe"}
    assert by_intent["provision_keys"].post["generated"] == ["corpus.key"]
    assert by_intent["create_first_admin"].post == {"result": "completed", "created": True}
    assert [e.seq for e in record.ledger] == list(range(1, len(record.ledger) + 1))
    contained = [e for e in record.ledger if e.target == PD + r"\state\update-inbox"]
    assert len(contained) == 1, "an entry is kept for a directory created in the same step"


@supplementary
def test_refuse_first_happens_at_step_one_and_publishes_no_intent(tmp_path):
    proc, raw = run_ps(tmp_path, r"""
La-Write
try { La-Step 'service' 'create' $null @('corpusfm-web'); 'NOT-REFUSED' } catch { $_.Exception.Message }
""", present=["service:corpusfm-web"])
    assert "REFUSE-FIRST" in proc.stdout and "NOT-REFUSED" not in proc.stdout
    assert raw["ledger"] == []


@supplementary
def test_a_failed_action_publishes_its_post_observation_and_rethrows(tmp_path):
    proc, raw = run_ps(tmp_path, rf"""
La-Write
$script:Present.Add('C:\Program Files') | Out-Null
try {{ La-Do 'dir' 'ensure' $null @('{INSTALL}') {{ throw 'boom' }} }} catch {{ 'RETHROWN ' + $_.Exception.Message }}
""")
    assert "RETHROWN boom" in proc.stdout, proc.stderr
    assert [(e["intent"], e["state"], e["post"]) for e in raw["ledger"]] == [
        ("create", "failed", {"exists": False})]
    ia.AttemptRecord.from_dict(raw)


@supplementary
def test_every_wrapper_is_a_pass_through_without_an_attempt(tmp_path):
    proc, raw = run_ps(tmp_path, r"""
function La-Step { throw 'the ordinary path reached the ledger' }
function La-Write { throw 'the ordinary path wrote a record' }
$out = La-Do 'dir' 'ensure' $null @('C:\x') { 'RAN' }
if ($out -ne 'RAN') { throw 'the action did not run' }
try { La-Do 'dir' 'ensure' $null @('C:\x') { throw 'boom' } } catch { 'PROPAGATED ' + $_.Exception.Message }
La-ProviderBegin 'foundation' $null 'foundation'
La-ProviderEnd 'foundation' 1 'x'
function Lc-Run($what, $args2) { return ('LC:' + $what) }
$lc = La-LcRun 'foundation' $null 'publication' @('composition','foundation')
if ($lc -ne 'LC:publication') { throw ('La-LcRun did not return Lc-Run: ' + $lc) }
'SURVIVED'
""", attempt=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PROPAGATED boom" in proc.stdout and "SURVIVED" in proc.stdout
    assert raw is None


@supplementary
def test_unreadable_proxy_facts_report_every_front_as_preexisting(tmp_path):
    proc, _ = run_ps(tmp_path, r"""
La-ProviderPost 'proxy_reconcile' 3 'Traceback: nothing useful' | ConvertTo-Json -Depth 5 -Compress
""")
    post = json.loads(proc.stdout.strip().splitlines()[-1])
    assert post["result"] == "manual_action_required"
    assert set(post["prior_family"]) == {"iis", "claris-nginx"}
    assert all(f["pool_existed"] and f["app_existed"] for f in post["prior_family"].values())


@supplementary
def test_a_moved_aside_root_is_recorded_and_the_recreated_root_is_created_and_not_refused(tmp_path):
    proc, raw = run_ps(tmp_path, rf"""
La-Write
$script:Present.Add('C:\Program Files') | Out-Null; $script:Present.Add('{INSTALL}') | Out-Null
La-Do 'dir' 'move_aside' ([ordered]@{{ moved_to = '{INSTALL}.replaced-1' }}) @('{INSTALL}') {{ $script:Present.Remove('{INSTALL}') | Out-Null }} | Out-Null
La-Do 'dir' 'ensure' $null @('{INSTALL}') {{ $script:Present.Add('{INSTALL}') | Out-Null }} | Out-Null
La-Do 'dir' 'ensure' $null @('{INSTALL}') {{ }} | Out-Null
'CREATED=' + (La-Created 'dir' '{INSTALL}')
""", present=["C:\\Program Files"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CREATED=True" in proc.stdout
    record = ia.AttemptRecord.from_dict(raw)
    assert [(e.intent, e.state) for e in record.ledger] == [
        ("move_aside", "done"), ("create", "done"), ("set_acl", "done")]
    assert record.ledger[0].post == {"exists": False, "moved_to": INSTALL + ".replaced-1"}
    assert ia.classify_target(record, INSTALL, "dir", observer=lambda t, k: "match")[0] == ia.CLASS_CREATED


# ── ruling 7: a nested patch hosting folder refuses before the container exists ─────


def _ps_begin(tmp_path, hosting):
    container = tmp_path / "attempt-not-created"
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "function Die($m) { throw ('DIE: ' + $m) }",
        "function La-Canon([string]$Path) { return $Path.TrimEnd('\\') }",
        ps_function("La-Inside"), ps_function("La-NestedHostingDir"), ps_function("La-BeginAttempt"),
        f"$script:InstallDir = '{INSTALL}'; $InstallDir = '{INSTALL}'",
        f"$script:PatchHostingDir = '{hosting}'; $PatchHostingDir = '{hosting}'",
        f"$script:AttemptDir = '{container}'",
        "$SchedRetiredPresent = $true; $SchedServiceRetired = 'corpusfm-scheduler'",
        "try { La-BeginAttempt } catch { $_.Exception.Message }",
    ])
    path = tmp_path / "begin.ps1"
    path.write_text(script, encoding="utf-8")
    proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                          capture_output=True, text=True)
    return proc, container


@supplementary
@pytest.mark.parametrize("hosting", [INSTALL, INSTALL + r"\hosted", INSTALL.upper() + "\\Hosted\\"])
def test_a_nested_patch_hosting_folder_refuses_before_the_container_exists(tmp_path, hosting):
    proc, container = _ps_begin(tmp_path, hosting)
    assert "-PatchHostingDir" in proc.stdout, proc.stdout + proc.stderr
    assert not container.exists()


@supplementary
def test_a_sibling_patch_hosting_folder_passes_the_nested_check(tmp_path):
    """The control: a sibling reaches the next preflight refusal, still before the container."""
    proc, container = _ps_begin(tmp_path, r"C:\CORPUSfm-Hosted")
    assert "retired corpusfm-scheduler" in proc.stdout and "-PatchHostingDir" not in proc.stdout
    assert not container.exists()


def test_the_nested_check_is_the_first_statement_of_the_preflight():
    body = ps_function("La-BeginAttempt")
    assert body.index("La-NestedHostingDir") < body.index("SchedRetiredPresent") < body.index("CreateDirectory")


def test_a_development_discard_names_its_execution_requirement_not_authority():
    discard = ps_function("La-AttemptDiscard")
    assert "Deletion authority is the protected attempt" in discard
    assert "rerun a complete private package" in discard
    assert discard.index("-WithCommands") < discard.index("Die (")
