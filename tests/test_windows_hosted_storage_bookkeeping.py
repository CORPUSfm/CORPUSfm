"""The Windows fresh install's write-ahead bookkeeping of the HOSTED storage database.

Measured live (signed 0.3004, w-test-private, 2026-09-29): after the storage bootstrap, FileMaker
Server holds `CORPUSfm_DB.fmp12` open with a sharing mode that refuses a read, and the ledger's post-
observation of the storage target died in `La-Sha256` (`Get-FileHash`: "being used by another
process"), leaving the target entry `intended` and the install at exit 1.

**What is real here:** the `La-` writer, `La-Observe` and `La-Sha256` text (current, or the pinned
pre-correction bytes), and the sharing refusal itself — the test holds a real local file open with
`FileShare.None`, and `Get-FileHash` fails on it with the same IOException message Windows gave.
**What is not:** macOS .NET emulates `FileShare` with advisory locks, not NTFS share modes; the Windows
paths are mapped to that local file by a `Get-FileHash` proxy; the SDDL and path doubles are those of
`test_windows_install_attempt`. Windows PowerShell 5.1 against a live FMS-hosted file (including
`Get-Acl` on it) remains the owed live gate. Each record the writer produces is read back by the
APPLICATION's own validator and recovery predicates.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from corpusfm.lifecycle import install_attempt as ia
from corpusfm.lifecycle import uninstall_plan as up
from tests.test_windows_install_attempt import DB, PD, REPO, TEXT, run_ps, supplementary

#: The installer commit whose `La-Observe` hashed every file, the storage target included (0.3004).
PRE_CORRECTION = "d70abf0594b759f7f26c72094a44ddc42248f3a4"
TARGET = DB + r"\CORPUSfm\CORPUSfm_DB.fmp12"
SHARING = "being used by another process"


def _function(text: str, name: str) -> str:
    start = re.search(rf"^function {re.escape(name)}\b", text, re.M)
    assert start, name
    i, depth, quote, comment = text.index("{", start.start()), 0, None, False
    for j in range(i, len(text)):
        ch = text[j]
        if comment:
            comment = ch != "\n"
        elif quote:
            quote = None if ch == quote else quote
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            comment = True
        elif ch in "{}":
            depth += 1 if ch == "{" else -1
            if depth == 0:
                return text[start.start():j + 1]
    raise AssertionError(name)


def _pinned_text() -> str:
    proc = subprocess.run(["git", "-C", str(REPO), "show", f"{PRE_CORRECTION}:installer/windows/install.ps1"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(f"{PRE_CORRECTION} is not in this repository")
    return proc.stdout.replace("\r\n", "\n")


def _prelude(text: str, local: Path) -> str:
    """The real hashing and observation text, over a Windows path mapped to a local file."""
    return f"""
$script:LocalFile = '{local}'
function Get-FileHash {{ param([string]$LiteralPath, [string]$Algorithm)
  if ($script:Mapped -notcontains $LiteralPath) {{ throw ('unmapped ' + $LiteralPath) }}
  Microsoft.PowerShell.Utility\\Get-FileHash -LiteralPath $script:LocalFile -Algorithm $Algorithm }}
$script:Mapped = New-Object System.Collections.Generic.List[string]
{_function(text, "La-Sha256")}
{_function(text, "La-Observe")}
function Hold([string]$Path) {{
  $script:Mapped.Add($Path); $script:Present.Add($Path) | Out-Null
  $script:Held = [IO.File]::Open($script:LocalFile, 'Open', 'ReadWrite', 'None') }}
La-Write
foreach ($p in @('C:\\Program Files', 'C:\\ProgramData', '{PD}', '{PD}\\config', '{DB}')) {{
  $script:Present.Add($p) | Out-Null }}
"""


BOOTSTRAP = rf"""
$target = '{TARGET}'
La-Step 'file' 'ensure' $null @($target)
$script:LaProviderTargetSeqs = $script:LaSeqs
$seq = [int](La-SeqOf 'file' $target)
La-ProviderBegin 'storage_bootstrap' ([ordered]@{{ observe = 'proven_fresh'; route = 'bootstrap'; target_seq = $seq }}) 'storage'
$script:Present.Add('{DB}\CORPUSfm') | Out-Null
Hold $target
try {{
  La-ProviderEnd 'storage_bootstrap' 5 '{{"result":"incomplete_safe","state":"existing_corpus_reachable"}}'
  'STORAGE-ENDED'
  La-ProviderBegin 'backfill_storage_projections' ([ordered]@{{ target_seq = $seq; route = 'bootstrap' }}) 'storage'
  La-ProviderEnd 'backfill_storage_projections' 0 'projections current'
  'BACKFILL-ENDED'
}} catch {{ 'CAUGHT: ' + $_.Exception.Message }} finally {{ $script:Held.Dispose() }}
"""


def _run(tmp_path: Path, text: str, body: str):
    local = tmp_path / "hosted.fmp12"
    local.write_bytes(b"hosted database bytes")
    return run_ps(tmp_path, _prelude(text, local) + body)


def _decide(record, *names):
    decisions = {n: up.Decision(up.REMOVE, up.RECORDED, "test") for n in names}
    return ia.attempt_filter(record, decisions, SimpleNamespace(services=(), ownership=()),
                             observer=lambda t, k: "match")


@supplementary
def test_the_pre_correction_bookkeeping_reproduces_the_live_windows_failure(tmp_path):
    proc, raw = _run(tmp_path, _pinned_text(), BOOTSTRAP)
    assert f"CAUGHT: The process cannot access the file" in proc.stdout, proc.stdout + proc.stderr
    assert SHARING in proc.stdout and "STORAGE-ENDED" not in proc.stdout
    ledger = {e["intent"]: e for e in raw["ledger"]}
    # Exactly the live record: the provider failed, the target entry was never resolved.
    assert ledger["storage_bootstrap"]["state"] == "failed"
    assert ledger["create"]["target"] == TARGET and ledger["create"]["state"] == "intended"


@supplementary
def test_the_hosted_storage_target_is_recorded_undigested_and_recovery_still_owns_it(tmp_path):
    proc, raw = _run(tmp_path, TEXT, BOOTSTRAP)
    assert "STORAGE-ENDED" in proc.stdout and "BACKFILL-ENDED" in proc.stdout, \
        proc.stdout + proc.stderr
    record = ia.AttemptRecord.from_dict(raw)
    target = next(e for e in record.ledger if e.kind == "file" and e.target == TARGET)
    assert target.prior == {"exists": False}
    assert target.state == ia.STATE_FAILED
    assert target.post["exists"] is True and target.post["sha256"] is None
    assert target.post["size"] == 5 and target.post["sddl"]
    assert ia.classify_target(record, TARGET, "file", observer=lambda t, k: "match")[0] \
        == ia.CLASS_CREATED
    narrowed = _decide(record, "storage_db", "storage_rc")
    assert narrowed["storage_db"].decision == up.REMOVE
    assert narrowed["storage_rc"].decision == up.REMOVE
    backfill = next(e for e in record.ledger if e.intent == "backfill_storage_projections")
    assert backfill.prior["target_seq"] == target.seq and backfill.state == ia.STATE_DONE


@supplementary
@pytest.mark.parametrize("pinned", [True, False], ids=["pre_correction", "corrected"])
def test_an_adopted_hosted_storage_target_is_observed_and_stays_preserved(tmp_path, pinned):
    """Adoption observes the target BEFORE the provider, while FMS already hosts it."""
    body = rf"""
Hold '{TARGET}'
$script:Present.Add('{DB}\CORPUSfm') | Out-Null
try {{
  La-Step 'file' 'ensure' $null @('{TARGET}')
  $seq = [int](La-SeqOf 'file' '{TARGET}')
  La-ProviderBegin 'storage_adopt' ([ordered]@{{ observe = 'existing_corpus_on_default'; route = 'adopt'; target_seq = $seq }}) 'storage'
  La-ProviderEnd 'storage_adopt' 0 '{{"result":"completed"}}'
  'ADOPT-ENDED'
}} catch {{ 'CAUGHT: ' + $_.Exception.Message }} finally {{ $script:Held.Dispose() }}
"""
    proc, raw = _run(tmp_path, _pinned_text() if pinned else TEXT, body)
    if pinned:
        assert SHARING in proc.stdout and "ADOPT-ENDED" not in proc.stdout, proc.stdout + proc.stderr
        return
    assert "ADOPT-ENDED" in proc.stdout, proc.stdout + proc.stderr
    record = ia.AttemptRecord.from_dict(raw)
    target = next(e for e in record.ledger if e.kind == "file")
    assert target.intent == "overwrite" and target.prior["sha256"] is None
    assert ia.classify_target(record, TARGET, "file", observer=lambda t, k: "match")[0] \
        == ia.CLASS_MODIFIED
    assert _decide(record, "storage_db", "storage_rc")["storage_db"].decision == up.PRESERVE


@supplementary
@pytest.mark.parametrize("path, when", [
    (DB + r"\PTLaunchPad_50.fmp12", "prior"),
    (PD + r"\config\other.yaml", "post"),
], ids=["another_hosted_database_present_before", "an_unrelated_file_locked_after_creation"])
def test_any_other_unreadable_file_still_refuses_and_publishes_no_undigested_entry(tmp_path, path,
                                                                                    when):
    if when == "prior":
        body = rf"""
Hold '{path}'
try {{ La-Step 'file' 'ensure' $null @('{path}'); 'RECORDED' }}
catch {{ 'CAUGHT: ' + $_.Exception.Message }} finally {{ $script:Held.Dispose() }}
"""
    else:
        body = rf"""
try {{ La-Do 'file' 'create' $null @('{path}') {{ Hold '{path}' }} | Out-Null; 'RECORDED' }}
catch {{ 'CAUGHT: ' + $_.Exception.Message }} finally {{ if ($script:Held) {{ $script:Held.Dispose() }} }}
"""
    proc, raw = _run(tmp_path, TEXT, body)
    assert SHARING in proc.stdout and "RECORDED" not in proc.stdout, proc.stdout + proc.stderr
    for entry in raw["ledger"]:
        for side in ("prior", "post"):
            observed = entry[side] or {}
            assert not (observed.get("exists") and "sha256" in observed
                        and observed["sha256"] is None), entry
    ia.AttemptRecord.from_dict(raw)


def test_only_the_recorded_storage_target_is_left_undigested():
    observe = _function(TEXT, "La-Observe")
    assert observe.count("La-Sha256 $Target") == 2, "every other file and git config stays hashed"
    assert "$script:AttemptRecord.paths.storage_target" in observe
    assert "-ine" in observe, "the exception is an exact (canonical) path match, nothing wider"
