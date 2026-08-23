"""One data-only interpretation boundary for installer provider outcomes.

The lifecycle providers own mutation, recovery evidence, and the six result words.  Installers own
sequencing.  This module is the narrow join between them: both platform scripts submit the same
versioned facts and receive one of three operator conditions without reinterpreting provider JSON.

Nothing here reads machine state or performs recovery.  A returned recovery command is assembled
only from the installation and operation identities supplied in the request and invokes the
provider's existing recovery verb.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from .cli import (
    admin_identity_skip_is_genuine,
    proxy_mixed_success_is_composable,
    storage_fresh_success_is_composable,
)
from .result import (
    COMPLETED,
    FAILED_BEFORE_CHANGE,
    INCOMPLETE_SAFE,
    MANUAL_ACTION_REQUIRED,
    NO_CHANGE,
    ROLLED_BACK,
)

SCHEMA_VERSION = 1
CONTINUE = "continue"
CORRECT_AND_RERUN = "correct_and_rerun"
RECOVER_FIRST = "recover_first"

PROVIDERS = frozenset({"admin_identity", "patch", "proxy", "storage"})
PHASES = frozenset({"provider", "preflight"})
PLATFORMS = frozenset({"posix", "windows"})
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_REQUEST_KEYS = frozenset({
    "schema_version", "phase", "provider", "exit_code", "installation_id",
    "expected_generation", "mode", "install_dir", "platform", "provider_result", "journal",
})
_OPTIONAL_REQUEST_KEYS = frozenset({"recovery_python", "recovery_source"})


class DispositionRefused(ValueError):
    """The submitted facts are not one supported installer/provider state."""


def _canonical_id(value: object) -> str | None:
    return value if isinstance(value, str) and _UUID.fullmatch(value) else None


def _provider_for_journal(journal: Mapping[str, Any]) -> str | None:
    subsystem = str(journal.get("current_subsystem") or "").strip().lower().replace("-", "_")
    mode = str(journal.get("mode") or "").strip().lower().replace("-", "_")
    for provider in PROVIDERS:
        stem = {
            "admin_identity": "admin_identity",
            "patch": "patch_compartment",
            "proxy": "proxy_policy",
            "storage": "storage",
        }[provider]
        if subsystem == stem or subsystem.startswith(stem + ":") or subsystem.startswith(stem + "_"):
            return provider
    # Proxy opens its journal before its first checkpoint, so a killed or wholly restored run may
    # retain provider identity only in the journal mode.  That exact mode is still authoritative.
    if not subsystem and mode == "proxy_policy":
        return "proxy"
    return None


def _journal_facts(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise DispositionRefused("journal must be a JSON object or null")
    return dict(value)


def _candidate_for(provider: str, payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidate = payload.get("candidates" if provider == "proxy" else "candidate")
    return candidate if isinstance(candidate, Mapping) and bool(candidate) else None


def _matching_journal(journal: Mapping[str, Any] | None, *, provider: str,
                      operation_id: str | None, installation_id: str) -> bool:
    if journal is None or operation_id is None:
        return False
    return (
        journal.get("operation_id") == operation_id
        and journal.get("installation_id") == installation_id
        and _provider_for_journal(journal) == provider
    )


def _candidate_journal_ready(provider: str, journal_state: object,
                             journal_result: object, provider_result: object) -> bool:
    """Protocol P composes from resolved evidence; Protocol F composes before resolution."""
    if provider == "patch":
        return journal_state == "resolved" and journal_result == provider_result
    return journal_state in {"open", "checkpointed", "needs_recovery"}


def _recovery_request(provider: str, operation_id: str, installation_id: str) -> tuple[list[str], dict]:
    if provider == "patch":
        return (["patch-compartment", "rollback", "--operation-id", operation_id], {})
    request: dict[str, Any] = {
        "schema_version": 1,
        "operation_id": operation_id,
        "installation_id": installation_id,
        "actor": "installer-recovery",
    }
    if provider in {"proxy", "admin_identity"}:
        request["credential_input"] = "prompt"
    family = {"proxy": "proxy", "admin_identity": "admin-identity", "storage": "storage"}[provider]
    return ([family, "abort", "--request", "{request}"], request)


def _posix_recovery(provider: str, operation_id: str, installation_id: str,
                    install_dir: str, *, python: str | None = None,
                    source: str | None = None) -> str:
    argv, request = _recovery_request(provider, operation_id, installation_id)
    python = python or f"{install_dir.rstrip('/')}/venv/bin/python"
    source = source or f"{install_dir.rstrip('/')}/src"
    if not request:
        command = shlex.join(
            ["env", f"PYTHONPATH={source}", python, "-m", "corpusfm.lifecycle", *argv])
        return (
            "sudo sh -ceu "
            + shlex.quote(f"rc=0; {command} || rc=$?; [ \"$rc\" -eq 0 ] || [ \"$rc\" -eq 2 ]")
        )
    payload = json.dumps(request, separators=(",", ":"), sort_keys=True)
    verb = " ".join(shlex.quote(part) for part in argv[:-1])
    return (
        "sudo sh -ceu "
        + shlex.quote(
            "d=$(mktemp -d /run/corpusfm-installer-recovery.XXXXXX); "
            "trap 'rm -rf \"$d\"' EXIT; umask 077; "
            "printf %s \"$1\" >\"$d/request.json\"; "
            "rc=0; "
            f"env PYTHONPATH={shlex.quote(source)} {shlex.quote(python)} -m corpusfm.lifecycle "
            f"{verb} \"$d/request.json\" || rc=$?; "
            "[ \"$rc\" -eq 0 ] || [ \"$rc\" -eq 2 ]"
        )
        + " sh " + shlex.quote(payload)
    )


def _ps_single(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _windows_recovery(provider: str, operation_id: str, installation_id: str,
                      install_dir: str, *, python: str | None = None,
                      source: str | None = None) -> str:
    root = str(PureWindowsPath(install_dir))
    python = python or str(PureWindowsPath(root) / "python" / "python.exe")
    source = source or str(PureWindowsPath(root) / "src")
    argv, request = _recovery_request(provider, operation_id, installation_id)
    if not request:
        script = (
            f"$env:PYTHONPATH={_ps_single(source)}; & {_ps_single(python)} -m corpusfm.lifecycle "
            + " ".join(_ps_single(part) for part in argv)
            + "; $code=$LASTEXITCODE; if ($code -eq 0 -or $code -eq 2) { exit 0 }; exit $code"
        )
    else:
        payload = json.dumps(request, separators=(",", ":"), sort_keys=True)
        cli = " ".join(_ps_single(part) for part in argv[:-1])
        # The fixed run directory is installation-independent on Windows.  Both the directory and
        # request receive the same protected SYSTEM/Administrators authority as installer requests.
        run_dir = r"C:\ProgramData\CORPUSfm\run"
        script = (
            "$ErrorActionPreference='Stop'; $code=1; "
            f"$env:PYTHONPATH={_ps_single(source)}; "
            f"$d=Join-Path {_ps_single(run_dir)} ('installer-recovery.'+[guid]::NewGuid().ToString('N')); "
            "New-Item -ItemType Directory -Path $d -Force | Out-Null; "
            "try { "
            "& icacls $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' "
            "'*S-1-5-32-544:(OI)(CI)F' | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'icacls directory failed' }; "
            "$r=Join-Path $d 'request.json'; "
            f"[IO.File]::WriteAllText($r,{_ps_single(payload)},"
            "(New-Object System.Text.UTF8Encoding($false))); "
            "& icacls $r /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'icacls request failed' }; "
            f"& {_ps_single(python)} -m corpusfm.lifecycle {cli} $r; $code=$LASTEXITCODE "
            "} finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }; "
            "if ($code -eq 0 -or $code -eq 2) { exit 0 }; exit $code"
        )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


def _runtime_override(request: Mapping[str, Any], platform: str) -> tuple[str | None, str | None]:
    python = request.get("recovery_python")
    source = request.get("recovery_source")
    if python is None and source is None:
        return None, None
    if not isinstance(python, str) or not isinstance(source, str) or not python or not source:
        raise DispositionRefused(
            "recovery_python and recovery_source must be supplied together as non-empty paths")
    path_type = PurePosixPath if platform == "posix" else PureWindowsPath
    if not path_type(python).is_absolute() or not path_type(source).is_absolute():
        raise DispositionRefused("recovery runtime paths must be absolute for the target platform")
    if any(char in python + source for char in "\r\n\t"):
        raise DispositionRefused("recovery runtime paths contain control characters")
    return python, source


def _recovery_command(provider: str, operation_id: str, installation_id: str,
                      install_dir: str, platform: str, *, python: str | None = None,
                      source: str | None = None) -> str:
    if platform == "posix":
        return _posix_recovery(provider, operation_id, installation_id, install_dir,
                               python=python, source=source)
    return _windows_recovery(provider, operation_id, installation_id, install_dir,
                             python=python, source=source)


def _answer(condition: str, *, compose: bool = False, retire_provider: str | None = None,
            operation_id: str | None = None, reason: str,
            recovery_command: str | None = None,
            first_administrator_owed: bool = False) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "condition": condition,
        "compose": bool(compose),
        "retire_provider": retire_provider,
        "operation_id": operation_id,
        "leave_services_stopped": condition == RECOVER_FIRST,
        "first_administrator_owed": bool(first_administrator_owed),
        "reason": reason,
        "recovery_command": recovery_command,
    }


def _recover(*, provider: str, operation_id: str | None, installation_id: str,
             install_dir: str, platform: str, reason: str,
             recovery_python: str | None = None, recovery_source: str | None = None) -> dict[str, Any]:
    if operation_id is None:
        raise DispositionRefused(
            f"{provider} recovery is owed but no canonical operation_id identifies it")
    return _answer(
        RECOVER_FIRST, operation_id=operation_id, reason=reason,
        recovery_command=_recovery_command(
            provider, operation_id, installation_id, install_dir, platform,
            python=recovery_python, source=recovery_source),
    )


def _preflight(request: Mapping[str, Any], journal: Mapping[str, Any] | None) -> dict[str, Any]:
    if journal is None:
        return _answer(CONTINUE, reason="no lifecycle journal is present")
    state = journal.get("state")
    operation_id = _canonical_id(journal.get("operation_id"))
    installation_id = _canonical_id(journal.get("installation_id"))
    provider = _provider_for_journal(journal)
    recovery_python, recovery_source = _runtime_override(request, str(request["platform"]))
    if not installation_id:
        raise DispositionRefused("the lifecycle journal has no canonical installation_id")
    if state in {"open", "checkpointed", "needs_recovery"}:
        if provider is None:
            raise DispositionRefused("the unresolved lifecycle journal does not identify its provider")
        return _recover(
            provider=provider, operation_id=operation_id, installation_id=installation_id,
            install_dir=str(request["install_dir"]), platform=str(request["platform"]),
            reason=f"lifecycle operation {operation_id} is unresolved and must be recovered first",
            recovery_python=recovery_python, recovery_source=recovery_source,
        )
    if state == "resolved" and journal.get("result") in {
            COMPLETED, NO_CHANGE, FAILED_BEFORE_CHANGE, ROLLED_BACK}:
        if provider is None or operation_id is None:
            raise DispositionRefused("the spent lifecycle journal does not identify its provider and operation")
        return _answer(
            CONTINUE, retire_provider=provider, operation_id=operation_id,
            reason=(f"the prior {provider} operation is resolved {journal.get('result')} and may "
                    "be retired; any unconsumed patch candidate is reconstructed by this run"),
        )
    raise DispositionRefused(
        f"journal state {state!r} with result {journal.get('result')!r} is not safely disposable")


def classify(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return the one installer disposition for a strict version-1 data request."""
    if not isinstance(request, Mapping):
        raise DispositionRefused("the disposition request is not a JSON object")
    extra = set(request) - (_REQUEST_KEYS | _OPTIONAL_REQUEST_KEYS)
    missing = _REQUEST_KEYS - set(request)
    if extra or missing:
        raise DispositionRefused(
            f"the disposition request has extra keys {sorted(extra)} and missing keys {sorted(missing)}")
    if request.get("schema_version") != SCHEMA_VERSION:
        raise DispositionRefused(f"unsupported schema_version {request.get('schema_version')!r}")
    phase = request.get("phase")
    if phase not in PHASES:
        raise DispositionRefused(f"phase must be one of {sorted(PHASES)}")
    if phase != "preflight" and any(key in request for key in _OPTIONAL_REQUEST_KEYS):
        raise DispositionRefused("recovery runtime paths are accepted only for preflight recovery")
    platform = request.get("platform")
    if platform not in PLATFORMS:
        raise DispositionRefused(f"platform must be one of {sorted(PLATFORMS)}")
    install_dir = request.get("install_dir")
    if not isinstance(install_dir, str) or not install_dir:
        raise DispositionRefused("install_dir must be a non-empty string")
    journal = _journal_facts(request.get("journal"))
    if phase == "preflight":
        return _preflight(request, journal)

    provider = request.get("provider")
    if provider not in PROVIDERS:
        raise DispositionRefused(f"provider must be one of {sorted(PROVIDERS)}")
    installation_id = _canonical_id(request.get("installation_id"))
    if installation_id is None:
        raise DispositionRefused("installation_id is absent or not canonical")
    expected_generation = request.get("expected_generation")
    if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
        raise DispositionRefused("expected_generation must be an integer")
    exit_code = request.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise DispositionRefused("exit_code must be an integer")
    payload = request.get("provider_result")
    if not isinstance(payload, Mapping):
        raise DispositionRefused("provider_result must be a JSON object")
    result = payload.get("result")
    expected_codes = {
        COMPLETED: {0}, NO_CHANGE: {0}, FAILED_BEFORE_CHANGE: {1, 4},
        ROLLED_BACK: {2}, MANUAL_ACTION_REQUIRED: {3}, INCOMPLETE_SAFE: {3, 5},
    }
    if result not in expected_codes or exit_code not in expected_codes[result]:
        raise DispositionRefused(
            f"provider result {result!r} and exit code {exit_code} do not form a supported pair")

    operation_id = _canonical_id(payload.get("operation_id"))
    journal_operation = _canonical_id(journal.get("operation_id")) if journal else None
    if operation_id and journal_operation and operation_id != journal_operation:
        raise DispositionRefused("the provider result and lifecycle journal name different operations")
    operation_id = operation_id or journal_operation
    journal_matches = _matching_journal(
        journal, provider=provider, operation_id=operation_id, installation_id=installation_id)
    journal_state = journal.get("state") if journal_matches else None
    journal_result = journal.get("result") if journal_matches else None
    candidate = _candidate_for(provider, payload)
    awaiting = payload.get("awaiting_composition") is True
    if awaiting and candidate is None:
        raise DispositionRefused("awaiting_composition is true but no candidate is present")

    if provider == "proxy":
        mixed, mixed_reason = proxy_mixed_success_is_composable(
            payload, installation_id=installation_id, expected_generation=expected_generation)
        if mixed:
            if not journal_matches or not _candidate_journal_ready(
                    provider, journal_state, journal_result, result):
                raise DispositionRefused(
                    "the mixed proxy candidate has no matching unresolved lifecycle journal")
            return _answer(CONTINUE, compose=True, operation_id=operation_id, reason=mixed_reason)

    if provider == "storage":
        fresh, fresh_reason = storage_fresh_success_is_composable(
            payload, installation_id=installation_id, expected_generation=expected_generation,
            mode=str(request.get("mode") or ""),
        )
        if fresh:
            if not journal_matches or not _candidate_journal_ready(
                    provider, journal_state, journal_result, result):
                raise DispositionRefused(
                    "the fresh storage candidate has no matching unresolved lifecycle journal")
            return _answer(
                CONTINUE, compose=True, operation_id=operation_id, reason=fresh_reason,
                first_administrator_owed=True,
            )

    if result in {COMPLETED, NO_CHANGE}:
        if candidate is not None:
            if not journal_matches or not _candidate_journal_ready(
                    provider, journal_state, journal_result, result):
                raise DispositionRefused(
                    f"the {provider} candidate has no matching unresolved lifecycle journal")
            if provider != "patch" and not awaiting:
                raise DispositionRefused("a provider candidate is present without awaiting_composition")
            if provider == "proxy":
                if payload.get("installation_id") != installation_id or \
                   payload.get("expected_generation") != expected_generation:
                    raise DispositionRefused("the proxy candidate inspected different installation facts")
            else:
                if candidate.get("inspected_installation_id") != installation_id or \
                   candidate.get("inspected_generation") != expected_generation:
                    raise DispositionRefused("the provider candidate inspected different installation facts")
            return _answer(
                CONTINUE, compose=True, operation_id=operation_id,
                reason=f"{provider} returned a candidate that is ready to compose",
            )
        if awaiting:
            raise DispositionRefused("the provider awaits composition but returned no candidate")
        if provider == "admin_identity":
            genuine, reason = admin_identity_skip_is_genuine(payload)
            if not genuine:
                return _answer(CORRECT_AND_RERUN, reason=reason)
        if journal_state in {"open", "checkpointed", "needs_recovery"}:
            return _recover(
                provider=provider, operation_id=operation_id, installation_id=installation_id,
                install_dir=install_dir, platform=platform,
                reason=f"{provider} returned no candidate but left an unresolved operation",
            )
        retire = provider if journal_state == "resolved" and operation_id else None
        return _answer(
            CONTINUE, retire_provider=retire, operation_id=operation_id,
            reason=f"{provider} completed with no candidate and no recovery owed",
        )

    if result == FAILED_BEFORE_CHANGE:
        retire = provider if journal_state == "resolved" and operation_id else None
        return _answer(
            CORRECT_AND_RERUN, retire_provider=retire, operation_id=operation_id,
            reason=str(payload.get("next_action") or
                       f"{provider} refused before changing the machine; correct the reported condition"),
        )

    if result == ROLLED_BACK and journal_state == "resolved":
        return _answer(
            CORRECT_AND_RERUN, retire_provider=provider, operation_id=operation_id,
            reason=f"{provider} restored and verified its changes; correct the reported condition",
        )

    if journal_state in {"open", "checkpointed", "needs_recovery"}:
        return _recover(
            provider=provider, operation_id=operation_id, installation_id=installation_id,
            install_dir=install_dir, platform=platform,
            reason=str(payload.get("next_action") or
                       f"{provider} left an unresolved operation that must be recovered first"),
        )

    raise DispositionRefused(
        f"{provider} returned {result!r}, but no matching unresolved recovery record is available")


__all__ = [
    "CONTINUE", "CORRECT_AND_RERUN", "RECOVER_FIRST", "SCHEMA_VERSION",
    "DispositionRefused", "classify",
]
