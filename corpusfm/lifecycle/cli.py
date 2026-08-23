"""The thin entrypoint a shell or PowerShell lifecycle script calls (packet 1246-01).

One command, so neither language grows its own copy of the lifecycle state model:

    python -m corpusfm.lifecycle status [--json]
    python -m corpusfm.lifecycle validate <manifest.json>
    python -m corpusfm.lifecycle propose --install-dir DIR [--marker install.yaml] [--json]
    python -m corpusfm.lifecycle result-vocabulary [--json]
    python -m corpusfm.lifecycle patch-compartment inspect  --request <root-owned.json>
    python -m corpusfm.lifecycle patch-compartment apply    --request <root-owned.json>
    python -m corpusfm.lifecycle patch-compartment rollback --operation-id <id>
    python -m corpusfm.lifecycle proxy status|reconcile|finalize|abort|retire --request <root-owned.json>
    python -m corpusfm.lifecycle proxy-public <verb> [<type>|all] [--json]
    python -m corpusfm.lifecycle admin-identity observe|reconcile|remove|finalize|abort --request <root-owned-json>

**`status`, `validate`, `propose` and `result-vocabulary` read and propose only. `patch-compartment
apply` and `rollback` MUTATE** — they create the compartment directory, register an Additional
Database Folder slot and seed the sandbox. This distinction is stated rather than implied because
the module said "never mutates" for as long as it was true and would otherwise keep saying it.

Publishing a locator and writing a manifest remain absent: those are 1246-04's single composed
write, and `patch-compartment` deliberately RETURNS candidate facts instead of writing them.

**`proxy` and `proxy-public` are TWO SURFACES, not one vocabulary with two spellings (1246-06 §8).**
`proxy` is the INTEGRATOR protocol: it takes a root-owned request because 1246-04 must plan and act
*before a manifest exists*, so it supplies its proposed web facts; `reconcile` there requires
`disposition=composed_candidate`, and `finalize`/`abort` resolve a composition. `proxy-public` is what
the `corpusfm-proxy` wrapper calls: **no request file, no disposition**, route facts read from
`manifest.web` only, and mutating verbs use `direct_commit` internally. An administrator is never
asked to choose a persistence mode, and `finalize`/`abort` are not reachable from there at all.

**`admin-identity observe` mutates nothing, asks for nothing, takes no lock and creates no Machine
Key** — it does report an unresolved operation, and whether discharging it will need FMS authority,
before anything can prompt. **`reconcile`, `remove` and `abort` MUTATE and hold the lifecycle lock;
`finalize` holds it too**, because it resolves the shared recovery evidence and deletes the backups an
`abort` would restore from. A successful `reconcile` is left AWAITING COMPOSITION: the journal record
and the recovery evidence stay in place until `finalize` proves the integrator wrote the candidate.
It classifies six independent fact axes and returns
exactly one tagged disposition — `prerequisite_required`, `not_applicable` or
`identity_observation` — plus `invalid_combination` when the observed facts violate a stated
relation. Only an `identity_observation` carries an `IdentityState`.

**No path override.** The layout comes from ``platform_layout()`` and cannot be redirected by a flag
or an environment variable — machine-wide authority that a variable can move is not machine-wide
authority. Tests exercise the layout-taking API directly.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping

from .bridge import propose_manifest
from .errors import LifecycleError, RecordInvalid, RecordMissing
from .journal import Journal
from .layout import platform_layout
from .locator import locator_for
from .lock import LifecycleLock
from .manifest import ManifestStore
from .result import (
    COMPLETED, FAILED_BEFORE_CHANGE, INCOMPLETE_SAFE, MANUAL_ACTION_REQUIRED, NO_CHANGE,
    RESULT_VOCABULARY, ROLLED_BACK,
)
from .schema import (
    LIFECYCLE_MODES, PROXY_TYPES, InstallationManifest, assert_identity_agrees,
)
from .uninstall_terminal import TerminalCleanupRefused


def _journal_state(layout) -> tuple[str, dict[str, Any]]:
    """Read the machine journal. Independent of the locator, so it is read unconditionally."""
    journal = Journal(layout)
    extra: dict[str, Any] = {}
    try:
        record = journal.read()
    except LifecycleError as exc:
        extra["journal_detail"] = str(exc)
        return "invalid", extra
    if record is None:
        return "none", extra
    extra["journal_operation"] = record.operation_id
    extra["journal_mode"] = record.mode
    if record.current_subsystem:
        extra["journal_subsystem"] = record.current_subsystem
    if record.result:
        extra["journal_result"] = record.result
    return record.state, extra


def _status() -> dict[str, Any]:
    layout = platform_layout()
    report: dict[str, Any] = {"locator_location": layout.describe_locator()}

    # The journal is machine state in its OWN right and is read BEFORE anything short-circuits.
    # The first version returned as soon as the locator was missing, so an interrupted fresh
    # install — journal open, locator not yet published, which is precisely the window a fresh
    # install spends most of its life in — reported "missing" and trustworthy. A direct probe
    # confirmed it. Interrupted work must never be invisible because the pointer to it never landed.
    journal_state, journal_extra = _journal_state(layout)
    report["journal"] = journal_state
    report.update(journal_extra)

    try:
        locator = locator_for(layout).read()
    except RecordMissing as exc:
        report["locator"] = "missing"
        report["detail"] = str(exc)
        return report
    except (RecordInvalid, LifecycleError) as exc:
        report["locator"] = "invalid"
        report["detail"] = str(exc)
        return report

    report["locator"] = "present"
    report["installation_id"] = locator.installation_id
    report["install_dir"] = locator.install_dir

    store = ManifestStore(locator.install_dir, locator.manifest_relative_path)
    report["manifest_path"] = str(store.path)
    try:
        manifest = store.read()
    except RecordMissing as exc:
        report["manifest"] = "missing"
        report["detail"] = str(exc)
        return report
    except LifecycleError as exc:
        report["manifest"] = "invalid"
        report["detail"] = str(exc)
        return report

    try:
        assert_identity_agrees(locator, manifest, manifest_path=str(store.path))
    except LifecycleError as exc:
        report["manifest"] = "mismatch"
        report["detail"] = str(exc)
        return report

    report["manifest"] = "valid"
    report["generation"] = manifest.generation
    report["migration_state"] = manifest.migration.state
    report["last_result"] = None if manifest.last_result is None else manifest.last_result.result
    return report


# States in which the machine's lifecycle record can be believed. "missing" belongs here: no
# locator is the honest answer "nothing is installed", not a failure. Every other state means state
# EXISTS and cannot be trusted, and an independent review was right that reporting those with exit 0
# hands a shell script a success it did not earn.
_TRUSTWORTHY_LOCATOR = {"missing", "present"}
_TRUSTWORTHY_MANIFEST = {None, "valid"}
# Only these two mean "no lifecycle operation is owed anything". `open`, `checkpointed` and
# `needs_recovery` all mean an operation stopped in the middle, whatever the locator says.
_SETTLED_JOURNAL = {"none", "resolved"}


def _status_is_trustworthy(report: dict[str, Any]) -> bool:
    if report.get("journal") not in _SETTLED_JOURNAL:
        return False
    if report.get("locator") not in _TRUSTWORTHY_LOCATOR:
        return False
    return report.get("manifest") in _TRUSTWORTHY_MANIFEST


def _render(report: dict[str, Any], as_json: bool) -> str:
    if as_json:
        return json.dumps(report, indent=2, sort_keys=True)
    return "\n".join(f"{k}: {v}" for k, v in report.items())


# ── patch-compartment ─────────────────────────────────────────────────────────
# Exit codes are PER VERB and never fall through to the generic handler below: a LifecycleError
# escaping to `return 2` would be read by a shell as `rolled_back`, which is a lie about whether a
# database was touched.
_PC_OK = 0                      # VERIFIED_READY
_PC_REFUSED = 1                 # failed_before_change / no_change — nothing was left behind
_PC_ROLLED_BACK = 2             # mutated, fully restored
_PC_MANUAL = 3                  # mutated, a human must act
_PC_BAD_REQUEST = 4             # the request file or its ownership was refused

# ── journal disposition, stated as the six words ──────────────────────────────
# Written as two EXPLICIT sets rather than "everything except three words". The complement form is
# what produced the wedge: `failed_before_change` — which every pre-mutation refusal returns, and
# which writes no recovery record at all — fell into the retain branch, so an ordinary refusal left
# the journal needing a recovery that had no evidence to perform. A new result word must be placed
# deliberately in one set or the other, and the assertion below makes forgetting it a build failure.
_RESOLVE_AND_CLEAR = frozenset({COMPLETED, NO_CHANGE, ROLLED_BACK, FAILED_BEFORE_CHANGE})
_RETAIN_RECOVERY = frozenset({INCOMPLETE_SAFE, MANUAL_ACTION_REQUIRED})
assert _RESOLVE_AND_CLEAR | _RETAIN_RECOVERY == RESULT_VOCABULARY
assert not (_RESOLVE_AND_CLEAR & _RETAIN_RECOVERY)

_REQUEST_KEYS = {
    "requested", "install_dir", "fms_root", "fms_database_dir", "storage_dirs", "protected_dirs",
    "service_identity", "fms_identity", "flavour", "seed",
}
_IDENTITY_KEYS = {"flavour", "account", "role"}


def _sandbox_decisions():
    from .patch_compartment import SandboxDecision

    return tuple(SandboxDecision)


class _RequestRefused(Exception):
    """The request file is not an acceptable input to a privileged operation."""


def _stat_refusal(st, what: str) -> str | None:
    """POSIX: why this stat result is unacceptable as privileged input, or None.

    Its own function so the RULE can be exercised against a stat result directly, instead of a test
    monkeypatching `Path.stat` — which patches it for every caller, pytest included.
    """
    if st.st_uid != 0:
        return f"{what} is not root-owned (uid {st.st_uid})"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{what} is group- or world-writable"
    return None


def _windows_authority_refusal(authority, *, system_sid: str, owner_sids: tuple,
                               what: str) -> str | None:
    """WINDOWS: the platform-native equivalent of root-owned-and-not-group-writable.

    The POSIX check used to be skipped entirely on Windows, which meant the rule protecting a
    privileged input simply did not exist there. A POSIX mode proves nothing about NTFS, so the same
    question is asked in the platform's own terms: is the DACL protected, is the owner the invoking
    elevated administrator or SYSTEM, and is anyone else named on it at all.
    """
    allowed = set(owner_sids) | {system_sid}
    if not authority.protected:
        return f"{what} does not carry a protected DACL"
    if authority.inherited:
        return f"{what} inherits access from its parent directory"
    if authority.owner not in allowed:
        return (f"{what} is owned by {authority.owner}, not the invoking administrator or SYSTEM")
    extra = [t for t in authority.trustees if t not in allowed]
    if extra:
        return f"{what} grants access to {', '.join(sorted(extra))}"
    return None


def _open_privileged_request(path: Path, *, authority_api=None):
    """Open ONCE, then judge and read the SAME open file.

    Stat-by-path then open-by-path is the TOCTOU this check exists to close: both calls follow
    symlinks, so a link swapped between them, or a root-owned file in a directory a non-root account
    can write, defeats a path-based check entirely. `os.fstat` on the descriptor answers about the
    object actually opened, and `O_NOFOLLOW` refuses to open a symlink at all.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise _RequestRefused(f"{path} could not be opened as a plain file: {exc.strerror}") from exc
    try:
        refusal = _privileged_input_refusal(fd, str(path), authority_api=authority_api)
        if refusal is not None:
            raise _RequestRefused(refusal)
        with os.fdopen(os.dup(fd), encoding="utf-8") as handle:
            return handle.read()
    finally:
        os.close(fd)


def _privileged_input_refusal(fd: int, what: str, *, authority_api=None) -> str | None:
    """One question, asked in each platform's own terms — and never skipped."""
    if os.name != "nt" and authority_api is None:
        return _stat_refusal(os.fstat(fd), what)
    api = authority_api
    if api is None:                                # pragma: no cover - platform-specific
        from .protection import real_windows_file_authority

        api = real_windows_file_authority()
    try:
        authority = api.authority_of(fd)
        system_sid = api.system_sid_text()
        owner_sids = tuple(api.invoking_owner_sids())
    except Exception as exc:
        # Fail CLOSED: ownership evidence that cannot be read is not ownership evidence.
        return f"{what}: its ownership and access could not be read ({type(exc).__name__})"
    return _windows_authority_refusal(authority, system_sid=system_sid, owner_sids=owner_sids,
                                      what=what)


def _read_request(path: str, *, authority_api=None):
    """Root-owned, not group/world-writable, no unknown keys, no credential.

    Ownership is checked because this file is an input to a privileged operation: a request a
    non-root account can rewrite between the check and the read is not a request, it is a channel.
    """
    from .service_identity import ServiceIdentity

    text = _open_privileged_request(Path(path), authority_api=authority_api)
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise _RequestRefused(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise _RequestRefused("the request must be a JSON object")

    unknown = set(raw) - _REQUEST_KEYS
    if unknown:
        raise _RequestRefused(f"unknown request key(s): {', '.join(sorted(unknown))}")
    missing = _REQUEST_KEYS - set(raw)
    if missing:
        raise _RequestRefused(f"missing request key(s): {', '.join(sorted(missing))}")

    def identity(value, what: str):
        if not isinstance(value, dict) or set(value) != _IDENTITY_KEYS:
            raise _RequestRefused(f"{what} must name exactly flavour, account and role")
        return ServiceIdentity(**value)

    from .patch_compartment import CompartmentInputs

    try:
        return CompartmentInputs(
            requested=Path(raw["requested"]),
            install_dir=Path(raw["install_dir"]),
            fms_root=Path(raw["fms_root"]),
            fms_database_dir=Path(raw["fms_database_dir"]),
            storage_dirs=tuple(Path(x) for x in raw["storage_dirs"]),
            protected_dirs=tuple(Path(x) for x in raw["protected_dirs"]),
            service_identity=identity(raw["service_identity"], "service_identity"),
            fms_identity=identity(raw["fms_identity"], "fms_identity"),
            flavour=str(raw["flavour"]),
            seed=Path(raw["seed"]),
        )
    except (TypeError, ValueError) as exc:
        raise _RequestRefused(f"the request is not well formed: {exc}") from exc


_KEYS_REQUEST_KEYS = frozenset({
    "schema_version", "actor", "flavour", "database_name", "database_search_dirs",
    "service_account", "web_sid", "scheduler_sid", "pre_service",
})


def _provision_keys(args) -> int:
    """Establish both key files, or FAIL. There is no warning path and no partial success.

    Exit 1 (`failed_before_change`) for every refusal: this operation never overwrites a Corpus Key
    and never leaves a half-written file, so a refusal genuinely means the installation is as it was.
    The installer must treat it as fatal — a box that continues past a missing Machine Key reaches
    the admin-identity provider and refuses there instead, which is how the failure this replaces
    presented.
    """
    from . import key_provisioning as kp

    try:
        text = _open_privileged_request(Path(args.request))
        raw = json.loads(text)
        if not isinstance(raw, dict):
            raise _RequestRefused("the request must be a JSON object")
        unknown = set(raw) - _KEYS_REQUEST_KEYS
        if unknown:
            raise _RequestRefused(f"unknown request key(s): {', '.join(sorted(unknown))}")
        for required in ("schema_version", "actor", "flavour", "database_name",
                         "database_search_dirs"):
            if required not in raw:
                raise _RequestRefused(f"missing request key: {required}")
        if raw["schema_version"] != 1:
            raise _RequestRefused(
                f"request schema_version {raw['schema_version']!r}; this build accepts 1")
        if not isinstance(raw["database_search_dirs"], list) or not raw["database_search_dirs"]:
            raise _RequestRefused(
                "database_search_dirs must be a non-empty list; an empty search cannot positively "
                "prove that no corpus exists")
    except _RequestRefused as exc:
        print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": "request_refused",
                          "detail": str(exc)}, indent=2, sort_keys=True))
        return _PC_BAD_REQUEST
    except (OSError, ValueError) as exc:
        print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": "request_unreadable",
                          "detail": str(exc)}, indent=2, sort_keys=True))
        return _PC_BAD_REQUEST

    flavour = str(raw["flavour"])
    pre_service = raw.get("pre_service", False)
    if not isinstance(pre_service, bool):
        print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": "request_refused",
                          "detail": "pre_service must be true or false"},
                         indent=2, sort_keys=True))
        return _PC_BAD_REQUEST
    if pre_service and flavour != "windows":
        print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": "request_refused",
                          "detail": "pre_service protection is a Windows mode; POSIX creates its "
                                    "service account before the keys are provisioned"},
                         indent=2, sort_keys=True))
        return _PC_BAD_REQUEST
    uid = gid = None
    if flavour != "windows":
        account = raw.get("service_account")
        if not account:
            print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": "request_refused",
                              "detail": "a POSIX request must name service_account"},
                             indent=2, sort_keys=True))
            return _PC_BAD_REQUEST
        try:
            uid, gid = kp.posix_service_ids(str(account))
        except kp.KeyProvisioningFailed as exc:
            print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": "service_account_missing",
                              "detail": str(exc)}, indent=2, sort_keys=True))
            return _PC_REFUSED

    try:
        report = kp.provision(
            database_name=str(raw["database_name"]),
            database_search_dirs=[str(d) for d in raw["database_search_dirs"]],
            flavour=flavour, service_uid=uid, service_gid=gid,
            web_sid=raw.get("web_sid"), scheduler_sid=raw.get("scheduler_sid"),
            pre_service=pre_service)
    except LifecycleError as exc:
        print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": type(exc).__name__,
                          "detail": str(exc)}, indent=2, sort_keys=True))
        return _PC_REFUSED
    except Exception as exc:                      # noqa: BLE001
        print(json.dumps({"result": FAILED_BEFORE_CHANGE, "code": type(exc).__name__,
                          "detail": f"key provisioning did not complete: {exc}"},
                         indent=2, sort_keys=True))
        return _PC_REFUSED

    print(json.dumps(report.payload(), indent=2, sort_keys=True))
    return 0


def _pc_emit(payload: dict[str, Any]) -> None:
    """The ONE place a patch-compartment result is printed.

    Three hand-built payloads previously bypassed the secret fence, and one of them printed
    `str(exc)` verbatim. A single emitter is what makes "no secret leaves this verb" checkable.
    """
    from .secret_guard import assert_no_secrets

    assert_no_secrets(payload, what="the patch-compartment result")
    print(json.dumps(payload, indent=2, sort_keys=True))


def _pc_finding(code: str, detail: str, *, state: str, next_action: str,
                operation_id: str | None = None) -> dict[str, Any]:
    return {
        "state": state, "result": "failed_before_change", "operation_id": operation_id,
        "next_action": next_action,
        "findings": [{"code": code, "detail": detail, "identity": None}],
        "candidate": None,
    }


def _pc_payload(report, *, operation_id: str | None, candidate=None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "state": report.state.value,
        "result": report.result,
        "operation_id": operation_id,
        "next_action": report.next_action,
        "findings": [
            {"code": f.code, "detail": f.detail, "identity": f.identity} for f in report.findings
        ],
        # A candidate that is not verified is not a candidate.
        "candidate": None if candidate is None else {
            "patch": candidate.patch.to_dict(),
            "patch_hosting_dir": str(candidate.patch_hosting_dir),
            "inspected_generation": candidate.inspected_generation,
            "inspected_installation_id": candidate.inspected_installation_id,
            **({"ownership": [dict(e) for e in candidate.ownership]}
               if candidate.ownership else {}),
        },
    }
    return payload


def _pc_exit(result_word: str, state_value: str) -> int:
    from .patch_compartment import CompartmentState
    from .result import (
        COMPLETED, INCOMPLETE_SAFE, MANUAL_ACTION_REQUIRED, ROLLED_BACK,
    )

    if state_value == CompartmentState.VERIFIED_READY.value and result_word in (
        COMPLETED, "no_change"
    ):
        return _PC_OK
    if result_word == ROLLED_BACK:
        return _PC_ROLLED_BACK
    if result_word in (MANUAL_ACTION_REQUIRED, INCOMPLETE_SAFE):
        return _PC_MANUAL
    return _PC_REFUSED


class _AuthorityRefused(Exception):
    """Installation authority could not be established. A refusal, never a default."""


def _published_identity() -> tuple[str, int]:
    """(installation_id, generation) — READ ONLY, and REQUIRED before any mutation.

    A valid locator is the precondition: an absent, unreadable or inconsistent one is refused, not
    defaulted. Only the narrower case — a valid locator whose manifest is not written yet — is
    permitted, and it is generation ZERO, which is exactly what `ManifestStore.write` expects for a
    first publication.

    The failure reason is RAISED rather than discarded: an apply that reached VERIFIED_READY on a
    box with no readable locator used to exit 0 with a null candidate and no explanation, which
    silently loses the handoff to 1246-04 on the one ordering the packet specifies.
    """
    layout = platform_layout()
    try:
        locator = locator_for(layout).read()
    except LifecycleError as exc:
        raise _AuthorityRefused(
            f"the installation locator is absent or unreadable: {exc}") from exc
    try:
        store = ManifestStore(locator.install_dir, locator.manifest_relative_path)
    except LifecycleError as exc:
        raise _AuthorityRefused(f"the manifest store cannot be addressed: {exc}") from exc
    try:
        manifest = store.read()
    except RecordMissing:
        return locator.installation_id, 0          # first publication
    except LifecycleError as exc:
        raise _AuthorityRefused(f"the installation manifest is unreadable: {exc}") from exc
    try:
        assert_identity_agrees(locator, manifest, manifest_path=str(store.path))
    except LifecycleError as exc:
        raise _AuthorityRefused(
            f"the locator and manifest disagree about this installation: {exc}") from exc
    return locator.installation_id, manifest.generation


def _recorded_sandbox_decision(*, published, inputs, mode: str, requested):
    """The manifest may authorize replacing exactly the sandbox it already owns.

    ``--sandbox replace`` remains the explicit conversion/fresh-install decision.  An ordinary
    update needs no operator to re-authorize replacing this installation's own shipped sandbox,
    but that authority comes from the complete published tuple -- never from the path alone and
    never from the installer's assertion that this is an update.
    """
    from .patch_compartment import SANDBOX_FILE, SandboxDecision
    from .schema import same_path

    if requested is not SandboxDecision.NONE or mode != "forward_update":
        return requested
    expected_sandbox = Path(inputs.requested) / SANDBOX_FILE
    if not (
        published.install_dir
        and same_path(published.install_dir, str(inputs.install_dir))
        and published.patch_hosting_dir
        and same_path(published.patch_hosting_dir, str(inputs.requested))
        and published.patch.folder_slot
        and published.patch.registered
        and published.patch.verified
        and published.patch.sandbox_file
        and same_path(published.patch.sandbox_file, str(expected_sandbox))
    ):
        return requested
    return SandboxDecision.REPLACE_EXACT_NAME


def _patch_compartment(args) -> int:
    """Every failure becomes a JSON report and a per-verb exit code; nothing escapes as a traceback."""
    from . import patch_compartment as pc
    from .fms_folders import build_adapter

    if args.pc_verb == "rollback":
        return _patch_compartment_rollback(args.operation_id)

    try:
        inputs = _read_request(args.request)
    except _RequestRefused as exc:
        _pc_emit(_pc_finding(
            "request_refused", str(exc), state="request_refused",
            next_action="Supply a root-owned request file with exactly the documented keys."))
        return _PC_BAD_REQUEST

    # BEFORE the adapter is constructed and before any filesystem work: authority first, so a box
    # whose installation record cannot be established never reaches the Admin API at all.
    try:
        installation_id, generation = _published_identity()
    except _AuthorityRefused as exc:
        _pc_emit(_pc_finding(
            "installation_authority_unavailable", str(exc),
            state="installation_authority_unavailable",
            next_action=("Repair or publish the installation locator, then re-run. Nothing was "
                         "created, changed or contacted.")))
        return _PC_REFUSED

    adapter = build_adapter()
    if adapter is None:
        _pc_emit(_pc_payload(
            pc.preflight_report(
                inputs, "no co-located FileMaker Server Admin API PKI key is configured"),
            operation_id=None))
        return _PC_REFUSED

    layout = platform_layout()
    journal = Journal(layout)
    operation_id = pc.new_operation_id()

    # An interrupted run is resumable by ONE command, so a new apply must not start on top of it —
    # and the command it names must be the one that works.
    if args.pc_verb == "apply" and journal.requires_recovery():
        record = journal.read()
        owed = record.operation_id if record else None
        # The rollback command is recommended ONLY when durable evidence exists that can satisfy it.
        # Naming a command that will refuse is how an operator gets sent in a circle.
        usable = False
        if owed:
            try:
                usable = pc.read_recovery(layout).operation_id == owed
            except pc.RecoveryEvidenceInvalid:
                usable = False
        _pc_emit(_pc_finding(
            "recovery_required",
            "a previous lifecycle operation stopped mid-flight and must be resolved first",
            state="recovery_required", operation_id=owed,
            next_action=(
                ("Run: python -m corpusfm.lifecycle patch-compartment rollback "
                 f"--operation-id {owed}") if usable else
                ("No durable rollback evidence exists for that operation, so rollback cannot "
                 "resolve it. Inspect the compartment and the lifecycle journal by hand before any "
                 "further operation."))))
        return _PC_MANUAL

    try:
        report = pc.inspect(inputs, adapter=adapter)
        if args.pc_verb == "inspect":
            _pc_emit(_pc_payload(report, operation_id=operation_id))
            return _pc_exit(report.result, report.state.value)

        plan_obj = pc.plan(report, inputs)
        # O7 attribution, half one: the compartment's contents BEFORE the sandbox is placed and
        # opened. Nothing about an `RC_Data_FMS` folder distinguishes ours from one that was already
        # there, so this reading is the only evidence that will ever exist — and it has to be taken
        # now, before the operation that would create ours.
        _rc_before = pc.compartment_inventory(Path(inputs.requested))
        with LifecycleLock(layout) as lock:
            # Re-read the published record UNDER the lifecycle lock.  It is the only authority that
            # can turn an update over an existing exact-name sandbox into replacement; a stale
            # pre-lock observation, the path alone, or the caller's mode cannot do that.
            decision = pc.SandboxDecision(args.sandbox)
            if args.mode == "forward_update" and decision is pc.SandboxDecision.NONE:
                from .published import read_published_installation

                published = read_published_installation()
                if (published.installation_id != installation_id
                        or published.generation != generation):
                    raise pc.CompartmentRefused(
                        "the installation record moved before patch replacement authority was read"
                    )
                decision = _recorded_sandbox_decision(
                    published=published, inputs=inputs, mode=args.mode, requested=decision)
            _clear_stale_evidence(layout, journal, lock)
            journal.begin(lock=lock, operation_id=operation_id,
                          installation_id=installation_id, mode=args.mode)
            journal.checkpoint(lock=lock, subsystem="patch_compartment",
                               intended_change=f"provision {inputs.requested}",
                               backups=[str(pc.recovery_path(layout))],
                               resume_hint=("python -m corpusfm.lifecycle patch-compartment "
                                            f"rollback --operation-id {operation_id}"))
            outcome = pc.apply(plan_obj, adapter=adapter, lock=lock,
                               decision=decision,
                               layout=layout, operation_id=operation_id,
                               installation_id=installation_id, mode=args.mode)
            _dispose(journal, layout, lock, outcome.result, operation_id)
    except LifecycleError as exc:
        _dispose_after_exception(journal, layout, operation_id, installation_id)
        _pc_emit(_pc_finding(type(exc).__name__, str(exc), state="refused",
                             operation_id=operation_id,
                             next_action="Resolve the reported lifecycle condition and re-run."))
        return _PC_REFUSED
    except OSError as exc:
        _dispose_after_exception(journal, layout, operation_id, installation_id)
        _pc_emit(_pc_finding(type(exc).__name__, exc.strerror or str(exc), state="refused",
                             operation_id=operation_id,
                             next_action="Resolve the reported filesystem condition and re-run."))
        return _PC_REFUSED

    candidate = None
    if outcome.state is pc.CompartmentState.VERIFIED_READY:
        slot = outcome.report.handoff.slot_index
        compartment = outcome.report.handoff.compartment_path
        if slot and compartment:
            # O7 attribution, half two: read the compartment back after the open/close proof and
            # record ONLY a path that appeared for this sandbox. `why` is carried into the findings
            # rather than dropped — the ruling requires the limitation to be REPORTED, and an empty
            # ownership tuple cannot be told apart from "there was nothing there".
            rc_entries, rc_why = pc.attribute_sandbox_rc(
                compartment=Path(compartment), before=_rc_before,
                after=pc.compartment_inventory(Path(compartment)))
            report_out = outcome.report
            if rc_why:
                report_out = dataclasses.replace(
                    report_out,
                    findings=report_out.findings + (
                        pc.Finding(code="sandbox_rc_not_attributed", detail=rc_why),))
                outcome = dataclasses.replace(outcome, report=report_out)
            candidate = pc.candidate_facts(
                report_out, compartment=compartment, slot=slot,
                generation=generation, installation_id=installation_id,
                sandbox_rc_ownership=rc_entries)
    _pc_emit(_pc_payload(outcome.report, operation_id=operation_id, candidate=candidate))
    return _pc_exit(outcome.result, outcome.state.value)


def _dispose(journal, layout, lock, result: str, operation_id: str) -> None:
    """Journal and recovery evidence, disposed by the RESULT WORD."""
    from . import patch_compartment as pc

    if result in _RESOLVE_AND_CLEAR:
        journal.resolve(lock=lock, result=result)
        pc.clear_recovery(layout, lock=lock)
        return
    journal.mark_needs_recovery(
        lock=lock, reason=f"patch-compartment {operation_id} ended {result}")


def _current_operation_evidence(layout, operation_id: str, installation_id: str):
    """The durable record IF it is evidence about THIS operation, else None.

    A file being present is not evidence. `.exists()` accepted a malformed record, a stale one from
    a finished operation, and one belonging to another installation — each of which would have
    marked recovery owed that no rollback could ever discharge.
    """
    from . import patch_compartment as pc

    try:
        record = pc.read_recovery(layout)
    except pc.RecoveryEvidenceInvalid:
        return None
    if record.operation_id != operation_id:
        return None
    if installation_id and record.installation_id != installation_id:
        return None
    return record


def _clear_stale_evidence(layout, journal, lock) -> None:
    """Retire a record left by a FINISHED operation before a new one begins.

    Harmless on its own — the journal is resolved, so nothing is owed — but leaving it means the
    next exception handler finds a file and has to decide what it means. Cleared while the answer
    is still unambiguous.
    """
    from . import patch_compartment as pc

    if journal.requires_recovery():
        return
    if pc.recovery_path(layout).exists():
        pc.clear_recovery(layout, lock=lock)


def _dispose_after_exception(journal, layout, operation_id: str,
                             installation_id: str = "") -> None:
    """Control escaped through an exception handler. Decide from VALIDATED DURABLE EVIDENCE, not
    from the fact that an exception happened, and not from a file's presence.

    An exception between `journal.begin` and the first `_persist` leaves a journal that no rollback
    can ever satisfy — there is no record for it — so it must resolve. Only a record that IS about
    this operation and this installation means a mutation was in flight.
    """
    from .lock import LifecycleLock

    try:
        record = _current_operation_evidence(layout, operation_id, installation_id)
        with LifecycleLock(layout) as lock:
            if record is not None:
                journal.mark_needs_recovery(
                    lock=lock,
                    reason=f"patch-compartment {operation_id} was interrupted mid-mutation")
            else:
                journal.resolve(lock=lock, result=FAILED_BEFORE_CHANGE)
    except (LifecycleError, OSError):        # pragma: no cover - the journal is already the problem
        pass


def _patch_compartment_rollback(operation_id: str) -> int:
    """A NEW PROCESS. Everything it needs comes off disk.

    The first version kept records in a per-process dict, which is not a recovery authority at all:
    an administrator's rollback is by definition a different process, so it always refused — and,
    combined with the apply-refuses-while-recovery-is-owed rule, that WEDGED the install.
    """
    from . import patch_compartment as pc
    from .fms_folders import build_adapter

    layout = platform_layout()
    try:
        record = pc.read_recovery(layout)
    except pc.RecoveryEvidenceInvalid as exc:
        # Fail CLOSED, and never as "nothing changed": a run that cannot read its own recovery
        # record knows less than nothing about what is on the box.
        _pc_emit(_pc_finding(
            "recovery_evidence_invalid", str(exc), state="recovery_evidence_invalid",
            operation_id=operation_id,
            next_action=("The compartment's state cannot be established from this box's recovery "
                         "evidence. Inspect it before any further operation; do NOT assume nothing "
                         "was changed.")))
        return _PC_MANUAL

    if record.operation_id != operation_id:
        _pc_emit(_pc_finding(
            "recovery_operation_mismatch",
            f"the stored recovery record is for operation {record.operation_id!r}",
            state="recovery_operation_mismatch", operation_id=operation_id,
            next_action=f"Re-run with --operation-id {record.operation_id}."))
        return _PC_MANUAL

    try:
        installation_id, _generation = _published_identity()
    except _AuthorityRefused as exc:
        _pc_emit(_pc_finding(
            "installation_authority_unavailable", str(exc),
            state="installation_authority_unavailable", operation_id=operation_id,
            next_action="Repair the installation locator, then re-run rollback."))
        return _PC_MANUAL

    if record.installation_id != installation_id:
        _pc_emit(_pc_finding(
            "recovery_installation_mismatch",
            "the recovery record belongs to a different installation",
            state="recovery_installation_mismatch", operation_id=operation_id,
            next_action="Do not roll back another installation's operation."))
        return _PC_MANUAL

    adapter = build_adapter()
    if adapter is None:
        _pc_emit(_pc_finding(
            "api_required_unavailable",
            "no co-located FileMaker Server Admin API PKI key is configured",
            state="api_required_unavailable", operation_id=operation_id,
            next_action="Configure the Admin API PKI key, then re-run rollback."))
        return _PC_REFUSED

    journal = Journal(layout)
    try:
        with LifecycleLock(layout) as lock:
            outcome = pc.rollback_changes(record, adapter=adapter)
            if outcome.result == ROLLED_BACK:      # resolve ONLY on success
                journal.resolve(lock=lock, result=outcome.result)
                pc.clear_recovery(layout, lock=lock)
    except (LifecycleError, OSError) as exc:
        _pc_emit(_pc_finding(type(exc).__name__, str(exc), state="refused",
                             operation_id=operation_id,
                             next_action="A human must reconcile the compartment."))
        return _PC_MANUAL

    _pc_emit(_pc_payload(outcome.report, operation_id=operation_id))
    return _pc_exit(outcome.result, outcome.state.value)


# ── proxy: TWO SURFACES, one engine (packet 1246-06 §8) ───────────────────────
#
# `proxy` is the INTEGRATOR protocol; `proxy-public` is what the `corpusfm-proxy` wrapper calls.
# They are separated HERE, in the parser, because that is the only place the separation can be
# checked mechanically: the public parser has no `--request` and no `--disposition` to accept, so
# no code path can make an administrator responsible for a persistence mode.

_PX_OK = 0                      # completed / no_change
_PX_REFUSED = 1                 # failed_before_change — nothing was left behind
_PX_ROLLED_BACK = 2             # mutated, fully restored
_PX_MANUAL = 3                  # mutated, a human must act
_PX_BAD_REQUEST = 4             # the request file or its ownership was refused

# §8.4: ONE key set per verb, not a union. A union let a key legal for one verb pass to another,
# which is how `status` — which mutates nothing and activates nothing — came to accept a credential
# transport. Each set is written out rather than derived, so adding a key to one verb cannot widen
# another by accident.
# `install_dir` and `fms_root` are REQUIRED of the integrator (Codex ruling 1). The integrator runs
# BEFORE the one composed manifest/locator publication, so it cannot resolve either through the
# locator — and hard-coded discovery is a guess about somebody else's machine. 1246-04 has already
# verified both as part of its three-path research; it supplies them.
_PX_STATUS_KEYS = frozenset({
    "schema_version", "installation_id", "expected_generation", "prefix", "port", "mcp_metadata",
    "types", "actor", "install_dir", "fms_root",
})
_PX_RECONCILE_KEYS = _PX_STATUS_KEYS | {"disposition", "credential_input"}
# `finalize` needs NO path inputs and `abort` needs none either: both read the facts the operation
# BOUND into its recovery record (ruling 1). A path supplied at recovery time is a path nobody can
# prove the operation actually used.
_PX_FINALIZE_KEYS = frozenset({"schema_version", "installation_id", "operation_id",
                               "committed_generation", "actor"})
_PX_ABORT_KEYS = frozenset({"schema_version", "installation_id", "operation_id", "actor",
                            "credential_input"})
_PX_RETIRE_KEYS = frozenset({"schema_version", "installation_id", "operation_id", "actor"})
_PX_REQUEST_KEYS = {
    "status": _PX_STATUS_KEYS, "reconcile": _PX_RECONCILE_KEYS,
    "finalize": _PX_FINALIZE_KEYS, "abort": _PX_ABORT_KEYS, "retire": _PX_RETIRE_KEYS,
}
_PX_SCHEMA_VERSION = 1

_PX_PUBLIC_VERBS = ("status", "add", "ignore", "remove", "reconcile")
_PX_PUBLIC_MUTATING = ("add", "ignore", "remove", "reconcile")
_PX_RETIRED_CHECKPOINT = "proxy_artifacts_retired"


class _PxRefused(Exception):
    """A proxy refusal carrying only a message. Nothing was published, activated or recorded."""


def _px_credential_input_ok(value) -> bool:
    """A TRANSPORT from a closed domain. It names a mode or an FD; it never carries a value."""
    from .proxy_transaction import (
        CREDENTIAL_ABSENT, CREDENTIAL_FD_PREFIX, CREDENTIAL_PROMPT, CREDENTIAL_STDIN,
    )

    if value in (CREDENTIAL_ABSENT, CREDENTIAL_PROMPT, CREDENTIAL_STDIN):
        return True
    return (isinstance(value, str) and value.startswith(CREDENTIAL_FD_PREFIX)
            and value[len(CREDENTIAL_FD_PREFIX):].isdigit())


def _px_read_request(path: str, verb: str, *, authority_api=None) -> dict:
    """Root-owned, not group/world-writable, and EXACTLY this verb's key set.

    `_open_privileged_request` is reused deliberately: the rule protecting a privileged input is the
    same whether the operation configures a database compartment or a web front, and two copies of
    it would drift apart.
    """
    from .proxy_transaction import COMPOSED_CANDIDATE

    text = _open_privileged_request(Path(path), authority_api=authority_api)
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise _RequestRefused(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise _RequestRefused("the request must be a JSON object")

    expected = _PX_REQUEST_KEYS[verb]
    unknown = set(raw) - expected
    if unknown:
        raise _RequestRefused(f"proxy {verb} does not accept key(s): {', '.join(sorted(unknown))}")
    missing = expected - set(raw)
    if missing:
        raise _RequestRefused(f"proxy {verb} is missing key(s): {', '.join(sorted(missing))}")

    if raw["schema_version"] != _PX_SCHEMA_VERSION:
        raise _RequestRefused(
            f"request schema_version {raw['schema_version']!r}; this build accepts "
            f"{_PX_SCHEMA_VERSION}")

    if verb == "reconcile" and raw["disposition"] != COMPOSED_CANDIDATE:
        # Neither a default nor an inference: the integrator surface COMPOSES, and a request asking
        # it to commit directly is addressed to the wrong surface.
        raise _RequestRefused(
            f"proxy reconcile requires disposition {COMPOSED_CANDIDATE!r}, "
            f"got {raw['disposition']!r}")

    if "credential_input" in expected and not _px_credential_input_ok(raw["credential_input"]):
        raise _RequestRefused(
            f"credential_input must be 'absent', 'prompt', 'stdin' or 'fd:<n>', "
            f"got {raw['credential_input']!r}")

    if verb in ("status", "reconcile"):
        # MCP ALWAYS INSTALLS (ruling 10, already-settled). The key stays in the schema so an
        # integrator states its intent explicitly, but the only intent this build accepts is `true`
        # — an accepted-and-ignored flag is worse than no flag, because it reads as a supported
        # option that silently does nothing. `False` is a refusal, not a mode.
        if raw["mcp_metadata"] is not True:
            raise _RequestRefused(
                "mcp_metadata must be exactly true: MCP always installs, and its metadata routes "
                f"are part of every rendering on every platform (got {raw['mcp_metadata']!r})")
        types = raw["types"]
        if not isinstance(types, list) or not types:
            raise _RequestRefused("types must be a non-empty list of supported proxy types")
        for name in types:
            if name not in PROXY_TYPES:
                raise _RequestRefused(
                    f"{name!r} is not a supported proxy type ('all' is a PUBLIC selector and is "
                    f"never a request value)")
        if not isinstance(raw["prefix"], str) or not raw["prefix"]:
            raise _RequestRefused("prefix must be a non-empty string")
        if not isinstance(raw["port"], int) or isinstance(raw["port"], bool) or raw["port"] <= 0:
            raise _RequestRefused("port must be a positive integer")
        for key in ("install_dir", "fms_root"):
            value = raw[key]
            if not isinstance(value, str) or not os.path.isabs(value):
                raise _RequestRefused(f"{key} must be an absolute path, got {value!r}")
            if value != os.path.normpath(value):
                raise _RequestRefused(
                    f"{key} must be canonical (no '.', '..' or duplicate separators), got {value!r}")
    return raw


def _px_emit(payload: dict[str, Any]) -> None:
    """The ONE place a proxy result is printed, and the ONE place the secret fence runs on it.

    **Why the emitted keys read `fms_admin_login_required` rather than the packet's
    `credentials_required`.** 1246-01's structural fence denies any key that tokenizes to
    `credential`/`credentials`, and it is deliberately a NAME rule — it cannot tell a boolean
    requirement flag from a field holding the value. The packet's own §9.4 wants exactly this to be
    "a flag, not a value", so the fence and the packet agree on the substance and collide only on
    the spelling. `secret_guard.py` belongs to 1246-01 and is not this packet's to widen, so the
    Python attribute keeps the packet's vocabulary (`plan.credentials_required`,
    `run.credentials_required`) and only the WIRE key differs. The reported fact is unchanged.
    """
    from .secret_guard import assert_no_secrets

    assert_no_secrets(payload, what="the proxy result")
    print(json.dumps(payload, indent=2, sort_keys=True))


def _px_refusal(code: str, detail: str, *, next_action: str, operation_id: str | None = None,
                **extra) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "result": FAILED_BEFORE_CHANGE, "operation_id": operation_id,
        "findings": [{"code": code, "detail": detail}], "next_action": next_action,
        "per_type": [], "candidates": {},
    }
    payload.update(extra)
    return payload


def _px_exit(result_word: str) -> int:
    from .result import (
        COMPLETED, INCOMPLETE_SAFE, MANUAL_ACTION_REQUIRED, NO_CHANGE, ROLLED_BACK,
    )

    if result_word in (COMPLETED, NO_CHANGE):
        return _PX_OK
    if result_word == ROLLED_BACK:
        return _PX_ROLLED_BACK
    if result_word in (MANUAL_ACTION_REQUIRED, INCOMPLETE_SAFE):
        return _PX_MANUAL
    return _PX_REFUSED


def _px_route_facts(published) -> tuple[str, int]:
    """`web.prefix` and `web.internal_port` from the PUBLISHED MANIFEST — and nowhere else.

    No fallback to `install.yaml`, to the environment, or to a default. Both fields are `| None` in
    the committed schema, so "published but empty" is a real state, and it is not usable: an
    installation whose own record cannot say where it is mounted must not have that guessed for it.
    """
    prefix = published.web_prefix
    port = published.web_internal_port
    if not prefix or not port:
        raise _PxRefused(
            "this installation's manifest does not record both a web prefix and an internal port, "
            "so its routing cannot be rendered; there is deliberately no fallback to install.yaml, "
            "the environment or a default")
    return prefix, int(port)


def _px_request_paths(request) -> dict:
    """The integrator's canonical paths, and the executor it will run (ruling 1).

    The request supplies both because it runs before the composed publication; the executor is then
    resolved from `install_dir` and its authority checked, so a run that cannot prove which helper
    it is about to hand root authority to refuses before touching anything.
    """
    from . import proxy_transaction as px

    install_dir = str(request["install_dir"])
    try:
        script = px.executor_script(is_windows=(os.name == "nt"), install_dir=install_dir)
    except px.ExecutorUnavailable as exc:
        raise _PxRefused(str(exc)) from exc
    return {"install_dir": install_dir, "fms_root": str(request["fms_root"]), "script": script}


def _px_published_paths(published) -> dict:
    """The same three facts for a PUBLIC command, from the manifest and from nowhere else."""
    from . import proxy_transaction as px

    if not published.install_dir or not published.fms_root:
        raise _PxRefused(
            "this installation's manifest does not record both an install directory and a "
            "FileMaker Server root, so the proxy provider cannot be addressed; there is "
            "deliberately no discovery fallback")
    try:
        script = px.executor_script(is_windows=(os.name == "nt"),
                                    install_dir=published.install_dir)
    except px.ExecutorUnavailable as exc:
        raise _PxRefused(str(exc)) from exc
    return {"install_dir": published.install_dir, "fms_root": published.fms_root, "script": script}


def _px_observations(types, *, prefix: str = "/corpusfm", install_dir=None, fms_root=None,
                     script=None):
    """Observe the machine — with the route and path facts the probe actually needs (ruling 2).

    **This function used to call `inventory()` with nothing.** `_real_probe()` therefore received
    `script=None`, the Windows probe could not be run at all, and every Windows field came back
    `None` — so the §6.4 refusal and the §13 publication fence were unreachable in production while
    every test injected observations past this seam. Threading the facts is what connects them.
    """
    from .proxy_inventory import _real_probe, inventory

    wanted = set(types)
    probe = _real_probe(prefix=prefix,
                        iis_app_dir=(Path(install_dir) / "proxy") if install_dir else None,
                        metadata_dir=(Path(install_dir) / "proxy-mcp") if install_dir else None,
                        script=script, fms_root=fms_root)
    return tuple(o for o in inventory(platform_probe=probe) if o.proxy_type in wanted)


def _px_plan(view, observations, *, verb: str, types, prefix: str, port: int, fms_root: str,
             install_dir: str) -> Any:
    """Plan with all THREE facts (ruling 4): observed, stored, and the DESIRED rendering.

    The desired fingerprint is computed here, at the boundary that knows this installation's prefix
    and port, and handed to a decision layer that stays pure. Without it `decide` had no way to tell
    "the block matches what we last applied" from "the block is what this installation should now
    have", and treated the first as the second.
    """
    from .proxy_policy import PolicyRequest, decide

    return decide(view, observations,
                  request=PolicyRequest(verb=verb, types=tuple(types),
                                        desired=_px_desired(types, prefix=prefix, port=port,
                                                            fms_root=fms_root,
                                                            install_dir=install_dir)))


def _px_desired(types, *, prefix: str, port: int, fms_root: str, install_dir: str) -> dict:
    """The desired FAMILY fingerprint per type, from AUTHORITATIVE paths only (rulings 1 and 3).

    An earlier version called `_verified_fms_root()` and, failing that, hard-coded
    `/opt/FileMaker/FileMaker Server`. Both are guesses about somebody else's machine, and a guess
    here silently changes what "current" means. The paths now arrive from the integrator's request
    or from the published manifest, and there is no third source.
    """
    from .proxy_inventory import fms_installation_root
    from .proxy_render import INCLUDE_NAME, desired_fingerprint

    # Windows publishes its Database Server directory in the manifest, while nginx belongs to the
    # enclosing FileMaker Server root. Execution already derives that root before rendering and
    # dispatch; planning must use the identical evidence-based derivation or it hashes a different
    # include path and rejects the exact family the executor just read back.
    installation_root = fms_installation_root(fms_root) or Path(fms_root)
    include_path = str(Path(installation_root, "NginxServer", "conf", INCLUDE_NAME))
    app_dir = str(Path(install_dir, "proxy"))
    metadata_dir = str(Path(install_dir, "proxy-mcp"))
    out = {}
    for proxy_type in types:
        try:
            out[proxy_type] = desired_fingerprint(
                proxy_type, prefix=prefix, port=port, include_path=include_path,
                app_dir=app_dir, metadata_dir=metadata_dir)
        except ValueError:
            continue          # a type with no rendering leaves the fact ABSENT, which refuses
    return out


def _px_apply_policy_verb(view, verb: str, types) -> dict:
    """Which verbs move POLICY, and to what. Returned as a mapping so the caller composes ONE write.

    `remove` is here because recording `ignored` is half of what it MEANS (§8.1): the routing is
    gone AND CORPUSfm is no longer responsible for the front. Leaving the policy `managed` would
    make the very next `reconcile` put the routing straight back.
    """
    from .proxy_policy import IGNORED, MANAGED

    if verb == "add":
        return {name: MANAGED for name in types}
    if verb in ("ignore", "remove"):
        return {name: IGNORED for name in types}
    return {}


def _px_lease(credential_input: str, *, prompter=None):
    """Obtain the operation-scoped lease named by the TRANSPORT, or None when none is asked for."""
    from .proxy_transaction import (
        CREDENTIAL_ABSENT, CREDENTIAL_PROMPT, open_credential_source, prompt_for_credential,
        read_credential_frame,
    )

    if credential_input == CREDENTIAL_ABSENT:
        return None
    if credential_input == CREDENTIAL_PROMPT:
        return prompt_for_credential(prompter)
    with open_credential_source(credential_input) as source:
        return read_credential_frame(source)


def _px_result_payload(run, *, next_action: str = "") -> dict[str, Any]:
    return {
        "result": run.result,
        "operation_id": run.operation_id,
        "installation_id": run.installation_id,
        "expected_generation": run.expected_generation,
        "disposition": run.disposition,
        "fms_admin_login_required": bool(run.credentials_required),
        "activation_required": list(run.activation_required),
        "per_type": [
            {"proxy_type": o.proxy_type, "action": o.action, "mechanism": o.mechanism,
             "result": o.result, "published": o.published, "activated": o.activated,
             "health_checked": o.health_checked, "restored": o.restored, "detail": o.detail,
             "operator_steps": list(o.operator_steps)}
            for o in run.outcomes
        ],
        "candidates": {name: entry.to_dict() for name, entry in run.candidates.items()},
        "findings": [],
        "next_action": next_action,
    }


def _px_unresolved(layout, published_policy) -> dict[str, Any]:
    """What an unresolved operation is, described WITHOUT touching it (§9.5).

    `manifest_matches_candidate` is the question both `finalize` and the public recovery
    precondition ask, and `abort_credentials_required` is the one an integrator must be able to
    answer BEFORE prompting an administrator for something it may turn out not to need.
    """
    from . import proxy_transaction as px

    try:
        record = px.read_recovery(layout)
    except px.RecoveryEvidenceInvalid:
        return {"present": False, "operation_id": None, "manifest_matches_candidate": None,
                "abort_fms_admin_login_required": None}
    published = {k: dict(v.to_dict()) for k, v in (published_policy or {}).items()}
    matches = all(published.get(name) == dict(entry)
                  for name, entry in record.candidates.items()) and bool(record.candidates)
    return {
        "present": True,
        "operation_id": record.operation_id,
        "manifest_matches_candidate": matches,
        "abort_fms_admin_login_required": px.abort_needs_credential(record),
    }


def _px_claris_active(observations) -> bool:
    """Whether the Claris nginx front is the selected one, for the executor's SECOND refusal.

    The decision layer refuses first; the executor refuses again rather than trusting its caller.
    `None` — cannot be determined — is not passed as active: an unknown is not a claim.
    """
    return any(o.proxy_type == "claris-nginx" and o.active is True for o in observations)


def _px_install_dir() -> Path:      # pragma: no cover - platform-specific
    """This installation's root, from its locator. The IIS artifacts live under it."""
    return Path(locator_for(platform_layout()).read().install_dir)


def _px_recovery_engine(record, engine=None):
    """The engine a RECOVERY path uses — built from the RECORD and nothing else (ruling 1).

    **It consults no locator, no manifest, no default and no source tree.** A pre-manifest abort is
    the case this exists for: 1246-04 fails before its composed write, so there IS no manifest to
    read, and an engine that fell back to one would either refuse or — worse — act on a different
    installation's facts. Everything it needs was bound into the record before the mutation began:
    the paths, the route, the executor and its digest.

    The executor is re-validated here, not merely re-read. A helper whose digest moved is not the
    helper that made the change, and rolling back through it would be running unknown code with
    root authority over FileMaker Server's configuration.
    """
    from . import proxy_transaction as px
    from .proxy_policy import MECH_CLARIS_ACTIVE

    active_fronts = {entry["proxy_type"] for entry in record.per_type
                     if entry.get("published") and entry.get("mechanism") == MECH_CLARIS_ACTIVE}
    if engine is not None:
        engine.set_active_fronts(active_fronts)
        return engine

    for field in ("install_dir", "fms_root", "executor_path", "executor_digest"):
        if not getattr(record, field, None):
            raise _PxRefused(
                f"this operation's recovery record does not bind {field}, so its restoration "
                f"cannot be performed without guessing; the evidence is retained untouched")

    script = Path(record.executor_path)
    expected_bin = Path(record.install_dir) / "bin"
    if script.parent != expected_bin:
        raise _PxRefused(
            f"the recorded executor {script} is not the installed sibling at {expected_bin}")
    refusal = px.executor_refusal(script, is_windows=(record.flavour == "windows"),
                                  install_dir=record.install_dir)
    if refusal is not None:
        raise _PxRefused(f"the recorded executor cannot be trusted for a restoration: {refusal}")
    try:
        seen = px.executor_digest(script)
    except OSError as exc:
        raise _PxRefused(f"the recorded executor could not be read ({exc.strerror})") from exc
    if seen != record.executor_digest:
        raise _PxRefused(
            "the proxy executor has changed since this operation ran, so it is not the helper that "
            "made the change; refusing to restore through it")

    engine = _px_engine(prefix=record.web_prefix, port=record.web_internal_port,
                        fms_root=record.fms_root, install_dir=record.install_dir, script=script,
                        operation_id=record.operation_id, flavour=record.flavour,
                        claris_nginx_active=bool(active_fronts))
    engine.set_active_fronts(active_fronts)
    return engine


def _px_engine(*, prefix: str, port: int, fms_root, install_dir, script=None,
               operation_id: str | None = None, flavour: str | None = None, executor=None,
               activator=None, health_check=None, claris_nginx_active: bool = False):
    """The real engine, or the injected one a test supplies.

    **Every authority fact is REQUIRED and explicit (ruling 1).** The previous version fell back to
    `_verified_fms_root()` and to the locator for the install directory, which meant a run could
    silently act on a machine's guessed layout instead of the one its caller had verified. Both
    fallbacks are gone: a caller that cannot state where FileMaker Server and CORPUSfm are has not
    established enough to mutate either.

    Injection is at the ENGINE, not inside it: the executor is an OS-native process and the
    activator is the only thing in this component that touches `fmsadmin`, so keeping both behind
    one seam is what lets every rule be exercised without a FileMaker Server — and what keeps the
    credential's blast radius to a single call site.
    """
    from . import proxy_transaction as px

    if executor is None:
        if not fms_root or not install_dir:
            raise _PxRefused(
                "the proxy provider needs this installation's FileMaker Server root and install "
                "directory, and neither is discovered: an integrator supplies them in its request "
                "and a public command reads them from the published manifest")
        is_windows = (flavour == "windows") if flavour else (os.name == "nt")
        install_dir = Path(install_dir)
        # `<InstallRoot>\proxy` and `\proxy-mcp` — the locations `install.ps1:228` and `:1287` use
        # today. 1246-04 removes those inline blocks and this provider owns the artifacts instead.
        iis_app_dir = (install_dir / "proxy") if is_windows else None
        metadata_dir = (install_dir / "proxy-mcp") if is_windows else None
        executor = px.real_executor(
            fms_root=fms_root, prefix=prefix, port=port, is_windows=is_windows,
            script=script or px.executor_script(is_windows=is_windows, install_dir=install_dir),
            iis_app_dir=iis_app_dir, metadata_dir=metadata_dir, operation_id=operation_id,
            evidence_dir=install_dir, claris_nginx_active=claris_nginx_active)
        # The Windows manifest already records `...\Database Server`; POSIX records the enclosing
        # FileMaker Server root. Normalize the first shape before appending the platform-relative
        # executable, or Windows attempts `Database Server\Database Server\fmsadmin.exe` and both
        # the activation and its restorative restart are impossible.
        from .proxy_inventory import fms_installation_root

        installation_root = fms_installation_root(fms_root) or Path(fms_root)
        fmsadmin = (Path(installation_root, "Database Server", "fmsadmin.exe") if is_windows else
                    Path(installation_root, "Database Server", "bin", "fmsadmin"))
        activator = activator or px.real_activator(fmsadmin=fmsadmin)
        # THE RECORDED PORT, passed through. Recovery reaches this same construction with
        # `record.web_internal_port`, so a restoration judges health by the identical rule.
        health_check = health_check or px.real_health_check(prefix=prefix,
                                                           internal_port=port)
    return px.ProxyEngine(executor=executor, activator=activator, health_check=health_check)


def _px_restore_all(engine, record, *, only=None) -> tuple[bool, list[dict]]:
    """Restore EVERY filesystem change the operation made — including validated INACTIVE ones.

    The manifest was never published, so nothing was ever authorized to persist. An inactive change
    that validated cleanly is still a change nobody agreed to keep.

    `only` narrows it to the types recovery classified as changed. A type still byte-identical to
    its before-image has nothing to put back, and asking the executor to restore it would fail for
    the absence of a backup publication never created.
    """
    details: list[dict] = []
    all_ok = True
    for entry in record.per_type:
        if not entry.get("published"):
            continue
        if only is not None and entry["proxy_type"] not in only:
            continue
        ok, detail = engine.restore(entry["proxy_type"])
        all_ok = all_ok and ok
        details.append({"proxy_type": entry["proxy_type"], "restored": ok, "detail": detail})
    return all_ok, details


def _px_classify(engine, record) -> dict:
    """Per type: does the artifact family STILL match the before-image this operation captured?

    **`True` = publication never changed it. `False` = it may have. `None` = we could not tell.**
    The third answer is not folded into either of the others: an unreadable or absent before-image
    means we do not know, and "do not know" must take the restoring path, not the cheap one.

    This exists because `prepare` changes no routing. An interruption between it and the mutation
    leaves a durable `prepared` record over a completely untouched box — and the abort path used to
    restore blindly, which needs a `.cfmbak` publication never created, so it failed and wedged the
    installation with `manual_action_required` for an operation that had changed nothing.
    """
    seen = {}
    for entry in record.per_type:
        if not entry.get("published"):
            continue
        name = entry["proxy_type"]
        if name not in (record.evidence or {}):
            seen[name] = None                   # no before-image to compare against
            continue
        report = engine.executor("classify", name, None)
        seen[name] = report.get("unchanged") if report.get("ok") else None
    return seen


def _px_abort(engine, record, acquire_lease) -> tuple[str, list[dict]]:
    """§9.3/§9.4. Resolves ONLY on verified success; otherwise `manual_action_required`.

    **The credential is acquired LAZILY, and this function owns that decision (Codex reinspection).**
    Every caller used to obtain a lease first — reading the transport, or prompting — and only then
    hand it here to be classified. So a `prepared`, evidence-bound, byte-identically unchanged
    operation still had its credential channel read: measured, `lease_calls=['fd:4']`. A transport
    read is not free and not private; it consumes a one-shot pipe and, on the public surface, puts a
    prompt in front of an administrator for a restart nobody needs.

    So `acquire_lease` arrives as a THUNK. Nothing opens it until the classification has proved that
    a changed or unclassifiable type actually requires a restoration restart — and once that is
    proved, it is acquired BEFORE the first restoration mutation, which is the rule that has always
    mattered: a half-restored box with no way to reactivate it is worse than one nobody touched.

    The lease is wiped on every exit, including the exceptional ones, because this is the only
    function that knows whether one was ever taken.
    """
    from . import proxy_transaction as _px
    from .result import MANUAL_ACTION_REQUIRED, NO_CHANGE, ROLLED_BACK

    # COMPATIBILITY, NARROWLY (packet 1246-10-04). The shipped executor's successful `restore`
    # used to delete the before-image while the lifecycle layer had not resolved yet, so a record
    # that is a COMPLETED total rollback can bind evidence that no longer exists. The restoration
    # in that state is already done and verified - by the run that performed it - and the record
    # itself says so: nothing published, nothing activated, no restart owed, every mutating front
    # rolled back. Only that exact shape may resolve without re-reading the evidence. Any other
    # phase or disposition still refuses below, because there missing evidence means the restoration
    # is unproven rather than complete.
    if _px.totally_rolled_back(record):
        return NO_CHANGE, [
            {"proxy_type": entry["proxy_type"], "restored": True,
             "detail": "restored and verified by the run that rolled back; nothing remained to do"}
            for entry in record.per_type or ()
        ]

    # The bound before-images are verified BEFORE anything is examined, restored, or asked for.
    # Evidence that changed since the operation bound it is not that operation's evidence.
    for name, binding in (record.evidence or {}).items():
        try:
            _px.verify_evidence(binding)
        except _px.RecoveryEvidenceInvalid as exc:
            raise _PxRefused(
                f"the before-image for {name} cannot be trusted: {exc}; every artifact is retained "
                f"and nothing has been restored") from exc

    # PHASE ONE NEVER MUTATES. A record still in `preparing` was interrupted before the first
    # executor call or partway through capturing before-images, and capture changes no routing —
    # so there is nothing to restore and nothing to ask for.
    if record.phase == _px.PHASE_PREPARING:
        return NO_CHANGE, []

    classified = _px_classify(engine, record)
    changed = [name for name, unchanged in classified.items() if unchanged is not True]
    if not changed:
        # PROVEN no-mutation interruption: every touched type still matches its before-image
        # exactly. Retire the preparation evidence and resolve honestly — no backup is needed
        # because none was ever created, and the credential transport is never touched.
        return NO_CHANGE, [{"proxy_type": name, "restored": False,
                            "detail": "unchanged since its before-image; nothing to restore"}
                           for name in classified]

    # Something did change, or could not be shown not to. The credential question is asked about
    # the CHANGED subset only — the record's flag is pessimistic by design and must not force one.
    needs_restart = any(entry["mechanism"] == "fmsadmin-restart"
                        for entry in record.per_type
                        if entry["proxy_type"] in changed and entry.get("published"))

    lease = None
    try:
        if needs_restart:
            # BEFORE the first restoration mutation, and only now.
            lease = acquire_lease()
            if lease is None:
                raise CredentialRefused(
                    "aborting this operation requires restoring previously ACTIVATED Linux "
                    "routing, which needs a NEW FMS admin credential — the lease from the process "
                    "that made the change was never persisted and did not survive it")

        restored, details = _px_restore_all(engine, record, only=changed)
        if not restored:
            return MANUAL_ACTION_REQUIRED, details
        if not needs_restart:
            return (ROLLED_BACK if details else NO_CHANGE), details

        back_ok = engine.activate(lease)
        healthy = engine.health("fms-web") if back_ok else False
        return (ROLLED_BACK if (back_ok and healthy) else MANUAL_ACTION_REQUIRED), details
    finally:
        # Every exit, including the exceptional ones. This is the only frame that knows whether a
        # lease was taken at all.
        if lease is not None:
            lease.wipe()


def _px_retire_operation(engine, record) -> None:
    """Retire exactly this resolved operation's executor artifacts, with positive confirmation.

    A type that published owns fixed-name backups plus operation-named evidence and is retired by
    its executor. A type that did not publish owns only the digest-bound preparation evidence; the
    provider removes that one exact file itself. Using the broad executor ``retire`` verb for the
    second case can delete another operation's fixed backup — the collision packet 1275 measured
    on Windows.
    """
    for entry in record.per_type:
        name = entry["proxy_type"]
        if entry.get("published"):
            report = engine.executor("retire", name, None)
            if not report.get("ok"):
                raise _PxRefused(
                    f"the proxy executor did not confirm retirement for {name} "
                    f"({report.get('detail') or 'no detail'}); the resolved journal and recovery "
                    "record remain available for retry")
            continue
        binding = (record.evidence or {}).get(name)
        if not binding:
            continue
        from . import proxy_transaction as px

        # Verify now, but retain this operation-specific preparation evidence until the durable
        # retirement receipt lands.  Removing it first would make a crash before that receipt
        # indistinguishable from unproved evidence loss on retry.
        px.verify_evidence(binding)


def _px_clear_unpublished_evidence(record) -> None:
    """Remove only exact operation-bound preparation evidence after retirement is receipted."""
    for entry in record.per_type:
        if entry.get("published"):
            continue
        binding = (record.evidence or {}).get(entry["proxy_type"])
        if not binding:
            continue
        path = Path(binding["path"])
        path.unlink(missing_ok=True)
        if path.exists():
            raise _PxRefused(
                f"the operation-named preparation evidence remains at {path}; the durable "
                "retirement receipt and recovery record remain available for retry")


def _px_record_after_abort(record, details):
    """Refine pessimistic intent into the artifact set a verified abort actually restored."""
    from .proxy_policy import FMSADMIN_RESTART_MECHANISMS

    restored = {item["proxy_type"] for item in details if item.get("restored") is True}
    entries = tuple(
        dict(entry,
             published=bool(entry.get("published") and entry["proxy_type"] in restored),
             activated=False,
             backup_reference=(entry.get("backup_reference")
                               if entry.get("published") and entry["proxy_type"] in restored
                               else None))
        for entry in record.per_type
    )
    restart_owed_by_shape = any(
        entry["published"] and entry["mechanism"] in FMSADMIN_RESTART_MECHANISMS
        for entry in entries)
    return dataclasses.replace(
        record, per_type=entries,
        restoration_restart_may_be_required=restart_owed_by_shape)


def _px_finish_retirement(layout, journal, record, engine) -> None:
    """Retire one resolved proxy operation with a durable, retryable receipt.

    The journal checkpoint closes the only ambiguous crash window: once it is present, a missing
    recovery record means retirement completed rather than that authority vanished.  Until it is
    present, the operation-bound recovery record remains mandatory and retirement is safely
    repeatable.
    """
    from . import proxy_transaction as px
    from .lock import LifecycleLock

    current = journal.read()
    if current is None:
        raise _PxRefused("the proxy lifecycle journal is absent; retirement cannot be proven")
    if current.operation_id != record.operation_id:
        raise _PxRefused(
            f"the journal is for operation {current.operation_id!r}, not {record.operation_id!r}")
    if current.installation_id != record.installation_id:
        raise _PxRefused("the journal and proxy recovery record name different installations")
    if current.mode != "proxy_policy" or current.state != "resolved":
        raise _PxRefused(
            f"proxy retirement requires a resolved proxy_policy journal, got "
            f"{current.mode!r}/{current.state!r}")

    if current.last_checkpoint != _PX_RETIRED_CHECKPOINT:
        _px_retire_operation(engine, record)
        with LifecycleLock(layout) as lock:
            journal.mark_resolved_checkpoint(lock=lock, checkpoint=_PX_RETIRED_CHECKPOINT)

    # The durable checkpoint now carries the proof needed if this process dies after unlinking the
    # companion record but before the installer discards the resolved journal.
    _px_clear_unpublished_evidence(record)
    with LifecycleLock(layout) as lock:
        px.clear_recovery(layout, lock=lock)


class CredentialRefused(_PxRefused):
    """A required credential was absent. Raised BEFORE any restoration begins."""


def _px_finalize(layout, record, *, published, committed_generation: int) -> tuple[bool, str]:
    """§9.2. Verify identity, generation and policy are EXACTLY equal, and only then retire."""
    if published.installation_id != record.installation_id:
        return False, (f"the published manifest is for installation "
                       f"{published.installation_id!r}, the recorded candidate for "
                       f"{record.installation_id!r}")
    if published.generation != committed_generation:
        return False, (f"the published manifest is at generation {published.generation}, "
                       f"finalize was told {committed_generation}")
    current = {k: dict(v.to_dict()) for k, v in (published.proxy_policy or {}).items()}
    for name, entry in record.candidates.items():
        if current.get(name) != dict(entry):
            return False, (f"the published proxy_policy for {name!r} is not exactly the recorded "
                           f"candidate; nothing is retired")
    return True, "the published manifest exactly matches the recorded candidate"


def _px_publish_policy(candidates, *, expected_generation: int):
    """The direct-commit manifest write: the SAME manifest authority, never a second store."""
    from dataclasses import replace as _replace

    from .lock import LifecycleLock
    from .manifest import ManifestStore

    layout = platform_layout()
    record = locator_for(layout).read()
    store = ManifestStore(Path(record.install_dir), record.manifest_relative_path, layout=layout)
    with LifecycleLock(layout) as lock:
        manifest = store.read()
        merged = dict(manifest.proxy_policy)
        merged.update(candidates)
        store.write(_replace(manifest, proxy_policy=merged), lock=lock,
                    expected_generation=expected_generation)


# ── the integrator surface ────────────────────────────────────────────────────

def _proxy_integrator(args, *, engine=None) -> int:
    """`python -m corpusfm.lifecycle proxy <verb> --request <root-owned.json>`.

    Every failure becomes a JSON report and a per-verb exit code; nothing escapes as a traceback,
    and nothing here is reachable from the public tool.
    """
    from . import proxy_transaction as px

    verb = args.px_verb
    try:
        request = _px_read_request(args.request, verb)
    except _RequestRefused as exc:
        _px_emit(_px_refusal("request_refused", str(exc),
                             next_action="Supply a root-owned request file with exactly this "
                                         "verb's documented keys."))
        return _PX_BAD_REQUEST

    try:
        if verb == "status":
            return _px_integrator_status(request, engine=engine)
        if verb == "reconcile":
            return _px_integrator_reconcile(request, engine=engine)
        if verb == "finalize":
            return _px_integrator_finalize(request, engine=engine)
        if verb == "retire":
            return _px_integrator_retire(request, engine=engine)
        return _px_integrator_abort(request, engine=engine)
    except px.CredentialUnavailable as exc:
        return _px_credential_refusal(exc)
    except (_PxRefused, px.ProxyRefused) as exc:
        _px_emit(_px_refusal("proxy_refused", str(exc),
                             next_action="Resolve the stated condition, then re-run."))
        return _PX_REFUSED
    except (LifecycleError, OSError) as exc:
        _px_emit(_px_refusal("proxy_failed", f"{type(exc).__name__}: {exc}",
                             next_action="Inspect this installation's lifecycle state."))
        return _PX_REFUSED


def _px_credential_refusal(exc) -> int:
    """A credential that could not be read is `failed_before_change`, never a traceback (ruling 8).

    §7.1 requires it: an EOF or short read before both fields complete is a refusal, and nothing was
    published or restarted. The failure happens before `journal.begin`, so no journal record and no
    recovery evidence exist to clean up — but the REPORTING was escaping as a stack trace, because
    `CredentialUnavailable` subclasses `proxy_transaction.ProxyRefused` and neither CLI surface
    caught that type. The message is the exception's own text, which by construction names the
    channel and never the value.
    """
    _px_emit(_px_refusal(
        "credential_unavailable", str(exc),
        next_action=("Supply a complete credential frame — two length-prefixed UTF-8 fields, user "
                     "then password, followed by EOF — and re-run. Nothing was published, "
                     "activated or recorded.")))
    return _PX_REFUSED


def _px_published_or_none():
    """The published installation, or None when this box has not published one yet.

    None is a legitimate answer ONLY on the integrator surface: 1246-04 must plan and act BEFORE the
    manifest exists, which is exactly why that surface carries its own proposed web facts. The
    public surface never accepts it.
    """
    from .published import InstallationNotPublished, read_published_installation

    try:
        return read_published_installation()
    except InstallationNotPublished:
        return None


def _px_integrator_status(request, *, engine=None) -> int:
    from .proxy_policy import ProxyPolicyView

    published = _px_published_or_none()
    view = ProxyPolicyView(entries=dict(published.proxy_policy) if published else {})
    paths = _px_request_paths(request)
    observations = _px_observations(request["types"], prefix=request["prefix"], **paths)
    plan = _px_plan(view, observations, verb="status", types=request["types"],
                    prefix=request["prefix"], port=int(request["port"]),
                    fms_root=paths["fms_root"], install_dir=paths["install_dir"])
    payload = _px_status_payload(plan, observations, view)
    payload["unresolved_operation"] = _px_unresolved(
        platform_layout(), published.proxy_policy if published else {})
    payload["installation_id"] = request["installation_id"]
    _px_emit(payload)
    return _PX_OK


def _px_status_payload(plan, observations, view, *, next_action: str = "") -> dict[str, Any]:
    """What `status` answers — and it mutates nothing to answer it (§10)."""
    from .proxy_policy import ACTION_PUBLISH, ACTION_REFUSE, ACTION_REMOVE, MECH_NONE

    by_type = {o.proxy_type: o for o in observations}
    return {
        "result": NO_CHANGE,
        "mutation_needed": [t.proxy_type for t in plan.types
                            if t.action in (ACTION_PUBLISH, ACTION_REMOVE)],
        "fms_admin_login_required": bool(plan.credentials_required),
        "refusals": [{"proxy_type": t.proxy_type, "reason": t.reason,
                      "operator_steps": list(t.operator_steps)}
                     for t in plan.types if t.action == ACTION_REFUSE],
        # Which types would need an activation step after their bytes changed. `status` can answer
        # this only because it now plans for real (ruling 6); while it short-circuited to
        # ACTION_NONE the list was structurally always empty.
        "activation_required": [t.proxy_type for t in plan.types
                                if t.action in (ACTION_PUBLISH, ACTION_REMOVE)
                                and t.mechanism != MECH_NONE],
        "per_type": [
            {"proxy_type": t.proxy_type, "policy": t.policy, "action": t.action,
             "activation_mechanism": t.mechanism, "installed": t.installed, "active": t.active,
             "owned_block": by_type[t.proxy_type].owned_block,
             "config_location": by_type[t.proxy_type].config_location,
             "detail": t.reason,
             # A refusal reported without its sequence is not actionable, and `status` is the verb
             # an administrator reads BEFORE deciding what to do.
             "operator_steps": list(t.operator_steps)}
            for t in plan.types
        ],
        "candidates": {},
        "findings": [],
        # A PARAMETER, not a placeholder every caller overwrites. The duplicate assignment left the
        # literal `""` dead in the dict and the real value three statements away.
        "next_action": next_action,
    }


def _px_authority(*, operation_id: str, installation_id: str, expected_generation: int,
                  disposition: str, prefix: str, port: int, paths: dict):
    """Assemble the operation's authority ONCE, so no caller can pass some of it and forget the rest.

    That was the defect: `_px_engine`, `intent_record` and `build_run_result` were each called
    through their old signatures, so the durable record ended up with none of the paths, no route,
    no executor identity and no evidence binding — every field the ruling added, present in the
    dataclass and absent from every real record.
    """
    from . import proxy_transaction as px

    script = Path(paths["script"])
    return px.OperationAuthority(
        operation_id=operation_id, installation_id=installation_id,
        expected_generation=expected_generation, disposition=disposition,
        flavour=(px.WINDOWS if os.name == "nt" else px.POSIX),
        install_dir=str(paths["install_dir"]), fms_root=str(paths["fms_root"]),
        web_prefix=prefix, web_internal_port=int(port),
        executor_path=str(script), executor_digest=px.executor_digest(script),
    )


def _px_prepare(eng, plan, authority, layout, journal, lock_factory):
    """Stage one of the two-stage operation (ruling 4): capture the before-image, change nothing.

    The executor's `prepare` verb touches no routing, so a crash here leaves evidence and an
    untouched box — a state a later process can classify cleanly instead of having to guess whether
    a mutation began. The capture is then validated and DIGEST-BOUND before `prepared` is written,
    and only a `prepared` record authorizes a mutation.
    """
    from . import proxy_transaction as px

    evidence = {}
    for planned in plan.mutating:
        report = eng.executor("prepare", planned.proxy_type)
        if not report.get("ok"):
            raise _PxRefused(
                f"the before-image for {planned.proxy_type} could not be captured "
                f"({report.get('detail') or 'no detail'}); nothing has been changed")
        path = report.get("evidence")
        if not path:
            continue                    # a type whose executor captures no file (apache today)
        binding = px.bind_evidence(path, operation_id=authority.operation_id,
                                   install_dir=authority.install_dir, flavour=authority.flavour)
        evidence[planned.proxy_type] = binding

    with lock_factory() as lock:
        px.write_recovery(layout, px.intent_record(
            plan=plan, authority=authority, phase=px.PHASE_PREPARED, evidence=evidence), lock=lock)
    return evidence


def _px_integrator_reconcile(request, *, engine=None) -> int:
    """Compose a candidate: run the transaction, leave the evidence and the journal OPEN (§9.1)."""
    from . import proxy_transaction as px
    from .lock import LifecycleLock
    from .journal import Journal
    from .proxy_policy import ProxyPolicyView

    published = _px_published_or_none()
    view = ProxyPolicyView(entries=dict(published.proxy_policy) if published else {})
    paths = _px_request_paths(request)
    observations = _px_observations(request["types"], prefix=request["prefix"], **paths)
    plan = _px_plan(view, observations, verb="reconcile", types=request["types"],
                    prefix=request["prefix"], port=int(request["port"]),
                    fms_root=paths["fms_root"], install_dir=paths["install_dir"])

    lease = None
    # Minted BEFORE the journal opens so the journal record and the recovery record are correlated
    # by one identity. Two independently generated ids would make a later process unable to say
    # whether the evidence it found belongs to the operation the journal is waiting on.
    operation_id = str(uuid.uuid4())
    authority = _px_authority(
        operation_id=operation_id, installation_id=request["installation_id"],
        expected_generation=int(request["expected_generation"]),
        disposition=px.COMPOSED_CANDIDATE, prefix=request["prefix"], port=int(request["port"]),
        paths=paths)
    layout = platform_layout()
    journal = Journal(layout)
    eng = engine or _px_engine(
        prefix=request["prefix"], port=int(request["port"]), fms_root=paths["fms_root"],
        install_dir=paths["install_dir"], script=paths["script"], operation_id=operation_id,
        claris_nginx_active=_px_claris_active(observations))
    plan = eng.preflight_inactive(plan)

    # A failed baseline preflight changes no bytes and opens no lifecycle operation.  Return the
    # per-front explanation, but no candidate: composing the old policy back into the manifest
    # would falsely describe the skipped front as work completed by this run.
    if not plan.mutating:
        outcomes = eng.run(plan, observations, lease=None)
        run = px.build_run_result(
            plan=plan, outcomes=outcomes, observations=observations, authority=authority,
            stored={t: (view.entries[t].config_fingerprint if t in view.entries else None)
                    for t in request["types"]}, evidence={})
        payload = _px_result_payload(run)
        payload["candidates"] = {}
        payload["composition_state"] = None
        payload["awaiting_composition"] = False
        payload["abort_fms_admin_login_required"] = False
        _px_emit(payload)
        return _px_exit(run.result)

    try:
        if plan.credentials_required:
            lease = _px_lease(request["credential_input"])
        with LifecycleLock(layout) as lock:
            journal.begin(lock=lock, operation_id=operation_id, mode="proxy_policy",
                          installation_id=request["installation_id"])
            # PHASE ONE. Every authority fact is already here; a process killed before `prepared`
            # left evidence and an untouched box.
            px.write_recovery(layout, px.intent_record(plan=plan, authority=authority), lock=lock)
        evidence = _px_prepare(eng, plan, authority, layout, journal,
                               lambda: LifecycleLock(layout))
        outcomes = eng.run(plan, observations, lease=lease)
        run = px.build_run_result(
            plan=plan, outcomes=outcomes, observations=observations, authority=authority,
            stored={t: (view.entries[t].config_fingerprint if t in view.entries else None)
                    for t in request["types"]},
            evidence=evidence)
        settled = px.totally_rolled_back(run.recovery_record)
        with LifecycleLock(layout) as lock:
            px.write_recovery(layout, run.recovery_record, lock=lock)
            if settled:
                # A TOTAL, VERIFIED ROLLBACK OWES NOTHING (packet 1246-10-04). Nothing was
                # published, nothing was activated, no restart is owed and every mutating front is
                # recorded as restored - so there is no live routing for the manifest to describe
                # and no candidate to compose. Marking it `needs_recovery` described work that did
                # not exist, and on Windows it produced a state no shipped verb could retire:
                # `abort` refused for evidence the successful restore had already deleted, and
                # `discard-provider` refused a record that was not resolved. Measured on
                # winfms2026, 2026-08-09, operation 515b6d84.
                journal.resolve(lock=lock, result=run.result)
            else:
                # DELIBERATELY NOT RESOLVED: the routing may now be live and the manifest does not
                # yet say so. 1246-04 finalizes or aborts; until then this installation owes a
                # resolution.
                journal.mark_needs_recovery(
                    lock=lock, reason=f"proxy {run.operation_id} {px.AWAITING_COMPOSITION}")
        if settled:
            # AFTER resolution, never before: a crash or refusal here leaves the resolved journal
            # and recovery record together, so the next installer can retry provider retirement.
            _px_finish_retirement(layout, journal, run.recovery_record, eng)
    finally:
        if lease is not None:
            lease.wipe()

    payload = _px_result_payload(run, next_action=(
        "" if settled else
        "Compose the manifest write, then call finalize with the committed generation; call abort "
        "if any later phase fails."))
    payload["composition_state"] = None if settled else px.AWAITING_COMPOSITION
    payload["awaiting_composition"] = not settled
    payload["abort_fms_admin_login_required"] = px.abort_needs_credential(run.recovery_record)
    _px_emit(payload)
    return _px_exit(run.result)


def _px_integrator_finalize(request, *, engine=None) -> int:
    from . import proxy_transaction as px
    from .journal import Journal
    from .lock import LifecycleLock
    from .published import InstallationNotPublished, read_published_installation

    layout = platform_layout()
    try:
        record = px.read_recovery(layout)
    except px.RecoveryEvidenceInvalid as exc:
        _px_emit(_px_refusal("recovery_evidence_invalid", str(exc),
                             operation_id=request["operation_id"],
                             next_action="Inspect this box's proxy evidence before any further "
                                         "operation; do NOT assume nothing was changed."))
        return _PX_MANUAL
    if record.operation_id != request["operation_id"]:
        _px_emit(_px_refusal(
            "recovery_operation_mismatch",
            f"the stored evidence is for operation {record.operation_id!r}",
            operation_id=request["operation_id"],
            next_action=f"Re-run finalize with operation_id {record.operation_id}."))
        return _PX_MANUAL

    journal = Journal(layout)
    current = journal.read()
    if current is not None and current.state == "resolved":
        _px_finish_retirement(
            layout, journal, record, _px_recovery_engine(record, engine))
        _px_emit({"result": current.result, "operation_id": record.operation_id,
                  "findings": [], "per_type": [], "candidates": {}, "next_action": "",
                  "detail": "the resolved operation's artifact retirement completed"})
        return _PX_OK

    try:
        published = read_published_installation()
    except InstallationNotPublished as exc:
        _px_emit(_px_refusal("installation_not_published", str(exc),
                             operation_id=record.operation_id,
                             next_action="Publish the composed manifest, then finalize."))
        return _PX_REFUSED

    ok, detail = _px_finalize(layout, record, published=published,
                              committed_generation=int(request["committed_generation"]))
    if not ok:
        # A mismatch does NOT finalize. The evidence stays exactly where it is.
        _px_emit(_px_refusal("finalize_mismatch", detail, operation_id=record.operation_id,
                             next_action="Abort this operation, or publish the exact candidate."))
        return _PX_MANUAL

    with LifecycleLock(layout) as lock:
        journal.resolve(lock=lock, result=COMPLETED)
    _px_finish_retirement(layout, journal, record, _px_recovery_engine(record, engine))
    _px_emit({"result": COMPLETED, "operation_id": record.operation_id, "findings": [],
              "per_type": [], "candidates": {}, "next_action": "",
              "detail": detail})
    return _PX_OK


def _px_integrator_abort(request, *, engine=None) -> int:
    from . import proxy_transaction as px
    from .journal import Journal
    from .lock import LifecycleLock

    layout = platform_layout()
    try:
        record = px.read_recovery(layout)
    except px.RecoveryEvidenceInvalid as exc:
        _px_emit(_px_refusal("recovery_evidence_invalid", str(exc),
                             operation_id=request["operation_id"],
                             next_action="Inspect this box's proxy evidence; do NOT assume nothing "
                                         "was changed."))
        return _PX_MANUAL
    if record.operation_id != request["operation_id"]:
        _px_emit(_px_refusal(
            "recovery_operation_mismatch",
            f"the stored evidence is for operation {record.operation_id!r}",
            operation_id=request["operation_id"],
            next_action=f"Re-run abort with operation_id {record.operation_id}."))
        return _PX_MANUAL

    journal = Journal(layout)
    current = journal.read()
    if current is not None and current.state == "resolved":
        _px_finish_retirement(
            layout, journal, record, _px_recovery_engine(record, engine))
        _px_emit({"result": current.result, "operation_id": record.operation_id,
                  "restored": [], "findings": [], "per_type": [], "candidates": {},
                  "next_action": ""})
        return _PX_OK

    try:
        # A THUNK, not a lease. `_px_abort` opens the transport only if the classification proves a
        # changed type actually needs a restoration restart — a `prepared`, unchanged operation must
        # not consume a one-shot pipe to discover it had nothing to do.
        eng = _px_recovery_engine(record, engine)
        result, details = _px_abort(
            eng, record, lambda: _px_lease(request["credential_input"]))
    except CredentialRefused as exc:
        # BEFORE restoration: every backup is byte-identical and the journal stays unresolved.
        _px_emit(_px_refusal("abort_credentials_required", str(exc),
                             operation_id=record.operation_id,
                             next_action="Re-run abort supplying credential_input; every backup is "
                                         "retained and nothing has been restored."))
        return _PX_REFUSED
    except px.CredentialUnavailable as exc:
        _px_emit(_px_refusal("abort_credentials_required", str(exc),
                             operation_id=record.operation_id,
                             next_action="Re-run abort with a complete credential frame; nothing "
                                         "has been restored."))
        return _PX_REFUSED

    if result in (ROLLED_BACK, NO_CHANGE):
        settled_record = _px_record_after_abort(record, details)
        with LifecycleLock(layout) as lock:
            px.write_recovery(layout, settled_record, lock=lock)
            journal.resolve(lock=lock, result=result)
        try:
            _px_finish_retirement(layout, journal, settled_record, eng)
        except _PxRefused as exc:
            _px_emit(_px_refusal(
                "retirement_incomplete", str(exc), result=MANUAL_ACTION_REQUIRED,
                operation_id=record.operation_id,
                next_action="Re-run proxy retire for this resolved operation; its recovery record "
                            "and journal remain intact."))
            return _PX_MANUAL
    _px_emit({"result": result, "operation_id": record.operation_id, "restored": details,
              "findings": [], "per_type": [], "candidates": {},
              "next_action": ("" if result in (ROLLED_BACK, NO_CHANGE) else
                              "Restoration could not be verified; the evidence is retained.")})
    return _px_exit(result)


def _px_integrator_retire(request, *, engine=None) -> int:
    """Finish provider-owned artifacts before an installer discards a resolved journal."""
    from . import proxy_transaction as px
    from .journal import Journal
    from .lock import LifecycleLock

    layout = platform_layout()
    journal = Journal(layout)
    current = journal.read()
    if current is None:
        raise _PxRefused("the proxy lifecycle journal is absent; nothing can be retired")
    if current.operation_id != request["operation_id"]:
        raise _PxRefused(
            f"the journal is for operation {current.operation_id!r}, not "
            f"{request['operation_id']!r}")
    if current.installation_id != request["installation_id"]:
        raise _PxRefused("the request and proxy lifecycle journal name different installations")
    if current.mode != "proxy_policy" or current.state != "resolved":
        raise _PxRefused(
            f"proxy retirement requires a resolved proxy_policy journal, got "
            f"{current.mode!r}/{current.state!r}")

    # A checkpoint with no companion record is the intentional crash-retry state after retirement,
    # not permission to infer success from absence alone.
    if current.last_checkpoint == _PX_RETIRED_CHECKPOINT:
        if not px.recovery_path(layout).exists():
            record = None
        else:
            try:
                record = px.read_recovery(layout)
            except px.RecoveryEvidenceInvalid as exc:
                raise _PxRefused(
                    f"the retirement receipt exists but its companion recovery record is invalid "
                    f"({exc})") from exc
        if record is not None:
            if (record.operation_id != current.operation_id or
                    record.installation_id != current.installation_id):
                raise _PxRefused("the retirement receipt and proxy recovery record do not agree")
            _px_clear_unpublished_evidence(record)
            with LifecycleLock(layout) as lock:
                px.clear_recovery(layout, lock=lock)
    else:
        try:
            record = px.read_recovery(layout)
        except px.RecoveryEvidenceInvalid as exc:
            raise _PxRefused(
                f"the resolved proxy journal has no retirement receipt and its recovery authority "
                f"cannot be read ({exc})") from exc
        if record.operation_id != current.operation_id:
            raise _PxRefused("the proxy recovery record belongs to a different operation")
        if record.installation_id != current.installation_id:
            raise _PxRefused("the proxy recovery record belongs to a different installation")
        _px_finish_retirement(
            layout, journal, record, _px_recovery_engine(record, engine))

    _px_emit({"result": COMPLETED, "operation_id": current.operation_id, "findings": [],
              "per_type": [], "candidates": {}, "next_action": "",
              "detail": "proxy artifacts retired; the resolved journal may now be discarded"})
    return _PX_OK


# ── the public administrator surface ──────────────────────────────────────────

def _proxy_public(args, *, engine=None) -> int:
    """`corpusfm-proxy status|add|ignore|remove|reconcile [<type>|all] [--json]`.

    No request file, no disposition, no `finalize`, no `abort`, no rollback flag. Route facts come
    from the published manifest and from nowhere else. Mutating verbs use `direct_commit`
    internally, and every one of them runs the §9.5 recovery precondition first.
    """
    from . import proxy_transaction as px
    from .proxy_policy import expand_selector

    try:
        types = expand_selector(args.selector)
    except ValueError as exc:
        _px_emit(_px_refusal("unsupported_type", str(exc),
                             next_action="Name a supported proxy type, or 'all'."))
        return _PX_BAD_REQUEST

    try:
        if args.px_verb == "status":
            return _px_public_status(types, engine=engine)
        return _px_public_mutate(args.px_verb, types, engine=engine)
    except px.CredentialUnavailable as exc:
        return _px_credential_refusal(exc)
    except (_PxRefused, px.ProxyRefused) as exc:
        _px_emit(_px_refusal("proxy_refused", str(exc),
                             next_action="Resolve the stated condition, then re-run."))
        return _PX_REFUSED
    except (LifecycleError, OSError) as exc:
        _px_emit(_px_refusal("proxy_failed", f"{type(exc).__name__}: {exc}",
                             next_action="Inspect this installation's lifecycle state."))
        return _PX_REFUSED


def _px_public_published():
    """The published installation — REQUIRED. The public tool has no other authority to read."""
    from .published import InstallationNotPublished, read_published_installation

    try:
        return read_published_installation()
    except InstallationNotPublished as exc:
        raise _PxRefused(
            f"{exc}; corpusfm-proxy reads this installation's identity and route facts from its "
            f"published manifest, and will not guess them") from exc


def _px_public_status(types, *, engine=None) -> int:
    """STRICTLY read-only. It never finalizes and never aborts (§9.5).

    An administrator must be able to look without changing anything — a diagnostic that mutates is
    not a diagnostic.
    """
    from .proxy_policy import ProxyPolicyView

    published = _px_public_published()
    prefix, port = _px_route_facts(published)
    paths = _px_published_paths(published)
    view = ProxyPolicyView(entries=dict(published.proxy_policy))
    observations = _px_observations(types, prefix=prefix, **paths)
    plan = _px_plan(view, observations, verb="status", types=types, prefix=prefix, port=port,
                    fms_root=paths["fms_root"], install_dir=paths["install_dir"])

    payload = _px_status_payload(plan, observations, view)
    payload["installation_id"] = published.installation_id
    payload["generation"] = published.generation
    payload["web"] = {"prefix": prefix, "internal_port": port}
    payload["unresolved_operation"] = _px_unresolved(platform_layout(), published.proxy_policy)
    _px_emit(payload)
    return _PX_OK


def _px_nothing_to_do(plan, view, verb: str, types) -> bool:
    """Would this run change nothing at all — no routing, and no policy to record?

    Its own question because a refusal must touch NOTHING (ruling 3), and "nothing" includes the
    journal. An earlier version opened a journal and resolved it `failed_before_change` for a run
    that had already decided to refuse every type, which leaves a record of an operation that never
    began. A refused type contributes no candidate either — §6.4's `remove` must refuse BEFORE
    recording `ignored` — so a wholly-refused run has no policy to write and no reason to journal.
    """
    from .proxy_policy import ACTION_REFUSE

    if plan.mutating:
        return False
    recordable = set(_px_apply_policy_verb(view, verb, types))
    refused = {t.proxy_type for t in plan.types if t.action == ACTION_REFUSE}
    return not (recordable - refused)


def _px_public_mutate(verb: str, types, *, engine=None) -> int:
    """One mutating verb — after the recovery precondition, and never alongside it (§9.5)."""
    from . import proxy_transaction as px
    from .journal import Journal
    from .lock import LifecycleLock
    from .proxy_policy import ProxyPolicyView

    published = _px_public_published()
    prefix, port = _px_route_facts(published)
    paths = _px_published_paths(published)
    layout = platform_layout()

    # RECOVERY FIRST, and recovery ALWAYS ends the invocation. Two mutations in one command, one of
    # them implicit and unrequested, is exactly the shape that makes a failure unattributable.
    handled, code = _px_recovery_precondition(layout, published, verb, engine=engine)
    if handled:
        return code

    view = ProxyPolicyView(entries=dict(published.proxy_policy))
    observations = _px_observations(types, prefix=prefix, **paths)
    plan = _px_plan(view, observations, verb=verb, types=types, prefix=prefix, port=port,
                    fms_root=paths["fms_root"], install_dir=paths["install_dir"])

    # Only a planned inactive mutation needs the read-only baseline check. Keep a genuine no-op
    # free of executor calls, and mint the operation identity early only when preflight needs the
    # same installed executor the eventual transaction will use.
    operation_id = None
    eng = engine
    if any(item.action == px.ACTION_PUBLISH and item.mechanism == px.MECH_NONE
           for item in plan.types):
        operation_id = str(uuid.uuid4())
        eng = eng or _px_engine(
            prefix=prefix, port=port, fms_root=paths["fms_root"],
            install_dir=paths["install_dir"], script=paths["script"],
            operation_id=operation_id, claris_nginx_active=_px_claris_active(observations))
        plan = eng.preflight_inactive(plan)

    if _px_nothing_to_do(plan, view, verb, types):
        # Report and stop, WITHOUT a journal, a credential or a manifest write. An inactive
        # baseline preflight may have made one read-only executor call to reach this answer.
        payload = _px_status_payload(
            plan, observations, view,
            next_action=("Resolve the stated condition, then re-run." if plan.refusals else ""))
        payload["result"] = (FAILED_BEFORE_CHANGE if plan.refusals else NO_CHANGE)
        payload["installation_id"] = published.installation_id
        payload["generation"] = published.generation
        _px_emit(payload)
        return _px_exit(payload["result"])

    lease = None
    operation_id = operation_id or str(uuid.uuid4())
    journal = Journal(layout)
    authority = _px_authority(
        operation_id=operation_id, installation_id=published.installation_id,
        expected_generation=published.generation, disposition=px.DIRECT_COMMIT,
        prefix=prefix, port=port, paths=paths)
    try:
        if plan.credentials_required:
            lease = px.prompt_for_credential()
        eng = eng or _px_engine(
            prefix=prefix, port=port, fms_root=paths["fms_root"],
            install_dir=paths["install_dir"], script=paths["script"], operation_id=operation_id,
            claris_nginx_active=_px_claris_active(observations))
        with LifecycleLock(layout) as lock:
            journal.begin(lock=lock, operation_id=operation_id, mode="proxy_policy",
                          installation_id=published.installation_id)
            px.write_recovery(layout, px.intent_record(plan=plan, authority=authority), lock=lock)
        evidence = _px_prepare(eng, plan, authority, layout, journal,
                               lambda: LifecycleLock(layout))
        outcomes = eng.run(plan, observations, lease=lease)
        run = px.build_run_result(
            plan=plan, outcomes=outcomes, observations=observations, authority=authority,
            stored={t: (view.entries[t].config_fingerprint if t in view.entries else None)
                    for t in types},
            evidence=evidence)
        # `add`/`ignore` move POLICY even where nothing on disk changed — that is what they are.
        candidates = dict(run.candidates)
        for name, policy in _px_apply_policy_verb(view, verb, types).items():
            if name in candidates:
                candidates[name] = _replace_policy(candidates[name], policy)
        with LifecycleLock(layout) as lock:
            px.write_recovery(layout, _record_with(run.recovery_record, candidates), lock=lock)
    finally:
        if lease is not None:
            lease.wipe()

    # Backups are RETAINED until the expected-generation manifest write succeeds — and a run that
    # composed NO candidate performs no write at all. An empty candidate set is exactly what a
    # wholly-refused run produces, and a generation bump recording nothing is still a publication.
    if candidates:
        try:
            _px_publish_policy(candidates, expected_generation=published.generation)
        except LifecycleError as exc:
            return _px_direct_commit_failed(layout, journal, run, exc, engine=engine)

    with LifecycleLock(layout) as lock:
        journal.resolve(lock=lock, result=run.result)
    _px_finish_retirement(layout, journal, run.recovery_record, eng)

    payload = _px_result_payload(run)
    payload["candidates"] = {k: v.to_dict() for k, v in candidates.items()}
    payload["generation"] = published.generation + (1 if candidates else 0)
    _px_emit(payload)
    return _px_exit(run.result)


def _replace_policy(entry, policy: str):
    from dataclasses import replace as _replace

    return _replace(entry, policy=policy)


def _record_with(record, candidates):
    from dataclasses import replace as _replace

    return _replace(record, candidates={k: v.to_dict() for k, v in candidates.items()})


def _px_direct_commit_failed(layout, journal, run, exc, *, engine=None) -> int:
    """A manifest-write failure or `GenerationConflict` triggers the SAME verified abort (§9.5)."""
    from . import proxy_transaction as px
    from .lock import LifecycleLock

    try:
        eng = _px_recovery_engine(run.recovery_record, engine)
        result, details = _px_abort(eng, run.recovery_record, px.prompt_for_credential)
    except (_PxRefused, px.ProxyRefused) as inner:
        _px_emit(_px_refusal(
            "manifest_write_failed", f"{exc}; and the abort could not proceed: {inner}",
            operation_id=run.operation_id,
            next_action="Every backup is retained and nothing was restored; re-run once the "
                        "credential is available."))
        return _PX_MANUAL

    if result in (ROLLED_BACK, NO_CHANGE):
        settled_record = _px_record_after_abort(run.recovery_record, details)
        with LifecycleLock(layout) as lock:
            px.write_recovery(layout, settled_record, lock=lock)
            journal.resolve(lock=lock, result=result)
        try:
            _px_finish_retirement(layout, journal, settled_record, eng)
        except _PxRefused as inner:
            _px_emit(_px_refusal(
                "retirement_incomplete", f"{exc}; rollback succeeded, but {inner}",
                result=MANUAL_ACTION_REQUIRED, operation_id=run.operation_id,
                next_action="Re-run proxy retire for this resolved operation."))
            return _PX_MANUAL
    _px_emit({"result": result, "operation_id": run.operation_id, "restored": details,
              "findings": [{"code": "manifest_write_failed", "detail": str(exc)}],
              "per_type": [], "candidates": {},
              "next_action": ("Re-run the verb." if result in (ROLLED_BACK, NO_CHANGE) else
                              "Restoration could not be verified; the evidence is retained.")})
    return _px_exit(result)


def _px_recovery_precondition(layout, published, verb: str, *, engine=None) -> tuple[bool, int]:
    """Exactly one of four things happens before any public mutating verb (§9.5).

    Returns `(handled, exit_code)`. `handled` True means recovery ran — or refused — and the
    invocation is OVER: the requested verb does not run in the same invocation, ever.
    """
    from . import proxy_transaction as px
    from .journal import Journal
    from .lock import LifecycleLock

    try:
        record = px.read_recovery(layout)
    except px.RecoveryEvidenceInvalid:
        return False, _PX_OK                        # no unresolved operation: proceed normally

    journal = Journal(layout)
    current = journal.read()
    if current is not None and current.state == "resolved":
        try:
            _px_finish_retirement(
                layout, journal, record, _px_recovery_engine(record, engine))
        except _PxRefused as exc:
            _px_emit(_px_refusal(
                "retirement_incomplete", str(exc), result=MANUAL_ACTION_REQUIRED,
                operation_id=record.operation_id,
                next_action=f"Re-run `corpusfm-proxy {verb}` to retry retirement."))
            return True, _PX_MANUAL
        _px_emit({"result": current.result, "operation_id": record.operation_id,
                  "recovery_completed": True, "per_type": [], "candidates": [],
                  "findings": [],
                  "next_action": f"Recovery completed. Re-run `corpusfm-proxy {verb}`."})
        return True, _PX_OK
    state = _px_unresolved(layout, published.proxy_policy)
    if state["manifest_matches_candidate"]:
        ok, detail = _px_finalize(layout, record, published=published,
                                  committed_generation=published.generation)
        if ok:
            eng = _px_recovery_engine(record, engine)
            with LifecycleLock(layout) as lock:
                journal.resolve(lock=lock, result=COMPLETED)
            _px_finish_retirement(layout, journal, record, eng)
            # STOPPING IS A SUCCESS OUTCOME, reported as one. The administrator's next action is one
            # keystroke, and the evidence is gone by then.
            _px_emit({"result": COMPLETED, "operation_id": record.operation_id,
                      "recovery_completed": True, "per_type": [], "candidates": [],
                      "findings": [],
                      "next_action": f"Recovery completed. Re-run `corpusfm-proxy {verb}`."})
            return True, _PX_OK

    try:
        eng = _px_recovery_engine(record, engine)
        result, details = _px_abort(eng, record, px.prompt_for_credential)
    except (_PxRefused, px.ProxyRefused) as exc:
        # REFUSE WITHOUT BEGINNING the requested mutation. All evidence intact, journal unresolved.
        _px_emit(_px_refusal(
            "recovery_blocked", str(exc), operation_id=record.operation_id,
            next_action="Every backup is retained and the journal is unresolved; supply the FMS "
                        "admin credential and re-run to complete recovery."))
        return True, _PX_REFUSED

    if result in (ROLLED_BACK, NO_CHANGE):
        settled_record = _px_record_after_abort(record, details)
        with LifecycleLock(layout) as lock:
            px.write_recovery(layout, settled_record, lock=lock)
            journal.resolve(lock=lock, result=result)
        try:
            _px_finish_retirement(layout, journal, settled_record, eng)
        except _PxRefused as exc:
            _px_emit(_px_refusal(
                "retirement_incomplete", str(exc), result=MANUAL_ACTION_REQUIRED,
                operation_id=record.operation_id,
                next_action=f"Recovery restored the operation. Re-run `corpusfm-proxy {verb}` "
                            "to finish retirement before starting another mutation."))
            return True, _PX_MANUAL
        _px_emit({"result": result, "operation_id": record.operation_id, "recovery_completed": True,
                  "restored": details, "per_type": [], "candidates": [], "findings": [],
                  "next_action": f"Recovery completed. Re-run `corpusfm-proxy {verb}`."})
        return True, _PX_OK

    _px_emit(_px_refusal(
        "recovery_unverified",
        "the recorded operation could not be restored and verified", operation_id=record.operation_id,
        next_action="Inspect the retained evidence; the requested verb was NOT started."))
    return True, _PX_MANUAL


# ── packet 1246-07: the Admin-API machine identity ───────────────────────────

_AI_SCHEMA_VERSION = 1

_AI_OBSERVE_KEYS = frozenset({
    "schema_version", "installation_id", "expected_generation", "install_dir", "fms_root",
    "secrets_dir", "host", "mode", "actor", "credential_input",
})
_AI_REQUEST_KEYS: dict[str, frozenset[str]] = {
    "observe": _AI_OBSERVE_KEYS,
    "reconcile": _AI_OBSERVE_KEYS,
    "remove": _AI_OBSERVE_KEYS | {"registration_name", "public_fingerprint"},
    "finalize": frozenset({"schema_version", "installation_id", "operation_id",
                           "committed_generation", "actor"}),
    "abort": frozenset({"schema_version", "installation_id", "operation_id", "actor",
                        "credential_input"}),
}


def _ai_credential_input_ok(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if value in ("absent", "prompt", "stdin"):
        return True
    return value.startswith("fd:") and value[3:].isdigit()


def _ai_read_request(path: str, verb: str, *, authority_api=None) -> dict:
    """Root-owned, not group/world-writable, and EXACTLY this verb's key set.

    `observe` has ONE key set for every mode — `credential_input` is always accepted and `absent` is
    an ordinary value. A schema whose accepted shape depends on its own contents cannot be checked
    before it is interpreted, which is the property `_reject_unknown` exists to give.
    """
    from .admin_identity import MODES

    text = _open_privileged_request(Path(path), authority_api=authority_api)
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise _RequestRefused(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise _RequestRefused("the request must be a JSON object")

    expected = _AI_REQUEST_KEYS[verb]
    unknown = set(raw) - expected
    if unknown:
        raise _RequestRefused(
            f"admin-identity {verb} does not accept key(s): {', '.join(sorted(unknown))}")
    missing = expected - set(raw)
    if missing:
        raise _RequestRefused(
            f"admin-identity {verb} is missing key(s): {', '.join(sorted(missing))}")
    if raw["schema_version"] != _AI_SCHEMA_VERSION:
        raise _RequestRefused(
            f"request schema_version {raw['schema_version']!r}; this build accepts "
            f"{_AI_SCHEMA_VERSION}")
    if "credential_input" in expected and not _ai_credential_input_ok(raw["credential_input"]):
        raise _RequestRefused(
            f"credential_input must be 'absent', 'prompt', 'stdin' or 'fd:<n>', "
            f"got {raw['credential_input']!r}")
    if "mode" in expected and raw["mode"] not in MODES:
        raise _RequestRefused(
            f"mode must be one of {MODES}; this component is not invoked in {raw['mode']!r}")
    if "expected_generation" in expected:
        gen = raw["expected_generation"]
        if not isinstance(gen, int) or isinstance(gen, bool) or gen < 0:
            raise _RequestRefused("expected_generation must be a non-negative integer (0 on fresh)")
    if "committed_generation" in expected:
        gen = raw["committed_generation"]
        # 1, not 0: finalize proves a manifest WAS written, and a written manifest is at least
        # generation 1. Accepting 0 here would accept "nothing was composed" as a composition.
        if not isinstance(gen, int) or isinstance(gen, bool) or gen < 1:
            raise _RequestRefused("committed_generation must be a positive integer")
    return raw


def _ai_emit(payload: dict[str, Any]) -> None:
    """The ONE place an admin-identity result is printed, through the secret fence."""
    from .secret_guard import assert_no_secrets

    assert_no_secrets(payload, what="the admin-identity result")
    print(json.dumps(payload, indent=2, sort_keys=True))


def _ai_refusal(code: str, detail: str, *, disposition: str = "invalid_combination",
                result: str = FAILED_BEFORE_CHANGE, next_action: str | None = None) -> dict:
    # `fms_admin_login_required`, not `credentials_required`: 1246-01's secret fence denies the key
    # token `credentials`, so the contract's internal name cannot be an EMITTED one. Same rule and
    # same spelling as `ObservationReport.payload`.
    return {"disposition": disposition, "result": result, "operation_id": None,
            "awaiting_composition": False, "unresolved_operation": None,
            "next_action": next_action if next_action is not None else detail,
            "prerequisite": None, "facts": None, "store_exists": None,
            "state": None, "fms_admin_login_required": False,
            "required_authority_operation": None,
            "mode_refusal": None, "findings": [{"code": code, "detail": detail}],
            "candidate": None}


#: One code per result word, TOTAL over the vocabulary — never a `.get(..., 3)` default. A word
#: this component does not emit today still has a defined code, because the next packet to emit one
#: must not silently inherit "a human must act".
_AI_EXIT_CODES: dict[str, int] = {
    COMPLETED: 0,
    NO_CHANGE: 0,
    FAILED_BEFORE_CHANGE: 1,
    ROLLED_BACK: 2,
    MANUAL_ACTION_REQUIRED: 3,
    INCOMPLETE_SAFE: 5,
}
_AI_BAD_REQUEST = 4


def _ai_exit(result_word: str) -> int:
    return _AI_EXIT_CODES[result_word]


def _ai_inputs(raw: dict):
    from .admin_identity_ops import IdentityInputs

    return IdentityInputs(
        installation_id=str(raw["installation_id"]),
        expected_generation=int(raw["expected_generation"]),
        install_dir=Path(raw["install_dir"]),
        fms_root=Path(raw["fms_root"]),
        secrets_dir=Path(raw["secrets_dir"]),
        host=str(raw["host"]),
        mode=str(raw["mode"]),
        actor=str(raw["actor"]),
    )


def _admin_identity(args, *, engine=None, lifecycle=None) -> int:
    """`observe` mutates nothing. `reconcile`, `remove` and `abort` MUTATE, under the lock.

    `finalize` and `abort` are integrator-surface composition verbs: they retire or discharge
    evidence a composed operation left, and an administrator never drives them casually.
    """
    from .admin_identity_ops import CredentialFrameRefused

    verb = args.ai_verb
    try:
        raw = _ai_read_request(args.request, verb)
    except _RequestRefused as exc:
        _ai_emit(_ai_refusal("request_refused", str(exc)))
        return _AI_BAD_REQUEST

    ops = engine if engine is not None else _ai_engine()
    layout = lifecycle if lifecycle is not None else platform_layout()
    journal = Journal(layout)
    lease = None
    try:
        # The transport is READ HERE, once, and only for a verb that can need one. An earlier
        # version validated `credential_input` in the schema and then passed `lease=None`
        # unconditionally, which made every reconcile refuse for want of authority it had been
        # handed — the surface 1246-04 must provision through could not provision anything.
        # `abort` reads a FRESH lease of its own: the one the interrupted operation held was wiped
        # when that process ended, and a credential is never persisted to be reused.
        if verb in ("reconcile", "remove", "abort"):
            lease = ops.CredentialLease.read(str(raw["credential_input"]))
        api = _ai_api() if engine is None else None
        probe = _ai_probe() if engine is None else None
        extra = {} if engine is not None else {"api": api, "probe": probe}
        if verb == "observe":
            report = ops.observe(_ai_inputs(raw), lifecycle_layout=layout, **extra)
        elif verb == "reconcile":
            with LifecycleLock(layout) as lock:
                report = ops.reconcile(_ai_inputs(raw), lease=lease, lifecycle_layout=layout,
                                       lock=lock, journal=journal, **extra)
        elif verb == "remove":
            with LifecycleLock(layout) as lock:
                report = ops.remove(_ai_inputs(raw),
                                    registration_name=str(raw["registration_name"]),
                                    public_fingerprint=str(raw["public_fingerprint"]),
                                    lease=lease, lifecycle_layout=layout, lock=lock,
                                    journal=journal, **extra)
        elif verb == "finalize":
            with LifecycleLock(layout) as lock:
                report = ops.finalize(
                    operation_id=str(raw["operation_id"]),
                    installation_id=str(raw["installation_id"]),
                    committed_generation=int(raw["committed_generation"]),
                    actor=str(raw["actor"]), lifecycle_layout=layout, lock=lock, journal=journal)
        else:
            with LifecycleLock(layout) as lock:
                report = ops.abort(
                    operation_id=str(raw["operation_id"]),
                    installation_id=str(raw["installation_id"]),
                    actor=str(raw["actor"]), lease=lease, lifecycle_layout=layout, lock=lock,
                    journal=journal, **({} if engine is not None else {"api": api}))
    except CredentialFrameRefused as exc:
        _ai_emit(_ai_refusal("credential_frame_refused", str(exc)))
        return 1
    except LifecycleError as exc:
        _ai_emit(_ai_refusal(type(exc).__name__, str(exc)))
        return 1
    except Exception as exc:            # noqa: BLE001
        # A traceback is not a result. The word is `manual_action_required` and NOT
        # `failed_before_change`: an arbitrary exception mid-operation cannot support the claim that
        # nothing was touched, and that claim is the whole meaning of the other word. Staged
        # material, the journal record and the recovery evidence are all LEFT IN PLACE — `abort`
        # discharges them from the operation's own record, which is why this no longer needs to
        # guess at a cleanup.
        _ai_emit(_ai_refusal(
            type(exc).__name__,
            f"the operation did not complete: {type(exc).__name__}",
            result=MANUAL_ACTION_REQUIRED,
            next_action=("Inspect `admin-identity observe`, then discharge the unresolved "
                         "operation it reports with `admin-identity abort`. Nothing was cleaned "
                         "up on the strength of an exception.")))
        return _ai_exit(MANUAL_ACTION_REQUIRED)
    finally:
        if lease is not None and hasattr(lease, "wipe"):
            lease.wipe()

    _ai_emit(report.payload())
    return _ai_exit(report.result)


def _ai_api():
    """The real Admin-API adapter: the four ADDITIVE primitives, never the delete-then-post ones."""
    from . import admin_identity_adapter

    return admin_identity_adapter.LiveAdminApi()


def _ai_probe():
    from . import admin_identity_adapter

    return admin_identity_adapter.reachability_probe


def _ai_engine():
    from . import admin_identity_ops

    return admin_identity_ops


# ── packet 1246-08: the storage identity ─────────────────────────────────────

_ST_SCHEMA_VERSION = 1

_ST_OBSERVE_KEYS = frozenset({
    "schema_version", "installation_id", "expected_generation", "install_dir", "fms_root",
    "fms_database_dir", "secrets_dir", "host", "mode", "actor",
})
_ST_REQUEST_KEYS: dict[str, frozenset[str]] = {
    "observe": _ST_OBSERVE_KEYS,
    "plan": _ST_OBSERVE_KEYS,
    "bootstrap": _ST_OBSERVE_KEYS,
    "adopt": _ST_OBSERVE_KEYS,
    "repair": _ST_OBSERVE_KEYS,
    "resume": _ST_OBSERVE_KEYS | {"operation_id"},
    "create-first-admin": _ST_OBSERVE_KEYS | {"admin_username", "admin_credential_input"},
    # EXACTLY §8.2's sets. A recovery verb runs in a fresh process AFTER the operation it
    # discharges, and its authority is the strict operation record plus the fixed lifecycle
    # layout — never a fresh caller path. The first implementation demanded paths, a host, a mode
    # and a generation here, which meant the contract's own documented request was REFUSED as
    # missing keys, and every one of those keys was an authority a caller could aim.
    "finalize": frozenset({"schema_version", "installation_id", "operation_id",
                           "committed_generation", "actor"}),
    "abort": frozenset({"schema_version", "installation_id", "operation_id", "actor"}),
}

#: There is NO `credential_input` on any storage verb. This component never authenticates as an FMS
#: administrator and never as a human: its three secrets are the promoted record, the shipped
#: bootstrap default and its own staged candidate. A transport key it would never read is a key an
#: integrator could be tempted to fill.
_ST_ADMIN_TRANSPORTS = ("prompt", "stdin")


def _st_transport_ok(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if value in _ST_ADMIN_TRANSPORTS:
        return True
    return value.startswith("fd:") and value[3:].isdigit()


def _st_read_request(path: str, verb: str, *, authority_api=None) -> dict:
    """Privileged input, judged on the OPEN DESCRIPTOR, with EXACTLY this verb's key set.

    No verb accepts a database, destination, credential path or password: the storage target is
    derived (`storage_identity.storage_target`) and the secrets are held, so a key for either would
    be an authority a caller could aim.
    """
    from .storage_identity import MODES

    text = _open_privileged_request(Path(path), authority_api=authority_api)
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise _RequestRefused(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise _RequestRefused("the request must be a JSON object")

    expected = _ST_REQUEST_KEYS[verb]
    unknown = set(raw) - expected
    if unknown:
        raise _RequestRefused(
            f"storage {verb} does not accept key(s): {', '.join(sorted(unknown))}")
    missing = expected - set(raw)
    if missing:
        raise _RequestRefused(
            f"storage {verb} is missing key(s): {', '.join(sorted(missing))}")
    if raw["schema_version"] != _ST_SCHEMA_VERSION:
        raise _RequestRefused(
            f"request schema_version {raw['schema_version']!r}; this build accepts "
            f"{_ST_SCHEMA_VERSION}")
    if "mode" in expected and raw["mode"] not in MODES:
        raise _RequestRefused(
            f"mode must be one of {MODES}; this component is not invoked in {raw['mode']!r}")
    if "expected_generation" in expected:
        gen = raw["expected_generation"]
        if not isinstance(gen, int) or isinstance(gen, bool) or gen < 0:
            raise _RequestRefused("expected_generation must be a non-negative integer")
    if "committed_generation" in expected:
        gen = raw["committed_generation"]
        # 1, not 0: finalize proves a manifest WAS written, and a written manifest is at least
        # generation 1. Accepting 0 would accept "nothing was composed" as a composition.
        if not isinstance(gen, int) or isinstance(gen, bool) or gen < 1:
            raise _RequestRefused("committed_generation must be a positive integer")
    if "admin_credential_input" in expected and not _st_transport_ok(raw["admin_credential_input"]):
        raise _RequestRefused(
            "admin_credential_input must be 'prompt', 'stdin' or 'fd:<n>'; there is no 'absent' "
            "form, because this verb cannot run without a secret")
    return raw


#: R5 (packet 1246-04-04). The ONE storage finding an installer may advance over despite exit 5.
ST_FRESH_SUCCESS_FINDING = "first_administrator_owed"

#: A canonical operation id: the lowercase 8-4-4-4-12 form every provider mints with `uuid4()`.
_ST_OPERATION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def proxy_mixed_success_is_composable(payload, *, installation_id: str,
                                      expected_generation: int) -> tuple[bool, str]:
    """May the installer compose a mixed proxy run despite exit 2?

    ``rolled_back`` is the aggregate word whenever any front rolled back, including a run where a
    different front was published and activated successfully. That run is not a total rollback:
    its journal deliberately remains open and its candidate must be composed. This predicate keeps
    the exception in the lifecycle layer and accepts only the exact mixed, candidate-bearing shape.
    """
    if not isinstance(payload, Mapping):
        return False, "the proxy result is not a JSON object"
    if payload.get("result") != ROLLED_BACK:
        return False, f"result is {payload.get('result')!r}, not {ROLLED_BACK!r}"
    if payload.get("awaiting_composition") is not True:
        return False, ("awaiting_composition is "
                       f"{payload.get('awaiting_composition')!r}, not exactly true")
    if payload.get("composition_state") != "awaiting_composition":
        return False, f"composition_state is {payload.get('composition_state')!r}"
    if payload.get("disposition") != "composed_candidate":
        return False, f"disposition is {payload.get('disposition')!r}"
    operation_id = payload.get("operation_id")
    if not isinstance(operation_id, str) or not _ST_OPERATION_ID.match(operation_id):
        return False, f"operation_id {operation_id!r} is absent or not canonical"
    if payload.get("installation_id") != installation_id:
        return False, "the proxy result belongs to a different installation"
    if payload.get("expected_generation") != expected_generation:
        return False, "the proxy result inspected a different manifest generation"
    candidates = payload.get("candidates")
    if not isinstance(candidates, Mapping) or not candidates:
        return False, "the proxy result carries no candidate to compose"
    per_type = payload.get("per_type")
    if not isinstance(per_type, list):
        return False, "the proxy result carries no per-type outcomes"
    completed = [entry for entry in per_type if isinstance(entry, Mapping)
                 and entry.get("result") == COMPLETED and entry.get("published") is True]
    restored = [entry for entry in per_type if isinstance(entry, Mapping)
                and entry.get("result") == ROLLED_BACK and entry.get("restored") is True]
    if not completed or not restored:
        return False, "the proxy result is not one published success plus one verified rollback"
    unsafe = [entry for entry in per_type if isinstance(entry, Mapping)
              and entry.get("result") in {FAILED_BEFORE_CHANGE, INCOMPLETE_SAFE,
                                           MANUAL_ACTION_REQUIRED}]
    if unsafe:
        return False, "the proxy result contains an unresolved per-type outcome"
    return True, "the mixed proxy run has a live published front and a verified restored front"


def storage_fresh_success_is_composable(payload, *, installation_id: str, expected_generation: int,
                                        mode: str) -> tuple[bool, str]:
    """May an installer advance over THIS `incomplete_safe`? Answered here, for both platforms.

    **Exit 5 remains a stop.** `lc_dispatch` / `Lc-Dispatch` die on it unconditionally and that does
    not change: `incomplete_safe` means an operation stopped part-way, and a shell that decided for
    itself which of those were survivable would be re-implementing a protocol it cannot see.

    There is exactly one exception, and it is not a failure at all. A FRESH install's `storage
    bootstrap` legitimately ends `incomplete_safe` with `first_administrator_owed`: the storage half
    succeeded and composed a candidate, and what is missing is the first administrator — which the
    installer creates at phase 19, *after* the candidate has been committed and finalized. Refusing
    it made a correct fresh install die at phase 18 with every service stopped; accepting exit 5
    generally would let a genuinely interrupted operation walk on.

    So the answer is a CONJUNCTION over the whole result, and every member is load-bearing:

      * `result` is exactly `incomplete_safe` — not a truthy word, not a prefix;
      * `awaiting_composition` is exactly `True` — the composition bracket really is open;
      * `candidate` is a non-null mapping carrying all three `StorageCandidate` fields;
      * `operation_id` is present and canonical, at the top level AND on the candidate's own
        installation, so the id the installer will commit against is the one the provider minted;
      * the findings carry `first_administrator_owed` — a DIFFERENT finding is a different
        situation, and an absent one is an unexplained partial success;
      * the invocation's `mode` is `fresh_install` — an update owes no first administrator, so an
        `incomplete_safe` there is an interruption;
      * the candidate's inspected installation and generation agree with the invocation's.

    Returns `(ok, reason)`. The reason is returned on BOTH paths so a refusal can say which member
    failed — a boolean alone turns "this exact shape" into "something was wrong".

    It takes only DATA. It resolves no path, reads no file and selects no installation, so a caller
    cannot aim it: the installation id and generation it checks against are the ones the caller must
    already have obtained from the published record.
    """
    if not isinstance(payload, Mapping):
        return False, "the storage result is not a JSON object"
    if payload.get("result") != INCOMPLETE_SAFE:
        return False, f"result is {payload.get('result')!r}, not {INCOMPLETE_SAFE!r}"
    if payload.get("awaiting_composition") is not True:
        return False, ("awaiting_composition is "
                       f"{payload.get('awaiting_composition')!r}, not exactly true")
    operation_id = payload.get("operation_id")
    if not isinstance(operation_id, str) or not _ST_OPERATION_ID.match(operation_id):
        return False, f"operation_id {operation_id!r} is absent or not canonical"
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return False, "the result carries no findings list"
    codes = {f.get("code") for f in findings if isinstance(f, Mapping)}
    if ST_FRESH_SUCCESS_FINDING not in codes:
        return False, (f"the findings are {sorted(c for c in codes if c)}, and none of them is "
                       f"{ST_FRESH_SUCCESS_FINDING!r}")
    if mode != "fresh_install":
        return False, f"mode is {mode!r}; only a fresh install can owe a first administrator"
    candidate = payload.get("candidate")
    if not isinstance(candidate, Mapping):
        return False, "the result composed no candidate, so there is nothing to commit"
    missing = [k for k in ("storage", "inspected_generation", "inspected_installation_id")
               if k not in candidate]
    if missing:
        return False, f"the candidate is missing {', '.join(missing)}"
    if not isinstance(candidate.get("storage"), Mapping):
        return False, "the candidate carries no storage block"
    if candidate.get("inspected_installation_id") != installation_id:
        return False, (f"the candidate inspected installation "
                       f"{candidate.get('inspected_installation_id')!r}, not {installation_id!r}")
    if candidate.get("inspected_generation") != expected_generation:
        return False, (f"the candidate inspected generation "
                       f"{candidate.get('inspected_generation')!r}, not {expected_generation!r}")
    return True, ("a fresh install whose storage succeeded and owes only its first administrator; "
                  f"operation {operation_id} at generation {expected_generation}")


#: C2 (packet 1246-04-04). The ONE finding that makes a candidate-free admin-identity result a
#: genuine already-published no-change rather than a refusal wearing the same result word.
AI_NO_PUBLICATION_FINDING = "no_publication_owed"


def admin_identity_skip_is_genuine(payload) -> tuple[bool, str]:
    """May the installer skip commit/finalize/discard for THIS admin-identity result?

    **The defect this closes, which correction R6 introduced.** `reconcile` returns a candidate-free
    `no_change` for FOUR states besides the published one — `LOCAL_UNUSABLE`, a terminal `UNKNOWN`,
    an inconclusive `UNKNOWN`, and `REJECTED`. All four exit 0. A disposition helper that asked only
    *"is there a candidate?"* answered `skip` for every one of them, and the installer printed
    *"admin_identity already published"* and carried on to a reported-successful install. Before R6
    those same results reached the commit helper and died loudly. The correction traded a loud stop
    for a false success, which is worse than what it replaced.

    So the skip now turns on the POSITIVE evidence that nothing is owed, not on the ABSENCE of a
    candidate. `_publication_owed` emits `no_publication_owed` exactly when it established that the
    manifest already records this identity (or that there is no manifest to record it in); no
    refusal state emits it. Every member below is required:

      * `result` exactly `no_change`;
      * `candidate` exactly null;
      * `awaiting_composition` exactly `False`;
      * `operation_id` absent or null — a skipped operation opened nothing, so it has no id;
      * the findings carry `no_publication_owed`.

    A result that satisfies some but not all of these is a CONTRADICTION and is refused rather than
    resolved: one half is missing and guessing which is a defect either way.

    Returns `(skip, reason)`. On a refusal the reason names the state's own findings, so the
    administrator sees why the identity could not be published rather than a claim that it was.
    """
    if not isinstance(payload, Mapping):
        return False, "the admin-identity result is not a JSON object"
    codes = [f.get("code") for f in payload.get("findings") or []
             if isinstance(f, Mapping)]
    if payload.get("result") != NO_CHANGE:
        return False, f"result is {payload.get('result')!r}, not {NO_CHANGE!r}"
    if payload.get("candidate") is not None:
        return False, "the result composed a candidate, so there is something to commit"
    if payload.get("awaiting_composition") is not False:
        return False, (f"awaiting_composition is {payload.get('awaiting_composition')!r}, "
                       "not exactly false")
    if payload.get("operation_id") is not None:
        return False, (f"the result names operation {payload.get('operation_id')!r}; an operation "
                       "that opened nothing has no id to name")
    if AI_NO_PUBLICATION_FINDING not in codes:
        return False, (f"the identity composed nothing and did not report "
                       f"{AI_NO_PUBLICATION_FINDING!r}; its findings are "
                       f"{sorted(c for c in codes if c)} — this is a refusal, not a published "
                       "identity")
    return True, "the installation record already publishes this machine identity"


#: C1 (packet 1246-04-04). What phase 18 may do, decided from its own storage OBSERVATION.
ST_ROUTE_BOOTSTRAP = "bootstrap"
ST_ROUTE_REPAIR = "repair"
ST_ROUTE_SKIP = "skip"
#: Packet 1246-10-04. A fresh installation over a corpus that already exists and that the
#: installation record does not yet publish.
ST_ROUTE_ADOPT = "adopt"


def storage_route_for_observation(payload, *, mode: str, repair_requested: bool
                                  ) -> tuple[str | None, str]:
    """Which storage verb this invocation may run — or none of them. Both platforms ask this.

    **The defect this closes.** Both installers chose the verb from the repair flag alone, so an
    ordinary update invoked `storage bootstrap` with `mode=forward_update`. `proven_fresh` appends
    `mode_is_fresh_install` for any mode but `fresh_install`, so `bootstrap` returned
    `failed_before_change`, the dispatcher died, and the box was left with every service stopped by
    phase 9. It was worse than "updates are broken": a fresh install that failed at or after phase 15
    re-runs at generation ≠ 1, so the installer's own advice — *re-run to resume* — walked into the
    same wall.

    **The authority is the OBSERVATION, not the shell.** `storage observe` already classifies this
    machine across eleven axes and returns a `state` plus `facts`; recomputing any part of that from
    shell would be a second opinion about a question the provider has already answered properly.
    This function reads the two fields the routing turns on and nothing else:

      * `state` — the classification;
      * `facts.manifest_expectation` — whether the published manifest carries a corpus. That is the
        "valid published StorageBlock" the ruling asks about, established by the provider rather
        than inferred here.

    **`bootstrap` is reachable from exactly one state.** `proven_fresh`, on a `fresh_install`. There
    is no path from a failed anything to a bootstrap, which is what makes "never reinterpret a
    failed bootstrap as an update plan" structural rather than a promise.

    Returns `(route, reason)` with `route` one of `bootstrap` / `repair` / `skip`, or `None` to
    refuse. The reason is returned on both paths so a refusal names the state it saw — a bare `None`
    turns "this exact situation" into "something was wrong".

    It takes only DATA: no path, no file, no installation selection.
    """
    from .storage_identity import MODES, ManifestExpectation, StorageState

    if not isinstance(payload, Mapping):
        return None, "the storage observation is not a JSON object"
    state = payload.get("state")
    known = {s.value for s in StorageState}
    if state not in known:
        return None, f"the observation reports state {state!r}, which this build does not route"
    facts = payload.get("facts")
    if not isinstance(facts, Mapping):
        return None, "the observation carries no facts, so nothing can be routed from it"
    expectation = facts.get("manifest_expectation")
    if expectation not in {e.value for e in ManifestExpectation}:
        return None, f"manifest_expectation is {expectation!r}, which this build does not route"
    if mode not in MODES:
        return None, f"mode {mode!r} is not one this component is invoked in"

    published = expectation == ManifestExpectation.EXPECTS_CORPUS.value

    # THE EXPLICIT OPTION SELECTS `repair`, NEVER `bootstrap` — and never over a machine with no
    # published corpus to repair, because `repair` refuses that itself and a request built to be
    # refused is an installer defect rather than a box condition.
    if repair_requested:
        if not published:
            return None, ("storage-access repair was requested and this installation publishes no "
                          "corpus; there is nothing to repair")
        if state not in (StorageState.EXISTING_CORPUS_ON_DEFAULT.value,
                         StorageState.EXISTING_CORPUS_REACHABLE.value):
            return None, (f"storage-access repair was requested and the observation reports "
                          f"{state!r}; only a reachable or default-credential corpus is repairable")
        return ST_ROUTE_REPAIR, f"explicit storage-access repair over {state!r}"

    # ADOPTION IS ROUTED FROM STORAGE EVIDENCE, NOT FROM THE MODE (developer ruling, 2026-08-09).
    # A retained corpus is neither fresh nor published: it exists, it is initialized, and this
    # installation's record names no storage. That is one situation, and which mode the shell calls
    # the invocation says nothing about it — the manifest's generation reflects admin identity,
    # patch and proxy, so a box that has composed those is "forward_update" while its storage is
    # still unowned. Deciding from the mode sent exactly that box to `repair`, which refuses a
    # corpus the record disowns; measured on winfms2026, 2026-08-09, at generation 12.
    #
    # `no_expectation`, NOT `not published` — an UNREADABLE record is also "not publishing", and a
    # record that exists and cannot be read consistently refuses rather than being adopted over.
    # (Caught by the exhaustive route control, which reached `adopt` from `unreadable`.)
    #
    # Placed AFTER explicit repair, so `-RepairStorageAccess` still selects repair and never lands
    # here, and BEFORE the mode split, so both ordinary modes reach it and neither reaches it from
    # any other state. `bootstrap` remains reachable from `proven_fresh` + `fresh_install` alone.
    if state == StorageState.EXISTING_CORPUS_ON_DEFAULT.value \
            and expectation == ManifestExpectation.NO_EXPECTATION.value \
            and mode in ("fresh_install", "forward_update"):
        return ST_ROUTE_ADOPT, ("an existing corpus answers on its default credential and this "
                                "installation publishes none")

    if mode == "fresh_install":
        if state != StorageState.PROVEN_FRESH.value:
            return None, (f"a fresh install requires a proven-fresh machine and the observation "
                          f"reports {state!r}; refusing to bootstrap over it")
        return ST_ROUTE_BOOTSTRAP, "a proven-fresh machine on a fresh install"

    # FORWARD UPDATE. Two states are ordinary; everything else refuses BEFORE any storage mutation.
    if state == StorageState.EXISTING_CORPUS_REACHABLE.value:
        if not published:
            return None, ("the corpus is reachable and the installation record does not publish it; "
                          "refusing to update over a record that does not know its own storage")
        return ST_ROUTE_SKIP, "the published corpus is reachable and needs nothing"
    if state == StorageState.EXISTING_CORPUS_ON_DEFAULT.value:
        if not published:
            return None, ("the corpus answers on its default credential and the installation record "
                          "does not publish it; refusing to repair a corpus this record disowns")
        return ST_ROUTE_REPAIR, "the published corpus answers on its default credential"
    return None, (f"the observation reports {state!r}; this update has no route for it and will not "
                  "guess one")


def _st_emit(payload: dict[str, Any]) -> None:
    """The ONE place a storage result is printed, through the secret fence."""
    from .secret_guard import assert_no_secrets

    assert_no_secrets(payload, what="the storage result")
    print(json.dumps(payload, indent=2, sort_keys=True))


def _st_refusal(code: str, detail: str, *, result: str = FAILED_BEFORE_CHANGE) -> dict:
    return {"state": None, "result": result, "operation_id": None, "next_action": detail,
            "facts": None, "findings": [{"code": code, "detail": detail}],
            "awaiting_composition": False, "unresolved_operation": None, "candidate": None}


#: One code per result word, TOTAL over the vocabulary — never a `.get(..., 3)` default.
_ST_EXIT_CODES: dict[str, int] = {
    COMPLETED: 0,
    NO_CHANGE: 0,
    FAILED_BEFORE_CHANGE: 1,
    ROLLED_BACK: 2,
    MANUAL_ACTION_REQUIRED: 3,
    INCOMPLETE_SAFE: 5,
}
_ST_BAD_REQUEST = 4


def _st_inputs(raw: dict):
    from .storage_identity import StorageInputs

    return StorageInputs(
        installation_id=str(raw["installation_id"]),
        expected_generation=int(raw["expected_generation"]),
        install_dir=Path(raw["install_dir"]),
        fms_root=Path(raw["fms_root"]),
        fms_database_dir=Path(raw["fms_database_dir"]),
        secrets_dir=Path(raw["secrets_dir"]),
        host=str(raw["host"]),
        mode=str(raw["mode"]),
        actor=str(raw["actor"]),
    )


def _storage_identity(args, *, engine=None, adapter=None, lifecycle=None) -> int:
    """`observe` and `plan` mutate nothing. Every other verb MUTATES, under the lock."""
    from .storage_identity import StorageIdentityError

    verb = args.storage_verb
    try:
        raw = _st_read_request(args.request, verb)
    except _RequestRefused as exc:
        _st_emit(_st_refusal("request_refused", str(exc)))
        return _ST_BAD_REQUEST

    ops = engine if engine is not None else _st_engine()
    layout = lifecycle if lifecycle is not None else platform_layout()
    journal = Journal(layout)

    # A recovery verb's request carries no `mode` and no paths; it needs neither inputs nor an
    # adapter here, because both come from the operation record and the fixed layout.
    recovery = verb in ("finalize", "abort")
    try:
        inputs = None if recovery else _st_inputs(raw)
    except StorageIdentityError as exc:
        _st_emit(_st_refusal("inputs_refused", str(exc)))
        return _ST_BAD_REQUEST

    try:
        api = adapter if adapter is not None else (None if recovery else _st_adapter(inputs))
        if verb == "observe":
            report = ops.observe(inputs, adapter=api, lifecycle_layout=layout, journal=journal)
        elif verb == "plan":
            from . import storage_identity as si

            facts = ops.collect_facts(inputs, adapter=api, lifecycle_layout=layout)
            planned = si.plan(facts, inputs)
            _st_emit({"state": planned.state, "result": NO_CHANGE, "operation_id": None,
                      "next_action": planned.next_action, "facts": facts.to_dict(),
                      "findings": [f.to_dict() for f in planned.findings],
                      "awaiting_composition": False, "unresolved_operation": None,
                      "candidate": None,
                      "changes": [c.to_dict() for c in planned.changes]})
            return _ST_EXIT_CODES[NO_CHANGE]
        elif verb == "bootstrap":
            with LifecycleLock(layout) as lock:
                report = ops.bootstrap(inputs, adapter=api, lock=lock, journal=journal,
                                       lifecycle_layout=layout)
        elif verb == "adopt":
            with LifecycleLock(layout) as lock:
                report = ops.adopt(inputs, adapter=api, lock=lock, journal=journal,
                                   lifecycle_layout=layout)
        elif verb == "repair":
            with LifecycleLock(layout) as lock:
                report = ops.repair(inputs, adapter=api, lock=lock, journal=journal,
                                    lifecycle_layout=layout)
        elif verb == "resume":
            with LifecycleLock(layout) as lock:
                report = ops.resume(inputs, str(raw["operation_id"]), adapter=api, lock=lock,
                                    journal=journal, lifecycle_layout=layout)
        elif verb == "create-first-admin":
            with LifecycleLock(layout) as lock:
                report = ops.create_first_admin(
                    inputs, str(raw["admin_username"]), str(raw["admin_credential_input"]),
                    adapter=api, lock=lock, journal=journal, lifecycle_layout=layout)
        elif verb == "finalize":
            with LifecycleLock(layout) as lock:
                report = ops.finalize(
                    str(raw["operation_id"]), str(raw["installation_id"]),
                    int(raw["committed_generation"]), str(raw["actor"]),
                    lock=lock, journal=journal, lifecycle_layout=layout)
        else:
            with LifecycleLock(layout) as lock:
                report = ops.abort(
                    str(raw["operation_id"]), str(raw["installation_id"]), str(raw["actor"]),
                    lock=lock, journal=journal, lifecycle_layout=layout)
    except LifecycleError as exc:
        _st_emit(_st_refusal(type(exc).__name__, str(exc)))
        return 1
    except Exception as exc:                     # noqa: BLE001
        # A traceback is not a result, and `failed_before_change` would be a claim this cannot
        # support: an arbitrary exception mid-operation cannot prove nothing was touched. Staged
        # material, the journal record and the operation record are LEFT IN PLACE for `abort`.
        _st_emit(_st_refusal(
            type(exc).__name__,
            f"the storage operation did not complete: {type(exc).__name__}",
            result=MANUAL_ACTION_REQUIRED))
        return _ST_EXIT_CODES[MANUAL_ACTION_REQUIRED]

    _st_emit(report.payload())
    return _ST_EXIT_CODES[report.result]


def _st_adapter(inputs):
    from . import storage_identity_adapter

    return storage_identity_adapter.build_adapter(inputs)


def _st_engine():
    from . import storage_identity_ops

    return storage_identity_ops



# ── packet 1246-04: the installer composition root ───────────────────────────

_CO_SCHEMA_VERSION = 1

#: OPTIONAL keys, and the reason this table exists at all rather than widening the required set
#: above. The ownership facts of packet 1246-09 are things the INSTALLER observed about its own run
#: — whether it created the service account, which helpers it wrote, where it put the CLI shim — and
#: the shipped installers belong to CLOSED children that this packet may not edit. Making them
#: required would abort every current install at the foundation phase. An installer that supplies
#: none publishes an EMPTY ownership table, which is the honest record of "nothing was claimed",
#: never a licence for the uninstaller to go looking.
#:
#: Unknown keys are still refused. Optional does not mean unvalidated.
_CO_OPTIONAL_KEYS: dict[str, frozenset[str]] = {
    "foundation": frozenset({"created_service_account", "privilege_helpers", "cli_shim",
                              "support_dir", "uninstaller_path", "version", "commit",
                              "installer_entry_point"}),
    "publish-installer": frozenset({"installer_entry_point"}),
}


_CO_REQUEST_KEYS: dict[str, frozenset[str]] = {
    # A foundation takes the installer's CLASSIFIED, VALIDATED facts and nothing else. No
    # `web_prefix`, no `port` — those are constants. No `expected_generation` — a foundation is by
    # definition 0 -> 1.
    # `created_service_account`, `privilege_helpers` and `cli_shim` are the FIXED installer-owned
    # resources of packet 1246-09 §O3. They are facts the installer OBSERVED about its own run — it
    # is the only party that knows whether it created the account — and each one is optional, so an
    # installer that supplies none publishes an empty ownership table rather than a wrong one.
    "foundation": frozenset({"schema_version", "installation_id", "install_dir",
                             "patch_hosting_dir", "fms_root", "actor", "installer_series",
                             "installer_version", "installer_bundle_protocol",
                             "installer_source"}),
    "publish-installer": frozenset({
        "schema_version", "installation_id", "expected_generation", "install_dir",
        "version", "commit", "installer_series", "installer_version",
        "installer_bundle_protocol", "installer_source", "actor",
    }),
    # A commit joins an operation that already exists. It carries the provider's own identifiers and
    # its secret-free candidate; it cannot select another install_dir or name another field.
    "commit-provider": frozenset({"schema_version", "provider", "operation_id", "installation_id",
                                  "inspected_generation", "candidate", "install_dir", "actor"}),
    # THE BOUNDARY (packet 1246-04 correction A). It retires one provider's journal after that
    # provider's own completion is proven, and it is deliberately the SMALLEST request in this
    # family: it names WHICH record, and nothing that could select a different one. No install_dir
    # (it chooses no installation), no generation (it publishes nothing), no candidate (it writes no
    # block), no credential (it contacts no provider).
    "discard-provider": frozenset({"schema_version", "provider", "operation_id", "installation_id",
                                   "actor"}),
}


def _co_read_request(path: str, verb: str, *, authority_api=None) -> dict:
    """Privileged input, judged on the OPEN DESCRIPTOR, with EXACTLY this verb's key set."""
    from .composition import PROVIDERS

    text = _open_privileged_request(Path(path), authority_api=authority_api)
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise _RequestRefused(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise _RequestRefused("the request must be a JSON object")
    expected = _CO_REQUEST_KEYS[verb]
    optional = _CO_OPTIONAL_KEYS.get(verb, frozenset())
    unknown = set(raw) - expected - optional
    if unknown:
        raise _RequestRefused(
            f"composition {verb} does not accept key(s): {', '.join(sorted(unknown))}")
    missing = expected - set(raw)
    if missing:
        raise _RequestRefused(
            f"composition {verb} is missing key(s): {', '.join(sorted(missing))}")
    if raw["schema_version"] != _CO_SCHEMA_VERSION:
        raise _RequestRefused(
            f"request schema_version {raw['schema_version']!r}; this build accepts "
            f"{_CO_SCHEMA_VERSION}")
    if verb in ("foundation", "publish-installer"):
        subject = "foundation" if verb == "foundation" else "publish-installer"
        version, commit = raw.get("version"), raw.get("commit")
        if (version is None) != (commit is None):
            raise _RequestRefused(f"{subject} version and commit must be supplied together")
        if version is not None:
            if not isinstance(version, str) or re.fullmatch(r"0\.[0-9]+", version) is None:
                raise _RequestRefused(
                    f"{subject} version must be the exact installed 0.<build> version")
            if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
                raise _RequestRefused(
                    f"{subject} commit must be the exact 40-character lowercase Git commit")
        installer_values = (
            raw.get("installer_series"), raw.get("installer_version"),
            raw.get("installer_bundle_protocol"), raw.get("installer_source"),
        )
        try:
            from .schema import InstallerBlock
            InstallerBlock.from_dict({
                "series": installer_values[0], "version": installer_values[1],
                "bundle_protocol": installer_values[2], "source": installer_values[3],
                "entry_point": raw.get("installer_entry_point"),
            })
        except Exception as exc:
            raise _RequestRefused(f"{subject} installer identity is invalid: {exc}") from exc
        if verb == "publish-installer":
            generation = raw.get("expected_generation")
            if (not isinstance(generation, int) or isinstance(generation, bool)
                    or generation < 1):
                raise _RequestRefused(
                    "publish-installer expected_generation must be a positive integer")
    if verb == "discard-provider":
        if raw["provider"] not in PROVIDERS:
            raise _RequestRefused(f"provider must be one of {PROVIDERS}, got {raw['provider']!r}")
        for key in ("operation_id", "installation_id"):
            value = raw[key]
            if not isinstance(value, str) or not value.strip():
                raise _RequestRefused(f"{key} must be a non-empty string, got {value!r}")
    if verb == "commit-provider":
        if raw["provider"] not in PROVIDERS:
            raise _RequestRefused(f"provider must be one of {PROVIDERS}, got {raw['provider']!r}")
        gen = raw["inspected_generation"]
        if not isinstance(gen, int) or isinstance(gen, bool) or gen < 1:
            raise _RequestRefused(
                "inspected_generation must be an integer of at least 1: providers run after the "
                "foundation has published generation 1")
        if not isinstance(raw["candidate"], dict):
            raise _RequestRefused("candidate must be a JSON object")
    return raw


def _co_emit(payload: dict[str, Any]) -> None:
    """The ONE place a composition result is printed, through the secret fence."""
    from .secret_guard import assert_no_secrets

    assert_no_secrets(payload, what="the composition result")
    print(json.dumps(payload, indent=2, sort_keys=True))


def _co_refusal(code: str, detail: str, *, result: str = FAILED_BEFORE_CHANGE) -> dict:
    return {"result": result, "operation_id": None, "provider": None,
            "committed_generation": None, "generation": None, "locator_published": False,
            "findings": [{"code": code, "detail": detail}], "next_action": detail}


#: One code per result word, TOTAL over the vocabulary — never a `.get(..., 3)` default.
_CO_EXIT_CODES: dict[str, int] = {
    COMPLETED: 0,
    NO_CHANGE: 0,
    FAILED_BEFORE_CHANGE: 1,
    ROLLED_BACK: 2,
    MANUAL_ACTION_REQUIRED: 3,
    INCOMPLETE_SAFE: 5,
}
_CO_BAD_REQUEST = 4


def _composition(args, *, engine=None, lifecycle=None, os_layout=None, locator_adapter=None) -> int:
    """`foundation` publishes generation 1 and its locator; `commit-provider` publishes one block."""
    from .errors import LifecycleError as _LE

    verb = args.co_verb
    try:
        raw = _co_read_request(args.request, verb)
    except _RequestRefused as exc:
        _co_emit(_co_refusal("request_refused", str(exc)))
        return _CO_BAD_REQUEST

    comp = engine if engine is not None else _co_engine()
    layout = lifecycle if lifecycle is not None else platform_layout()
    journal = Journal(layout)
    osl = os_layout if os_layout is not None else _co_os_layout()

    try:
        with LifecycleLock(layout) as lock:
            if verb == "foundation":
                out = comp.foundation(
                    installation_id=str(raw["installation_id"]),
                    install_dir=Path(raw["install_dir"]),
                    fms_root=Path(raw["fms_root"]),
                    patch_hosting_dir=(Path(raw["patch_hosting_dir"])
                                       if raw["patch_hosting_dir"] else None),
                    created_service_account=bool(raw.get("created_service_account")),
                    privilege_helpers=tuple(raw.get("privilege_helpers") or ()),
                    cli_shim=(str(raw["cli_shim"]) if raw.get("cli_shim") else None),
                    support_dir=(str(raw["support_dir"]) if raw.get("support_dir") else None),
                    uninstaller_path=(str(raw["uninstaller_path"])
                                      if raw.get("uninstaller_path") else None),
                    version=(str(raw["version"]) if raw.get("version") else None),
                    commit=(str(raw["commit"]) if raw.get("commit") else None),
                    installer_series=(str(raw["installer_series"])
                                      if raw.get("installer_series") else None),
                    installer_version=(str(raw["installer_version"])
                                       if raw.get("installer_version") else None),
                    installer_bundle_protocol=(int(raw["installer_bundle_protocol"])
                                               if raw.get("installer_bundle_protocol") else None),
                    installer_source=(str(raw["installer_source"])
                                      if raw.get("installer_source") else None),
                    installer_entry_point=(
                        str(raw["installer_entry_point"])
                        if raw.get("installer_entry_point") else None
                    ),
                    lock=lock, journal=journal, lifecycle_layout=layout, os_layout=osl,
                    locator_adapter=locator_adapter)
                payload = {"result": out.result, "operation_id": out.operation_id,
                           "provider": None, "committed_generation": None,
                           "generation": out.generation,
                           "locator_published": out.locator_published,
                           "uninstaller_path": out.uninstaller_path,
                           "installer_entry_point": out.installer_entry_point,
                           "installation_id": out.installation_id, "resumed": out.resumed,
                           "findings": [],
                           "next_action": "The installation record is published."}
            elif verb == "publish-installer":
                out = comp.publish_installer_identity(
                    installation_id=str(raw["installation_id"]),
                    expected_generation=int(raw["expected_generation"]),
                    install_dir=Path(raw["install_dir"]), version=str(raw["version"]),
                    commit=str(raw["commit"]),
                    installer_series=str(raw["installer_series"]),
                    installer_version=str(raw["installer_version"]),
                    installer_bundle_protocol=int(raw["installer_bundle_protocol"]),
                    installer_source=str(raw["installer_source"]),
                    installer_entry_point=(
                        str(raw["installer_entry_point"])
                        if raw.get("installer_entry_point") else None
                    ),
                    lock=lock, journal=journal, lifecycle_layout=layout)
                payload = {
                    "result": out.result, "operation_id": out.operation_id, "provider": None,
                    "committed_generation": out.generation, "generation": out.generation,
                    "locator_published": False, "previous_schema": out.previous_schema,
                    "installer_entry_point": out.installer_entry_point,
                    "adopted": out.adopted, "findings": [],
                    "next_action": "The installed installer identity is published.",
                }
            elif verb == "discard-provider":
                # It NEVER contacts a provider, mutates product state or consumes a credential: it
                # reads the journal, cross-checks identity, and either retires a matching resolved
                # record or refuses and leaves it exactly where it was.
                from .composition import discard_provider_journal

                result = discard_provider_journal(
                    journal, lock, operation_id=str(raw["operation_id"]),
                    installation_id=str(raw["installation_id"]),
                    provider=str(raw["provider"]))
                payload = {"result": result, "operation_id": str(raw["operation_id"]),
                           "provider": str(raw["provider"]), "committed_generation": None,
                           "generation": None, "locator_published": False, "findings": [],
                           "next_action": ("The provider journal is retired; the next provider may "
                                           "begin." if result == "completed" else
                                           "There was no journal record to retire.")}
            else:
                out = comp.commit_provider(
                    provider=str(raw["provider"]), operation_id=str(raw["operation_id"]),
                    installation_id=str(raw["installation_id"]),
                    inspected_generation=int(raw["inspected_generation"]),
                    candidate=raw["candidate"], install_dir=Path(raw["install_dir"]),
                    lock=lock, journal=journal, lifecycle_layout=layout)
                payload = {"result": out.result, "operation_id": out.operation_id,
                           "provider": out.provider,
                           "committed_generation": out.committed_generation,
                           "generation": out.committed_generation, "locator_published": False,
                           "already_committed": out.already_committed, "findings": [],
                           "next_action": (
                               f"Committed at generation {out.committed_generation}; call that "
                               "provider's finalize with it." )}
    except _LE as exc:
        _co_emit(_co_refusal(type(exc).__name__, str(exc)))
        return 1
    except Exception as exc:                     # noqa: BLE001
        # A traceback is not a result, and `failed_before_change` would be a claim this cannot
        # support: an arbitrary exception mid-write cannot prove nothing landed.
        _co_emit(_co_refusal(type(exc).__name__,
                             f"the composition did not complete: {type(exc).__name__}",
                             result=MANUAL_ACTION_REQUIRED))
        return _CO_EXIT_CODES[MANUAL_ACTION_REQUIRED]

    _co_emit(payload)
    return _CO_EXIT_CODES[payload["result"]]


def _co_engine():
    from . import composition

    return composition


def _co_os_layout():
    from . import os_layout as _osl

    return _osl.platform_os_layout()


# ── packet 1246-09 stage 5: the uninstall ─────────────────────────────────────
#
# **Two verbs, and the difference is where authority comes from.** `start` observes the box and
# writes down what it is about to do; `resume` reads what was written down and does exactly that.
# Neither accepts a path, a name, a fingerprint, a root or a host, because every one of those is a
# TARGET — and §X's whole finding was that a caller which supplies a target could supply any target.
#
# **SCHEMA 2 (stage 6): a request carries no FACTS either.** `fms_state` and `service_binding` are
# gone. The first was already only half-believed — §AE.1 proved absence locally and overrode every
# other claim — and the second could not be produced by any caller at all: it decides three service
# removals, and nothing on this box computed it. Both are observed now, from the recorded root, the
# platform's fixed service names and `canonical_service_records`. What is left is the installation
# the caller expects to be operating on, an actor for the record, whether `--force` was given, and
# how a credential would be transported IF an operation proves it needs one.

_UN_SCHEMA_VERSION = 2

#: The same canonical form the pending record and the manifest use. It is compared, not displayed.
_UN_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

#: EXACTLY these keys, per verb. `force` is on both because an interrupted forced uninstall is
#: resumed the same way it was started. Not one of them can aim anything or assert anything: the
#: target of every operation comes from the record, and every fact comes from the box.
_UN_COMMON = frozenset({"schema_version", "installation_id", "actor", "force",
                        "credential_transport"})
_UN_REQUEST_KEYS: dict[str, frozenset[str]] = {
    "plan": _UN_COMMON,
    "start": _UN_COMMON,
    "resume": _UN_COMMON,
}

#: How a credential reaches this process if an operation proves it needs one. **Never JSON, never
#: argv, never an environment variable, never a temporary file** — the transports are 1246-04's
#: `CredentialLease.read`, which both current uninstallers get wrong.
#:
#: `none` is the honest default and the FIRST call always uses it: an uninstall that needs no FMS
#: restart never asks for anything, and one that does answers `credential_required` before touching
#: the box, which is the only signal a launcher acts on. `prompt` is then the PREFERRED second call —
#: **the CLI reads the console itself**, so a launcher never encodes, frames or holds credential
#: bytes. `stdin` and `fd:<n>` remain for approved non-interactive callers that already hold a
#: verified administrator, which is how the installers use the same transport today.
_UN_TRANSPORTS = ("none", "stdin", "prompt")


def _un_transport_ok(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return value in _UN_TRANSPORTS or (value.startswith("fd:") and value[3:].isdigit())


def _un_read_request(path: str, verb: str, *, authority_api=None) -> dict:
    """Privileged input, judged on the OPEN DESCRIPTOR, with EXACTLY this verb's key set."""
    text = _open_privileged_request(Path(path), authority_api=authority_api)
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise _RequestRefused(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise _RequestRefused("the request must be a JSON object")
    # **THE VERSION FIRST.** A schema-1 request carries two keys this build retired, and reporting it
    # as *unknown keys* would tell a caller to delete them rather than that it is speaking the wrong
    # version of the request. The version is the answer to both.
    if raw.get("schema_version") != _UN_SCHEMA_VERSION:
        raise _RequestRefused(
            f"request schema_version {raw.get('schema_version')!r}; this build accepts "
            f"{_UN_SCHEMA_VERSION}. Schema 2 removed 'fms_state' and 'service_binding': FileMaker "
            "Server's condition and the service binding are observed from installed evidence and "
            "are no longer a caller's to state")
    expected = _UN_REQUEST_KEYS[verb]
    unknown = set(raw) - expected
    if unknown:
        raise _RequestRefused(
            f"uninstall {verb} does not accept key(s): {', '.join(sorted(unknown))}")
    missing = expected - set(raw)
    if missing:
        raise _RequestRefused(
            f"uninstall {verb} is missing key(s): {', '.join(sorted(missing))}")
    if not isinstance(raw["installation_id"], str) or not _UN_UUID.match(raw["installation_id"]):
        raise _RequestRefused(
            "installation_id must be a canonical lowercase UUID; it is compared against the "
            "locator and the pending record, so a value that cannot match is not an identity")
    if not isinstance(raw["actor"], str) or not raw["actor"]:
        raise _RequestRefused("actor must be a non-empty string")
    if not isinstance(raw["force"], bool):
        raise _RequestRefused("force must be a boolean")
    if not _un_transport_ok(raw["credential_transport"]):
        raise _RequestRefused(
            f"credential_transport must be one of {_UN_TRANSPORTS} or 'fd:<n>'; a credential never "
            "travels in this request")
    return raw


def _un_credential(transport: str):
    """A CALLABLE, or `None`. It is invoked only when a recorded operation has PROVED it needs one.

    §G derives the need *after* observation, and this is that rule as a shape: the proxy removal asks
    the real plan whether an activation restart is required and calls this only then, so an uninstall
    that never reaches such an operation never reads a descriptor and never touches a console.

    **`prompt` is read by THIS process, at this moment.** That is the whole point of it: a launcher
    that never sees the bytes cannot log them, frame them wrongly, leave them in a shell variable or
    put them in an argv. `CredentialLease.read` refuses a prompt on a stream that is not a terminal,
    so an unattended run stops with a reason instead of blocking for ever.
    """
    if transport == "none":
        return None

    def acquire():
        from .admin_identity_ops import CredentialLease

        return CredentialLease.read(transport)

    return acquire


def _un_collaborators(layout, *, credential):
    """The shipped collaborators, every one of them LAZY.

    **It takes no request** (stage 6). It used to, for the two facts the request carried; now that
    every fact is observed, the only thing a request contributes to this object is the credential
    transport — which is passed in already resolved, as a provider.

    Each `build_*` is called at most once, and only by the operation that needs it — so an uninstall
    with no proxy work opens no network client and reads no credential, which is §G's *derive the
    need after observation* expressed as a shape rather than as a convention.

    **`runner=None` is deliberate and is not a gap:** it selects `service_control`'s own
    fixed-argv subprocess execution, which is the real one. **`fms=None` is deliberate too:** the
    storage handler turns it into its own recorded-root absence check, which is the second
    admissible unhosted proof. A builder that cannot construct returns `None`, and the driver turns
    that into a named refusal that RETAINS the operation.
    """
    from .uninstall_resume import Collaborators

    return Collaborators(
        credential=credential,
        build_folders=_un_build_folders, build_fms=_un_build_folders,
        build_admin_api=_un_build_admin_api,
        build_proxy_observe=lambda: _un_build_proxy_observe(layout),
        build_proxy_engine=lambda: _un_build_proxy_engine(layout))


def _un_build_folders():
    """ONE adapter for both the folder slots and the database operations — the same authenticated
    session serves both, and `fms_folders` warns twice that the FMS session pool is small."""
    from . import fms_folders

    return fms_folders.build_adapter()


def _un_build_admin_api():
    from . import admin_identity_adapter

    return admin_identity_adapter.LiveAdminApi()


def _un_build_proxy_observe(layout):
    """Bind inventory to the same agreeing published paths the removal engine consumes.

    ``inventory()`` deliberately refuses to discover an FMS root.  An uninstall request supplies no
    target either, so the root, route and executor are read from the still-published manifest.  The
    dependency relation keeps that manifest until proxy removal has checkpointed.
    """
    from . import proxy_transaction as px

    record = locator_for(layout).read()
    if record is None:
        return None
    manifest = ManifestStore(Path(record.install_dir), layout=layout).read()
    if manifest is None or manifest.installation_id.lower() != record.installation_id.lower():
        return None
    if not manifest.paths.fms_root or not manifest.paths.install_dir:
        return None
    is_windows = layout.locator_file is None
    try:
        script = px.executor_script(is_windows=is_windows,
                                    install_dir=manifest.paths.install_dir)
    except px.ExecutorUnavailable:
        return None
    types = tuple(manifest.proxy_policy)
    return lambda: _px_observations(
        types, prefix=manifest.web.prefix or "/corpusfm",
        install_dir=manifest.paths.install_dir, fms_root=manifest.paths.fms_root,
        script=script)


def _un_build_proxy_engine(layout):
    """The real engine, from the AGREEING PUBLISHED MANIFEST — never from a caller.

    **This is the one place a resume reads the manifest, and it reads it for exactly one thing:**
    where FileMaker Server and this installation are, so a proxy edit can be executed. It derives no
    deletion target and re-plans nothing; every target still comes from the pending record. The
    dependency relation keeps `install_dir` — where the manifest lives — until the proxy work has
    checkpointed, so the manifest is there while it is needed and gone afterwards.
    """
    record = locator_for(layout).read()
    if record is None:
        return None
    manifest = ManifestStore(Path(record.install_dir), layout=layout).read()
    if manifest is None or manifest.installation_id.lower() != record.installation_id.lower():
        return None
    if not manifest.paths.fms_root or not manifest.paths.install_dir:
        return None
    # Removal writes the before-image beside the installed family.  It must name THIS durable
    # uninstall operation: without the id the Windows executor has nowhere to publish evidence,
    # so a crash after its first IIS deletion leaves a pending operation with no restoration
    # authority.  The pending record is already published before this lazy builder is reached.
    from . import uninstall_pending

    pending_record = uninstall_pending.read(layout)
    if pending_record is None or (
            pending_record.installation_id.lower() != record.installation_id.lower()):
        return None
    web = manifest.web
    return _px_engine(prefix=web.prefix or "/corpusfm", port=web.internal_port or 8533,
                      fms_root=manifest.paths.fms_root, install_dir=manifest.paths.install_dir,
                      operation_id=pending_record.operation_id)


#: One code per result word, TOTAL over the vocabulary — never a `.get(..., n)` default.
_UN_EXIT_CODES: dict[str, int] = {
    COMPLETED: 0,
    NO_CHANGE: 0,
    FAILED_BEFORE_CHANGE: 1,
    ROLLED_BACK: 2,
    MANUAL_ACTION_REQUIRED: 3,
    INCOMPLETE_SAFE: 5,
}
_UN_BAD_REQUEST = 4


def _un_emit(payload: dict) -> None:
    """STRICTLY one JSON object on stdout, with the same keys every time.

    Through the same structural secret guard the manifest and the journal use, and it is worth
    saying exactly what that buys: the guard is **structural**, so it refuses a payload that NAMES a
    secret (a `password` key) and it does not read free text. It cannot catch a credential someone
    interpolates into a detail string, and nothing here should be read as claiming it does. What it
    closes is the route by which a future field called `password` or `token` becomes report output
    — on the one verb in this file that handles an FMS administrator credential.
    """
    from .secret_guard import assert_no_secrets

    assert_no_secrets(payload, what="the uninstall report")
    print(json.dumps(payload, indent=2, sort_keys=True))


def _un_refusal(reason: str, detail: str, result: str = FAILED_BEFORE_CHANGE) -> dict:
    from .uninstall_resume import Report

    return Report(result=result, reason=reason, detail=detail).to_dict()


def _un_runtime(args, *, stager=None) -> int:
    """`uninstall runtime` — stage this process's own interpreter outside its installation.

    **It takes no lock and publishes nothing**, because it changes nothing about the installation:
    it reads where this process is running from and copies it. A caller that ran it and then did
    nothing has left the box exactly as it was, minus a temporary directory it created itself.

    One JSON object either way, like every other verb here, so a launcher reads the answer the same
    way it reads a result. A refusal is exit 1 — nothing was staged and nothing was touched — and the
    launcher stops there rather than beginning an uninstall it now knows cannot finish.
    """
    from . import uninstall_runtime

    engine = stager if stager is not None else uninstall_runtime
    try:
        print(json.dumps(engine.stage(args.destination), indent=2, sort_keys=True))
    except LifecycleError as exc:
        print(json.dumps({"result": "refused", "reason": type(exc).__name__, "detail": str(exc)},
                         indent=2, sort_keys=True))
        return 1
    return 0


def _uninstall(args, *, lifecycle=None, driver=None, collaborators=None, terminal_cleaner=None) -> int:
    """`start` and `resume`. Both MUTATE, both under the lock, both for the whole invocation.

    (`runtime` is the third verb and is none of those things — it stages a copy of this process's own
    interpreter and changes nothing — so it is dispatched away before any of this applies.)

    **ONE exception boundary, around everything that can fail**: collaborator construction, lock
    acquisition, observation, publication, dispatch, checkpointing and the tail. Every ordinary
    exception leaves exactly one JSON object on stdout and a code from the total map — never a
    traceback, never empty output. `KeyboardInterrupt` and `SystemExit` are not ordinary exceptions
    and are not caught: an operator interrupting an uninstall wants it to stop, not to be told a
    story about what it thinks happened.

    **The word depends on how far the invocation got, and that is measured rather than guessed.**
    `Progress` records the two events that make a change durable — the pending publication and each
    checkpoint — so a failure before either is `failed_before_change` however late it looks, and one
    after either is `incomplete_safe`. An exception that is not a `LifecycleError` says nothing
    about how far it got, so it is `manual_action_required`: the honest word for *a human should
    look*.
    """
    from .errors import LockUnavailable
    from .layout import POSIX, platform_layout
    from .lock import LifecycleLock
    from .uninstall_resume import Progress, ResumeRefused

    verb = args.un_verb
    if verb == "runtime":
        return _un_runtime(args)
    try:
        raw = _un_read_request(args.request, verb)
    except _RequestRefused as exc:
        _un_emit(_un_refusal("request_refused", str(exc)))
        return _UN_BAD_REQUEST

    engine = driver
    if engine is None:
        from . import uninstall_resume as engine                          # noqa: PLC0415
    layout = lifecycle if lifecycle is not None else platform_layout()
    if verb == "plan":
        parties = collaborators if collaborators is not None else _un_collaborators(
            layout, credential=None)
        try:
            payload = engine.preview(
                layout, collaborators=parties, installation_id=raw["installation_id"],
                force=raw["force"])
        except ResumeRefused as exc:
            _un_emit(_un_refusal(exc.reason, exc.detail))
            return _UN_EXIT_CODES[FAILED_BEFORE_CHANGE]
        except Exception as exc:                                          # noqa: BLE001
            _un_emit(_un_refusal(type(exc).__name__, str(exc)))
            return _UN_EXIT_CODES[FAILED_BEFORE_CHANGE]
        finally:
            parties.wipe()
        _un_emit(payload)
        return 0
    posix_service_uid = None
    if layout.kind == POSIX:
        try:
            import pwd
            posix_service_uid = pwd.getpwnam("corpusfm").pw_uid
        except KeyError:
            pass
    progress = Progress()
    parties = None
    try:
        parties = collaborators if collaborators is not None else _un_collaborators(
            layout, credential=_un_credential(raw["credential_transport"]))
        # ONE lock, held for the WHOLE invocation — publication, execution, checkpointing and the
        # finalization tail. Two operations interleaving over one pending record is how a resource
        # already removed reappears as still owed.
        with LifecycleLock(layout) as lock:
            entry = engine.start if verb == "start" else engine.resume
            report = entry(layout, lock=lock, collaborators=parties,
                           installation_id=raw["installation_id"], force=raw["force"],
                           progress=progress)
        # The fixed product containers hold the lock and journal, so they cannot be removed by an
        # ordinary pending operation.  A finalized report proves all recorded work and the entire
        # control plane are gone; outside the lock, the lifecycle retires those now-empty-or-stale
        # containers itself.  No path comes from the launcher.
        if report.finalized:
            cleaner = terminal_cleaner
            if cleaner is None:
                from .os_layout import os_layout_for_lifecycle
                from .uninstall_terminal import retire
                cleaner = retire
                machine_layout = os_layout_for_lifecycle(layout)
                removed = cleaner(layout, machine_layout,
                                  posix_service_uid=posix_service_uid)
            else:
                machine_layout = None
                removed = cleaner(layout, machine_layout)
            if removed:
                report = dataclasses.replace(
                    report,
                    detail=report.detail + "; fixed product-data containers are gone")
    except ResumeRefused as exc:
        # Authority could not be established: nothing was written and nothing was touched.
        _un_emit(_un_refusal(exc.reason, exc.detail))
        return _UN_EXIT_CODES[FAILED_BEFORE_CHANGE]
    except LockUnavailable as exc:
        _un_emit(_un_refusal("lock_unavailable", str(exc)))
        return _UN_EXIT_CODES[FAILED_BEFORE_CHANGE]
    except TerminalCleanupRefused as exc:
        # Product and lifecycle records are already gone at this boundary. Calling that
        # `incomplete_safe` would promise a resume through an installation which no longer exists;
        # this is the narrow honest state: inspect/remove the named fixed residue.
        _un_emit(_un_refusal(type(exc).__name__, str(exc), result=MANUAL_ACTION_REQUIRED))
        return _UN_EXIT_CODES[MANUAL_ACTION_REQUIRED]
    except LifecycleError as exc:
        word = INCOMPLETE_SAFE if progress.mutated else FAILED_BEFORE_CHANGE
        _un_emit(_un_refusal(type(exc).__name__, str(exc), result=word))
        return _UN_EXIT_CODES[word]
    except Exception as exc:                                              # noqa: BLE001
        # Not a lifecycle refusal and not a lock: this says nothing about how far the invocation
        # got. The pending record and the journal are exactly where they were left, and a human
        # decides. `manual_action_required` is the word for that; `incomplete_safe` would promise a
        # resume nobody has established is safe.
        _un_emit(_un_refusal(type(exc).__name__, str(exc), result=MANUAL_ACTION_REQUIRED))
        return _UN_EXIT_CODES[MANUAL_ACTION_REQUIRED]
    finally:
        if parties is not None:
            parties.wipe()

    _un_emit(report.to_dict())
    return _UN_EXIT_CODES[report.result]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="corpusfm-lifecycle",
        description=(
            "Read CORPUSfm machine-lifecycle state. status, validate, propose and "
            "result-vocabulary never mutate; patch-compartment apply and rollback DO mutate."
        ),
    )
    sub = parser.add_subparsers(dest="verb", required=True)

    p_status = sub.add_parser("status", help="report locator, manifest and journal state")
    p_status.add_argument("--json", action="store_true")

    p_validate = sub.add_parser("validate", help="validate a manifest file without installing it")
    p_validate.add_argument("path")
    p_validate.add_argument("--json", action="store_true")

    p_propose = sub.add_parser("propose", help="propose a manifest for an existing installation")
    p_propose.add_argument("--install-dir", required=True)
    p_propose.add_argument("--marker", default=None, help="path to an existing install.yaml")
    p_propose.add_argument("--patch-hosting-dir", default=None)
    p_propose.add_argument("--fms-root", default=None)
    p_propose.add_argument("--json", action="store_true")

    p_vocab = sub.add_parser("result-vocabulary", help="print the six lifecycle result words")
    p_vocab.add_argument("--json", action="store_true")

    p_compartment = sub.add_parser(
        "patch-compartment",
        help="inspect, apply or roll back the FMS Additional Database Folder compartment",
    )
    pc_sub = p_compartment.add_subparsers(dest="pc_verb", required=True)
    pc_inspect = pc_sub.add_parser("inspect", help="read-only; mutates nothing")
    pc_inspect.add_argument("--request", required=True)
    pc_inspect.add_argument("--mode", default="fresh_install", choices=LIFECYCLE_MODES)
    pc_inspect.add_argument("--sandbox", default="none",
                            choices=[d.value for d in _sandbox_decisions()])
    pc_apply = pc_sub.add_parser("apply", help="MUTATES: create, register, seed and prove")
    pc_apply.add_argument("--request", required=True)
    # The journal's mode vocabulary is 1246-01's and has no compartment entry. Taking the caller's
    # real mode is honest; inventing a schema value here would edit another packet's surface.
    pc_apply.add_argument("--mode", default="fresh_install", choices=LIFECYCLE_MODES)
    pc_apply.add_argument("--sandbox", default="none",
                          choices=[d.value for d in _sandbox_decisions()])
    pc_rollback = pc_sub.add_parser("rollback", help="MUTATES: restore a recorded operation")
    pc_rollback.add_argument("--operation-id", required=True, dest="operation_id")

    # THE INTEGRATOR SURFACE. Every verb takes a root-owned request because 1246-04 must plan and
    # act before a manifest exists, so it supplies its own proposed web facts.
    p_proxy = sub.add_parser(
        "proxy", help="INTEGRATOR: compose, finalize or abort a proxy-policy operation")
    px_sub = p_proxy.add_subparsers(dest="px_verb", required=True)
    for verb, helptext in (
        ("status", "read-only; mutates nothing"),
        ("reconcile", "MUTATES: compose a candidate (disposition composed_candidate)"),
        ("finalize", "retire a composed candidate's evidence after the manifest agrees"),
        ("abort", "MUTATES: restore every change a composed candidate made"),
        ("retire", "MUTATES: retire artifacts for one resolved proxy operation"),
    ):
        px_verb = px_sub.add_parser(verb, help=helptext)
        px_verb.add_argument("--request", required=True)

    # THE PUBLIC SURFACE. It has NO --request and NO --disposition to accept, and no finalize,
    # abort or rollback verb — recovery is something the tool does to become usable again, never
    # something the administrator drives (1246-06 §8.1, §9.5).
    p_public = sub.add_parser(
        "proxy-public", help="what the corpusfm-proxy administrator wrapper calls")
    pub_sub = p_public.add_subparsers(dest="px_verb", required=True)
    for verb in _PX_PUBLIC_VERBS:
        pub_verb = pub_sub.add_parser(verb)
        pub_verb.add_argument("selector", nargs="?", default=None,
                              help="a supported proxy type, or 'all'")
        pub_verb.add_argument("--json", action="store_true")

    # THE ADMIN-API MACHINE IDENTITY (packet 1246-07). Every verb takes a privileged request:
    # `observe` runs before a manifest exists, so the integrator supplies the facts it has verified.
    p_ident = sub.add_parser(
        "admin-identity", help="observe or reconcile the FMS Admin-API machine identity")
    ai_sub = p_ident.add_subparsers(dest="ai_verb", required=True)
    for verb, helptext in (
        ("observe", "read-only; mutates nothing and asks for nothing"),
        ("reconcile", "MUTATES: provision or replace the exact registration"),
        ("remove", "MUTATES: remove the exact recorded registration, then the local material"),
        ("finalize", "retire a composed candidate's evidence after the manifest agrees"),
        ("abort", "MUTATES: restore what a composed candidate changed"),
    ):
        ai_verb = ai_sub.add_parser(verb, help=helptext)
        ai_verb.add_argument("--request", required=True)

    # THE STORAGE IDENTITY (packet 1246-08). `observe`/`plan` mutate nothing; the rest MUTATE under
    # the lock. `resume` is the ONLY verb that continues an operation — a new bootstrap or repair
    # refuses over an open one rather than quietly picking it up.
    p_storage = sub.add_parser(
        "storage", help="observe, provision or repair this installation's storage identity")
    st_sub = p_storage.add_subparsers(dest="storage_verb", required=True)
    for verb, helptext in (
        ("observe", "read-only; mutates nothing and asks for nothing"),
        ("plan", "read-only; show what a mutating verb would do"),
        ("bootstrap", "MUTATES: provision a proven-fresh corpus"),
        ("adopt", "MUTATES: compose an existing corpus this installation does not yet publish"),
        ("repair", "MUTATES: rotate the automation credential off its default"),
        ("resume", "MUTATES: continue the recorded storage operation"),
        ("create-first-admin", "MUTATES: create the first CORPUSfm administrator"),
        ("finalize", "retire a composed operation's evidence after the manifest agrees"),
        ("abort", "MUTATES: undo what the recorded operation placed"),
    ):
        st_verb = st_sub.add_parser(verb, help=helptext)
        st_verb.add_argument("--request", required=True)

    # THE UNINSTALL (packet 1246-09, stage 5). Two verbs, and the difference between them is where
    # authority comes from — never a caller-selected target.
    p_uninstall = sub.add_parser(
        "uninstall",
        help="MUTATES: remove this installation from what it recorded about itself, resumably")
    un_sub = p_uninstall.add_subparsers(dest="un_verb", required=True)
    for verb, helptext in (
        ("plan", "READ ONLY: observe and report the removal plan without publishing it"),
        ("start", "MUTATES: observe, plan, publish the pending record, and execute"),
        ("resume", "MUTATES: continue an interrupted uninstall from its pending record alone"),
    ):
        un_verb = un_sub.add_parser(verb, help=helptext)
        un_verb.add_argument("--request", required=True)
    # THE SHORT-LIVED RUNTIME (packet 1000-14). Not an uninstall verb in the sense the two above are:
    # it removes nothing, reads no pending record, takes no request and holds no target authority. It
    # copies the interpreter and product code THIS process is running into material the caller has
    # already created and protected, and reports what to run instead. It lives under `uninstall`
    # because the launchers may name exactly one lifecycle module and this is theirs.
    un_runtime = un_sub.add_parser(
        "runtime",
        help="stage this installation's own interpreter outside itself, so the removal can finish")
    un_runtime.add_argument("--destination", required=True)

    # THE KEY FILES (packet 1246-10-03). Privileged, installer-only, and deliberately NOT a verb an
    # administrator drives: the secrets directory is administrator-owned and service-non-writable, so
    # nothing running as the service can establish these — which is exactly the defect that made a
    # fresh install impossible.
    p_keys = sub.add_parser(
        "provision-keys",
        help="INSTALLER: establish this installation's Corpus and Machine keys at the fixed path")
    p_keys.add_argument("--request", required=True)

    # THE COMPOSITION ROOT (packet 1246-04). Two integrator-only verbs; no administrator surface.
    p_comp = sub.add_parser(
        "composition",
        help="INTEGRATOR: publish the installation record, commit one provider, or retire its journal")
    co_sub = p_comp.add_subparsers(dest="co_verb", required=True)
    for verb, helptext in (
        ("foundation", "MUTATES: publish generation 1 and the locator"),
        ("publish-installer", "MUTATES: adopt or advance installer identity within one series"),
        ("commit-provider", "MUTATES: publish exactly one provider's manifest block"),
        ("discard-provider", "MUTATES: retire one provider's RESOLVED journal record"),
    ):
        co_verb = co_sub.add_parser(verb, help=helptext)
        co_verb.add_argument("--request", required=True)

    args = parser.parse_args(argv)

    # Handled BEFORE the shared try: its exit codes are per-verb, and a LifecycleError reaching
    # the generic `return 2` below would be read by a shell as `rolled_back`.
    if args.verb == "patch-compartment":
        return _patch_compartment(args)

    if args.verb == "admin-identity":
        return _admin_identity(args)

    if args.verb == "storage":
        return _storage_identity(args)

    if args.verb == "uninstall":
        return _uninstall(args)

    if args.verb == "composition":
        return _composition(args)

    if args.verb == "provision-keys":
        return _provision_keys(args)

    if args.verb == "proxy":
        return _proxy_integrator(args)

    if args.verb == "proxy-public":
        return _proxy_public(args)

    try:
        if args.verb == "status":
            report = _status()
            print(_render(report, args.json))
            return 0 if _status_is_trustworthy(report) else 1

        if args.verb == "validate":
            with open(args.path, encoding="utf-8") as handle:
                manifest = InstallationManifest.from_dict(json.load(handle))
            print(
                _render(
                    {
                        "manifest": "valid",
                        "installation_id": manifest.installation_id,
                        "generation": manifest.generation,
                    },
                    args.json,
                )
            )
            return 0

        if args.verb == "propose":
            manifest = propose_manifest(
                install_dir=args.install_dir,
                marker_path=args.marker,
                patch_hosting_dir=args.patch_hosting_dir,
                fms_root=args.fms_root,
            )
            print(json.dumps(manifest.to_dict(), indent=2, sort_keys=True))
            return 0

        if args.verb == "result-vocabulary":
            words = sorted(RESULT_VOCABULARY)
            print(json.dumps(words) if args.json else "\n".join(words))
            return 0
    except LifecycleError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    parser.error(f"unknown verb {args.verb!r}")
    return 2
