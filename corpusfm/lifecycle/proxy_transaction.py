"""Planning, dispatch, activation cohorts, the credential lease and the composition handoff.

Packet 1246-06 §6-§9. Shared Python owns policy, planning, cohort partitioning, result derivation,
journaling and dispatch; **each OS-native executor owns its ENTIRE per-type filesystem transaction**.
The split this module refuses to make is the one an earlier draft made and review rejected: a
transaction whose backup lives on one side of a process boundary and whose rollback lives on the
other is not a transaction.

Three separations are load-bearing here, and each replaces a defect that was measured rather than
imagined:

**Publication, validation and activation are three things.** Neither Linux front can validate an
unwritten artifact, so publication necessarily precedes validation — which means a VALIDATION failure
is not an ACTIVATION failure, and must restart nothing. The running service never consumed the
candidate.

**Cohorts are per activation MECHANISM, not per run.** Linux `fms-nginx`/`apache` share one
`fmsadmin restart httpserver`; active Windows Claris nginx uses its own restart cohort; Windows
`iis` is live on publication and is never in one. An inactive front is never activated at all.

**A credential lease is operation-scoped and never persisted.** An in-process rollback reuses it; a
LATER-PROCESS abort cannot, and must obtain a new one. Claiming otherwise would be claiming a secret
outlived the process that held it.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import posixpath
import re
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .proxy_inventory import (
    BLOCK_ABSENT, BLOCK_DRIFTED, BLOCK_INVALID, ProxyObservation,
)
from .proxy_policy import (
    ACTION_NONE, ACTION_PUBLISH, ACTION_REFUSE, ACTION_REMOVE, FMSADMIN_RESTART_MECHANISMS,
    MECH_FMSADMIN_RESTART,
    MECH_CLARIS_ACTIVE, MECH_IIS_PUBLISH, MECH_NONE, PlannedType, PolicyRequest, ProxyPlan,
    candidate_entry, decide, mechanism_for,
)
from .result import (
    COMPLETED, FAILED_BEFORE_CHANGE, INCOMPLETE_SAFE, MANUAL_ACTION_REQUIRED, NO_CHANGE,
    ROLLED_BACK, validate_result,
)
from .schema import PROXY_TYPES

# The two persistence dispositions. EXPLICIT — there is no inferred default for a mutating operation.
COMPOSED_CANDIDATE = "composed_candidate"
DIRECT_COMMIT = "direct_commit"
DISPOSITIONS: tuple[str, ...] = (COMPOSED_CANDIDATE, DIRECT_COMMIT)

# The journal state a composed candidate leaves behind until 1246-04 finalizes or aborts it.
AWAITING_COMPOSITION = "awaiting_composition"

# The two-stage operation (ruling 4). `prepare` captures the before-image and changes NO routing, so
# a crash during preparation leaves evidence and an untouched box — cleanly classifiable. Only once
# the capture is validated and digest-bound does a mutation become permissible.
PHASE_PREPARING = "preparing"
PHASE_PREPARED = "prepared"
PHASE_MUTATED = "mutated"
PHASES: tuple[str, ...] = (PHASE_PREPARING, PHASE_PREPARED, PHASE_MUTATED, AWAITING_COMPOSITION)

POSIX = "posix"
WINDOWS = "windows"
FLAVOURS: tuple[str, ...] = (POSIX, WINDOWS)

# `credential_input` transport values. A MODE or an FD — never a value.
CREDENTIAL_ABSENT = "absent"
CREDENTIAL_PROMPT = "prompt"
CREDENTIAL_STDIN = "stdin"
CREDENTIAL_FD_PREFIX = "fd:"


class ProxyRefused(Exception):
    """A pre-mutation refusal. Nothing was published, activated or recorded."""


class CredentialUnavailable(ProxyRefused):
    """A required credential was missing or malformed. Distinguished so recovery can say so."""


# ── the credential lease ──────────────────────────────────────────────────────────────────────


class CredentialLease:
    """Two length-prefixed UTF-8 fields, read ONCE, held to an operation's terminal point.

    **Held, not re-read.** §6.3's restoration restart is a SECOND `fmsadmin` invocation; a credential
    scoped to one invocation would make every activation failure unrecoverable.

    **Never persisted.** Not to the journal, the manifest, the recovery record, a log, an environment
    variable or a request file. That is why a later-process abort must obtain a NEW lease rather than
    find this one.

    **It IS placed, unavoidably, in the argv of the `fmsadmin` child.** `fmsadmin` has no documented
    stdin or file password path (`installer/SPEC.md:388-395`), and that brief `ps`-visible exposure is
    already accepted and minimized project-wide. This class does not pretend to remove it; it bounds
    it to that one child and wipes afterwards.
    """

    __slots__ = ("_user", "_password", "_wiped")

    def __init__(self, user: str, password: str):
        self._user = user
        self._password = password
        self._wiped = False

    @property
    def wiped(self) -> bool:
        return self._wiped

    def use(self, fn: Callable[[str, str], Any]) -> Any:
        """Hand the values to exactly one call. Never returns them to a caller."""
        if self._wiped:
            raise CredentialUnavailable("this credential lease has already been wiped")
        return fn(self._user, self._password)

    def wipe(self) -> None:
        self._user = ""
        self._password = ""
        self._wiped = True

    # No __repr__/__str__ leak: the defaults would print the instance, never the fields, but the
    # fields are named here explicitly so a future dataclass conversion cannot quietly change that.
    def __repr__(self) -> str:                      # pragma: no cover - trivial
        return f"<CredentialLease wiped={self._wiped}>"


def read_credential_frame(source) -> CredentialLease:
    """Exactly two length-prefixed UTF-8 fields, user then password, followed by EOF.

    An EOF or short read before both fields complete is a **refusal**, not an empty credential. That
    distinction is the whole point: an empty password silently attempted against FMS is worse than a
    clean failure, because it looks like a credential problem at the server rather than a truncated
    channel here.
    """
    def _exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = source.read(n - len(buf))
            if not chunk:
                raise CredentialUnavailable(
                    "the credential stream ended before both fields were complete")
            buf += chunk
        return buf

    try:
        fields = []
        for _ in range(2):
            raw_len = _exact(4)
            length = int.from_bytes(raw_len, "big")
            if length > 4096:
                raise CredentialUnavailable("credential field length is implausible")
            fields.append(_exact(length).decode("utf-8"))
    except CredentialUnavailable:
        raise
    except Exception as exc:
        raise CredentialUnavailable(f"the credential stream is malformed ({exc})") from exc
    return CredentialLease(fields[0], fields[1])


def open_credential_source(credential_input: str):
    """Resolve the TRANSPORT. It names a mode or an FD; it never carries a value."""
    if credential_input == CREDENTIAL_STDIN:
        import sys

        return sys.stdin.buffer
    if credential_input.startswith(CREDENTIAL_FD_PREFIX):
        try:
            fd = int(credential_input[len(CREDENTIAL_FD_PREFIX):])
        except ValueError as exc:
            raise CredentialUnavailable(f"{credential_input!r} is not a usable FD") from exc
        try:
            return os.fdopen(os.dup(fd), "rb", closefd=True)
        except OSError as exc:
            # A syntactically valid FD that is not open is still a channel this process cannot
            # read. It must arrive as a refusal, not as an OSError escaping to a CLI boundary that
            # is looking for a credential failure.
            raise CredentialUnavailable(
                f"{credential_input!r} is not an open file descriptor in this process") from exc
    raise CredentialUnavailable(f"{credential_input!r} is not a credential transport")


def prompt_for_credential(prompter=None) -> CredentialLease:
    """The interactive path: a secure, non-echoing prompt, read at the moment of use."""
    import getpass
    import sys

    def console_prompt():
        # Keep stdout as the one-result JSON channel consumed by installed launchers.
        print("FMS admin user: ", end="", file=sys.stderr, flush=True)
        return input(), getpass.getpass("FMS admin password: ")

    ask = prompter or console_prompt
    user, password = ask()
    if not user or not password:
        raise CredentialUnavailable("no FMS admin credential was supplied")
    return CredentialLease(user, password)


# ── the transaction ───────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TypeOutcome:
    """One type's outcome. Per-type results never collapse into a run-level verdict (§6.3)."""

    proxy_type: str
    action: str
    mechanism: str
    result: str
    published: bool = False
    activated: bool = False
    health_checked: bool = False
    restored: bool = False
    fingerprint: str | None = None
    config_location: str | None = None
    backup_reference: str | None = None
    detail: str = ""
    operator_steps: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecoveryRecord:
    """Evidence a composed candidate leaves behind. **Carries NO credential — a FLAG, not a value.**

    It also carries the PATHS and the EXECUTOR IDENTITY this operation used (rulings 1 and 6),
    because a later abort runs *before* any manifest exists — the integrator's whole point — and so
    has nothing else to read them from. Re-discovering them would be a guess about the machine at a
    moment when the machine is already half-changed.
    """

    operation_id: str
    installation_id: str
    expected_generation: int
    disposition: str
    restoration_restart_may_be_required: bool
    per_type: tuple[Mapping[str, Any], ...]
    # The candidate `proxy_policy` block this operation would publish. Recorded because §9.2 and
    # §9.5 both ask the SAME question of a later process — "does the published manifest exactly
    # match what this operation composed?" — and a process that did not compose it has no other way
    # to know. It is policy, not routing content, and carries no secret.
    candidates: Mapping[str, Any] = field(default_factory=dict)
    # ── the authority facts, all REQUIRED for an executable operation (ruling 5) ──
    # They are optional in the dataclass only so a caller can build one field at a time; the reader
    # requires every one of them for any phase past `preparing`, because an operation missing any
    # of them is not one a later process could execute a restoration for.
    flavour: str | None = None                 # "posix" | "windows" — whose path syntax to parse
    install_dir: str | None = None
    fms_root: str | None = None
    web_prefix: str | None = None
    web_internal_port: int | None = None
    # The EXACT executor this operation ran, and its digest. Recovery refuses if either changed: a
    # replaced helper is not the helper that made the change, and rolling back through it would be
    # running unknown code with root authority over FMS configuration.
    executor_path: str | None = None
    executor_digest: str | None = None
    # Per proxy type, `{"path": ..., "sha256": ...}` — the operation-bound before-image the executor
    # captured, BOUND BY DIGEST (ruling 4). A path alone binds nothing: the file it names can be
    # replaced between the write and the restoration, and the earlier field's own comment claimed a
    # digest it did not store.
    evidence: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    # Where in the two-stage operation this record was written (ruling 4).
    phase: str = "preparing"

    def to_dict(self) -> dict:
        return {
            "operation_id": self.operation_id,
            "installation_id": self.installation_id,
            "expected_generation": self.expected_generation,
            "disposition": self.disposition,
            "restoration_restart_may_be_required": self.restoration_restart_may_be_required,
            "per_type": [dict(x) for x in self.per_type],
            "candidates": {k: dict(v) for k, v in self.candidates.items()},
            "flavour": self.flavour,
            "install_dir": self.install_dir,
            "fms_root": self.fms_root,
            "web_prefix": self.web_prefix,
            "web_internal_port": self.web_internal_port,
            "executor_path": self.executor_path,
            "executor_digest": self.executor_digest,
            "evidence": {k: dict(v) for k, v in self.evidence.items()},
            "phase": self.phase,
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "RecoveryRecord":
        """STRICT (ruling 6). Exact key set, real types, validated vocabularies. **No coercion.**

        The previous version ran every field through `str()`, `int()` or `bool()`, which accepts
        anything: `bool("false")` is `True`, `int(True)` is `1`, and `str({...})` turns a hostile
        object into a plausible-looking identifier. This record decides whether a restoration runs
        and against which installation, so a value it cannot read as the right type is a refusal,
        not something to convert.
        """
        _exact_keys(raw, {
            "operation_id", "installation_id", "expected_generation", "disposition",
            "restoration_restart_may_be_required", "per_type", "candidates", "flavour",
            "install_dir", "fms_root", "web_prefix", "web_internal_port", "executor_path",
            "executor_digest", "evidence", "phase",
        }, "the recovery record")

        flavour = _one_of(raw["flavour"], FLAVOURS, "flavour")
        phase = _one_of(raw["phase"], PHASES, "phase")
        record = RecoveryRecord(
            operation_id=_uuid(raw["operation_id"], "operation_id"),
            installation_id=_uuid(raw["installation_id"], "installation_id"),
            expected_generation=_nonneg_int(raw["expected_generation"], "expected_generation"),
            disposition=_one_of(raw["disposition"], DISPOSITIONS, "disposition"),
            restoration_restart_may_be_required=_real_bool(
                raw["restoration_restart_may_be_required"], "restoration_restart_may_be_required"),
            per_type=tuple(_per_type_entry(x, i, flavour) for i, x in
                           enumerate(_a_list(raw["per_type"], "per_type"))),
            candidates=_candidates(raw["candidates"]),
            flavour=flavour,
            # OPTIONAL AT THE FIELD LEVEL, REQUIRED BY PHASE. Phase one exists precisely so a crash
            # before the facts are established is representable; `_assert_relations` is where every
            # later phase is made to bind them.
            install_dir=_opt(raw["install_dir"], "install_dir", flavour),
            fms_root=_opt(raw["fms_root"], "fms_root", flavour),
            web_prefix=(None if raw["web_prefix"] is None else _web_prefix(raw["web_prefix"])),
            web_internal_port=(None if raw["web_internal_port"] is None
                               else _port(raw["web_internal_port"])),
            executor_path=_opt(raw["executor_path"], "executor_path", flavour),
            executor_digest=_opt_digest(raw["executor_digest"], "executor_digest"),
            evidence=_evidence(raw["evidence"], flavour),
            phase=phase,
        )
        _assert_relations(record)
        return record


# ── the strict readers `from_dict` is built from ──────────────────────────────
# Separate named functions rather than inline checks, so each rule is testable on its own and so a
# future field cannot be added without choosing one. The same shape `patch_compartment` uses.

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _exact_keys(raw: Any, expected: set, what: str) -> None:
    if not isinstance(raw, dict):
        raise RecoveryEvidenceInvalid(f"{what} is not an object")
    missing = expected - set(raw)
    if missing:
        raise RecoveryEvidenceInvalid(f"{what} is missing {', '.join(sorted(missing))}")
    unknown = set(raw) - expected
    if unknown:
        raise RecoveryEvidenceInvalid(
            f"{what} carries unknown field(s): {', '.join(sorted(unknown))}")


def _real_bool(value: Any, what: str) -> bool:
    """A real bool. `bool("false")` is True, and this one decides whether a credential is needed."""
    if value is not True and value is not False:
        raise RecoveryEvidenceInvalid(f"{what} must be true or false, got {value!r}")
    return value


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise RecoveryEvidenceInvalid(f"{what} must be a non-empty string, got {value!r}")
    return value


def _uuid(value: Any, what: str) -> str:
    """The CANONICAL lowercase hyphenated form. Three spellings of one UUID compare unequal, and
    identity comparison is what decides whether a record is evidence about this operation."""
    text = _text(value, what)
    if not _UUID_RE.match(text):
        raise RecoveryEvidenceInvalid(
            f"{what} must be a canonical lowercase hyphenated UUID, got {text!r}")
    return text


def _nonneg_int(value: Any, what: str) -> int:
    """A real int. `int(True)` is 1 and `bool` is a subclass of `int`, so the type is checked."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RecoveryEvidenceInvalid(f"{what} must be a non-negative integer, got {value!r}")
    return value


def _one_of(value: Any, allowed: Sequence[str], what: str) -> str:
    if value not in allowed:
        raise RecoveryEvidenceInvalid(f"{what} must be one of {tuple(allowed)}, got {value!r}")
    return value


def _a_list(value: Any, what: str) -> list:
    if not isinstance(value, (list, tuple)):
        raise RecoveryEvidenceInvalid(f"{what} must be a list, got {type(value).__name__}")
    return list(value)


def _abs(value: Any, what: str, flavour: str) -> str:
    r"""An absolute, canonical path in the RECORDED PLATFORM'S syntax (ruling 5).

    **Not the host's.** `os.path` on a POSIX box reads `C:\CORPUSfm` as a relative path and
    `/opt/x` as absolute on Windows — so parsing a Windows record with the host's rules either
    refuses a correct path or accepts a nonsensical one. A restoration decides where to write from
    this value; whose syntax it is in is not a detail.
    """
    text = _text(value, what)
    module = ntpath if flavour == WINDOWS else posixpath
    if not module.isabs(text):
        raise RecoveryEvidenceInvalid(f"{what} must be an absolute {flavour} path, got {text!r}")
    if text != module.normpath(text):
        raise RecoveryEvidenceInvalid(
            f"{what} must be canonical (no '.', '..' or duplicate separators), got {text!r}")
    return text


def _opt(value: Any, what: str, flavour: str) -> str | None:
    """An absolute canonical path, or None. `None` is legal only where the phase rules allow it."""
    return None if value is None else _abs(value, what, flavour)


def _within_root(candidate: str, root: str, flavour: str) -> bool:
    """Canonical containment in the recorded platform's syntax. `startswith` would accept a sibling
    directory whose name merely begins with the root's."""
    module = ntpath if flavour == WINDOWS else posixpath
    root = module.normpath(root)
    candidate = module.normpath(candidate)
    if flavour == WINDOWS:
        root, candidate = root.lower(), candidate.lower()
    return candidate == root or candidate.startswith(root.rstrip("\\/") + module.sep)


def _web_prefix(value: Any) -> str:
    text = _text(value, "web_prefix")
    if not text.startswith("/"):
        raise RecoveryEvidenceInvalid(f"web_prefix must start with '/', got {text!r}")
    return text


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise RecoveryEvidenceInvalid(f"web_internal_port must be a TCP port, got {value!r}")
    return value


def _opt_digest(value: Any, what: str) -> str | None:
    if value is None:
        return None
    text = _text(value, what)
    if not _SHA256_RE.match(text):
        raise RecoveryEvidenceInvalid(f"{what} must be a lowercase SHA-256 hex digest, got {text!r}")
    return text


def _per_type_entry(raw: Any, index: int, flavour: str) -> dict:
    what = f"per_type[{index}]"
    _exact_keys(raw, {"proxy_type", "action", "mechanism", "published", "activated",
                      "backup_reference"}, what)
    from .proxy_policy import MECHANISMS, PLAN_ACTIONS
    from .schema import PROXY_TYPES

    published = _real_bool(raw["published"], f"{what}.published")
    activated = _real_bool(raw["activated"], f"{what}.activated")
    backup = raw["backup_reference"]
    # Packet 1275 compatibility, deliberately one-way. Windows PowerShell reports an absent
    # optional string as ``""``; 0.2477 copied that value into one retained record for an IIS
    # outcome that published and activated nothing. Accept only that exact harmless legacy shape
    # so a corrected package can recover the operation. Every new record writes ``null`` below,
    # and an empty reference attached to a claimed mutation remains invalid.
    if backup == "" and not published and not activated:
        backup = None
    entry = {
        "proxy_type": _one_of(raw["proxy_type"], PROXY_TYPES, f"{what}.proxy_type"),
        "action": _one_of(raw["action"], PLAN_ACTIONS, f"{what}.action"),
        "mechanism": _one_of(raw["mechanism"], MECHANISMS, f"{what}.mechanism"),
        "published": published,
        "activated": activated,
        "backup_reference": (None if backup is None else
                             _abs(backup, f"{what}.backup_reference", flavour)),
    }
    # ACTIVATED IMPLIES PUBLISHED. A type nothing wrote cannot have been activated, and a record
    # claiming otherwise describes an operation that never happened — which a restoration would
    # then act on.
    if entry["activated"] and not entry["published"]:
        raise RecoveryEvidenceInvalid(
            f"{what} claims it was activated but never published; that operation did not happen")
    return entry


def _evidence(raw: Any, flavour: str) -> dict:
    """`{proxy_type: {"path": ..., "sha256": ...}}` — bound BY DIGEST (ruling 4).

    A path alone binds nothing: the file it names can be replaced between the capture and the
    restoration, and the previous field's own comment claimed a digest it did not store.
    """
    from .schema import PROXY_TYPES

    if not isinstance(raw, dict):
        raise RecoveryEvidenceInvalid("evidence must be an object")
    out = {}
    for name, binding in raw.items():
        if name not in PROXY_TYPES:
            raise RecoveryEvidenceInvalid(f"evidence names an unsupported type {name!r}")
        what = f"evidence[{name!r}]"
        _exact_keys(binding, {"path", "sha256"}, what)
        out[name] = {
            "path": _abs(binding["path"], f"{what}.path", flavour),
            "sha256": _digest(binding["sha256"], f"{what}.sha256"),
        }
    return out


def _digest(value: Any, what: str) -> str:
    text = _text(value, what)
    if not _SHA256_RE.match(text):
        raise RecoveryEvidenceInvalid(f"{what} must be a lowercase SHA-256 hex digest, got {text!r}")
    return text


def _assert_relations(record: "RecoveryRecord") -> None:
    """The cross-field rules. A record can be field-by-field valid and still describe nothing real.

    Every one of these was reachable: an operation past `preparing` with no executor bound, two
    entries for one type, an evidence file outside the installation it claims to belong to, a
    candidate for a type the operation never touched, or a restart flag disagreeing with the
    per-type evidence that decides whether a credential is needed.
    """
    if record.phase != PHASE_PREPARING:
        for name in ("install_dir", "fms_root", "web_prefix", "web_internal_port", "executor_path",
                     "executor_digest"):
            if getattr(record, name) in (None, ""):
                raise RecoveryEvidenceInvalid(
                    f"a record in phase {record.phase!r} must bind {name}; without it a later "
                    f"process cannot execute this operation's restoration")

    if record.executor_path and record.install_dir:
        module = ntpath if record.flavour == WINDOWS else posixpath
        expected = module.join(record.install_dir, "bin")
        if module.dirname(record.executor_path) != expected:
            raise RecoveryEvidenceInvalid(
                f"executor_path must be the installed sibling under {expected}, got "
                f"{record.executor_path!r}")

    seen = [e["proxy_type"] for e in record.per_type]
    if len(seen) != len(set(seen)):
        raise RecoveryEvidenceInvalid(f"per_type names a proxy type twice: {sorted(seen)}")

    for name in record.candidates:
        if seen and name not in seen:
            raise RecoveryEvidenceInvalid(
                f"candidates names {name!r}, which this operation's per_type never touched")

    for name, binding in record.evidence.items():
        if record.install_dir and not _within_root(binding["path"], record.install_dir,
                                                   record.flavour):
            raise RecoveryEvidenceInvalid(
                f"evidence[{name!r}] lies outside this installation at {binding['path']!r}")
        if record.operation_id not in binding["path"]:
            raise RecoveryEvidenceInvalid(
                f"evidence[{name!r}] is not named for this operation; a fixed-name before-image "
                f"cannot say which operation it describes")

    needs = any(e["mechanism"] in FMSADMIN_RESTART_MECHANISMS and e["published"]
                for e in record.per_type)
    if record.per_type and record.restoration_restart_may_be_required != needs:
        raise RecoveryEvidenceInvalid(
            "restoration_restart_may_be_required disagrees with the per-type evidence; that flag "
            "decides whether an abort must obtain a credential")


def _candidates(raw: Any) -> dict:
    """Every candidate must be a legal `ProxyPolicyEntry` for a supported type — validated through
    the schema's own reader, because `finalize` compares these against the published manifest and a
    shape the manifest could never hold can never match."""
    from .schema import PROXY_TYPES, ProxyPolicyEntry

    if not isinstance(raw, dict):
        raise RecoveryEvidenceInvalid("candidates must be an object")
    out = {}
    for name, entry in raw.items():
        if name not in PROXY_TYPES:
            raise RecoveryEvidenceInvalid(f"candidates names an unsupported type {name!r}")
        try:
            out[name] = dict(ProxyPolicyEntry.from_dict(entry, proxy_type=name).to_dict())
        except Exception as exc:
            raise RecoveryEvidenceInvalid(f"candidates[{name!r}] is not a valid entry: {exc}") from exc
    return out


@dataclass(frozen=True)
class ProxyRunResult:
    """What a run returns. `composed_candidate` additionally leaves §9.1's evidence open."""

    operation_id: str
    installation_id: str
    expected_generation: int
    disposition: str
    outcomes: tuple[TypeOutcome, ...]
    candidates: Mapping[str, Any] = field(default_factory=dict)
    recovery_record: RecoveryRecord | None = None
    result: str = NO_CHANGE
    activation_required: tuple[str, ...] = ()
    credentials_required: bool = False


def derive_run_result(outcomes: Sequence[TypeOutcome]) -> str:
    """The run's word, DERIVED from the per-type words. Never invented, never flattening.

    **An inactive success is not turned into a rollback because an unrelated active front failed.**
    That is the specific mistake this function exists to prevent, so the precedence is written as an
    ordered list rather than a chain of conditionals nobody can audit.
    """
    words = [o.result for o in outcomes]
    if not words:
        return NO_CHANGE
    for dominant in (MANUAL_ACTION_REQUIRED, FAILED_BEFORE_CHANGE, INCOMPLETE_SAFE, ROLLED_BACK):
        if dominant in words:
            return dominant
    if COMPLETED in words:
        return COMPLETED
    return NO_CHANGE


def partition_cohorts(plan: ProxyPlan) -> dict[str, tuple[PlannedType, ...]]:
    """Group the MUTATING types by activation mechanism (§6.2).

    Unchanged, absent and ignored types are absent from every cohort by construction — they are not
    in `plan.mutating` — which is what makes "a changed inactive type is never in a rollback cohort"
    a property of the data rather than a rule someone must remember.
    """
    cohorts: dict[str, list[PlannedType]] = {m: [] for m in
                                             (MECH_FMSADMIN_RESTART, MECH_IIS_PUBLISH, MECH_NONE)}
    for planned in plan.mutating:
        cohorts.setdefault(planned.mechanism, []).append(planned)
    return {k: tuple(v) for k, v in cohorts.items()}


@dataclass
class ExecutorCall:
    """One dispatch to an OS-native executor. Recorded so a test can assert what was invoked."""

    verb: str
    proxy_type: str
    payload: dict


class ProxyEngine:
    """Dispatch, cohorts, activation and result derivation.

    The executor and the activator are injected. That is not a testing convenience: the executor is
    an OS-native process and the activator is the only thing in this component that touches
    `fmsadmin`, so keeping both behind one seam is what lets every rule above be exercised without a
    FileMaker Server — and what keeps the credential's blast radius to a single call site.
    """

    def __init__(self, *, executor, activator=None, health_check=None):
        self.executor = executor
        self.activator = activator
        self.health_check = health_check
        self.calls: list[ExecutorCall] = []
        # Which fronts are ACTIVE, learned from the plan the engine is given — never re-derived and
        # never guessed. A rollback needs it after the plan has been consumed (packet 1252): restoring
        # an active front's bytes without saying so leaves the running server on the configuration it
        # already loaded.
        self._active_fronts: set[str] = set()

    def set_active_fronts(self, proxy_types) -> None:
        """Bind independently-observed active fronts for execution or later recovery."""
        self._active_fronts = set(proxy_types)
        bind = getattr(self.executor, "set_active_fronts", None)
        if callable(bind):
            bind(self._active_fronts)

    def preflight_inactive(self, plan: ProxyPlan) -> ProxyPlan:
        """Do not mutate an inactive front whose existing FMS baseline cannot validate.

        An installed-but-inactive front is optional topology, not part of the route currently
        serving CORPUSfm.  Publishing into a baseline that FMS itself cannot validate would turn an
        unrelated dormant-front defect (for example, Apache naming an absent ``server.pem`` while
        nginx is live) into an installer failure.  Validate it read-only first and leave it exactly
        alone when it is already unusable.  Active fronts deliberately never take this path: their
        candidate still has to publish and validate strictly before activation.
        """
        revised: list[PlannedType] = []
        for planned in plan.types:
            if planned.action != ACTION_PUBLISH or planned.mechanism != MECH_NONE:
                revised.append(planned)
                continue
            self.calls.append(ExecutorCall("validate", planned.proxy_type, {}))
            report = self.executor("validate", planned.proxy_type, None)
            if report.get("ok"):
                revised.append(planned)
                continue
            detail = (report.get("detail") or "the existing configuration did not validate").strip()
            revised.append(replace(
                planned, action=ACTION_NONE,
                reason=(f"inactive {planned.proxy_type} front left unchanged because its existing "
                        f"FileMaker Server configuration does not validate: {detail}"),
                operator_steps=(
                    f"Repair the existing {planned.proxy_type} FileMaker Server configuration if "
                    "you intend to activate that front.",
                    "Re-run the CORPUSfm installer afterward to publish its route there.",
                ),
            ))
        types = tuple(revised)
        return ProxyPlan(
            types=types,
            credentials_required=any(
                item.action in (ACTION_PUBLISH, ACTION_REMOVE)
                and item.mechanism in FMSADMIN_RESTART_MECHANISMS
                for item in types
            ),
            refusals=tuple(item for item in types if item.action == ACTION_REFUSE),
        )

    # -- per-type: publish + validate/stage; activation is cohort-owned. ------------------------
    def _publish_and_validate(self, planned: PlannedType,
                              obs: ProxyObservation) -> TypeOutcome:
        # ACTIVE Claris takes the executor's explicit verbs. They stage the exact family and retain
        # the before-image; this engine's fmsadmin cohort owns activation and restorative restart.
        removing = planned.action == ACTION_REMOVE
        if planned.mechanism == MECH_CLARIS_ACTIVE:
            verb = "remove-active" if removing else "publish-active"
        else:
            verb = "remove" if removing else "publish"
        self.calls.append(ExecutorCall(verb, planned.proxy_type, {"desired": planned.desired}))
        # The desired fingerprint travels WITH the dispatch. The real executor ignores it — it
        # computes its own readback, which is the point of comparing them — but a stand-in that had
        # no way to know what a correct executor would return could only ever be wrong or be
        # exempted, and exempting it would retire the check.
        report = self.executor(verb, planned.proxy_type, planned.desired)
        ok = bool(report.get("ok"))
        if not ok:
            # A publication OR VALIDATION failure. The running service never consumed the candidate,
            # so NOTHING is activated or restarted here — only the bytes are put back.
            restored = bool(report.get("restored"))
            verified = bool(report.get("restore_verified"))
            return TypeOutcome(
                proxy_type=planned.proxy_type, action=planned.action, mechanism=planned.mechanism,
                result=(ROLLED_BACK if (restored and verified) else MANUAL_ACTION_REQUIRED),
                published=False, restored=restored,
                backup_reference=report.get("backup"),
                detail=report.get("detail", ""),
            )
        seen = report.get("fingerprint")
        if planned.action == ACTION_PUBLISH and planned.desired and seen != planned.desired:
            # THE READBACK DISAGREES WITH THE PLAN (ruling 3). What is now on disk is not what this
            # installation was supposed to have — so it must not become the new stored authority,
            # and the bytes go back. Publishing the mismatch would record somebody else's state as
            # ours and make the next reconcile call the box current.
            restored, detail = self.restore(planned.proxy_type)
            return TypeOutcome(
                proxy_type=planned.proxy_type, action=planned.action,
                mechanism=planned.mechanism,
                result=(ROLLED_BACK if restored else MANUAL_ACTION_REQUIRED),
                published=False, restored=restored, backup_reference=report.get("backup"),
                detail=("the published artifact family does not match the intended rendering; "
                        + detail),
            )
        if (planned.proxy_type == "iis" and planned.action == ACTION_PUBLISH
                and not report.get("config_location")):
            # A fresh IIS observation is ABSENT and therefore cannot name a location. Publication
            # is the first authority that can report where the family landed. Without that half,
            # the manifest can reconcile by fingerprint but an uninstall cannot prove what to
            # remove. Treat the missing read-back as a validation failure and restore it.
            restored, detail = self.restore(planned.proxy_type)
            return TypeOutcome(
                proxy_type=planned.proxy_type, action=planned.action,
                mechanism=planned.mechanism,
                result=(ROLLED_BACK if restored else MANUAL_ACTION_REQUIRED),
                published=False, restored=restored, backup_reference=report.get("backup"),
                detail=("the published IIS family did not report its configuration location; "
                        + detail),
            )
        return TypeOutcome(
            proxy_type=planned.proxy_type, action=planned.action, mechanism=planned.mechanism,
            result=COMPLETED, published=True,
            activated=False, fingerprint=seen,
            config_location=report.get("config_location"),
            backup_reference=report.get("backup"), detail=report.get("detail", ""),
        )

    def restore(self, proxy_type: str) -> tuple[bool, str]:
        """Put the previous bytes back — and, on an ACTIVE front, get them SERVED again.

        The active-front evidence travels with the restore (packet 1252). Without it the executor
        restores the file and leaves the running nginx serving the configuration it already loaded,
        so a rollback would be byte-exact on disk and invisible to every client — the failure mode a
        rollback exists to prevent. The evidence is the same observation the plan used; the
        application still issues no reload of its own.
        """
        active = proxy_type in self._active_fronts
        self.calls.append(ExecutorCall("restore", proxy_type, {"claris_nginx_active": active}))
        report = self.executor("restore", proxy_type, None)
        return bool(report.get("ok")) and bool(report.get("restore_verified")), \
            report.get("detail", "")

    def run(self, plan: ProxyPlan, observations, *, lease: CredentialLease | None = None,
            ) -> tuple[TypeOutcome, ...]:
        """Execute a plan: per-type publication/validation, then per-mechanism activation."""
        self.set_active_fronts(p.proxy_type for p in plan.types
                               if p.mechanism == MECH_CLARIS_ACTIVE)
        by_type = {o.proxy_type: o for o in observations}
        outcomes: dict[str, TypeOutcome] = {}

        for planned in plan.types:
            if planned.action == ACTION_REFUSE:
                outcomes[planned.proxy_type] = TypeOutcome(
                    proxy_type=planned.proxy_type, action=ACTION_REFUSE,
                    mechanism=planned.mechanism, result=FAILED_BEFORE_CHANGE,
                    detail=planned.reason, operator_steps=planned.operator_steps)
                continue
            if planned.action == ACTION_NONE:
                outcomes[planned.proxy_type] = TypeOutcome(
                    proxy_type=planned.proxy_type, action=ACTION_NONE,
                    mechanism=planned.mechanism, result=NO_CHANGE, detail=planned.reason,
                    operator_steps=planned.operator_steps)
                continue
            outcomes[planned.proxy_type] = self._publish_and_validate(
                planned, by_type[planned.proxy_type])

        cohorts = partition_cohorts(plan)

        # Windows IIS: PUBLICATION IS ACTIVATION, and it is verified by the fingerprint, not by an
        # application probe (developer ruling, 2026-08-09). `_publish_and_validate` has already read
        # the family back and compared it to the exact desired rendering; a family that matches IS
        # the live route, because on IIS there is nothing further to activate and no FMS restart.
        #
        # It used to call `real_health_check` here, and that probe cannot answer this question at
        # phase 17. Measured on winfms2026, 2026-08-09, in two independent ways. First, the 502
        # exception the Linux path relies on is unreachable: a closed loopback port on Windows
        # TIMES OUT rather than refusing, so `real_upstream_listening` answers `None`, and `None is
        # False` correctly withholds the exception. Second, and worse, `/corpusfm` answers 301 then
        # 502 on that box with ZERO CORPUSfm applications registered - the FMS front returns it for
        # that path either way - so a 502 there would not have proved the route existed even if the
        # upstream check had answered. The probe was therefore rolling back families it had just
        # proved correct, for an upstream that cannot start until phase 21.
        #
        # Runtime health is not abandoned; it MOVES to where an upstream exists. The installer's
        # phase-21 gates are the verification: both services Running, loopback login, the proxied
        # route through IIS/FMS, MCP refusing unauthenticated access, retained storage readable, and
        # no journal left behind. A failure there still refuses the installation.
        for planned in cohorts.get(MECH_IIS_PUBLISH, ()):
            out = outcomes[planned.proxy_type]
            if not out.published:
                continue
            outcomes[planned.proxy_type] = replace(
                out, activated=True, health_checked=False,
                detail=(out.detail + "; runtime health is deferred to the installer's post-start "
                        "verification, where an upstream exists to answer").lstrip("; "))

        # One restart per mechanism cohort. Active Windows Claris and active Linux fronts use the
        # same authenticated fmsadmin operation, but remain separate cohorts because their durable
        # mechanism names are distinct.
        for mechanism in FMSADMIN_RESTART_MECHANISMS:
            cohort = tuple(p for p in cohorts.get(mechanism, ())
                           if outcomes[p.proxy_type].published)
            if cohort:
                outcomes = self._activate_fms_cohort(cohort, outcomes, lease)

        # Inactive changes are COMPLETE at validation and were never in a cohort.
        for planned in cohorts.get(MECH_NONE, ()):
            out = outcomes[planned.proxy_type]
            if out.published:
                outcomes[planned.proxy_type] = replace(
                    out, detail=(out.detail + " (configured and validated; activation is the "
                                             "administrator's)").strip())

        return tuple(outcomes[t.proxy_type] for t in plan.types)

    def _activate_fms_cohort(self, cohort, outcomes, lease):
        if lease is None:
            # Refuse BEFORE restarting anything. Nothing is half-activated.
            for planned in cohort:
                out = outcomes[planned.proxy_type]
                outcomes[planned.proxy_type] = replace(
                    out, result=MANUAL_ACTION_REQUIRED,
                    detail="published and validated, but no FMS admin credential was available to "
                           "activate it; the previous configuration is still serving")
            return outcomes

        ok = self.activate(lease)
        healthy = self.health("fms-web") if ok else False
        if ok and healthy:
            for planned in cohort:
                outcomes[planned.proxy_type] = replace(
                    outcomes[planned.proxy_type], activated=True, health_checked=True)
            return outcomes

        # The shared activation failed: restore EVERY type in THIS cohort, then ONE restoration
        # restart. Types outside the cohort keep their results — an inactive success is not undone
        # because an unrelated active front failed.
        restored_all = True
        for planned in cohort:
            good, detail = self.restore(planned.proxy_type)
            restored_all = restored_all and good
            outcomes[planned.proxy_type] = replace(
                outcomes[planned.proxy_type], restored=good, detail=detail)

        back_ok = self.activate(lease) if restored_all else False
        back_healthy = self.health("fms-web") if back_ok else False
        verdict = ROLLED_BACK if (restored_all and back_ok and back_healthy) \
            else MANUAL_ACTION_REQUIRED
        for planned in cohort:
            outcomes[planned.proxy_type] = replace(
                outcomes[planned.proxy_type], result=verdict, activated=False, health_checked=True)
        return outcomes

    def activate(self, lease: CredentialLease) -> bool:
        if self.activator is None:
            return False
        self.calls.append(ExecutorCall("activate", "fms-web", {}))
        return bool(lease.use(self.activator))

    def health(self, what: str) -> bool:
        if self.health_check is None:
            return True
        self.calls.append(ExecutorCall("health", what, {}))
        return bool(self.health_check(what))


def totally_rolled_back(record) -> bool:
    """Is this recovery record a COMPLETED, total, verified rollback with nothing left live?

    A run that rolled every mutating front back published nothing, activated nothing, and owes no
    restoration restart — so there is no live routing the manifest has yet to describe, and nothing
    for `finalize` or `abort` to do. Leaving it `needs_recovery` described work that did not exist,
    and on Windows it produced a state no shipped verb could retire.

    Deliberately NARROW, and every clause is load-bearing. A manual-action or incomplete restoration
    is not this. An activated or published front is not this — the routing may be live. An owed
    restart is not this — the box is not yet where the record says. And at least one front must
    actually have rolled back, so a run that merely observed cannot slip through as "resolved".
    """
    if record.phase != PHASE_MUTATED:
        return False
    if record.restoration_restart_may_be_required:
        return False
    for entry in record.per_type or ():
        if entry.get("published") or entry.get("activated"):
            return False
    words = {(candidate or {}).get("last_result")
             for candidate in (record.candidates or {}).values()}
    if words & {MANUAL_ACTION_REQUIRED, INCOMPLETE_SAFE, COMPLETED}:
        return False
    return ROLLED_BACK in words


def build_run_result(*, plan: ProxyPlan, outcomes: Sequence[TypeOutcome], observations,
                     authority: OperationAuthority,
                     stored: Mapping[str, str | None] | None = None,
                     evidence: Mapping[str, Mapping[str, str]] | None = None) -> ProxyRunResult:
    """Assemble the structured result, including the candidates and the recovery record.

    `stored` is the manifest's existing `config_fingerprint` per type — required so a run that
    publishes nothing carries the previous value forward instead of recording what it saw
    (ruling 4). `authority` carries the same facts the INTENT record already bound, so the outcome
    record refines rather than introduces them (ruling 1).
    """
    if authority.disposition not in DISPOSITIONS:
        raise ProxyRefused(
            f"disposition must be one of {', '.join(DISPOSITIONS)} and must be stated explicitly; "
            f"got {authority.disposition!r}"
        )
    by_type = {o.proxy_type: o for o in observations}
    planned_by_type = {p.proxy_type: p for p in plan.types}
    candidates = {}
    for out in outcomes:
        planned = planned_by_type[out.proxy_type]
        if planned.action == ACTION_REFUSE:
            continue                                     # a refusal records NOTHING, not even policy
        candidates[out.proxy_type] = candidate_entry(
            planned, replace(by_type[out.proxy_type],
                             config_location=(out.config_location
                                              if out.published and out.config_location
                                              else by_type[out.proxy_type].config_location)),
            result=validate_result(out.result),
            fingerprint=(out.fingerprint if out.published
                         else _prior_fingerprint((stored or {}).get(out.proxy_type))))
    # The CANONICAL hyphenated form: the journal and the recovery record are correlated by
    # this string, and three spellings of one UUID compare unequal.
    op = authority.operation_id
    needs_restart = any(o.mechanism in FMSADMIN_RESTART_MECHANISMS and o.published
                        for o in outcomes)
    record = RecoveryRecord(
        operation_id=op, installation_id=authority.installation_id,
        expected_generation=authority.expected_generation, disposition=authority.disposition,
        flavour=authority.flavour, install_dir=authority.install_dir, fms_root=authority.fms_root,
        web_prefix=authority.web_prefix, web_internal_port=authority.web_internal_port,
        executor_path=authority.executor_path, executor_digest=authority.executor_digest,
        evidence=dict(evidence or {}), phase=PHASE_MUTATED,
        restoration_restart_may_be_required=needs_restart,
        per_type=tuple({"proxy_type": o.proxy_type, "action": o.action, "mechanism": o.mechanism,
                        "published": o.published, "activated": o.activated,
                        # An executor is a shell-process boundary. PowerShell's absent optional
                        # string arrives as ``""``; the durable schema's absent path is ``null``.
                        # Normalize here instead of persisting a record the reader rejects.
                        "backup_reference": o.backup_reference or None} for o in outcomes),
        candidates={name: entry.to_dict() for name, entry in candidates.items()},
    )
    return ProxyRunResult(
        operation_id=op, installation_id=authority.installation_id,
        expected_generation=authority.expected_generation, disposition=authority.disposition,
        outcomes=tuple(outcomes), candidates=candidates, recovery_record=record,
        result=derive_run_result(outcomes),
        activation_required=tuple(o.proxy_type for o in outcomes
                                  if o.published and not o.activated
                                  and o.mechanism in (MECH_NONE, *FMSADMIN_RESTART_MECHANISMS)),
        credentials_required=plan.credentials_required,
    )


def _prior_fingerprint(stored: str | None) -> str | None:
    """The STORED `config_fingerprint`, carried forward exactly (Codex ruling 4).

    **It used to return the OBSERVED digest**, which laundered operator-edited bytes into stored
    authority: run `corpusfm-proxy ignore` — or any run that published nothing — over a hand-edited
    block, and the edit was recorded as "the last successfully applied rendering". The next
    reconcile then compared against the edit and called the box current. Drift erased itself.

    Observation answers "what is on disk". Stored authority answers "what did WE last apply". Only a
    successful publication may move the second, so when nothing was published the previous value is
    returned untouched — including `None`.
    """
    return stored


# ── the real executor, activator and health check ─────────────────────────────────────────────
#
# These are the only three places this component reaches the machine, and they are together so the
# credential's blast radius is one function long enough to read in full.


class ExecutorUnavailable(ProxyRefused):
    """The OS-native executor could not be resolved to a trustworthy file. A refusal, never a
    fallback — this process is about to hand it root-level authority over FMS configuration."""


def executor_script(*, is_windows: bool, install_dir: Path | str, authority_api=None) -> Path:
    """`<InstallDir>/bin/cfm-proxy-exec.{sh,ps1}` — the installed sibling, and NOTHING else.

    **A published installation never falls back to the development tree (ruling 7).** The first
    version resolved `Path(__file__).parents[2] / "installer"`, which on an installed box under
    site-packages misses both candidates and produces "the proxy executor could not be run" — while
    on a box that happened to have a source checkout it would have executed *that*, with root
    authority, from a tree nobody installed.

    Structure and existence are checked exactly: the lifecycle package lives at `<InstallDir>/lib`,
    so its executor is its sibling at `<InstallDir>/bin`. A missing, misplaced or
    untrusted-writable helper REFUSES before any mutation.
    """
    name = "cfm-proxy-exec.ps1" if is_windows else "cfm-proxy-exec.sh"
    candidate = Path(install_dir) / "bin" / name
    refusal = executor_refusal(candidate, is_windows=is_windows, authority_api=authority_api,
                               install_dir=install_dir)
    if refusal is not None:
        raise ExecutorUnavailable(refusal)
    return candidate


def executor_digest(path: Path | str) -> str:
    """The executor's own SHA-256, bound into the recovery record.

    Recovery refuses when it no longer matches: a replaced helper is not the helper that made the
    change, and rolling back through it would be running unknown code with root authority over
    FileMaker Server's configuration.
    """
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def executor_refusal(path: Path, *, is_windows: bool, authority_api=None,
                     install_dir: Path | str | None = None) -> str | None:
    """Why this file is not acceptable as a privileged executor, or None.

    **REPLACEMENT authority, not just file authority (Codex ruling 7).** A perfectly protected file
    inside a directory somebody else can write is not protected at all: they cannot edit it, they
    simply delete it and put their own there. So the ANCESTRY is checked too — `<InstallDir>/bin`
    and `<InstallDir>` — and on Windows the DACL is actually read rather than waved through, which
    the first version did by returning `None` unconditionally.
    """
    if not path.is_file():
        return (f"{path} does not exist; the proxy executor is installed beside this package at "
                f"<InstallDir>/bin and is never resolved from a source tree")
    if path.is_symlink():
        return f"{path} is a symlink; a privileged executor must be a plain file"

    ancestors = [path.parent]
    if install_dir is not None:
        ancestors.append(Path(install_dir))
    for directory in ancestors:
        if directory.is_symlink():
            return (f"{directory} is a symlink; a privileged executor's directory must not be "
                    f"redirectable")

    if is_windows:
        return _windows_executor_refusal(path, ancestors, authority_api=authority_api)

    info = path.stat()
    refusal = posix_executor_refusal(uid=info.st_uid, mode=info.st_mode,
                                     executable=os.access(str(path), os.X_OK), what=str(path))
    if refusal is not None:
        return refusal
    for directory in ancestors:
        try:
            dir_info = directory.stat()
        except OSError as exc:
            return f"{directory} could not be inspected ({exc.strerror})"
        refusal = posix_directory_refusal(uid=dir_info.st_uid, mode=dir_info.st_mode,
                                          what=str(directory))
        if refusal is not None:
            return refusal
    return None


def _windows_executor_refusal(path: Path, ancestors, *, authority_api=None) -> str | None:
    """NTFS authority for the file AND its replace-capable parents.

    **Evidence label: policy-through-doubles until 1246-10.** The rule below is exercised against an
    injected `WindowsFileAuthorityApi`, exactly as the privileged-request check already is. No real
    DACL has been read by any test, and this packet does not claim one has.
    """
    api = authority_api
    if api is None:                                     # pragma: no cover - platform-specific
        from .protection import real_windows_file_authority

        api = real_windows_file_authority()
    try:
        system_sid = api.system_sid_text()
        allowed = set(api.invoking_owner_sids()) | {system_sid}
    except Exception as exc:
        return f"the invoking Windows identity could not be read ({type(exc).__name__})"

    for target, is_directory in [(path, False)] + [(item, True) for item in ancestors]:
        # BY PATH (ruling 7). `os.open(dir, O_RDONLY)` is a POSIX idiom — on Windows opening a
        # DIRECTORY that way fails, so the descriptor form could never have run against
        # `<InstallDir>/bin`, which is exactly the replacement-capable parent this check is for.
        try:
            authority = api.authority_of_path(str(target))
        except Exception as exc:
            # Fail CLOSED: authority evidence that cannot be read is not authority evidence.
            return f"{target}: its ownership and access could not be read ({type(exc).__name__})"
        refusal = windows_authority_refusal(authority, allowed=allowed, what=str(target),
                                            is_directory=is_directory)
        if refusal is not None:
            return refusal
    return None


def windows_authority_refusal(authority, *, allowed: set, what: str,
                              is_directory: bool | None = None) -> str | None:
    """The Windows half of the rule, as a pure predicate over a `FileAuthority`."""
    if not authority.protected:
        return f"{what} does not carry a protected DACL"
    if authority.inherited:
        return f"{what} inherits access from its parent directory"
    if authority.owner not in allowed:
        return (f"{what} is owned by {authority.owner}, not the invoking administrator or SYSTEM")
    extra = [t for t in authority.trustees if t not in allowed]
    if extra:
        # Older/injected authority readers do not report masks.  Preserve their fail-closed
        # semantics: an unexplained trustee is acceptable only when the real DACL read proves its
        # allowed ACEs are read/traverse-only.  This matters after phase 20, when the two registered
        # services intentionally receive RX on the install root and bin directory.
        if is_directory is None or not authority.grants:
            unsafe = extra
        else:
            from .protection import DIRECTORY_AUTHORITY, FILE_WRITE_AUTHORITY

            forbidden = DIRECTORY_AUTHORITY if is_directory else FILE_WRITE_AUTHORITY
            masks: dict[str, int] = {}
            for trustee, mask in authority.grants:
                masks[trustee] = masks.get(trustee, 0) | mask
            unsafe = [trustee for trustee in extra
                      if trustee not in masks or masks[trustee] & forbidden]
        if unsafe:
            return f"{what} grants write or replacement authority to {', '.join(sorted(unsafe))}"
    return None


def posix_directory_refusal(*, uid: int, mode: int, what: str) -> str | None:
    """A directory somebody else can write is a directory in which our helper can be REPLACED.

    Separate from the file rule because the failure is different: the file's own mode says who may
    edit it, and the directory's says who may swap it out from under us. Only the first was checked,
    which made the second a hole with a guard in front of it.
    """
    import stat as stat_mod

    if uid != 0:
        return f"{what} is not root-owned (uid {uid}), so this executor can be replaced"
    if mode & (stat_mod.S_IWGRP | stat_mod.S_IWOTH):
        return f"{what} is group- or world-writable, so this executor can be replaced"
    return None


def posix_executor_refusal(*, uid: int, mode: int, executable: bool, what: str) -> str | None:
    """The POSIX ownership rule, as a PURE predicate over a stat result.

    Separated because a test cannot create a root-owned file: driven through a real path, the uid
    clause fires first and every clause after it becomes unreachable, so a mutation to the
    group-writable check survived while looking guarded. Given the values directly, each clause has
    its own control.
    """
    import stat as stat_mod

    if uid != 0:
        return f"{what} is not root-owned (uid {uid})"
    if mode & (stat_mod.S_IWGRP | stat_mod.S_IWOTH):
        return f"{what} is group- or world-writable"
    if not executable:
        return f"{what} is not executable"
    return None


def real_executor(*, fms_root: Path | str, prefix: str, port: int, script: Path | str,
                  is_windows: bool = False, runner=None, iis_app_dir: Path | str | None = None,
                  metadata_dir: Path | str | None = None, claris_nginx_active: bool = False,
                  powershell: str = "powershell", render_dir: Path | str | None = None,
                  operation_id: str | None = None, evidence_dir: Path | str | None = None):
    """Dispatch one type's whole filesystem transaction to the OS-native executor.

    It returns the executor's ONE JSON object, unwrapped. A non-JSON or absent answer is a FAILURE
    report, never an empty success: a dispatcher that cannot read its executor's answer knows less
    than nothing about what is on the box.

    **The two executors take their arguments differently and that is not cosmetic.** The shell script
    takes `--fms-root`-style flags; the PowerShell script takes named `-FmsRoot` parameters, and a
    `[switch]` rather than a boolean because PowerShell cannot bind a `[bool]` parameter through
    `-File` at all. Passing one style to the other silently produces a script that ignores every
    argument it was given.
    """
    # THE ENCLOSING FMS ROOT, DERIVED BEFORE ANY RENDER OR DISPATCH (packet 1252). The Windows
    # manifest contract records the Database Server directory; every nginx artifact — FMS's own
    # configuration, CORPUSfm's include beside it — lives under its parent, and the installed
    # executor builds `NginxServer\conf\…` from whatever `-FmsRoot` it is handed. Passing the
    # recorded value through unchanged made the executor look under `…\Database Server\NginxServer`
    # and deny "no FMS nginx configuration at …". Derived here, once, so the include path this
    # module renders and the root the executor receives cannot disagree.
    from .proxy_inventory import fms_installation_root

    fms_root = fms_installation_root(fms_root) or Path(fms_root)

    import subprocess as sp

    run = runner or (lambda argv: sp.run(argv, capture_output=True, text=True, timeout=300))
    # Where the operation-bound before-image is written. Beside the installation, because the
    # lifecycle layer binds its path into the recovery record and requires it to lie under
    # `install_dir` — evidence outside the installation is not this installation's to trust.
    evidence_root = Path(evidence_dir) if evidence_dir else (
        Path(iis_app_dir).parent if iis_app_dir else Path(fms_root))

    # The plan owns the fresh active-front observation.  Keep that evidence mutable so an engine
    # built before uninstall observation can bind the exact fronts its plan subsequently consumes.
    # Capturing only the constructor's default made the installed uninstaller select
    # ``remove-active`` correctly, then omit the executor's required ``-ClarisNginxActive`` switch.
    # ``*`` preserves the existing constructor flag's exact argv behavior for recovery callers;
    # the plan-bound setter below replaces it with the observed per-front set before ordinary run.
    active_fronts = {"*"} if claris_nginx_active else set()

    def call(verb: str, proxy_type: str, desired: str | None = None) -> dict:
        # RENDER ONCE, HERE (ruling 4). The executors never compose their own text: the block they
        # write and the digest planning compared against must be the same bytes, and two renderers
        # drift the moment either is edited.
        rendered = _render_for(proxy_type, prefix=prefix, port=port, fms_root=fms_root,
                               render_dir=render_dir, iis_app_dir=iis_app_dir,
                               metadata_dir=metadata_dir) if verb in ("publish", "publish-active") else {}
        scratch = rendered.pop("_scratch", None)
        try:
            # `finally`, so an exception from the subprocess or an unreadable result sweeps the
            # scratch directory just as a clean return does. Anything else leaves one temp tree per
            # failure, which is the shape that accumulates fastest.
            return _dispatch(verb, proxy_type, rendered)
        finally:
            # RETIRED (ruling 8). A rendered candidate is reproducible from the manifest and is NOT
            # recovery authority — only the executor's own before-image and backups are — so leaving
            # one temp directory per publication behind is litter, not evidence. A caller that needs
            # the artifacts as named evidence passes `render_dir` and keeps them itself.
            if scratch is not None:
                import shutil

                shutil.rmtree(scratch, ignore_errors=True)

    def _dispatch(verb: str, proxy_type: str, rendered: dict) -> dict:
        if is_windows:
            # No -ExecutionPolicy Bypass (packet 1380-02 D20). Same reasoning as the probe seam in
            # proxy_inventory: an installed local executor with no Mark of the Web runs under
            # RemoteSigned, and under AllSigned the deployed publisher leaf is the authority.
            argv = [powershell, "-NoProfile", "-File", str(script),
                    "-Verb", verb, "-Type", proxy_type, "-FmsRoot", str(fms_root),
                    "-Prefix", prefix]
            if iis_app_dir:
                argv += ["-IisAppDir", str(iis_app_dir)]
            if metadata_dir:
                argv += ["-MetadataDir", str(metadata_dir)]
            for flag, key in (("-BlockFile", "block"), ("-IncludeFile", "include"),
                              ("-WebConfigFile", "web_config")):
                if rendered.get(key):
                    argv += [flag, str(rendered[key])]
            if operation_id:
                argv += ["-OperationId", operation_id]
            if "*" in active_fronts or proxy_type in active_fronts:
                argv.append("-ClarisNginxActive")
        else:
            argv = [str(script), verb, proxy_type, "--fms-root", str(fms_root)]
            for flag, key in (("--block-file", "block"), ("--include-file", "include")):
                if rendered.get(key):
                    argv += [flag, str(rendered[key])]
            if operation_id:
                argv += ["--operation-id", operation_id, "--evidence-dir", str(evidence_root)]
        try:
            proc = run(argv)
        except Exception as exc:
            return {"ok": False, "restored": False, "restore_verified": False,
                    "detail": f"the proxy executor could not be run ({type(exc).__name__})"}
        text = (proc.stdout or "").strip().splitlines()
        for line in reversed(text):
            try:
                report = json.loads(line)
            except ValueError:
                continue
            if isinstance(report, dict):
                return report
        return {"ok": False, "restored": False, "restore_verified": False,
                "detail": "the proxy executor emitted no readable result"}

    def set_active_fronts(proxy_types) -> None:
        active_fronts.clear()
        active_fronts.update(proxy_types)

    call.set_active_fronts = set_active_fronts
    return call


def _render_for(proxy_type: str, *, prefix: str, port: int, fms_root, render_dir,
                iis_app_dir=None, metadata_dir=None) -> dict:
    """Write this type's rendered artifacts to files the executor can read.

    Files rather than argv because a `web.config` and an nginx include are multi-line documents and
    an argv vector is not a document channel. They carry no credential — the renderer produces only
    routing text — so the ordinary temp directory is the right place when no `render_dir` is given.
    """
    import tempfile

    from . import proxy_render as render

    scratch = None
    if render_dir:
        base = Path(render_dir)
    else:
        scratch = Path(tempfile.mkdtemp(prefix="cfm-render-"))
        base = scratch
    base.mkdir(parents=True, exist_ok=True)
    out: dict[str, Any] = {"_scratch": scratch}

    if proxy_type == "iis":
        primary = base / "web.config"
        primary.write_text(render.render_web_config(prefix=prefix, port=port), encoding="utf-8")
        out["web_config"] = primary
        # One document per exact metadata vpath, written into the METADATA directory the executor
        # reads, named as it derives the name — so a missing one is a FAILURE there rather than a
        # silently unmounted route here. This one is not scratch: the executor owns that directory.
        meta = Path(metadata_dir) if metadata_dir else base
        meta.mkdir(parents=True, exist_ok=True)
        for route in render.metadata_routes(prefix):
            (meta / f"{render.metadata_slug(route)}.webconfig").write_text(
                render.render_metadata_web_config(route=route, port=port), encoding="utf-8")
        return out

    include_path = None
    if proxy_type in ("fms-nginx", "claris-nginx"):
        include_path = str(Path(fms_root, "NginxServer", "conf", render.INCLUDE_NAME))
        inc = base / render.INCLUDE_NAME
        inc.write_text(render.render_include(prefix=prefix, port=port), encoding="utf-8")
        out["include"] = inc
    block = base / "block.txt"
    block.write_text(render.render_block(proxy_type, prefix=prefix, port=port,
                                         include_path=include_path), encoding="utf-8")
    out["block"] = block
    return out


def redact_argv(argv: Sequence[str]) -> list[str]:
    """Any surfaced command line replaces the value after `-p` with `****` (§7)."""
    out = list(argv)
    for i, token in enumerate(out[:-1]):
        if token == "-p":
            out[i + 1] = "****"
    return out


def real_activator(*, fmsadmin: Path | str, runner=None):
    """The ONE `fmsadmin` call site in this component. Cross-platform, argv only, absolute path.

    The credential reaches `fmsadmin` in that child's argv and there is no alternative channel —
    `installer/SPEC.md:388-395` records this as the project's accepted, minimized exposure. **This
    function does not remove it and must never be described as doing so.** What it does bound: the
    path is the verified absolute one rather than a `PATH` lookup, the invocation is an argv vector
    rather than a shell string (so no history, `-x` trace or `set -o xtrace` can capture it), and no
    diagnostic prints the value — `redact_argv` is applied to anything surfaced.
    """
    import subprocess as sp

    run = runner or (lambda argv: sp.run(argv, capture_output=True, text=True, timeout=300))

    def activate(user: str, password: str) -> bool:
        argv = [str(fmsadmin), "restart", "httpserver", "-y", "-u", user, "-p", password]
        try:
            proc = run(argv)
        except Exception:
            return False
        return getattr(proc, "returncode", 1) == 0

    return activate


def real_upstream_listening(*, host: str = "127.0.0.1", timeout: float = 1.0):
    """Is something listening on this port? **Three answers, never two.**

    ``True`` a connection was established · ``False`` the connection was explicitly REFUSED ·
    ``None`` the question could not be answered.

    The middle answer is the only one that licenses accepting a 502, so it has to mean exactly one
    thing. A blanket ``except OSError: return False`` folded *timeout*, *permission denied*,
    *network unreachable* and *invalid port* into "nothing is listening" — and every one of those is
    a failure to observe, not an observation. Under that reading a firewalled or unreachable
    upstream would have made a 502 look like a healthy front, which is the exact inversion the 502
    exception exists to avoid.

    ``ECONNREFUSED`` is checked on the errno as well as by exception type: it is the one result that
    positively proves the port is closed, because something answered the SYN to say so.

    Injectable, and deliberately not a shell call: `ss`/`lsof`/`netstat` would make this depend on a
    tool's output format, on PATH, and on privilege — three things this component has already been
    bitten by.
    """
    import errno
    import socket

    def listening(port) -> bool | None:
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return False
        except OSError as exc:
            # Some stacks surface a refusal as a bare OSError carrying the errno.
            return False if getattr(exc, "errno", None) == errno.ECONNREFUSED else None
        except Exception:                 # noqa: BLE001 - an invalid port is unreadable, not absent
            return None

    return listening


def real_health_check(*, prefix: str, internal_port: int, opener=None, host: str = "127.0.0.1",
                      connector=None):
    """Did the FRONT actually answer after the change? Never inferred from an exit code.

    **It checks the front, not the application behind it**, and the difference is the whole point.
    An earlier version fetched `http://127.0.0.1:<internal_port><prefix>` — the loopback CORPUSfm
    process — which answers identically whether the proxy configuration is correct, broken, or was
    never written at all. It would have reported every activation healthy.

    The front serves HTTPS on 443. Certificate verification is deliberately DISABLED: a stock FMS
    box presents `CN=Claris Self Signed Certificate (Not for Production Use)`, and CORPUSfm's floor
    case is an IP address with an untrusted certificate. Requiring a trusted chain here would make
    the health check fail on the configuration the product must always support. This is a liveness
    probe against the local machine, not an authentication of it.

    **502 WITH NO UPSTREAM IS A LIVE FRONT (RC3, measured on fms-server 2026-08-08).** This treated
    every status ≥ 500 as unhealthy, on the premise its own docstring stated — *a 401 or a 404 from
    CORPUSfm is a live route*. That premise assumes CORPUSfm is already answering. **At phase 17 of
    a fresh install it cannot be:** the services do not start until phase 21, nothing listens on the
    internal port, and a correctly published route therefore proxies to a dead upstream and the
    front returns **502**. So the one piece of evidence that the route EXISTS was read as failure,
    the transaction restored a correct configuration, failed the same probe again, and reported
    `manual_action_required`. No fresh Linux install could activate the proxy.

    The narrow exception is therefore: **exactly 502, and only when this checker independently
    observes that the internal port is not listening.** If something IS listening there, a 502 means
    the front could not reach an upstream that exists — a real fault, and still unhealthy. Every
    other 5xx stays unhealthy whether or not the upstream is absent, and a refused or unreadable
    front is unhealthy as before. The port is REQUIRED and comes from the caller's recorded
    authority; there is no default to drift from and no boolean a caller could assert instead.
    """
    import ssl

    context = ssl._create_unverified_context()
    port = int(internal_port)
    upstream_listening = connector or real_upstream_listening(host=host)

    def check(_what: str) -> bool:
        import urllib.request

        # Probe INSIDE the owned location. On FileMaker's Windows front the bare `/corpusfm`
        # receives a generic 301 even when no CORPUSfm route exists; accepting that answer made a
        # successful restart look like proof of publication. The trailing slash is the first path
        # the rendered nginx `location /corpusfm/` and the IIS application actually own.
        owned = prefix if prefix.startswith('/') else '/' + prefix
        url = f"https://{host}{owned.rstrip('/')}/"
        get = opener or (lambda u: urllib.request.urlopen(u, timeout=10, context=context))
        try:
            with get(url) as response:
                status = int(getattr(response, "status", 0) or 0)
        except Exception as exc:
            status = getattr(exc, "code", None)      # HTTPError IS an answer
            if status is None:
                return False                          # refused or unreadable: not a live front
            status = int(status)
        # Any answered status short of a server error proves the front is routing. A 401 or a 404
        # from CORPUSfm is a live route; a refused connection is not.
        if 200 <= status < 500:
            return True
        if status == 502:
            # `is False`, never merely falsy. `None` means the observation FAILED, and an
            # unanswerable question must not license accepting a bad gateway.
            return upstream_listening(port) is False
        return False

    return check


# ── durable evidence ──────────────────────────────────────────────────────────────────────────
#
# Beside the journal, in the same lifecycle-controlled state directory, under its OWN filename.
# Separate from the patch compartment's record on purpose: two components sharing one evidence file
# would make "is a recovery owed, and for what" unanswerable the moment both had run.

RECOVERY_FILENAME = "proxy-recovery.json"
RECOVERY_FILE_MODE = 0o600


class RecoveryEvidenceInvalid(Exception):
    """The durable record is absent, unreadable or malformed. NEVER read as "nothing happened"."""


def recovery_path(layout) -> Path:
    return Path(layout.journal_file).parent / RECOVERY_FILENAME


def write_recovery(layout, record: RecoveryRecord, *, lock) -> Path:
    """Written BEFORE the mutation it covers, and secret-fenced on the way out.

    The fence is not decoration here: this record is the one artifact of the whole component that
    outlives the process, so it is the only place a credential could become durable. §9.4 says it
    stores a FLAG, and this is where that is enforced rather than intended.
    """
    from .lock import require_lock
    from .secret_guard import assert_no_secrets
    from .atomic import atomic_write_text

    require_lock(lock, "recording proxy recovery authority")
    payload = record.to_dict()
    # The writer and reader are one contract. Validate BEFORE replacing the prior durable record;
    # if a post-mutation result is malformed, the conservative earlier record remains available
    # for recovery instead of being overwritten by evidence the recovery command cannot parse.
    RecoveryRecord.from_dict(payload)
    assert_no_secrets(payload, what="the proxy recovery record")
    target = recovery_path(layout)
    atomic_write_text(target, json.dumps(payload, indent=2, sort_keys=True) + "\n",
                      mode=RECOVERY_FILE_MODE)
    return target


def read_recovery(layout) -> RecoveryRecord:
    target = recovery_path(layout)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RecoveryEvidenceInvalid(f"no proxy recovery record at {target}") from exc
    except (OSError, ValueError) as exc:
        raise RecoveryEvidenceInvalid(
            f"the proxy recovery record at {target} cannot be read: {type(exc).__name__}") from exc
    try:
        return RecoveryRecord.from_dict(raw)
    except (TypeError, ValueError) as exc:
        raise RecoveryEvidenceInvalid(f"the proxy recovery record is malformed: {exc}") from exc


def clear_recovery(layout, *, lock) -> None:
    """Retire the record. Only ever called after the journal resolved."""
    from .lock import require_lock

    require_lock(lock, "clearing proxy recovery authority")
    recovery_path(layout).unlink(missing_ok=True)


@dataclass(frozen=True)
class OperationAuthority:
    """Everything an operation must already know before it is allowed to change anything.

    One value rather than nine parameters, because the rule is that they travel TOGETHER: the
    defect this replaces was a caller that had them all and passed none, so the durable record
    described an operation nobody could later execute a restoration for.
    """

    operation_id: str
    installation_id: str
    expected_generation: int
    disposition: str
    flavour: str
    install_dir: str
    fms_root: str
    web_prefix: str
    web_internal_port: int
    executor_path: str
    executor_digest: str


def intent_record(*, plan: ProxyPlan, authority: OperationAuthority,
                  phase: str = PHASE_PREPARING,
                  evidence: Mapping[str, Mapping[str, str]] | None = None) -> RecoveryRecord:
    """The record written BEFORE any mutation, carrying EVERY authority fact already (ruling 1).

    **The outcome record refines; it never introduces.** A path that first appears after the change
    is a path no crash-interrupted operation ever had — which is the whole window this record
    exists to cover. So the paths, the route, the executor and its digest are all here, in the
    first write, and the later record only fills in what actually happened.

    `restoration_restart_may_be_required` is set PESSIMISTICALLY from the plan: a crash may have
    left an activation half-done. Reporting a credential as possibly-needed and then not needing it
    is a wasted prompt; the reverse is a half-restored box.
    """
    mutating = plan.mutating
    return RecoveryRecord(
        operation_id=authority.operation_id, installation_id=authority.installation_id,
        expected_generation=authority.expected_generation, disposition=authority.disposition,
        restoration_restart_may_be_required=any(
            p.mechanism in FMSADMIN_RESTART_MECHANISMS for p in mutating),
        per_type=tuple({"proxy_type": p.proxy_type, "action": p.action, "mechanism": p.mechanism,
                        # `published` is the question a recovering process asks: "might this type's
                        # bytes have been changed?" Before the run, for a type we are about to
                        # mutate, the honest answer is yes — restoring an unchanged file is a no-op,
                        # while skipping a changed one is the failure this record exists to prevent.
                        "published": True, "activated": False, "backup_reference": None}
                       for p in mutating),
        candidates={},
        flavour=authority.flavour, install_dir=authority.install_dir, fms_root=authority.fms_root,
        web_prefix=authority.web_prefix, web_internal_port=authority.web_internal_port,
        executor_path=authority.executor_path, executor_digest=authority.executor_digest,
        evidence=dict(evidence or {}), phase=phase,
    )


def bind_evidence(path: str, *, operation_id: str, install_dir: str, flavour: str) -> dict:
    """Validate a before-image the executor captured, and bind it BY DIGEST (ruling 4).

    A path alone binds nothing — the file it names can be replaced between the capture and the
    restoration. So the digest is computed HERE, by the lifecycle layer, from the bytes that are
    actually on disk at the moment the operation is declared prepared. `verify_evidence` recomputes
    it before any restoration, and a mismatch refuses without touching the box.
    """
    module = ntpath if flavour == WINDOWS else posixpath
    if not module.isabs(path) or path != module.normpath(path):
        raise RecoveryEvidenceInvalid(
            f"the before-image path {path!r} is not an absolute canonical {flavour} path")
    if not _within_root(path, install_dir, flavour):
        raise RecoveryEvidenceInvalid(
            f"the before-image at {path!r} lies outside this installation")
    if operation_id not in path:
        raise RecoveryEvidenceInvalid(
            f"the before-image at {path!r} is not named for operation {operation_id}")
    target = Path(path)
    if target.is_symlink():
        raise RecoveryEvidenceInvalid(f"the before-image at {path!r} is a symlink")
    try:
        payload = target.read_bytes()
    except OSError as exc:
        raise RecoveryEvidenceInvalid(
            f"the before-image at {path!r} could not be read ({exc.strerror})") from exc
    return {"path": path, "sha256": hashlib.sha256(payload).hexdigest()}


def verify_evidence(binding: Mapping[str, str]) -> None:
    """Recompute the bound digest immediately before a restoration consumes the evidence.

    A file that changed since it was bound is not the before-image this operation captured, and
    restoring from it would write somebody else's idea of the previous state onto the box.
    """
    target = Path(binding["path"])
    if target.is_symlink():
        raise RecoveryEvidenceInvalid(f"{binding['path']} became a symlink since it was bound")
    try:
        payload = target.read_bytes()
    except OSError as exc:
        raise RecoveryEvidenceInvalid(
            f"the bound before-image at {binding['path']} could not be read ({exc.strerror})"
        ) from exc
    seen = hashlib.sha256(payload).hexdigest()
    if seen != binding["sha256"]:
        raise RecoveryEvidenceInvalid(
            f"the before-image at {binding['path']} no longer matches the digest this operation "
            f"bound; refusing to restore from evidence that changed")


def abort_needs_credential(record: RecoveryRecord) -> bool:
    """Whether a LATER-PROCESS abort of this operation will need a NEW credential lease.

    The record stores the flag, never the credential. This is what lets 1246-04 report the answer
    BEFORE prompting an administrator for something it may not need.
    """
    return bool(record.restoration_restart_may_be_required)


__all__ = [
    "AWAITING_COMPOSITION", "COMPOSED_CANDIDATE", "CREDENTIAL_ABSENT", "CREDENTIAL_FD_PREFIX",
    "CREDENTIAL_PROMPT", "CREDENTIAL_STDIN", "CredentialLease", "CredentialUnavailable",
    "DIRECT_COMMIT", "DISPOSITIONS", "ExecutorCall", "ExecutorUnavailable", "ProxyEngine",
    "ProxyRefused", "executor_digest", "executor_refusal", "posix_directory_refusal",
    "posix_executor_refusal", "windows_authority_refusal",
    "ProxyRunResult", "RecoveryEvidenceInvalid", "RecoveryRecord", "TypeOutcome",
    "abort_needs_credential", "build_run_result", "clear_recovery", "derive_run_result",
    "executor_script", "open_credential_source", "partition_cohorts", "prompt_for_credential",
    "read_credential_frame", "read_recovery", "real_activator", "real_executor",
    "real_health_check", "real_upstream_listening", "recovery_path", "redact_argv",
    "write_recovery",
]


# ── owned-routing removal for an uninstall (packet 1246-09 §Z) ────────────────────────────────
#
# **The uninstaller does not edit a proxy configuration.** It asks this component to remove what
# this component published, and that is the whole reason this callable lives here: a second editor
# of somebody else's file — with its own idea of backups, validation and rollback — is how an
# uninstall breaks FileMaker Server's `:443`.
#
# The retired stage-4 executor called `proxy_tool.remove_owned_routing(...)`, an interface that
# existed nowhere. This is the real one.

REMOVAL_COMPLETED = "completed"
REMOVAL_ALREADY_ABSENT = "already_absent"
REMOVAL_REFUSED = "refused"
REMOVAL_FAILED = "failed_unknown"
#: **A PRE-ACTION state** (packet 1246-09 stage 6): this front's removal needs an FMS administrator
#: credential to take effect, none could be obtained, and nothing was edited, activated or run. It is
#: never a rejected credential — a rejection can only happen to a credential that was supplied, and
#: that is a failed activation, which is `failed_unknown`.
REMOVAL_CREDENTIAL_REQUIRED = "credential_required"
REMOVAL_STATES: tuple = (REMOVAL_COMPLETED, REMOVAL_ALREADY_ABSENT, REMOVAL_REFUSED,
                         REMOVAL_FAILED, REMOVAL_CREDENTIAL_REQUIRED)

#: Only these permit a later checkpoint. A refusal changed nothing; a failure does not know.
REMOVAL_CHECKPOINTABLE: frozenset = frozenset({REMOVAL_COMPLETED, REMOVAL_ALREADY_ABSENT})


@dataclass(frozen=True)
class RecordedFront:
    """One front as the INSTALLATION recorded it. Not as the box currently presents it.

    `proxy_type` is validated against `PROXY_TYPES`, which `RecoveryRecord` and the manifest both
    already do at their own boundaries — this one had skipped it, and an unvalidated type flows
    through `decide` into the privileged executor's argv as a positional token.
    """

    proxy_type: str
    config_location: str
    config_fingerprint: str

    def __post_init__(self):
        if self.proxy_type not in PROXY_TYPES:
            raise ProxyRefused(
                f"proxy_type must be one of {PROXY_TYPES}, got {self.proxy_type!r}")
        for field_name in ("config_location", "config_fingerprint"):
            if not getattr(self, field_name):
                raise ProxyRefused(f"a recorded front needs a {field_name}")


@dataclass(frozen=True)
class OwnedRoutingRemoval:
    """Per-front outcome, with the observation that decided it and the one that confirmed it."""

    proxy_type: str
    state: str
    before: str = ""                 # the owned-block state observed before acting
    after: str = ""                  # …and after
    detail: str = ""

    def __post_init__(self):
        # Its sibling `ControlResult` enforces this and it did not. A state outside the closed set
        # makes `may_checkpoint` quietly False rather than loudly wrong, which is the failure mode
        # a closed vocabulary exists to prevent.
        if self.state not in REMOVAL_STATES:
            raise ProxyRefused(f"state must be one of {REMOVAL_STATES}, got {self.state!r}")

    @property
    def may_checkpoint(self) -> bool:
        return self.state in REMOVAL_CHECKPOINTABLE


def _front_drift(front: RecordedFront, obs: ProxyObservation) -> str:
    """Why this front must not be mutated — or `""` when the record and the box agree.

    Three separate disagreements, kept apart because they mean different things:
    a front we did not record, a configuration at a different location, and a block whose bytes are
    not the bytes we published. **Any of them preserves.** A fingerprint mismatch means somebody
    edited what we wrote, and removing "our" block from a file we no longer recognise is removing
    somebody else's work.
    """
    if obs is None:
        return f"{front.proxy_type} was recorded but is not observed on this box"
    if not obs.installed:
        return f"{front.proxy_type} is recorded but is no longer installed"
    # **EXACT EQUALITY, and a MISSING observed value is not agreement.** These read
    # `if obs.config_location and ...` and `if obs.fingerprint and ...`, so an observation that
    # could not determine either one passed the check by having nothing to disagree with. "We could
    # not read where the configuration is" is not "it is where we recorded", and acting on the
    # second when the box said the first is the whole class of error this function exists to stop.
    if not obs.config_location:
        return (f"{front.proxy_type}'s configuration location could not be determined; a missing "
                "observation is not agreement with the recorded location")
    if obs.config_location != front.config_location:
        return (f"{front.proxy_type} configuration is at {obs.config_location!r}, and this "
                f"installation recorded {front.config_location!r}")
    if obs.owned_block == BLOCK_DRIFTED:
        return (f"{front.proxy_type}'s owned block has drifted from what this installation "
                "published; the bytes are somebody's edit and are preserved")
    if obs.owned_block == BLOCK_INVALID:
        return f"{front.proxy_type}'s owned block could not be read; it is preserved"
    if not obs.fingerprint:
        return (f"{front.proxy_type}'s owned block could not be fingerprinted; a missing "
                "observation is not agreement with the recorded fingerprint")
    if obs.fingerprint != front.config_fingerprint:
        return (f"{front.proxy_type}'s owned block fingerprints {obs.fingerprint!r}, and this "
                f"installation recorded {front.config_fingerprint!r}")
    return ""


def _absent_block_outcome(front: RecordedFront, obs: ProxyObservation, *, engine,
                          lease: "CredentialLease | None") -> "OwnedRoutingRemoval":
    """An absent owned block is not automatically a finished removal.

    **It may be the residue of *bytes removed, activation failed*.** A previous run can have taken
    our block out of `fms_nginx.conf` and then failed to restart FMS's web server — the file no
    longer contains the routing, and the RUNNING server still serves it. Reporting `already_absent`
    there checkpoints a removal that has not taken effect, and the routing survives every later
    resume because no run ever sees a block to remove again.

    So where the mechanism needs activation, the activation is retried and health re-checked
    through the ordinary engine. Missing credentials or a failed activation stays non-checkpointable.
    """
    mechanism = mechanism_for(obs)
    if mechanism not in FMSADMIN_RESTART_MECHANISMS:
        return OwnedRoutingRemoval(
            proxy_type=front.proxy_type, state=REMOVAL_ALREADY_ABSENT,
            before=BLOCK_ABSENT, after=BLOCK_ABSENT,
            detail=f"no owned block is present and {mechanism} needs no activation")
    if lease is None:
        # A BACKSTOP since stage 6: `remove_owned_routing` now determines the same requirement from
        # the same `mechanism_for`, before anything acts, and answers `credential_required` — so this
        # branch is not reached through that path. It is kept, and directly tested, because this
        # function is called with an explicit lease elsewhere and a credential-less caller must never
        # fall through to a checkpointable answer.
        return OwnedRoutingRemoval(
            proxy_type=front.proxy_type, state=REMOVAL_FAILED,
            before=BLOCK_ABSENT, after=BLOCK_ABSENT,
            detail=("the owned block is absent but this front needs an FMS restart to take effect, "
                    "and no admin credential was available to prove it did; the bytes may be the "
                    "residue of a removal that never activated"))
    if not engine.activate(lease):
        return OwnedRoutingRemoval(
            proxy_type=front.proxy_type, state=REMOVAL_FAILED,
            before=BLOCK_ABSENT, after=BLOCK_ABSENT,
            detail="the owned block is absent but the FMS restart failed; the running server may "
                   "still be serving the routing the bytes no longer describe")
    if not engine.health(front.proxy_type):
        return OwnedRoutingRemoval(
            proxy_type=front.proxy_type, state=REMOVAL_FAILED,
            before=BLOCK_ABSENT, after=BLOCK_ABSENT,
            detail="the FMS restart succeeded but the front did not come back healthy")
    return OwnedRoutingRemoval(
        proxy_type=front.proxy_type, state=REMOVAL_ALREADY_ABSENT,
        before=BLOCK_ABSENT, after=BLOCK_ABSENT,
        detail="the owned block is absent and the FMS restart has been re-proved")


def _credentials_required(recorded, before, *, policy) -> bool:
    """Whether the removal about to run needs an FMS administrator credential — from the REAL plan.

    **Pure, and it runs before anything acts.** `_front_drift`, `mechanism_for` and `decide` do no
    I/O, so asking this question changes nothing and cannot be the thing that goes wrong.

    Two sources, because the removal has two paths that activate:

    * a front whose owned block is already ABSENT still goes through `_absent_block_outcome`, which
      retries the activation to prove the bytes were not the residue of a removal that never took
      effect. That path needs the credential and no plan describes it;
    * every other actionable front is planned, and `plan.credentials_required` is the planner's own
      answer — computed from the same `mechanism_for` this reads, over the same observations.

    A plan that cannot be built claims nothing: the plan stage runs again inside the acting region
    and is reported there, exactly as it is today.
    """
    absent, actionable = [], []
    for front in recorded:
        obs = before.get(front.proxy_type)
        if obs is not None and obs.owned_block == BLOCK_ABSENT:
            absent.append(obs)
            continue
        if _front_drift(front, obs):
            # Refused before any activation is attempted; it needs nothing.
            continue
        actionable.append(obs)
    if any(mechanism_for(o) in FMSADMIN_RESTART_MECHANISMS for o in absent):
        return True
    if not actionable:
        return False
    request = PolicyRequest(verb="remove", types=tuple(o.proxy_type for o in actionable))
    try:
        plan = decide(policy, actionable, request=request)
    except Exception:                                                     # noqa: BLE001
        return False
    return bool(plan.credentials_required)


def remove_owned_routing(*, fronts, policy, observe, engine,
                         lease: "CredentialLease | None" = None, credential=None) -> tuple:
    """Remove exactly the routing this installation published, at exactly the recorded fronts.

    `policy` is the `ProxyPolicyView` the CALLER holds, and it is required rather than read here.
    Resolving the installation inside this function would tie a removal to a locator the uninstall
    is in the middle of retiring — and would make the callable untestable without an installed box,
    which is the same reason the executor and the activator are injected.

    `observe` is called to read the box **before** deciding and **again after** acting — the second
    call is the read-back, and `completed` is reported only when the owned block is then **absent**.
    `engine` is the ordinary `ProxyEngine`, so removal runs through the same bounded executor and
    the same activation mechanism as every other proxy mutation. There is no second editor.

    `lease` is a credential already held; `credential` is a PROVIDER for one, called at most once and
    only after the plan says an activation restart is required. Supply either, or neither — with
    neither, a removal that needs a restart answers `credential_required` for every front before
    anything is touched, which is the one refusal a launcher may act on.

    **The manifest is not updated here.** An uninstall is not a policy change: writing a new
    `proxy_policy` block mid-teardown would record a state the installation is in the middle of
    leaving, and the record is what a resume reads.

    Returns one `OwnedRoutingRemoval` per recorded front, in the order given.
    """
    recorded = tuple(fronts)
    if not recorded:
        raise ProxyRefused("removal needs at least one recorded front")

    # **THE PRE-ACTION BOUNDARY, and it is exactly this one call.** `observe` is a collaborator: it
    # reads a machine, and reading a machine fails. An exception here happens before anything has
    # been decided, planned or run — so it is a REFUSAL, which is this component's word for *nothing
    # changed*, and the caller retains the whole operation. `KeyboardInterrupt` and `SystemExit` are
    # not ordinary exceptions and are not converted.
    #
    # **Only the exception TYPE is reported.** A collaborator's message can carry whatever it was
    # handed — a host, a path, an argv containing a credential — and this text reaches a report.
    #
    # **`KeyboardInterrupt` and `SystemExit` are not converted, and `except Exception` is what
    # guarantees it** — both are `BaseException` and neither is an `Exception`. An explicit re-raise
    # clause was written here first and a mutation control showed it could not fire; a guard that
    # cannot fire reads like protection and is not any. The rule lives in the hierarchy, and the
    # regression that proves it mutates this clause to `BaseException`.
    try:
        before = {o.proxy_type: o for o in observe()}
    except Exception as exc:                                              # noqa: BLE001
        raise ProxyRefused(
            f"the initial proxy observation raised {type(exc).__name__}; nothing was attempted and "
            "every recorded front is preserved") from exc

    # **THE CREDENTIAL, DETERMINED AND ACQUIRED HERE — still before anything acts.** The need comes
    # from the real plan and the observed mechanism, so a front that publishes without activating
    # (Windows IIS) never reaches this and an operator is never asked for a password to do something
    # that did not need one. `credential` is a PROVIDER and is called at most once, only now.
    #
    # A provider that fails is not a second kind of refusal here: it answers `None` like any other
    # unavailable collaborator, and the caller — which is the one that knows whether a credential was
    # CONFIGURED — decides whether that is *none was supplied* or *the one supplied is unusable*.
    if lease is None and _credentials_required(recorded, before, policy=policy):
        if credential is not None:
            try:
                lease = credential()
            except Exception:                                             # noqa: BLE001
                lease = None
        if lease is None:
            return tuple(OwnedRoutingRemoval(
                proxy_type=front.proxy_type, state=REMOVAL_CREDENTIAL_REQUIRED,
                before=(before[front.proxy_type].owned_block
                        if front.proxy_type in before else ""),
                detail="this front's removal takes effect only after a FileMaker Server restart, "
                       "and no administrator credential was available; nothing was edited, "
                       "activated or run, and the whole operation is still owed")
                for front in recorded)

    # `results` is threaded in because the except branch READS it — the verdicts already reached
    # survive an exception. Nothing else is: an out-parameter nobody reads is a second piece of
    # recoverable state that is not one.
    results: dict[str, OwnedRoutingRemoval] = {}
    stage = ["the owned-block re-check"]
    try:
        decided = _remove_observed(recorded, before, results, policy=policy, observe=observe,
                                   engine=engine, lease=lease, stage=stage)
        # The executor's same-directory backups are intentionally durable until the removal and
        # its read-back have BOTH succeeded.  The uninstall has no provider-finalize phase after
        # this operation checkpoints, so leaving retirement to some later lifecycle step strands
        # ``*.cfmbak`` residue that every future publication correctly refuses to cross.
        #
        # Retire only when the WHOLE recorded family is checkpointable.  If one front drifted or
        # failed, every restore point stays with the still-owed collection.  Retirement itself is
        # idempotent; a partial retire failure leaves this operation owed and the next resume can
        # safely retry every front, including one whose backup is already absent.
        if all(outcome.may_checkpoint for outcome in decided):
            stage[0] = "the proxy transaction retirement"
            retired = []
            for outcome in decided:
                report = engine.executor("retire", outcome.proxy_type, None)
                if not report.get("ok"):
                    retired.append(replace(
                        outcome, state=REMOVAL_FAILED,
                        detail=(report.get("detail") or
                                "the proxy executor did not confirm backup retirement")))
                else:
                    retired.append(outcome)
            return tuple(retired)
        return decided
    except Exception as exc:                                              # noqa: BLE001
        # **PAST THE PRE-ACTION BOUNDARY, MUTATION MAY HAVE HAPPENED.** `_absent_block_outcome` can
        # activate an FMS restart, the engine writes, and the post-action observation runs after
        # both — so nothing here can honestly say *nothing changed*. `failed_unknown` is the word
        # for that, it is never checkpointable, and the caller retains the whole operation.
        #
        # A `ProxyRefused` raised in here is converted too, deliberately: once the engine may have
        # run, "the component refused" and "the component refused after doing something" are not
        # distinguishable from out here, and only one of them is safe to report.
        #
        # **The region is drawn conservatively and one member of it is provably pure.** `decide` does
        # no I/O — it is inside this block because `_absent_block_outcome` above it can already have
        # activated an FMS restart, so by the time the plan is built the run has passed the point of
        # certainty regardless of what the plan stage itself does. That reports "a change may already
        # have been made" on a run where the plan failed and nothing had, which is the safe error.
        return _uncertain_after(recorded, results, boundary=stage[0], exc=exc)


def _uncertain_after(recorded, results: dict, *, boundary: str, exc: BaseException) -> tuple:
    """Every front the run did not finish, marked uncertain — decided ones keep what they decided.

    The operation is retained whole by the caller either way; keeping the per-front verdicts that
    WERE reached loses nothing and says more.
    """
    detail = (f"{boundary} raised {type(exc).__name__}; a change may already have been made and "
              "this front is left owed")
    return tuple(
        results.get(front.proxy_type)
        or OwnedRoutingRemoval(proxy_type=front.proxy_type, state=REMOVAL_FAILED, detail=detail)
        for front in recorded)


def _remove_observed(recorded, before, results, *, policy, observe, engine, lease, stage) -> tuple:
    """The decided half. `stage` names the boundary currently being crossed, for honest reporting.

    **Every write to `results` records a verdict that was REACHED** — never a placeholder written
    before the work — which is what makes the uncertain path's guarantee hold: an exception always
    leaves the front being worked on undecided, so at least one front comes back non-checkpointable
    and `run_proxy` can never read the result as a completion.
    """
    actionable = []
    for front in recorded:
        obs = before.get(front.proxy_type)
        if obs is not None and obs.owned_block == BLOCK_ABSENT:
            results[front.proxy_type] = _absent_block_outcome(front, obs, engine=engine,
                                                              lease=lease)
            continue
        drift = _front_drift(front, obs)
        if drift:
            results[front.proxy_type] = OwnedRoutingRemoval(
                proxy_type=front.proxy_type, state=REMOVAL_REFUSED,
                before=(obs.owned_block if obs else ""), detail=drift)
            continue
        actionable.append(front)

    if actionable:
        stage[0] = "the proxy removal plan"
        request = PolicyRequest(verb="remove", types=tuple(f.proxy_type for f in actionable))
        plan = decide(policy, [before[f.proxy_type] for f in actionable], request=request)
        stage[0] = "the proxy engine"
        outcomes = {o.proxy_type: o for o in
                    engine.run(plan, [before[f.proxy_type] for f in actionable], lease=lease)}
        stage[0] = "the post-action proxy observation"
        after = {o.proxy_type: o for o in observe()}
        stage[0] = "the post-action read-back"
        for front in actionable:
            outcome = outcomes.get(front.proxy_type)
            observed_after = after.get(front.proxy_type)
            block_after = observed_after.owned_block if observed_after else ""
            if outcome is None:
                results[front.proxy_type] = OwnedRoutingRemoval(
                    proxy_type=front.proxy_type, state=REMOVAL_FAILED,
                    before=before[front.proxy_type].owned_block, after=block_after,
                    detail="the plan produced no outcome for this front")
                continue
            if outcome.result != COMPLETED:
                results[front.proxy_type] = OwnedRoutingRemoval(
                    proxy_type=front.proxy_type, state=REMOVAL_FAILED,
                    before=before[front.proxy_type].owned_block, after=block_after,
                    detail=f"the proxy engine reported {outcome.result!r}: {outcome.detail}")
                continue
            # THE READ-BACK. The engine reporting `completed` is the engine's account of its own
            # run; `completed` here requires the block to be observably gone.
            if block_after != BLOCK_ABSENT:
                results[front.proxy_type] = OwnedRoutingRemoval(
                    proxy_type=front.proxy_type, state=REMOVAL_FAILED,
                    before=before[front.proxy_type].owned_block, after=block_after,
                    detail=("the engine reported completion and the owned block is still "
                            f"{block_after!r} on re-observation"))
                continue
            results[front.proxy_type] = OwnedRoutingRemoval(
                proxy_type=front.proxy_type, state=REMOVAL_COMPLETED,
                before=before[front.proxy_type].owned_block, after=BLOCK_ABSENT)

    return tuple(results[f.proxy_type] for f in recorded)
