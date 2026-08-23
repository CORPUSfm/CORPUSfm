"""Observe, reconcile and remove the Admin-API machine identity (packet 1246-07).

``observe`` is read-only and asks for nothing. ``reconcile`` and ``remove`` mutate, take the lifecycle
lock, bracket their work in the journal, and return a **candidate** the integrator composes into its
single manifest write — this component performs no manifest write of its own.

**Three safety rules are structural here, not documented:**

* **Never pre-delete.** The component never calls ``register_public_key``; it looks with GET, and it
  replaces with the documented exact-name PATCH.
* **Never remove the last working local material before its replacement authenticates.** New material
  is STAGED beside the old; promotion is a rename after the new pair authenticated; a failed
  replacement leaves the original where it was.
* **Never delete a remote registration on less than a matched name AND fingerprint**, followed by a
  read-back proving absence. The FMS delete body is name-scoped, so the guarantee lives entirely in
  the observation before and the read-back after.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import admin_identity_store as store
from .admin_identity import (
    ClassifiedResult,
    FmsPresence,
    IdentityFacts,
    IdentityState,
    LocalAuthentication,
    LocalMaterial,
    Reachability,
    RemoteObservation,
    RemoteRegistration,
    RemovalAction,
    RemovalFacts,
    Tag,
    apply_mode_policy,
    attach_store_evidence,
    classify,
    plan_removal,
)
from .errors import LifecycleError
from .lock import require_lock
from .result import (
    COMPLETED,
    FAILED_BEFORE_CHANGE,
    MANUAL_ACTION_REQUIRED,
    NO_CHANGE,
    ROLLED_BACK,
)

CREDENTIAL_TRANSPORTS: tuple[str, ...] = ("absent", "prompt", "stdin")


class IdentityOperationError(LifecycleError):
    """An identity operation could not proceed. Never raised past the CLI."""


class CredentialFrameRefused(IdentityOperationError):
    """The credential frame was short, malformed, or arrived where none was meaningful."""


class GenerationDivergence(IdentityOperationError):
    """The installation record is not at the generation the request claims. Refused before change."""


# ── inputs ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IdentityInputs:
    """Everything 1246-04 supplies. The component derives nothing it was not given."""

    installation_id: str
    expected_generation: int
    install_dir: Path
    fms_root: Path
    secrets_dir: Path
    host: str
    mode: str
    actor: str


@dataclass(frozen=True)
class IdentityCandidate:
    """What the integrator composes into its ONE manifest write. This component writes none."""

    registration_name: str
    public_fingerprint: str
    last_observation: str
    last_success_utc: str
    inspected_generation: int
    inspected_installation_id: str

    def as_pki_block(self):
        """A VALIDATED `schema.PkiBlock`. Round-tripped through the schema's own validator rather
        than constructed, so a candidate that would not survive the manifest never leaves here."""
        from .schema import PkiBlock

        return PkiBlock.from_dict({
            "registration_name": self.registration_name,
            "public_fingerprint": self.public_fingerprint,
            "last_observation": self.last_observation,
            "last_success_utc": self.last_success_utc,
        })


@dataclass
class ObservationReport:
    """One tagged result, plus the facts that produced it. ``state`` is set only on an observation."""

    tag: Tag
    facts: IdentityFacts
    result: str
    state: IdentityState | None = None
    reason: str | None = None
    required_authority_operation: str | None = None
    credentials_required: bool = False
    mode_refusal: str | None = None
    store_exists: bool | None = None
    finding: str | None = None
    findings: list = field(default_factory=list)
    next_action: str = ""
    candidate: IdentityCandidate | None = None
    operation_id: str | None = None
    awaiting_composition: bool = False
    unresolved_operation: dict | None = None

    def payload(self) -> dict:
        return {
            "disposition": self.tag.value,
            "result": self.result,
            "operation_id": self.operation_id,
            "awaiting_composition": self.awaiting_composition,
            "unresolved_operation": self.unresolved_operation,
            "next_action": self.next_action,
            "prerequisite": self.reason if self.tag is Tag.PREREQUISITE_REQUIRED else None,
            "facts": {
                "presence": self.facts.fms_presence.value,
                "local": self.facts.local_material.value,
                "reachability": self.facts.reachability.value,
                "authentication": self.facts.local_authentication.value,
                "remote": self.facts.remote_registration.value,
            },
            "store_exists": self.store_exists,
            "state": None if self.state is None else self.state.value,
            # THE EMITTED NAME IS NOT THE ATTRIBUTE NAME, and the reason is 1246-01's structural
            # secret fence: `secret_guard` denies the key token `credentials` outright, so a payload
            # carrying `credentials_required` is REFUSED before it can be printed — measured, not
            # predicted. The internal attribute keeps the contract's name; the wire name follows the
            # precedent 1246-06 §8.1 set for exactly this collision ("the EMITTED name; the internal
            # attribute remains `credentials_required`"). A boolean requirement is not a credential,
            # but the fence reads names, not intent, and widening the fence for one packet's
            # convenience is how a structural guard becomes advisory.
            "fms_admin_login_required": bool(self.credentials_required),
            "required_authority_operation": self.required_authority_operation,
            "mode_refusal": self.mode_refusal,
            "findings": [{"code": c, "detail": d} for c, d in self.findings],
            "candidate": None if self.candidate is None else {
                "pki": {
                    "registration_name": self.candidate.registration_name,
                    "public_fingerprint": self.candidate.public_fingerprint,
                    "last_observation": self.candidate.last_observation,
                    "last_success_utc": self.candidate.last_success_utc,
                },
                "inspected_generation": self.candidate.inspected_generation,
                "inspected_installation_id": self.candidate.inspected_installation_id,
            },
        }


# ── the credential lease ────────────────────────────────────────────────────

class CredentialLease:
    """FMS admin credentials, read ONCE and held to a terminal point.

    Two length-prefixed UTF-8 fields — user then password — followed by EOF. An EOF or short read
    before both fields complete is a REFUSAL, not an empty credential: an empty password would be
    offered to FileMaker Server as if it were one.

    Never journaled, never logged, never placed in a request file or an environment variable, never
    reread, and never retained past ``wipe()``. It is supplied to ``fms_admin_pki``'s primitives,
    which reach FMS over HTTPS Basic — so it never enters any child process's argv.
    """

    __slots__ = ("_user", "_password", "_wiped")

    def __init__(self, user: str, password: str):
        self._user = user
        self._password = password
        self._wiped = False

    @classmethod
    def from_frame(cls, raw: bytes) -> "CredentialLease":
        fields = []
        offset = 0
        for _ in range(2):
            if offset + 4 > len(raw):
                raise CredentialFrameRefused(
                    "the credential frame ended before both length-prefixed fields were read; "
                    "refusing rather than treating a short read as an empty credential"
                )
            length = int.from_bytes(raw[offset:offset + 4], "big")
            offset += 4
            if offset + length > len(raw):
                raise CredentialFrameRefused(
                    "a credential field is shorter than its declared length; refusing"
                )
            fields.append(raw[offset:offset + length].decode("utf-8"))
            offset += length
        if offset != len(raw):
            raise CredentialFrameRefused("trailing bytes after the credential frame; refusing")
        user, password = fields
        # EMPTINESS IS CHECKED SEPARATELY FROM FRAMING, and after exact decoding. A frame of two
        # ZERO-LENGTH fields is perfectly well formed — every bounds check above passes — and it
        # produced `Basic Og==` on the wire: the empty administrator credential this class's own
        # docstring promises to refuse, reached by a route the short-read check never sees. Each
        # field is reported independently so the caller learns WHICH one was empty, and non-empty
        # input is never trimmed or reinterpreted — a password of spaces is a password.
        if not user or not password:
            missing = " and ".join(
                name for name, value in (("administrator name", user), ("password", password))
                if not value
            )
            raise CredentialFrameRefused(
                f"the credential frame carried an empty {missing}; an empty value is a refusal, "
                "not a credential, and is never offered to FileMaker Server"
            )
        return cls(user, password)

    @classmethod
    def read(cls, transport: str, *, reader=None, prompter=None, stream=None,
             interactive: bool | None = None) -> "CredentialLease | None":
        """Every declared transport, implemented. ``absent`` · ``fd:<n>`` · ``stdin`` · ``prompt``.

        ``prompt`` is reached ONLY when the transport is exactly ``prompt`` — an unattended run
        supplies ``absent``, ``stdin`` or a descriptor and can never be stopped at a console it has
        no one sitting at. A ``prompt`` on a stream that is not a terminal is a REFUSAL for the same
        reason: a silent installer that blocks forever is worse than one that says why it stopped.

        On Windows the framed bytes arrive on ``StandardInput.BaseStream`` exactly as they do here —
        the frame is binary and length-prefixed, so PowerShell string piping (which re-encodes and
        appends a newline) is not a transport and must not be used. *(Installer wiring is 1246-04's;
        this is the contract it wires to.)*
        """
        if transport == "absent":
            return None
        if transport not in CREDENTIAL_TRANSPORTS and not transport.startswith("fd:"):
            raise CredentialFrameRefused(f"{transport!r} is not a credential transport")
        # EVERY acquisition failure is a CREDENTIAL-INPUT REFUSAL, not an exception for someone else
        # to interpret. `fd:99` is schema-legal and raises `OSError` from `os.dup`; that used to
        # escape to the CLI's generic catch-all, which answered `manual_action_required`, exit 3, and
        # advised running `abort` — for a request that never took a lock, never reached FileMaker
        # Server and left nothing to discharge. A bad credential source is a refusal before change.
        try:
            if reader is not None:
                return cls.from_frame(reader())
            if transport.startswith("fd:"):
                fd = int(transport.split(":", 1)[1])
                with os.fdopen(os.dup(fd), "rb") as handle:
                    return cls.from_frame(handle.read())
            if transport == "stdin":
                return cls.from_frame(cls._stdin_bytes(stream))
        except CredentialFrameRefused:
            raise
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise CredentialFrameRefused(
                f"the credential source {transport!r} could not be read: {type(exc).__name__}: "
                f"{exc}. Nothing was changed and no operation was started."
            ) from exc
        return cls._prompted(prompter, interactive=interactive)

    @staticmethod
    def _stdin_bytes(stream=None) -> bytes:
        import sys

        source = stream if stream is not None else getattr(sys.stdin, "buffer", None)
        if source is None:
            raise CredentialFrameRefused(
                "standard input carries no binary stream; the credential frame is bytes, and a "
                "text stream would re-encode it"
            )
        return source.read()

    @classmethod
    def _prompted(cls, prompter=None, *, interactive: bool | None = None) -> "CredentialLease":
        import getpass
        import sys

        if prompter is None:
            if interactive is None:
                interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
            if not interactive:
                raise CredentialFrameRefused(
                    "credential_input 'prompt' needs a terminal; this run has none. Supply the "
                    "credential frame on a descriptor or standard input instead."
                )
            prompter = _console_prompter
        try:
            user, password = prompter()
        except CredentialFrameRefused:
            raise
        except Exception as exc:                   # noqa: BLE001 - any prompt failure is a refusal
            raise CredentialFrameRefused(
                f"the credential prompt could not be completed: {type(exc).__name__}: {exc}"
            ) from exc
        if not user or not password:
            raise CredentialFrameRefused(
                "an empty administrator name or password is a refusal, not a credential"
            )
        return cls(user, password)

    @property
    def user(self) -> str:
        self._assert_live()
        return self._user

    @property
    def password(self) -> str:
        self._assert_live()
        return self._password

    def use(self, fn):
        """Hand both fields to one in-process authority call without exposing a second lease type.

        The uninstall can need the same administrator first for exact PKI work and then for the
        FMS-owned proxy restart.  The former reads the two properties; the latter accepts this
        callback shape.  Both remain bounded by the same wipe at the invocation boundary.
        """
        self._assert_live()
        return fn(self._user, self._password)

    def _assert_live(self) -> None:
        if self._wiped:
            raise CredentialFrameRefused(
                "this credential lease was wiped; a new frame is required. A lease is never "
                "persisted, so it cannot outlive the operation that read it."
            )

    def wipe(self) -> None:
        self._user = ""
        self._password = ""
        self._wiped = True

    @property
    def wiped(self) -> bool:
        return self._wiped

    def __repr__(self) -> str:                     # never render the value
        return "<CredentialLease wiped>" if self._wiped else "<CredentialLease held>"


def _console_prompter() -> tuple[str, str]:        # pragma: no cover - requires a real terminal
    """The secure console path: the password never echoes and neither value is stored."""
    import getpass
    import sys

    # stdout belongs exclusively to the lifecycle JSON result. ``input(prompt)`` writes its prompt
    # there, which made an otherwise valid interactive uninstall return ``prompt + JSON`` and the
    # installed launcher correctly refuse it as more than one result. Prompts are console detail.
    print("FM Server admin account username: ", end="", file=sys.stderr, flush=True)
    return (input(),
            getpass.getpass("FM Server admin account password: "))


# ── the two authorities ─────────────────────────────────────────────────────
#
# The TYPE selects the transport, so there is no value a caller can pass that reaches Basic auth
# without a real password. An earlier version had one lease-shaped authority whose `password` was
# `""` for the self-removal path; the adapter did not recognise it and offered the empty string to
# FileMaker Server as if it were a credential.

@dataclass(frozen=True)
class BasicAdminAuthority:
    """An administrator credential. Reaches FMS over HTTPS Basic, through the lease."""

    lease: "CredentialLease"

    @property
    def user(self) -> str:
        return self.lease.user

    @property
    def password(self) -> str:
        return self.lease.password


@dataclass(frozen=True)
class InstalledIdentityAuthority:
    """This box's own working identity. Authenticates by PKI; carries NO password at all.

    There is no ``password`` attribute deliberately: a caller that reaches for one gets an
    ``AttributeError`` at the point of the mistake rather than an empty string on the wire.
    """

    registration_name: str
    private_pem: bytes

    def __repr__(self) -> str:
        return f"<installed identity {self.registration_name}, PKI authority>"


def _authority(lease: "CredentialLease | None"):
    return None if lease is None else BasicAdminAuthority(lease)


def _get_keys(api, host: str, authority) -> tuple[bool, list, str]:
    """One GET, routed by AUTHORITY TYPE. Neither branch can borrow the other's transport."""
    if isinstance(authority, InstalledIdentityAuthority):
        return api.get_public_keys_as_identity(host, authority.registration_name,
                                               authority.private_pem)
    return api.get_public_keys(host, authority.user, authority.password)


def _delete_key(api, host: str, authority, name: str) -> tuple[bool, str]:
    if isinstance(authority, InstalledIdentityAuthority):
        return api.delete_public_key_exact_as_identity(host, authority.registration_name,
                                                       authority.private_pem, name)
    return api.delete_public_key_exact(host, authority.user, authority.password, name)


# ── observation ─────────────────────────────────────────────────────────────

#: The Windows installer's `-FmsRoot` contract points at the DATABASE SERVER directory, not at the
#: installation root — `…\FileMaker Server\Database Server` — and that is what the generation-1
#: manifest records. Recognising it needs concrete evidence, because a basename proves nothing: any
#: directory can be called "Database Server". These are the executables a real one holds.
_WINDOWS_DATABASE_SERVER = "Database Server"
_WINDOWS_DATABASE_SERVER_EVIDENCE = ("fmsadmin.exe",)


def _presence(inputs: IdentityInputs, *, evidence=None) -> FmsPresence:
    """FMS presence from authoritative LOCAL evidence — never from the network.

    Two accepted shapes, both local and both evidenced:

    - the canonical **installation root**, evidenced by its own directories; and
    - on Windows only, the **Database Server directory itself**, evidenced by its identity AND the
      canonical executable it contains.

    The second exists because the Windows installer has always passed `$FmsBin` — the Database
    Server directory — where this function expected the root, so a box with FileMaker Server plainly
    installed classified `NOT_APPLICABLE` and admin identity composed nothing. Measured on
    winfms2026, 2026-08-08, with FMS detected, FMUpgradeTool present and OData answering 200. This
    is compatibility with that existing contract, not a second path authority: the manifest's
    recorded `fms_root` is unchanged, and nothing here consults the network, PATH, the registry, or
    a caller-supplied "installed" claim.
    """
    if evidence is not None:
        return evidence(inputs.fms_root)
    try:
        root = Path(inputs.fms_root)
        if not root.exists():
            return FmsPresence.ABSENT
        # An installation is evidenced by its own directories, not by its name.
        for marker in ("Database Server", "Admin", "Data"):
            if (root / marker).exists():
                return FmsPresence.INSTALLED
        if os.name == "nt" and root.name == _WINDOWS_DATABASE_SERVER:
            if all((root / exe).is_file() for exe in _WINDOWS_DATABASE_SERVER_EVIDENCE):
                return FmsPresence.INSTALLED
        return FmsPresence.ABSENT
    except OSError:
        return FmsPresence.UNKNOWN


def _collect_facts(
    inputs: IdentityInputs,
    *,
    api=None,
    probe=None,
    evidence=None,
    layout=None,
    credential=None,
):
    """THE SHARED READ-ONLY STEP: the six fact axes and the carried store evidence, and nothing else.

    Split out of `observe` so that `remove` can consume exactly the same facts and the same
    classification **without** the mode step. It used to reach them by calling `observe`, which meant
    every removal ran `apply_mode_policy` — the reconciliation question — and carried its verdict in
    the payload, so a SUCCESSFUL uninstall delete could be reported as
    `completed` beside `operation_update_not_permitted_in_uninstall`. Clearing the field afterwards
    would have hidden that; not computing it is what makes the claim structural.

    The one authentication is attempted only when there is usable local material to attempt it with,
    and the authorized GET runs only when a credential was already supplied for a mutating mode —
    ``observe`` never asks for one.

    It also REPORTS an unresolved operation and whether discharging it will need FMS authority —
    before anything prompts. An administrator who is going to be asked for a password deserves to
    learn that from a read-only command first.
    """
    authority = _authority(credential)
    presence = _presence(inputs, evidence=evidence)
    reachability = Reachability.NOT_APPLICABLE
    authentication = LocalAuthentication.NOT_ATTEMPTED
    remote = RemoteRegistration.NOT_OBSERVED
    exists = None

    prerequisite = store.machine_key_present(inputs.secrets_dir, layout=layout)
    try:
        exists = store.store_exists(inputs.secrets_dir, layout=layout)
    except OSError:
        exists = None

    if presence is FmsPresence.INSTALLED:
        reachability = Reachability.ANSWERED if _probe(inputs, probe) else Reachability.UNANSWERED

    if not prerequisite:
        local = LocalMaterial.UNCLASSIFIED
    else:
        local = store.classify_local_material(inputs.secrets_dir, layout=layout)

    if (
        prerequisite
        and presence is FmsPresence.INSTALLED
        and reachability is Reachability.ANSWERED
        and local is LocalMaterial.PRESENT_USABLE
    ):
        authentication = _authenticate(inputs, api=api, layout=layout)
        if authentication is LocalAuthentication.EXPLICITLY_REJECTED and authority is not None:
            # The GET REFINES the state (§5.4) by moving the remote axis; it does not un-observe the
            # refusal. An earlier version rewrote this axis to NOT_ATTEMPTED so the refined rows
            # would key cleanly — which changed no state (the remote axis is consulted first) and
            # destroyed the one diagnostic that says the relationship was refused.
            remote = _observe_remote(inputs, authority, api=api, layout=layout)
    elif (
        prerequisite
        and presence is FmsPresence.INSTALLED
        and reachability is Reachability.ANSWERED
        and local is LocalMaterial.ABSENT
        and authority is not None
    ):
        remote = _observe_remote(inputs, authority, api=api, layout=layout)

    facts = IdentityFacts(
        prerequisite_established=prerequisite,
        fms_presence=presence,
        local_material=local,
        reachability=reachability,
        local_authentication=authentication,
        remote_registration=remote,
    )
    return facts, exists


def observe(
    inputs: IdentityInputs,
    *,
    api=None,
    probe=None,
    evidence=None,
    layout=None,
    credential=None,
    lifecycle_layout=None,
) -> ObservationReport:
    """The read-only verb. Collect the facts, classify them, then apply the MODE policy.

    The mode step belongs to observation and reconciliation and to nothing else — see
    ``_observed_report``, which `remove` uses instead.
    """
    facts, exists = _collect_facts(inputs, api=api, probe=probe, evidence=evidence, layout=layout,
                                   credential=credential)
    report = _observed_report(facts, exists)
    report.credentials_required, report.mode_refusal = apply_mode_policy(
        _classified(facts, exists), inputs.mode)
    report.unresolved_operation = _unresolved(lifecycle_layout)
    return report


def _unresolved(lifecycle_layout) -> dict | None:
    """What this box still owes — THREE answers, not two: nothing, a valid operation, or evidence
    that cannot be adjudicated.

    The third used to be reported as the first. `RecoveryEvidenceInvalid` was caught and turned into
    `None`, so malformed evidence answered *"nothing owed"* — and the same reader then let a second
    operation start on top of it. "There is no record" and "there is a record I cannot read" owe
    opposite work.

    ``abort_fms_admin_login_required`` and not ``…credentials…``: 1246-01's secret fence denies the
    key token ``credentials`` outright, so the contract's internal word cannot be an emitted one —
    the same collision and the same 1246-06 precedent as ``fms_admin_login_required`` below.
    """
    if lifecycle_layout is None:
        return None
    from . import admin_identity_recovery as rec

    verdict, payload = rec.inspect_recovery(lifecycle_layout)
    if verdict == rec.NO_RECORD:
        return None
    if verdict == rec.INVALID:
        return {
            "operation_id": None,
            "kind": None,
            "state": "recovery_evidence_invalid",
            "remote_operation": None,
            "detail": payload,
            "abort_fms_admin_login_required": False,
        }
    record = payload
    # A remove is terminal: aborting it CLASSIFIES what happened, and a classification needs the
    # registry read, so authority is owed there too. A reconcile awaiting composition needs it only
    # when a remote change was actually published.
    needs_authority = record.kind == rec.KIND_REMOVE or record.remote_operation is not None
    return {
        "operation_id": record.operation_id,
        "kind": record.kind,
        "state": record.state,
        "remote_operation": record.remote_operation,
        "abort_fms_admin_login_required": needs_authority,
    }


class EvidenceNotClear(IdentityOperationError):
    """Unresolved or unreadable recovery evidence stands in the way of a new operation."""


def _assert_evidence_clear(lifecycle_layout, journal, *, lock) -> str | None:
    """No new mutating operation begins over unresolved or invalid evidence. Returns a retirable
    inert-preparation operation id, or ``None``.

    Three conditions are separated, because they owe different things:

    * **Invalid evidence** — refuse, visibly, naming it. It is retained; a human adjudicates it.
    * **A valid record past preparation, or an unresolved journal** — refuse: an operation is owed.
    * **A PREPARED record with a clear journal** — INERT. Evidence was published and the journal was
      never opened, so nothing was mutated. It has an explicit retirement path and is retired here
      rather than wedging the box, which is the whole reason preparation has its own phase.

    The journal is cross-checked against the record: two accounts of the same box naming different
    operations or different installations is a condition no verb may act through.
    """
    from . import admin_identity_recovery as rec

    verdict, payload = rec.inspect_recovery(lifecycle_layout)
    journal_record = None
    try:
        journal_record = journal.read()
    except LifecycleError as exc:
        raise EvidenceNotClear(
            f"the lifecycle journal cannot be read ({exc}); refusing to start an operation over "
            "evidence nobody can interpret") from exc
    journal_owed = journal_record is not None and journal.requires_recovery()

    if verdict == rec.INVALID:
        raise EvidenceNotClear(
            f"recovery_evidence_invalid: {payload}. The evidence is RETAINED and must be "
            "adjudicated by hand; no operation starts over a record this build cannot read.")

    if verdict == rec.NO_RECORD:
        if journal_owed:
            raise EvidenceNotClear(
                f"lifecycle operation {journal_record.operation_id} is unresolved and no "
                "admin-identity recovery record accompanies it")
        return None

    record = payload
    if journal_record is not None:
        if journal_record.operation_id != record.operation_id:
            raise EvidenceNotClear(
                f"the journal names operation {journal_record.operation_id} and the recovery record "
                f"names {record.operation_id}; two accounts of this box disagree")
        if journal_record.installation_id != record.installation_id:
            raise EvidenceNotClear(
                "the journal and the recovery record name different installations")

    if journal_owed:
        raise EvidenceNotClear(
            f"admin-identity operation {record.operation_id} ({record.state}) is unresolved; "
            "discharge it with `admin-identity abort` or `finalize` before starting another")

    if record.state != rec.PREPARED:
        # A RESOLVED journal that matches this record is terminal: the operation finished and only
        # its residual files are left. Retire them and get on with the new operation rather than
        # sending an administrator to adjudicate a crash between two adjacent lines.
        try:
            verdict, result, _detail = rec.discharge_terminal_evidence(
                lifecycle_layout, lock=lock, journal=journal,
                operation_id=record.operation_id, installation_id=record.installation_id)
        except rec.PreparationNotDischargeable as exc:
            raise EvidenceNotClear(str(exc)) from exc
        if verdict == rec.TERMINAL:
            return record.operation_id
        raise EvidenceNotClear(
            f"a recovery record for operation {record.operation_id} is in state {record.state!r} "
            "with a resolved journal; the two disagree and only a human may settle it")

    # THE SAME shared discharge `abort` uses. It cross-checks the journal itself, so this path
    # cannot retire evidence over an owed journal either.
    try:
        rec.discharge_preparation(lifecycle_layout, lock=lock, journal=journal,
                                  operation_id=record.operation_id,
                                  installation_id=record.installation_id)
    except rec.PreparationNotDischargeable as exc:
        raise EvidenceNotClear(str(exc)) from exc
    return record.operation_id


def _classified(facts: IdentityFacts, exists: bool | None):
    """Classification plus carried evidence. No mode has been anywhere near this."""
    return attach_store_evidence(classify(facts), exists)


def _observed_report(facts: IdentityFacts, exists: bool | None) -> ObservationReport:
    """A report built from the classification ALONE.

    `credentials_required` and `mode_refusal` are left at their defaults — `False` and `None`. Only
    `observe` (and through it `reconcile`) fills them in; `remove` computes its own requirement from
    `plan_removal` and never asks the mode question at all.
    """
    result = _classified(facts, exists)
    report = ObservationReport(
        tag=result.tag,
        facts=facts,
        result=NO_CHANGE if result.tag is not Tag.INVALID_COMBINATION else FAILED_BEFORE_CHANGE,
        state=result.state,
        reason=result.reason,
        required_authority_operation=result.required_authority_operation,
        store_exists=result.store_exists,
        finding=result.finding,
        next_action=_next_action(result),
    )
    if result.tag is Tag.INVALID_COMBINATION:
        report.findings.append(("invalid_fact_combination", str(result.reason)))
    if result.finding:
        report.findings.append((result.finding, "an authorized GET has not been performed"))
    return report


def _next_action(result: ClassifiedResult) -> str:
    if result.tag is Tag.PREREQUISITE_REQUIRED:
        return ("Establish the published layout and invoke the current Machine Key authority, "
                "then observe again.")
    if result.tag is Tag.NOT_APPLICABLE:
        return ("No FileMaker Server is installed on this box; no Admin-API identity applies. "
                "Nothing is claimed about any remote registration.")
    if result.tag is Tag.INVALID_COMBINATION:
        return f"The observed facts violate {result.reason}; nothing was changed."
    mapping = {
        IdentityState.WORKING: "Nothing to do; the identity authenticates.",
        IdentityState.UNKNOWN: "Report the FileMaker Server condition; nothing was changed.",
        IdentityState.LOCAL_UNUSABLE: ("Preserve the material and report it; replacement is a "
                                       "deliberate authorized act."),
        IdentityState.NOT_INSTALLED: "Provision the identity with FMS authority.",
        IdentityState.LOCAL_ONLY: "Register the existing public key with FMS authority.",
        IdentityState.REMOTE_ONLY: "Replace the exact registration with FMS authority.",
        IdentityState.MISMATCHED: "Replace the exact registration with FMS authority.",
        IdentityState.REJECTED: ("Diagnose, then look: an authorized GET refines this state before "
                                 "any replacement."),
    }
    return mapping.get(result.state, "")


def _probe(inputs: IdentityInputs, probe) -> bool:
    """One read-only, unauthenticated reachability probe. Carries no credential."""
    if probe is None:
        return False
    try:
        return bool(probe(inputs.host))
    except Exception:                             # noqa: BLE001 - a failed probe is UNANSWERED
        return False


def _authenticate(inputs: IdentityInputs, *, api, layout) -> LocalAuthentication:
    """Authenticate against the REQUEST's host and the FIXED registration name.

    **A stored value is evidence, never network authority.** This used to read `identity.host` and
    `identity.registration_name` off the store while every other call in this module used
    `inputs.host` and `store.REGISTRATION_NAME` — so a stored host could send the one authenticated
    request to a different box, and the run would report `WORKING` about a machine nobody probed.
    Under the Unknowable-Install principle an address MOVING is the expected case, which makes the
    stored copy the stale one by construction.

    A stored registration name that is not the fixed one is corrupt evidence and is refused by
    `classify_local_material` before this is reached; the guard is repeated here because this
    function is what would otherwise put that name on the wire.
    """
    identity = store.load(inputs.secrets_dir, layout=layout)
    if identity is None:
        return LocalAuthentication.NOT_ATTEMPTED
    if identity.registration_name != store.REGISTRATION_NAME:
        return LocalAuthentication.NOT_ATTEMPTED
    if api is None:
        return LocalAuthentication.INCONCLUSIVE
    try:
        ok = api.authenticate(inputs.host, store.REGISTRATION_NAME, identity.private_pem)
    except Exception:                             # noqa: BLE001 - a failed attempt proves nothing
        return LocalAuthentication.INCONCLUSIVE
    if ok is True:
        return LocalAuthentication.SUCCEEDED
    if ok is False:
        return LocalAuthentication.EXPLICITLY_REJECTED
    return LocalAuthentication.INCONCLUSIVE


@dataclass(frozen=True)
class RemoteSnapshot:
    """What ONE authorized GET established about the exact registration name.

    Kept separate from ``RemoteRegistration`` because the classifier's axis answers "how does the
    registry relate to my local material", and a failure classification needs a different question:
    "which of three specific fingerprints is up there now". Collapsing them is how a failed **Add**
    ended up sharing the **Update** path's reasoning and reporting `failed_before_change` for a
    registration that had actually landed.
    """

    answered: bool
    present: bool
    readable: bool
    fingerprint: str | None = None
    public_material: str | None = None


def _remote_snapshot(inputs, authority, *, api, registration_name: str | None = None
                     ) -> RemoteSnapshot:
    if api is None or authority is None:
        return RemoteSnapshot(answered=False, present=False, readable=False)
    wanted = registration_name or store.REGISTRATION_NAME
    try:
        ok, entries, _msg = _get_keys(api, inputs.host, authority)
    except Exception:                             # noqa: BLE001
        return RemoteSnapshot(answered=False, present=False, readable=False)
    if not ok:
        return RemoteSnapshot(answered=False, present=False, readable=False)
    match = next((e for e in entries if e.get("name") == wanted), None)
    if match is None:
        return RemoteSnapshot(answered=True, present=False, readable=True)
    material = match.get("publicKey", "")
    try:
        return RemoteSnapshot(answered=True, present=True, readable=True,
                              fingerprint=store.fingerprint_of_public_pem(material),
                              public_material=material)
    except Exception:                             # noqa: BLE001 - unreadable key material
        return RemoteSnapshot(answered=True, present=True, readable=False)


def _observe_remote(inputs, authority, *, api, layout) -> RemoteRegistration:
    """The authorized GET. Compares by canonical DER fingerprint, never by raw PEM."""
    if api is None or authority is None:
        return RemoteRegistration.NOT_OBSERVED
    snapshot = _remote_snapshot(inputs, authority, api=api)
    if not snapshot.answered:
        return RemoteRegistration.INCONCLUSIVE
    if not snapshot.present:
        return RemoteRegistration.CONFIRMED_ABSENT
    if not snapshot.readable:
        return RemoteRegistration.INCONCLUSIVE
    identity = store.load(inputs.secrets_dir, layout=layout)
    if identity is None:
        return RemoteRegistration.CONFIRMED_PRESENT
    if snapshot.fingerprint == identity.public_fingerprint():
        return RemoteRegistration.CONFIRMED_MATCHING
    return RemoteRegistration.CONFIRMED_MISMATCH


# ── reconciliation ──────────────────────────────────────────────────────────

def _inspect_generation(inputs: IdentityInputs) -> tuple[int, str | None]:
    """The generation ACTUALLY on disk, read from the installation's own manifest.

    Opened WITHOUT a layout, so the store is structurally a reader and no code path here can gain a
    manifest write by holding it. ``0`` means *no manifest exists* — never *I could not tell*, which
    is why a present-but-unreadable manifest raises out of here rather than answering zero.
    """
    from .manifest import ManifestStore

    manifest_store = ManifestStore(inputs.install_dir)
    if not manifest_store.exists():
        return 0, None
    manifest = manifest_store.read()
    return manifest.generation, manifest.installation_id


def _published_pki(inputs: IdentityInputs):
    """The `pki` block the installation's own manifest carries, or ``None`` when there is none.

    Read from the manifest rather than from the request, for the same reason
    `_generation_authority` is: a caller's claim about what is published is not evidence that it is.
    """
    from .manifest import ManifestStore

    manifest_store = ManifestStore(inputs.install_dir)
    if not manifest_store.exists():
        return None
    return manifest_store.read().pki


def _publication_owed(inputs: IdentityInputs, *, layout) -> tuple[bool, str]:
    """Does a WORKING identity still owe the installation record a publication? Three answers.

    **1. There is no manifest at all.** Nothing is owed, and this is not a near-miss: there is
    nothing to be absent FROM, and `composition.commit_provider` refuses any
    `inspected_generation < 1` outright — so a candidate offered here could never be composed by
    anything. This is the pre-foundation observation window, and the honest answer is that no work
    exists yet.

    **2. The manifest already records this identity.** Nothing is owed. Compared on the two
    IDENTITY-BEARING fields — the registration name and the public fingerprint. `last_observation`
    and `last_success_utc` are re-derived on every observation (`_candidate` stamps `utc_now_iso()`),
    so including them would make the answer "owed" on every single run: each invocation would
    publish a fresh timestamp, consume a generation, and the installation's generation would ratchet
    upward forever for a machine identity that never changed. The two observational fields are
    therefore excluded deliberately, not by oversight.

    **3. A manifest exists and does not carry this identity.** Publication IS owed. That is ordinary
    reconcile work and it takes the ordinary bracket — which is what makes the returned candidate
    composable, because `commit_provider` joins an operation and an offer with no operation behind
    it cannot be taken up.

    A `None` fingerprint on either side is never a match: an unpublished block and an unreadable
    local pair are both *unknown*, and unknown is not agreement.
    """
    published = _published_pki(inputs)
    if published is None:
        return False, ("this installation publishes no manifest yet, so there is nothing for a "
                       "machine identity to be recorded in")
    identity = store.load(inputs.secrets_dir, layout=layout)
    local_fingerprint = identity.public_fingerprint() if identity else None
    if not local_fingerprint:
        return False, "the local machine identity has no readable public fingerprint to publish"
    if (published.registration_name == store.REGISTRATION_NAME
            and published.public_fingerprint == local_fingerprint):
        return False, ("the manifest already records exactly this registration name and public "
                       "fingerprint")
    return True, "the manifest does not record this machine identity"


def _generation_authority(inputs: IdentityInputs) -> int:
    """Establish the generation INDEPENDENTLY, then compare the caller's claim to it.

    An earlier version echoed ``request.expected_generation`` straight into the candidate, so §9.2's
    compare-and-swap check compared the installer's own number to itself and could only ever agree.
    A stale or invented value now refuses BEFORE anything is mutated.
    """
    actual, installation_id = _inspect_generation(inputs)
    if installation_id is not None and installation_id != inputs.installation_id:
        raise GenerationDivergence(
            f"the manifest at {inputs.install_dir} belongs to installation {installation_id}, not "
            f"{inputs.installation_id}; refusing to act on another installation's record"
        )
    if actual != inputs.expected_generation:
        raise GenerationDivergence(
            f"the request expects generation {inputs.expected_generation} and the installation "
            f"record is at {actual}; another lifecycle operation has written since this request "
            "was composed"
        )
    return actual


def reconcile(
    inputs: IdentityInputs,
    *,
    lease: CredentialLease | None,
    api,
    probe=None,
    evidence=None,
    layout=None,
    lifecycle_layout=None,
    lock=None,
    journal=None,
    generate=None,
) -> ObservationReport:
    """Bring the identity to WORKING, or explain honestly why it could not.

    GET before Add on every path. Replacement is the exact-name PATCH. New material is staged and
    promoted only after the new pair authenticates.

    **The lock and the journal are REQUIRED, not optional.** They used to default to ``None`` and
    the CLI passed neither, so the shipped path ran every mutation with no serialization and no
    recovery bracket while the tests exercised a bracket nothing used.

    On success the operation is left **awaiting composition**: the journal stays open and the
    recovery evidence stays on disk until ``finalize`` proves the integrator wrote the candidate.
    """
    from . import admin_identity_recovery as rec

    if lock is None or journal is None:
        raise IdentityOperationError(
            "reconcile mutates: it requires a held lifecycle lock and a journal, and it will not "
            "run without the bracket that makes an interrupted run recoverable"
        )
    held = require_lock(lock, "reconciling the Admin-API machine identity")
    lifecycle_layout = lifecycle_layout if lifecycle_layout is not None else held.layout
    # AN OPERATION ID EXISTS ONLY WHEN AN OPERATION OPENS (correction F1).
    #
    # This used to mint one here and attach it to the report BEFORE every branch, so every
    # observation and every no-change answer came back naming an operation that had never existed —
    # no journal, no recovery record, nothing to resume or abort. It reads as harmless and is not:
    # `cli.admin_identity_skip_is_genuine` refuses a candidate-free result that names an operation,
    # precisely because an operation that opened nothing has no id to name. So the ONE case that
    # rule exists to permit — the genuinely already-published identity — could never satisfy it, and
    # a healthy update died at the admin-identity phase with generations already consumed.
    #
    # The id is now minted immediately before the bracket opens, and the SAME id is bound into the
    # report, the recovery record and the journal.
    authority = _authority(lease)
    report = observe(inputs, api=api, probe=probe, evidence=evidence, layout=layout,
                     credential=lease, lifecycle_layout=lifecycle_layout)

    if report.tag is not Tag.IDENTITY_OBSERVATION:
        return report

    # The generation is established INDEPENDENTLY here — before the no-change branch, because that
    # branch also returns a candidate the integrator composes, and a candidate carrying an
    # unverified generation is exactly what §9.2's compare-and-swap exists to prevent.
    try:
        inspected = _generation_authority(inputs)
    except GenerationDivergence as exc:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(("generation_divergence", str(exc)))
        return report

    if report.state in (IdentityState.WORKING,):
        # A WORKING IDENTITY CAN STILL NEED PUBLICATION (packet 1246-04-04, correction R6).
        #
        # This branch used to return `no_change` WITH a candidate and WITHOUT opening anything. The
        # integrator then called `composition commit-provider`, whose `_require_matching_entry`
        # looked for this operation in the journal, found nothing, and raised `ProviderMismatch` —
        # so every update of a box whose machine identity was already working died at the
        # admin-identity phase with the services already stopped. A candidate is an offer to compose,
        # and composing joins an operation; an offer with no operation behind it cannot be taken up.
        #
        # So the question is no longer "is the identity working" but "does the MANIFEST already say
        # so". If it does, this is a genuine no-change: no candidate, no journal, no evidence, no
        # generation consumed. If it does not, the identity is working and unpublished, and that is
        # ordinary reconcile work — it falls through to the same bracket every other publication
        # uses, so the record, its durability checks and `finalize`/`abort` are the shipped ones
        # rather than a weaker no-mutation shape invented here.
        owed, why = _publication_owed(inputs, layout=layout)
        if not owed:
            report.result = NO_CHANGE
            report.candidate = None
            report.awaiting_composition = False
            report.next_action = (
                f"Nothing is owed for this machine identity ({why}); no generation is consumed and "
                "no operation is opened."
            )
            report.findings.append(("no_publication_owed", why))
            return report
        report.findings.append(
            ("identity_working_but_unpublished",
             "the machine identity authenticates, and the installation record does not carry it; "
             "publishing it is composition work and opens the ordinary operation bracket"))
    if report.state is IdentityState.LOCAL_UNUSABLE:
        # Preserve the bytes. Replacement is a deliberate authorized act, never automatic.
        report.result = NO_CHANGE
        return report
    if report.state is IdentityState.UNKNOWN and report.required_authority_operation is None:
        # Terminal UNKNOWN: presence unknown, FMS unreachable, or an inconclusive answer. No
        # credential can help a question that was not answered, so none is requested.
        report.result = NO_CHANGE
        return report
    if report.state is IdentityState.UNKNOWN and lease is None:
        # UNKNOWN because we have not been ALLOWED to look yet. Reporting `no_change` here would
        # hide the one thing the integrator needs: that an authorized GET is what is missing.
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("fms_authority_required",
             "the registry has not been read; an authorized GET needs FMS admin authority, "
             "supplied through the protected credential frame")
        )
        return report
    if report.state is IdentityState.UNKNOWN:
        # Authority was supplied, so `observe` already ran the GET and the remote axis is whatever it
        # saw; an UNKNOWN that survives that is an inconclusive answer, not a missing permission.
        report.result = NO_CHANGE
        return report
    if report.state is IdentityState.REJECTED:
        report.result = NO_CHANGE
        report.findings.append(
            ("diagnose_before_replacing",
             "authentication was refused by an answering FMS; an authorized GET refines this state "
             "before any replacement is attempted")
        )
        return report
    if lease is None:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("fms_authority_required",
             "this reconciliation needs FMS admin authority; supply it through the protected "
             "credential frame (FM_ADMIN_USER / FM_ADMIN_PASS for an unattended run)")
        )
        return report
    if report.mode_refusal is not None:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(("mode_refusal", report.mode_refusal))
        return report

    try:
        inert = _assert_evidence_clear(lifecycle_layout, journal, lock=lock)
    except EvidenceNotClear as exc:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(("recovery_evidence_not_clear", str(exc)))
        return report
    if inert is not None:
        report.findings.append(
            ("inert_preparation_retired",
             f"operation {inert} published recovery evidence and never opened the journal, so it "
             "mutated nothing; its inert evidence was retired before this operation began"))

    # ── THE ORDER IS THE CONTRACT (F4) ──────────────────────────────────────
    # 1. the lock is held and no prior operation is owed  2. before-images captured durably
    # 3. recovery evidence published durably  4. journal opened durably  5. only then, mutation.
    #
    # It used to be 4-2-3-5: `journal.begin` ran first and `_mutate` captured the backups and wrote
    # the record afterwards, so a crash or a full disk during capture left an UNRESOLVED JOURNAL WITH
    # NO USABLE EVIDENCE — the one state no verb can discharge. Preparation now completes before the
    # journal opens, and a crash in that window leaves inert evidence and a clear journal, which
    # `_assert_evidence_clear` retires explicitly.
    # HERE, and nowhere earlier: the next statement publishes durable evidence under this id and the
    # one after it opens the journal with it.
    operation_id = str(uuid.uuid4())
    report.operation_id = operation_id
    try:
        prepared = _prepare(inputs, report, authority=authority, api=api, layout=layout,
                            lifecycle_layout=lifecycle_layout, lock=lock, generate=generate,
                            operation_id=operation_id, inspected_generation=inspected)
    except _PreparationRefused as exc:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append((exc.code, str(exc)))
        return report

    journal.begin(lock=lock, operation_id=operation_id,
                  installation_id=inputs.installation_id, mode=inputs.mode)
    try:
        report = _mutate(inputs, report, prepared=prepared, authority=authority, api=api,
                         layout=layout, lifecycle_layout=lifecycle_layout, lock=lock,
                         journal=journal, operation_id=operation_id,
                         inspected_generation=inspected)
    except BaseException:
        journal.mark_needs_recovery(
            lock=lock, reason=f"admin-identity {operation_id} was interrupted mid-operation")
        raise
    report.operation_id = operation_id
    if report.awaiting_composition:
        # Deliberately NOT resolved. The remote half is published and the local half is promoted,
        # but the manifest write that records them is the integrator's, and retiring the evidence
        # before that write means an interrupted composition has nothing to resume from.
        return report
    if report.result in (COMPLETED, NO_CHANGE, FAILED_BEFORE_CHANGE):
        journal.resolve(lock=lock, result=report.result)
        rec.clear_recovery(lifecycle_layout, lock=lock)
    else:
        journal.mark_needs_recovery(
            lock=lock, reason=f"admin-identity {operation_id} ended {report.result}")
    return report


class _PreparationRefused(IdentityOperationError):
    """Preparation could not complete. Nothing has been mutated and no journal was opened."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class _Prepared:
    """Everything step 5 needs, captured and made durable in steps 2 and 3."""

    record: object
    private_pem: bytes
    public_pem: bytes
    prior: RemoteSnapshot
    stages_material: bool
    operation: str


def _prepare(inputs, report, *, authority, api, layout, lifecycle_layout, lock, generate,
             operation_id, inspected_generation) -> "_Prepared":
    """STEPS 2 AND 3: capture the before-images durably, then publish the evidence — and mutate
    NOTHING. The journal has not been opened when this runs, so a failure here is inert.
    """
    from . import admin_identity_recovery as rec

    existing = store.load(inputs.secrets_dir, layout=layout)

    # GET BEFORE ADD, on every path — and the answer is retained, because a failure classification
    # needs to know what was there BEFORE. An unreadable registry refuses here rather than mutating
    # into a state nothing could later classify.
    prior = _remote_snapshot(inputs, authority, api=api)
    if not prior.answered:
        raise _PreparationRefused(
            "remote_state_unread_before_change",
            "the registry could not be read before the change; refusing to publish into a state "
            "this run would not be able to classify afterwards. Nothing was changed.")

    # §6: MISMATCHED is "Update the exact name with THIS public key. Generate a new pair only if the
    # existing one cannot be used" — and R8 guarantees it IS usable on that row, so rotating there
    # would discard a good private key for no reason and for no rule.
    # WORKING joins this set for correction R6. A working identity reaching `_prepare` is one the
    # MANIFEST does not yet carry, and the fix for that is to record the pair the box already uses —
    # not to mint a new one. Generating here would rotate a key that authenticates, invalidating
    # every client that trusts it, in order to write a record.
    reuse = report.state in (IdentityState.LOCAL_ONLY, IdentityState.MISMATCHED,
                             IdentityState.WORKING)
    if reuse and existing is not None:
        private_pem = existing.private_pem
        public_pem = store.public_pem_of_private_pem(private_pem)
        stages_material = False
    else:
        private_pem, public_pem = (generate or _generate)()
        stages_material = True
    attempted = store.fingerprint_of_private_pem(private_pem)

    local_before = store.read_store_bytes(inputs.secrets_dir, layout=layout)
    try:
        local_backup = local_digest = None
        if local_before is not None:
            path, local_digest = rec.write_backup(lifecycle_layout, operation_id,
                                                  rec.LOCAL_BEFORE, local_before)
            local_backup = str(path)
        remote_backup = remote_digest = None
        if prior.present and prior.readable:
            path, remote_digest = rec.write_backup(
                lifecycle_layout, operation_id, rec.REMOTE_BEFORE,
                (prior.public_material or "").encode("ascii"))
            remote_backup = str(path)
    except rec.RecoveryEvidenceInvalid as exc:
        _discard_backups(lifecycle_layout, operation_id)
        raise _PreparationRefused(
            "before_image_not_durable",
            f"the before-images could not be captured durably ({exc}); nothing was changed and no "
            "operation was opened") from exc
    except OSError as exc:
        _discard_backups(lifecycle_layout, operation_id)
        raise _PreparationRefused(
            "before_image_not_durable",
            f"the before-images could not be written ({exc}); nothing was changed and no operation "
            "was opened") from exc

    operation = ("add" if report.state in (IdentityState.NOT_INSTALLED, IdentityState.LOCAL_ONLY)
                 else "update")
    record = rec.IdentityRecovery(
        operation_id=operation_id,
        installation_id=inputs.installation_id,
        kind=rec.KIND_RECONCILE,
        mode=inputs.mode,
        actor=inputs.actor,
        host=inputs.host,
        path_flavour=_flavour(inputs.secrets_dir),
        install_dir=_canonical(inputs.install_dir),
        secrets_dir=_canonical(inputs.secrets_dir),
        registration_name=store.REGISTRATION_NAME,
        inspected_generation=inspected_generation,
        state=rec.PREPARED,
        remote_operation=None,
        prior_remote_present=prior.present,
        prior_remote_fingerprint=prior.fingerprint,
        prior_remote_backup=remote_backup,
        prior_remote_backup_sha256=remote_digest,
        attempted_fingerprint=attempted,
        local_present=local_before is not None,
        local_backup=local_backup,
        local_backup_sha256=local_digest,
        created_utc=_utc(),
    )
    try:
        rec.write_recovery(lifecycle_layout, record, lock=lock)
    except (rec.RecoveryEvidenceInvalid, OSError) as exc:
        _discard_backups(lifecycle_layout, operation_id)
        raise _PreparationRefused(
            "recovery_evidence_not_durable",
            f"the recovery record could not be published ({exc}); nothing was changed and no "
            "operation was opened") from exc
    return _Prepared(record=record, private_pem=private_pem, public_pem=public_pem, prior=prior,
                     stages_material=stages_material, operation=operation)


def _discard_backups(lifecycle_layout, operation_id: str) -> None:
    """Preparation failed and nothing was opened: its own inert files go, and nothing else."""
    from . import admin_identity_recovery as rec

    for suffix in rec.BACKUP_SUFFIXES:
        try:
            rec.backup_path(lifecycle_layout, operation_id, suffix).unlink(missing_ok=True)
        except (OSError, rec.RecoveryEvidenceInvalid):
            pass


def _flavour(path) -> str:
    from .schema import path_flavour

    return path_flavour(str(path))


def _canonical(path) -> str:
    from .schema import canonical_path

    return canonical_path(str(path), field_name="path")


def _utc() -> str:
    from .schema import utc_now_iso

    return utc_now_iso()


def _mutate(inputs, report, *, prepared, authority, api, layout, lifecycle_layout, lock, journal,
            operation_id, inspected_generation) -> ObservationReport:
    """STEP 5. The journal is open and the evidence is on disk; only now may anything change."""
    from dataclasses import replace as _replace

    from . import admin_identity_recovery as rec

    record = prepared.record
    prior = prepared.prior
    private_pem, public_pem = prepared.private_pem, prepared.public_pem
    attempted = record.attempted_fingerprint
    operation = prepared.operation

    journal.checkpoint(
        lock=lock, subsystem="admin_identity",
        intended_change=f"{report.state.value}: publish the registration",
        backups=[str(rec.recovery_path(lifecycle_layout))],
        resume_hint=("python -m corpusfm.lifecycle admin-identity abort --request <file> "
                     f"(operation {operation_id})"),
    )
    # The journal is now durable, so the record moves out of inert preparation and names what it is
    # about to do — before it does it.
    record = _replace(record, state=rec.OPEN, remote_operation=operation)
    rec.write_recovery(lifecycle_layout, record, lock=lock)

    staged = None
    if prepared.stages_material:
        staged = store.stage(
            inputs.secrets_dir,
            store.StoredIdentity(store.REGISTRATION_NAME, inputs.host, private_pem),
            layout=layout,
        )

    # Re-read the generation immediately before touching FileMaker Server: the window between the
    # first check and here is exactly where another lifecycle tool would have written.
    moved = _generation_moved(inputs, inspected_generation)
    if moved is not None:
        if staged is not None:
            store.discard_staged(inputs.secrets_dir, layout=layout)
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(("generation_divergence", moved))
        return report

    if operation == "add":
        ok, message = api.add_public_key(inputs.host, authority.user, authority.password,
                                         store.REGISTRATION_NAME, public_pem)
    else:
        ok, message = api.update_public_key(inputs.host, authority.user, authority.password,
                                            store.REGISTRATION_NAME, public_pem)

    if not ok:
        return _publish_failed(inputs, report, authority=authority, api=api, layout=layout,
                               lifecycle_layout=lifecycle_layout, lock=lock, record=record,
                               operation=operation, message=message, staged=staged, prior=prior,
                               attempted=attempted, private_pem=private_pem,
                               inspected_generation=inspected_generation)

    if not _authenticates(api, inputs.host, private_pem):
        # The remote change landed but the new pair does not authenticate. The OLD local material is
        # untouched — staging is what makes that true — and nothing is deleted.
        if staged is not None:
            store.discard_staged(inputs.secrets_dir, layout=layout)
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(
            ("registration_published_but_unproven",
             f"the {operation} reported success and the new pair did not authenticate; the previous "
             "local material is intact and nothing was deleted")
        )
        return report

    return _publish_succeeded(inputs, report, layout=layout, lifecycle_layout=lifecycle_layout,
                              lock=lock, record=record, staged=staged, private_pem=private_pem,
                              inspected_generation=inspected_generation)


def _publish_succeeded(inputs, report, *, layout, lifecycle_layout, lock, record, staged,
                       private_pem, inspected_generation) -> ObservationReport:
    """The registration is up and the pair authenticates. Promote, then AWAIT COMPOSITION."""
    from dataclasses import replace as _replace

    from . import admin_identity_recovery as rec

    if staged is not None:
        store.promote_staged(inputs.secrets_dir, layout=layout)
    moved = _generation_moved(inputs, inspected_generation)
    if moved is not None:
        # The remote and local halves agree, but the number this candidate would be composed against
        # has moved. Handing the integrator a candidate carrying a stale generation is how a
        # compare-and-swap silently discards someone else's write.
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(("generation_divergence_after_change", moved))
        return report
    rec.write_recovery(lifecycle_layout, _replace(record, state=rec.AWAITING_COMPOSITION),
                       lock=lock)
    report.result = COMPLETED
    report.state = IdentityState.WORKING
    report.awaiting_composition = True
    report.candidate = _candidate(inputs, report, layout=layout,
                                  inspected_generation=inspected_generation,
                                  fingerprint=store.fingerprint_of_private_pem(private_pem))
    report.next_action = (
        "Compose the returned candidate into the installation manifest, then run "
        f"`admin-identity finalize` for operation {record.operation_id}. The recovery evidence and "
        "the journal record stay in place until it does."
    )
    return report


def _generation_moved(inputs, inspected_generation: int) -> str | None:
    """``None`` when the on-disk generation still agrees; a reason string when it has moved."""
    try:
        actual, _ = _inspect_generation(inputs)
    except LifecycleError as exc:
        return f"the installation record could not be re-read ({exc})"
    if actual != inspected_generation:
        return (f"the installation record moved from generation {inspected_generation} to {actual} "
                "while this operation was running")
    return None


def _publish_failed(inputs, report, *, authority, api, layout, lifecycle_layout, lock, record,
                    operation, message, staged, prior, attempted, private_pem,
                    inspected_generation):
    """A refused Add or a failed Update — classified the SAME WAY, from what the registry now holds.

    **The result word turns on what the RE-OBSERVATION establishes about the REMOTE half**, not on
    whether a local temporary file was cleaned up, and not on which operation was attempted. Two
    earlier versions got this wrong in the same direction: one returned `rolled_back` whenever staged
    material had been discarded, and one restricted the "it landed anyway" reasoning to `update`, so
    an **Add** that landed while reporting failure returned `failed_before_change` — "the box is as
    it was" — for a registration that was up and whose private half had just been discarded.

    Three fingerprints are compared, never two: what was there before, what this operation tried to
    publish, and anything else. Nothing here deletes, and there is no delete-then-post fallback.
    """
    after = _remote_snapshot(inputs, authority, api=api)
    report.facts = IdentityFacts(
        prerequisite_established=report.facts.prerequisite_established,
        fms_presence=report.facts.fms_presence,
        local_material=report.facts.local_material,
        reachability=report.facts.reachability,
        local_authentication=report.facts.local_authentication,
        remote_registration=_axis_from(after, inputs, layout=layout),
    )
    if operation == "add" and "1708" in str(message):
        report.findings.append(
            ("name_present_key_unknown",
             "FileMaker Server refused the Add because the name is taken; that proves presence and "
             "nothing about whose key holds it. Re-observed with GET; no deletion was attempted.")
        )
    else:
        report.findings.append(
            (f"{operation}_failed",
             "the registration operation did not succeed; the registry was re-read with GET rather "
             "than assumed, and no delete-then-post fallback was used")
        )

    def _keep_staged(code: str, detail: str) -> ObservationReport:
        # Staged material is RETAINED whenever the attempted key might be up: discarding it would
        # destroy the private half of a registration that is live on FileMaker Server.
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append((code, detail))
        return report

    def _discard(code: str | None = None, detail: str = "") -> ObservationReport:
        if staged is not None:
            store.discard_staged(inputs.secrets_dir, layout=layout)
        report.result = FAILED_BEFORE_CHANGE
        if code:
            report.findings.append((code, detail))
        return report

    if not after.answered or (after.present and not after.readable):
        return _keep_staged(
            "remote_state_unverified",
            f"the {operation} failed and the registry could not be re-read; the prior registration "
            "may be intact or may already hold the attempted key. Nothing was deleted, and the "
            "staged material is retained because discarding it could destroy the private half of a "
            "live registration. Re-run once FileMaker Server answers.")

    if not after.present:
        if not prior.present:
            # Absent before, absent now: the prior state stands. Staging a temporary file is not
            # mutation (`result.py::classify_failure`), so nothing durable changed anywhere.
            return _discard()
        return _keep_staged(
            "prior_registration_unexpectedly_absent",
            f"the {operation} failed and the registration that was present beforehand is now gone; "
            "this operation deleted nothing, so something else removed it")

    if after.fingerprint == attempted:
        if _authenticates(api, inputs.host, private_pem):
            report.findings.append(
                (f"{operation}_landed_despite_failure",
                 f"the {operation} reported failure and the registry now holds the key it tried to "
                 "publish, and that pair authenticates; the operation is treated as completed")
            )
            return _publish_succeeded(
                inputs, report, layout=layout, lifecycle_layout=lifecycle_layout, lock=lock,
                record=record, staged=staged, private_pem=private_pem,
                inspected_generation=inspected_generation)
        return _keep_staged(
            f"{operation}_landed_but_unproven",
            f"the {operation} reported failure, the registry now holds the key it tried to publish, "
            "and that pair does not authenticate; the local material was not promoted")

    if prior.present and after.fingerprint == prior.fingerprint:
        # Re-observed and the prior registration stands unchanged, whichever operation was attempted.
        return _discard()

    return _keep_staged(
        "remote_holds_a_third_key",
        f"the {operation} failed and the registry holds neither the prior registration nor the key "
        "this operation tried to publish; nothing was deleted and nothing local was promoted")


def _axis_from(snapshot: RemoteSnapshot, inputs, *, layout) -> RemoteRegistration:
    """The classifier's axis, derived from a snapshot already in hand — no second GET."""
    if not snapshot.answered:
        return RemoteRegistration.INCONCLUSIVE
    if not snapshot.present:
        return RemoteRegistration.CONFIRMED_ABSENT
    if not snapshot.readable:
        return RemoteRegistration.INCONCLUSIVE
    identity = store.load(inputs.secrets_dir, layout=layout)
    if identity is None:
        return RemoteRegistration.CONFIRMED_PRESENT
    if snapshot.fingerprint == identity.public_fingerprint():
        return RemoteRegistration.CONFIRMED_MATCHING
    return RemoteRegistration.CONFIRMED_MISMATCH


def _well_formed_fingerprint(value: object) -> bool:
    """`sha256:<64 lowercase hex>` — the only shape §9.1 produces, and the only one a delete accepts."""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[len("sha256:"):]
    return len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def _self_authority(inputs, *, layout):
    """A WORKING identity removes itself by PKI — no admin password. ``None`` when it cannot.

    The FMS delete endpoint needs an authenticated session, and a working identity can mint one from
    material this box already holds, so an administrator prompt buys nothing on that path. What it
    returns is an `InstalledIdentityAuthority`, which has **no password attribute at all** — the
    lease-shaped predecessor presented `password == ""` and the adapter, not recognising it, offered
    that empty string to FileMaker Server as if it were a credential.
    """
    identity = store.load(inputs.secrets_dir, layout=layout)
    if identity is None:
        return None
    # THE FIXED NAME, never the stored one. The stored name becomes the JWT `iss`, so this is the
    # other place a poisoned store could aim a request — and "the path is unreachable today" is not
    # a reason to leave the wrong value in it. There is one registration per installation and its
    # name is fixed; the store's copy is evidence about it, not a second source for it.
    return InstalledIdentityAuthority(store.REGISTRATION_NAME, identity.private_pem)


def _authenticates(api, host: str, private_pem: bytes) -> bool:
    try:
        return api.authenticate(host, store.REGISTRATION_NAME, private_pem) is True
    except Exception:                             # noqa: BLE001
        return False


def _generate():
    from corpusfm.server.fms_admin_pki import generate_keypair

    return generate_keypair()


def _candidate(inputs, report, *, layout, inspected_generation: int,
               fingerprint: str | None = None) -> IdentityCandidate:
    """``inspected_generation`` is the number READ FROM THE MANIFEST, never the request's claim."""
    from .schema import utc_now_iso

    if fingerprint is None:
        identity = store.load(inputs.secrets_dir, layout=layout)
        fingerprint = identity.public_fingerprint() if identity else ""
    return IdentityCandidate(
        registration_name=store.REGISTRATION_NAME,
        public_fingerprint=fingerprint,
        last_observation=(report.state.value if report.state else ""),
        last_success_utc=utc_now_iso(),
        inspected_generation=inspected_generation,
        inspected_installation_id=inputs.installation_id,
    )


# ── removal ─────────────────────────────────────────────────────────────────

def remove(
    inputs: IdentityInputs,
    *,
    registration_name: str,
    public_fingerprint: str,
    lease: CredentialLease | None,
    api,
    probe=None,
    evidence=None,
    layout=None,
    lifecycle_layout=None,
    lock=None,
    journal=None,
) -> ObservationReport:
    """Remove the EXACT recorded registration, then the local material.

    Four preconditions, in order, then the delete, then a read-back proving absence. Any one of them
    unmet is a refusal — and an unmet precondition never becomes a name-only delete, which is the
    behaviour this contract replaces.

    **Deletion is TERMINAL and the bracket reflects that.** Intent is persisted before the DELETE so
    an interrupted run can be CLASSIFIED — there is nothing to restore, so ``abort`` on a removal
    decides what happened rather than putting anything back, and no removal ever reports
    ``rolled_back``.
    """
    from . import admin_identity_recovery as rec

    if lock is None or journal is None:
        raise IdentityOperationError(
            "remove mutates: it requires a held lifecycle lock and a journal, and an irreversible "
            "deletion without persisted intent is exactly the case recovery evidence exists for"
        )
    held = require_lock(lock, "removing the Admin-API machine identity")
    lifecycle_layout = lifecycle_layout if lifecycle_layout is not None else held.layout
    operation_id = str(uuid.uuid4())
    authority = _authority(lease)
    # THE SAME FACTS AND THE SAME CLASSIFICATION AS `observe`, AND NOT ITS MODE STEP. Removal asks
    # `plan_removal`; `apply_mode_policy` answers a question about reconciliation and is never
    # reached from here — which is a property of the call graph, not of a field being cleared.
    facts, exists = _collect_facts(inputs, api=api, probe=probe, evidence=evidence, layout=layout,
                                   credential=lease)
    report = _observed_report(facts, exists)
    report.unresolved_operation = _unresolved(lifecycle_layout)
    report.operation_id = operation_id

    try:
        inert = _assert_evidence_clear(lifecycle_layout, journal, lock=lock)
    except EvidenceNotClear as exc:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(("recovery_evidence_not_clear", str(exc)))
        return report
    if inert is not None:
        report.findings.append(
            ("inert_preparation_retired",
             f"operation {inert} published recovery evidence and never opened the journal, so it "
             "mutated nothing; its inert evidence was retired before this operation began"))

    if report.tag is Tag.NOT_APPLICABLE:
        # A LOCAL DELETION IS STILL A MUTATION. This branch used to call `remove_local` directly,
        # before any journal, any evidence and any lock check — so an interruption left material
        # half-removed with no account of it anywhere.
        return _local_cleanup_transaction(
            inputs, report, layout=layout, lifecycle_layout=lifecycle_layout, lock=lock,
            journal=journal, operation_id=operation_id, registration_name=registration_name,
            finding=("no_installed_registration_cleanup",
                     "no FileMaker Server is installed on this box, so no installed-registration "
                     "cleanup was applicable; nothing is claimed about any remote registration"))

    if report.tag is Tag.PREREQUISITE_REQUIRED:
        # A prerequisite failure is not an FMS condition, and saying "FileMaker Server did not
        # answer" about one is a false reason for a true refusal.
        report.result = NO_CHANGE
        report.findings.append(
            ("prerequisite_required",
             "the Machine Key authority has not been established, so the local material cannot be "
             "classified; nothing was removed and nothing is claimed about the remote registration")
        )
        return report

    if report.tag is Tag.INVALID_COMBINATION:
        # The observed facts contradict a stated relation. Nothing here may act on them.
        report.result = FAILED_BEFORE_CHANGE
        return report

    decision, observation, snapshot = _removal_decision(
        inputs, report, registration_name=registration_name,
        public_fingerprint=public_fingerprint, authority=authority, api=api, layout=layout)
    report.findings.append(("removal_plan", f"{decision.action.value}: {decision.reason}"))
    report.credentials_required = decision.admin_authority_required

    if decision.action is RemovalAction.NOTHING_TO_REMOVE:
        report.result = NO_CHANGE
        report.findings.append(
            ("nothing_to_remove",
             "no local material and no recorded registration; nothing was changed"))
        return report

    if decision.action is RemovalAction.PRESERVE_AND_REPORT:
        # NEVER `no_change`. `no_change` is a SUCCESS word, and reporting success for an uninstall
        # that left a registration standing is the exact defect this rewrite closes.
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(_preserve_finding(decision, snapshot, public_fingerprint))
        return report

    if decision.action is RemovalAction.ADMIN_AUTHORITY_REQUIRED:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("fms_authority_required",
             "the registration list has not been read and this box holds no identity that can read "
             "it; FMS admin authority is what completes this cleanup, for cleanup only"))
        return report

    if decision.action is RemovalAction.LOCAL_ONLY_CLEANUP:
        # Remote absence is ESTABLISHED (or no FMS is installed). Removing this installation's own
        # local material — including material that is present-but-unusable — is now licensed, and it
        # goes through the SAME intent/evidence/journal ordering as a remote deletion.
        return _local_cleanup_transaction(
            inputs, report, layout=layout, lifecycle_layout=lifecycle_layout, lock=lock,
            journal=journal, operation_id=operation_id, registration_name=registration_name,
            finding=("remote_registration_confirmed_absent",
                     "the recorded registration is not present, so this installation's own local "
                     "material was the only thing left to clean up"))

    # A DELETE is planned. Only now does the recorded pair have to be usable, because only now is it
    # about to authorize something. (A malformed record could not have produced PRESENT_MATCHING, so
    # this is a belt-and-braces refusal rather than the only guard.)
    if not _well_formed_fingerprint(public_fingerprint):
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("recorded_fingerprint_unusable",
             f"the recorded fingerprint {public_fingerprint!r} is not a sha256:<64 hex> value; "
             "refusing to delete on a pair this installation cannot vouch for"))
        return report

    delete_authority = authority
    if decision.action is RemovalAction.DELETE_WITH_INSTALLED_IDENTITY:
        # The identity deletes itself BY PKI. The authority it gets has no password field to leave
        # empty, and an administrator prompt buys nothing on this path.
        delete_authority = _self_authority(inputs, layout=layout)
    if delete_authority is None:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("fms_authority_required",
             "removing this exact registration requires FMS admin authority, for cleanup only"))
        return report

    # INTENT IS PERSISTED BEFORE THE DELETE, and the journal opens only once it is durable. A crash
    # between the DELETE and the local cleanup is otherwise indistinguishable from a crash before
    # either, and the two owe opposite work.
    try:
        record = _removal_record(inputs, operation_id=operation_id,
                                 registration_name=registration_name, remote_operation="delete",
                                 prior_fingerprint=snapshot.fingerprint, layout=layout)
        record = _open_removal(record, lifecycle_layout=lifecycle_layout, lock=lock,
                               journal=journal, inputs=inputs, operation_id=operation_id,
                               intended=f"delete the exact registration {registration_name}",
                               remote_operation="delete")
    except (rec.RecoveryEvidenceInvalid, OSError) as exc:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("recovery_evidence_not_durable",
             f"the deletion's intent could not be recorded ({exc}); nothing was deleted"))
        return report
    try:
        deleted, message = _delete_key(api, inputs.host, delete_authority, registration_name)
        ok_after, after, _m = _get_keys(api, inputs.host, delete_authority)
        still_there = ok_after and any(e.get("name") == registration_name for e in after)
        if not deleted or not ok_after or still_there:
            report.result = MANUAL_ACTION_REQUIRED
            report.findings.append(
                ("removal_not_verified",
                 f"the delete reported {message!r} and the read-back did not prove absence; the "
                 "local material is preserved")
            )
        else:
            store.remove_local(inputs.secrets_dir, layout=layout)
            report.result = COMPLETED
            report.findings.append(
                ("exact_registration_removed",
                 "the exact recorded registration was deleted on a name and fingerprint match, "
                 "proven absent by read-back, and the local material was removed to match"))
    except BaseException:
        journal.mark_needs_recovery(
            lock=lock, reason=f"admin-identity removal {operation_id} was interrupted")
        raise
    if report.result == COMPLETED:
        journal.resolve(lock=lock, result=report.result)
        rec.clear_recovery(lifecycle_layout, lock=lock)
    else:
        journal.mark_needs_recovery(
            lock=lock, reason=f"admin-identity removal {operation_id} ended {report.result}")
    return report


def _removal_record(inputs, *, operation_id, registration_name, remote_operation,
                    prior_fingerprint, layout):
    """A removal's evidence. It captures no before-image, because a deletion restores nothing —
    what it buys is CLASSIFIABILITY: a later process can tell what an interruption achieved."""
    from . import admin_identity_recovery as rec

    return rec.IdentityRecovery(
        operation_id=operation_id,
        installation_id=inputs.installation_id,
        kind=rec.KIND_REMOVE,
        mode=inputs.mode,
        actor=inputs.actor,
        host=inputs.host,
        path_flavour=_flavour(inputs.secrets_dir),
        install_dir=_canonical(inputs.install_dir),
        secrets_dir=_canonical(inputs.secrets_dir),
        registration_name=registration_name,
        inspected_generation=_inspect_generation(inputs)[0],
        state=rec.PREPARED,
        remote_operation=None,
        prior_remote_present=remote_operation is not None,
        prior_remote_fingerprint=prior_fingerprint if remote_operation is not None else None,
        local_present=store.store_exists(inputs.secrets_dir, layout=layout),
        created_utc=_utc(),
    )


def _open_removal(record, *, lifecycle_layout, lock, journal, inputs, operation_id, intended,
                  remote_operation):
    """STEPS 3 → 4 → the OPEN flip, in that order, for every deleting branch of `remove`."""
    from dataclasses import replace as _replace

    from . import admin_identity_recovery as rec

    rec.write_recovery(lifecycle_layout, record, lock=lock)
    journal.begin(lock=lock, operation_id=operation_id,
                  installation_id=inputs.installation_id, mode=inputs.mode)
    journal.checkpoint(
        lock=lock, subsystem="admin_identity", intended_change=intended,
        backups=[str(rec.recovery_path(lifecycle_layout))],
        resume_hint=("python -m corpusfm.lifecycle admin-identity abort --request <file> "
                     f"(operation {operation_id})"),
    )
    opened = _replace(record, state=rec.OPEN, remote_operation=remote_operation)
    rec.write_recovery(lifecycle_layout, opened, lock=lock)
    return opened


def _local_cleanup_transaction(inputs, report, *, layout, lifecycle_layout, lock, journal,
                               operation_id, registration_name, finding):
    """Remove this installation's own local material, bracketed exactly like a remote deletion.

    There is nothing to restore — the point of the bracket is that an interruption is CLASSIFIABLE
    in a later process rather than invisible.
    """
    from . import admin_identity_recovery as rec

    code, detail = finding
    if not store.store_exists(inputs.secrets_dir, layout=layout):
        report.result = NO_CHANGE
        report.findings.append((code, detail))
        return report

    try:
        record = _removal_record(inputs, operation_id=operation_id,
                                 registration_name=registration_name, remote_operation=None,
                                 prior_fingerprint=None, layout=layout)
        record = _open_removal(record, lifecycle_layout=lifecycle_layout, lock=lock,
                               journal=journal, inputs=inputs, operation_id=operation_id,
                               intended="remove this installation's local identity material",
                               remote_operation=None)
    except (rec.RecoveryEvidenceInvalid, OSError) as exc:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("recovery_evidence_not_durable",
             f"the cleanup's intent could not be recorded ({exc}); nothing was removed"))
        return report

    try:
        removed = store.remove_local(inputs.secrets_dir, layout=layout)
    except BaseException:
        journal.mark_needs_recovery(
            lock=lock, reason=f"admin-identity local cleanup {operation_id} was interrupted")
        raise
    report.result = COMPLETED if removed else NO_CHANGE
    # BOTH halves of the finding are emitted. The code used to be discarded and only the detail
    # survived, so `no_installed_registration_cleanup` and `remote_registration_confirmed_absent`
    # were evidence-shaped code that appeared in no result anybody could read.
    report.findings.append((code, detail))
    report.findings.append(("local_material_removed" if removed else "no_local_material",
                            "this installation's own local identity material"))
    journal.resolve(lock=lock, result=report.result)
    rec.clear_recovery(lifecycle_layout, lock=lock)
    return report


def _preserve_finding(decision, snapshot, public_fingerprint):
    """One truthful finding per preservation reason. TOTAL over them, with no default.

    A default was the defect: `fms_presence_unknown` fell through to the divergence text, so a box
    whose *installation evidence* could not be read was told its fingerprints diverged — while the
    two fingerprints were identical, printed side by side in the same sentence. A false reason for a
    true refusal is the rule the prerequisite branch above states in as many words, and this is the
    same mistake in the same file.
    """
    mapping = {
        "fms_unreachable": (
            "pending_remote_cleanup",
            "FileMaker Server did not answer; the local material and a pending record are "
            "preserved, and the remote registration is NOT claimed removed. No credential is "
            "requested, because no password makes an unreachable server answer."),
        "fms_presence_unknown": (
            "fms_presence_unreadable",
            "this box's FileMaker Server installation evidence could not be read, so it is unknown "
            "whether a server — and therefore a registration — is there at all. Nothing was "
            "removed, nothing is claimed about any remote registration, and no credential is "
            "requested: an unreadable answer is not an absent FileMaker Server."),
        "registry_unreadable": (
            "get_unavailable_no_delete",
            "the registration list could not be read; refusing to delete by name alone"),
        "registration_is_not_ours": (
            "fingerprint_divergence_no_delete",
            f"the observed registration fingerprints {snapshot.fingerprint or 'unreadably'} and "
            f"the record says {public_fingerprint}; refusing to delete, and requesting no "
            "credential for an act this contract forbids"),
    }
    try:
        return mapping[decision.reason]
    except KeyError:                               # pragma: no cover - a guard against a new reason
        raise IdentityOperationError(
            f"no preservation finding is defined for {decision.reason!r}; a preserved removal must "
            "say truthfully why, and a new reason must be given its own words rather than "
            "inheriting another's"
        ) from None


def _removal_decision(inputs, report, *, registration_name, public_fingerprint, authority, api,
                      layout):
    """Observe with the BEST authority this box has, then decide. Never consults a mode permit.

    The authority order matters: an administrator credential when one was supplied, otherwise the
    installed identity when it can authenticate. A box with neither cannot read the registry, and
    that is a distinct fact from an unreadable one — `NOT_ATTEMPTED` versus `UNREADABLE`.
    """
    identity = store.load(inputs.secrets_dir, layout=layout)
    local = report.facts.local_material
    authenticates = report.facts.local_authentication is LocalAuthentication.SUCCEEDED
    matches_record = bool(
        identity is not None
        and _well_formed_fingerprint(public_fingerprint)
        and identity.public_fingerprint() == public_fingerprint
    )

    look_with = authority
    if look_with is None and authenticates:
        look_with = _self_authority(inputs, layout=layout)

    snapshot = RemoteSnapshot(answered=False, present=False, readable=False)
    if look_with is None:
        observation = RemoteObservation.NOT_ATTEMPTED
    else:
        snapshot = _remote_snapshot(inputs, look_with, api=api,
                                    registration_name=registration_name)
        if not snapshot.answered:
            observation = RemoteObservation.UNREADABLE
        elif not snapshot.present:
            observation = RemoteObservation.ABSENT
        elif not snapshot.readable:
            observation = RemoteObservation.PRESENT_DIVERGENT
        elif (_well_formed_fingerprint(public_fingerprint)
              and snapshot.fingerprint == public_fingerprint):
            observation = RemoteObservation.PRESENT_MATCHING
        else:
            observation = RemoteObservation.PRESENT_DIVERGENT

    facts = RemovalFacts(
        presence=report.facts.fms_presence,
        reachable=report.facts.reachability is Reachability.ANSWERED,
        local=local,
        local_matches_record=matches_record,
        local_authenticates=authenticates,
        observation=observation,
    )
    return plan_removal(facts), observation, snapshot


# ── composition and discharge ───────────────────────────────────────────────

def _terminal_evidence(report, lifecycle_layout, *, lock, journal, operation_id,
                       installation_id):
    """`None` when the operation is live; a finished report when the journal has already spoken.

    Called FIRST by `abort` and `finalize`, and consulted by the new-operation precondition, so a
    crash between `journal.resolve` and `clear_recovery` is discharged idempotently instead of
    sending a mutating verb back out to FileMaker Server.
    """
    from . import admin_identity_recovery as rec

    try:
        verdict, result, detail = rec.discharge_terminal_evidence(
            lifecycle_layout, lock=lock, journal=journal, operation_id=operation_id,
            installation_id=installation_id)
    except rec.PreparationNotDischargeable as exc:
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(("terminal_evidence_not_dischargeable", str(exc)))
        return report
    if verdict is rec.NOT_TERMINAL or verdict == rec.NOT_TERMINAL:
        return None
    report.result = result
    report.findings.append(("terminal_result_already_recorded", detail))
    report.next_action = "Nothing is owed: the lifecycle journal already recorded this operation."
    return report


def _load_operation(lifecycle_layout, *, operation_id: str, installation_id: str):
    """The recovery record IF it is evidence about THIS operation and THIS installation.

    A file being present is not evidence. Every field a caller could otherwise supply — the host,
    the install dir, the secrets dir, the generation, the backups — comes off this record, so a
    record that is not ours must never be reached.
    """
    from . import admin_identity_recovery as rec

    record = rec.read_recovery(lifecycle_layout)
    if record.operation_id != operation_id:
        raise rec.RecoveryEvidenceInvalid(
            f"the stored recovery record is for operation {record.operation_id!r}, not "
            f"{operation_id!r}")
    if record.installation_id != installation_id:
        raise rec.RecoveryEvidenceInvalid(
            "the stored recovery record belongs to a different installation")
    return record


def finalize(
    *,
    operation_id: str,
    installation_id: str,
    committed_generation: int,
    actor: str,
    lifecycle_layout,
    lock,
    journal,
) -> ObservationReport:
    """Retire the evidence a composed operation no longer needs — after PROVING it was composed.

    It takes the lifecycle lock. The frame said finalize takes neither lock nor journal; that was
    wrong and is corrected here (Codex, 2026-08-05): finalize RESOLVES shared recovery evidence and
    deletes the backups an abort would restore from, so two of them running at once is a lost
    restore point. Serialization is not optional for a step that destroys the way back.

    Four checks, all of them against the manifest the integrator actually wrote — never against what
    the request claims: the operation, the installation, the committed generation
    (``inspected_generation + 1``, exactly), and that the published PKI block IS the candidate.
    """
    from . import admin_identity_recovery as rec
    from .manifest import ManifestStore

    # THE LOCK IS PROVEN FIRST — before the evidence is even READ. It used to be proven by
    # `journal.resolve`, the LAST thing this function does, so every check and every read happened
    # outside the guarantee. Reading shared recovery authority is already an act that must be
    # serialized against the abort that would restore from it.
    require_lock(lock, "finalizing an admin-identity operation")
    report = _bare_report(operation_id)
    # A MATCHING RESOLVED JOURNAL IS TERMINAL. Nothing below may run over it.
    terminal = _terminal_evidence(report, lifecycle_layout, lock=lock, journal=journal,
                                  operation_id=operation_id, installation_id=installation_id)
    if terminal is not None:
        return terminal
    record = _load_operation(lifecycle_layout, operation_id=operation_id,
                             installation_id=installation_id)
    if record.kind != rec.KIND_RECONCILE:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("not_a_composed_operation",
             f"operation {operation_id} is a {record.kind}; there is no candidate to finalize and "
             "its evidence is discharged by abort, which classifies rather than composes"))
        return report
    if record.state != rec.AWAITING_COMPOSITION:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("operation_not_awaiting_composition",
             f"operation {operation_id} is in state {record.state!r}; only an operation that proved "
             "its new pair has a candidate to compose"))
        return report
    if committed_generation != record.inspected_generation + 1:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("committed_generation_unexpected",
             f"the operation inspected generation {record.inspected_generation}, so the composed "
             f"manifest must be at {record.inspected_generation + 1}, not {committed_generation}"))
        return report

    manifest_store = ManifestStore(record.install_dir)
    if not manifest_store.exists():
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("nothing_composed",
             f"no installation manifest at {record.install_dir}; the candidate was never written, "
             "so the evidence that would restore this box is retained"))
        return report
    manifest = manifest_store.read()
    problems = []
    if manifest.installation_id != installation_id:
        problems.append("the composed manifest belongs to a different installation")
    if manifest.generation != committed_generation:
        problems.append(f"the composed manifest is at generation {manifest.generation}, "
                        f"not {committed_generation}")
    if manifest.pki.registration_name != record.registration_name:
        problems.append("the composed manifest records a different registration name")
    if manifest.pki.public_fingerprint != record.attempted_fingerprint:
        problems.append("the composed manifest records a different public fingerprint than the "
                        "candidate this operation proved")
    if problems:
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(("composition_unverified", "; ".join(problems)))
        return report

    journal.resolve(lock=lock, result=COMPLETED)
    rec.clear_recovery(lifecycle_layout, lock=lock)
    report.result = COMPLETED
    report.next_action = "Nothing further is owed for this operation."
    report.findings.append(
        ("composition_verified",
         f"the manifest at generation {committed_generation} records the candidate this operation "
         "proved; the recovery evidence and its backups were retired"))
    return report


def abort(
    *,
    operation_id: str,
    installation_id: str,
    actor: str,
    lease: CredentialLease | None,
    api,
    lifecycle_layout,
    lock,
    journal,
    layout=None,
) -> ObservationReport:
    """Discharge an unresolved operation from ITS OWN evidence. No caller-supplied paths.

    A reconcile is RESTORED; a removal is CLASSIFIED, because a deletion has no way back and
    pretending otherwise would produce the one word this vocabulary must never emit for it.
    """
    from . import admin_identity_recovery as rec

    # THE LOCK IS PROVEN FIRST — before the evidence is read, before a credential is used, before
    # FileMaker Server is contacted, and before anything is restored or retired. `journal.resolve`
    # used to be the first thing that noticed a bad lock, by which point an abort had already
    # deleted a registration and rewritten local material.
    require_lock(lock, "aborting an admin-identity operation")
    report = _bare_report(operation_id)
    # A MATCHING RESOLVED JOURNAL IS TERMINAL — checked before the record is interpreted, before a
    # credential is touched, and long before FileMaker Server is contacted. This is the one that
    # mattered: `abort` used to run the whole restore and only then raise on `resolved -> resolved`.
    terminal = _terminal_evidence(report, lifecycle_layout, lock=lock, journal=journal,
                                  operation_id=operation_id, installation_id=installation_id)
    if terminal is not None:
        return terminal
    record = _load_operation(lifecycle_layout, operation_id=operation_id,
                             installation_id=installation_id)
    inputs = _inputs_from(record)

    # A PREPARED record proves no PRODUCT mutation was reached — a record only leaves PREPARED in
    # the same lock-held step that publishes OPEN before the first mutation. It proves nothing about
    # the JOURNAL, and the two are discharged together or not at all.
    if record.state == rec.PREPARED:
        try:
            rec.discharge_preparation(lifecycle_layout, lock=lock, journal=journal,
                                      operation_id=operation_id, installation_id=installation_id)
        except rec.PreparationNotDischargeable as exc:
            report.result = MANUAL_ACTION_REQUIRED
            report.findings.append(("preparation_not_dischargeable", str(exc)))
            return report
        report.result = NO_CHANGE
        report.findings.append(
            ("inert_preparation_retired",
             "the operation published its evidence before reaching any mutation; any owed journal "
             "was resolved FIRST and the inert evidence was retired afterwards. Nothing was "
             "restored, because nothing was changed."))
        return report

    # EVERY backup this record names is re-verified against its recorded digest BEFORE anything is
    # restored from any of them. A truncated or replaced backup must never reach the store.
    try:
        rec.verify_backups(lifecycle_layout, record)
    except rec.BackupUnusable as exc:
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(
            ("backup_unusable",
             f"{exc} — nothing was restored, nothing was deleted, and the evidence is retained"))
        return report

    # THE MANIFEST IS READ FIRST — before any mutation, before a credential is used, and before any
    # evidence is retired. An abort that does not ask whether the candidate was already COMPOSED
    # will happily undo a published operation and then destroy the evidence of it: measured, a
    # composed reconcile was rolled back on both halves, leaving the manifest recording one
    # fingerprint and the registry holding another, with nothing left to reconcile them from.
    verdict, detail = _composition_verdict(record)
    if verdict == "composed":
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("candidate_already_composed",
             f"{detail} — this operation's candidate is already recorded in the installation "
             "manifest, so there is nothing to abort. Nothing was changed and the evidence is "
             "retained for `finalize`."))
        return report
    if verdict == "divergent":
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(
            ("composition_state_divergent",
             f"{detail} — the installation record neither matches the state this operation started "
             "from nor records its candidate, so it is not safe to restore or to retire anything. "
             "Nothing was changed and the evidence is retained."))
        return report

    authority = _authority(lease)
    if authority is None and record.remote_operation is not None:
        # Restoration and classification both need the registry read. Refusing BEFORE touching
        # anything, with the evidence retained, is the only honest answer.
        report.result = FAILED_BEFORE_CHANGE
        report.findings.append(
            ("fms_authority_required",
             f"discharging operation {operation_id} reaches FileMaker Server; supply the "
             "administrator credential frame. Nothing was changed and the evidence is retained."))
        return report

    if record.kind == rec.KIND_REMOVE:
        return _abort_removal(report, record, inputs, authority=authority, api=api, layout=layout,
                              lifecycle_layout=lifecycle_layout, lock=lock, journal=journal)
    return _abort_reconcile(report, record, inputs, authority=authority, api=api, layout=layout,
                            lifecycle_layout=lifecycle_layout, lock=lock, journal=journal)


def _composition_verdict(record) -> tuple[str, str]:
    """``("pre_composition" | "composed" | "divergent", detail)`` — read-only, no lock of its own.

    **A missing manifest is handled EXPLICITLY, not treated as permission.** On a first installation
    (`inspected_generation == 0`) there genuinely is no record yet and abort may proceed. A missing
    manifest where the operation inspected a LATER generation means the record this operation was
    composed against has gone, which nothing here may restore over.
    """
    from . import admin_identity_recovery as rec
    from .manifest import ManifestStore

    if not record.install_dir:
        return "pre_composition", "the operation records no installation directory"
    manifest_store = ManifestStore(record.install_dir)
    if not manifest_store.exists():
        if record.inspected_generation == 0:
            return "pre_composition", "no installation manifest exists yet (first publication)"
        return ("divergent",
                f"no installation manifest at {record.install_dir}, but this operation inspected "
                f"generation {record.inspected_generation}")
    try:
        manifest = manifest_store.read()
    except LifecycleError as exc:
        return "divergent", f"the installation manifest could not be read ({exc})"

    if manifest.installation_id != record.installation_id:
        return "divergent", "the installation manifest belongs to a different installation"

    if manifest.generation == record.inspected_generation:
        return ("pre_composition",
                f"the manifest is still at generation {manifest.generation}, the state this "
                "operation started from")

    if record.kind == rec.KIND_REMOVE:
        # A removal composes no candidate, so a moved generation is somebody else's write.
        return ("divergent",
                f"the manifest moved to generation {manifest.generation} during a removal")

    composed = (
        manifest.generation == record.inspected_generation + 1
        and manifest.pki.registration_name == record.registration_name
        and manifest.pki.public_fingerprint == record.attempted_fingerprint
    )
    if composed:
        return "composed", f"the manifest is at generation {manifest.generation}"
    return ("divergent",
            f"the manifest is at generation {manifest.generation} and records "
            f"{manifest.pki.public_fingerprint!r} for {manifest.pki.registration_name!r}")


def _abort_reconcile(report, record, inputs, *, authority, api, layout, lifecycle_layout, lock,
                     journal):
    from . import admin_identity_recovery as rec

    if record.remote_operation is None:
        # Nothing reached FileMaker Server. Only the local half can be out of step.
        _restore_local(record, inputs, layout=layout, lifecycle_layout=lifecycle_layout)
        journal.resolve(lock=lock, result=ROLLED_BACK)
        rec.clear_recovery(lifecycle_layout, lock=lock)
        report.result = ROLLED_BACK
        report.findings.append(
            ("local_state_restored",
             "the operation stopped before reaching FileMaker Server; the local material was "
             "restored to its before-image"))
        return report

    current = _remote_snapshot(inputs, authority, api=api)
    if not current.answered:
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(
            ("remote_state_unverified",
             "the registry could not be read, so nothing may be restored or deleted on the strength "
             "of a guess; the evidence is retained and this is re-runnable"))
        return report

    if record.remote_operation == "add":
        if not current.present:
            _restore_local(record, inputs, layout=layout, lifecycle_layout=lifecycle_layout)
            return _resolved(report, record, lifecycle_layout, lock, journal, ROLLED_BACK,
                             ("registration_absent_local_restored",
                              "the added registration is not present; the local material was "
                              "restored to its before-image"))
        if not current.readable or current.fingerprint != record.attempted_fingerprint:
            report.result = MANUAL_ACTION_REQUIRED
            report.findings.append(
                ("registration_is_not_ours_no_delete",
                 "the registration under this name is not the one this operation added; refusing to "
                 "delete a registration this installation did not create"))
            return report
        deleted, message = _delete_key(api, inputs.host, authority, record.registration_name)
        after = _remote_snapshot(inputs, authority, api=api)
        if not deleted or not after.answered or after.present:
            report.result = MANUAL_ACTION_REQUIRED
            report.findings.append(
                ("removal_not_verified",
                 f"the delete reported {message!r} and the read-back did not prove absence; the "
                 "local material and the evidence are preserved"))
            return report
        _restore_local(record, inputs, layout=layout, lifecycle_layout=lifecycle_layout)
        return _resolved(report, record, lifecycle_layout, lock, journal, ROLLED_BACK,
                         ("added_registration_removed",
                          "the registration this operation added was removed on an exact name and "
                          "fingerprint match, proven absent by read-back, and the local material was "
                          "restored"))

    # An update. The prior registration is restored by PATCHing back the captured bytes — never by
    # deleting, which would leave the box with no remote identity at all.
    if not record.prior_remote_backup:
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(
            ("prior_registration_not_captured",
             "the registration this operation replaced was not captured, so it cannot be restored; "
             "refusing to delete instead. A human must reconcile the registry."))
        return report
    prior_material = rec.read_backup(lifecycle_layout, record.operation_id, rec.REMOTE_BEFORE,
                                     expected_sha256=record.prior_remote_backup_sha256)
    ok, message = api.update_public_key(inputs.host, authority.user, authority.password,
                                        record.registration_name, prior_material)
    after = _remote_snapshot(inputs, authority, api=api)
    if not ok or not after.answered or not after.present or not after.readable or \
            after.fingerprint != record.prior_remote_fingerprint:
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(
            ("prior_registration_not_restored",
             f"restoring the previous registration reported {message!r} and the read-back did not "
             "prove it back in place; the local material and the evidence are preserved"))
        return report
    _restore_local(record, inputs, layout=layout, lifecycle_layout=lifecycle_layout)
    return _resolved(report, record, lifecycle_layout, lock, journal, ROLLED_BACK,
                     ("prior_registration_restored",
                      "the previous registration was restored by exact-name update, proven by "
                      "read-back, and the local material was restored to its before-image"))


def _abort_removal(report, record, inputs, *, authority, api, layout, lifecycle_layout, lock,
                   journal):
    """A deletion cannot be undone, so this CLASSIFIES what the interrupted removal achieved."""
    from . import admin_identity_recovery as rec

    if record.remote_operation is None:
        # A LOCAL-ONLY cleanup. Nothing remote was ever in scope, so the registry is not read and no
        # credential is owed: the local half alone says what happened.
        if store.store_exists(inputs.secrets_dir, layout=layout):
            return _resolved(report, record, lifecycle_layout, lock, journal, NO_CHANGE,
                             ("local_cleanup_did_not_proceed",
                              "the interrupted local cleanup removed nothing; the material is "
                              "still here"))
        return _resolved(report, record, lifecycle_layout, lock, journal, COMPLETED,
                         ("local_cleanup_completed",
                          "the interrupted local cleanup had already removed this installation's "
                          "material; nothing further is owed"))

    current = _remote_snapshot(inputs, authority, api=api)
    local_there = store.store_exists(inputs.secrets_dir, layout=layout)
    if not current.answered:
        report.result = MANUAL_ACTION_REQUIRED
        report.findings.append(
            ("remote_state_unverified",
             "the registry could not be read, so it is unknown whether the removal completed; the "
             "local material and the evidence are retained"))
        return report
    if current.present and current.readable and \
            current.fingerprint == record.prior_remote_fingerprint and local_there:
        return _resolved(report, record, lifecycle_layout, lock, journal, NO_CHANGE,
                         ("removal_did_not_proceed",
                          "the exact registration is still present and the local material is still "
                          "here; the interrupted removal changed nothing"))
    if not current.present and local_there:
        store.remove_local(inputs.secrets_dir, layout=layout)
        return _resolved(report, record, lifecycle_layout, lock, journal, COMPLETED,
                         ("removal_completed_locally",
                          "the registration is proven absent, so the interrupted removal had already "
                          "deleted it; the local material was cleaned up to match"))
    if not current.present and not local_there:
        return _resolved(report, record, lifecycle_layout, lock, journal, COMPLETED,
                         ("removal_already_complete",
                          "the registration is proven absent and no local material remains"))
    report.result = MANUAL_ACTION_REQUIRED
    report.findings.append(
        ("removal_state_divergent",
         "the registry holds something other than the registration this removal recorded, or the "
         "two halves disagree; the evidence is retained and nothing was deleted"))
    return report


def _resolved(report, record, lifecycle_layout, lock, journal, result, finding):
    from . import admin_identity_recovery as rec

    journal.resolve(lock=lock, result=result)
    rec.clear_recovery(lifecycle_layout, lock=lock)
    report.result = result
    report.findings.append(finding)
    return report


def _restore_local(record, inputs, *, layout, lifecycle_layout) -> None:
    """Put the local half back exactly as it was — bytes, or absence."""
    from . import admin_identity_recovery as rec

    store.discard_staged(inputs.secrets_dir, layout=layout)
    if record.local_present and record.local_backup_sha256:
        store.write_store_bytes(
            inputs.secrets_dir,
            rec.read_backup(lifecycle_layout, record.operation_id, rec.LOCAL_BEFORE,
                            expected_sha256=record.local_backup_sha256),
            layout=layout)
    elif not record.local_present:
        store.remove_local(inputs.secrets_dir, layout=layout)


def _inputs_from(record) -> IdentityInputs:
    """Everything an abort acts on comes off the RECORD. No caller-supplied path reaches here."""
    return IdentityInputs(
        installation_id=record.installation_id,
        expected_generation=record.inspected_generation,
        install_dir=Path(record.install_dir) if record.install_dir else Path("."),
        fms_root=Path("."),
        secrets_dir=Path(record.secrets_dir),
        host=record.host,
        mode=record.mode or "uninstall",
        actor=record.actor,
    )


def _bare_report(operation_id: str) -> ObservationReport:
    """A report for a verb that does not classify identity state — only the operation's outcome."""
    facts = IdentityFacts(
        prerequisite_established=False,
        fms_presence=FmsPresence.UNKNOWN,
        local_material=LocalMaterial.UNCLASSIFIED,
        reachability=Reachability.NOT_APPLICABLE,
        local_authentication=LocalAuthentication.NOT_ATTEMPTED,
        remote_registration=RemoteRegistration.NOT_OBSERVED,
    )
    return ObservationReport(tag=Tag.IDENTITY_OBSERVATION, facts=facts, result=NO_CHANGE,
                             operation_id=operation_id)


__all__ = [
    "CREDENTIAL_TRANSPORTS",
    "BasicAdminAuthority",
    "CredentialFrameRefused",
    "CredentialLease",
    "GenerationDivergence",
    "IdentityCandidate",
    "IdentityInputs",
    "IdentityOperationError",
    "InstalledIdentityAuthority",
    "ObservationReport",
    "RemoteSnapshot",
    "abort",
    "finalize",
    "observe",
    "reconcile",
    "remove",
]
