"""The CORPUSfm storage identity: facts, classification and a pure plan (packet 1246-08).

The subject is *this installation's corpus and the one credential that reaches it* — a thing that is
present or absent, reachable or not, initialized or not, ours or somebody else's. The previous
generation of this code was named for an EVENT (``run_bootstrap``) and took its policy from switches
its caller set, which is how a narrow credential repair came to pass ``do_init_settings=True``.

Three properties this module exists to hold:

* **Eleven axes, independent by construction.** In particular there are THREE probe axes — the
  promoted secret, the shipped bootstrap default, and a staged candidate — because those are three
  facts that can be true at once. One ``Authentication`` value cannot represent them, and a
  classifier that separates states on an ordering the axis never licensed is guessing.
* **Classification never reads the lifecycle journal.** The journal is shared by eight lifecycle
  modes (``schema.LIFECYCLE_MODES``); an interrupted *proxy* operation is not evidence about
  storage. Operation evidence is a separate, strictly parsed storage record — see
  ``storage_identity_recovery``.
* **``plan`` is pure.** It reads no disk, no journal and no network. A planner that silently
  depended on on-disk state could not be reasoned about by the operation that consumes it.

The classifier is an ORDERED FIRST MATCH and it is TOTAL: every combination of axis values yields
exactly one state, or a named relational refusal raised before classification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import LifecycleError
from .schema import LIFECYCLE_MODES, StorageBlock, utc_now_iso

#: The fixed storage database. NOT a parameter, NOT a request key, NOT derived from a config file.
STORAGE_DATABASE_NAME = "CORPUSfm_DB"
STORAGE_DATABASE_FILENAME = "CORPUSfm_DB.fmp12"

#: The subdirectory of the main FMS Databases directory that holds the corpus.
STORAGE_SUBDIRECTORY = "CORPUSfm"

#: The one FileMaker account CORPUSfm authenticates as. Least privilege; never ``[Full Access]``.
AUTOMATION_ACCOUNT = "CORPUSfm-Automation"

#: The local/offline ``[Full Access]`` recovery account. CORPUSfm never knows or stores its password.
RECOVERY_ACCOUNT = "CORPUSfm-Admin"

#: FileMaker's fresh-file convention: the initial password IS the account name. This is the value
#: the administrator restores in FileMaker Pro before ``repair-storage-access`` can act (§10.4), and
#: the value a shipped template arrives on.
BOOTSTRAP_SECRET = AUTOMATION_ACCOUNT

#: Modes in which this component may be invoked. A narrower set than LIFECYCLE_MODES: this component
#: has nothing to do during a proxy transaction or a code-only update.
MODES: tuple[str, ...] = ("fresh_install", "forward_update", "repair_storage_access", "uninstall")


class StorageIdentityError(LifecycleError):
    """Anything this component refuses that is not an ordinary reported state."""


class RelationViolated(StorageIdentityError):
    """Observed facts violate a relation that must hold. Refused by NAME, never classified."""


# ── axis vocabularies ────────────────────────────────────────────────────────


class FmsPresence(str, Enum):
    INSTALLED = "installed"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class DatabaseKnown(str, Enum):
    KNOWN = "known"
    NOT_KNOWN = "not_known"
    UNKNOWN = "unknown"


class TargetFile(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class HostedState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class LocalMaterial(str, Enum):
    ABSENT = "absent"
    USABLE = "usable"
    UNUSABLE = "unusable"
    #: The pre-Machine-Key answer. "No record is stored" and "the record cannot be decrypted yet"
    #: are indistinguishable before the prerequisite, and must not be reported as either.
    UNCLASSIFIED = "unclassified"


class ProbeFact(str, Enum):
    """One secret, one answer.

    ``INCONCLUSIVE`` is deliberately NOT merged into ``REFUSED``. A 401 is evidence that a secret is
    wrong; a timeout is evidence about the network. Collapsing them is how a blip becomes "the
    credential is broken" and then becomes a rotation nobody needed.
    """

    NOT_ATTEMPTED = "not_attempted"
    ACCEPTED = "accepted"
    REFUSED = "refused"
    INCONCLUSIVE = "inconclusive"


class Reachability(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class SettingsState(str, Enum):
    INITIALIZED = "initialized"
    EMPTY = "empty"
    MISSING = "missing"
    UNKNOWN = "unknown"


class UserTable(str, Enum):
    EMPTY = "empty"
    NON_EMPTY = "non_empty"
    UNKNOWN = "unknown"


class ManifestExpectation(str, Enum):
    EXPECTS_CORPUS = "expects_corpus"
    NO_EXPECTATION = "no_expectation"
    UNREADABLE = "unreadable"


class OperationEvidence(str, Enum):
    """Storage-specific. Derived from a strict storage record, cross-checked against the journal."""

    NONE = "none"
    MATCHING_OPEN = "matching_open"
    MATCHING_RESOLVED = "matching_resolved"
    #: The journal is unresolved but no matching storage record exists — an interrupted proxy, PKI,
    #: patch, recovery or updater operation. NEVER storage evidence.
    FOREIGN_OPEN = "foreign_open"
    UNREADABLE = "unreadable"


class OperationPhase(str, Enum):
    """Ordered. A resume continues from exactly one; an abort undoes exactly what precedes it."""

    PREPARED = "prepared"
    TEMPLATE_PLACED = "template_placed"
    HOSTED = "hosted"
    SETTINGS_INITIALIZED = "settings_initialized"
    IDENTITY_ESTABLISHED = "identity_established"
    ROTATION_ATTEMPTED = "rotation_attempted"
    CANDIDATE_PROVEN = "candidate_proven"
    AWAITING_COMPOSITION = "awaiting_composition"
    RESOLVED = "resolved"


PHASE_ORDER: tuple[str, ...] = tuple(p.value for p in OperationPhase)


class StorageState(str, Enum):
    PREREQUISITE_REQUIRED = "prerequisite_required"
    FMS_ABSENT = "fms_absent"
    FMS_UNREACHABLE = "fms_unreachable"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    INDETERMINATE = "indeterminate"
    EXISTING_CORPUS_UNREADABLE = "existing_corpus_unreadable"
    CANDIDATE_PROVEN = "candidate_proven"
    EXISTING_CORPUS_UNINITIALIZED = "existing_corpus_uninitialized"
    EXISTING_CORPUS_ON_DEFAULT = "existing_corpus_on_default"
    EXISTING_CORPUS_REACHABLE = "existing_corpus_reachable"
    PROVEN_FRESH = "proven_fresh"


#: The four bounded same-name traces. A trace is a CONFLICT with a ruled destination, not an
#: ambiguity — which is why the search is bounded to the databases directory and its immediate
#: children rather than being a filesystem walk for a filename.
CONFLICT_HOSTED_ELSEWHERE = "hosted_elsewhere"
CONFLICT_FILE_OUTSIDE_TARGET = "file_outside_target"
CONFLICT_RESIDUE_BESIDE_TARGET = "residue_beside_target"
CONFLICT_TARGET_DIR_OCCUPIED = "target_dir_occupied"

_RESIDUE_SUFFIXES = (".bak", ".old", ".removed", "~")


# ── inputs, facts, plan ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class StorageInputs:
    """Everything the integrator supplies. Note what is ABSENT: no database name, no destination
    path, no credential path, no password. Those are derived or held, never chosen by a caller."""

    installation_id: str
    expected_generation: int
    install_dir: Path
    fms_root: Path
    fms_database_dir: Path
    secrets_dir: Path
    host: str
    mode: str
    actor: str

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise StorageIdentityError(
                f"mode {self.mode!r} is not one of {MODES}; this component is not invoked in it"
            )
        if self.mode not in LIFECYCLE_MODES:  # pragma: no cover - MODES is a subset by construction
            raise StorageIdentityError(f"mode {self.mode!r} is not a lifecycle mode")


def storage_target(fms_database_dir: Path | str) -> Path:
    """The ONE storage destination, DERIVED (packet 1246-08 §6.0, Codex ruling R7).

    ``<authoritative main FMS Databases directory>/CORPUSfm/CORPUSfm_DB.fmp12``. There is no
    request key that can move it, which is what makes the fresh-proof conjunction's target clause
    mean something on a box that has no manifest yet.
    """
    return Path(fms_database_dir) / STORAGE_SUBDIRECTORY / STORAGE_DATABASE_FILENAME


def storage_target_dir(fms_database_dir: Path | str) -> Path:
    return Path(fms_database_dir) / STORAGE_SUBDIRECTORY


@dataclass(frozen=True)
class StorageFacts:
    """Eleven independent axes plus two carried facts. No journal state, no operation state."""

    fms_presence: str
    database_known: str
    target_file: str
    hosted_state: str
    local_material: str
    promoted_probe: str
    default_probe: str
    candidate_probe: str
    odata: str
    settings_state: str
    user_table: str
    manifest_expectation: str
    conflicts: tuple[str, ...] = ()
    observed_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fms_presence": self.fms_presence,
            "database_known": self.database_known,
            "target_file": self.target_file,
            "hosted_state": self.hosted_state,
            "local_material": self.local_material,
            "promoted_probe": self.promoted_probe,
            "default_probe": self.default_probe,
            "candidate_probe": self.candidate_probe,
            "odata": self.odata,
            "settings_state": self.settings_state,
            "user_table": self.user_table,
            "manifest_expectation": self.manifest_expectation,
            "conflicts": list(self.conflicts),
            "observed_utc": self.observed_utc,
        }


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class PlannedChange:
    kind: str
    target: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "target": self.target, "detail": self.detail}


@dataclass(frozen=True)
class StoragePlan:
    inputs: StorageInputs
    facts: StorageFacts
    state: str
    changes: tuple[PlannedChange, ...] = ()
    findings: tuple[Finding, ...] = ()
    next_action: str = ""


@dataclass(frozen=True)
class StorageCandidate:
    """What 1246-04 composes into its ONE compare-and-swap manifest write. No write happens here."""

    storage: StorageBlock
    inspected_generation: int
    inspected_installation_id: str
    #: The EXACT removable paths this installation has accepted as its storage (packet 1000-17).
    #: `storage.database_name` is a NAME; without these, an uninstaller would have to derive a
    #: deletion target from an FMS root plus a name, which is inference — and inference is how a
    #: name search ends up inside FileMaker Server's own trash. Bootstrap accounts for the file it
    #: placed; adoption accounts for the exact hosted path whose identity and carried key it proved
    #: before composing. In both cases uninstall removes the installation's corpus and its RC data.
    owned_paths: tuple = ()

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "storage": self.storage.to_dict(),
            "inspected_generation": self.inspected_generation,
            "inspected_installation_id": self.inspected_installation_id,
        }
        if self.owned_paths:
            payload["ownership"] = [dict(e) for e in self.owned_paths]
        return payload


def storage_ownership_entries(*, database_path: str | None,
                              rc_paths: "tuple[str, ...]" = ()) -> tuple:
    """The storage provider's ownership additions, as plain dicts for the candidate.

    One database entry and one entry per RC path it caused. Both kinds are canonicalized and
    conflict-checked by `OwnershipEntry.from_dict` and the manifest validator; nothing here decides
    whether a path is ours — the CALLER must pass only the exact corpus path this installation has
    proved and accepted, plus that file's exact FileMaker RC path.
    """
    entries = []
    if database_path:
        entries.append({"ownership_class": "exact_resource", "kind": "storage_database_path",
                        "identifier": str(database_path)})
    for rc in rc_paths:
        entries.append({"ownership_class": "exact_resource", "kind": "storage_rc_path",
                        "identifier": str(rc)})
    return tuple(entries)


# ── relational validity ──────────────────────────────────────────────────────


_ATTEMPTED = (ProbeFact.ACCEPTED.value, ProbeFact.REFUSED.value, ProbeFact.INCONCLUSIVE.value)


def validate_relations(facts: StorageFacts) -> None:
    """Refuse an impossible combination by NAME, before anything classifies it.

    A combination that cannot occur is not a state; treating it as one manufactures an answer where
    the observation was broken.
    """
    attempted = [
        p for p in (facts.promoted_probe, facts.default_probe, facts.candidate_probe)
        if p in _ATTEMPTED
    ]
    if attempted and facts.odata == Reachability.UNREACHABLE.value:
        raise RelationViolated(
            "probe_without_reachability: a credential was probed against a server reported "
            "unreachable"
        )
    if facts.database_known == DatabaseKnown.KNOWN.value \
            and facts.fms_presence == FmsPresence.ABSENT.value:
        raise RelationViolated(
            "database_known_without_fms: FileMaker Server cannot know a database if it is absent"
        )
    if facts.hosted_state in (HostedState.OPEN.value, HostedState.CLOSED.value) \
            and facts.database_known != DatabaseKnown.KNOWN.value:
        raise RelationViolated(
            "hosted_state_without_known_database: a status is a property of a known database"
        )
    if facts.promoted_probe in _ATTEMPTED and facts.local_material != LocalMaterial.USABLE.value:
        raise RelationViolated(
            "promoted_probed_without_usable_material: the promoted secret cannot be probed until "
            "it has been read"
        )
    if facts.local_material != LocalMaterial.USABLE.value \
            and facts.promoted_probe != ProbeFact.NOT_ATTEMPTED.value:
        raise RelationViolated(
            "promoted_probe_without_material: unusable, absent or unclassified material cannot "
            "have been probed"
        )
    if facts.user_table != UserTable.UNKNOWN.value and not _any_accepted(facts):
        raise RelationViolated(
            "user_table_without_authentication: the USER table is read through the corpus"
        )


def _any_accepted(facts: StorageFacts) -> bool:
    return ProbeFact.ACCEPTED.value in (
        facts.promoted_probe, facts.default_probe, facts.candidate_probe
    )


def _any_inconclusive(facts: StorageFacts) -> bool:
    return ProbeFact.INCONCLUSIVE.value in (
        facts.promoted_probe, facts.default_probe, facts.candidate_probe
    )


def _all_attempted_refused(facts: StorageFacts) -> bool:
    attempted = [
        p for p in (facts.promoted_probe, facts.default_probe, facts.candidate_probe)
        if p in _ATTEMPTED
    ]
    return bool(attempted) and all(p == ProbeFact.REFUSED.value for p in attempted)


def _present(facts: StorageFacts) -> bool:
    return (
        facts.database_known == DatabaseKnown.KNOWN.value
        or facts.target_file == TargetFile.PRESENT.value
    )


# ── classification ───────────────────────────────────────────────────────────


def classify(facts: StorageFacts) -> str:
    """Ordered FIRST MATCH over facts alone. TOTAL: the last row catches everything.

    ``validate_relations`` runs first and raises; this function never sees an impossible point.
    """
    validate_relations(facts)

    if facts.local_material == LocalMaterial.UNCLASSIFIED.value:
        return StorageState.PREREQUISITE_REQUIRED.value
    if facts.fms_presence == FmsPresence.ABSENT.value:
        return StorageState.FMS_ABSENT.value
    if facts.odata != Reachability.REACHABLE.value:
        return StorageState.FMS_UNREACHABLE.value
    if facts.conflicts:
        return StorageState.CONFLICTING_EVIDENCE.value
    if (
        facts.fms_presence == FmsPresence.UNKNOWN.value
        or facts.database_known == DatabaseKnown.UNKNOWN.value
        or facts.target_file == TargetFile.UNKNOWN.value
        or (_present(facts) and not _any_accepted(facts) and _any_inconclusive(facts))
    ):
        return StorageState.INDETERMINATE.value
    if _present(facts) and _all_attempted_refused(facts):
        return StorageState.EXISTING_CORPUS_UNREADABLE.value
    if _present(facts) and facts.candidate_probe == ProbeFact.ACCEPTED.value:
        return StorageState.CANDIDATE_PROVEN.value
    if _present(facts) and _any_accepted(facts) and facts.settings_state in (
        SettingsState.EMPTY.value, SettingsState.MISSING.value
    ):
        # UNCONDITIONAL. A present, authenticable database with empty SETTINGS is either a
        # half-finished install or a corpus somebody emptied, and SETTINGS cannot tell them apart.
        # Initialization is reachable ONLY from an operation whose own record proves it placed the
        # file, which does not go through classification at all.
        return StorageState.EXISTING_CORPUS_UNINITIALIZED.value
    if (
        _present(facts)
        and facts.default_probe == ProbeFact.ACCEPTED.value
        and facts.settings_state == SettingsState.INITIALIZED.value
    ):
        return StorageState.EXISTING_CORPUS_ON_DEFAULT.value
    if (
        _present(facts)
        and facts.promoted_probe == ProbeFact.ACCEPTED.value
        and facts.settings_state == SettingsState.INITIALIZED.value
    ):
        return StorageState.EXISTING_CORPUS_REACHABLE.value
    if _proven_fresh_facts(facts):
        return StorageState.PROVEN_FRESH.value
    return StorageState.INDETERMINATE.value


#: The fact-side clauses of the fresh conjunction. Clauses 8 (operation evidence) and 9 (mode) are
#: NOT here: the first is on-disk state the operation layer reads, the second is an input. Keeping
#: them out is what lets ``plan`` stay pure.
FRESH_FACT_CLAUSES: tuple[str, ...] = (
    "fms_installed",
    "odata_reachable",
    "database_not_known",
    "target_file_absent",
    "no_conflicts",
    "manifest_not_expecting_corpus",
    "manifest_readable",
)


def fresh_clause_failures(facts: StorageFacts) -> tuple[str, ...]:
    """Which fact-side fresh clauses do NOT hold. Empty means all seven hold."""
    failures = []
    if facts.fms_presence != FmsPresence.INSTALLED.value:
        failures.append("fms_installed")
    if facts.odata != Reachability.REACHABLE.value:
        failures.append("odata_reachable")
    if facts.database_known != DatabaseKnown.NOT_KNOWN.value:
        failures.append("database_not_known")
    if facts.target_file != TargetFile.ABSENT.value:
        failures.append("target_file_absent")
    if facts.conflicts:
        failures.append("no_conflicts")
    if facts.manifest_expectation == ManifestExpectation.EXPECTS_CORPUS.value:
        failures.append("manifest_not_expecting_corpus")
    if facts.manifest_expectation == ManifestExpectation.UNREADABLE.value:
        failures.append("manifest_readable")
    return tuple(failures)


def _proven_fresh_facts(facts: StorageFacts) -> bool:
    return not fresh_clause_failures(facts)


def proven_fresh(facts: StorageFacts, *, mode: str, evidence: str) -> tuple[bool, tuple[str, ...]]:
    """The COMPLETE nine-clause conjunction. All nine, or no bootstrap.

    Returns ``(ok, failed_clause_names)``. There is no flag, consent form or ``--yes`` that turns a
    short conjunction into a bootstrap; the caller gets the failures so it can say which.
    """
    failures = list(fresh_clause_failures(facts))
    if evidence != OperationEvidence.NONE.value:
        failures.append("no_open_operation")
    if mode != "fresh_install":
        failures.append("mode_is_fresh_install")
    return (not failures, tuple(failures))


# ── the pure plan ────────────────────────────────────────────────────────────

_NEXT_ACTION: dict[str, str] = {
    StorageState.PREREQUISITE_REQUIRED.value:
        "Establish the published layout and the Machine Key, then observe again.",
    StorageState.FMS_ABSENT.value:
        "FileMaker Server was not found at the supplied installation root. Install or repair "
        "FileMaker Server first; CORPUSfm does not install it.",
    StorageState.FMS_UNREACHABLE.value:
        "FileMaker Server did not answer over OData. Confirm it is running and that the OData API "
        "is enabled, then run this step again.",
    StorageState.CONFLICTING_EVIDENCE.value:
        "Another CORPUSfm storage database was found outside the installation's own location. "
        "Nothing was changed. Resolve the conflict in FileMaker Server before continuing.",
    StorageState.INDETERMINATE.value:
        "The storage state could not be established. Nothing was changed. Re-run once FileMaker "
        "Server answers consistently.",
    StorageState.EXISTING_CORPUS_UNREADABLE.value:
        "The storage database exists but no known credential opens it.",
    StorageState.CANDIDATE_PROVEN.value:
        "A credential rotation is part-way through and its new value already works. Resume the "
        "recorded operation.",
    StorageState.EXISTING_CORPUS_UNINITIALIZED.value:
        "A storage database is present but its settings are not initialized. CORPUSfm will not "
        "initialize a database it did not create. Nothing was changed.",
    StorageState.EXISTING_CORPUS_ON_DEFAULT.value:
        "The automation account is on its default password. Run the storage-access repair to "
        "rotate it to a fresh value.",
    StorageState.EXISTING_CORPUS_REACHABLE.value:
        "Storage is reachable and the stored credential works. Nothing to do.",
    StorageState.PROVEN_FRESH.value:
        "No corpus exists on this machine. A fresh storage database can be created.",
}


def plan(facts: StorageFacts, inputs: StorageInputs) -> StoragePlan:
    """PURE. No disk, no journal, no network — derived from facts and inputs alone.

    The operation layer re-establishes facts under the lock and evaluates the operation-evidence
    clause itself; this exists so an integrator can SHOW a plan without performing one.
    """
    state = classify(facts)
    changes: list[PlannedChange] = []
    target = str(storage_target(inputs.fms_database_dir))
    if state == StorageState.PROVEN_FRESH.value and inputs.mode == "fresh_install":
        changes = [
            PlannedChange("place_template", target, "copy the shipped storage database"),
            PlannedChange("host", STORAGE_DATABASE_NAME, "host it and wait for OPEN"),
            PlannedChange("prove_build", target, "compare the database build marker"),
            PlannedChange("init_settings", STORAGE_DATABASE_NAME, "initialize the settings record"),
            PlannedChange("establish_identity", STORAGE_DATABASE_NAME,
                          "record the corpus identity and canary"),
            PlannedChange("rotate", AUTOMATION_ACCOUNT,
                          "rotate the automation password off its default"),
            PlannedChange("promote", str(inputs.secrets_dir),
                          "promote the proven credential record"),
        ]
    elif state == StorageState.EXISTING_CORPUS_ON_DEFAULT.value \
            and inputs.mode in ("repair_storage_access", "forward_update", "fresh_install"):
        changes = [
            PlannedChange("rotate", AUTOMATION_ACCOUNT,
                          "rotate the automation password off its default"),
            PlannedChange("promote", str(inputs.secrets_dir),
                          "promote the proven credential record"),
        ]
    findings = tuple(
        Finding("fresh_clause_unmet", c) for c in fresh_clause_failures(facts)
    ) if state != StorageState.PROVEN_FRESH.value and inputs.mode == "fresh_install" else ()
    return StoragePlan(
        inputs=inputs,
        facts=facts,
        state=state,
        changes=tuple(changes),
        findings=findings,
        next_action=_NEXT_ACTION[state],
    )


def next_action_for(state: str) -> str:
    return _NEXT_ACTION[state]


# ── conflict search ──────────────────────────────────────────────────────────


def find_conflicts(
    fms_database_dir: Path | str,
    hosted: tuple[dict, ...] | None,
) -> tuple[str, ...]:
    """The bounded same-name search of §6.0.

    Bounded to the databases directory and its immediate children ON PURPOSE: an unbounded walk for
    a filename is the "broad deletion derived from names" the parent's shared fences forbid, one
    operation earlier. What is searched here is what an uninstall could later be asked to act on.
    """
    root = Path(fms_database_dir)
    target_dir = storage_target_dir(root)
    target = storage_target(root)
    found: list[str] = []

    if hosted is not None:
        for entry in hosted:
            name = str(entry.get("filename") or entry.get("name") or "")
            if _same_database_name(name):
                folder = str(entry.get("folder") or "")
                if folder and not _folder_is_target(folder, target_dir):
                    found.append(CONFLICT_HOSTED_ELSEWHERE)
                    break

    try:
        if (root / STORAGE_DATABASE_FILENAME).exists():
            found.append(CONFLICT_FILE_OUTSIDE_TARGET)
        else:
            for child in sorted(root.iterdir()):
                if not child.is_dir() or child == target_dir:
                    continue
                if (child / STORAGE_DATABASE_FILENAME).exists():
                    found.append(CONFLICT_FILE_OUTSIDE_TARGET)
                    break
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        pass

    try:
        if target_dir.is_dir():
            extras = []
            for child in sorted(target_dir.iterdir()):
                if child == target:
                    continue
                lowered = child.name.lower()
                if lowered.startswith(STORAGE_DATABASE_FILENAME.lower()) and any(
                    lowered.endswith(s) for s in _RESIDUE_SUFFIXES
                ):
                    found.append(CONFLICT_RESIDUE_BESIDE_TARGET)
                    continue
                if _is_filemaker_rc_data(child, target):
                    continue
                extras.append(child.name)
            if extras:
                found.append(CONFLICT_TARGET_DIR_OCCUPIED)
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        pass

    # Deterministic and de-duplicated: a caller compares this tuple, and set order is not stable.
    order = (
        CONFLICT_HOSTED_ELSEWHERE,
        CONFLICT_FILE_OUTSIDE_TARGET,
        CONFLICT_RESIDUE_BESIDE_TARGET,
        CONFLICT_TARGET_DIR_OCCUPIED,
    )
    return tuple(name for name in order if name in found)


def _same_database_name(candidate: str) -> bool:
    value = candidate.strip()
    if value.lower().endswith(".fmp12"):
        value = value[:-6]
    return value.lower() == STORAGE_DATABASE_NAME.lower()


def _folder_is_target(folder: str, target_dir: Path) -> bool:
    """FMS reports folders in its own verbatim forms (``filelinux:/…/``, ``filewin:/…/``).

    Comparing the tail is deliberate: the prefix is a transport spelling, not a location, and a
    string comparison against the raw value reports a false conflict on every box.
    """
    cleaned = folder.strip().rstrip("/\\")
    for prefix in ("filelinux:", "filewin:", "filemac:", "file:"):
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix):]
            break
    cleaned = cleaned.replace("\\", "/").rstrip("/")
    wanted = str(target_dir).replace("\\", "/").rstrip("/")
    return cleaned.lower().endswith(wanted.lower()) or wanted.lower().endswith(cleaned.lower())


def _is_filemaker_rc_data(child: Path, target: Path) -> bool:
    """FileMaker's own per-database sidecar data, which belongs to the file this run placed."""
    name = child.name
    stem = target.stem
    return name.startswith(f"{stem}.") or name == f"{stem} Backups" or name.startswith("RC_Data")


__all__ = [
    "AUTOMATION_ACCOUNT",
    "BOOTSTRAP_SECRET",
    "RECOVERY_ACCOUNT",
    "STORAGE_DATABASE_NAME",
    "STORAGE_DATABASE_FILENAME",
    "STORAGE_SUBDIRECTORY",
    "MODES",
    "PHASE_ORDER",
    "DatabaseKnown",
    "Finding",
    "FmsPresence",
    "HostedState",
    "LocalMaterial",
    "ManifestExpectation",
    "OperationEvidence",
    "OperationPhase",
    "PlannedChange",
    "ProbeFact",
    "Reachability",
    "RelationViolated",
    "SettingsState",
    "StorageCandidate",
    "StorageFacts",
    "StorageIdentityError",
    "StorageInputs",
    "StoragePlan",
    "StorageState",
    "TargetFile",
    "UserTable",
    "classify",
    "find_conflicts",
    "fresh_clause_failures",
    "next_action_for",
    "plan",
    "proven_fresh",
    "storage_target",
    "storage_target_dir",
    "validate_relations",
]
