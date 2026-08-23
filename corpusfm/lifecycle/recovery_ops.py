"""`corpusfm-recovery create` / `adopt` (packet 1246-02, deliverable 3).

Two operations, each with a stated postcondition on failure.

**create** — write a reusable password-protected copy of this corpus's Corpus Key.
It proves the local key actually opens this corpus before writing anything, writes the file
owner-only, then **reopens the bytes it just wrote and proves them against the live corpus**. A file
that was never reopened is a file nobody has evidence about; the whole point of the artifact is that
it will be used months later, alone, when nothing else survives.

**adopt** — install a Corpus Key carried by a Recovery File onto this installation.
The candidate key stays in memory until it has matched this corpus's identity and read real data.
A wrong password, a wrong corpus, an unsupported version or a failed verification changes **nothing
at all** — not the local key, not the Machine Key, not PKI, and not the Recovery File, which is
never consumed and never revoked by being used.

**What neither does.** Neither packages, moves, hosts or backs up the FileMaker database —
FileMaker owns that. Neither repairs automation access; adoption *requires* it and reports the exact
next action when it is missing, but repairing it belongs to 1246-08. Neither rotates a key.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from . import corpus_identity, recovery_format
from .errors import LifecycleError, RecordInvalid, RecordMissing
from .artifact_ownership import ownership_backend
from .atomic import atomic_write_bytes
from .recovery_format import RECOVERY_SUFFIX
from .schema import canonical_path, paths_overlap
from .result import COMPLETED, FAILED_BEFORE_CHANGE

# The administrator must knowingly hold both the file and its passphrase, so nothing here generates
# a passphrase, and nothing here creates a Recovery File on the administrator's behalf.
_OWNED_CLASSES = ("exclusive_tree",)

# `absent` is ESTABLISHED emptiness. `error` is an inability to look, and refuses.
VERIFY_OUTCOMES = ("absent", "readable", "unreadable", "error")

RECOVERY_FILE_MODE = 0o600
KEY_FILE_MODE = 0o600
KEY_DIR_MODE = 0o700


class RecoveryDestinationRefused(LifecycleError):
    """The requested output path is inside a tree that uninstall would remove."""


class RecoveryOutputExists(LifecycleError):
    """A file is already there. Replacing it needs a named decision, never bare consent."""


class WrongCorpus(LifecycleError):
    """The Recovery File belongs to a different corpus than this installation's."""


class AdoptionPreconditionMissing(LifecycleError):
    """The destination is not ready to adopt (no install, unreachable DB, or broken access)."""


@dataclass
class RecoveryResult:
    result: str
    path: str = ""
    corpus_id: str = ""
    detail: str = ""
    owner: str = ""             # who the artifact belongs to
    protection: str = ""        # what was VERIFIED to govern access, in the platform's own terms
    warning: str = ""           # stated when the answer is not the ideal one (direct-root, etc.)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def owned_trees(manifest) -> list[str]:
    """Every tree whose removal is uninstall's, from the manifest's own ownership record.

    Derived from what was recorded, never from a path's shape — "it looks like a CORPUSfm folder"
    is exactly the reasoning the parent packet forbids for removal, and a refusal that used it would
    be wrong in both directions.
    """
    trees = []
    for entry in getattr(manifest, "ownership", ()) or ():
        if entry.ownership_class in _OWNED_CLASSES and entry.kind in ("directory", "tree"):
            trees.append(entry.identifier)
    paths = getattr(manifest, "paths", None)
    if paths is not None and paths.install_dir:
        trees.append(paths.install_dir)
    return [t for t in trees if t]


def assert_destination_allowed(destination: Path | str, manifest) -> None:
    """A Recovery File inside an uninstall-owned tree is deleted by the very event it exists for."""
    target = canonical_path(str(destination), field_name="recovery destination")
    for tree in owned_trees(manifest):
        if paths_overlap(tree, target):
            raise RecoveryDestinationRefused(
                f"{target} is inside {tree}, which uninstall removes. A Recovery File must live "
                "somewhere CORPUSfm does not own — removable media, a backup share, a password "
                "manager's file store."
            )
    if not str(target).endswith(RECOVERY_SUFFIX):
        raise RecordInvalid(f"a Recovery File must be named *{RECOVERY_SUFFIX}")


def create_recovery_file(
    *,
    destination: Path | str,
    manifest,
    backend,
    corpus_key: bytes | str,
    password: str,
    replace_authorized: bool = False,
    now: Optional[Callable[[], str]] = None,
    ownership=None,
) -> RecoveryResult:
    """Prove, write, reopen, prove again.

    `replace_authorized` is the **named exceptional decision** for overwriting an existing file. It
    is deliberately not reachable from ordinary consent: `--yes` means "I accept the ordinary
    confirmations", and destroying somebody's only copy of a corpus key is not one of those.
    """
    destination = Path(destination)
    assert_destination_allowed(destination, manifest)
    recovery_format.assert_passphrase_acceptable(password)

    # 1. Prove the LOCAL key opens THIS corpus before writing anything. Without this the file is a
    #    guess: it would faithfully preserve a key that opens nothing.
    record = corpus_identity.require_identity(backend)
    corpus_identity.assert_key_opens(record, corpus_key)
    corpus_id = record["corpus_id"]

    if destination.exists() and not replace_authorized:
        raise RecoveryOutputExists(
            f"{destination} already exists. Replacing a Recovery File may destroy the only copy of "
            "a Corpus Key; that needs an explicit replacement decision, not ordinary confirmation."
        )

    payload = recovery_format.build_recovery_file(
        corpus_key=corpus_key,
        corpus_id=corpus_id,
        password=password,
        created_utc=(now or _now_utc)(),
    )

    # Hold the file being replaced — its BYTES **and** its owner and access protection. An
    # authorized replacement whose verification then fails must not leave the administrator with
    # neither the old file nor a working new one, and "the old file" means the whole thing: bytes
    # with somebody else's ownership are not the file that was there.
    ownership = ownership_backend() if ownership is None else ownership
    previous = None
    previous_protection = None
    if destination.exists():
        previous = destination.read_bytes()
        previous_protection = ownership.capture(destination)

    identity = ownership.invoking_identity()

    # NO `dir_mode`. The destination's parent is the ADMINISTRATOR's — a USB stick, a backup share,
    # a password manager's folder — and chmodding it would silently change the permissions of a
    # directory CORPUSfm does not own and cannot reason about. The parent is left exactly as found.
    #
    # Ownership and protection are established on the STAGED file, before the replace publishes it.
    # Securing it afterwards would leave a window in which the artifact exists at its final path
    # under whatever the parent directory grants — which, on an arbitrary destination, is the whole
    # problem. (Developer ruling 2026-08-02: the file belongs to the administrator who invoked the
    # command, not to the elevated process identity.)
    atomic_write_bytes(destination, payload.encode("utf-8"), mode=RECOVERY_FILE_MODE,
                       prepare=lambda staged: ownership.apply(staged, identity))

    # 2. Reopen the bytes that actually landed and prove them against the live corpus. Verifying the
    #    in-memory value would prove only that this process can talk to itself.
    try:
        written = recovery_format.read_recovery_file_bytes(destination)
        reopened = recovery_format.open_recovery_file(written, password)
        if reopened["corpus_id"] != corpus_id:
            raise RecordInvalid("the Recovery File was written but names a different corpus")
        corpus_identity.assert_key_opens(record, reopened["corpus_key"])
        # What actually governs access, read back from the published file rather than assumed from
        # what we asked for. On Windows this REFUSES if the DACL still inherits from the parent or
        # grants anyone beyond the owner and SYSTEM.
        protection = ownership.describe(destination)
    except Exception as exc:
        _restore_or_remove(destination, previous, previous_protection, ownership)
        raise _mark_rolled_back(exc) if previous is not None else exc

    return RecoveryResult(
        result=COMPLETED, path=str(destination), corpus_id=corpus_id,
        detail="reopened and verified against the live corpus",
        owner=protection.owner, protection=protection.detail,
        warning=identity.warning or "",
    )


def _restore_or_remove(destination: Path, previous: bytes | None,
                       protection=None, ownership=None) -> None:
    """Put back exactly what was there — bytes, owner and protection — including "nothing"."""
    if previous is None:
        if destination.exists():
            destination.unlink()
        return
    atomic_write_bytes(destination, previous, mode=RECOVERY_FILE_MODE)
    if protection is not None and ownership is not None:
        # Restoring only the bytes would hand the administrator's file to whoever this process is.
        ownership.restore(destination, protection)


def _mark_rolled_back(exc: BaseException) -> BaseException:
    """Tag an exception that followed a completed restore.

    The CLI reported every failure as `failed_before_change`. That is a different claim from
    `rolled_back` — the first says the machine was never touched, the second says it was touched and
    put back — and only the operation knows which happened. Reporting the reassuring one for both is
    the kind of inaccuracy an administrator acts on.
    """
    exc.lifecycle_mutated = True
    exc.lifecycle_restored = True
    return exc


@dataclass
class AdoptionCandidate:
    corpus_key: str
    corpus_id: str


def open_candidate(raw: bytes | str, password: str) -> AdoptionCandidate:
    """Authenticate the file and hold the key in memory only. Touches no installation state."""
    data = recovery_format.open_recovery_file(raw, password)
    return AdoptionCandidate(corpus_key=data["corpus_key"], corpus_id=data["corpus_id"])


def adopt_recovery_file(
    *,
    source: Path | str,
    backend,
    corpus_key_destination: Path | str,
    password: str,
    preconditions: Mapping[str, Any],
    verify_data: Callable[[str], str],
) -> RecoveryResult:
    """Install the carried Corpus Key, or change nothing.

    `preconditions` is what the caller established about the destination — an installed CORPUSfm, a
    reachable intended database, working automation access. They are *required*, and a missing one
    is reported with the exact next action; repairing it is 1246-08's, not this operation's.
    """
    source = Path(source)
    destination = Path(corpus_key_destination)

    missing = [k for k in ("installed", "database_reachable", "automation_access")
               if not preconditions.get(k)]
    if missing:
        raise AdoptionPreconditionMissing(
            "cannot adopt into this installation: " + ", ".join(sorted(missing)) +
            ". Adoption needs a complete installation, the intended database hosted and reachable, "
            "and working automation access — repair those first, then adopt."
        )

    try:
        raw = recovery_format.read_recovery_file_bytes(source)
    except FileNotFoundError as exc:
        raise RecordMissing(f"no Recovery File at {source}") from exc

    before = destination.read_bytes() if destination.exists() else None

    # Authenticate first; a wrong password never reaches installation state.
    candidate = open_candidate(raw, password)

    # Match THIS corpus. An empty corpus can still answer, which is the whole reason the identity
    # record exists — otherwise a fresh installation would accept any corpus's key.
    record = corpus_identity.require_identity(backend)
    if record["corpus_id"] != candidate.corpus_id:
        raise WrongCorpus(
            f"this Recovery File is for corpus {candidate.corpus_id}, and this installation's "
            f"corpus is {record['corpus_id']}. Nothing was changed."
        )
    corpus_identity.assert_key_opens(record, candidate.corpus_key)

    # Verify representative encrypted data BEFORE the local key is replaced.
    # Verification is REQUIRED, not an option a caller may omit. It was optional in the first
    # implementation and the shipped command did omit it, so the contract held only for tests —
    # exactly the gap an independent review found. A caller with genuinely nothing to read supplies
    # a probe that answers `absent`; it may not decline to answer.
    outcome = verify_data(candidate.corpus_key)
    # Vocabulary first, THEN the decision. Written the other way round, the unrecognised-outcome
    # check silently did the unreadable check's job too — a mutation that deleted the unreadable
    # branch still refused, so the branch was not independently load-bearing and the test that
    # claimed to guard it was passing for the wrong reason. Found by the mutation battery.
    if outcome not in VERIFY_OUTCOMES:
        raise RecordInvalid(f"data verification returned an unrecognised outcome {outcome!r}")
    if outcome == "error":
        raise RecordInvalid(
            "this corpus's stored data could not be read at all, so nothing was established about "
            "the carried key. That is not the same as an empty corpus. Nothing was changed."
        )
    if outcome == "unreadable":
        raise RecordInvalid(
            "the carried key matched this corpus's identity but did not read stored data. "
            "Nothing was changed."
        )

    try:
        # The key destination IS ours — a lifecycle-owned secrets directory — so its mode is ours
        # to establish. That is the difference from the Recovery File's parent above.
        atomic_write_bytes(destination, candidate.corpus_key.encode("ascii"),
                           mode=KEY_FILE_MODE, dir_mode=KEY_DIR_MODE)
        landed = destination.read_bytes().strip()
        if landed != candidate.corpus_key.encode("ascii"):
            raise RecordInvalid("the adopted key did not land byte for byte")
    except Exception as exc:
        _restore_or_remove(destination, before)
        raise _mark_rolled_back(exc) if before is not None else exc

    return RecoveryResult(result=COMPLETED, path=str(source), corpus_id=candidate.corpus_id,
                          detail="the Recovery File is unchanged and remains reusable")


def failed_before_change(detail: str) -> RecoveryResult:
    return RecoveryResult(result=FAILED_BEFORE_CHANGE, detail=detail)
