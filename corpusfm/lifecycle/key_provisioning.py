"""Provision this installation's two key files, from the privileged installer (packet 1246-10-03).

**Why this exists, measured.** The installers used to reach the keys by running
``crypto.get_corpus_key(); get_machine_key()`` *as the service account*, guarded by a test for
``$INSTALL_DIR/.corpusfm/{corpus,secret,machine,server}.key`` — the retired home. On a published
1246-03 installation the resolver answers the FIXED secrets directory, which is administrator-owned
and deliberately **not writable by the service**, so the Machine Key could not be created; the
installer downgraded that to *"created on first use"* and carried on, and phase 15 then refused with
``prerequisite_required: authoritative_machine_key``. There is no later first use — the runtime never
writes there. A fresh install could not complete.

So provisioning is the **privileged installer's** job, not an unprivileged runtime resolver's, and
this module is that operation. Its shape follows from the two keys being different in kind:

* **The Corpus Key is IRREPLACEABLE.** It interprets everything the corpus owns. Reuse and verify it
  when present; never overwrite it; never consult the retired ``secret.key``. When it is absent, the
  question is not *may I make one* but *is there a corpus that would be lost by making one* — so
  absence is FATAL beside any existing or hosted database, and generation requires POSITIVE proof
  that no database exists. The proof is positive on purpose: "I looked and found nothing" only counts
  when the looking succeeded, so a directory that could not be read refuses rather than passing.
* **The Machine Key is REPLACEABLE.** It protects box-local material its owning packets recreate.
  Reuse and verify when present; generate at the fixed published path when absent.

**One policy, not two.** Ownership and modes come from :mod:`protection` — the secrets directory
administrator-owned and not group-writable, each key ``root:<service group>`` at ``0640`` on POSIX
and a protected DACL on Windows. Restating that here would be a second authority to drift from.

**The last step is the one that matters.** Establishing bytes and permissions proves what this
operation did; it does not prove the application can get the key. So it finishes by calling the REAL
published resolvers — ``crypto.get_corpus_key()`` and ``crypto.get_machine_key()`` — and requires
they return the exact on-disk bytes. Anything less is a command mistaken for a state, which is the
defect this module replaces.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import LifecycleError

#: The two current names, from ``crypto`` so there is one authority for what these files are called.
#: The retired ``secret.key`` / ``server.key`` are deliberately absent and are never consulted here.
from corpusfm.core import crypto as _crypto

CORPUS_KEY = _crypto.CORPUS_KEY_FILENAME
MACHINE_KEY = _crypto.MACHINE_KEY_FILENAME

#: A Fernet key is 32 random bytes, urlsafe-base64 encoded. Exactly 44 characters, no newline.
FERNET_KEY_LENGTH = 44

REUSED = "reused"
GENERATED = "generated"

#: The web app's signing secret. NOT a Fernet key — `secrets.token_hex(32)`, the format
#: `app.web.auth._session_secret` already reads — so it goes through its own establisher rather than
#: `_validate_key_bytes`. It is REPLACEABLE: regenerating it costs every live session a re-login and
#: nothing else, so the Corpus Key's absence rules do not apply to it.
#:
#: The APPLICATION must never create it (packet 1246-10-04). The unit runs `ProtectSystem=strict`
#: with the secrets directory read-only, so the app's own first-use generation raised
#: `OSError: [Errno 30] Read-only file system` and the web service exited 1 on every start —
#: measured on fms-server 2026-08-08. `protection.READ_ONLY_SECRETS` already named this file, so the
#: policy and the runtime agreed all along; what was missing is the privileged step that creates it.
SESSION_SECRET = "session_secret"
SESSION_SECRET_BYTES = 32


class KeyProvisioningFailed(LifecycleError):
    """Every failure here is fatal to the install. There is no partial success to carry forward."""


@dataclass(frozen=True)
class CorpusProof:
    """Positive evidence about whether a corpus already exists. ``proven_empty`` is never a default.

    ``unreadable`` is why this is a dataclass rather than a boolean: a directory we could not read is
    not an absence, and collapsing the two is how a fresh key gets minted beside a corpus that is
    already encrypted under another one.
    """

    searched: tuple[str, ...]
    found: tuple[str, ...]
    unreadable: tuple[str, ...]

    @property
    def proven_empty(self) -> bool:
        return not self.found and not self.unreadable

    def describe(self) -> str:
        if self.found:
            return f"an existing database is present: {', '.join(self.found)}"
        if self.unreadable:
            return (f"these locations could not be read, so no corpus could be ruled out: "
                    f"{', '.join(self.unreadable)}")
        return f"no database exists under any of: {', '.join(self.searched) or '(nothing searched)'}"


@dataclass(frozen=True)
class KeyResult:
    name: str
    action: str
    path: str


@dataclass(frozen=True)
class ProvisionReport:
    keys: tuple[KeyResult, ...]
    secrets_dir: str
    corpus_proof: CorpusProof | None

    def payload(self) -> dict:
        return {
            "result": "completed",
            "secrets_dir": self.secrets_dir,
            "keys": [{"name": k.name, "action": k.action, "path": k.path} for k in self.keys],
            "corpus_evidence": (
                None if self.corpus_proof is None else {
                    "searched": list(self.corpus_proof.searched),
                    "found": list(self.corpus_proof.found),
                    "unreadable": list(self.corpus_proof.unreadable),
                    "proven_empty": self.corpus_proof.proven_empty,
                }
            ),
        }


def prove_no_corpus(database_name: str, search_dirs) -> CorpusProof:
    """Look for an existing CORPUSfm database. Report what was found AND what could not be read.

    A missing directory is a genuine absence — there is nothing there. A directory that raises is
    not: it is an unanswered question, and it lands in ``unreadable`` so the caller refuses.

    **The walk is explicit, and it has to be.** The first version used ``Path.rglob``, and its own
    control caught what that costs: ``pathlib``'s globbing SWALLOWS permission errors, so a directory
    the installer cannot read comes back looking empty. That turns "I could not tell" into "proven
    empty" — the one conversion this function exists to prevent, and the one that would mint a fresh
    Corpus Key beside an unreadable corpus.
    """
    stem = Path(str(database_name)).stem.casefold()
    if not stem:
        raise KeyProvisioningFailed(
            "the corpus proof needs the database name; an empty name can rule nothing out")

    searched: list[str] = []
    found: list[str] = []
    unreadable: list[str] = []

    for raw in search_dirs:
        directory = Path(str(raw))
        searched.append(str(directory))
        try:
            if not directory.exists():
                continue
            if not directory.is_dir():
                unreadable.append(f"{directory} (not a directory)")
                continue
        except OSError as exc:
            unreadable.append(f"{directory} ({exc})")
            continue
        _walk(directory, stem, found, unreadable)

    return CorpusProof(tuple(searched), tuple(sorted(set(found))), tuple(sorted(set(unreadable))))


def _walk(directory: Path, stem: str, found: list, unreadable: list) -> None:
    """Depth-first, with every failure RECORDED rather than skipped. Symlinked dirs are not followed.

    Not following links is not tidiness: a link out of the search set would let the answer depend on
    somewhere nobody named, and a cycle would never terminate.

    ``Removed_by_FMS`` is FileMaker Server's removal quarantine, not a hosted database location.
    A database retained there is not an existing corpus and must not block a fresh installation.
    """
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        unreadable.append(f"{directory} ({exc})")
        return
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                if entry.name.casefold() == "removed_by_fms":
                    continue
                _walk(Path(entry.path), stem, found, unreadable)
            elif entry.is_file(follow_symlinks=False) and entry.name.casefold().endswith(".fmp12") \
                    and Path(entry.name).stem.casefold() == stem:
                found.append(entry.path)
        except OSError as exc:
            unreadable.append(f"{entry.path} ({exc})")


def _validate_key_bytes(raw: bytes, *, path: Path) -> bytes:
    """Exact length, then real Fernet syntax. Length first so the error names the cheap fault."""
    from cryptography.fernet import Fernet

    if len(raw) != FERNET_KEY_LENGTH:
        raise KeyProvisioningFailed(
            f"{path} holds {len(raw)} bytes; a key file must be exactly {FERNET_KEY_LENGTH} "
            "(urlsafe-base64 of 32 random bytes) with no trailing newline")
    try:
        Fernet(raw)
    except Exception as exc:                      # noqa: BLE001 - any rejection is the same verdict
        raise KeyProvisioningFailed(
            f"{path} is not a usable Fernet key: {exc}") from exc
    return raw


def _read_key(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise KeyProvisioningFailed(f"{path} exists and could not be read: {exc}") from exc


def _generate(path: Path) -> bytes:
    """Atomic, private at creation, then read back. A write that was not read back is a claim."""
    from cryptography.fernet import Fernet

    from .atomic import atomic_write_bytes

    key = Fernet.generate_key()
    _validate_key_bytes(key, path=path)
    try:
        # 0600 at creation: the file is administrator-only from the instant it exists, and the
        # protector below widens it to the service's read-only group access afterwards. The reverse
        # order — publish, then restrict — is readable by whoever gets there in between.
        atomic_write_bytes(path, key, mode=0o600)
    except OSError as exc:
        raise KeyProvisioningFailed(
            f"could not create {path}: {exc}. The privileged installer must be able to write the "
            "fixed secrets directory; nothing else provisions these files.") from exc

    written = _read_key(path)
    if written != key:
        raise KeyProvisioningFailed(
            f"{path} read back different bytes than were written; refusing to continue")
    return written


def _establish_one(path: Path, *, is_corpus: bool, proof_for_absent) -> KeyResult:
    if path.exists():
        _validate_key_bytes(_read_key(path), path=path)
        return KeyResult(path.name, REUSED, str(path))

    if is_corpus:
        proof = proof_for_absent()
        if not proof.proven_empty:
            raise KeyProvisioningFailed(
                f"the Corpus Key is missing at {path} and this is not a proven-new corpus — "
                f"{proof.describe()}. The Corpus Key is irreplaceable: generating one here would "
                "leave the existing corpus permanently unreadable. Restore the installation's own "
                "corpus.key, then re-run.")

    _generate(path)
    return KeyResult(path.name, GENERATED, str(path))


def _establish_session_secret(path: Path) -> KeyResult:
    """Reuse a non-empty value byte-for-byte; otherwise generate one. Never prints it.

    An EMPTY or whitespace-only file is treated as absent: the app strips what it reads, so an empty
    file yields an empty signing secret, which is worse than no file at all.
    """
    import secrets as _secrets

    from .atomic import atomic_write_bytes

    existing = b""
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise KeyProvisioningFailed(f"{path} exists and could not be read: {exc}") from exc
    if existing.strip():
        return KeyResult(path.name, REUSED, str(path))

    value = _secrets.token_hex(SESSION_SECRET_BYTES).encode("ascii")
    try:
        # 0600 at creation, for the same reason the keys are: administrator-only from the instant it
        # exists, widened to the service's read-only group access by the protector afterwards.
        atomic_write_bytes(path, value, mode=0o600)
    except OSError as exc:
        raise KeyProvisioningFailed(
            f"could not create {path}: {exc}. The privileged installer must be able to write the "
            "fixed secrets directory; the service may not create this file.") from exc

    if path.read_bytes() != value:
        raise KeyProvisioningFailed(
            f"{path} read back different bytes than were written; refusing to continue")
    return KeyResult(path.name, GENERATED, str(path))


def _protector(*, flavour: str, service_uid, service_gid, web_sid, scheduler_sid, protector,
               pre_service: bool = False):
    if protector is not None:
        return protector
    from .protection import platform_protector

    return platform_protector(service_uid=service_uid, service_gid=service_gid,
                              web_sid=web_sid, scheduler_sid=scheduler_sid,
                              pre_service=pre_service)


def provision(
    *,
    database_name: str,
    database_search_dirs,
    flavour: str,
    service_uid: int | None = None,
    service_gid: int | None = None,
    web_sid: str | None = None,
    scheduler_sid: str | None = None,
    pre_service: bool = False,
    protector=None,
    os_layout=None,
) -> ProvisionReport:
    """Establish both keys at the published location, protect them, and prove the resolvers agree.

    The secrets directory is NOT a parameter. There is exactly one location for this installation's
    keys and a caller-supplied path could only ever disagree with it, so it comes from published
    authority — and the platform layout must AGREE with it, which is what catches a record naming
    another installation's directory.

    **That authority is the RECORD, read here, not the ambient resolver** (packet 1000-07). The path
    used to come from `app_paths.secrets_dir()`, which answers from a per-process cache of "where is
    the layout" — the question a lifecycle operation establishing that layout cannot usefully ask,
    and the one `app_paths` documents itself as not serving. `read_published_installation()` runs the
    locator → manifest → identity-agreement chain and returns the recorded location as a fact, so the
    provisioned path is the one the installation published rather than one this process happened to
    have resolved earlier. A record that exists and cannot be read consistently still REFUSES; it
    never falls back.
    """
    from . import app_paths
    from . import os_layout as ol
    from . import published as pub

    try:
        published = app_paths.is_published()
    except Exception as exc:                      # noqa: BLE001 - indeterminate is not unpublished
        raise KeyProvisioningFailed(
            f"whether this installation is published could not be established ({exc}); refusing to "
            "provision keys into a location that cannot be named") from exc
    if not published:
        raise KeyProvisioningFailed(
            "this installation publishes no record, so there is no authoritative secrets directory "
            "to provision into. The foundation must be published first.")
    try:
        secrets = pub.read_published_installation().secrets_dir
    except Exception as exc:                      # noqa: BLE001
        raise KeyProvisioningFailed(
            f"the published secrets directory could not be resolved: {exc}") from exc
    if not secrets:
        # A published record that names no secrets directory is contradictory, not a licence to pick
        # one: the platform layout below would then be the ONLY authority, and agreeing with itself
        # is not agreement.
        raise KeyProvisioningFailed(
            "the published record names no secrets directory; refusing to provision keys into a "
            "location the installation has not recorded")

    layout = os_layout if os_layout is not None else ol.platform_os_layout()
    if Path(layout.secrets_dir) != Path(secrets):
        raise KeyProvisioningFailed(
            f"the published record resolves secrets to {secrets} and this platform's fixed layout "
            f"is {layout.secrets_dir}; refusing to provision keys into a disputed location")

    if not Path(secrets).is_dir():
        raise KeyProvisioningFailed(
            f"{secrets} is not a directory; the privileged installer must create the fixed secrets "
            "directory before provisioning keys into it")

    results = [
        _establish_one(
            Path(secrets) / CORPUS_KEY, is_corpus=True,
            proof_for_absent=lambda: prove_no_corpus(database_name, database_search_dirs)),
        _establish_one(Path(secrets) / MACHINE_KEY, is_corpus=False, proof_for_absent=None),
        _establish_session_secret(Path(secrets) / SESSION_SECRET),
    ]

    prot = _protector(flavour=flavour, service_uid=service_uid, service_gid=service_gid,
                      web_sid=web_sid, scheduler_sid=scheduler_sid, protector=protector,
                      pre_service=pre_service)
    try:
        prot.apply(layout, stage="key_provisioning")
    except Exception as exc:                      # noqa: BLE001
        raise KeyProvisioningFailed(
            f"the provisioned keys could not be protected: {exc}") from exc
    problems = prot.verify(layout)
    if problems:
        raise KeyProvisioningFailed(
            "the provisioned keys are not protected as intended: " + "; ".join(problems))

    _assert_resolvers_agree(secrets)

    proof = None
    for result in results:
        if result.name == CORPUS_KEY and result.action == GENERATED:
            proof = prove_no_corpus(database_name, database_search_dirs)
    return ProvisionReport(tuple(results), str(secrets), proof)


def _assert_resolvers_agree(secrets) -> None:
    """The real published resolvers must return the exact on-disk bytes. Nothing else closes this.

    Reading the file here and calling that success would prove only that this module can read a file
    it just wrote. The question is whether the APPLICATION's resolver — the same one phase 15 and
    every service use — reaches the same bytes, so that resolver is the one asked.
    """
    from corpusfm.core import crypto

    crypto.reset_key_cache()
    for filename, resolver in ((CORPUS_KEY, crypto.get_corpus_key),
                               (MACHINE_KEY, crypto.get_machine_key)):
        path = Path(secrets) / filename
        on_disk = _read_key(path)
        try:
            resolved = resolver()
        except Exception as exc:                  # noqa: BLE001
            raise KeyProvisioningFailed(
                f"{filename} is provisioned at {path} and the published resolver could not return "
                f"it: {exc}") from exc
        if resolved != on_disk:
            raise KeyProvisioningFailed(
                f"the published resolver for {filename} returned bytes that are not the ones at "
                f"{path}; this installation would run against a different key than it provisioned")


def posix_service_ids(account: str) -> tuple[int, int]:
    """The service account's uid/gid, or a refusal naming the account. Never a guessed default."""
    import pwd

    try:
        entry = pwd.getpwnam(account)
    except KeyError as exc:
        raise KeyProvisioningFailed(
            f"the service account {account!r} does not exist; the installer must create it before "
            "provisioning keys it has to read") from exc
    return entry.pw_uid, entry.pw_gid


__all__ = [
    "CORPUS_KEY", "MACHINE_KEY", "FERNET_KEY_LENGTH", "REUSED", "GENERATED",
    "KeyProvisioningFailed", "CorpusProof", "KeyResult", "ProvisionReport",
    "prove_no_corpus", "provision", "posix_service_ids",
]
