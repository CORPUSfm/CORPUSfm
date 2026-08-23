"""`corpusfm-recovery` — the administrator's Recovery File tool (packet 1246-02, deliverable 3).

    corpusfm-recovery create <path.cfmrecovery> [--replace-existing-file] [--verbose|--silent]
    corpusfm-recovery adopt  <path.cfmrecovery> [--verbose|--silent]
    corpusfm-recovery inspect <path.cfmrecovery>

**Elevated.** Both mutating verbs touch machine key material, so both demand elevation up front
rather than failing halfway through with a permission error.

**The passphrase is prompted, twice on create and once on adopt.** It never appears in argv, in an
environment variable, in the transcript, in a log line or in any lifecycle record — there is no flag
that accepts it, which is the only way to make that true rather than merely intended.

**`inspect` needs no passphrase and no installation, and everything it prints is an UNVERIFIED
CLAIM.** The header is authenticated as associated data, but nothing verifies that authentication
until a passphrase opens the AEAD — so an administrator holding an unlabelled file learns what it
*says* it is, which is enough to sort a drawer and not enough to act on. Saying it was answerable
"from the authenticated header alone" was false, and it is the kind of false that gets believed.

**`--replace-existing-file` is a named exceptional authorization, not consent.** `--yes` and
`--silent` mean "I accept the ordinary confirmations". Overwriting somebody's only copy of a Corpus
Key is not an ordinary confirmation, so no combination of ordinary flags can reach it.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Callable, Optional

from . import recovery_format
from .consent import Consent
from .errors import LifecycleError
from .output import OutputEngine
from .privilege import require_elevation
from .recovery_format import MIN_PASSPHRASE_LEN
from .result import COMPLETED, FAILED_BEFORE_CHANGE, classify_failure

PROMPT_CREATE = "  Recovery passphrase: "
PROMPT_CONFIRM = "  Confirm passphrase:  "
PROMPT_ADOPT = "  Recovery passphrase: "


class PassphraseMismatch(LifecycleError):
    """The two typed passphrases differ."""


def prompt_new_passphrase(reader: Optional[Callable[[str], str]] = None) -> str:
    """Twice, and they must match. A mistyped passphrase on create produces a file nobody can open,
    and the mistake is undiscoverable until the day it matters."""
    ask = reader or getpass.getpass
    first = ask(PROMPT_CREATE)
    recovery_format.assert_passphrase_acceptable(first)
    second = ask(PROMPT_CONFIRM)
    if first != second:
        raise PassphraseMismatch("the passphrases did not match — nothing was written")
    return first


def prompt_passphrase(reader: Optional[Callable[[str], str]] = None) -> str:
    return (reader or getpass.getpass)(PROMPT_ADOPT)


def _inspect(path: str, out: OutputEngine) -> int:
    header = recovery_format.read_header(recovery_format.read_recovery_file_bytes(path))
    out.discovery(f"claims to be for corpus {header['corpus_id']} (UNVERIFIED)")
    out.detail(f"claims it was created {header['created_utc']}")
    out.detail(
        f"claims protection by {header['kdf']['name']} "
        f"({header['kdf']['memory_kib']} KiB, {header['kdf']['iterations']} passes, "
        f"{header['kdf']['lanes']} lanes) and {header['cipher']['name']}"
    )
    out.warning(
        "None of this is verified. The header is authenticated, but nothing checks that "
        "authentication until a passphrase opens the file."
    )
    out.result(COMPLETED)
    return 0


# Both mutating verbs are lifecycle operations, and they were not treated as ones: they took no
# lock and opened no journal, so a `create` could run beside an installer or a key migration and
# neither would know. The lock makes them mutually exclusive; the journal makes an interrupted one
# visible afterwards instead of leaving a machine nobody can reason about.
_JOURNAL_MODES = {"create": "recovery_create", "adopt": "recovery_adopt"}


def _run_lifecycle_operation(args, consent: Consent, out: OutputEngine) -> int:
    """Hold the machine lifecycle lock, journal the operation, and report what actually happened.

    **The result word is derived, not assumed.** Every exception used to be reported as
    `failed_before_change`, which is a lie whenever something *was* changed and put back — that case
    is `rolled_back`, and the difference is exactly what an administrator needs in order to know
    whether to look at the machine. The operations themselves say which of the two they left behind.
    """
    from .layout import platform_layout
    from .session import lifecycle_operation

    layout = platform_layout()
    with lifecycle_operation(layout) as session:
        manifest, backend = _resolve_installation(out)
        operation_id = _new_operation_id()
        session.journal.begin(
            lock=session.lock,
            operation_id=operation_id,
            installation_id=manifest.installation_id,
            mode=_JOURNAL_MODES[args.verb],
        )
        try:
            if args.verb == "create":
                result = _create(args.path, manifest, backend, consent, out)
            else:
                result = _adopt(args.path, manifest, backend, out)
        except Exception as exc:
            # `mutated`/`restored` come from the operation, not from a guess. An exception carrying
            # `lifecycle_restored = True` says: something changed and was put back.
            outcome = classify_failure(
                mutated=bool(getattr(exc, "lifecycle_mutated", False)),
                restored=bool(getattr(exc, "lifecycle_restored", False)),
            )
            session.journal.resolve(lock=session.lock, result=outcome)
            out.failure(f"{type(exc).__name__}: {exc}")
            out.result(outcome)
            return 2
        session.journal.resolve(lock=session.lock, result=result.result)
        return 0


def _new_operation_id() -> str:
    import uuid
    return str(uuid.uuid4())


def _resolve_installation(out: OutputEngine):
    """The manifest this machine's locator points at, plus a storage backend for its corpus.

    Discovery goes through the lifecycle record and nowhere else. A tool that could find an
    installation some other way — a well-known path, an environment variable — would be a second
    authority over installation topology, which is the whole thing packet 1246 exists to remove.
    """
    from .layout import platform_layout
    from .locator import locator_for
    from .manifest import ManifestStore
    from .schema import assert_identity_agrees

    layout = platform_layout()
    locator = locator_for(layout).read()
    store = ManifestStore(locator.install_dir, locator.manifest_relative_path)
    manifest = store.read()
    assert_identity_agrees(locator, manifest, manifest_path=str(store.path))
    out.detail(f"installation {manifest.installation_id} at {manifest.paths.install_dir}")

    from corpusfm.storage import get_backend
    return manifest, get_backend()


def _corpus_key_path(manifest):
    """Where adoption STAGES the Corpus Key — from the manifest it already read, never ambiently.

    This asked `crypto.corpus_key_file()`, which resolves through the ambient application resolver.
    Wrong for lifecycle work and wrong in the same way `KeyMigration.verify()` is careful about: an
    operation that installs a key into a named installation must write it where *that* record says,
    not where this process happens to resolve. The two agree today, which is exactly why the defect
    would have survived — they stop agreeing the moment adoption runs against a manifest other than
    the resolver's own answer, and then the key lands in the wrong installation's secrets directory.
    """
    from pathlib import Path

    from corpusfm.core.crypto import CORPUS_KEY_FILENAME

    return Path(manifest.paths.secrets_dir) / CORPUS_KEY_FILENAME


def _create(path: str, manifest, backend, consent: Consent, out: OutputEngine):
    from . import recovery_ops

    recovery_ops.assert_destination_allowed(path, manifest)
    replace = consent.has_exceptional("replace_existing_file")
    passphrase = prompt_new_passphrase()
    out.register_secret(passphrase)

    from corpusfm.core import crypto
    result = recovery_ops.create_recovery_file(
        destination=path, manifest=manifest, backend=backend,
        corpus_key=crypto.get_corpus_key(), password=passphrase,
        replace_authorized=replace,
    )
    out.discovery(f"corpus {result.corpus_id}")
    out.phase(result.detail)
    # Path, owner, and what was VERIFIED to govern access — never anything about the key itself.
    out.phase(f"wrote {result.path}")
    out.phase(f"belongs to {result.owner}; {result.protection}")
    if result.warning:
        out.warning(result.warning)
    out.action(
        "Store this file and its passphrase apart from the machine. Without both, encrypted "
        "corpus data cannot be recovered."
    )
    out.result(result.result)
    return result


def probe_adoption_preconditions(manifest, backend) -> dict:
    """What is actually true about this destination, established rather than assumed.

    A single settings read answers both remaining questions at once: it can only succeed if the
    intended database is hosted and reachable AND the automation account authenticates against it.
    Repairing either is 1246-08's; this only reports.
    """
    reachable = access = False
    try:
        backend.load_fm_settings()
        reachable = access = True
    except Exception:
        pass
    return {
        "installed": bool(manifest and manifest.installation_id),
        "database_reachable": reachable,
        "automation_access": access,
    }


def corpus_data_probe(backend) -> "Callable[[str], str]":
    """Answer, for a candidate key, whether this corpus's stored data actually opens under it.

    Returns `absent` when the corpus holds nothing of the kind — a fresh installation adopting into
    an empty corpus is the normal case and must not be reported as a failure — `readable` when a
    real encrypted blob decrypted, and `unreadable` when one exists and did not. Only the last
    stops an adoption. Distinguishing the first two is the whole point: an empty corpus that
    reported `readable` would let a broken key through, and one that reported `unreadable` would
    block a legitimate first adoption.
    """
    def probe(candidate_key: str) -> str:
        from cryptography.fernet import Fernet
        from corpusfm.core.crypto import _is_fernet
        import gzip

        try:
            blobs = list(_representative_blobs(backend))
        except StorageUnreachable:
            # "I could not look" is not "there is nothing there". The first version swallowed every
            # backend exception and yielded nothing, so a storage outage produced `absent` and let
            # the adoption through — absence INFERRED from an inability to inspect.
            return "error"

        fernet = Fernet(candidate_key.encode("ascii"))
        saw_encrypted = False
        for raw in blobs:
            if not raw or not _is_fernet(raw):
                continue                       # plaintext or a stub proves nothing about the key
            saw_encrypted = True
            try:
                gzip.decompress(fernet.decrypt(raw))
            except Exception:
                try:
                    fernet.decrypt(raw)        # a non-gzip secret blob is still proof
                except Exception:
                    return "unreadable"
        return "readable" if saw_encrypted else "absent"

    return probe


class StorageUnreachable(LifecycleError):
    """A required part of the inventory could not be read, so nothing was established."""


def _representative_blobs(backend):
    """One sample per kind the packet names: corpus blob, USER secret, job credential, AI keys.

    **Raises rather than yielding nothing.** Every required read must either produce a sample or
    prove there is none; a read that FAILED proves neither, and treating it as "none" is how an
    outage becomes a green light.
    """
    from corpusfm.artifact.capabilities import VISIBLE_TYPES

    def rows_of(table, **kw):
        try:
            rows, _ = backend.engine.page(table, page=1, per_page=1, **kw)
            return rows
        except Exception as exc:
            raise StorageUnreachable(f"could not list {table}: {exc}") from exc

    def blob_of(table, key, field):
        try:
            return backend.engine.blob_get(table, key, field)
        except Exception as exc:
            raise StorageUnreachable(f"could not read {table}.{field}: {exc}") from exc

    for row in rows_of("STORAGE", isin={"Type": list(VISIBLE_TYPES)}):
        yield blob_of("STORAGE", row.key, "ArtifactData")
    for table, field in (("USER", "SecretData"), ("JOB", "CredentialData")):
        for row in rows_of(table):
            yield blob_of(table, row.key, field)
    try:
        yield backend.read_ai_keys()
    except AttributeError:
        pass                                   # a backend without the container has none to offer
    except Exception as exc:
        raise StorageUnreachable(f"could not read the AI keys container: {exc}") from exc


def _adopt(path: str, manifest, backend, out: OutputEngine):
    from . import recovery_ops

    preconditions = probe_adoption_preconditions(manifest, backend)
    passphrase = prompt_passphrase()
    out.register_secret(passphrase)
    result = recovery_ops.adopt_recovery_file(
        source=path, backend=backend, corpus_key_destination=_corpus_key_path(manifest),
        password=passphrase,
        preconditions=preconditions,
        verify_data=corpus_data_probe(backend),
    )
    out.discovery(f"corpus {result.corpus_id}")
    out.preservation(result.detail)
    out.result(result.result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corpusfm-recovery",
        description=(
            "Create or adopt a CORPUSfm Recovery File — a reusable, password-protected copy of "
            "this corpus's Corpus Key. It never contains the database, the automation password, "
            "the Machine Key, PKI or user secrets."
        ),
    )
    sub = parser.add_subparsers(dest="verb", required=True)

    create = sub.add_parser("create", help="write a Recovery File for this corpus")
    create.add_argument("path", help=f"destination, ending in {recovery_format.RECOVERY_SUFFIX}")
    create.add_argument(
        "--replace-existing-file", action="store_true",
        help="named authorization to overwrite an existing file; --yes does NOT imply it",
    )

    adopt = sub.add_parser("adopt", help="install the Corpus Key a Recovery File carries")
    adopt.add_argument("path", help="the Recovery File to adopt")

    inspect = sub.add_parser(
        "inspect", help="print what the file says about itself (no passphrase, no installation)")
    inspect.add_argument("path")

    for p in (create, adopt, inspect):
        p.add_argument("--verbose", action="store_true")
        p.add_argument("--silent", action="store_true")
    for p in (create, adopt):
        p.add_argument("--yes", action="store_true",
                       help="pre-approve ordinary confirmations (never an exceptional one)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode = "verbose" if args.verbose else ("silent" if args.silent else "default")
    out = OutputEngine(mode=mode)

    try:
        if args.verb == "inspect":
            return _inspect(args.path, out)

        consent = Consent.from_flags(
            yes=args.yes, silent=args.silent,
            authorized={"replace_existing_file"}
            if getattr(args, "replace_existing_file", False) else set(),
        )
        require_elevation(f"{args.verb} a Recovery File")
        return _run_lifecycle_operation(args, consent, out)
    except LifecycleError as exc:
        out.failure(f"{type(exc).__name__}: {exc}")
        out.result(FAILED_BEFORE_CHANGE)
        return 2
    except OSError as exc:
        out.failure(f"{type(exc).__name__}: {exc}")
        out.result(FAILED_BEFORE_CHANGE)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
