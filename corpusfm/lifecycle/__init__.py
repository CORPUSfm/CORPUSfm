"""CORPUSfm machine-lifecycle core (packet 1246-01).

**One** state model, **one** locator/manifest authority, **one** lock and journal, **one** result
vocabulary, **one** output contract — shared by every lifecycle tool on both operating systems. The
parent packet's fence is explicit: no later child may invent a second manifest, locator, lock,
journal or output engine. This package is where they all live.

The frame it comes from: the *machine lifecycle* owns installation topology, mutation authority,
recovery checkpoints and administrator-facing lifecycle output. The running web application owns
runtime preferences only. Today's `install.yaml` cannot own the first set because the application
reads and rewrites it as runtime and storage configuration — so this is a neutral substrate beside
it, not a rename of it. ``bridge`` reads a few facts from the marker to propose a manifest; nothing
here deletes, moves or demotes it. Later children migrate consumers one at a time.

What this package deliberately does NOT do: create or ACL the OS directories it names (1246-03),
move any key or credential (1246-02, 1246-08), change an installer flag (1246-04), implement a proxy
(1246-06), or remove anything (1246-09).

Entry points: import from Python, or call ``python -m corpusfm.lifecycle`` — the one command a shell
or PowerShell lifecycle script uses to reach this core, so neither language grows its own copy.
"""

from __future__ import annotations

from .consent import Consent
from .errors import (
    ElevationRequired,
    ExceptionalAuthorizationRequired,
    GenerationConflict,
    IdentityMismatch,
    LifecycleError,
    LockNotHeld,
    LockUnavailable,
    RecordInvalid,
    RecordMissing,
    RecoveryRequired,
    SchemaVersionUnsupported,
    SecretInLifecycleRecord,
)
from .corpus_identity import (
    CorpusIdentityConflict,
    CorpusKeyDoesNotOpenThisCorpus,
    establish_identity,
    read_identity,
    require_identity,
)
from .journal import Journal
from .layout import LifecycleLayout, platform_layout, posix_layout, windows_layout
from .lock import LifecycleLock
from .locator import locator_for
from .manifest import ManifestStore
from .output import OutputEngine
from .result import (
    COMPLETED,
    FAILED_BEFORE_CHANGE,
    INCOMPLETE_SAFE,
    MANUAL_ACTION_REQUIRED,
    NO_CHANGE,
    RESULT_VOCABULARY,
    ROLLED_BACK,
    classify_failure,
    validate_result,
)
from .key_migration import CutoverProof, KeyMigration, MigrationStateError, SealResidueUnsupported
from .recovery_format import (
    RECOVERY_SUFFIX,
    RecoveryFileInvalid,
    RecoveryPasswordWrong,
    build_recovery_file,
    open_recovery_file,
    read_header,
)
from .recovery_ops import adopt_recovery_file, create_recovery_file
from .session import LifecycleSession, lifecycle_operation
from .schema import (
    JOURNAL_SCHEMA_VERSION,
    LOCATOR_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    InstallerBlock,
    InstallationManifest,
    JournalRecord,
    LocatorRecord,
    assert_identity_agrees,
)

__all__ = [
    "Consent",
    "CorpusIdentityConflict",
    "CorpusKeyDoesNotOpenThisCorpus",
    "CutoverProof",
    "KeyMigration",
    "MigrationStateError",
    "RECOVERY_SUFFIX",
    "RecoveryFileInvalid",
    "RecoveryPasswordWrong",
    "SealResidueUnsupported",
    "adopt_recovery_file",
    "build_recovery_file",
    "create_recovery_file",
    "establish_identity",
    "open_recovery_file",
    "read_header",
    "read_identity",
    "require_identity",
    "InstallationManifest",
    "InstallerBlock",
    "Journal",
    "JournalRecord",
    "LifecycleError",
    "LifecycleLayout",
    "LifecycleLock",
    "LifecycleSession",
    "LocatorRecord",
    "ManifestStore",
    "OutputEngine",
    "RESULT_VOCABULARY",
    "COMPLETED",
    "NO_CHANGE",
    "ROLLED_BACK",
    "INCOMPLETE_SAFE",
    "MANUAL_ACTION_REQUIRED",
    "FAILED_BEFORE_CHANGE",
    "ElevationRequired",
    "ExceptionalAuthorizationRequired",
    "GenerationConflict",
    "IdentityMismatch",
    "LockNotHeld",
    "LockUnavailable",
    "RecordInvalid",
    "RecordMissing",
    "RecoveryRequired",
    "SchemaVersionUnsupported",
    "SecretInLifecycleRecord",
    "JOURNAL_SCHEMA_VERSION",
    "LOCATOR_SCHEMA_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "assert_identity_agrees",
    "classify_failure",
    "lifecycle_operation",
    "locator_for",
    "platform_layout",
    "posix_layout",
    "windows_layout",
    "validate_result",
]
