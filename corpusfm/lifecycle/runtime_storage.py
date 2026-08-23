"""The ONE runtime resolver for a published installation's storage (packet 1246-10-04).

**What this replaces.** Every runtime consumer resolved storage from `install.yaml` — the backend
flag, the host, the database name, the account and the password — and `server_configs.yaml` held a
second copy. Those are the stores the 1246 family exists to retire. The installer no longer writes
either of them for storage, so a consumer left on them resolves *nothing* and, worse, several of
them fell back to LocalBackend or local YAML **silently**: the box answers, the pages render, and
the corpus is simply not there.

**The chain, and every link is required.**

1. the published **locator** and its validated **manifest**, through `published.read_published_installation`;
2. `manifest.storage` **initialized**, with a corpus id and a database name;
3. the credential record from the **fixed validated secrets directory** — never a caller path;
4. the record's `corpus_id` **agrees** with the manifest's, and its account is the fixed automation
   identity;
5. the co-located host, the recorded database name, the fixed account, the held secret and the ruled
   TLS posture — and an OData backend built from exactly those.

**What it will not do.** It takes no path, no name and no credential from a caller. It writes
nothing and persists nothing. On a published installation it has **no legacy fallback**: a link that
cannot be established raises, because substituting local storage for a corpus that exists is the
failure this module was written to end.

**The one thing that is not an error.** A tree that publishes *no* installation — a development
checkout, the test suite — resolves to `None`, and its caller keeps the LocalBackend path. That is
the dev/test path the project keeps deliberately; it is selected by the *absence* of an
installation record, never as a fallback from one that exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import LifecycleError

#: The co-located deployment's host. CORPUSfm runs on the FileMaker Server box; the corpus is
#: reached over loopback. Not a setting, and deliberately not read from a config file.
COLOCATED_HOST = "localhost"


class StorageAuthorityUnavailable(LifecycleError):
    """A published installation exists and its storage authority could not be established.

    Never raised for an unpublished tree — that answers `None` and keeps LocalBackend.
    """


@dataclass(frozen=True)
class ResolvedStorage:
    """The facts a backend is built from. The secret is held, not published."""

    installation_id: str
    database_name: str
    corpus_id: str
    account: str
    host: str
    verify_ssl: bool
    connection_name: str | None = None
    _secret: str = field(repr=False, default="")

    def backend(self):
        """The explicit `FileMakerODataBackend`. Five values, none of them from a config file."""
        from corpusfm.storage.fm_odata import FileMakerODataBackend

        return FileMakerODataBackend(
            host=self.host,
            database=self.database_name,
            username=self.account,
            password=self._secret,
            verify_ssl=self.verify_ssl,
        )


def published_installation() -> Any | None:
    """The published installation, or `None` when this tree publishes none."""
    from .published import InstallationNotPublished, read_published_installation

    try:
        return read_published_installation()
    except InstallationNotPublished:
        return None


def is_published() -> bool:
    return published_installation() is not None


def resolve() -> ResolvedStorage | None:
    """`None` when nothing is published; a resolved authority otherwise; raise when it disagrees."""
    published = published_installation()
    if published is None:
        return None

    block = getattr(published, "storage", None)
    if block is None:
        raise StorageAuthorityUnavailable(
            "this installation publishes no storage block; its corpus has not been composed yet")
    database = getattr(block, "database_name", None)
    corpus_id = getattr(block, "corpus_id", None)
    if not getattr(block, "initialized", False) or not database or not corpus_id:
        raise StorageAuthorityUnavailable(
            "the published storage block is not an initialized corpus "
            f"(database={database!r}, corpus_id={corpus_id!r}, "
            f"initialized={getattr(block, 'initialized', None)!r})")

    access = _held_credential()
    if access is None:
        raise StorageAuthorityUnavailable(
            "this installation publishes a corpus and holds no credential for it; the storage "
            "access record is absent or could not be read")
    if access.corpus_id and access.corpus_id != corpus_id:
        raise StorageAuthorityUnavailable(
            "the held credential names a different corpus than the installation record; refusing "
            "to open either")
    from .storage_identity import AUTOMATION_ACCOUNT

    if access.account != AUTOMATION_ACCOUNT:
        raise StorageAuthorityUnavailable(
            f"the held credential is for account {access.account!r}, not the automation identity")
    if not access.secret:
        raise StorageAuthorityUnavailable("the held credential carries no secret")

    from .storage_identity_adapter import VERIFY_SSL

    return ResolvedStorage(
        installation_id=published.installation_id,
        database_name=str(database),
        corpus_id=str(corpus_id),
        account=AUTOMATION_ACCOUNT,
        host=COLOCATED_HOST,
        verify_ssl=VERIFY_SSL,
        connection_name=getattr(block, "connection_name", None),
        _secret=access.secret,
    )


def _held_credential():
    """The promoted record, from the FIXED validated secrets directory alone.

    The path is asked of `os_layout`, not of a caller, and `storage_identity_store` validates it
    against that same fixed location before opening anything — so the directory is named twice by
    the same authority and by nobody else.
    """
    from . import os_layout, storage_identity_store as store

    try:
        return store.load(os_layout.platform_os_layout().secrets_dir)
    except Exception:  # noqa: BLE001 — an unreadable store is "no credential", judged by the caller
        return None


def backend():
    """The storage backend for a published installation, or `None` when nothing is published."""
    resolved = resolve()
    return None if resolved is None else resolved.backend()


def fm_storage_active() -> bool | None:
    """Tri-state, and the middle value is the point.

    `True` — a published installation whose corpus is composed: FM OData is the store.
    `False` — a published installation with no corpus composed yet.
    `None` — nothing is published; the caller keeps whatever it did before.
    """
    published = published_installation()
    if published is None:
        return None
    block = getattr(published, "storage", None)
    return bool(block is not None and getattr(block, "initialized", False)
                and getattr(block, "database_name", None))


def database_name() -> str | None:
    """The corpus this installation owns, from the manifest. `None` when nothing is published."""
    published = published_installation()
    if published is None:
        return None
    block = getattr(published, "storage", None)
    return getattr(block, "database_name", None) if block is not None else None


def connection_name() -> str | None:
    published = published_installation()
    if published is None:
        return None
    block = getattr(published, "storage", None)
    return getattr(block, "connection_name", None) if block is not None else None


__all__ = [
    "COLOCATED_HOST",
    "ResolvedStorage",
    "StorageAuthorityUnavailable",
    "backend",
    "connection_name",
    "database_name",
    "fm_storage_active",
    "is_published",
    "published_installation",
    "resolve",
]
