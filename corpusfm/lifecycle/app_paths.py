"""Where the running application finds its config, state, secrets and logs (packet 1246-03-01).

Every one of those locations used to be `Path.home()/.corpusfm`, steered by the installer setting
`HOME`. That made the layout invisible to the code depending on it, unavailable to any process the
installer did not launch, and redirectable by anyone who could set an environment variable.

**An installed runtime has ONE answer: a valid, agreeing locator and manifest.** There is no second
production authority and no fallback. Missing, unreadable, invalid or disagreeing installed authority
**refuses** — it never resolves to a home directory, never to the fixed OS locations, never at all:

    published       locator and manifest readable and agreeing, `paths` complete → the manifest
    indeterminate   anything else on an installed box                            → refuse
    development     EXPLICITLY selected in-process, and only with no installation trace

The distinction worth spelling out, because it is subtle and it is why this module has more than one
refusal: **a published installation that cannot be READ is not an unpublished one.** A transient I/O
error, a permission difference between two identities, or a half-written record must never resolve to
some *other* layout — that is how two processes on one box end up using different directories.

**The development seam is in-process only.** `use_development_layout()` is a Python call. There is no
environment variable, no argv, no file and no manifest field that selects it, so nothing a deployed
box can carry reaches it. It refuses outright if this machine shows any *installation trace* — a
locator, or on POSIX merely the locator directory — which is what makes an installed box whose
records were stripped **refuse** rather than quietly become a development box.

*(Superseded, recorded because the code carried it: an earlier draft of this module answered
`unpublished` — no locator and no manifest → the legacy home — as a production fallback that also
served development. The developer withdrew that premise on 2026-08-03: there is one destination
format, and the two existing development installations are converted once by 1246-10.)*

**Lifecycle code does not use this module.** Migration and conversion work from explicit recorded
source and destination paths — the same rule that makes `KeyMigration.verify()` read staged keys by
path rather than through the ambient key resolver. An ambient resolver is for application code that
has no business knowing which state the box is in.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .errors import LifecycleError

PUBLISHED = "published"
DEVELOPMENT = "development"
INDETERMINATE = "indeterminate"

RESOLUTION_STATES: tuple[str, ...] = (PUBLISHED, DEVELOPMENT, INDETERMINATE)

_PATH_FIELDS = ("config_dir", "state_dir", "secrets_dir", "log_dir", "run_dir")

#: The installer-owned asset tree, a fixed sibling of the Git checkout inside the install root:
#: ``<install root>/assets/{db,addon}``. It is NOT inside ``src/`` — the deployed checkout must hold
#: no untracked content, and `tree_inspection` refuses any (packet 1257).
ASSETS_DIRNAME = "assets"


class InstallationStateUnclear(LifecycleError):
    """No usable installation authority. Never falls back, never guesses."""


class DevelopmentLayoutRefused(LifecycleError):
    """The development seam was engaged on a machine that carries an installation trace."""


@dataclass(frozen=True)
class ResolvedPaths:
    """One snapshot of the answer, so a long operation cannot straddle a publication."""

    state: str
    config_dir: Path
    state_dir: Path
    secrets_dir: Path
    log_dir: Path
    run_dir: Path
    assets_dir: Path
    source: str = ""

    def describe(self) -> str:
        return f"{self.state} ({self.source})" if self.source else self.state


_lock = threading.RLock()
_cached: Optional[ResolvedPaths] = None
_development: Optional[Callable[[], Path]] = None


# ── the development seam ──────────────────────────────────────────────────────────────

def development_layout(root: Path | str) -> ResolvedPaths:
    """The shape of a development tree. Pure — selecting it is a separate, checked act."""
    base = Path(root)
    return ResolvedPaths(
        state=DEVELOPMENT,
        config_dir=base,
        state_dir=base,
        secrets_dir=base,
        log_dir=base / "logs",
        run_dir=base,
        assets_dir=base / "assets",
        source=f"development layout {base}",
    )


def use_development_layout(root: Path | str | Callable[[], Path]) -> None:
    """Select a development layout for THIS PROCESS. Tests and development only.

    Refuses if the machine carries any installation trace. That check is the whole value of this
    function: without it, "no records" would mean development, and an installed box whose locator was
    deleted — by a failed uninstall, a botched restore, or someone tidying `/etc` — would silently
    start resolving a developer's directory while holding production data.

    There is deliberately no environment or argv route here. An installed entrypoint never calls
    this, and nothing it can be handed makes it call this.

    `root` may be a callable, and the development answer is then re-derived on every resolution
    rather than snapshotted. That is for the test harness, which patches `HOME` *inside* a test —
    after the fixture has run. A frozen development root would have silently ignored those patches,
    which is the same frozen-answer defect this packet removed from `crypto`, one layer up.
    """
    global _development, _cached
    trace = _installation_trace()
    if trace:
        raise DevelopmentLayoutRefused(
            f"refusing a development layout: this machine carries an installation trace ({trace}). "
            "An installation whose records are missing or unreadable must be repaired or removed, "
            "never resolved as a development tree."
        )
    factory = root if callable(root) else (lambda fixed=Path(root): fixed)
    with _lock:
        _development = factory
        _cached = None
    _reset_dependent_caches()


def clear_development_layout() -> None:
    """Forget the development selection. Tests only."""
    global _development, _cached
    with _lock:
        _development = None
        _cached = None
    _reset_dependent_caches()


def development_layout_active() -> bool:
    with _lock:
        return _development is not None


# ── caches ────────────────────────────────────────────────────────────────────────────

def reset_cache() -> None:
    """Forget the resolved snapshot AND every answer derived from it.

    A path cache is not the only thing that can hold a pre-publication answer: `core.crypto` caches
    the key BYTES it read, so a process that resolved its secrets directory before publication would
    keep using keys from the old one long after the paths moved. Clearing one without the other is
    the frozen-cache defect wearing a different hat.
    """
    global _cached
    with _lock:
        _cached = None
    _reset_dependent_caches()


_dependent_resets: list[Callable[[], None]] = []


def register_cache_reset(fn: Callable[[], None]) -> Callable[[], None]:
    """Register a cache that is derived from the resolved paths and must die with them.

    A registry rather than direct calls, because the alternative is this module importing
    `core.crypto` and `app.web.auth` — the lifecycle layer reaching up into the web application to
    clear a cookie secret. A consumer that was never imported has no cache to clear, so registration
    at import is exactly the right condition.
    """
    with _lock:
        if fn not in _dependent_resets:
            _dependent_resets.append(fn)
    return fn


def _reset_dependent_caches() -> None:
    """Run every registered reset, then raise if any failed.

    **Every one runs even when one raises.** A first version let the first failure abort the loop,
    which meant an unrelated consumer's bug could leave the key bytes intact after the paths moved —
    a partially-reset process is the frozen-cache defect with a smaller blast radius and the same
    shape. Failures are collected and re-raised afterwards, so nothing is swallowed either.
    """
    with _lock:
        callbacks = list(_dependent_resets)
    failures = []
    for fn in callbacks:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected and re-raised below
            failures.append(f"{getattr(fn, '__qualname__', fn)}: {exc}")
    if failures:
        raise LifecycleError(
            "a cache derived from the application paths could not be cleared ("
            + "; ".join(failures)
            + "); the process may still hold answers from the previous layout"
        )


# ── resolution ────────────────────────────────────────────────────────────────────────

def resolve(*, layout=None, locator=None) -> ResolvedPaths:
    """The current snapshot, computed once per process.

    `layout` and `locator` are injection seams for tests; production passes neither and gets the
    real platform answer. An injected call is never cached, so a test cannot poison the process.
    """
    global _cached
    with _lock:
        if _cached is not None and layout is None and locator is None:
            return _cached
        resolved = _resolve_uncached(layout=layout, locator=locator)
        # A DEVELOPMENT answer is never cached: its root is re-derived on every resolution so a test
        # that patches HOME after the harness selected the seam still gets its own directory.
        if layout is None and locator is None and resolved.state != DEVELOPMENT:
            _cached = resolved
        return resolved


def _adapter_for(layout=None, locator=None):
    from .layout import platform_layout
    from .locator import locator_for

    layout = platform_layout() if layout is None else layout
    if locator is not None:
        return layout, locator
    try:
        return layout, locator_for(layout)
    except Exception as exc:  # a locator we cannot even construct is not an absent one
        raise InstallationStateUnclear(
            f"the CORPUSfm installation locator for {layout.describe_locator()} could not be "
            f"opened ({exc}); refusing to guess this installation's layout"
        ) from exc


def _installation_trace(layout=None, locator=None) -> Optional[str]:
    """Any durable sign this machine holds an installation record.

    Stronger than "the locator file is readable" on purpose. Removing `locator.json` leaves
    `/etc/corpusfm` behind, and that directory is enough to know this is not a clean machine.

    **Every fixed lifecycle directory counts, not just the locator's.** A first version checked
    `locator_dir` alone, which is `None` on Windows — the locator is a registry key there — so
    deleting that key left NO recognized trace and a Windows box with its whole installation intact
    could have been selected as a development tree. The run and state directories exist on both
    platforms, so checking them closes the hole for Windows and widens it for POSIX at the same
    time. *(Found by review; the POSIX-only version had a passing test, which is exactly how a
    platform-specific hole survives.)*
    """
    try:
        layout, adapter = _adapter_for(layout=layout, locator=locator)
    except InstallationStateUnclear as exc:
        return str(exc)
    try:
        if adapter.exists():
            return adapter.describe()
    except Exception as exc:
        return f"{layout.describe_locator()} could not be examined ({exc})"

    candidates = [getattr(layout, "locator_dir", None)]
    for attr in ("lock_file", "journal_file"):
        target = getattr(layout, attr, None)
        candidates.append(None if target is None else Path(target).parent)
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            present = Path(candidate).exists()
        except OSError as exc:
            # An unanswerable probe is not an absent one. Raising the ruled refusal here rather than
            # leaking a raw OSError keeps every "we do not know" on one path.
            raise InstallationStateUnclear(
                f"could not determine whether {candidate} exists ({exc}); refusing to decide "
                "whether this machine carries an installation"
            ) from exc
        if present:
            return f"the installed directory {candidate} exists"
    return None


def _resolve_uncached(*, layout=None, locator=None) -> ResolvedPaths:
    layout, adapter = _adapter_for(layout=layout, locator=locator)

    try:
        present = adapter.exists()
    except Exception as exc:
        raise InstallationStateUnclear(
            f"could not determine whether {layout.describe_locator()} exists ({exc}); refusing to "
            "guess this installation's layout"
        ) from exc

    if present:
        return _published_paths(layout, adapter)

    # No locator. Before anything else: is there still a trace of an installation? An installed box
    # that lost its records must refuse — becoming a development box is the worst available answer,
    # because it is the one that keeps running.
    residue = _installation_trace(layout=layout, locator=adapter)
    if residue:
        raise InstallationStateUnclear(
            f"{layout.describe_locator()} holds no readable record, but this machine still carries "
            f"an installation trace ({residue}); refusing to resolve any layout for a stripped or "
            "half-removed installation"
        )

    with _lock:
        factory = _development
    if factory is not None:
        return development_layout(factory())

    raise InstallationStateUnclear(
        f"no CORPUSfm installation record at {layout.describe_locator()} and no development layout "
        "was selected for this process; refusing to invent one"
    )


def _published_paths(layout, adapter) -> ResolvedPaths:
    # From here the installation claims to be published. Every failure below is INDETERMINATE — a
    # published installation that cannot be read is not an unpublished one, and the difference is
    # the whole reason this function has more than one answer.
    try:
        record = adapter.read()
    except Exception as exc:
        raise InstallationStateUnclear(
            f"{layout.describe_locator()} exists but could not be read ({exc}); refusing to resolve "
            "any other layout, which would silently give two processes different answers"
        ) from exc

    try:
        manifest = _read_manifest(record)
    except InstallationStateUnclear:
        raise
    except Exception as exc:
        raise InstallationStateUnclear(
            f"the installation manifest named by {layout.describe_locator()} could not be read "
            f"({exc}); refusing to guess this installation's layout"
        ) from exc

    return _paths_from_manifest(manifest, source=layout.describe_locator())


def _read_manifest(record):
    from .manifest import ManifestStore
    from .schema import assert_identity_agrees

    # Deliberately opened WITHOUT a layout: that makes it a reader whose mutators all refuse. The
    # application resolving its own paths must never acquire a write path by doing so.
    store = ManifestStore(Path(record.install_dir), record.manifest_relative_path)
    if not store.exists():
        raise InstallationStateUnclear(
            f"the locator names a manifest at {store.path} that does not exist; this installation's "
            "record is contradictory and will not be guessed at"
        )
    manifest = store.read()
    # The locator and the manifest must agree about WHICH installation this is. 1246-01 requires it
    # at publication; reading without checking meant a locator pointed at another installation's
    # manifest would have been believed — the resolver would hand this box another box's layout.
    try:
        assert_identity_agrees(record, manifest, manifest_path=str(store.path))
    except LifecycleError as exc:
        raise InstallationStateUnclear(
            f"the locator and the manifest disagree about which installation this is ({exc}); "
            "refusing to resolve this installation's layout from a contradictory record"
        ) from exc
    return manifest


def _paths_from_manifest(manifest, *, source: str) -> ResolvedPaths:
    paths = manifest.paths
    missing = [name for name in _PATH_FIELDS if not getattr(paths, name, None)]
    if missing:
        raise InstallationStateUnclear(
            "the installation manifest is published but does not record "
            + ", ".join(missing)
            + " — a partially recorded layout is contradictory, not a reason to resolve anything else"
        )
    # DERIVED from the published install root, never recorded separately (packet 1257). The assets
    # are a fixed sibling of `src/` inside the installation the manifest already names, so a second
    # recorded field could only ever disagree with `install_dir` — and a disagreement about where
    # the storage DB template lives is not something to resolve at runtime. `install_dir` is a
    # required field of `PathsBlock`, so this cannot be reached with nothing to derive from.
    if not getattr(paths, "install_dir", None):
        raise InstallationStateUnclear(
            "the installation manifest is published but does not record install_dir, so the asset "
            "root cannot be derived — a published installation with no root is contradictory"
        )
    return ResolvedPaths(
        state=PUBLISHED,
        config_dir=Path(paths.config_dir),
        state_dir=Path(paths.state_dir),
        secrets_dir=Path(paths.secrets_dir),
        log_dir=Path(paths.log_dir),
        run_dir=Path(paths.run_dir),
        assets_dir=Path(paths.install_dir) / ASSETS_DIRNAME,
        source=source,
    )


# ── the application-facing answers ────────────────────────────────────────────────────

def config_dir() -> Path:
    return resolve().config_dir


def state_dir() -> Path:
    return resolve().state_dir


def secrets_dir() -> Path:
    return resolve().secrets_dir


def log_dir() -> Path:
    return resolve().log_dir


def run_dir() -> Path:
    return resolve().run_dir


def assets_dir() -> Path:
    """``<install root>/assets`` — the installer-owned, application-READ-ONLY payload tree."""
    return resolve().assets_dir


# ── overrides ─────────────────────────────────────────────────────────────────────────

class CorpusKeyUnavailable(LifecycleError):
    """The Corpus Key is absent from a published installation. It cannot be regenerated."""


_warned_overrides: set[str] = set()


def _warn_override_ignored(name: str, what: str) -> None:
    if name in _warned_overrides:
        return
    _warned_overrides.add(name)
    import logging

    logging.getLogger(__name__).warning(
        "%s is set but IGNORED on a published installation: %s comes from this installation's "
        "record, not from an override. Remove the setting to silence this.", name, what,
    )


def development_override(name: str, reader: Callable[[], object], *, what: str):
    """Resolve FIRST, then consult `reader` — and only honour it in development.

    **The rule this enforces (developer, 2026-08-03):**

    > *"'Explicit configuration' does not exempt a path from installation authority. If an override
    > works when locator/manifest resolution refuses, it is an alternate authority path regardless
    > of intent."*

    An earlier version of this packet argued that an operator-set variable is configuration rather
    than a fallback, and left `CORPUSFM_AUDIT_LOG`, a stored `archive_dir`, `CORPUSFM_OAUTH_LOCK`
    and two key/secret variables able to answer on a box whose own record could not be read. That is
    the home-directory fallback wearing a different hat — a second way to get an answer when the
    first one refused — and intent does not change what it is.

    **The ordering is structural here, not merely observed** (review, 2026-08-03). The boolean helper
    above leaves each call site free to read its variable first and check permission second, which
    happens to refuse correctly today only because the very next line resolves anyway. The ruled
    order is that *indeterminate authority refuses before an override is considered*, and the only
    way to make that testable rather than reviewable is to own both steps: nothing reads the
    environment or a stored setting until this function has an answer about the installation.

    Returns the override's value in development, `None` otherwise.
    """
    state = resolve().state          # 1. authority. An indeterminate installation raises here.
    value = reader()                 # 2. only now is the override consulted at all
    if not value:
        return None
    if state == DEVELOPMENT:
        return value
    _warn_override_ignored(name, what)
    return None


def assert_corpus_key_present(path: Path) -> None:
    """Refuse — with the exact recovery action — rather than manufacture a Corpus Key.

    **The one irreplaceable piece of machine-local state (developer ruling, 2026-08-03).** The
    durable recovery boundary is two things: the storage database, and the Corpus Key that
    interprets its protected values (or a Recovery File that can restore that key). Everything else
    on this box — Machine Key, session secret, locks, caches, PKI, service definitions, ACLs, proxy
    configuration — is replaceable scaffolding and is recreated at its authoritative published path.

    A generated Corpus Key is not a failure, it is a *disguised* one: the installation comes up
    working and cannot read a single protected value, and nothing says so. So this is the only
    secret whose absence stops the process, and the message names the action that actually recovers
    it rather than a generic repair.
    """
    if path.exists():
        return
    raise CorpusKeyUnavailable(
        f"the Corpus Key is missing from {path.parent} on a published installation, and it cannot "
        "be regenerated: a new key would not decrypt anything already stored, and the installation "
        "would come up working while unable to read its own protected values. Restore it from a "
        "CORPUSfm Recovery File — `corpusfm-recovery adopt <file.cfmrecovery>` — or from a backup "
        "of this file. If neither exists, the protected values in the storage database cannot be "
        "recovered by any means."
    )


def _reset_override_warnings() -> None:
    """Tests only — so a poisoned control can observe the warning more than once."""
    _warned_overrides.clear()


def is_published() -> bool:
    """True when this process is running against a published installation.

    The one question application code legitimately asks, because it decides whether a missing secret
    may be created (development: yes, that is first run) or must fail closed (published: the
    installer provisions secrets, and an unprivileged process inventing one is the defect). It
    RAISES for an indeterminate installation — "is this published" has no honest answer there.
    """
    return resolve().state == PUBLISHED


def running_on_published_install() -> bool:
    """`is_published()` that never raises — for callers that must degrade, not refuse."""
    try:
        return is_published()
    except LifecycleError:
        return False


__all__ = [
    "PUBLISHED",
    "DEVELOPMENT",
    "INDETERMINATE",
    "RESOLUTION_STATES",
    "DevelopmentLayoutRefused",
    "InstallationStateUnclear",
    "CorpusKeyUnavailable",
    "ResolvedPaths",
    "assert_corpus_key_present",
    "clear_development_layout",
    "config_dir",
    "development_layout",
    "development_layout_active",
    "development_override",
    "is_published",
    "log_dir",
    "reset_cache",
    "resolve",
    "run_dir",
    "running_on_published_install",
    "secrets_dir",
    "state_dir",
    "use_development_layout",
]
