"""The one read-only way application code learns what this installation published.

**Why this module exists (Codex ruling, 2026-08-04).** Packet 1246-01 fenced the application off from
the lifecycle write API, and `tests/test_lifecycle_app_fence.py` enforces it by NAME: an application
module may not import `ManifestStore`, `locator_for`, `LifecycleLock`, `Journal` or any other
mutation-capable primitive. That principle is intact and is not being weakened.

What the fence also assumed — and what the manifest-authority design of 1246-03/1246-05 superseded —
is that application code never needs to perform the read chain itself. It does now: the patch
compartment's authority lives in the manifest, and `db_helper.load_published_patch_authority()` is the
runtime-facing resolver the packet requires. Executing that chain in an application module meant
importing exactly the primitives the fence forbids.

So the read is moved here, where it belongs, and the application consumes a **projection**:

    platform layout  ->  locator read  ->  manifest read  ->  identity agreement  ->  frozen facts

**This module exposes no write, no repair and no publication operation, and it never will.** It has
one public function and two frozen result types. The store it opens is deliberately constructed
WITHOUT a `LifecycleLayout`, which `manifest.ManifestStore._authority` makes write-refusing by
construction — so even the object this module holds internally has no write path. What crosses the
boundary is plain strings, ints and bools: nothing the caller could mutate anything with, and nothing
that carries a store, a locator adapter or a lock.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .errors import LifecycleError


class InstallationNotPublished(LifecycleError):
    """No readable, self-consistent published installation. Never falls back, never guesses.

    Missing, unreadable, invalid and mismatched records all arrive here, because a caller deciding
    whether it may proceed never needs to tell them apart — the answer is the same.
    """


@dataclass(frozen=True)
class PublishedPatchFacts:
    """The manifest's `patch` block, projected. Field-for-field with `schema.PatchBlock`, so a
    consumer reads `.verified` / `.registered` / `.folder_slot` / `.sandbox_file` exactly as it would
    have — but it is a value, not a record, and it arrives with no route back to the store."""

    folder_slot: str | None
    registered: bool
    verified: bool
    sandbox_file: str | None


@dataclass(frozen=True)
class PublishedInstallation:
    """What one installation published, as facts. No store, no adapter, no lock, no write path."""

    installation_id: str
    generation: int
    patch_hosting_dir: str | None
    patch: PublishedPatchFacts
    manifest_path: str
    locator_description: str
    # Added by packet 1246-06 so the PUBLIC `corpusfm-proxy` tool can read its route facts and stored
    # policy through this same read authority. `web_prefix` and `web_internal_port` are `| None` in
    # the committed schema, so "present but empty" is a real state — a consumer that needs them must
    # REFUSE rather than default (1246-06 §8.3).
    #
    # `proxy_policy` maps a `PROXY_TYPES` name to `schema.ProxyPolicyEntry` — schema's OWN frozen
    # record, deliberately rather than a new projection type. A frozen record is a value with no
    # write path, and reusing it means this module exports **no new public name**, so `__all__`,
    # `READ_FACADE_NAMES` and the 1246-01 application fence are untouched by the widening.
    # `config_fingerprint` there is the last SUCCESSFULLY APPLIED rendering; drift is recomputed
    # against it and never stored (1246-06 §4).
    web_prefix: str | None = None
    web_internal_port: int | None = None
    proxy_policy: Mapping[str, Any] = field(default_factory=dict)
    # Added by Codex ruling 1 (2026-08-04). The proxy provider needs BOTH paths, and a public
    # command must take them from the published record rather than discover them: hard-coded FMS
    # root discovery is a guess about somebody else's machine, and an install directory derived
    # from `__file__` is a guess about our own. Both are plain strings on the existing frozen
    # result, so no new public name crosses the 1246-01 fence.
    install_dir: str | None = None
    fms_root: str | None = None
    # Added by packet 1000-07 so LIFECYCLE code can take the recorded secrets location from this
    # read chain instead of `app_paths.secrets_dir()`. The ambient resolver answers "where is the
    # layout" from a per-process cache; an operation that establishes or moves that layout must work
    # from the record it can name, which is the rule `app_paths` states about itself and the guard
    # `test_lifecycle_code_does_not_resolve_paths_ambiently` enforces. It is a plain string on the
    # existing frozen result, so no new public name crosses the 1246-01 application fence, and
    # `None` is a real state — a caller that needs it must REFUSE rather than default.
    secrets_dir: str | None = None
    # Added by packet 1246-10-04 so the RUNTIME can resolve its corpus through this same read
    # authority instead of `install.yaml`. It is `schema.StorageBlock` — schema's OWN frozen record,
    # for exactly the reason `proxy_policy` is: a frozen record is a value with no write path, and
    # reusing it exports **no new public name**, so the 1246-01 application fence is untouched.
    # `None` is a real state (an installation whose corpus is not composed yet) and a consumer that
    # needs a corpus must REFUSE rather than default — which is the whole point of the cutover.
    storage: Any = None
    # Added by packet 1247 so the RUNTIME can check the stored Admin-API identity against what this
    # installation actually published. It is `schema.PkiBlock` — schema's OWN frozen record, for the
    # same reason `storage` and `proxy_policy` are: a frozen record is a value with no write path, and
    # reusing it exports **no new public name**, so the 1246-01 application fence is untouched. The
    # block carries a name, a fingerprint and observations; there is no field a PEM could live in, so
    # widening the façade here cannot widen what private material crosses it. An empty block is a real
    # state (an installation with no identity composed yet) and a consumer must REFUSE rather than
    # default.
    pki: Any = None
    # Added by packet 1276 so `update_service.operator_command()` can print the recorded installer
    # launcher through this read authority instead of importing `ManifestStore` — the lifecycle app
    # fence caught exactly that import (app commit 5fe73847). A plain string on the existing frozen
    # result: no new public name crosses the 1246-01 fence, `None` is a real state (an older
    # manifest that recorded no entry point), and a consumer without it falls back to the generic
    # installer handoff rather than guessing a path.
    installer_entry_point: str | None = None


def read_published_installation() -> PublishedInstallation:
    """Run the published-installation read chain and return its facts.

    **It takes NO arguments, deliberately (Codex finding, 2026-08-04).** The first version carried a
    `layout` keyword "as an injection seam for tests". That was an alternate authority selector
    sitting on the exact boundary this module exists to remove: a caller handing in its own
    `LifecycleLayout` chooses which machine's locator is read, which is the whole of the decision
    this function is supposed to own. An injection point is not made safe by the intent behind it —
    the same argument settled `app_paths.development_override`, where an operator-set variable that
    answered when installation authority refused was ruled an alternate authority path *regardless
    of intent*. It is the same shape, so it gets the same answer.

    `platform_layout()` is therefore obtained internally and cannot be supplied. A test that needs a
    different machine redirects the platform lookup BELOW this boundary — by patching
    `corpusfm.lifecycle.layout.platform_layout`, which is what the harness does — rather than
    reaching through the public API.

    Every failure of the chain raises `InstallationNotPublished`. Never writes. Never takes the
    lifecycle lock. Never repairs anything it finds wrong — a record that cannot be read consistently
    is refused rather than mended, which is the 1246-03 rule this layer applies everywhere.
    """
    from .layout import platform_layout
    from .locator import locator_for
    from .manifest import ManifestStore
    from .schema import assert_identity_agrees

    try:
        layout = platform_layout()
        adapter = locator_for(layout)
        record = adapter.read()
    except Exception as exc:
        raise InstallationNotPublished(
            f"this installation's locator could not be read ({exc})"
        ) from exc

    try:
        # Opened WITHOUT a layout on purpose: a reader whose every mutator refuses.
        store = ManifestStore(Path(record.install_dir), record.manifest_relative_path)
        manifest = store.read()
        assert_identity_agrees(record, manifest, manifest_path=str(store.path))
    except Exception as exc:
        raise InstallationNotPublished(
            f"this installation's manifest could not be read or does not agree with its locator "
            f"({exc})"
        ) from exc

    try:
        # Re-validated rather than trusted: `read()` built it, but the permission a caller derives
        # from this answer is large enough that the block goes back through its own validator.
        from .schema import PatchBlock

        patch = PatchBlock.from_dict(manifest.patch.to_dict())
    except Exception as exc:
        raise InstallationNotPublished(
            f"the manifest's patch block is invalid ({exc})"
        ) from exc

    try:
        # Re-validated through the record's own validator, for the same reason the patch block is:
        # the permission a caller derives from this answer is large enough to re-check.
        from .schema import ProxyPolicyEntry

        policy = MappingProxyType({
            name: ProxyPolicyEntry.from_dict(entry.to_dict(), proxy_type=name)
            for name, entry in (manifest.proxy_policy or {}).items()
        })
    except Exception as exc:
        raise InstallationNotPublished(
            f"the manifest's proxy_policy block is invalid ({exc})"
        ) from exc

    try:
        # Re-validated through its own validator, like the patch and proxy blocks above: the
        # permission a caller derives from it — which corpus the runtime opens — is large.
        from .schema import StorageBlock

        raw_storage = getattr(manifest, "storage", None)
        storage = StorageBlock.from_dict(raw_storage.to_dict()) if raw_storage is not None else None
    except Exception as exc:
        raise InstallationNotPublished(
            f"the manifest's storage block is invalid ({exc})"
        ) from exc

    try:
        # Re-validated through its own validator, like every other block projected here: the
        # permission a caller derives from it — whether a stored private key may authenticate as this
        # installation — is exactly the kind this module re-checks rather than trusts.
        from .schema import PkiBlock

        raw_pki = getattr(manifest, "pki", None)
        pki = PkiBlock.from_dict(raw_pki.to_dict()) if raw_pki is not None else None
    except Exception as exc:
        raise InstallationNotPublished(
            f"the manifest's pki block is invalid ({exc})"
        ) from exc

    raw_dir = getattr(manifest.paths, "patch_hosting_dir", None)
    raw_install = getattr(manifest.paths, "install_dir", None)
    raw_fms = getattr(manifest.paths, "fms_root", None)
    raw_secrets = getattr(manifest.paths, "secrets_dir", None)
    return PublishedInstallation(
        installation_id=manifest.installation_id,
        generation=manifest.generation,
        patch_hosting_dir=(os.path.normpath(str(raw_dir)) if raw_dir else None),
        patch=PublishedPatchFacts(
            folder_slot=patch.folder_slot,
            registered=bool(patch.registered),
            verified=bool(patch.verified),
            sandbox_file=patch.sandbox_file,
        ),
        manifest_path=str(store.path),
        locator_description=layout.describe_locator(),
        web_prefix=getattr(manifest.web, "prefix", None),
        web_internal_port=getattr(manifest.web, "internal_port", None),
        proxy_policy=policy,
        install_dir=(os.path.normpath(str(raw_install)) if raw_install else None),
        fms_root=(os.path.normpath(str(raw_fms)) if raw_fms else None),
        storage=storage,
        secrets_dir=(os.path.normpath(str(raw_secrets)) if raw_secrets else None),
        pki=pki,
        installer_entry_point=(getattr(manifest.installer, "entry_point", None) or None),
    )


__all__ = [
    "InstallationNotPublished",
    "PublishedInstallation",
    "PublishedPatchFacts",
    "read_published_installation",
]
