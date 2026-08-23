"""Privileged FMS-Databases-dir file ops — platform-split behind one (ok, output) contract.

On **Linux** the unprivileged corpusfm service cannot write the fmserver-owned Databases directory,
so the installer drops a fixed-purpose root helper (cfm-db-helper) + a narrow NOPASSWD sudoers rule
and this module brokers every op through it (copy a db out so it can be patched, place a patched
file in, remove it). On **Windows** the CORPUSfm services run as LocalSystem, which already has
FullControl on the Databases dir — so there is no broker; the same ops are direct filesystem calls
in ``win_db_ops``. Callers use this module uniformly; the split lives here. Hosting/opening/closing
databases is NOT done here — that goes through fmsadmin / the Admin API (PKI).

**Packet 1246-05-02 — the compartment is READ FROM THE VERIFIED MANIFEST, and the privileged broker
is bounded by facts rather than by a failed lookup.**

Three things changed shape here, and each was a safety defect rather than an untidiness:

*One authority.* ``load_published_patch_authority()`` is the ONE resolver. It runs
``platform_layout -> locator_for(layout).read -> read-only ManifestStore.read ->
assert_identity_agrees -> validated PatchBlock``, and every missing / unreadable / invalid /
mismatched / indeterminate / unverified answer arrives as one ``PatchAuthorityError``. No consumer
re-implements that chain, no consumer reads an app-config mirror, and an explicitly selected
development layout yields quarantine-only capability — never installed patch authority.

*The verified-compartment prerequisite precedes the preference branch.* ``check_apply_target`` used
to return ``(True, "")`` before any compartment lookup whenever ``restrict_apply_to_compartment``
was off, so OFF plus an unverified compartment enabled patching of any non-storage hosted database.
The preference is a widening of an already-authorized set; it is never an authorization.

*A failed lookup is not a permission — and ordinary placement has no business outside the
compartment at all.* ``place``/``copy_out``/``remove`` and the former ``place_via_handoff`` all used
to fall through to the privileged broker, and thence to the main FMS Databases directory, when
``_compartment_path()`` returned ``None``. That is gone, and so is the generic route itself:

- **``place`` writes only inside the verified compartment.** An outside-compartment target refuses
  before any dispatch. It takes no authority argument, because an argument that unlocks the broker
  is a route, and a route is what was being removed.
- **``place_via_handoff`` is retired.** It was the generic name-addressed way to the broker and had
  no legitimate caller left once the apply loop moved to ``place_authorized``.
- **Only ``place_authorized`` performs a forward broker placement**, behind five facts it checks
  immediately before the write — including an observation of the target, which is what makes
  creating something that was not there impossible rather than merely discouraged.
- **Only ``restore_authorized`` / ``_restore_write`` perform the bounded restore**, from the same
  operation's captured backup onto its captured target.
- ``copy_out`` and ``remove`` keep the five gates. Neither can bring a file into existence: the
  broker refuses a copy-out of a database that is not there, and a removal creates nothing.

*(Codex ruling, 2026-08-04, superseding the packet's four-generic-routes language. Its ground was
measured, not theoretical: ``complete_apply_authority`` validates the backup it is HANDED and cannot
know whether ``copy_out_for`` produced it, so an authority built from a caller-supplied file drove
the old ``place`` into creating a file outside the compartment. The remedy is a smaller surface, not
a provenance registry — and certainly not a claim that a Python dataclass is unforgeable.)*

Authorization is minted once per operation and CARRIED, split at the close: an ``ApplyPermit``
authorizes closing and copying out one target, and an ``ApplyAuthority`` — completable only after a
successful post-close copy-out — is what places and what restores.

All functions return (ok, output) and never raise, except the resolver and the small helpers that
exist to raise ``PatchAuthorityError``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import uuid
from collections import OrderedDict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

HELPER = "/opt/CORPUSfm/bin/cfm-db-helper"
HANDOFF_ROOT = "/var/lib/corpusfm/handoff"

# The Linux broker's own confined root (installer/linux/cfm-db-helper.sh ``DBDIR``). Kept in step
# with the script: it is what makes a broker-disposition target a resolvable canonical path rather
# than a bare name, which is what an ApplyPermit has to capture.
BROKER_DATABASES_DIR = "/opt/FileMaker/FileMaker Server/Data/Databases"

DIRECT_COMPARTMENT = "direct_compartment"
BROKER = "broker"

PUBLICATION_OCCURRED = "yes"
PUBLICATION_DID_NOT_OCCUR = "no"
PUBLICATION_UNCERTAIN = "uncertain"

_CHUNK = 1024 * 1024


def _is_windows() -> bool:
    return os.name == "nt"


def staging_dir() -> str:
    """Base directory for caller-side staging (the mkdtemp parent). On Linux this is ``/tmp`` —
    the sudo broker confines external paths to ``/tmp/cfm*``. On Windows there is no such confinement
    (the direct-FS ``place`` handles same-volume itself), so use the system temp dir, which exists
    and is LocalSystem-writable (``/tmp`` does not exist on Windows)."""
    return tempfile.gettempdir() if _is_windows() else "/tmp"


# ── the ONE resolver ──────────────────────────────────────────────────────────────────────


class PatchAuthorityError(Exception):
    """The ONE fail-closed error. Missing, unreadable, invalid, mismatched and indeterminate
    authority all arrive here — a caller never distinguishes them to decide whether to proceed,
    because the answer is always no."""


@dataclass(frozen=True)
class PublishedPatchAuthority:
    """What the verified manifest says about this installation's patch compartment."""

    installation_id: str
    generation: int
    patch_hosting_dir: Path
    patch: Any                      # lifecycle.published.PublishedPatchFacts — a frozen projection


def load_published_patch_authority(*, require_verified: bool = True) -> PublishedPatchAuthority:
    """The exact production chain, in this order:

      platform_layout()  ->  locator_for(layout).read()  ->  read-only ManifestStore.read()
                         ->  assert_identity_agrees(locator, manifest)
                         ->  validated PatchBlock + canonical patch_hosting_dir

    Raises ``PatchAuthorityError`` for every failure of that chain. Consults NO app-config mirror
    and NO private app_paths helper (nothing underscore-prefixed, and not ``resolve()`` — this
    answer is about the PATCH compartment, not about process directories).

    ``require_verified`` defaults to True because that is what every runtime permission needs:
    ``patch.registered`` means the Additional Database Folder read back, and it is not sufficient
    for anything. Only readiness, whose whole job is to report an unverified compartment AS
    unverified rather than as absent, passes False.

    Never writes. Never takes the lifecycle lock. Never repairs anything it finds wrong.
    """
    from corpusfm.lifecycle.app_paths import development_layout_active

    # A development layout is not a weaker installation; it is not an installation. Materialization
    # into the quarantine continues there; hosting and patching stay closed.
    if development_layout_active():
        raise PatchAuthorityError(
            "a development layout is explicitly selected for this process, so there is no installed "
            "patch compartment: hosting, patching and applying are closed. Inert materialization "
            "into the <archive>/_generated/ quarantine is unaffected."
        )

    # The read chain itself lives in `corpusfm.lifecycle.published`, and this module imports NOTHING
    # else from the lifecycle package. That is the 1246-01 application fence, kept: an application
    # module must not import `ManifestStore`, `locator_for`, `LifecycleLock`, `Journal` or any other
    # mutation-capable primitive. The fence's PRINCIPLE survives untouched; only its assumption that
    # application code never performs the read was superseded by the manifest-authority design, and
    # the façade is where that read now happens.
    from corpusfm.lifecycle.published import (
        InstallationNotPublished, read_published_installation,
    )

    try:
        published = read_published_installation()
    except InstallationNotPublished as exc:
        raise PatchAuthorityError(
            f"{exc}; the patch compartment has no authority and every patch/apply route is refused"
        ) from exc

    if not published.patch_hosting_dir:
        raise PatchAuthorityError(
            "the manifest records no patch_hosting_dir, so this installation has no patch "
            "compartment; hosting, patching and applying are refused"
        )
    hosting = Path(published.patch_hosting_dir)

    if require_verified and not published.patch.verified:
        raise PatchAuthorityError(
            f"the patch compartment at {hosting} is not VERIFIED "
            f"(registered={published.patch.registered}); registration alone is never a runtime "
            "permission, so hosting, patching and applying are refused"
        )

    return PublishedPatchAuthority(
        installation_id=published.installation_id,
        generation=published.generation,
        patch_hosting_dir=hosting,
        patch=published.patch,
    )


def hosting_dir() -> "str | None":
    """The one VERIFIED patch compartment, or None.

    Answers from ``load_published_patch_authority()`` and from nowhere else — no install.yaml
    marker, no app-config mirror, no environment. ``None`` here means *refuse*, never "not
    configured, carry on": every caller that could host, patch or apply treats it as a refusal.
    """
    try:
        return str(load_published_patch_authority().patch_hosting_dir)
    except PatchAuthorityError:
        return None
    except Exception:  # pragma: no cover - the resolver's own contract is to raise the one error
        return None


def compartment_dirs() -> list[str]:
    """The apply COMPARTMENT: the single verified PatchHostingDir, or empty.

    It was a union of two install.yaml markers ({support_dir, hosting_dir}); both markers are gone
    and the compartment is now one proven directory. Empty means no verified compartment, which the
    gate treats as a refusal rather than as a permissive state."""
    d = hosting_dir()
    return [d] if d else []


def sandbox_file_path() -> Path:
    """The one sandbox file INSIDE the verified compartment, as the manifest records it.

    Raises ``PatchAuthorityError`` when there is no verified compartment, when the manifest records
    no sandbox, when the recorded path escapes the compartment, or when the file is absent. **An
    absent sandbox is a refusal, never a re-creation somewhere else** — the behaviour this replaces
    would have had the broker write ``CORPUSfm_Sandbox.fmp12`` into the main FMS Databases directory.
    """
    authority = load_published_patch_authority()
    recorded = authority.patch.sandbox_file
    if not recorded:
        raise PatchAuthorityError(
            "the verified patch compartment records no sandbox file; the sandbox dry-run is refused"
        )
    p = Path(os.path.normpath(str(recorded)))
    base = authority.patch_hosting_dir
    try:
        base_real = base.resolve()
        p_real = p.resolve()
    except Exception as exc:  # pragma: no cover - defensive
        raise PatchAuthorityError(f"the recorded sandbox path is unusable ({exc})") from exc
    if base_real != p_real.parent:
        raise PatchAuthorityError(
            f"the recorded sandbox {p} does not sit inside the verified compartment {base}; refusing "
            "to treat it as this installation's sandbox"
        )
    if p.is_symlink() or not p_real.is_file():
        raise PatchAuthorityError(
            f"the compartment sandbox {p} is absent or is not a regular file. An absent sandbox is a "
            "refusal — it is never re-created somewhere else. Re-provision the patch compartment."
        )
    return p_real


def force_hostable_mode(path: "str | Path") -> None:
    """Force a generated .fmp12 to mode 664 (g+w) so the fmserver user can host it R/W from the shared
    setgid compartment. The ``corpusfm-web`` service runs UMask=0022 → it materializes 644
    (group-read-only) by default → FMS cannot write it → hosting fails with a cryptic error (the UMASK
    TRAP, packet 1061 box probe). The setgid dir supplies the *group* (fmsadmin) but NOT the group-write
    bit, so set it explicitly. No-op on Windows (LocalSystem already has FullControl; POSIX modes don't
    apply). Best-effort — never raises."""
    if _is_windows():
        return
    try:
        os.chmod(str(path), 0o664)
    except Exception:
        pass


def _norm_db(name: str) -> str:
    """Canonical compare form for a DB name: trimmed, .fmp12-insensitive, lower-cased — matching
    install.is_storage_database's normalization so the guards agree across platforms."""
    n = (name or "").strip()
    return (n[:-6] if n.lower().endswith(".fmp12") else n).lower()


def _safe_db_name(db_name: str) -> bool:
    """A hosted-DB name must be a bare basename — never a path. Reject empty, path separators (``/``
    or ``\\`` on either platform), and ``..`` (packet 1000/1066 finding 2). This is the single
    validation both the gate and the FS ops apply; the Linux broker has its own ``valid_name`` guard
    as a further backstop."""
    n = (db_name or "").strip()
    return bool(n) and "/" not in n and "\\" not in n and ".." not in n


def _digest(path: "str | Path") -> str:
    h = hashlib.sha256()
    with open(str(path), "rb") as fh:
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _compartment_path(db_name: str) -> "Path | None":
    """The real on-disk path of ``<db_name>.fmp12`` hosted from the VERIFIED compartment, or None.

    This is the SINGLE resolver used by BOTH the gate (``check_apply_target``) and the write ops, so
    'the gate approved this name' and 'the write touches this file' can never diverge (packet
    1000/1066 finding 1). Because the compartment is a CORPUSfm-owned folder, the service reads AND
    writes it directly — no sudo broker.

    Symlink-safe: a matched entry that is a symlink, or whose realpath escapes the compartment
    folder, is rejected. Case- and .fmp12-insensitive. Never raises.

    **A None from here is not a permission.** It says only that the name is not in the compartment;
    what may then happen is decided by ``_authorize_outside_compartment``."""
    target = _norm_db(db_name)
    for d in compartment_dirs():
        try:
            base = Path(d)
            if not base.is_dir():
                continue
            base_real = base.resolve()
            for f in base.iterdir():
                if not f.name.lower().endswith(".fmp12") or _norm_db(f.name) != target:
                    continue
                if f.is_symlink():
                    continue
                fr = f.resolve()
                if fr.is_file() and base_real in fr.parents:
                    return fr
        except Exception:
            continue
    return None


def _place_direct(src: "str | Path", target: Path) -> tuple[bool, str]:
    """Same-volume atomic swap of a (patched) file onto an EXISTING compartment file the service owns.
    Write a sibling temp then ``os.replace`` (atomic within one filesystem → the live file is always
    the whole old or whole new file), and force mode 664 so ``fmserver`` can host it R/W (Linux; no-op
    on Windows). Never raises."""
    target = Path(target)
    tmp = target.with_name(f".{target.stem}.cfmswap.{os.getpid()}")
    try:
        shutil.copy2(str(src), str(tmp))       # same dir as target → guaranteed same volume
        os.replace(str(tmp), str(target))       # atomic swap
        force_hostable_mode(target)
        return True, f"placed '{target.name}' in the compartment"
    except Exception as exc:
        try:
            tmp.unlink()
        except Exception:
            pass
        return False, f"compartment place failed: {exc}"


def publish_into_compartment(src: "str | Path", db_name: str) -> tuple[bool, str]:
    """Publish a NEW database file into the verified compartment. **Atomic, and NO-REPLACE.**

    Publishing a new file is a different operation from replacing an existing one, and must not be
    forced through ``place()``, whose contract is *replace an existing compartment file* and which
    reaches ``os.replace`` — a call that silently overwrites. Here an existing destination is a
    refusal that leaves the world byte-identical.

    ``os.link`` is the primitive: it is atomic and it FAILS when the destination exists, which is
    exactly the no-replace guarantee. Where linking is unavailable, ``O_CREAT|O_EXCL`` supplies the
    same guarantee (the destination did not exist, so a cleaned-up partial is not data loss)."""
    if not _safe_db_name(db_name):
        return (False, f"refused: '{db_name}' is not a valid database name.")
    try:
        authority = load_published_patch_authority()
    except PatchAuthorityError as exc:
        return (False, f"refused: no verified patch compartment to publish into — {exc}")
    src = Path(src)
    if not src.is_file():
        return (False, f"refused: no such source file: '{src}'")
    dest = authority.patch_hosting_dir / f"{db_name}.fmp12"
    if dest.is_symlink() or dest.exists():
        return (False,
                f"refused: '{dest}' already exists. Publication never replaces an existing "
                "destination; nothing was changed.")
    tmp = dest.with_name(f".{dest.stem}.cfmpub.{os.getpid()}")
    try:
        shutil.copy2(str(src), str(tmp))
        try:
            os.link(str(tmp), str(dest))
        except FileExistsError:
            return (False,
                    f"refused: '{dest}' appeared while publishing. Publication never replaces an "
                    "existing destination; nothing was changed.")
        except OSError:
            # No hard links here — O_EXCL gives the same never-overwrite guarantee.
            fd = os.open(str(dest), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o664)
            try:
                with os.fdopen(fd, "wb") as out, open(str(tmp), "rb") as fh:
                    shutil.copyfileobj(fh, out, _CHUNK)
                    out.flush()
                    os.fsync(out.fileno())
            except Exception:
                try:
                    dest.unlink()
                except Exception:
                    pass
                raise
        force_hostable_mode(dest)
        return True, f"published '{dest.name}' into the compartment"
    except FileExistsError:
        return (False,
                f"refused: '{dest}' already exists. Publication never replaces an existing "
                "destination; nothing was changed.")
    except Exception as exc:
        return False, f"compartment publication failed: {exc}"
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass


def _compartment_restriction_enabled() -> bool:
    """The server-wide ``restrict_apply_to_compartment`` setting (packet 1066), default ON. Fails SAFE
    to the restrictive posture (True) if the config can't be read.

    It is a PREFERENCE, never an authorization: it widens an already-authorized set when off. The
    verified-compartment prerequisite is decided before this is consulted."""
    try:
        from corpusfm.app.app_config import load_app_config
        return bool(load_app_config().restrict_apply_to_compartment)
    except Exception:
        return True


def _storage_identity_gate(db_name: str) -> tuple[bool, str]:
    """The storage-database refusal, and its UNANSWERABLE case.

    An unanswerable storage identity used to be swallowed (``except: pass``) and the target passed
    on. It is now a refusal: not knowing whether this is CORPUSfm's own data is not a reason to
    patch it."""
    try:
        from corpusfm.install import is_storage_database
        storage = bool(is_storage_database(db_name))
    except Exception as exc:
        return (False,
                f"refused: could not determine whether '{db_name}' is the CORPUSfm storage database "
                f"({exc}). An unanswerable storage identity is refused, never passed.")
    if storage:
        return (False,
                f"refused: '{db_name}' is the CORPUSfm storage database — never a patch/apply "
                "target (it holds CORPUSfm's own data). Read-only jobs are allowed.")
    return (True, "")


def check_apply_target(db_name: str) -> tuple[bool, str]:
    """Apply-target policy, unified across Linux + Windows: (ok, reason); reason is '' when allowed.
    Checked EARLY by every apply entry point so a refusal never leaves a production DB closed.

    **Order (packet 1246-05-02 §3, and the order is the safety property):**

      1. **Storage DB → REFUSE, always, first** — orthogonal to every switch. An UNANSWERABLE
         storage identity refuses too.
      2. **Verified-compartment prerequisite** — missing / unreadable / indeterminate / unverified
         compartment authority refuses every patch/apply route.
      3. **Only then** the ``restrict_apply_to_compartment`` preference — ON narrows to the
         compartment, OFF widens the eligible set *within an already-authorized world*.

    Step 3 used to sit at step 2 and return ``(True, "")`` before any compartment lookup, so OFF
    plus an unverified compartment enabled patching of any non-storage hosted database. The
    preference is not an authorization.

    Membership is decided by ``_compartment_path`` — the SAME resolver the write ops use — so an
    approval can never point at a different file than the write touches."""
    if not _safe_db_name(db_name):
        return (False, f"refused: '{db_name}' is not a valid database name (a bare file name is "
                       "required — no path separators or '..').")

    ok, reason = _storage_identity_gate(db_name)
    if not ok:
        return (False, reason)

    try:
        load_published_patch_authority()
    except PatchAuthorityError as exc:
        return (False,
                f"refused: this installation has no VERIFIED CORPUSfm patch compartment, so no "
                f"patch/apply route is open — {exc} Target: '{db_name}'.")

    if not _compartment_restriction_enabled():
        return (True, "")

    if _compartment_path(db_name) is not None:
        return (True, "")
    return (False,
            f"refused: '{db_name}' is hosted from the default Databases directory (or a location "
            f"CORPUSfm cannot verify). CORPUSfm patches only files hosted from its verified "
            f"compartment. Host '{db_name}' from the compartment, or turn off the compartment "
            f"restriction (Settings → FileMaker) for a dedicated patch box.")


def helper_available() -> bool:
    """True when the privileged DB path is usable: the scoped helper is installed (Linux) or the
    Windows direct-FS path is available (LocalSystem + FMS Databases dir present).

    **Its absence selects nothing.** A compartment target needs no helper at all; an
    outside-compartment target needs the broker and refuses without it, *before* any close."""
    if _is_windows():
        from corpusfm.server import win_db_ops
        return win_db_ops.available()
    return Path(HELPER).exists()


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            ["sudo", "-n", HELPER, *args],
            capture_output=True, text=True, timeout=120,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"cfm-db-helper invocation failed: {exc}"
    return r.returncode == 0, (r.stdout + r.stderr).strip()


# ── the privileged broker boundary: FIVE gates, rechecked by the operation itself ──────────


def _no_clobber_gate(db_name: str, target: "Path | None", *, operation: str) -> tuple[bool, str]:
    """The fifth gate: nothing outside the compartment is ever brought into EXISTENCE by these
    routes. Publishing a new file is ``publish_into_compartment``, which is no-replace and
    compartment-only.

    **Where the guarantee comes from, per route — stated truthfully this time.** Two earlier versions
    of this docstring were wrong, and both are recorded because the second was the more instructive
    mistake. The first said existence is "proven by the broker at the moment it acts (it refuses
    ``no such database``)": true of the broker's ``copy-out`` arm only, since its ``place`` arm
    checks the SOURCE and then ``mv -f`` onto the destination unconditionally. The second said an
    ``ApplyAuthority`` "can only be completed from a backup ``copy_out_for`` produced": also false —
    ``complete_apply_authority`` validates the backup it is HANDED, and cannot know where it came
    from. **A caller-supplied file therefore completed an authority for a target that did not exist,
    and the old ``place`` created it.** Measured, not argued.

    The remedy was to remove the route rather than to describe it better, so the honest content of
    this gate is now small:

    - **copy_out / copy_out_for** — the broker refuses a database that is not there, and on Windows
      ``win_db_ops.copy_out`` returns *no such hosted database*. Nothing is created either way.
    - **remove** — ``rm -f`` / ``unlink``. A removal cannot bring a file into existence.
    - **place** — no longer reaches here at all. It refuses every outside-compartment target.
    - **place_authorized** — the ONLY forward broker placement, and it does not rely on this gate for
      creation-safety. Its fifth revalidation OBSERVES the target immediately before writing and
      refuses unless it still holds the captured original content; an absent target is refused
      there, by a fact, at the moment it matters.
    - **Windows** — the Databases directory IS locally stat-able as LocalSystem, so the existence
      check is made here directly rather than inferred.
    """
    if target is None:
        return (False,
                f"refused: CORPUSfm cannot resolve a canonical path for '{db_name}' outside its "
                "compartment, so it cannot prove the operation replaces an existing database "
                f"rather than creating one. {operation} refused.")
    if _is_windows():
        from corpusfm.server import win_db_ops
        if win_db_ops._find_hosted(db_name) is None:
            return (False,
                    f"refused: no existing hosted database '{db_name}' at {target}; these routes "
                    "never create a database outside the compartment.")
    return (True, "")


def _authorize_outside_compartment(
    db_name: str, target: "Path | None", *, operation: str,
) -> tuple[bool, str]:
    """The FIVE gates every outside-compartment operation rechecks ITSELF rather than trusting its
    caller. ``_compartment_path() is None`` authorizes nothing on its own.

    1. the verified-compartment prerequisite;
    2. the preference — global access must be EXPLICITLY enabled;
    3. the target gate;
    4. the storage refusal, evaluated independently rather than inherited;
    5. the no-clobber check.
    """
    try:
        load_published_patch_authority()
    except PatchAuthorityError as exc:
        return (False,
                f"refused: {operation} outside the compartment requires a VERIFIED patch "
                f"compartment — {exc}")

    if _compartment_restriction_enabled():
        return (False,
                f"refused: '{db_name}' is not in CORPUSfm's compartment and global patch access is "
                f"not enabled, so {operation} has no route. Host it from the compartment, or turn "
                "off the compartment restriction (Settings → FileMaker) for a dedicated patch box.")

    ok, reason = check_apply_target(db_name)
    if not ok:
        return (False, reason)

    ok, reason = _storage_identity_gate(db_name)
    if not ok:
        return (False, reason)

    return _no_clobber_gate(db_name, target, operation=operation)


def _broker_target_path(db_name: str) -> "Path | None":
    """The canonical path an outside-compartment operation would act on, resolved ONCE.

    Linux: the broker's own confined root. Windows: the file's existing location (subfolder honored),
    else the top level. ``None`` when it cannot be resolved — which refuses rather than proceeds."""
    if not _safe_db_name(db_name):
        return None
    if _is_windows():
        from corpusfm.server import win_db_ops
        found = win_db_ops._find_hosted(db_name)
        if found is not None:
            return found
        root = win_db_ops.databases_dir()
        return None if root is None else (root / f"{db_name}.fmp12")
    return Path(BROKER_DATABASES_DIR) / f"{db_name}.fmp12"


def _resolve_target(db_name: str) -> "tuple[Path | None, str]":
    """(canonical target, disposition). Resolved ONCE per operation and then carried, never
    re-derived from a database name inside the operation's steps."""
    cp = _compartment_path(db_name)
    if cp is not None:
        return cp, DIRECT_COMPARTMENT
    return _broker_target_path(db_name), BROKER


def copy_out(db_name: str, dest: "str | Path") -> tuple[bool, str]:
    """Copy a hosted db's .fmp12 OUT to a caller-owned dest, so the service can read/patch it.

    An IN-COMPARTMENT file is copied DIRECTLY — the service owns the folder, no broker needed, and
    it reads exactly the file the gate approved. Anything else goes through the five gates before
    the broker (Linux) / direct-FS (Windows) is reached; a failed compartment lookup alone refuses."""
    if not _safe_db_name(db_name):
        return (False, f"refused: '{db_name}' is not a valid database name.")
    target, disposition = _resolve_target(db_name)
    if disposition == DIRECT_COMPARTMENT:
        try:
            shutil.copy2(str(target), str(dest))
            return True, f"copied compartment '{db_name}' -> {dest}"
        except Exception as exc:
            return False, f"compartment copy-out failed: {exc}"
    ok, reason = _authorize_outside_compartment(db_name, target, operation="copy-out")
    if not ok:
        return (False, reason)
    if _is_windows():
        from corpusfm.server import win_db_ops
        return win_db_ops.copy_out(db_name, dest)
    return _run(["copy-out", db_name, str(dest)])


def place(src: "str | Path", db_name: str) -> tuple[bool, str]:
    """Place a (patched) .fmp12 onto an existing file in the VERIFIED COMPARTMENT. Nothing else.

    **Surface reduction, Codex ruling 2026-08-04 — this supersedes the packet language that kept
    four generic filesystem routes.** The previous version accepted an ``ApplyAuthority`` and, on
    strength of it, dispatched to the privileged broker for an outside-compartment target. That was
    unsound, and it was measured: ``complete_apply_authority`` validates the backup it is *handed*,
    never that ``copy_out_for`` produced it, so a caller supplying its own file completed an
    authority for a target that did not exist and this function then CREATED it outside the
    compartment. The fix is not a provenance registry and not a claim that a dataclass is
    unforgeable — it is that ordinary public ``place`` has no business outside the compartment at
    all.

    So: **only ``place_authorized`` performs a forward broker placement**, behind its own five
    fact-based checks made immediately before the write, including an observation of the target;
    and **only ``restore_authorized`` / ``_restore_write`` perform the corresponding bounded
    restore**. There is no third way to write outside the compartment, and no argument to this
    function that creates one."""
    if not _safe_db_name(db_name):
        return (False, f"refused: '{db_name}' is not a valid database name.")
    target, disposition = _resolve_target(db_name)
    if disposition == DIRECT_COMPARTMENT:
        return _place_direct(src, target)
    return (False,
            f"refused: '{db_name}' is not hosted from CORPUSfm's verified compartment, and "
            "ordinary placement never writes outside it. A separately authorized apply performs "
            "that placement through its own operation-scoped authority; there is no route here.")


def _place_via_broker(src: "str | Path", db_name: str) -> tuple[bool, str]:
    """Dispatch to the platform's privileged mechanism. Gates are the caller's; this only dispatches."""
    if _is_windows():
        from corpusfm.server import win_db_ops
        return win_db_ops.place(src, db_name)
    handoff = _make_handoff()
    if handoff is None:
        return (False,
                "refused: the root-owned handoff is unavailable, so there is no race-free way to "
                "hand the broker a source it cannot have swapped. A missing privileged mechanism "
                "is never a reason to write the file some other way.")
    try:
        try:
            shutil.copyfile(str(src), handoff)
        except Exception as exc:  # pragma: no cover - defensive
            return False, f"handoff staging copy failed: {exc}"
        return _run(["place", handoff, db_name])
    finally:
        _run(["rmhandoff", handoff])


def remove(db_name: str) -> tuple[bool, str]:
    """Remove the hosted db_name.fmp12 (sandbox/teardown). In-compartment: direct unlink. Otherwise
    the five gates, then the broker (Linux) / direct-FS (Windows) — never from a failed lookup."""
    if not _safe_db_name(db_name):
        return (False, f"refused: '{db_name}' is not a valid database name.")
    target, disposition = _resolve_target(db_name)
    if disposition == DIRECT_COMPARTMENT:
        try:
            target.unlink()
            return True, f"removed compartment '{db_name}'"
        except FileNotFoundError:
            return True, f"'{db_name}' not present"
        except Exception as exc:
            return False, f"compartment remove failed: {exc}"
    ok, reason = _authorize_outside_compartment(db_name, target, operation="remove")
    if not ok:
        return (False, reason)
    if _is_windows():
        from corpusfm.server import win_db_ops
        return win_db_ops.remove(db_name)
    return _run(["remove", db_name])


def _make_handoff() -> "str | None":
    """Ask the broker to pre-create a root-owned handoff dir + a service-owned 0600 file inside,
    returning the file path (the service writes the payload into it). None when unavailable — an
    old helper without the op, or the handoff root not provisioned. **A None is a refusal**, not a
    licence to write the file some other way."""
    ok, out = _run(["mkhandoff"])
    if not ok or not out:
        return None
    path = out.strip().splitlines()[-1].strip()
    return path if path.startswith(HANDOFF_ROOT + "/") else None


# ``place_via_handoff`` is RETIRED (Codex ruling, 2026-08-04). It was the generic name-addressed
# route to the privileged broker, and after this packet moved the apply loop onto
# ``place_authorized`` it had no legitimate caller left: its sandbox users wanted the compartment's
# own file (``replace_sandbox_file``), and its promote user wanted a no-replace publication
# (``publish_into_compartment``). An obsolete generic route that can still write the fmserver-owned
# directory is exactly the surface this family exists to remove, so it is gone rather than kept
# "in case". The TOCTOU-closed handoff itself is NOT retired — it lives in ``_place_via_broker``,
# reachable only from ``place_authorized`` and ``_restore_write``.


def replace_sandbox_file(produced: "str | Path") -> tuple[bool, str]:
    """Overwrite the compartment's own sandbox file — direct, confined, atomic, under the
    compartment's own permissions. **Never the privileged helper**, and never a re-creation
    elsewhere: an absent sandbox refuses."""
    try:
        target = sandbox_file_path()
    except PatchAuthorityError as exc:
        return (False, f"refused: {exc}")
    return _place_direct(produced, target)


# ── authorization, minted once per operation and CARRIED — split at the close ──────────────


@dataclass(frozen=True)
class ApplyPermit:
    """Minted BEFORE any close. Opaque, in-process, unforgeable: never argv, never JSON, never a
    manifest field, never user input, never reconstructed from a database name.

    It authorizes exactly two things — CLOSING and COPYING OUT this one target during this one
    operation. It is NOT sufficient to place anything and NOT sufficient to restore anything."""

    operation_id: str
    installation_id: str
    manifest_generation: int
    target_path: Path                  # THE canonical target, resolved once, never re-resolved
    database: str
    disposition: str                   # DIRECT_COMPARTMENT | BROKER
    compartment_verified: bool         # the verified-compartment prerequisite, decided
    access_decision: str               # the restriction / global-access decision, recorded
    storage_check: str                 # "answerable_non_storage" — the only passing value
    pre_close_identity: dict           # target identity + metadata as observed BEFORE the close
    helper_available: bool             # required for disposition == BROKER


@dataclass(frozen=True)
class ApplyAuthority:
    """Completed only AFTER the close and a SUCCESSFUL copy-out. Carries every ApplyPermit field
    plus what only a closed file can supply. This is what places and what restores."""

    permit: ApplyPermit
    backup_path: Path                  # canonical
    backup_size: int
    backup_digest: str
    original_digest: str               # the target's original content, established FROM the
                                       # post-close backup — never from a digest taken while open
    proposed_digest: "str | None"      # the forward/output digest, once generated
    state: str                         # the operation state machine


@dataclass(frozen=True)
class PlacementOutcome:
    """Placement REPORTS whether publication occurred. Mutation is never inferred from an exit code:
    an ambiguous status is ``uncertain``, which routes to the restore inspection rather than a guess."""

    ok: bool
    published: str                     # PUBLICATION_OCCURRED | _DID_NOT_OCCUR | _UNCERTAIN
    output: str


@dataclass(frozen=True)
class RestoreOutcome:
    """One of the lifecycle result words, chosen by INSPECTING the target rather than by which step
    failed: ``no_change`` (nothing was placed), ``rolled_back`` (this operation's own doing, undone),
    ``manual_action_required`` (an independent change we refuse to overwrite)."""

    result: str
    output: str
    backup_path: "Path | None" = None


# Bounded on purpose: a long-lived web process would otherwise accumulate one id per apply forever.
# The bound is generous next to the number of applies a box performs between restarts, and an id
# that ages out belongs to an operation whose permit and authority are unreachable anyway (they are
# in-process objects held only by the loop that minted them).
_CONSUMED_LIMIT = 4096
_CONSUMED_OPERATIONS: "OrderedDict[str, None]" = OrderedDict()


def close_operation(operation_id: str) -> None:
    """End an apply operation. Its permit and authority authorize nothing afterwards."""
    _CONSUMED_OPERATIONS[operation_id] = None
    while len(_CONSUMED_OPERATIONS) > _CONSUMED_LIMIT:
        _CONSUMED_OPERATIONS.popitem(last=False)


def _operation_is_live(operation_id: str) -> bool:
    return operation_id not in _CONSUMED_OPERATIONS


def mint_apply_permit(db_name: str) -> "tuple[ApplyPermit | None, str]":
    """The five authorization steps, ALL of them before any close (packet 1246-05-02 §3.2).

    A failure at any of the five closes nothing, so a refusal never leaves a production database
    down. The backup is deliberately NOT required here: the real loop closes and then copies out,
    because that backup is both the restore point and the patch source, and a copy taken while FMS
    holds the file open is neither.

    **The storage refusal leads**, as it does in ``check_apply_target`` and for the same reason: it
    is orthogonal to every switch and to the installation's state, so "this is CORPUSfm's own data"
    must be the answer an operator gets whether or not a compartment was ever provisioned."""
    if not _safe_db_name(db_name):
        return None, f"refused: '{db_name}' is not a valid database name."

    # 1. storage identity answerable and non-storage — first, always
    ok, reason = _storage_identity_gate(db_name)
    if not ok:
        return None, reason

    # 2. valid, VERIFIED authority
    try:
        authority = load_published_patch_authority()
    except PatchAuthorityError as exc:
        return None, (f"refused: this installation has no VERIFIED CORPUSfm patch compartment, so "
                      f"no apply route is open — {exc}")

    # 3. the restriction / global-access preference permits this target
    ok, reason = check_apply_target(db_name)
    if not ok:
        return None, reason

    # 4. the exact canonical target, resolved once, with its pre-close identity
    target, disposition = _resolve_target(db_name)
    if target is None:
        return None, (f"refused: CORPUSfm cannot resolve a canonical path for '{db_name}', so it "
                      "cannot authorize an operation against it.")

    # 5. a broker disposition needs its privileged mechanism — checked HERE, before the close
    helper = helper_available()
    if disposition == BROKER and not helper:
        return None, (f"refused: '{db_name}' is outside CORPUSfm's compartment, so this apply needs "
                      "the privileged placement mechanism, which is not available. Nothing was "
                      "closed. Helper unavailability never selects a weaker route.")

    return ApplyPermit(
        operation_id=uuid.uuid4().hex,
        installation_id=authority.installation_id,
        manifest_generation=authority.generation,
        target_path=target,
        database=db_name,
        disposition=disposition,
        compartment_verified=True,
        access_decision=("compartment_restricted" if _compartment_restriction_enabled()
                         else "global_access_enabled"),
        storage_check="answerable_non_storage",
        pre_close_identity=_identity_of(target),
        helper_available=helper,
    ), ""


def _identity_of(target: Path) -> dict:
    """What can be observed of the target without opening it. On Linux a broker target sits in a
    directory the service cannot stat, so ``resolvable`` is honestly False there rather than faked."""
    try:
        st = target.stat()
        return {"resolvable": True, "path": str(target), "size": st.st_size,
                "mtime_ns": st.st_mtime_ns, "is_symlink": target.is_symlink()}
    except Exception as exc:
        return {"resolvable": False, "path": str(target), "reason": str(exc)}


def copy_out_for(permit: ApplyPermit, dest: "str | Path") -> tuple[bool, str]:
    """Copy the permit's exact target out. Takes the PERMIT — never a database name, and it
    re-resolves nothing."""
    if not isinstance(permit, ApplyPermit):
        return (False, "refused: copy-out requires an ApplyPermit minted for this operation.")
    if not _operation_is_live(permit.operation_id):
        return (False, "refused: this operation is finished; its permit authorizes nothing.")
    if permit.disposition == DIRECT_COMPARTMENT:
        try:
            shutil.copy2(str(permit.target_path), str(dest))
            return True, f"copied compartment '{permit.database}' -> {dest}"
        except Exception as exc:
            return False, f"compartment copy-out failed: {exc}"
    ok, reason = _authorize_outside_compartment(
        permit.database, permit.target_path, operation="copy-out")
    if not ok:
        return (False, reason)
    if _is_windows():
        from corpusfm.server import win_db_ops
        return win_db_ops.copy_out(permit.database, dest)
    return _run(["copy-out", permit.database, str(dest)])


def complete_apply_authority(
    permit: ApplyPermit, backup_path: "str | Path",
) -> "tuple[ApplyAuthority | None, str]":
    """Complete the authority from a POST-CLOSE backup. The original digest is established from that
    backup and never from a digest taken while the database was open."""
    if not isinstance(permit, ApplyPermit):
        return None, "refused: an ApplyAuthority can only be completed from an ApplyPermit."
    if not _operation_is_live(permit.operation_id):
        return None, "refused: this operation is finished."
    backup = Path(backup_path)
    try:
        size = backup.stat().st_size
        if size <= 0:
            return None, f"refused: the backup at {backup} is empty; it is not a restore point."
        digest = _digest(backup)
    except Exception as exc:
        return None, f"refused: the backup at {backup} is unusable ({exc}); no authority is completed."
    target, disposition = _resolve_target(permit.database)
    if target != permit.target_path or disposition != permit.disposition:
        return None, (f"refused: '{permit.database}' no longer resolves to the target this operation "
                      f"authorized ({permit.target_path}); nothing further is done.")
    return ApplyAuthority(
        permit=permit, backup_path=backup.resolve(), backup_size=size, backup_digest=digest,
        original_digest=digest, proposed_digest=None, state="authorized",
    ), ""


def with_proposed(authority: ApplyAuthority, produced: "str | Path") -> "tuple[ApplyAuthority | None, str]":
    """Record the digest of what is about to be placed, so 'the target changed' and 'the target
    changed BECAUSE WE CHANGED IT' can be told apart during recovery."""
    if not isinstance(authority, ApplyAuthority):
        return None, "refused: a proposed digest belongs to an ApplyAuthority."
    try:
        digest = _digest(produced)
    except Exception as exc:
        return None, f"refused: the produced file is unreadable ({exc})."
    return replace(authority, proposed_digest=digest, state="proposed"), ""


def _observe_target(authority: ApplyAuthority) -> tuple[str, str]:
    """('digest', <sha>) | ('absent', '') | ('unknown', reason).

    A compartment target is read directly. A broker target is read the only way the unprivileged
    service can read it — by copying it out — so an honest answer is available on both platforms
    instead of a guess."""
    permit = authority.permit
    if permit.disposition == DIRECT_COMPARTMENT:
        try:
            if not permit.target_path.exists():
                return "absent", ""
            return "digest", _digest(permit.target_path)
        except Exception as exc:
            return "unknown", str(exc)
    work = None
    try:
        work = Path(tempfile.mkdtemp(prefix="cfm_observe_", dir=staging_dir()))
        probe = work / "target.fmp12"
        if _is_windows():
            from corpusfm.server import win_db_ops
            ok, out = win_db_ops.copy_out(permit.database, str(probe))
        else:
            ok, out = _run(["copy-out", permit.database, str(probe)])
        if not ok:
            if "no such database" in (out or "").lower():
                return "absent", ""
            return "unknown", out
        return "digest", _digest(probe)
    except Exception as exc:
        return "unknown", str(exc)
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


def place_authorized(authority: ApplyAuthority, produced: "str | Path") -> PlacementOutcome:
    """The forward placement. Revalidates FIVE facts immediately before it, and any divergence
    refuses BEFORE the first byte is written."""
    if not isinstance(authority, ApplyAuthority):
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                "refused: placement requires an ApplyAuthority — an ApplyPermit "
                                "authorizes closing and copying out, and nothing else.")
    permit = authority.permit
    if not _operation_is_live(permit.operation_id):
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                "refused: this operation is finished; its authority authorizes nothing.")
    if authority.proposed_digest is None:
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                "refused: nothing was recorded about what is being placed.")

    # 1. the manifest generation has not moved
    try:
        current = load_published_patch_authority()
    except PatchAuthorityError as exc:
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                f"refused before writing: the patch compartment is no longer "
                                f"authoritative — {exc}")
    if current.generation != permit.manifest_generation or \
            current.installation_id != permit.installation_id:
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                "refused before writing: this installation's manifest moved while "
                                "the apply was in flight.")

    # 2. the target identity still resolves to the captured path
    target, disposition = _resolve_target(permit.database)
    if target != permit.target_path or disposition != permit.disposition:
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                f"refused before writing: '{permit.database}' no longer resolves to "
                                f"{permit.target_path}.")

    # 3. the restore point is intact BEFORE the thing that might need it happens
    try:
        if _digest(authority.backup_path) != authority.backup_digest:
            return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                    "refused before writing: the pristine backup no longer matches "
                                    "its recorded digest.")
    except Exception as exc:
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                f"refused before writing: the pristine backup is unreadable ({exc}).")

    # 4. what is about to be placed is what was produced
    try:
        if _digest(produced) != authority.proposed_digest:
            return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                    "refused before writing: the file to be placed is not the one "
                                    "this operation produced.")
    except Exception as exc:
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                f"refused before writing: the produced file is unreadable ({exc}).")

    # 5. the current target still matches the captured original state
    kind, value = _observe_target(authority)
    if kind != "digest" or value != authority.original_digest:
        detail = {"absent": "the target is gone", "unknown": f"the target could not be read ({value})"}\
            .get(kind, "the target changed underneath this operation")
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR,
                                f"refused before writing: {detail}.")

    if permit.disposition == DIRECT_COMPARTMENT:
        ok, out = _place_direct(produced, permit.target_path)
        return PlacementOutcome(
            ok, PUBLICATION_OCCURRED if ok else PUBLICATION_DID_NOT_OCCUR, out)

    ok, reason = _authorize_outside_compartment(
        permit.database, permit.target_path, operation="place")
    if not ok:
        return PlacementOutcome(False, PUBLICATION_DID_NOT_OCCUR, reason)
    ok, out = _place_via_broker(produced, permit.database)
    # A privileged mechanism that reports failure may still have acted. Never infer from the code.
    return PlacementOutcome(ok, PUBLICATION_OCCURRED if ok else PUBLICATION_UNCERTAIN, out)


def restore_authorized(authority: ApplyAuthority) -> RestoreOutcome:
    """Rollback is an OBLIGATION, not a second authorization — and it INSPECTS before it writes.

    It does not re-evaluate ``restrict_apply_to_compartment`` and does not require the forward gate
    to still hold: an administrator toggling the preference mid-apply, or a compartment that became
    unverified, would otherwise strand a half-applied database beside a pristine backup the product
    refuses to use.

    It is bounded absolutely: only this operation's authority, only its captured backup and target,
    consumed with the operation that minted it."""
    if not isinstance(authority, ApplyAuthority):
        return RestoreOutcome("failed_before_change",
                              "refused: restore requires this operation's ApplyAuthority.")
    permit = authority.permit
    if not _operation_is_live(permit.operation_id):
        return RestoreOutcome("failed_before_change",
                              "refused: this operation is finished; its authority authorizes nothing.")

    kind, value = _observe_target(authority)

    if kind == "digest" and value == authority.original_digest:
        return RestoreOutcome("no_change",
                              "the target still holds its original content — nothing was placed, so "
                              "no restore write is owed.")

    if kind == "absent" or (kind == "digest" and value == authority.proposed_digest):
        ok, out = _restore_write(authority)
        if not ok:
            return RestoreOutcome(
                "manual_action_required",
                f"the pristine backup could not be put back ({out}). It is preserved at "
                f"{authority.backup_path}.", authority.backup_path)
        return RestoreOutcome("rolled_back", f"restored the pristine backup: {out}")

    if kind == "unknown":
        return RestoreOutcome(
            "manual_action_required",
            f"the target could not be inspected ({value}), so CORPUSfm will not write over it. The "
            f"pristine backup is preserved at {authority.backup_path}.", authority.backup_path)

    return RestoreOutcome(
        "manual_action_required",
        f"the target at {permit.target_path} matches neither this operation's original nor its "
        f"proposed content — it was changed independently and CORPUSfm will not overwrite it. The "
        f"pristine backup is preserved at {authority.backup_path}.", authority.backup_path)


def _restore_write(authority: ApplyAuthority) -> tuple[bool, str]:
    """Put the captured backup back onto the captured target. No gate, by design; bounded by the
    authority itself, which names one path and one source and dies with the operation."""
    permit = authority.permit
    if permit.disposition == DIRECT_COMPARTMENT:
        return _place_direct(authority.backup_path, permit.target_path)
    return _place_via_broker(authority.backup_path, permit.database)
