"""Install marker — records the deployment mode and storage config.

Written by the installer (or on first run of a packaged build) into this installation's config
directory, which `lifecycle.app_paths` resolves from the published installation record. It was
`~/.corpusfm/install.yaml` before packet 1246-03-01; there is no longer a home-directory answer.

Minimal contents (always present):
    mode: standalone   # or: server
    installed_at: 2026-05-16
    version: "1.0"

Optional FM backend config (server mode, storage_backend: fm_odata):
    storage_backend: fm_odata
    fm_host: 192.168.1.246
    fm_database: CORPUSfm
    fm_user: CORPUSfm
    fm_password: enc:<fernet>    # Fernet-encrypted at rest; plaintext when read back
    fm_verify_ssl: false        # optional, default false
    storage_connection: <name>  # ServerConfig backing storage (lock key)

The apply compartment is NOT recorded here (packet 1246-05-02). The ``support_dir`` and
``hosting_dir`` marker keys are gone: an install.yaml key is a configured claim, and the compartment
has to be a PROVEN one. It now lives in the installation manifest as ``paths.patch_hosting_dir`` plus
the ``patch`` block, read by ``db_helper.load_published_patch_authority()``.
(windows_apply_allowlist — the pre-1066 name-based Windows gate — is SUPERSEDED and ignored.)

Credentials are stored here (not in FileMaker); fm_password is Fernet-encrypted
at rest via core.crypto and decrypted by read_install_config() for callers.

Public API:
    read_install_mode() -> str | None
    read_install_config() -> dict
    write_install_marker(mode, version)
    write_fm_backend_config(host, database, user, password, *, verify_ssl, connection_name)
    activate_fm_backend(config_name, database=None) -> bool
    storage_backend_connection() -> str | None
    ensure_marker_written(mode, version)
    marker_path() -> Path
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Optional

import yaml

from corpusfm.core.crypto import (
    decrypt_secret,
    encrypt_secret,
    is_legacy_plaintext_secret,
)

_VALID_MODES = ("standalone", "server")


def marker_path() -> Path:
    """The install marker, in this installation's config directory (packet 1246-03-01).

    Was `Path.home()/.corpusfm/install.yaml`, i.e. wherever the installer happened to point HOME.
    Now it is whatever the published installation record names — `/etc/corpusfm` on Linux,
    `ProgramData\\CORPUSfm\\config` on Windows — found by the layout rather than by an environment
    variable. **There is no home-directory fallback:** an installation whose record is missing or
    unreadable raises `InstallationStateUnclear` rather than answering from `HOME`, and that
    propagates on purpose. `read_install_mode()` fails closed to `server` for a *corrupt marker*;
    an unresolvable *layout* is a different and larger failure, and silently reading some other
    file's mode would be the exact substitution this packet exists to remove."""
    from corpusfm.lifecycle import app_paths
    return app_paths.config_dir() / "install.yaml"


def _write_marker(p: Path, data: dict) -> None:
    """Write install.yaml 0600 under a 0700 parent. It carries the (Fernet-encrypted) fm_password
    plus the FM host/user/database topology — so keep the file itself non-world-readable, not just
    the secret inside it (defense in depth; the box key must not be the only thing standing between
    a local read and the credential). On Windows chmod is a no-op — the installer ACL-locks the
    ConfigHome tree instead."""
    from corpusfm.core import secure_fs
    secure_fs.write_text_private(
        p, yaml.dump(data, default_flow_style=False, allow_unicode=True), encoding="utf-8")


def read_install_mode() -> Optional[str]:
    """Return 'standalone', 'server', or None if no marker exists.

    A PRESENT-but-unparseable/invalid marker fails CLOSED → 'server' (auth on): a corrupt
    install.yaml on a real deployment must never silently disable auth/gates/CSRF. Only a
    genuinely ABSENT marker returns None (the LocalBackend dev/test path — not server, no auth)."""
    p = marker_path()
    if not p.exists():
        return None
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        mode = data.get("mode", "").strip().lower()
    except Exception:
        return "server"
    return mode if mode in _VALID_MODES else "server"


def write_install_marker(mode: str, version: str = "1.0") -> None:
    """Write (or overwrite) the install marker with the given mode."""
    if mode not in _VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {_VALID_MODES}")
    p = marker_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "mode": mode,
        "installed_at": str(date.today()),
        "version": version,
    }
    _write_marker(p, data)


def read_install_config() -> dict:
    """Return the full install.yaml contents as a dict, or {} if not present.

    `fm_password` is decrypted for callers (in-memory is always plaintext). A legacy
    plaintext value on disk is migrated to encrypted-at-rest on first read (best-effort,
    once — after that it carries the `enc:` marker and is never rewritten)."""
    p = marker_path()
    if not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    pw = str(data.get("fm_password", ""))
    if pw and not is_legacy_plaintext_secret(pw):
        data["fm_password"] = decrypt_secret(pw)  # encrypted on disk → plaintext for callers
    elif pw:
        # legacy plaintext on disk: pw is already the value to return; re-save encrypted once.
        try:
            disk = dict(data)
            disk["fm_password"] = encrypt_secret(pw)
            _write_marker(p, disk)
        except Exception:
            pass
    return data


def write_fm_backend_config(
    host: str,
    database: str,
    user: str,
    password: str,
    *,
    verify_ssl: bool = False,
    connection_name: Optional[str] = None,
) -> None:
    """Merge FM OData backend connection fields into install.yaml.

    Preserves all existing fields (mode, version, installed_at, etc.) and
    adds/updates the FM backend entries. When ``connection_name`` is given it is
    recorded as ``storage_connection`` — the name of the ServerConfig that backs
    storage. That name is the lock key: the Connections UI makes that connection
    read-only and unremovable while it is the active backend.
    """
    p = marker_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = yaml.safe_load(p.read_text(encoding="utf-8")) or {} if p.exists() else {}
    except Exception:
        existing = {}
    existing.update({
        "storage_backend": "fm_odata",
        "fm_host": host,
        "fm_database": database,
        "fm_user": user,
        "fm_password": encrypt_secret(password),
        "fm_verify_ssl": verify_ssl,
    })
    if connection_name:
        existing["storage_connection"] = connection_name
    _write_marker(p, existing)


def write_web_deployment(prefix: str, port: int) -> None:
    """Record the co-located reverse-proxy deployment in install.yaml.

    `web_prefix` is the migration marker the app reads (deployment.py): its presence means
    this install has been put behind the FMS web server at `prefix` (e.g. "/corpusfm"), so
    the app prefixes its URLs, sets a Secure cookie, and drops the un-migrated warning gate.
    The installer writes this after applying the proxy + flipping the unit."""
    p = marker_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = yaml.safe_load(p.read_text(encoding="utf-8")) or {} if p.exists() else {}
    except Exception:
        existing = {}
    existing["web_prefix"] = "/" + str(prefix).strip("/")
    existing["web_port"] = int(port)
    _write_marker(p, existing)


def _existing_marker_mapping_or_raise(p: Path) -> dict:
    """Read the RAW install.yaml mapping for a merge-write, or ``{}`` when the file genuinely does not
    exist. If the file EXISTS but is unreadable, malformed, or not a mapping, RAISE (packet 1180
    correction) — a merge-write must never substitute ``{}`` for an unreadable file, which would erase
    the FM topology + the encrypted credential. The caller fails BEFORE any mutation, so the file's bytes
    are preserved for hand recovery."""
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8")
    except Exception as exc:
        raise RuntimeError("install.yaml could not be read; refusing to overwrite it (FM topology + "
                           "credential preserved). Fix file permissions, then retry.") from exc
    try:
        data = yaml.safe_load(text)
    except Exception as exc:
        raise RuntimeError("install.yaml is malformed (invalid YAML); refusing to overwrite it (FM "
                           "topology + credential preserved). Fix the file, then retry.") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RuntimeError("install.yaml is not a mapping; refusing to overwrite it (FM topology + "
                           "credential preserved). Fix the file, then retry.")
    return data


def set_public_base_url(url: str) -> None:
    """Persist the **MCP address** (install.yaml ``public_base_url``, packet 1180) — the
    one deployment-wide HTTPS base another machine uses to reach this box, including the web prefix; the
    durable value remote jobs, MCP identity, and generated external links all resolve through
    ``deployment.external_base()``. Reachable from another host (a LAN address is fine), not necessarily
    internet-public. An empty/blank value clears it. Writes ONLY ``public_base_url`` (never re-creates
    the retired ``push_callback_url``) and preserves all other install.yaml fields (fm_password stays
    encrypted on disk — we read/write the raw mapping, no decrypt round-trip).

    RAISES before mutating if an existing install.yaml is unreadable/malformed/not-a-mapping — it never
    substitutes an empty mapping for a broken file (which would erase the FM topology + credential)."""
    p = marker_path()
    existing = _existing_marker_mapping_or_raise(p)     # refuse to clobber a broken file (before mkdir/write)
    p.parent.mkdir(parents=True, exist_ok=True)
    val = (url or "").strip().rstrip("/")
    if val:
        existing["public_base_url"] = val
    else:
        existing.pop("public_base_url", None)
    existing.pop("push_callback_url", None)     # never leave the retired key behind
    _write_marker(p, existing)


RETIRED_PUSH_CALLBACK_ENV = "CORPUSFM_PUSH_CALLBACK_URL"    # retired (packet 1180); never consumed


def retired_push_env_warning() -> str:
    """A one-line rename warning when the retired ``CORPUSFM_PUSH_CALLBACK_URL`` is present in the
    environment, else ``""``. Bounded migration code — the app NEVER consumes this variable as an
    alternate MCP address. CORPUSfm owns no service environment file that ever carried
    this variable (the only owned env files, ``.mcp_env`` / ``.ai_env``, hold the MCP token and AI keys,
    never a callback URL), so an administrator-owned environment must rename it to
    ``CORPUSFM_PUBLIC_BASE_URL`` themselves — there is no owned file to migrate automatically."""
    import os
    if os.environ.get(RETIRED_PUSH_CALLBACK_ENV, "").strip():
        return (f"{RETIRED_PUSH_CALLBACK_ENV} is retired and ignored — rename it to "
                "CORPUSFM_PUBLIC_BASE_URL (the MCP address). It is not used as an "
                "alternate value.")
    return ""


def _norm_base_for_migration(v: str) -> str:
    """Normalize a deployment base for equivalence comparison during migration ONLY: case-fold the
    scheme + host and drop exactly one trailing slash. Everything else — userinfo, port, path, params,
    query, fragment — is preserved VERBATIM, so two values that differ in any of those compare UNEQUAL
    (a difference must surface as a conflict, never be normalized away). Never rewrites a caller's value."""
    from urllib.parse import urlsplit, urlunsplit
    s = (v or "").strip()
    if s.endswith("/"):
        s = s[:-1]
    try:
        p = urlsplit(s)
        netloc = (p.hostname or "").lower()
        if p.port is not None:
            netloc = f"{netloc}:{p.port}"
        if p.username is not None or p.password is not None:      # userinfo preserved case-sensitively
            userinfo = p.username or ""
            if p.password is not None:
                userinfo += ":" + p.password
            netloc = userinfo + "@" + netloc
        return urlunsplit((p.scheme.lower(), netloc, p.path, p.query, p.fragment))
    except Exception:
        return s.lower()


def _write_verify_restore(p: Path, data: dict, prior_bytes: str, *,
                          expect_present=None, expect_absent=None) -> str:
    """Write ``data`` to the marker and PROVE the on-disk result matches expectations. If the write cannot
    be proven, RESTORE the exact prior bytes verbatim and prove THAT (packet 1180 correction — an unproven
    migration write must not be left half-applied). Returns:

    - ``"ok"`` — written and proven.
    - ``"restored"`` — write unproven; the exact prior install.yaml bytes were restored and confirmed.
    - ``"unrecoverable"`` — write unproven AND the prior bytes could not be restored/confirmed.
    """
    try:
        _write_marker(p, data)
        check = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        ok = True
        if expect_absent and expect_absent in check:
            ok = False
        if expect_present:
            k, val = expect_present
            if str(check.get(k, "") or "").strip() != val:
                ok = False
        if ok:
            return "ok"
    except Exception:
        pass
    try:
        from corpusfm.core import secure_fs
        secure_fs.write_text_private(p, prior_bytes, encoding="utf-8")
        if p.read_text(encoding="utf-8") == prior_bytes:
            return "restored"
    except Exception:
        pass
    return "unrecoverable"


def migrate_public_base_url_config() -> "tuple[str, str]":
    """One-time, atomic migration of the retired persisted ``push_callback_url`` → ``public_base_url``
    (packet 1180). Idempotent — a no-op once done. Returns ``(status, warning)``:

    - ``("noop", "")`` — nothing legacy to migrate.
    - ``("migrated", "")`` — the legacy key was renamed to ``public_base_url`` (absent case, after
      VALIDATING the legacy value) or dropped as a duplicate of an equivalent ``public_base_url``
      (both-present-equivalent case). The write is re-read and proven before this is returned.
    - ``("conflict", <warning>)`` — BOTH keys exist with DIFFERENT values; nothing is written (never
      silently pick one and discard the other) and the caller surfaces the choice.
    - ``("invalid_legacy", <warning>)`` — the legacy-only value is NOT a valid MCP address
      for this deployment; it is left UNTOUCHED (no ``public_base_url`` written) with actionable guidance.
    - ``("error", <warning>)`` — the file could not be read/parsed, OR the write could not be proven; an
      unproven write restores the exact prior bytes (or, if even that fails, reports that exact recovery
      is required). Never reported as noop and never silently swallowed (packet 1180 correction).

    Reads/writes the RAW install.yaml mapping so ``fm_password`` stays encrypted on disk (no decrypt
    round-trip). This is bounded migration code — the only current place the retired key name appears."""
    p = marker_path()
    if not p.exists():
        return ("noop", "")
    try:
        prior_bytes = p.read_text(encoding="utf-8")
    except Exception:
        return ("error", "install.yaml could not be read; the MCP address migration did "
                         "not run (check file permissions).")
    try:
        raw = yaml.safe_load(prior_bytes)
    except Exception:
        return ("error", "install.yaml could not be parsed (malformed YAML); the External CORPUSfm "
                         "address migration did not run. Fix the file, then reload.")
    if raw is None:
        return ("noop", "")
    if not isinstance(raw, dict):
        return ("error", "install.yaml is not a valid mapping; the MCP address migration "
                         "did not run. Fix the file, then reload.")
    old = str(raw.get("push_callback_url", "") or "").strip()   # NO pre-strip of slashes (packet 1180)
    new = str(raw.get("public_base_url", "") or "").strip()
    if not old:
        return ("noop", "")

    if new:
        if _norm_base_for_migration(old) == _norm_base_for_migration(new):
            raw2 = dict(raw)
            raw2.pop("push_callback_url", None)
            st = _write_verify_restore(p, raw2, prior_bytes, expect_absent="push_callback_url")
            if st == "ok":
                return ("migrated", "")
            if st == "restored":
                return ("error", "Could not remove the retired push_callback_url line (write not "
                                 "confirmed); the prior install.yaml was restored. Remove it by hand.")
            return ("error", "Could not remove the retired push_callback_url line AND could not restore "
                             "install.yaml — exact recovery is required (restore install.yaml from backup).")
        return ("conflict",
                "install.yaml has conflicting deployment addresses: public_base_url and the retired "
                "push_callback_url differ. Remove the push_callback_url line (keep public_base_url) to "
                "resolve — CORPUSfm will not choose between them.")

    # legacy-only → VALIDATE the value before writing it as the primary key; invalid data is left alone.
    from corpusfm.app.web.deployment import _validate_external_base
    valid = _validate_external_base(old)
    if not valid:
        return ("invalid_legacy",
                "install.yaml has a retired push_callback_url that is not a valid MCP address for this "
                "deployment, so it was NOT migrated automatically. Set a valid public_base_url in "
                "Settings -> MCP (https://<host> with the web prefix, non-loopback) and remove the "
                "push_callback_url line.")
    raw2 = dict(raw)
    raw2["public_base_url"] = valid
    raw2.pop("push_callback_url", None)
    st = _write_verify_restore(p, raw2, prior_bytes, expect_present=("public_base_url", valid),
                               expect_absent="push_callback_url")
    if st == "ok":
        return ("migrated", "")
    if st == "restored":
        return ("error", "Could not migrate push_callback_url → public_base_url (write not confirmed); "
                         "the prior install.yaml was restored. Set the address in Settings.")
    return ("error", "Could not migrate push_callback_url → public_base_url AND could not restore "
                     "install.yaml — exact recovery is required (restore install.yaml from backup).")


def storage_backend_connection() -> Optional[str]:
    """Return the name of the ServerConfig serving as the storage backend.

    Returns None when storage is local, or when an fm_odata backend was written
    without a recorded connection name (legacy / raw-credential installs).
    """
    from corpusfm.lifecycle import runtime_storage

    if runtime_storage.is_published():        # published record wins; no install.yaml for storage
        return runtime_storage.connection_name()
    config = read_install_config()
    if config.get("storage_backend") != "fm_odata":
        return None
    return config.get("storage_connection") or None


def storage_database_name() -> Optional[str]:
    """The FM file CORPUSfm uses as its OWN storage backend (``fm_database`` in
    install.yaml), or None when storage is local. This file must never be the target
    of a patch / apply / close / open operation — see is_storage_database()."""
    # THE PATCH REFUSAL DEPENDS ON THIS (packet 1246-08 §11.2 row 3). A reader left on the retired
    # store returns None on a published box, `is_storage_database` then returns False, and the guard
    # that keeps apply/close/open away from CORPUSfm's own corpus silently stops refusing.
    from corpusfm.lifecycle import runtime_storage

    if runtime_storage.is_published():
        return runtime_storage.database_name()
    config = read_install_config()
    if config.get("storage_backend") != "fm_odata":
        return None
    return config.get("fm_database") or None


def is_storage_database(name: str) -> bool:
    """True when ``name`` is CORPUSfm's own storage-backend database (case- and
    .fmp12-insensitive). Patch/apply/close/open tools MUST refuse it so they can never
    take CORPUSfm's own data store offline or rewrite it. Read-only jobs are fine.

    **A PROTECTION PREDICATE IS A UNION, NOT A SELECTION (packet 1246-10-04).** Every other consumer
    picks one authority — the published record when there is one. This one asks BOTH, because the
    two can legitimately disagree mid-migration: a published installation that has not composed its
    corpus yet names none, while the retired store still does. Selecting the published answer there
    returns False and the guard silently stops refusing, which is §11.2 row 3's named hazard. A name
    that EITHER authority calls the corpus is refused."""
    if not name:
        return False

    def _norm(n: str) -> str:
        n = n.strip()
        return (n[:-6] if n.lower().endswith(".fmp12") else n).lower()

    candidates = set()
    try:
        from corpusfm.lifecycle import runtime_storage

        published = runtime_storage.database_name()
        if published:
            candidates.add(_norm(published))
    except Exception:  # noqa: BLE001 — an unreadable record narrows nothing; the legacy name stands
        pass
    try:
        config = read_install_config()
        if config.get("storage_backend") == "fm_odata" and config.get("fm_database"):
            candidates.add(_norm(config["fm_database"]))
    except Exception:  # noqa: BLE001
        pass

    return _norm(name) in candidates


def ensure_marker_written(mode: str, version: str = "1.0") -> None:
    """Write the marker only if it does not already exist."""
    if read_install_mode() is None:
        write_install_marker(mode, version)
