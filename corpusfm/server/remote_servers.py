"""Remote FMS server registry (packet 1015, redesigned 2026-07-08).

A remote FileMaker server the Jobs page can target. Its ONLY job is to authenticate to that
server's **Admin API** (fmsadmin account + password → session token → hosted-file list) so the
Jobs page can populate its file gallery for that server. It carries NO file-access (OData)
credential and NO PKI — file access is a per-JOB concern (JOB.CredentialData), set on the job.

Fields: **Name · Host · Account · Password · Verify-TLS** (Account/Password = the fmsadmin
Admin-API credential; Verify-TLS is an opt-in per-server toggle, default off — FMS certs are commonly
self-signed). Stored in the FileMaker DB (the SERVER logical table) so they are PORTABLE —
they survive a reinstall / restore / db-move and travel with the corpus, exactly like the
git-export credentials (GITREG, packet 1009/S1-B/C) this module mirrors. Each server is one SERVER
record keyed by a uuid4; the display NAME is the indexed lookup slot. The non-secret config
(name/host/account) rides the record's ``JSONOfRecord``; the fmsadmin PASSWORD rides the
Corpus-Key-encrypted ``SecretData`` container, never jor (the table-wide no-secret-in-jor fence).

Analysis half ONLY — a remote server is a discovery + pull source, never an apply/FMUpgradeTool
target (structural: FMUpgradeTool is co-located to the file's own box).

The local co-located server is resolved from the published installation transport. SERVER is the
REMOTE layer alongside it (a job's ``server_ref`` is the sentinel ``"local"`` or a SERVER record's
uuid).

Public API:
    RemoteServer                                    # the dataclass (name/host/account/password/id)
    add_server(cfg, overwrite=False) -> None
    get_server(name) -> RemoteServer                # raises KeyError if absent
    get_server_by_id(server_id) -> RemoteServer | None
    list_servers() -> list[RemoteServer]            # sorted by name
    remove_server(name) -> bool
    verify_server(cfg) -> tuple[bool, str, list]    # (ok, message, hosted databases via Admin API)
    is_valid_server_name(name) -> bool
"""

from __future__ import annotations

import json
import re
import uuid as _uuidlib
from dataclasses import asdict, dataclass

_SERVER = "SERVER"
# The non-secret RemoteServer fields persisted to the record jor. The fmsadmin ``password`` is the
# SECRET → the SecretData container (never jor). ``name`` is the indexed lookup slot. The account
# (a username) is stored under the jor key ``fmsadmin_user`` — NOT ``account``, which the universal
# secret fence (projections.SECRET_JOR_KEYS) flags and would strip.
_JOR_ACCOUNT_KEY = "fmsadmin_user"

_SAFE_NAME = re.compile(r"[^\w._-]")


@dataclass
class RemoteServer:
    name: str
    host: str = ""            # bare host or host:port (no scheme) — e.g. "fms2.example.com"
    account: str = ""         # the fmsadmin Admin-API account (lists the server's hosted files)
    password: str = ""        # SECRET → SecretData container (never jor)
    verify_ssl: bool = False  # opt-in TLS verification for this server (default off: FMS certs are
                              # commonly self-signed / hostname-scoped). Turn ON when the box has a
                              # real cert — CORPUSfm then verifies TLS on every Admin-API + push call.
    callback_url: str = ""    # where THIS peer POSTs its schema back to CORPUSfm — the address from
                              # that server's perspective (packet 1219). It lives here, not globally,
                              # because two remote servers on different networks can each be right and
                              # one shared value cannot be right for both. Blank = the install's
                              # asserted address.
    id: str = ""              # the record's uuid4 key (assigned on first save)


def migrate_job_callbacks_to_servers() -> "tuple[int, list]":
    """One-time, idempotent promotion of per-job ``callback_url`` onto its SERVER record (packet 1219).

    The callback used to live on the JOB, defaulting to one global address. It now lives on the server
    it belongs to. A job carrying an explicit callback holds a fact the admin chose, so it is PROMOTED
    rather than dropped — but only onto a server that has none, because a server record already
    carrying a callback is the newer, deliberate value.

    Returns ``(promoted, conflicts)``; ``conflicts`` names each job whose callback disagreed with an
    already-set server callback so the caller can SAY so. A conflict is never resolved silently — that
    is the one outcome this migration exists to prevent.
    """
    promoted, conflicts = 0, []
    # Read the RAW stored config, not a loaded JobConfig. `JobConfig.from_dict` names the keys it
    # accepts, so it silently drops `callback_url` now that JobSource no longer declares it — a
    # loaded job cannot see the value this migration exists to rescue.
    try:
        import yaml
        from corpusfm.storage import get_backend
        eng = get_backend().engine
        rows = eng.list_all("JOB")
    except Exception:
        return (0, [])
    for row in rows:
        try:
            cfg = yaml.safe_load(row.jor.get("ConfigJSON", "") or "") or {}
        except Exception:
            continue
        src = (cfg.get("source") or {}) if isinstance(cfg, dict) else {}
        job_name = cfg.get("name") or row.jor.get("Name", "?")
        raw = str(src.get("callback_url", "") or "").strip()
        ref = str(src.get("server_ref", "") or "").strip()
        if not raw or not ref or ref == "local":
            continue
        srv = get_server_by_id(ref)
        if srv is None:
            conflicts.append((job_name, raw, "server no longer exists"))
            continue
        existing = (srv.callback_url or "").strip()
        if existing and existing != raw:
            conflicts.append((job_name, raw, f"server already set to {existing}"))
            continue
        if existing:
            continue
        srv.callback_url = raw
        try:
            add_server(srv, overwrite=True)
            promoted += 1
        except Exception:
            conflicts.append((job_name, raw, "could not write the server record"))
    return (promoted, conflicts)


def is_valid_server_name(name: str) -> bool:
    """A server name must be usable as a single URL path segment — it appears in the CRUD/Test routes
    as ``{name}``. A '/' (or space) splits the path and the route 404s (and the record becomes
    undeletable from the UI). Same safe set the git-export credentials use."""
    return bool(name) and _SAFE_NAME.search(name) is None


# ── FM-DB storage (SERVER table; the fmsadmin password in the SecretData container) ────

def _engine():
    """The storage engine (both backends expose it), or None when unavailable."""
    try:
        from corpusfm.storage import get_backend
        return getattr(get_backend(), "engine", None)
    except Exception:
        return None


def _to_jor(cfg: "RemoteServer") -> dict:
    return {"name": cfg.name, "host": cfg.host, _JOR_ACCOUNT_KEY: cfg.account,
            "verify_ssl": bool(cfg.verify_ssl), "callback_url": cfg.callback_url or ""}


def _from(jor: dict, key: str, secret: dict) -> "RemoteServer":
    return RemoteServer(
        name=jor.get("name", ""),
        host=jor.get("host", ""),
        account=jor.get(_JOR_ACCOUNT_KEY, "") or "",
        password=secret.get("password", "") or "",
        verify_ssl=bool(jor.get("verify_ssl", False)),   # absent on pre-1000-sweep records → off
        callback_url=(jor.get("callback_url", "") or ""),
        id=key,
    )


def _find(eng, name: str):
    """The SERVER row whose indexed ``name`` slot matches (case-insensitive, like USER.Username /
    GITREG), or None. Records are keyed by a uuid4 (NOT the name), so key-addressed FM OData ops
    (update/delete) work exactly like every other table; the name is a slot we look up on."""
    return eng.get_one(_SERVER, name=name) if name else None


def _load_secret(eng, key: str) -> dict:
    from corpusfm.core.crypto import decode_blob, decompress
    try:
        raw = eng.blob_get(_SERVER, key, "SecretData")
        if not raw:
            return {}
        return json.loads(decompress(decode_blob(raw)).decode("utf-8"))
    except Exception:
        return {}


def _save_secret(eng, key: str, cfg: "RemoteServer") -> None:
    from corpusfm.core.crypto import compress, encode_blob
    secret = {"password": cfg.password or ""}
    blob = encode_blob(
        compress(json.dumps(secret, ensure_ascii=False).encode("utf-8")),
        encrypt_on=True)   # ALWAYS Corpus-Key-encrypted — a server password is never a plaintext blob
    eng.blob_put(_SERVER, key, "SecretData", blob)


def add_server(cfg: "RemoteServer", overwrite: bool = False) -> None:
    """Store a remote server in the SERVER table (config in jor, fmsadmin password in the SecretData
    container).

    Raises ValueError if the name is invalid, or if it already exists and overwrite=False.
    """
    if not is_valid_server_name(cfg.name):
        raise ValueError(
            "Server name may only contain letters, digits, dot, dash, and underscore "
            "(no slashes or spaces) — it is used in the server's web address."
        )
    eng = _engine()
    if eng is None:
        raise RuntimeError("No storage backend available to store the server.")
    existing = _find(eng, cfg.name)
    if existing is not None and not overwrite:
        raise ValueError(f"Server '{cfg.name}' already exists. Pass overwrite=True to replace.")
    key = existing.key if existing is not None else str(_uuidlib.uuid4())
    cfg.id = key
    # On overwrite, an empty password field means "keep the stored secret" (the UI never round-trips a
    # password back to the client), so merge rather than clobber the container to blank.
    if existing is not None:
        if not cfg.password:
            cfg.password = _load_secret(eng, key).get("password", "") or ""
        eng.update(_SERVER, key, _to_jor(cfg))
    else:
        eng.create(_SERVER, key, _to_jor(cfg))
    _save_secret(eng, key, cfg)


def get_server(name: str) -> "RemoteServer":
    """Load a RemoteServer by name. Raises KeyError if it does not exist."""
    eng = _engine()
    if eng is None:
        raise KeyError(f"Server '{name}' not found (no storage backend).")
    row = _find(eng, name)
    if row is None:
        raise KeyError(f"Server '{name}' not found.")
    return _from(row.jor, row.key, _load_secret(eng, row.key))


def get_server_by_id(server_id: str) -> "RemoteServer | None":
    """Load a RemoteServer by its record uuid (a Job's ``server_ref``), or None. A direct key read."""
    if not server_id:
        return None
    eng = _engine()
    if eng is None:
        return None
    rows = eng.get_by_keys(_SERVER, [server_id])
    if not rows:
        return None
    return _from(rows[0].jor, rows[0].key, _load_secret(eng, rows[0].key))


def list_servers() -> list["RemoteServer"]:
    """Return all remote servers sorted by name. Returns [] if the backend is unavailable."""
    eng = _engine()
    if eng is None:
        return []
    try:
        out = [_from(r.jor, r.key, _load_secret(eng, r.key)) for r in eng.list_all(_SERVER)]
    except Exception:
        return []
    return sorted(out, key=lambda c: c.name)


def remove_server(name: str) -> bool:
    """Delete the named server. True if it existed, else False.

    Deleting the record removes ALL its fields, INCLUDING the SecretData container — so there is no
    separate blob_delete (a bare record delete is what FM OData wants; a blob_delete-then-delete 404s
    though the row is gone — box-verified for GITREG, packet 1009)."""
    eng = _engine()
    if eng is None:
        return False
    row = _find(eng, name)
    if row is None:
        return False
    eng.delete(_SERVER, row.key)
    return True


def verify_server(cfg: "RemoteServer") -> "tuple[bool, str, list]":
    """Prove the fmsadmin account reaches the server's Admin API and can list its hosted files (the
    per-server Test). Returns (ok, message, databases). Never raises — every transport/auth failure is
    a precise message. NO OData, NO PKI: the Admin API user/password path only (packet 1015)."""
    from corpusfm.server.fms_client import FMSError, list_admin_databases
    if not cfg.host:
        return False, "Set the server host first.", []
    if not cfg.account or not cfg.password:
        return False, "Set the fmsadmin account and password first.", []
    try:
        dbs = list_admin_databases(cfg.host, cfg.account, cfg.password, verify_ssl=cfg.verify_ssl)
    except FMSError as exc:
        return False, str(exc), []
    except Exception as exc:  # noqa: BLE001
        return False, f"Test failed: {exc}", []
    n = len(dbs)
    return True, f"Reachable — {n} database{'' if n == 1 else 's'} hosted (via the Admin API).", dbs
