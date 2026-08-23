"""The SINGLE live adapter for the storage identity (packet 1246-08 §6.4, §8.3).

Two halves, deliberately kept apart:

* **The OData half** builds an EXPLICIT ``FileMakerODataBackend`` from five values this component
  already holds — authoritative host, the FIXED database name, the FIXED automation account, a
  secret handed in by the store, and the ruled TLS posture. It never calls ``storage.get_backend()``,
  ``install.read_install_config()`` or ``install.activate_fm_backend()``, and never reads
  ``install.yaml`` or ``server_configs.yaml``. Those are the stores this packet exists to retire; a
  component that resolved through them would answer about the wrong corpus — or, on a new-format
  box, cheerfully answer about a LocalBackend and report "no users".
* **The Admin-API half** routes through 1246-07's installed machine identity. There is no second
  Admin-API client here and no FMS administrator password: when that authority is absent the
  database-known and hosted axes are UNKNOWN, which is the correct conservative answer and makes
  ``PROVEN_FRESH`` unreachable.

Three ``fm_bootstrap`` functions are REUSED UNMODIFIED — ``probe``, ``init_settings`` and
``reset_automation_password``. All three are clean transport that persists nothing. ``run_bootstrap``
is never called on any path: it fuses SETTINGS initialization, rotation, two credential writes and
backend activation, so calling it with narrower flags still imports all five policies.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

from .storage_identity import (
    AUTOMATION_ACCOUNT,
    STORAGE_DATABASE_NAME,
)

#: The co-located posture, ruled: the floor case is an IP address and an untrusted certificate, and
#: it must always work. This is not a weakening — CORPUSfm never REQUIRES a valid chain, and the
#: certificate-trust half is the administrator's layer.
VERIFY_SSL = False


class StorageAdapter(Protocol):
    """Everything this component does to FileMaker. Injectable in full."""

    # OData half — the explicitly constructed backend.
    def probe(self, secret: str) -> Any: ...
    def init_settings(self, secret: str) -> None: ...
    def rotate(self, current: str, new: str) -> dict: ...
    def backend(self, secret: str) -> Any: ...

    # Admin-API half — 1246-07's identity.
    def list_databases(self) -> tuple[dict, ...] | None: ...
    def open_database(self) -> None: ...
    def close_database(self) -> None: ...
    def await_status(self, target: str) -> bool: ...


@dataclass
class LiveStorageAdapter:
    """The real adapter. Constructed once per operation, from the integrator's authoritative host
    and the FIXED secrets directory — never from a config file."""

    host: str
    secrets_dir: Any = None
    database: str = STORAGE_DATABASE_NAME
    account: str = AUTOMATION_ACCOUNT
    verify_ssl: bool = VERIFY_SSL
    _api: Any = None

    # ── OData half ───────────────────────────────────────────────────────────

    def probe(self, secret: str):
        from corpusfm.server.fm_bootstrap import probe as _probe

        return _probe(self.host, self.database, self.account, secret, verify_ssl=self.verify_ssl)

    def init_settings(self, secret: str) -> None:
        from corpusfm.server.fm_bootstrap import init_settings as _init

        _init(self.host, self.database, self.account, secret, verify_ssl=self.verify_ssl)

    def rotate(self, current: str, new: str) -> dict:
        from corpusfm.server.fm_bootstrap import reset_automation_password as _reset

        return _reset(self.host, self.database, self.account, current, new,
                      verify_ssl=self.verify_ssl)

    def backend(self, secret: str):
        """The EXPLICIT backend. Five values, none of them from a config file."""
        from corpusfm.storage.fm_odata import FileMakerODataBackend

        return FileMakerODataBackend(
            host=self.host,
            database=self.database,
            username=self.account,
            password=secret,
            verify_ssl=self.verify_ssl,
        )

    # ── Admin-API half ───────────────────────────────────────────────────────

    def _admin(self):
        """``(module, host, key_name, private_pem)`` or None. One resolution per adapter.

        **The identity comes from 1246-07's store in the FIXED secrets directory, and the host from
        the integrator — never from ``load_admin_pki_for_apply()``.** That resolver reaches
        ``install.storage_backend_connection()`` → ``install.read_install_config()``
        (`fms_admin_pki.py:632-633`), which is the store this packet exists to retire, and it reads
        the LEGACY per-connection file inside the software root rather than the published one. On a
        new-format box it therefore answers about nothing, and every database axis would go UNKNOWN
        while appearing to have consulted an authority.

        Only the TRANSPORT primitive is borrowed from ``fms_admin_pki``; the authority is 1246-07's.
        """
        if self._api is None:
            from corpusfm.server import fms_admin_pki
            from . import admin_identity_store

            if self.secrets_dir is None:
                return None
            try:
                identity = admin_identity_store.load(self.secrets_dir)
            except Exception:  # noqa: BLE001 — unusable authority is UNKNOWN, never a traceback
                return None
            if identity is None or not identity.private_pem:
                return None
            self._api = (fms_admin_pki, self.host, identity.registration_name,
                         identity.private_pem)
        return self._api

    def _request(self, method: str, path: str, *, json_body: dict | None = None) -> dict:
        pki, host, name, pem = self._require_admin()
        ok, status, body = pki.admin_api_request(
            host, name, pem, method, path, json_body=json_body, verify_ssl=self.verify_ssl,
        )
        if not ok:
            raise RuntimeError(f"Admin API {method} {path} failed with status {status}")
        inner = body.get("response") if isinstance(body, dict) else None
        return inner if isinstance(inner, dict) else {}

    def list_databases(self) -> tuple[dict, ...] | None:
        """None means "the Admin API could not answer" — NOT "there are no databases".

        Those are different facts, and conflating them would let an unreachable Admin API look like
        a clean box: the one wrong answer that leads to placing a template on top of a corpus.
        """
        if self._admin() is None:
            return None
        try:
            data = self._request("GET", "/databases")
        except Exception:  # noqa: BLE001 — an unreachable Admin API is UNKNOWN, never absence
            return None
        rows = data.get("databases")
        return tuple(r for r in rows if isinstance(r, dict)) if isinstance(rows, list) else ()

    def _database_id(self) -> int:
        rows = self.list_databases()
        if rows is None:
            raise RuntimeError("the Admin API did not answer, so the database id is unknown")
        for row in rows:
            name = str(row.get("filename") or row.get("name") or "")
            stem = name[:-6] if name.lower().endswith(".fmp12") else name
            if stem.lower() == self.database.lower():
                return int(row["id"])
        raise RuntimeError(f"FileMaker Server does not list a database named {self.database!r}")

    def open_database(self) -> None:
        self._request("PATCH", f"/databases/{self._database_id()}", json_body={"status": "OPENED"})

    def close_database(self) -> None:
        self._request("PATCH", f"/databases/{self._database_id()}", json_body={"status": "CLOSED"})

    def await_status(self, target: str) -> bool:
        pki, host, name, pem = self._require_admin()
        try:
            return bool(pki.wait_until_status(
                host, name, pem, self.database, target, verify_ssl=self.verify_ssl,
            ))
        except Exception:  # noqa: BLE001
            return False

    def _require_admin(self):
        admin = self._admin()
        if admin is None:
            raise RuntimeError(
                "the FileMaker Admin API identity is not available, so the storage database "
                "cannot be hosted or closed"
            )
        return admin


def build_adapter(inputs) -> StorageAdapter:
    """The ONE construction path.

    It does not raise past the CLI and it does not return None: a missing Admin-API authority is a
    REPORTABLE FACT (the database-known and hosted axes go UNKNOWN), not a construction failure.
    Returning None here would force every caller to invent a state for "no adapter", which is the
    shape 1246-05-01 §6.3 warns about.

    Both authorities come from the request: the host the integrator verified, and the FIXED secrets
    directory it validated. Nothing here consults a config file.
    """
    return LiveStorageAdapter(host=inputs.host, secrets_dir=inputs.secrets_dir)


def settle(seconds: float) -> None:
    """One place to wait, so a test can replace it without patching ``time`` globally."""
    time.sleep(seconds)


__all__ = ["VERIFY_SSL", "LiveStorageAdapter", "StorageAdapter", "build_adapter", "settle"]
