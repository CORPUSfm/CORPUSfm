"""Stateless FileMaker storage transport used by the installation lifecycle."""

from __future__ import annotations

import json
from dataclasses import dataclass

import requests

from corpusfm.core.addon.scripts import CHANGE_AUTOMATION_PASSWORD as _CHANGE_PW_SCRIPT
from corpusfm.storage.fm_registry import SETTING_TABLE as _SETTING_TABLE

_SETTINGS_DEFAULTS = {
    "preferred_addon_locale": "", "ui_locale": "", "ai_summary_provider": "",
    "ai_summary_model": "", "ai_summary_base_url": "", "ai_embedding_model": "",
    "ai_embedding_base_url": "",
}


@dataclass
class ProbeResult:
    reachable: bool = False
    authed: bool = False
    has_odata: bool = False
    is_default_credential: bool = False
    settings_state: str = "unknown"
    error: str = ""

    def to_dict(self) -> dict:
        return vars(self).copy()


def probe(host: str, database: str, username: str, password: str, *, verify_ssl: bool = True) -> ProbeResult:
    """Read-only OData capability probe; it never stores or changes credentials."""
    result = ProbeResult()
    session = requests.Session()
    session.auth = (username, password)
    session.verify = verify_ssl
    session.headers.update({"Accept": "application/json"})
    base = f"https://{host}/fmi/odata/v4/{database}"
    try:
        response = session.get(base + "/", timeout=10)
        result.reachable = True
        result.authed = response.status_code not in (401, 403)
    except requests.exceptions.ConnectionError:
        result.error = f"Cannot reach {host} — check the host and FileMaker Server."
        return result
    except requests.exceptions.Timeout:
        result.error = f"Connection to {host} timed out."
        return result
    except Exception as exc:
        result.error = str(exc)
        return result
    if not result.authed:
        result.error = "Authentication failed — check the username and password."
        return result
    try:
        result.has_odata = session.get(base + "/$metadata", timeout=10).status_code == 200
    except Exception:
        pass
    if not result.has_odata:
        result.error = "OData API not accessible; verify the fmodata extended privilege."
    result.is_default_credential = bool(password and password == username)
    if result.has_odata:
        result.settings_state = _check_settings(session, base)
    return result


def init_settings(host: str, database: str, username: str, password: str,
                  *, verify_ssl: bool = True) -> None:
    session = requests.Session()
    session.auth = (username, password)
    session.verify = verify_ssl
    session.headers.update({"Accept": "application/json"})
    _ensure_settings(session, f"https://{host}/fmi/odata/v4/{database}")


def reset_automation_password(host: str, database: str, username: str, current_password: str,
                              new_password: str, *, verify_ssl: bool = True) -> dict:
    """Rotate the target account; persistence and policy remain lifecycle-owned."""
    import time
    base = f"https://{host}/fmi/odata/v4/{database}"
    session = requests.Session()
    session.verify = verify_ssl

    def works(password: str) -> bool:
        try:
            return session.get(base + "/", auth=(username, password), timeout=10).status_code != 401
        except Exception:
            return False

    if works(new_password):
        return {"ok": True, "changed": False, "error": ""}
    if not current_password or not works(current_password):
        return {"ok": False, "changed": False,
                "error": "neither the target nor the current credential authenticates"}
    try:
        response = session.post(
            base + f"/Script.{_CHANGE_PW_SCRIPT}",
            json={"scriptParameterValue": {"password": new_password}},
            headers={"Content-Type": "application/json"}, auth=(username, current_password), timeout=20)
        response.raise_for_status()
        code = ((response.json() if response.content else {}).get("scriptResult") or {}).get("code", 0)
        if code and str(code) not in ("0", ""):
            return {"ok": False, "changed": False, "error": f"FM script error {code}"}
    except Exception as exc:
        return {"ok": False, "changed": False, "error": str(exc)}
    for _ in range(10):
        time.sleep(3)
        if works(new_password):
            return {"ok": True, "changed": True, "error": ""}
    return {"ok": False, "changed": True,
            "error": "password set but the new credential was not accepted after propagation"}


def _parse_jor_from_record(record: dict) -> dict:
    value = record.get("JSONOfRecord", {})
    if isinstance(value, str):
        try:
            value = json.loads(value) if value else {}
        except Exception:
            value = {}
    return value if isinstance(value, dict) else {}


def _check_settings(session: requests.Session, base: str) -> str:
    try:
        response = session.get(f"{base}/{_SETTING_TABLE}", timeout=10)
        if response.status_code != 200 or not response.json().get("value", []):
            return "missing"
        value = _parse_jor_from_record(response.json()["value"][0])
        return "initialized" if any(value.get(k) is not None for k in _SETTINGS_DEFAULTS) else "empty"
    except Exception:
        return "unknown"


def _ensure_settings(session: requests.Session, base: str) -> None:
    response = session.get(f"{base}/{_SETTING_TABLE}", timeout=10)
    if response.status_code != 200:
        raise RuntimeError(f"{_SETTING_TABLE} entity set not accessible (HTTP {response.status_code})")
    values = response.json().get("value", [])
    if values:
        record = values[0]
        value = _parse_jor_from_record(record)
        merged = {**_SETTINGS_DEFAULTS, **{k: v for k, v in value.items() if v not in (None, "")}}
        if record.get("@editLink"):
            patch = session.patch(record["@editLink"], json={"JSONOfRecord": json.dumps(merged)},
                                  headers={"Content-Type": "application/json"}, timeout=10)
            patch.raise_for_status()
    else:
        created = session.post(f"{base}/{_SETTING_TABLE}",
                               json={"JSONOfRecord": json.dumps(_SETTINGS_DEFAULTS)},
                               headers={"Content-Type": "application/json"}, timeout=10)
        created.raise_for_status()
