"""FMS schema-XML extraction over OData + the fmsadmin CLI.

CORPUSfm gets a hosted file's DDR XML through one of the addon's supported export scripts,
triggered over **OData** (or the local fmsadmin CLI). There is NO FileMaker Data API here —
the Data-API/container path was retired (it depended on an "export → container" script the
addon never shipped); the mechanisms below are the ones the addon actually provides.

Protocol — Local (fms_local):
    fmsadmin CLI runs a named script on the local FMS instance.
    Script writes XML to a known path (source.path).
    corpusfm reads that path directly.

Protocol — Push trigger (fms_push):
    POST /fmi/odata/v4/{database}/Script.{script_name}
    scriptParameterValue = {"serverURL": "<corpusfm_url>", "password": "<token>"}
    FM script (PostToServer) saves XML, POSTs it to corpusfm_url/api/upload
    with Authorization: Bearer {token}.  The OData call blocks until the FM
    script completes (i.e., after FM has already POSTed the XML back).
    Maps to CFM.TOOLS.ExportSchemaXML.PostToServer. This is the REMOTE-capable
    path (FM reaches out to CORPUSfm); no filesystem, no Data API.

Protocol — Documents-file (fms_save_to_documents / bootstrap):
    POST /fmi/odata/v4/{database}/Script.CFM.TOOLS.ExportSchemaXML.SaveToDocumentsFolder
    Script writes XML to Get(DocumentsPath)/Cfm_{ts}.xml and returns "ok: file:/path/..."
    CORPUSfm reads the file directly from the local filesystem.
    Co-located deployments only (CORPUSfm on the same machine as FMS).
    This is the zero-admin default pull: returning only a path sidesteps FileMaker's
    ~1M-character script-result cap (which truncates schema XML returned inline).
    Get(DocumentsPath) — FM Server's Data/Documents folder — is persistent and
    world-readable (mode 664), unlike Get(TemporaryPath) whose session dir FM
    destroys when the OData call returns (and which CORPUSfm cannot read).

High-level pull helpers (used by corpusfm.server.jobs.sources):
    pull_fms_local(source, credentials, *, timeout=300) -> bytes
    pull_fms_save_to_documents_job(source, credentials, *, timeout=300) -> bytes
    trigger_fms_push(source, credentials, public_url) -> None

Bootstrap / co-located helper:
    pull_fms_save_to_documents(host, database, credentials, *, verify_ssl, timeout=300) -> bytes
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from corpusfm.server.jobs.config import JobSource


# ── Exception ─────────────────────────────────────────────────────────────────

class FMSError(Exception):
    """Raised for FileMaker Server API errors."""


class FMSPushTimeout(FMSError):
    """The fms_push trigger call exceeded OUR configured export bound (packet 1142 §H) — the call
    died on our clock, not the server's. Names the limit so the user knows it is theirs to raise."""


class FMSPushConnectionReset(FMSError):
    """The fms_push trigger call was ended by the REMOTE side (a connection close/reset before a
    response) — the server (FMS, its web layer, or the network) ended it, not our bound. Reported
    distinctly so the user looks server-side, not at our limit (packet 1142 §H)."""


# ── Remote-server hosted-file discovery (fmsadmin Admin API, packet 1015 redesign) ──

def list_admin_databases(host: str, username: str, password: str, *, verify_ssl: bool = False,
                         timeout: int = 30) -> list:
    """The files a remote FMS hosts, via the **Admin API** using an fmsadmin account + password.

    POST /fmi/admin/api/v2/user/auth (Basic) → session token → GET /databases → logout. NO OData
    (server-side OData blockers may be engaged), NO PKI (a remote box we never registered a key on).
    Returns raw filenames (may carry ``.fmp12``). Powers the remote-server Test + the Jobs-page file
    gallery. Raises FMSError on any transport/auth failure so the caller can report a precise
    diagnosis. ``verify_ssl`` is the per-server opt-in TLS toggle (default off — a remote FMS cert is
    commonly self-signed / hostname-scoped; turn it on when the box has a real cert)."""
    from corpusfm.server import fms_admin_pki as pki
    try:
        token = pki.authenticate_basic(host, username, password, verify_ssl=verify_ssl)
    except RuntimeError as exc:
        raise FMSError(str(exc)) from exc
    except requests.RequestException as exc:
        raise FMSError(f"Could not reach the Admin API at {host}: {exc}") from exc
    try:
        return [d for d in pki.list_databases(host, token, verify_ssl=verify_ssl) if d]
    except requests.RequestException as exc:
        raise FMSError(f"Admin API list-databases failed: {exc}") from exc
    finally:
        try:
            pki.logout(host, token, verify_ssl=verify_ssl)
        except Exception:
            pass


def list_admin_hosted_databases(host: str, username: str, password: str, *, verify_ssl: bool = False,
                                timeout: int = 30) -> list:
    """The remote server's hosted files as `HostedDatabase` PROJECTIONS (packet 1330).

    Beside `list_admin_databases`, which keeps returning filenames for the remote-server Test. Without
    this the Jobs gallery could see a LOCAL file's runtime status but never a remote one, so a closed
    file on a configured remote server stayed amber/Automatable — the reported defect, surviving on the
    other adapter (found by Codex review, 2026-08-26).

    Same single authenticate/list/logout sequence; no additional Admin API session."""
    from corpusfm.server import fms_admin_pki as pki
    try:
        token = pki.authenticate_basic(host, username, password, verify_ssl=verify_ssl)
    except RuntimeError as exc:
        raise FMSError(str(exc)) from exc
    except requests.RequestException as exc:
        raise FMSError(f"Could not reach the Admin API at {host}: {exc}") from exc
    try:
        return [d for d in pki.list_hosted_databases(host, token, verify_ssl=verify_ssl) if d.filename]
    except requests.RequestException as exc:
        raise FMSError(f"Admin API list-databases failed: {exc}") from exc
    finally:
        try:
            pki.logout(host, token, verify_ssl=verify_ssl)
        except Exception:
            pass


# ── High-level pull helpers ───────────────────────────────────────────────────

def pull_fms_local(source: JobSource, credentials: dict, *, timeout: float = 300.0) -> bytes:
    """Pull FM DDR XML via the fmsadmin CLI (same-host deployment).

    Runs a named FM script via `fmsadmin run script`, waits for completion,
    then reads the XML from source.path (where the script writes the file).

    credentials dict keys: admin_user, admin_pass (fmsadmin credentials)
    source.script:    FM script name to trigger
    source.databases: FM database name(s) — first entry used
    source.path:      local filesystem path where the script writes the XML
    """
    _require_source_fields(source, ("databases", "script", "path"))
    database = (source.databases or [""])[0]

    # Defence-in-depth: a database/script name beginning with '-' would be parsed as an fmsadmin
    # option, not a positional. Operator-authored config, so refuse it outright rather than rely
    # on a separator fmsadmin may not honour.
    for _label, _val in (("database", database), ("script", source.script)):
        if str(_val).startswith("-"):
            raise FMSError(f"Invalid {_label}: must not start with '-'.")

    admin_user = credentials.get("admin_user", "admin")
    admin_pass = credentials.get("admin_pass", "")

    cmd = [
        "fmsadmin", "run", "script",
        "-y",                    # suppress confirmation prompts
        "-u", admin_user,
        "-p", admin_pass,
        database,
        source.script,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise FMSError(
            "fmsadmin CLI not found — fms_local source type requires corpusfm to run "
            "on the same machine as FileMaker Server"
        )
    except subprocess.TimeoutExpired:
        raise FMSError(f"fmsadmin run script timed out after {timeout:g}s")

    if result.returncode != 0:
        raise FMSError(
            f"fmsadmin run script failed (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    # Give the script a moment to finish writing the file
    output_path = Path(source.path)
    deadline = time.time() + 60
    while time.time() < deadline:
        if output_path.exists() and output_path.stat().st_size > 0:
            break
        time.sleep(1)
    else:
        raise FMSError(
            f"fms_local: script completed but XML file not found at {output_path} "
            "after 60 seconds"
        )

    return output_path.read_bytes()


def _extract_script_result(resp) -> str:
    """Extract the FM script result text from an OData `Script.*` response.

    FileMaker 22.x returns a nested object:
        {"scriptResult": {"code": N, "resultParameter": "...", "truncated": bool}}
    Older / alternate shapes: {"value": "..."} or a bare text body.
    Returns the result-parameter string ("" if none could be found).

    Note: FM caps the script result parameter at ~1,000,000 characters (an engine
    limit shared by PSoS / Data API / OData). Callers that need the full schema XML
    must NOT return it inline — use SaveToDocumentsFolder, which returns only a path.
    """
    if "json" in resp.headers.get("Content-Type", ""):
        try:
            body = resp.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            sr = body.get("scriptResult")
            if isinstance(sr, dict):
                return str(sr.get("resultParameter") or "")
            if isinstance(sr, str):
                return sr
            val = body.get("value")
            if isinstance(val, str):
                return val
    return resp.text.strip()


from corpusfm.core.addon.scripts import SAVE_TO_DOCUMENTS as _SAVE_TO_DOCS_SCRIPT
from corpusfm.core.addon.scripts import DELETE_FROM_DOCUMENTS as _DELETE_DOCS_SCRIPT


def _delete_documents_file(host, database, username, password, filename, *, verify_ssl):
    """Best-effort: ask FM to delete the just-read export file from its Documents
    folder. CORPUSfm can't delete it itself (the dir is fmserver-owned) and FM
    never auto-cleans Get(DocumentsPath), so without this the Cfm_*.xml exports
    accumulate. The FM script guards on the Cfm_ prefix / .xml suffix.
    """
    url = f"https://{host.rstrip('/')}/fmi/odata/v4/{database}/Script.{_DELETE_DOCS_SCRIPT}"
    body = {"scriptParameterValue": json.dumps({"filename": filename})}
    try:
        requests.post(url, auth=(username, password), json=body, verify=verify_ssl, timeout=60)
    except requests.RequestException:
        pass  # cleanup is best-effort — the file simply lingers if this fails


def pull_fms_save_to_documents_job(
    source: JobSource, credentials: dict, *, timeout: float = 300.0,
) -> bytes:
    """Job-dispatch wrapper for the SaveToDocumentsFolder pull (fms_save_to_documents source).

    Zero-admin, co-located pull: the FM SaveToDocumentsFolder script writes the full
    schema XML to FM's Documents folder and returns only its path, sidestepping
    FileMaker's ~1M-character script-result cap. Requires CORPUSfm on the same host as FMS.

    credentials dict keys: username, password, verify_ssl (optional)
    """
    _require_source_fields(source, ("server", "databases"))
    host = re.sub(r"^https?://", "", source.server.rstrip("/"))
    database = (source.databases or [""])[0]
    verify_ssl = str(credentials.get("verify_ssl", "true")).lower() != "false"
    return pull_fms_save_to_documents(
        host, database, credentials, verify_ssl=verify_ssl, timeout=timeout,
    )


def pull_fms_save_to_documents(
    host: str,
    database: str,
    credentials: dict,
    *,
    verify_ssl: bool = True,
    timeout: float = 300.0,
) -> bytes:
    """Pull FM DDR XML via SaveToDocumentsFolder (co-located deployments only).

    Calls SaveToDocumentsFolder via OData — the FM script writes the schema XML to
    Get(DocumentsPath)/Cfm_{ts}.xml (FM Server's persistent, world-readable Data/
    Documents folder) and returns "ok: file:/path/...". CORPUSfm reads that file
    from the local filesystem.

    Requires CORPUSfm to be running on the same machine as FileMaker Server.

    Raises FMSError if the script is absent, disabled, or returns an unexpected result.
    Raises FileNotFoundError if the file cannot be read (wrong machine or path issue).
    """
    username = credentials.get("username", "")
    password = credentials.get("password", "")

    url = f"https://{host.rstrip('/')}/fmi/odata/v4/{database}/Script.{_SAVE_TO_DOCS_SCRIPT}"
    try:
        resp = requests.post(url, auth=(username, password), verify=verify_ssl, timeout=timeout)
        resp.raise_for_status()
    except requests.Timeout as exc:
        raise FMSError(f"SaveToDocumentsFolder timed out after {timeout:g}s") from exc
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else 0
        if code == 404:
            raise FMSError(
                f"Script '{_SAVE_TO_DOCS_SCRIPT}' not found in '{database}'. "
                "Install the CORPUSfm addon in the target database."
            ) from exc
        raise FMSError(f"SaveToDocumentsFolder OData call failed ({code}): {exc}") from exc
    except requests.RequestException as exc:
        raise FMSError(f"SaveToDocumentsFolder connection error: {exc}") from exc

    # FM 22.x wraps the result as {"scriptResult": {"resultParameter": "ok: file:..."}}
    result_str = _extract_script_result(resp)

    if not result_str.startswith("ok:"):
        raise FMSError(
            f"SaveToDocumentsFolder returned unexpected result for '{database}': {result_str!r}. "
            "Ensure the script is enabled in the CORPUSfm addon (the guard Exit Script "
            "step must have enable=\"False\")."
        )

    # Parse "ok: file:/path/..." — handle file: URI and bare POSIX paths
    path_str = result_str[len("ok:"):].strip()
    parsed = urlparse(path_str)
    if parsed.scheme == "file":
        file_path = Path(parsed.path)
    else:
        file_path = Path(path_str)

    if not file_path.exists():
        raise FileNotFoundError(
            f"SaveToDocumentsFolder wrote to {file_path} but the file cannot be read. "
            "Confirm CORPUSfm is running on the same machine as FileMaker Server."
        )

    xml_bytes = file_path.read_bytes()
    # corpusfm can't delete from the fmserver-owned Documents dir, so ask FM to
    # remove its own export file (FM never auto-cleans Get(DocumentsPath)).
    _delete_documents_file(host, database, username, password, file_path.name, verify_ssl=verify_ssl)
    return xml_bytes


def pull_fms_save_to_file_path(
    source: JobSource, credentials: dict, *, timeout: float = 300.0,
) -> bytes:
    """Pull FM DDR XML via SaveToFilePath (packet 1015): trigger the FM SaveToFilePath script over
    OData with the target path as its parameter, then read that path back off the filesystem.

    Only works when CORPUSfm can SEE the path FM wrote to — a co-located job (local disk) or a remote
    job whose target path is a shared mount. There is no result-size cap (the XML never rides the
    script result — only the path does).

    NOTE (untested — 2026-07-08): the addon's SaveToFilePath script parameter contract is assumed to
    be ``{"filePath": "<path>"}``; the two DEFAULT methods (SaveToDocumentsFolder / PostToServer) are
    the box-validated paths.

    credentials dict keys: username, password (OData auth), verify_ssl (optional).
    """
    _require_source_fields(source, ("server", "databases", "file_path"))
    host = re.sub(r"^https?://", "", source.server.rstrip("/"))
    database = (source.databases or [""])[0]
    file_path = source.file_path or ""
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    verify_ssl = str(credentials.get("verify_ssl", "true")).lower() != "false"

    from corpusfm.core.addon.scripts import SAVE_TO_FILE_PATH
    url = f"https://{host.rstrip('/')}/fmi/odata/v4/{database}/Script.{SAVE_TO_FILE_PATH}"
    body = {"scriptParameterValue": json.dumps({"filePath": file_path})}
    try:
        resp = requests.post(
            url, auth=(username, password), json=body, verify=verify_ssl, timeout=timeout,
        )
        resp.raise_for_status()
    except requests.Timeout as exc:
        raise FMSError(f"SaveToFilePath timed out after {timeout:g}s") from exc
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else 0
        if code == 404:
            raise FMSError(
                f"Script '{SAVE_TO_FILE_PATH}' not found in '{database}'. "
                "Install the CORPUSfm addon in the target database."
            ) from exc
        raise FMSError(f"SaveToFilePath OData call failed ({code}): {exc}") from exc
    except requests.RequestException as exc:
        raise FMSError(f"SaveToFilePath connection error: {exc}") from exc

    output_path = Path(file_path)
    deadline = time.time() + 60
    while time.time() < deadline:
        if output_path.exists() and output_path.stat().st_size > 0:
            return output_path.read_bytes()
        time.sleep(1)
    raise FileNotFoundError(
        f"SaveToFilePath: FM was asked to write {output_path}, but CORPUSfm cannot read it. "
        "The path must be on a filesystem CORPUSfm can see (co-located disk, or a shared mount)."
    )


def probe_export_script(host: str, database: str, credentials: dict, *, verify_ssl: bool = True) -> dict:
    """Readiness probe (Stage 3): call SaveToDocumentsFolder and report the outcome WITHOUT
    raising. Proves addon-present + creds-valid + OData-reachable in one call. Cleans up the
    file FM writes on success. Returns a structured dict for file_readiness.classify_probe:
        {ok: bool, http_status: int|None, fm_code: str, result: str, error: str}
    Does not read the (potentially multi-MB) export back — readiness only needs the verdict.
    """
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    url = f"https://{host.rstrip('/')}/fmi/odata/v4/{database}/Script.{_SAVE_TO_DOCS_SCRIPT}"
    try:
        resp = requests.post(url, auth=(username, password), verify=verify_ssl, timeout=120)
    except requests.RequestException as exc:
        return {"ok": False, "http_status": None, "fm_code": "", "result": "", "error": str(exc)}
    if resp.status_code != 200:
        # Keep FileMaker's OWN error code (packet 1330-02). The HTTP status cannot discriminate:
        # measured on a live box, a closed file, a file with OData disabled, a wrong password and a
        # non-existent file ALL answer 501 with FM 802. The code in the body is the actual diagnosis
        # and was being thrown away.
        fm_code = ""
        try:
            err = (resp.json() or {}).get("error") or {}
            fm_code = str(err.get("code") or "").strip()
        except Exception:
            fm_code = ""
        return {"ok": False, "http_status": resp.status_code, "fm_code": fm_code, "result": "",
                "error": f"HTTP {resp.status_code}" + (f" (FileMaker {fm_code})" if fm_code else "")}
    try:
        result = _extract_script_result(resp)
    except Exception as exc:
        return {"ok": False, "http_status": 200, "result": "", "error": str(exc)}
    ok = result.startswith("ok:")
    if ok:
        try:  # best-effort cleanup of the file FM just wrote
            path_str = result[len("ok:"):].strip()
            parsed = urlparse(path_str)
            fname = Path(parsed.path if parsed.scheme == "file" else path_str).name
            _delete_documents_file(host, database, username, password, fname, verify_ssl=verify_ssl)
        except Exception:
            pass
    return {"ok": ok, "http_status": 200, "result": result, "error": "" if ok else "unexpected result"}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _require_source_fields(source: JobSource, fields: tuple) -> None:
    missing = [f for f in fields if not getattr(source, f, None)]
    if missing:
        raise ValueError(
            f"source type '{source.type}' requires: {', '.join(missing)}"
        )


def trigger_fms_push(source: "JobSource", credentials: dict, public_url: str,
                     *, push_token: str = "", timeout: float = 300.0) -> str:
    """Trigger an fms_push run by calling the FM PostToServer script via OData, and RETURN ITS VERDICT
    (packet 1142 — the run's acquire step reads the script result; the old signature discarded it).

    FM's script receives {"serverURL": public_url, "password": push_token} as its script parameter,
    saves the DDR, POSTs it back to public_url/api/upload with Authorization: Bearer {push_token}, and
    exits with a result: ``"ok"`` (POST accepted), ``"error: <code>"`` (export/read-back/POST failure or
    bad parameter), or ``""`` (an unconfigured target whose security-guard Exit Script fires first).
    ``push_token`` is the RAW ONE-TIME bearer token minted for THIS run — it keys directly to the
    acquiring QUEUE record, so /api/upload resolves + deposits into the exact run. (Legacy fallback:
    The token must be supplied explicitly for this run.)

    This call BLOCKS until the FM script completes (which includes FM having already POSTed the XML
    back). ``timeout`` is OUR bound on that block — the effective per-job export bound (packet 1142 §H);
    on expiry we raise :class:`FMSPushTimeout` (our clock). A remote close/reset raises
    :class:`FMSPushConnectionReset` (the server's clock). Both name which side ended the call.

    Returns the raw script-result string (the verdict) for the acquire step to interpret. credentials
    dict keys: username, password (OData auth), verify_ssl (optional).
    """
    _require_source_fields(source, ("server", "databases", "script"))
    username = _cred(credentials, "username")
    password = _cred(credentials, "password")
    verify_ssl = str(credentials.get("verify_ssl", "true")).lower() != "false"
    database = (source.databases or [""])[0]

    token = push_token
    if not token:
        raise FMSError("fms_push trigger requires a one-time push token")
    if not public_url:
        raise FMSError("fms_push trigger could not derive the CORPUSfm callback URL")

    script_param = json.dumps({"serverURL": public_url.rstrip("/"), "password": token})
    url = f"{source.server.rstrip('/')}/fmi/odata/v4/{database}/Script.{source.script}"
    session = requests.Session()
    session.verify = verify_ssl
    try:
        resp = session.post(
            url,
            auth=(username, password),
            json={"scriptParameterValue": script_param},
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.Timeout as exc:
        raise FMSPushTimeout(
            f"the export exceeded the configured limit of {int(timeout)}s — FileMaker was still "
            f"exporting when our bound ran out; raise the job's export timeout if this is normal"
        ) from exc
    except requests.ConnectionError as exc:
        raise FMSPushConnectionReset(
            f"the connection was ended by the server before a response ({exc}) — the limit was not "
            f"ours; check FileMaker Server's OData / web-server / script timeouts"
        ) from exc
    except requests.HTTPError as exc:
        raise FMSError(f"fms_push trigger OData call failed: {exc}") from exc
    return _extract_script_result(resp)


def _cred(credentials: dict, key: str) -> str:
    value = credentials.get(key)
    if not value:
        raise ValueError(
            f"Missing credential '{key}' — ensure the credential group includes {key.upper()}"
        )
    return value
