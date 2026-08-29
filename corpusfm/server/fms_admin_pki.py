"""FileMaker Server Admin API PKI (public-key) authentication helper.

FileMaker Server's Admin API supports public-key auth: you register a public key
(named) in the Admin Console (Administration → Administrator → Add Public Key),
then sign an RS256 JWT with the matching private key and exchange it at
``/fmi/admin/api/v2/user/auth`` (``Authorization: PKI <jwt>``) for a session
token — no admin password. The JWT claims are ``iss`` = the public-key name
(case-sensitive, must match the console exactly), ``aud`` = ``fmsadminapi``,
``exp`` = expiry. Reference: ``[install]/Tools/AdminAPI_PKIAuth`` on the server.

This module generates the keypair (RSA-4096 PEM, equivalent to
``ssh-keygen -t rsa -b 4096 -m PEM`` + ``openssl rsa -pubout`` but in-process,
no subprocess), signs the JWT, exchanges it, and stores the private key
Fernet-encrypted under the **Machine Key** (packet 1007; named in 1246-02) — a machine-scoped
secret that belongs to this installation, never leaves it, and is never carried by a Recovery File.
Only the public key ever leaves the host.

Registration is turnkey: ``register_public_key()`` installs the public key via the
Admin API (``POST /server/config/pkipublickey``) using the admin password ONCE
(Basic auth) — no manual Admin-Console paste. ``delete_public_key()`` is the
uninstall companion. The private key never leaves the host; the admin password is
used transiently for register/deregister and is never stored.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Optional

import urllib3
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# The PKI private key is machine-scoped, so it is encrypted under the Machine Key and never under
# the portable Corpus Key. Encrypting it under the portable key was the original bug: adopting a
# migrated key orphaned the box's own PKI blob, leaving PKI unusable until it was re-registered.
# Under the Machine Key the box's PKI survives any Corpus Key change untouched. (Aliased locally so
# the call sites below keep reading `encrypt`/`decrypt`.)

# Admin-API calls run over the FMS web server's https — on the box that's the LOOPBACK
# (https://127.0.0.1/…), which can't cert-verify against the FMS public cert (its SAN/CN is the
# hostname, not 127.0.0.1), so callers pass verify_ssl=False. Silence the resulting
# InsecureRequestWarning at the source (mirrors fm_bootstrap / fm_odata) so installer/uninstaller +
# CLI loopback PKI snippets stay quiet. Real PKI/Admin-API errors are unaffected (they raise / return
# status, never via this warning).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_AUD = "fmsadminapi"
_DEFAULT_KEY_NAME = "CORPUSfm-AdminAPI"
# ── Key generation ──────────────────────────────────────────────────────────

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh RSA-4096 keypair.

    Returns (private_pem, public_pem). The public key is SubjectPublicKeyInfo
    PEM ("BEGIN PUBLIC KEY") — the exact format FMS expects in Add Public Key
    (same as ``openssl rsa -pubout``).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# ── JWT (the "PKI token") ───────────────────────────────────────────────────

def _b64u(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def build_pki_jwt(
    key_name: str,
    private_pem: bytes,
    exp_seconds: int = 3600,
    *,
    now: Optional[int] = None,
) -> str:
    """Build the RS256 JWT FMS verifies against the registered public key.

    key_name must equal the public key's name in the Admin Console exactly.
    """
    issued = int(time.time()) if now is None else now
    priv = serialization.load_pem_private_key(private_pem, password=None)
    header = _b64u(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64u(json.dumps(
        {"iss": key_name, "aud": _AUD, "exp": issued + exp_seconds},
        separators=(",", ":"),
    ).encode())
    signing_input = header + b"." + payload
    signature = _b64u(priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))
    return (signing_input + b"." + signature).decode()


def _clean_host(host: str) -> str:
    return host.replace("https://", "").replace("http://", "").rstrip("/")


def authenticate(
    host: str,
    key_name: str,
    private_pem: bytes,
    *,
    verify_ssl: bool = False,
    exp_seconds: int = 3600,
) -> str:
    """Exchange a signed PKI JWT for an FMS Admin API session token.

    Returns the session token (use it as ``Authorization: Bearer <token>`` for
    subsequent admin calls). Raises RuntimeError with the FMS message on failure.
    """
    import requests

    jwt_token = build_pki_jwt(key_name, private_pem, exp_seconds)
    url = f"https://{_clean_host(host)}/fmi/admin/api/v2/user/auth"
    resp = requests.post(
        url,
        headers={"Authorization": "PKI " + jwt_token},
        verify=verify_ssl,
        timeout=30,
    )
    try:
        body = resp.json()
    except Exception:
        raise RuntimeError(f"PKI auth failed (HTTP {resp.status_code}): non-JSON response")
    token = (body.get("response") or {}).get("token", "")
    if resp.status_code != 200 or not token:
        msgs = body.get("messages") or [{}]
        raise RuntimeError(f"PKI auth failed (HTTP {resp.status_code}): {msgs}")
    return token


def logout(host: str, session_token: str, *, verify_ssl: bool = False) -> bool:
    """Release an Admin API session. Returns True if FMS confirmed the release.

    The FMS Admin API v2 sign-out is ``DELETE /fmi/admin/api/v2/user/auth/{token}`` —
    the session token is a PATH parameter (like the Data API's /sessions/{token}). The
    header-only form (no token in the path) is a silent no-op, so sessions linger ~15 min
    and FMS caps concurrent ones (error 956 "Maximum number of Admin API sessions
    exceeded"). Best-effort: never raises; falls back to the header-only form if the path
    form is rejected by an older build.
    """
    import requests
    host = _clean_host(host)
    headers = {"Authorization": "Bearer " + session_token}
    try:
        resp = requests.delete(
            f"https://{host}/fmi/admin/api/v2/user/auth/{session_token}",
            headers=headers, verify=verify_ssl, timeout=15,
        )
        if resp.status_code < 400:
            return True
        requests.delete(
            f"https://{host}/fmi/admin/api/v2/user/auth",
            headers=headers, verify=verify_ssl, timeout=15,
        )
    except Exception:
        pass
    return False


def authenticate_basic(
    host: str,
    admin_user: str,
    admin_pass: str,
    *,
    verify_ssl: bool = False,
) -> str:
    """Exchange FMS Admin Console credentials (Basic auth) for a session token.

    This is the password-based bootstrap path — used ONCE to register a PKI public
    key (after which everything uses PKI, no password). Returns the session token;
    raises RuntimeError with the FMS message on failure.
    """
    import requests

    cred = base64.b64encode(f"{admin_user}:{admin_pass}".encode()).decode("ascii")
    url = f"https://{_clean_host(host)}/fmi/admin/api/v2/user/auth"
    resp = requests.post(
        url,
        headers={"Authorization": "Basic " + cred},
        verify=verify_ssl,
        timeout=30,
    )
    try:
        body = resp.json()
    except Exception:
        raise RuntimeError(f"Admin auth failed (HTTP {resp.status_code}): non-JSON response")
    token = (body.get("response") or {}).get("token", "")
    if resp.status_code != 200 or not token:
        msgs = body.get("messages") or [{}]
        raise RuntimeError(f"Admin auth failed (HTTP {resp.status_code}): {msgs}")
    return token


def register_public_key(
    host: str,
    admin_user: str,
    admin_pass: str,
    key_name: str,
    public_pem,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """Register a PKI public key in FMS via the Admin API (turnkey — no manual paste).

    POST /fmi/admin/api/v2/server/config/pkipublickey  body {name, publicKey}.
    Authenticates with the admin password ONCE (Basic), registers, then logs out.
    After this the matching private key authenticates via PKI with no password.
    Returns (ok, message). Never the storage DB — caller scope (this is server config).
    """
    import json
    import requests

    if isinstance(public_pem, (bytes, bytearray)):
        public_pem = bytes(public_pem).decode("ascii")
    token = authenticate_basic(host, admin_user, admin_pass, verify_ssl=verify_ssl)
    url = f"https://{_clean_host(host)}/fmi/admin/api/v2/server/config/pkipublickey"
    hdrs = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    try:
        # Idempotent register. A key under this name may already be registered by a PRIOR install
        # whose private key is now gone (notably: the Windows uninstaller does not deregister, so the
        # key survives uninstall/reinstall cycles). We hold a different private key, so we can't reuse
        # it — and FMS rejects a duplicate name with error 1708 ("Parameter value is invalid"). So
        # deregister any existing key of this name first (ignore "not found"), then register ours.
        try:
            requests.delete(
                url, headers=hdrs, data=json.dumps({"names": [key_name]}),
                verify=verify_ssl, timeout=30,
            )
        except Exception:
            pass
        resp = requests.post(
            url,
            headers=hdrs,
            data=json.dumps({"name": key_name, "publicKey": public_pem}),
            verify=verify_ssl,
            timeout=30,
        )
        try:
            msgs = resp.json().get("messages") or [{}]
        except Exception:
            return False, f"HTTP {resp.status_code}: non-JSON response"
        ok = resp.status_code == 200 and msgs[0].get("code") == "0"
        return ok, str(msgs)
    finally:
        logout(host, token, verify_ssl=verify_ssl)


def delete_public_key(
    host: str,
    admin_user: str,
    admin_pass: str,
    key_name: str,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """Deregister a PKI public key from FMS by name (the uninstall companion).

    DELETE /fmi/admin/api/v2/server/config/pkipublickey  body {names: [name]}.
    Authenticates with the admin password (Basic), deletes, logs out. Returns
    (ok, message); best-effort — a missing key is not a hard error for callers.
    """
    import json
    import requests

    token = authenticate_basic(host, admin_user, admin_pass, verify_ssl=verify_ssl)
    try:
        resp = requests.delete(
            f"https://{_clean_host(host)}/fmi/admin/api/v2/server/config/pkipublickey",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            data=json.dumps({"names": [key_name]}),
            verify=verify_ssl,
            timeout=30,
        )
        try:
            msgs = resp.json().get("messages") or [{}]
        except Exception:
            return False, f"HTTP {resp.status_code}: non-JSON response"
        ok = resp.status_code == 200 and msgs[0].get("code") == "0"
        return ok, str(msgs)
    finally:
        logout(host, token, verify_ssl=verify_ssl)


def deregister_local_key(
    admin_user: str,
    admin_pass: str,
    *,
    host: str = "127.0.0.1",
    key_name: str = _DEFAULT_KEY_NAME,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """Deregister the co-located CORPUSfm Admin-API key (uninstall hygiene).

    The single deregistration entry point both uninstallers call, so the task is identical across
    OSes (only the invoking shell differs). Deletes by the CONSTANT key name at localhost, so it
    needs NO stored config — robust even when the PKI config is missing/unreadable or resolves to a
    different path per platform (the stored-config iteration silently found nothing on Windows). A
    missing key returns (False, ...); a deregister failure never blocks an uninstall.
    """
    try:
        return delete_public_key(host, admin_user, admin_pass, key_name, verify_ssl=verify_ssl)
    except Exception as exc:
        return False, str(exc)


def admin_api_request(
    host: str,
    key_name: str,
    private_pem: bytes,
    method: str,
    path: str,
    *,
    params: Optional[dict] = None,
    json_body: Optional[dict] = None,
    verify_ssl: bool = False,
) -> tuple[bool, int, dict]:
    """Make one authenticated Admin API v2 call via PKI (no password), then log out.

    ``path`` is appended to ``/fmi/admin/api/v2`` (e.g. ``/clients``). Returns
    (ok, http_status, body). ok is True only on HTTP 200 with FMS message code "0".
    Each call opens + releases its own session (the FMS pool is small — 956 if leaked).
    This is the generic substrate for the broad-control MCP tools (the fms_api / Full FMS API gate).
    """
    import json as _json
    import requests

    token = authenticate(host, key_name, private_pem, verify_ssl=verify_ssl)
    try:
        url = f"https://{_clean_host(host)}/fmi/admin/api/v2{path}"
        headers = {"Authorization": "Bearer " + token}
        data = None
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            data = _json.dumps(json_body)
        resp = requests.request(
            method.upper(), url, headers=headers, params=params, data=data,
            verify=verify_ssl, timeout=60,
        )
        try:
            body = resp.json()
        except Exception:
            body = {}
        msgs = body.get("messages") or [{}]
        ok = resp.status_code == 200 and msgs[0].get("code") == "0"
        return ok, resp.status_code, body
    finally:
        logout(host, token, verify_ssl=verify_ssl)


#: The Admin API `databases` fields this product reads. A PROJECTION, not the FMS object: `clients`,
#: encryption/decrypt metadata, `size`, `id` and any future key stay on the wire. A record that carries
#: only what a caller needs cannot leak what it does not (packet 1330).
@dataclass(frozen=True)
class HostedDatabase:
    filename: str            #: exactly as FMS returned it (carries `.fmp12`)
    name: str                #: bare name — the identity used everywhere else
    status: str              #: runtime status verbatim: NORMAL / CLOSED / OPENING / CLOSING / ""
    ext_privileges: tuple    #: normalized `enabledExtPrivileges`, lowercased, order preserved

    @property
    def open(self) -> "bool | None":
        """True/False against `_OPEN_RUNTIME`, or **None when FMS reported no status at all**.

        None is not "closed". An omitted status asserts nothing — inventing a closed state from an
        absent field would paint a live file gray. (Measured 2026-08-26: all 36 records on a live box
        carried a status, so this is a defensive case, not the expected one.)"""
        if not self.status:
            return None
        return self.status.upper() in _OPEN_RUNTIME


def _hosted_database(record: dict) -> HostedDatabase:
    """One Admin API `databases` entry -> the projection. Pure."""
    filename = str(record.get("filename") or "")
    privs = record.get("enabledExtPrivileges") or []
    return HostedDatabase(
        filename=filename,
        name=strip_fmp12(filename),
        status=str(record.get("status") or "").strip(),
        ext_privileges=tuple(str(p).strip().lower() for p in privs if str(p).strip()),
    )


def strip_fmp12(filename: str) -> str:
    """`Foo.fmp12` -> `Foo`. Kept here so the record primitive has no import cycle with discovery."""
    return filename[:-6] if filename.lower().endswith(".fmp12") else filename


def list_hosted_databases(host: str, session_token: str, *, verify_ssl: bool = False) -> list:
    """The hosted databases as `HostedDatabase` projections (packet 1330).

    Beside `list_databases`, not instead of it: the installed-identity Test, the remote-server Test and
    remote discovery all consume the filename list, and widening that return type would pull unrelated
    Settings contracts into this packet."""
    import requests

    resp = requests.get(
        f"https://{_clean_host(host)}/fmi/admin/api/v2/databases",
        headers={"Authorization": "Bearer " + session_token},
        verify=verify_ssl,
        timeout=30,
    )
    dbs = (resp.json().get("response") or {}).get("databases") or []
    return [_hosted_database(d) for d in dbs if d.get("filename")]


def list_databases(host: str, session_token: str, *, verify_ssl: bool = False) -> list[str]:
    """List hosted database filenames using a session token (for connection test).

    The filename PROJECTION of `list_hosted_databases`. Its callers (Settings' PKI Test, the
    remote-server Test, remote discovery) want names and nothing else; leave them that way."""
    return [d.filename for d in list_hosted_databases(host, session_token, verify_ssl=verify_ssl)]


# ── Database open/close via Admin API (no fmsadmin, no password) ─────────────

def _database_id(host: str, session_token: str, db_name: str, *, verify_ssl: bool = False):
    """Resolve the Admin API database id for a name (with or without .fmp12)."""
    import requests

    want = db_name if db_name.lower().endswith(".fmp12") else db_name + ".fmp12"
    resp = requests.get(
        f"https://{_clean_host(host)}/fmi/admin/api/v2/databases",
        headers={"Authorization": "Bearer " + session_token},
        verify=verify_ssl,
        timeout=30,
    )
    for d in (resp.json().get("response") or {}).get("databases") or []:
        if d.get("filename", "").lower() == want.lower():
            return d.get("id")
    return None


def set_database_status(
    host: str,
    key_name: str,
    private_pem: bytes,
    db_name: str,
    status: str,
    *,
    force: bool = False,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """Open/close a hosted database via the Admin API using PKI (no password).

    status is the PATCH target: "OPENED" or "CLOSED" (verified live 2026-06-04 —
    note GET reports runtime status "NORMAL"/"CLOSED", PATCH takes "OPENED"/"CLOSED").
    Returns (ok, message).
    """
    import json
    import requests

    token = authenticate(host, key_name, private_pem, verify_ssl=verify_ssl)
    try:
        db_id = _database_id(host, token, db_name, verify_ssl=verify_ssl)
        if db_id is None:
            return False, f"database {db_name!r} not found via Admin API"
        payload: dict = {"status": status}
        if force:
            payload["force"] = True
        resp = requests.patch(
            f"https://{_clean_host(host)}/fmi/admin/api/v2/databases/{db_id}",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            data=json.dumps(payload),
            verify=verify_ssl,
            timeout=60,
        )
        try:
            msgs = resp.json().get("messages") or [{}]
        except Exception:
            return False, f"HTTP {resp.status_code}: non-JSON response"
        ok = resp.status_code == 200 and msgs[0].get("code") == "0"
        return ok, str(msgs)
    finally:
        logout(host, token, verify_ssl=verify_ssl)


def close_database_pki(host, key_name, private_pem, db_name, *, force=True, verify_ssl=False):
    return set_database_status(host, key_name, private_pem, db_name, "CLOSED", force=force, verify_ssl=verify_ssl)


def open_database_pki(host, key_name, private_pem, db_name, *, verify_ssl=False):
    return set_database_status(host, key_name, private_pem, db_name, "OPENED", verify_ssl=verify_ssl)


# GET reports runtime status; these are the open-ish runtime values (PATCH targets
# differ: PATCH takes OPENED/CLOSED, GET reports NORMAL/CLOSED/OPENING/CLOSING).
_OPEN_RUNTIME = {"NORMAL", "OPENED", "OPEN"}


def database_runtime_status(host, session_token, db_name, *, verify_ssl=False) -> str:
    """The Admin API runtime status string for ``db_name`` (e.g. 'NORMAL', 'CLOSED',
    'CLOSING'), reusing an existing session token. '' if the DB isn't listed."""
    import requests

    want = db_name if db_name.lower().endswith(".fmp12") else db_name + ".fmp12"
    resp = requests.get(
        f"https://{_clean_host(host)}/fmi/admin/api/v2/databases",
        headers={"Authorization": "Bearer " + session_token},
        verify=verify_ssl,
        timeout=30,
    )
    for d in (resp.json().get("response") or {}).get("databases") or []:
        if d.get("filename", "").lower() == want.lower():
            return str(d.get("status", ""))
    return ""


def wait_until_status(host, key_name, private_pem, db_name, target, *,
                      timeout=90.0, interval=3.0, verify_ssl=False) -> bool:
    """Poll until ``db_name`` reaches ``target`` runtime status, reusing ONE Admin API
    session for the whole wait (the FMS session pool is small — error 956 if exhausted).

    target 'CLOSED' matches runtime CLOSED; target 'OPEN' matches NORMAL/OPENED.
    Returns True on match, False on timeout. FMS close/open is async, so callers must
    wait on this before acting on the file (the swap's lsof guard) or declaring success.
    """
    import time

    targ = str(target).upper()
    token = authenticate(host, key_name, private_pem, verify_ssl=verify_ssl)
    try:
        deadline = time.monotonic() + timeout
        while True:
            st = database_runtime_status(host, token, db_name, verify_ssl=verify_ssl).upper()
            if targ == "CLOSED" and st == "CLOSED":
                return True
            if targ in _OPEN_RUNTIME and st in _OPEN_RUNTIME:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval)
    finally:
        logout(host, token, verify_ssl=verify_ssl)


# ── Packet 1246-07: four ADDITIVE Admin-API primitives ───────────────────────
#
# Added BESIDE `register_public_key` / `delete_public_key`, which are NOT modified and keep their
# existing lifecycle callers until their
# assigned retirement owners switch them. The 1246-07 component never calls either, for one reason:
# `register_public_key` performs an UNCONDITIONAL delete-then-post (`:246-252`), which destroys a
# registration nobody has established is ours or broken. These four are the safe shapes.
#
# Endpoint contract MEASURED on both FMS 26.0.1.68 lanes, 2026-08-04, from the installed Admin API
# documentation and one live read-only GET per box:
#   GET    /server/config/pkipublickey   -> {"response": {"pkiPublicKey": [ {...}, ... ]}}
#   POST   /server/config/pkipublickey   <- {"name", "publicKey"}
#   PATCH  /server/config/pkipublickey   <- {"name", "publicKey"}     (exact-name replacement)
#   DELETE /server/config/pkipublickey   <- {"names": [...]}          (name-scoped; no fingerprint)
#
# Two measured surprises the readers below depend on:
#   * the live response key is `pkiPublicKey` (SINGULAR) while the document's own component schema
#     says `pkiPublicKeys` (plural) — an implementation written from the schema reads nothing and
#     concludes the registration is absent, which is the worst available wrong answer;
#   * `id` is a UUID STRING, not the integer the rendered sample shows.

_PKI_PUBLIC_KEY_PATH = "/server/config/pkipublickey"


def _admin_basic_session(host: str, admin_user: str, admin_pass: str, *, verify_ssl: bool = False):
    """One Basic-auth session for a single primitive call. The caller logs out."""
    return authenticate_basic(host, admin_user, admin_pass, verify_ssl=verify_ssl)


def get_public_keys(
    host: str,
    admin_user: str,
    admin_pass: str,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, list[dict], str]:
    """GET the registered Admin-API public keys. Returns ``(ok, entries, message)``.

    An entry carries ``id`` (UUID string), ``name``, ``publicKey`` (PEM with line breaks stripped),
    ``dateAdded`` and ``lastAccessed``. **An unrecognised response shape returns ok=False** rather
    than an empty list: "the server answered something I cannot read" and "the registration is
    absent" are different facts, and only one of them may authorize an Add.
    """
    import json
    import requests

    token = _admin_basic_session(host, admin_user, admin_pass, verify_ssl=verify_ssl)
    try:
        resp = requests.get(
            f"https://{_clean_host(host)}/fmi/admin/api/v2{_PKI_PUBLIC_KEY_PATH}",
            headers={"Authorization": "Bearer " + token},
            verify=verify_ssl,
            timeout=30,
        )
        try:
            body = resp.json()
        except Exception:
            return False, [], f"HTTP {resp.status_code}: non-JSON response"
        msgs = body.get("messages") or [{}]
        if resp.status_code != 200 or msgs[0].get("code") != "0":
            return False, [], str(msgs)
        response = body.get("response")
        if not isinstance(response, dict):
            return False, [], "response envelope is not an object"
        entries = response.get("pkiPublicKey")
        if not isinstance(entries, list):
            # Deliberately NOT falling back to the schema's plural spelling: a server that answers
            # in a shape we have not measured is unobserved, not empty.
            return False, [], "response carries no readable pkiPublicKey list"
        return True, [e for e in entries if isinstance(e, dict)], json.dumps(msgs)
    finally:
        logout(host, token, verify_ssl=verify_ssl)


def _read_pki_public_key_list(ok: bool, status: int, body: dict) -> tuple[bool, list[dict], str]:
    """The measured GET response shape, read once for both authorities.

    Same two surprises as ``get_public_keys``: the live key is SINGULAR ``pkiPublicKey``, and an
    unrecognised shape answers ``ok=False`` — "I cannot read this" never becomes "it is absent".
    """
    import json

    msgs = (body or {}).get("messages") or [{}]
    if not ok:
        return False, [], f"HTTP {status}: {msgs}"
    response = (body or {}).get("response")
    if not isinstance(response, dict):
        return False, [], "response envelope is not an object"
    entries = response.get("pkiPublicKey")
    if not isinstance(entries, list):
        return False, [], "response carries no readable pkiPublicKey list"
    return True, [e for e in entries if isinstance(e, dict)], json.dumps(msgs)


def get_public_keys_pki(
    host: str,
    key_name: str,
    private_pem: bytes,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, list[dict], str]:
    """The same measured GET, authenticated by the INSTALLED IDENTITY rather than a password.

    This exists so a working identity can inspect and remove ITSELF without an administrator
    credential. It reaches the Admin API through ``admin_api_request``, whose session is minted from
    the private key — **it never calls ``authenticate_basic`` and never carries a password**, which
    is the property the removal path depends on and a test asserts directly.
    """
    ok, status, body = admin_api_request(host, key_name, private_pem, "GET",
                                         _PKI_PUBLIC_KEY_PATH, verify_ssl=verify_ssl)
    return _read_pki_public_key_list(ok, status, body)


def delete_public_key_exact_pki(
    host: str,
    key_name: str,
    private_pem: bytes,
    target_name: str,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """The same measured name-scoped DELETE, authenticated by the installed identity.

    The body is FileMaker's ``{"names": [...]}`` exactly as measured. As with the Basic primitive,
    this enforces no precondition: its caller performs the name+fingerprint match and the read-back.
    """
    ok, status, body = admin_api_request(host, key_name, private_pem, "DELETE",
                                         _PKI_PUBLIC_KEY_PATH,
                                         json_body={"names": [target_name]}, verify_ssl=verify_ssl)
    return ok, str((body or {}).get("messages") or f"HTTP {status}")


def add_public_key(
    host: str,
    admin_user: str,
    admin_pass: str,
    key_name: str,
    public_pem,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """POST a NEW registration. **Never pre-deletes.**

    FMS refuses a duplicate name with error 1708. That refusal is a POSITIVE presence oracle and it
    is returned as-is: it means the name is taken, it proves nothing about whose key holds it, and it
    never authorizes a deletion. The caller re-observes with GET.
    """
    import json
    import requests

    if isinstance(public_pem, (bytes, bytearray)):
        public_pem = bytes(public_pem).decode("ascii")
    token = _admin_basic_session(host, admin_user, admin_pass, verify_ssl=verify_ssl)
    try:
        resp = requests.post(
            f"https://{_clean_host(host)}/fmi/admin/api/v2{_PKI_PUBLIC_KEY_PATH}",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            data=json.dumps({"name": key_name, "publicKey": public_pem}),
            verify=verify_ssl,
            timeout=30,
        )
        try:
            msgs = resp.json().get("messages") or [{}]
        except Exception:
            return False, f"HTTP {resp.status_code}: non-JSON response"
        ok = resp.status_code == 200 and msgs[0].get("code") == "0"
        return ok, str(msgs)
    finally:
        logout(host, token, verify_ssl=verify_ssl)


def update_public_key(
    host: str,
    admin_user: str,
    admin_pass: str,
    key_name: str,
    public_pem,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """PATCH an EXISTING registration in place — exact-name replacement, one call.

    This is what makes a second transitional registration name unnecessary: delete-then-post opens a
    window in which the box has no remote identity, and Update does not.

    **What is NOT established:** what a FAILED Update does to the prior registration. That was not
    exercised on either lane (§3.7 was GET-only), so a caller that sees a failure must re-observe
    with GET and classify from what it sees — never fall back to delete-then-post.
    """
    import json
    import requests

    if isinstance(public_pem, (bytes, bytearray)):
        public_pem = bytes(public_pem).decode("ascii")
    token = _admin_basic_session(host, admin_user, admin_pass, verify_ssl=verify_ssl)
    try:
        resp = requests.patch(
            f"https://{_clean_host(host)}/fmi/admin/api/v2{_PKI_PUBLIC_KEY_PATH}",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            data=json.dumps({"name": key_name, "publicKey": public_pem}),
            verify=verify_ssl,
            timeout=30,
        )
        try:
            msgs = resp.json().get("messages") or [{}]
        except Exception:
            return False, f"HTTP {resp.status_code}: non-JSON response"
        ok = resp.status_code == 200 and msgs[0].get("code") == "0"
        return ok, str(msgs)
    finally:
        logout(host, token, verify_ssl=verify_ssl)


def delete_public_key_exact(
    host: str,
    admin_user: str,
    admin_pass: str,
    key_name: str,
    *,
    verify_ssl: bool = False,
) -> tuple[bool, str]:
    """DELETE one registration by name — callable ONLY after an exact name+fingerprint match.

    The FMS body is name-scoped (``{"names": [...]}``); there is no fingerprint-scoped delete. So the
    whole guarantee lives in the observation that precedes this call and the read-back that follows
    it, which is why removal is specified as a sequence rather than as a call. This primitive
    enforces neither — its caller (``admin_identity_ops.remove``) does, and nothing else may call it.
    """
    import json
    import requests

    token = _admin_basic_session(host, admin_user, admin_pass, verify_ssl=verify_ssl)
    try:
        resp = requests.delete(
            f"https://{_clean_host(host)}/fmi/admin/api/v2{_PKI_PUBLIC_KEY_PATH}",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            data=json.dumps({"names": [key_name]}),
            verify=verify_ssl,
            timeout=30,
        )
        try:
            msgs = resp.json().get("messages") or [{}]
        except Exception:
            return False, f"HTTP {resp.status_code}: non-JSON response"
        ok = resp.status_code == 200 and msgs[0].get("code") == "0"
        return ok, str(msgs)
    finally:
        logout(host, token, verify_ssl=verify_ssl)
