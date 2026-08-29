"""Multi-user access store — named accounts + per-user GATES, backed by the USER table (packet 1007).

Users live in the storage DB (logical ``USER`` → ``TABLE6``), not a disk file: they TRAVEL with a
corpus wherever it goes (the old ``users.yaml`` did not). Only NON-secret lookup keys are indexed slots
(``Username`` — the case-insensitive login key; ``IsActive``). The sensitive material — the PBKDF2
password hash+salt — rides the Corpus-Key-encrypted ``SecretData`` container, never ``JSONOfRecord`` (the
table-wide secret fence enforces this). So a stolen ``.fmp12`` without the Corpus Key reveals
neither the reversible secrets nor the one-way hashes.

MCP tokens moved OUT of the USER record to their own ``MCPTOKEN`` table (packet 1029 —
``corpusfm.app.web.mcp_tokens``): a user has MANY named tokens, each independently deletable. This
module's ``resolve_mcp_token`` delegates there; the old single-token-per-user fields are retired.

Auth needs the Corpus Key (a box-local file always present on a running box) + the DB reachable. When someone
is locked out **with the DB up**, the on-box ``corpusfm users`` CLI resets it. When the DB is DOWN there
is no user-store remedy at all — the CLI writes to this same table — and no surface may offer one
(packet 1201); the repair is the FileMaker file itself via its local ``[Full Access]`` account.

Gates (booleans per user) govern the UI (page load) and MCP (token → user → gates) uniformly:
  automation   — Jobs / Monitoring / Runs
  library_mcp  — Artifacts / Tags / Explorer / Diff / Merge + MCP read/data tools (coupled)
  patching     — apply patches (ISV page OR MCP patch tools)
  fms_api      — Full FMS API: broad FileMaker Server control via MCP (Admin API, no password)
  settings     — = Admin: manage all users + all config

Documentation / About / Your-account are ungated (any logged-in user).
auth_method is the forward-compat seam for the deferred cloud-SSO / 2FA work ("password" today).
"""

from __future__ import annotations

import json as _json
import logging
import uuid as _uuidlib
from dataclasses import dataclass, field
from typing import Optional

from corpusfm.app.web.auth import hash_password, verify_password

log = logging.getLogger("corpusfm.users")


class UserStoreUnavailable(RuntimeError):
    """The USER table couldn't be read because the storage backend is unreachable — NOT because the
    user doesn't exist (packet 1067). Lets the auth layer tell a storage OUTAGE from a genuine
    unauth/deleted user, so an outage returns a degraded 503 instead of a 401 that redirect-churns
    the SPA to /login."""


GATES = ("automation", "library_mcp", "patching", "fms_api", "settings")

_USER = "USER"


@dataclass
class User:
    # NO password_hash here, deliberately. It lives ONLY in the Corpus-Key-encrypted SecretData container,
    # and every loader except verify_login reads the record WITHOUT that container — so a hash field on
    # this model is silently "" for almost every User in existence. Code that then does
    # `verify_password(pw, u.password_hash)` fails closed against an empty hash and rejects the CORRECT
    # password, with no error to notice. That exact bug shipped twice (the MCP-access "no token yet"
    # page, then /api/account/password, which rejected every password change for every user). Keeping
    # the secret off the model makes the broken state unrepresentable. To check a password, call
    # verify_user_password(); to check a login, call verify_login().
    id: str                       # the engine record key (uuid)
    username: str
    gates: set = field(default_factory=set)
    display_name: str = ""
    active: bool = True
    created_at: str = ""
    created_by: str = ""
    auth_method: str = "password"   # "password" | "oidc" | "ldap" (packet 1065)
    external_id: str = ""           # the IdP subject/email an external (oidc/ldap) user matches on
    prefs: dict = field(default_factory=dict)   # navigation, locale, calculation/script palettes

    @property
    def is_local(self) -> bool:
        """A local username/password account — the mandatory break-glass class (packet 1065)."""
        return self.auth_method == "password"

    @property
    def is_admin(self) -> bool:
        return "settings" in self.gates

    def has_gate(self, gate: str) -> bool:
        return gate in self.gates


# ── engine access ────────────────────────────────────────────────────────────

def _engine(backend=None):
    """The storage engine (USER lives in the DB). None when no engine is available (no store)."""
    try:
        if backend is None:
            from corpusfm.storage import get_backend
            backend = get_backend()
        return getattr(backend, "engine", None)
    except Exception:
        return None


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def _jor(u_username: str, active: bool, *, gates, display_name, created_at,
         created_by, auth_method, prefs, external_id="") -> dict:
    """Build the NON-SECRET record body. No password secret ever appears here (the fence)."""
    return {
        "Username": u_username,
        "IsActive": bool(active),
        "gates": sorted(g for g in gates if g in GATES),
        "display_name": display_name or u_username,
        "created_at": created_at or "",
        "created_by": created_by or "",
        "auth_method": auth_method or "password",
        "external_id": external_id or "",
        "prefs": dict(prefs or {}),
    }


def _user_from_row(row) -> User:
    j = row.jor
    u = User(
        id=row.key,
        username=str(j.get("Username", "")),
        gates={g for g in (j.get("gates") or []) if g in GATES},
        display_name=str(j.get("display_name", "")),
        active=_bool(j.get("IsActive", True)),
        created_at=str(j.get("created_at", "")),
        created_by=str(j.get("created_by", "")),
        auth_method=str(j.get("auth_method", "password")),
        external_id=str(j.get("external_id", "")),
        prefs=dict(j.get("prefs") or {}),
    )
    return u


def _bool(v) -> bool:
    return v in (True, 1, "1", "true")


# ── SecretData container (Corpus-Key-encrypted; never jor) ─────────────────────────

def _load_secret(engine, key: str) -> dict:
    from corpusfm.core.crypto import decode_blob, decompress
    try:
        raw = engine.blob_get(_USER, key, "SecretData")
        if not raw:
            return {}
        return _json.loads(decompress(decode_blob(raw)).decode("utf-8"))
    except Exception:
        log.debug("users: secret load failed for %s", key, exc_info=True)
        return {}


def _save_secret(engine, key: str, secret: dict) -> None:
    from corpusfm.core.crypto import compress, encode_blob
    blob = encode_blob(
        compress(_json.dumps(secret, ensure_ascii=False).encode("utf-8")),
        encrypt_on=True)   # ALWAYS Corpus-Key-encrypted — a hash/secret is never a bulk plaintext blob
    engine.blob_put(_USER, key, "SecretData", blob)


# ── reads ─────────────────────────────────────────────────────────────────────

def load_users(*, backend=None) -> list[User]:
    """All users (NON-secret view — gates/active/has_token from jor; no container reads)."""
    e = _engine(backend)
    if e is None:
        return []
    try:
        return [_user_from_row(r) for r in e.list_all(_USER)]
    except Exception:
        log.debug("users: list failed", exc_info=True)
        return []


def get_user(username: str, *, backend=None) -> Optional[User]:
    """Look up a user by username (case-insensitive indexed slot). NON-secret view."""
    e = _engine(backend)
    if e is None:
        return None
    try:
        r = e.get_one(_USER, Username=_norm(username))
        return _user_from_row(r) if r is not None else None
    except Exception:
        log.debug("users: get_user failed", exc_info=True)
        return None


def get_user_by_id(uid: str, *, backend=None, raise_on_error: bool = False) -> Optional[User]:
    e = _engine(backend)
    if e is None or not uid:
        return None
    try:
        rows = e.get_by_keys(_USER, [uid])
        return _user_from_row(rows[0]) if rows else None
    except Exception as exc:
        # A genuinely-absent user returns [] above (→ None) WITHOUT raising; reaching here means the
        # read itself failed — the storage backend is unreachable. raise_on_error lets the auth layer
        # distinguish that outage from an expired/deleted session (packet 1067).
        log.debug("users: get_user_by_id failed", exc_info=True)
        if raise_on_error:
            raise UserStoreUnavailable(str(exc)) from exc
        return None


def users_exist(*, backend=None, raise_on_error: bool = False) -> bool:
    """Whether ANY user is configured. ``raise_on_error`` draws the same absent-vs-unreadable line as
    ``get_user_by_id``: a storage outage is not an empty user store, and a caller that acts on the
    difference (the login page, the installer's first-admin detect) must not be handed a definite
    ``False`` it cannot trust. Default off so read-only callers keep the old best-effort shape."""
    e = _engine(backend)
    if e is None:
        if raise_on_error:
            raise UserStoreUnavailable("no storage engine")
        return False
    try:
        return bool(e.list_all(_USER))
    except Exception as exc:
        log.debug("users: users_exist failed", exc_info=True)
        if raise_on_error:
            raise UserStoreUnavailable(str(exc)) from exc
        return False


def _all_for_guard(e) -> list[User]:
    try:
        return [_user_from_row(r) for r in e.list_all(_USER)]
    except Exception:
        return []


def _admin_count(users: list[User]) -> int:
    return sum(1 for u in users if u.active and "settings" in u.gates)


def _would_orphan_local_admin(e, uid: str) -> bool:
    """True when removing/demoting/deactivating user ``uid`` would leave NO active local-password
    Settings-admin (packet 1065 break-glass). The mandatory invariant: at least one local admin can
    always log in even with the IdP down. Only fires when the TARGET is itself the last such admin — an
    all-SSO admin set with no local admin is a lock-out risk (the IdP could be unreachable). For a
    pure-password install this is identical to the old last-admin guard (every admin is local)."""
    users = _all_for_guard(e)
    target = next((u for u in users if u.id == uid), None)
    if target is None:
        return False
    if not (target.active and "settings" in target.gates and target.is_local):
        return False
    others = [u for u in users
              if u.id != uid and u.active and "settings" in u.gates and u.is_local]
    return not others


def _row_for(e, uid: str):
    rows = e.get_by_keys(_USER, [uid])
    return rows[0] if rows else None


# ── auth ────────────────────────────────────────────────────────────────────────

def verify_login(username: str, password: str, *, backend=None) -> Optional[User]:
    e = _engine(backend)
    if e is None:
        return None
    try:
        r = e.get_one(_USER, Username=_norm(username))
    except Exception:
        return None
    if r is None or not _bool(r.jor.get("IsActive", True)):
        return None
    ph = _load_secret(e, r.key).get("password_hash", "")
    if ph and verify_password(password, ph):
        return _user_from_row(r)
    return None


def verify_user_password(uid: str, password: str, *, backend=None) -> bool:
    """Does ``password`` match the stored hash for user ``uid``?

    The ONLY correct way to check a known user's password: it reads the hash from the SecretData
    container at call time. Never compare against a hash carried on a ``User`` — the model doesn't
    carry one, for the reason documented on the dataclass. Fails closed on a missing/absent secret
    (an external oidc/ldap user has no hash → False, never a bypass).
    """
    e = _engine(backend)
    if e is None or not uid or not password:
        return False
    r = _row_for(e, uid) if e is not None else None
    if r is None or not _bool(r.jor.get("IsActive", True)):
        return False
    ph = _load_secret(e, uid).get("password_hash", "")
    return bool(ph) and verify_password(password, ph)


# ── writes ────────────────────────────────────────────────────────────────────

def create_user(username: str, password: str, gates, *, display_name: str = "",
                created_by: str = "", now: str = "", backend=None) -> User:
    """Create a user in the USER table. Raises ValueError on a duplicate/invalid username, or
    RuntimeError when no storage engine is available (the USER table needs the DB)."""
    uname = (username or "").strip()
    if not uname or not uname.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise ValueError("Username must be alphanumeric (plus _ . -).")
    e = _engine(backend)
    if e is None:
        raise RuntimeError("no storage engine — the user store needs the database")
    if e.get_one(_USER, Username=_norm(uname)) is not None:
        raise ValueError(f"User '{uname}' already exists.")
    key = str(_uuidlib.uuid4())
    jor = _jor(uname, True, gates=gates, display_name=display_name, created_at=now,
               created_by=created_by, auth_method="password", prefs={})
    e.create(_USER, key, jor)
    _save_secret(e, key, {"password_hash": hash_password(password)})
    return _user_from_row(_row_for(e, key))


def create_external_user(username: str, *, auth_method: str, external_id: str = "", gates=(),
                         display_name: str = "", created_by: str = "", now: str = "",
                         backend=None) -> User:
    """JIT-create an EXTERNAL (oidc/ldap) user (packet 1065) — no password, no SecretData container.
    Default gates are EMPTY: a gateless account reaches only Documentation + its own account
    (`require_gate` redirects it to /docs), so auto-provisioning exposes nothing until an admin grants
    gates or a group→gate mapping does. Raises ValueError on a duplicate/invalid username."""
    if auth_method not in ("oidc", "ldap"):
        raise ValueError("create_external_user requires auth_method oidc|ldap")
    uname = (username or "").strip()
    if not uname or not uname.replace("_", "").replace("-", "").replace(".", "").replace("@", "").isalnum():
        raise ValueError("Username must be alphanumeric (plus _ . - @).")
    e = _engine(backend)
    if e is None:
        raise RuntimeError("no storage engine — the user store needs the database")
    if e.get_one(_USER, Username=_norm(uname)) is not None:
        raise ValueError(f"User '{uname}' already exists.")
    key = str(_uuidlib.uuid4())
    jor = _jor(uname, True, gates=gates, display_name=display_name, created_at=now,
               created_by=created_by, auth_method=auth_method, prefs={}, external_id=external_id)
    e.create(_USER, key, jor)
    return _user_from_row(_row_for(e, key))


def get_user_by_external_id(external_id: str, *, auth_method: str = "", backend=None) -> Optional[User]:
    """Find an external user by IdP subject/email (optionally scoped to an auth_method). external_id is
    not an indexed slot (rare, tiny table) → scan. Returns the NON-secret view."""
    xid = (external_id or "").strip().lower()
    if not xid:
        return None
    for u in load_users(backend=backend):
        if (u.external_id or "").strip().lower() == xid and (not auth_method or u.auth_method == auth_method):
            return u
    return None


def apply_sso_gates(uid: str, gates, *, backend=None) -> None:
    """Set an SSO user's effective gates at login (packet 1065 Ph2 — group→gate mapping is authoritative
    and refreshes each login). Unguarded on purpose: an SSO user is never the local break-glass admin, so
    the group mapping fully owns their gates (add/remove). Never touches a local user's gates."""
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        return
    if str(r.jor.get("auth_method", "password")) == "password":
        return                                   # never let SSO login rewrite a local user's gates
    new = sorted({g for g in gates if g in GATES})
    if new == [g for g in (r.jor.get("gates") or []) if g in GATES]:
        return                                   # unchanged → no write
    jor = dict(r.jor)
    jor["gates"] = new
    e.update(_USER, uid, jor)


def set_user_password(uid: str, password: str, *, backend=None) -> None:
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        raise ValueError("User not found.")
    secret = _load_secret(e, uid)
    secret["password_hash"] = hash_password(password)
    _save_secret(e, uid, secret)


def update_user_gates(uid: str, gates, *, backend=None) -> None:
    """Set a user's gates. Refuses to drop the LAST active Settings-admin (no lock-out)."""
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        raise ValueError("User not found.")
    new = {g for g in gates if g in GATES}
    cur = {g for g in (r.jor.get("gates") or []) if g in GATES}
    if "settings" in cur and "settings" not in new and _would_orphan_local_admin(e, uid):
        raise ValueError("Cannot remove Settings access from the last local admin (break-glass).")
    jor = dict(r.jor)
    jor["gates"] = sorted(new)
    e.update(_USER, uid, jor)


#: The last update target this user chose to skip (packet 1341). A top-level, non-secret operational
#: field on the USER record — deliberately NOT a personal preference: it is never offered through
#: `clean_prefs`, `/api/account/prefs`, or the account UI, because a user does not "prefer" a skipped
#: commit. One scalar per user is naturally bounded: skipping a later head overwrites the earlier
#: value, and a DIFFERENT registered target re-arms the prompt.
_SKIPPED_UPDATE_HEAD = "SkippedUpdateHead"


def skipped_update_head(uid: str, *, backend=None) -> str:
    """The head this user last skipped, or "". Absent on every record written before packet 1341."""
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        return ""
    return str(r.jor.get(_SKIPPED_UPDATE_HEAD) or "")


def set_skipped_update_head(uid: str, head: str, *, backend=None) -> None:
    """Record the head this user skipped. Raises when the user cannot be read, so the caller can keep
    the prompt open rather than report a skip it did not persist."""
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        raise ValueError("User not found.")
    jor = dict(r.jor)
    jor[_SKIPPED_UPDATE_HEAD] = str(head or "")
    e.update(_USER, uid, jor)


def set_user_active(uid: str, active: bool, *, backend=None) -> None:
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        raise ValueError("User not found.")
    if not active and _would_orphan_local_admin(e, uid):
        raise ValueError("Cannot deactivate the last local admin (break-glass).")
    jor = dict(r.jor)
    jor["IsActive"] = bool(active)
    e.update(_USER, uid, jor)


def delete_user(uid: str, *, acting_user_id: str = "", backend=None) -> None:
    """Delete a user. Guards: never delete yourself; never delete the last Settings-admin."""
    if uid == acting_user_id:
        raise ValueError("You cannot delete your own account.")
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        raise ValueError("User not found.")
    if _would_orphan_local_admin(e, uid):
        raise ValueError("Cannot delete the last local admin (break-glass).")
    e.delete(_USER, uid)
    # Cascade: drop the user's MCP tokens (no orphan rows / lingering secret hashes).
    try:
        from corpusfm.app.web import mcp_tokens
        mcp_tokens.delete_all_for(uid, backend=backend)
    except Exception:
        log.debug("users: token cascade-delete failed for %s", uid, exc_info=True)
    # Cascade: drop the user's OAuth records too — their browser consents, access tokens, codes,
    # transactions and (packet 1183) refresh families with every generation in them. Registered DCR
    # clients are GLOBAL and stay: another user may have
    # authorized the same client. Both cascades are hygiene, not the boundary — every credential
    # already fails closed the moment the USER row above disappears (the owner cannot be resolved), so
    # a failure here is LOGGED and never re-raised into the deletion.
    try:
        from corpusfm.app.web import oauth_store
        oauth_store.delete_all_for_subject(uid, backend=backend)
    except Exception:
        log.warning("users: OAuth cascade-delete did not complete for user %s — credentials still fail "
                    "closed (the owner no longer resolves); residue may remain", uid, exc_info=True)


def clean_prefs(body: dict) -> dict:
    """Validate a personal-prefs payload → only known keys with allowed values.

    landing_page ∈ landing.LANDING_KEYS (any landable page); docs_drawer_side ∈ {left, right};
    addon_locale ∈ FM_ADDON_LOCALES or "" (system default); calculation_palette and script_palette
    are curated syntax-palette ids. Unknown keys dropped."""
    from corpusfm.app.app_config import FM_ADDON_LOCALES
    from corpusfm.app.web.landing import LANDING_KEYS
    out: dict = {}
    if "landing_page" in body:
        v = str(body["landing_page"]).strip().lower()
        out["landing_page"] = v if v in LANDING_KEYS else "artifacts"
    if "docs_drawer_side" in body:
        v = str(body["docs_drawer_side"]).strip().lower()
        out["docs_drawer_side"] = v if v in ("left", "right") else "right"
    if "addon_locale" in body:
        v = str(body["addon_locale"]).strip().lower()
        out["addon_locale"] = v if v in FM_ADDON_LOCALES else ""
    from corpusfm.extensions.export.syntax_palettes import clean_palette_id
    if "calculation_palette" in body:
        out["calculation_palette"] = clean_palette_id(body["calculation_palette"])
    if "script_palette" in body:
        out["script_palette"] = clean_palette_id(body["script_palette"])
    return out


def set_user_prefs(uid: str, prefs: dict, *, backend=None) -> None:
    """Merge validated personal prefs into a user's stored prefs."""
    e = _engine(backend)
    r = _row_for(e, uid) if e is not None else None
    if r is None:
        raise ValueError("User not found.")
    jor = dict(r.jor)
    merged = dict(jor.get("prefs") or {})
    merged.update(clean_prefs(prefs))
    jor["prefs"] = merged
    e.update(_USER, uid, jor)


# ── MCP tokens ────────────────────────────────────────────────────────────────
# Per-user MCP tokens live in their OWN table now (many named tokens per user — packet 1029,
# corpusfm.app.web.mcp_tokens). This shim keeps the verifier's call site stable.

def resolve_mcp_token(token: str, *, backend=None) -> Optional[User]:
    """Resolve a bearer token to its active owner (with the owner's current gates), or None."""
    from corpusfm.app.web import mcp_tokens
    return mcp_tokens.resolve(token, backend=backend)
