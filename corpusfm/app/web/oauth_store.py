"""OAuth persistence — backed by the OAUTH table (packet 1179).

The SHARED, multi-worker-safe storage adapter under the FastMCP ``OAuthProvider`` (see
:mod:`corpusfm.mcp.oauth_provider`). Nothing authoritative lives in provider instance state; every
credential is written here and re-read on the next request, so a deactivation or gate change takes
effect immediately and a credential minted by one worker is enforceable by another.

Storage (logical ``OAUTH`` → ``TABLE11``, a free-spare claim; the packet-1029 MCPTOKEN pattern). ONE
Type-discriminated table holds seven record kinds:

  Type       Handle (indexed)      Secret hash (the Corpus Key container)   Purpose
  client     client_id             —                               a registered public PKCE client
  txn        opaque txn handle     —                               server-held authorization transaction
  code       non-secret half       sha256(secret half)             authorization code (single use)
  token      non-secret half       sha256(secret half)             OAuth access token (bounded, revocable)
  consent    —(Subject+ClientId)   —                               a consent grant (user↔client↔resource)
  family     opaque family id      —                               one refresh lineage (packet 1183)
  refresh    non-secret half       sha256(secret half)             one refresh generation (rotating)

Every credential lookup is INDEXED (by ``Handle``, or by ``Subject``/``ClientId`` for consent) and
SHAPE-DISPATCHED — a no-dot OAuth access token never touches the manual per-user token store, and a
dotted manual token never fans out through here. The SECRET half's SHA-256 hash rides the Corpus Key-
encrypted ``SecretData`` container, never ``JSONOfRecord`` (the table-wide secret fence). Non-secret
metadata (redirect URIs, requested scopes, resource, expiry, single-use / revoked flags, PKCE
challenge, subject) rides jor. Expiry is enforced in code, fail-closed. A store outage fails closed
(returns None / False) — never opens access.

Packet 1182 adds the USER-OWNED half: a ``consent`` row IS the user-facing "browser connection", and
:func:`list_connections_for` / :func:`disconnect` / :func:`delete_all_for_subject` are its list, revoke
and user-deletion primitives. Those three are the only functions here that RAISE
(:class:`OAuthStoreUnavailable`) instead of failing quietly — an account surface must be able to tell
"nothing matched" from "this did not happen". The exchange path became
:func:`exchange_code_for_token`, which consumes the code, re-checks the live grant and mints inside ONE
critical section so a Disconnect can never be raced around — binding the token to the CODE's own
resource, so no exchange can turn a grant for one audience into a token for another.

The SAME composition applies one step earlier: :func:`approve_authorization` consumes the authorization
transaction, re-checks the live grant, records the consent and mints the code in ONE section, so an
in-flight browser approval cannot straddle a Disconnect and rebuild the grant it just removed.

Both of those decisions read the grant STRICTLY (:func:`_find_consent_row_strict`): inside a decision a
store read failure must NOT flatten into "no consent". The public read keeps the quiet fail-closed
variant; a decision that cannot see the grant consumes nothing and creates nothing.

Packet 1183 adds the DURABLE half: an OAuth authorization now also creates a REFRESH FAMILY. The access
credential ROTATES every 8 hours, silently — nobody signs in because of it. One family is one
connection's credential lineage; each generation is one ``refresh`` row, rotated on every use
(:func:`rotate_refresh`). The whole lifecycle runs under the SAME critical section as the code exchange
and Disconnect, so those three can never interleave.

The family row is also the connection's REVOCATION BARRIER: an access token that names a family is only
valid while that family is active and inside its current effective boundaries, and every revocation path
retires the family row before it walks the descendants it minted. So an interrupted revocation, and an
administrator policy tightened after issuance, both reach credentials that are already in a client's
hands — the token row's own flags are hygiene, not the authority.

Nothing sits above the family. There is no server-wide control: OAuth sign-in is available whenever this
box has a usable MCP address, and a connection ends in exactly three ways — Disconnect, its owner being
deactivated, or its own boundaries passing (packet 1220). There is deliberately no fourth: an
administrator cannot end everyone's connections in one action, and no stored row can put this store into
a state that refuses them all.
"""

from __future__ import annotations

import hashlib
import hmac
import json as _json
import logging
import math
import os
import secrets
import time
import uuid as _uuidlib
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

# Module-level (unlike the other oauth_policy imports here, which stay function-local): every
# fail-closed branch below names this exception, and an import that could itself fail would defeat the
# point. oauth_policy pulls app_config lazily, so this direction carries no cycle.
from corpusfm.app.web.oauth_policy import PolicyUnavailable, current_policy as _current_policy

log = logging.getLogger("corpusfm.oauth_store")

_TBL = "OAUTH"

# ── Cross-process single-use serialization (packet 1179 review §1) ───────────────
# The OAUTH table is the AUTHORITY; this file lock is SYNCHRONIZATION ONLY. A read-then-write pair
# (re-read the record, check its single-use flag, then write) is not atomic across the multiple worker
# processes the co-located service may run, and the SqliteEngine/OData engine offer no compare-and-swap.
# So every single-use decision (subject first-bind, txn consume, code consume) runs INSIDE this
# box-wide `filelock` critical section, re-reading the record under the lock before deciding — making
# "exactly one winner" a real cross-process guarantee. `filelock` is cross-platform (Linux + Windows)
# and pinned in BOTH locked server constraints (constraints-server-py313.txt / -win-py313.txt).
# Acquisition is BOUNDED (a timeout) and FAILS CLOSED: if the lock can't be taken, the caller treats
# the operation as not-performed (no consume, no bind) rather than racing unserialized.

_LOCK_TIMEOUT_SECONDS = 10.0


def _lock_timeout() -> float:
    """Bounded acquisition timeout. ``CORPUSFM_OAUTH_LOCK_TIMEOUT`` overrides the default (a test shortens
    it to prove the fail-closed path when the lock is genuinely held by another process)."""
    raw = os.environ.get("CORPUSFM_OAUTH_LOCK_TIMEOUT")
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return _LOCK_TIMEOUT_SECONDS


def _oauth_lock_path() -> Path:
    """Stable, install-owned lock path in this installation's run directory, shared by every worker
    process on this box. ``CORPUSFM_OAUTH_LOCK`` overrides it (tests point it at a temp file).

    **The home-directory fallback is gone (packet 1246-03-01).** This used to end with
    ``except Exception: return Path.home()/".corpusfm"/"oauth.lock"``, which was harmless while the
    config home *was* that directory and became the exact hole this packet closes the moment paths
    came from an installation record: `InstallationStateUnclear` is an `Exception`, so a box that
    could not resolve its own layout would quietly take a lock in whichever home the process
    happened to have — and two processes with different `HOME` values would take *different* locks
    while believing they shared one. A lock nobody else takes is worse than no lock. It refuses now.
    """
    from corpusfm.lifecycle import app_paths

    # DEVELOPMENT ONLY (packet 1246-03-01). A published installation locks in its own run directory.
    # An override here is worse than a misplaced file: two processes reading different values take
    # DIFFERENT locks while believing they share one, which is precisely the race this lock exists
    # to prevent.
    override = app_paths.development_override(
        "CORPUSFM_OAUTH_LOCK", lambda: os.environ.get("CORPUSFM_OAUTH_LOCK"),
        what="the OAuth lock location")
    if override:
        return Path(override)
    return app_paths.run_dir() / "oauth.lock"


class OAuthStoreUnavailable(RuntimeError):
    """A mutation could not be completed honestly (store or lock failure). Raised only by the
    account-facing primitives (packet 1182), whose caller must distinguish "did not happen" from
    "nothing matched" — the credential paths keep their fail-closed None/False contract."""


class OAuthLockUnavailable(OAuthStoreUnavailable):
    """The cross-process serialization lock could not be acquired within the bound — fail closed."""


@contextmanager
def oauth_critical_section():
    """Box-wide bounded, fail-closed critical section for every single-use OAUTH decision. Raises
    :class:`OAuthLockUnavailable` on a timeout / lock error so the caller does NOT proceed unserialized."""
    from filelock import FileLock, Timeout
    p = _oauth_lock_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    timeout = _lock_timeout()
    lock = FileLock(str(p), timeout=timeout)
    try:
        lock.acquire()
    except Timeout as exc:
        raise OAuthLockUnavailable(f"OAuth serialization lock timed out after {timeout}s") from exc
    except Exception as exc:                      # unwritable dir / odd FS → fail closed, never race
        raise OAuthLockUnavailable("OAuth serialization lock could not be acquired") from exc
    try:
        yield
    finally:
        try:
            lock.release()
        except Exception:
            log.debug("oauth_store: lock release failed", exc_info=True)

# The reserved OAuth access-token prefix — a no-dot opaque string, distinct from the manual
# `<token_id>.<secret>` shape, so verify_token can shape-dispatch without a cross-store fan-out.
ACCESS_TOKEN_PREFIX = "cfmoa_"
_CODE_PREFIX = "cfmoc_"
_TXN_PREFIX = "cfmtx_"
REFRESH_TOKEN_PREFIX = "cfmor_"        # opaque, no-dot, OAuth-shaped (packet 1183)
_FAMILY_PREFIX = "cfmfam_"             # NON-secret lineage identifier (never a credential)
_HANDLE_HEX = 16                       # fixed-width non-secret lookup half (token_hex(8))

# Bounded lifetimes. The access credential stays SHORT and ROTATES every 8 hours (packet 1183) — the
# client exchanges a refresh credential for a successor, so the connection outlives each access token
# without any of them becoming a long-lived credential, and without anyone signing in.
CODE_TTL_SECONDS = 60
TXN_TTL_SECONDS = 600
ACCESS_TTL_SECONDS = 8 * 3600

# Rotation-concurrency tolerance (packet 1183). Ordinary clients fire parallel requests, and two of them
# can present the SAME refresh credential at once: one rotates, the other arrives to find it spent. That
# is not a compromise signal, so a verified replay THIS SOON after the credential was spent returns
# invalid_grant and mints nothing — while leaving the winner's family untouched. It never makes the spent
# credential valid again, so a stolen retired credential gains no usable grace-period access. Beyond the
# window a verified replay IS the compromise signal and revokes the whole family.
REFRESH_ROTATION_WINDOW_SECONDS = 30.0


def _engine(backend=None):
    try:
        if backend is None:
            from corpusfm.storage import get_backend
            backend = get_backend()
        return getattr(backend, "engine", None)
    except Exception:
        return None


def _now() -> float:
    """The one clock every lifetime decision in this module reads. It is a module-level seam on purpose:
    a lifetime test must be able to stand at a chosen instant (a 30-day boundary, the far side of the
    rotation-concurrency window) instead of sleeping, so the intended outcome is established
    deterministically rather than by process timing (packet 1183)."""
    return time.time()


def _owner_gates(subject: str, *, backend=None):
    """The owner's CURRENT gates (sorted), or None when the account is missing or inactive. Resolved from
    durable state on every call — a deactivated or deleted user fails closed at once, with no cached
    copy anywhere. The provider's own live-gate resolution delegates here so there is ONE rule.

    ``backend`` is threaded through so a decision made against an explicitly supplied store resolves the
    owner from THAT store — the owner check and the credential it guards must never read different
    databases."""
    if not subject:
        return None
    try:
        from corpusfm.app.web import users as _us
        u = _us.get_user_by_id(subject, backend=backend)
    except Exception:
        return None
    if u is None or not u.active:
        return None
    return sorted(u.gates)


class _LineageCorrupt(ValueError):
    """A stored MONOTONIC COUNTER (a refresh generation) or a generation's own timeline is not the schema
    it was written with — never interpreted, never coerced (review round 6)."""


def _stored_counter(value, field: str) -> int:
    """ONE stored monotonic counter, validated to a non-negative integer, or :class:`_LineageCorrupt`.

    NOTHING is coerced, because the counter is compared for EQUALITY against a live value and ``int()``
    manufactures a match out of a damaged one: ``int("1")``, ``int(1.5)`` and ``int(True)`` all produce 1,
    which equals family generation 1 — so a malformed ``Generation`` would satisfy the check that
    authorizes a rotation. ``bool`` is excluded explicitly: it is an ``int`` subclass and would otherwise
    pass as 0/1."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _LineageCorrupt(f"{field} is not a stored non-negative integer")
    return value


def _sha(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _mint_credential(prefix: str) -> tuple[str, str, str]:
    """Return (full_credential, handle, secret). ``handle`` is a fixed-width non-secret lookup half;
    ``secret`` is high-entropy. The full string carries NO dot (OAuth shape). Format:
    ``<prefix><handle:16hex><secret>`` — split by the fixed handle width, no ambiguous delimiter."""
    handle = secrets.token_hex(_HANDLE_HEX // 2)      # 16 hex chars
    secret = secrets.token_urlsafe(32)
    return prefix + handle + secret, handle, secret


def _split_credential(prefix: str, cred: str) -> Optional[tuple[str, str]]:
    if not cred or not cred.startswith(prefix):
        return None
    body = cred[len(prefix):]
    if len(body) <= _HANDLE_HEX:
        return None
    return body[:_HANDLE_HEX], body[_HANDLE_HEX:]


# ── SecretData container (Corpus-Key-encrypted; never jor) ─────────────────────────

def _save_secret_hash(engine, key: str, secret_hash: str) -> None:
    from corpusfm.core.crypto import compress, encode_blob
    blob = encode_blob(
        compress(_json.dumps({"secret_hash": secret_hash}).encode("utf-8")),
        encrypt_on=True)   # ALWAYS Corpus-Key-encrypted (the secret fence)
    engine.blob_put(_TBL, key, "SecretData", blob)


def _load_secret_hash(engine, key: str) -> str:
    from corpusfm.core.crypto import decode_blob, decompress
    try:
        raw = engine.blob_get(_TBL, key, "SecretData")
        if not raw:
            return ""
        return str(_json.loads(decompress(decode_blob(raw)).decode("utf-8")).get("secret_hash", ""))
    except Exception:
        log.debug("oauth_store: secret-hash load failed for %s", key, exc_info=True)
        return ""


# ── clients (public PKCE; exact loopback redirect URIs) ───────────────────────

def save_client(record: dict, *, backend=None) -> bool:
    """Persist a registered public client. ``record`` must carry ``client_id`` and ``redirect_uris``."""
    e = _engine(backend)
    if e is None:
        return False
    cid = str(record.get("client_id") or "")
    if not cid:
        return False
    key = str(_uuidlib.uuid4())
    created = _now()
    e.create(_TBL, key, {
        "Type": "client", "Handle": cid, "ClientId": cid,
        "ClientRecord": record, "CreatedAt": created,
        "ExpiresAt": created + CLIENT_ABANDONED_SECONDS,
    })
    return True


def get_client_strict(client_id: str, *, backend=None) -> Optional[dict]:
    """The registered client record, RAISING :class:`OAuthStoreUnavailable` when the store could not be
    read (packet 1182 review round 5).

    ``None`` here means exactly one thing: there is no usable registration for this ``client_id`` — no
    row, or a row whose ``ClientRecord`` is not a record. A read that FAILED is a different fact, and an
    account surface that collapses the two reports a live client as an unregistered one: the connection
    list would quietly show a short-id fallback label and still claim it read your connections
    successfully. Callers that only need to fail closed keep using :func:`get_client`."""
    e = _engine(backend)
    if e is None:
        raise OAuthStoreUnavailable("the OAuth store is unavailable")
    if not client_id:
        return None
    try:
        r = e.get_one(_TBL, Type="client", Handle=client_id)
    except Exception as exc:
        raise OAuthStoreUnavailable("could not read the client registration") from exc
    if r is None:
        return None
    rec = r.jor.get("ClientRecord")
    return rec if isinstance(rec, dict) else None


def get_client(client_id: str, *, backend=None) -> Optional[dict]:
    """Fail-closed client lookup for the PROTOCOL paths: ``None`` on an absent client OR a store
    failure. Those callers refuse the request either way, so the distinction buys them nothing."""
    try:
        return get_client_strict(client_id, backend=backend)
    except OAuthStoreUnavailable:
        log.debug("oauth_store: get_client failed", exc_info=True)
        return None


# ── authorization transactions (server-held; opaque; single use) ──────────────

def create_txn(*, client_id: str, redirect_uri: str, redirect_uri_provided_explicitly: bool,
               code_challenge: str, scopes, resource: str, state: Optional[str],
               backend=None) -> Optional[str]:
    """Create a server-held authorization transaction; return its opaque single-use handle."""
    e = _engine(backend)
    if e is None:
        return None
    try:
        with oauth_critical_section():
            # Cleanup uses this same lock. Re-resolve inside it so a client cannot be deleted after the
            # provider resolved it but before its first relationship row is created.
            if get_client_strict(client_id, backend=backend) is None:
                return None
            handle = _TXN_PREFIX + secrets.token_urlsafe(24)
            key = str(_uuidlib.uuid4())
            now = _now()
            e.create(_TBL, key, {
                "Type": "txn", "Handle": handle, "ClientId": client_id,
                "RedirectUri": redirect_uri,
                "RedirectUriProvidedExplicitly": bool(redirect_uri_provided_explicitly),
                "CodeChallenge": code_challenge, "Scopes": list(scopes or []),
                "Resource": resource, "State": state, "Subject": "",
                "ExpiresAt": now + TXN_TTL_SECONDS, "Used": False, "CreatedAt": now,
            })
            return handle
    except Exception:
        log.debug("oauth_store: transaction create failed closed", exc_info=True)
        return None


def get_txn(handle: str, *, backend=None) -> Optional[dict]:
    """Return a live (unexpired, unused) transaction record + its engine key, or None."""
    e = _engine(backend)
    if e is None or not handle:
        return None
    try:
        r = e.get_one(_TBL, Type="txn", Handle=handle)
    except Exception:
        return None
    if r is None:
        return None
    j = dict(r.jor)
    if j.get("Used") or float(j.get("ExpiresAt", 0)) < _now():
        return None
    j["_key"] = r.key
    return j


def _get_txn_row(e, handle: str):
    """The raw (row, jor) for a live (unexpired, unused) txn, or (None, None). Caller holds the lock."""
    try:
        r = e.get_one(_TBL, Type="txn", Handle=handle)
    except Exception:
        return None, None
    if r is None:
        return None, None
    j = dict(r.jor)
    if j.get("Used") or float(j.get("ExpiresAt", 0)) < _now():
        return None, None
    return r, j


def bind_txn_subject(handle: str, subject: str, *, backend=None) -> bool:
    """FIRST-BIND-ONLY owner binding, serialized cross-process. Under the lock: empty→subject binds;
    same-subject is an idempotent no-op success; a DIFFERENT already-bound subject can NEVER be
    overwritten (returns False). Returns False on any store/lock failure (fail closed)."""
    e = _engine(backend)
    if e is None or not subject:
        return False
    try:
        with oauth_critical_section():
            r, j = _get_txn_row(e, handle)
            if r is None:
                return False
            cur = j.get("Subject") or ""
            if cur and cur != subject:
                return False                     # another user already owns this transaction
            if cur == subject:
                return True                      # idempotent same-user re-bind
            j["Subject"] = subject
            e.update(_TBL, r.key, j)
            return True
    except OAuthLockUnavailable:
        log.warning("oauth_store: bind_txn_subject fail-closed (lock unavailable)")
        return False
    except Exception:
        log.debug("oauth_store: bind_txn_subject failed", exc_info=True)
        return False


def consume_txn(handle: str, *, backend=None) -> Optional[dict]:
    """Consume a live transaction — EXACTLY ONE winner across processes. Under the lock: re-read; if
    already used/expired → None (this caller did NOT consume it); else flip Used and return the record.
    Never claims consumption from an unconditional write: the pre-state is checked under the lock and
    only the caller that flips the flag receives the record."""
    e = _engine(backend)
    if e is None:
        return None
    try:
        with oauth_critical_section():
            r, j = _get_txn_row(e, handle)
            if r is None:
                return None
            j["Used"] = True
            e.update(_TBL, r.key, j)          # inside the lock: this caller is the sole winner
            j["_key"] = r.key
            return j
    except OAuthLockUnavailable:
        log.warning("oauth_store: consume_txn fail-closed (lock unavailable)")
        return None
    except Exception:
        log.debug("oauth_store: consume_txn failed", exc_info=True)
        return None


# ── authorization codes (hash-only; bound; short expiry; single use) ──────────

def _mint_code_row(e, *, client_id: str, subject: str, scopes, code_challenge: str, redirect_uri: str,
                   redirect_uri_provided_explicitly: bool, resource: str) -> Optional[str]:
    """Write one authorization-code record + its secret hash. No lock of its own, so it composes inside
    an existing critical section (the atomic approval) as well as outside one."""
    cred, handle, secret = _mint_credential(_CODE_PREFIX)
    key = str(_uuidlib.uuid4())
    e.create(_TBL, key, {
        "Type": "code", "Handle": handle, "ClientId": client_id, "Subject": subject,
        "Scopes": list(scopes or []), "CodeChallenge": code_challenge, "RedirectUri": redirect_uri,
        "RedirectUriProvidedExplicitly": bool(redirect_uri_provided_explicitly),
        "Resource": resource, "ExpiresAt": _now() + CODE_TTL_SECONDS, "Used": False, "CreatedAt": _now(),
    })
    try:
        _save_secret_hash(e, key, _sha(secret))
    except Exception:
        try:
            e.delete(_TBL, key)
        except Exception:
            log.debug("oauth_store: code rollback delete failed for %s", key, exc_info=True)
        return None
    return cred


def mint_code(*, client_id: str, subject: str, scopes, code_challenge: str, redirect_uri: str,
              redirect_uri_provided_explicitly: bool, resource: str, backend=None) -> Optional[str]:
    e = _engine(backend)
    if e is None:
        return None
    return _mint_code_row(e, client_id=client_id, subject=subject, scopes=scopes,
                          code_challenge=code_challenge, redirect_uri=redirect_uri,
                          redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
                          resource=resource)


def load_code(cred: str, *, backend=None) -> Optional[dict]:
    """Validate + return an authorization-code record (unexpired, unused, correct secret), or None.
    Does NOT consume — the caller consumes on a successful exchange."""
    parts = _split_credential(_CODE_PREFIX, cred)
    e = _engine(backend)
    if parts is None or e is None:
        return None
    handle, secret = parts
    try:
        r = e.get_one(_TBL, Type="code", Handle=handle)
    except Exception:
        return None
    if r is None:
        return None
    stored = _load_secret_hash(e, r.key)
    if not stored or not hmac.compare_digest(stored, _sha(secret)):
        return None
    j = dict(r.jor)
    if j.get("Used") or float(j.get("ExpiresAt", 0)) < _now():
        return None
    j["_key"] = r.key
    return j


def consume_code(cred: str, *, backend=None) -> bool:
    """Consume an authorization code — EXACTLY ONE winner across processes (single use). Under the lock:
    re-validate (secret hash + unexpired + unused), then flip Used. Two simultaneous exchanges of the
    same code therefore mint at most one access token (only the winner returns True; the loser gets
    False → the provider raises invalid_grant and never mints). Fail closed on lock unavailability.

    The token endpoint no longer calls this: consume and mint must share ONE critical section to be
    ordered against a user Disconnect, so the production path is :func:`exchange_code_for_token`
    (packet 1182). This stays as the standalone single-use primitive."""
    parts = _split_credential(_CODE_PREFIX, cred)
    e = _engine(backend)
    if parts is None or e is None:
        return False
    handle, secret = parts
    try:
        with oauth_critical_section():
            try:
                r = e.get_one(_TBL, Type="code", Handle=handle)
            except Exception:
                return False
            if r is None:
                return False
            stored = _load_secret_hash(e, r.key)
            if not stored or not hmac.compare_digest(stored, _sha(secret)):
                return False
            j = dict(r.jor)
            if j.get("Used") or float(j.get("ExpiresAt", 0)) < _now():
                return False
            j["Used"] = True
            e.update(_TBL, r.key, j)          # sole winner under the lock
            return True
    except OAuthLockUnavailable:
        log.warning("oauth_store: consume_code fail-closed (lock unavailable)")
        return False
    except Exception:
        log.debug("oauth_store: consume_code failed", exc_info=True)
        return False


# ── access tokens (hash-only; bounded; revocable; audience-bound) ─────────────

def _create_token_row(e, *, subject: str, client_id: str, resource: str, scopes,
                      family_id: str = "", not_after: Optional[float] = None) -> Optional[tuple[str, int]]:
    """Write one access-token record + its secret hash. No lock, no cleanup — the caller owns both, so
    this composes inside an existing critical section (the atomic exchange) as well as outside one.

    ``family_id`` binds the token to its refresh lineage, so revoking a family reaches every access token
    it ever minted. ``not_after`` CAPS the 8-hour lifetime to the family's remaining effective lifetime:
    a token minted near an inactivity or absolute boundary must not outlive the connection it belongs to.
    Returns None rather than a zero/negative-lifetime token."""
    cred, handle, secret = _mint_credential(ACCESS_TOKEN_PREFIX)
    expires_at = int(_now()) + ACCESS_TTL_SECONDS
    if not_after is not None:
        expires_at = min(expires_at, int(not_after))
    if expires_at <= int(_now()):
        return None
    key = str(_uuidlib.uuid4())
    e.create(_TBL, key, {
        "Type": "token", "Handle": handle, "Subject": subject, "ClientId": client_id,
        "Resource": resource, "Scopes": list(scopes or []), "FamilyId": family_id,
        "ExpiresAt": expires_at, "Revoked": False, "CreatedAt": _now(),
    })
    try:
        _save_secret_hash(e, key, _sha(secret))
    except Exception:
        try:
            e.delete(_TBL, key)
        except Exception:
            log.debug("oauth_store: token rollback delete failed for %s", key, exc_info=True)
        return None
    return cred, expires_at


def mint_token(*, subject: str, client_id: str, resource: str, scopes, backend=None) -> Optional[tuple[str, int]]:
    """Mint a bounded OAuth access token; return (token_string, expires_at_epoch) or None."""
    e = _engine(backend)
    if e is None:
        return None
    minted = _create_token_row(e, subject=subject, client_id=client_id, resource=resource, scopes=scopes)
    if minted is None:
        return None
    # A token mint is a RARE issuance event (not a per-request path), so run the bounded, oldest-first
    # sweep here — no process-local counter (which resets on every restart before it ever fires), no
    # per-request scan. Best-effort: its result never affects this mint (review §6).
    try:
        cleanup_expired(backend=backend)
    except Exception:
        log.debug("oauth_store: post-mint cleanup failed", exc_info=True)
    return minted


def exchange_code_for_token(cred: str, *, expected_client_id: str, expected_resource: str,
                            backend=None) -> Optional[tuple[str, int, dict, str]]:
    """Consume an authorization code AND mint its access token inside ONE critical section (packet 1182).

    This closes the consume→mint→disconnect race. Splitting the two steps left a window in which a
    Disconnect could run AFTER a winning consume and BEFORE the mint: it would revoke every token that
    existed, report success, and then the in-flight exchange would mint a SURVIVING token for a grant the
    user had just removed. Holding one section over consume + consent-recheck + mint makes the two
    operations strictly ordered against each other: an exchange that gets there first mints and is then
    revoked by Disconnect; an exchange that gets there after finds no consent row and mints nothing.

    The audience is the CODE's, never the caller's. ``expected_resource`` is checked for an EXACT match
    against the resource stored on the validated code row and the token is minted from the row's value —
    so an exchange cannot present a code consented for resource A and receive a token bound to resource
    B (which would survive a Disconnect of B, whose consent was never consulted). A mismatch refuses
    before the consume, leaving the code unused: a wrong-audience request changes nothing, and the
    legitimate exchange still works.

    Packet 1183 makes the SAME section create the connection's refresh family. In order: revoke any
    prior family and every access token for this exact (subject, client, resource) — so a new browser
    authorization can never leave an older family or an older token usable — then create ONE new family
    with its issued policy ceilings and an immutable absolute expiry, then its generation-0 refresh
    credential, then the access token. Nothing is returned until every durable row exists; a failure at
    any step rolls back to "no usable credential" and the user reauthorizes, which is the only safe
    failure — never a false success with an untracked credential.

    The whole live grant is re-read inside the section (review round 2): the owner must still resolve as
    an ACTIVE account, the consent row must still exist, and the code's scopes must still be covered by
    that row's CURRENT ceiling. Each of those is checked BEFORE the consume, so a deactivation, deletion
    or consent narrowing that lands after the provider's pre-lock check refuses without burning the code
    and without minting a family that carries the stale, wider ceiling.

    ``expected_client_id`` is the client the token request AUTHENTICATED as, and it completes that
    re-read (review round 3). The framework resolves the client and matches it against the code one step
    earlier, outside this lock, so client identity was the last part of the grant still decided by a
    pre-lock read: a DCR registration deleted or rewritten in that window would have been exchanged
    against anyway. Here the authenticated id must equal the freshly loaded code row's own ``ClientId``
    AND still resolve STRICTLY to a registered client record naming that same id — a mismatch, a missing
    registration or a read failure all refuse before the consume, minting nothing and burning nothing.

    Returns ``(token, expires_at, code_record, refresh_token)``, or None (NOTHING minted) when the code
    is invalid / already used / expired, when the requested
    audience is not the code's, when the authenticated client is not the code's or no longer resolves,
    when the owner is no longer active, when the user↔client↔resource consent grant no longer exists or
    no longer covers the code's scopes, or when the lock or store is unavailable (fail closed — the
    framework maps that to invalid_grant).
    """
    parts = _split_credential(_CODE_PREFIX, cred)
    e = _engine(backend)
    if parts is None or e is None:
        return None
    handle, secret = parts
    try:
        with oauth_critical_section():
            try:
                r = e.get_one(_TBL, Type="code", Handle=handle)
            except Exception:
                return None
            if r is None:
                return None
            stored = _load_secret_hash(e, r.key)
            if not stored or not hmac.compare_digest(stored, _sha(secret)):
                return None
            j = dict(r.jor)
            if j.get("Used") or float(j.get("ExpiresAt", 0)) < _now():
                return None
            subject = str(j.get("Subject") or "")
            client_id = str(j.get("ClientId") or "")
            code_resource = str(j.get("Resource") or "")
            if str(expected_client_id or "") != client_id:
                # Refused BEFORE the consume, like the audience check: a request authenticated as another
                # client was never entitled to this code and must not be able to burn it.
                log.warning("oauth_store: exchange refused — authenticated client is not the code's")
                return None
            try:
                registered = get_client_strict(client_id, backend=backend)
            except OAuthStoreUnavailable:
                # STRICT: an unreadable registration is not "unregistered", and neither answer may
                # consume the code.
                log.warning("oauth_store: exchange fail-closed (client registration unreadable)")
                return None
            if not registered or str(registered.get("client_id") or "") != client_id:
                log.warning("oauth_store: exchange refused — client registration no longer resolves")
                return None
            if str(expected_resource or "") != code_resource:
                # Refuse BEFORE the consume: this request was never entitled to the code, so burning it
                # would let a wrong-audience caller destroy a legitimate exchange.
                log.warning("oauth_store: exchange refused — requested audience is not the code's")
                return None
            # The LIVE grant decides, and every part of it is re-read HERE, inside the section — the
            # provider's own owner check ran one step earlier, OUTSIDE this lock, so a deactivation,
            # deletion or consent narrowing that lands in between would otherwise still mint a family
            # carrying the stale, broader ceiling (review round 2).
            if _owner_gates(subject, backend=backend) is None:
                # Missing, deleted, deactivated OR unreadable owner — one fail-closed answer for all
                # four, taken before the consume so an outage never burns a valid single-use code.
                log.warning("oauth_store: exchange fail-closed (owner is not active)")
                return None
            try:
                # The ONE policy read of this exchange, taken here for the same reason as the checks
                # above: BEFORE the consume and before the prior connection is revoked. Reading it later
                # (where packet 1189 first put it) meant an outage could land after this user's existing
                # family, refresh credentials and access tokens had already been retired — leaving them
                # with no connection at all and nothing to recover, which is worse than the loosening
                # the packet set out to prevent. Found by review.
                _pid, _cur_idle, _cur_absolute = _current_policy()
            except PolicyUnavailable:
                log.warning("oauth_store: exchange fail-closed (browser-connection policy unreadable)")
                return None
            policy = (_cur_idle, _cur_absolute)
            try:
                consent = _find_consent_row_strict(e, subject, client_id, code_resource)
            except Exception:
                # STRICT on purpose: a swallowed read would read as "the grant is gone" and burn this
                # user's valid single-use code during an outage. Nothing consumed, nothing minted.
                log.warning("oauth_store: exchange fail-closed (consent lookup failed)")
                return None
            if consent is None:
                return None                       # a Disconnect won the race: issue nothing, consume nothing
            scopes = list(j.get("Scopes") or [])
            if not set(scopes).issubset(set(consent.jor.get("Scopes") or [])):
                # The code's ceiling was recorded at approval; the consent row is the CURRENT one. A
                # narrowing between the two must not be out-voted by the older, wider copy.
                log.warning("oauth_store: exchange fail-closed (code scopes exceed the live consent ceiling)")
                return None
            j["Used"] = True
            e.update(_TBL, r.key, j)              # sole winner under the lock (single use preserved)
            try:
                _revoke_connection_credentials(e, subject, client_id, code_resource)
            except Exception:
                log.warning("oauth_store: exchange fail-closed (prior credentials not revocable)")
                return None                       # never add a second family beside one we cannot retire
            created = _create_family(e, subject=subject, client_id=client_id,
                                     resource=code_resource, scopes=scopes,
                                     policy_id=_pid, idle_seconds=_cur_idle,
                                     absolute_seconds=_cur_absolute)
            if created is None:
                return None
            family_id, refresh_cred, fam = created
            try:
                # The writer's own read-back: a family that cannot state its own lifetime must never
                # reach a client, and every later surface would refuse it anyway (review round 5).
                idle_expires, absolute_expires = _effective_family_bounds(fam, policy=policy)
            except _FamilyCorrupt:
                log.warning("oauth_store: exchange fail-closed (new family lifetime is not valid)")
                try:
                    _revoke_family(e, subject, family_id)
                except Exception:
                    log.debug("oauth_store: family rollback failed", exc_info=True)
                return None
            minted = _create_token_row(e, subject=subject, client_id=client_id,
                                       resource=code_resource, scopes=scopes,
                                       family_id=family_id,
                                       not_after=min(idle_expires, absolute_expires))
            if minted is None:
                try:
                    _revoke_family(e, subject, family_id)   # no access token → retire the new lineage
                except Exception:
                    log.debug("oauth_store: family rollback failed", exc_info=True)
                return None
            try:
                _cleanup_dead_rows(e, CLEANUP_PAGE)   # already inside the section — never re-acquire
            except Exception:
                log.debug("oauth_store: post-mint cleanup failed", exc_info=True)
            token, expires_at = minted
            j["_key"] = r.key
            return token, expires_at, j, refresh_cred
    except OAuthLockUnavailable:
        log.warning("oauth_store: exchange_code_for_token fail-closed (lock unavailable)")
        return None
    except Exception:
        log.debug("oauth_store: exchange_code_for_token failed", exc_info=True)
        return None


def load_token(cred: str, *, backend=None) -> Optional[dict]:
    """Validate + return an access-token record (unexpired, not revoked, correct secret), or None.
    Shape-dispatched: a credential without the OAuth prefix returns None WITHOUT touching the store.

    A token that names a refresh FAMILY is additionally validated against that family
    (:func:`_family_backing_valid`, review round 2). Its own ``Revoked``/``ExpiresAt`` fields are a
    best-effort per-token record; the family row is the connection's authoritative revocation barrier and
    its effective boundaries are the connection's lifetime. Reading only the token row let two real
    conditions through: a family revoked but whose descendant token write failed, and an access token
    minted before the administrator tightened the policy past this family's now-effective boundary."""
    parts = _split_credential(ACCESS_TOKEN_PREFIX, cred)
    if parts is None:
        return None
    e = _engine(backend)
    if e is None:
        return None
    handle, secret = parts
    try:
        r = e.get_one(_TBL, Type="token", Handle=handle)
    except Exception:
        return None
    if r is None:
        return None
    stored = _load_secret_hash(e, r.key)
    if not stored or not hmac.compare_digest(stored, _sha(secret)):
        return None
    j = dict(r.jor)
    if j.get("Revoked") or int(j.get("ExpiresAt", 0)) < int(_now()):
        return None
    if str(j.get("FamilyId") or "") and not _family_backing_valid(e, j):
        return None
    j["_key"] = r.key
    return j


def revoke_token(cred: str, *, backend=None) -> bool:
    """Revoke by the COMPLETE token credential. The secret half is verified against the stored hash
    before revoking — a correct handle with a WRONG secret is an inert no-op (returns False), so a
    leaked non-secret handle cannot revoke someone's token. Idempotent on an already-revoked token."""
    parts = _split_credential(ACCESS_TOKEN_PREFIX, cred)
    if parts is None:
        return False
    e = _engine(backend)
    if e is None:
        return False
    handle, secret = parts
    try:
        r = e.get_one(_TBL, Type="token", Handle=handle)
    except Exception:
        return False
    if r is None:
        return False
    stored = _load_secret_hash(e, r.key)
    if not stored or not hmac.compare_digest(stored, _sha(secret)):
        return False                          # wrong secret for a real handle → inert no-op
    body = dict(r.jor)
    body["Revoked"] = True
    try:
        e.update(_TBL, r.key, body)
        return True
    except Exception:
        return False


# ── refresh families (packet 1183) ────────────────────────────────────────────
# ONE browser connection carries ONE refresh FAMILY: a ``family`` row (the lineage — owner, client,
# resource, consented ceiling, the policy ceilings it was ISSUED under, and an absolute expiry that
# rotation never moves) plus one ``refresh`` row per GENERATION. Exactly one generation is `current`;
# using it marks it `spent` and creates its successor, so no credential is ever usable twice.
#
# Spent generations are KEPT — with their hash — until the family's absolute expiry. That is what makes a
# replay RECOGNIZABLE: delete the row and a stolen retired credential looks like an unrelated unknown
# token, and the theft is invisible. A verified replay outside the rotation-concurrency window is the
# compromise signal and revokes the whole family: every generation and every access token it minted.
#
# Revocation writes an expiry in the PAST onto the retired rows. The bounded cleanup sweep orders
# oldest-expiry-first, so a retired family is reached on the next sweep instead of sorting behind a year
# of live records — the same reason the access-token sweep is ordered that way.

FAMILY_ACTIVE = "active"
FAMILY_REVOKED = "revoked"
GEN_CURRENT = "current"
GEN_SPENT = "spent"
GEN_REVOKED = "revoked"

# rotate_refresh outcomes. Everything except OK is one invalid_grant on the wire — the distinction is for
# the server's own decisions and tests, never for the client (a caller learns nothing about WHY).
REFRESH_OK = "ok"
REFRESH_INVALID = "invalid_grant"          # unknown / wrong client / wrong audience / expired / a loser
REFRESH_REUSE_REVOKED = "reuse_revoked"    # verified replay past the window → the family is now revoked
REFRESH_FAILED = "failed"                  # lock or store failure — nothing was decided (fail closed)


class _FamilyCorrupt(ValueError):
    """A stored family row does not carry the lifetime schema it was written with — never interpreted."""


def _validate_family_lifetime(fam: dict) -> float:
    """Strictly validate ONE family row's issued lifetime schema; return its ``LastRotatedAt`` (review
    round 5).

    The family row IS the connection's lifetime, so a row that does not carry the schema
    :func:`_create_family` wrote has exactly one honest reading: it does not answer. Reading it
    permissively was a fail-OPEN in both directions the packet forbids — a missing or damaged
    ``AbsoluteExpiresAt``/``IdleSeconds`` degraded to the CURRENT administrator policy, so a
    Strict-issued family whose 30-day ceiling was lost inherited Standard's year, and a policy loosening
    became retroactive for exactly the rows least able to vouch for themselves.

    Required, with no coercion: ``IdleSeconds``, ``AbsoluteExpiresAt`` and ``AuthorizedAt`` as finite
    positive stored numbers with the absolute expiry FOLLOWING the authorization
    (:func:`oauth_policy.validate_issued_bounds`), plus ``LastRotatedAt`` as a finite stored number — the
    inactivity boundary is measured from it arithmetically. Anything else RAISES, and every caller fails
    closed."""
    from corpusfm.app.web.oauth_policy import IssuedBoundsInvalid, validate_issued_bounds
    try:
        validate_issued_bounds(
            fam.get("IdleSeconds"), fam.get("AbsoluteExpiresAt"), fam.get("AuthorizedAt"))
    except IssuedBoundsInvalid as exc:
        raise _FamilyCorrupt(f"refresh family lifetime: {exc}") from exc
    last = fam.get("LastRotatedAt")
    if isinstance(last, bool) or not isinstance(last, (int, float)):
        raise _FamilyCorrupt("refresh family lifetime: LastRotatedAt is not a stored number")
    last = float(last)
    if not math.isfinite(last):
        raise _FamilyCorrupt("refresh family lifetime: LastRotatedAt is not a valid issuance time")
    return last


def _effective_family_bounds(fam: dict, *, policy=None) -> tuple[float, float]:
    """``(idle_expires_at, absolute_expires_at)`` actually enforced for this family right now.

    Both come from the STRICTER of the family's issued ceilings and the CURRENT administrator policy, so
    tightening the policy shortens live connections immediately while loosening it never extends one
    granted under a tighter policy. The inactivity boundary is measured from this family's last
    successful issuance — its own protocol activity, not a user-facing "last used" telemetry field.

    RAISES :class:`_FamilyCorrupt` when the row's lifetime schema is not valid; every caller treats that
    as fail-closed, because the alternative is inheriting a ceiling the family was never granted."""
    from corpusfm.app.web.oauth_policy import IssuedBoundsInvalid, effective_bounds
    last = _validate_family_lifetime(fam)
    try:
        idle_seconds, absolute = effective_bounds(
            fam.get("IdleSeconds"), fam.get("AbsoluteExpiresAt"), fam.get("AuthorizedAt"),
            policy=policy)
    except IssuedBoundsInvalid as exc:                     # unreachable past the validation above
        raise _FamilyCorrupt(f"refresh family lifetime: {exc}") from exc
    return last + idle_seconds, absolute


def _family_lifetime_valid(fam: dict, *, policy=None) -> bool:
    """Whether this family's lifetime schema can back a decision at all. The quiet form of
    :func:`_effective_family_bounds` for the paths whose answer is simply "refuse this family".

    :class:`PolicyUnavailable` is deliberately NOT caught here and NOT folded into ``False``. This
    function answers a question about the ROW; an unreadable authority is a fact about the SERVER, and
    collapsing the two would let a transient outage be reported to a caller as "this connection is
    damaged" (packet 1189). It propagates to callers that state that difference."""
    try:
        _effective_family_bounds(fam, policy=policy)
        return True
    except _FamilyCorrupt:
        log.warning("oauth_store: refresh family refused (its stored lifetime schema is not valid)")
        return False


def reauthorization_due_at(fam: dict, *, policy=None) -> float:
    """When this connection next needs a browser sign-in: the EARLIER of its effective inactivity and
    absolute boundaries. The one lifetime fact the account view may show — it is derived from stored
    family state, not from invented device/last-used telemetry.

    RAISES :class:`_FamilyCorrupt` for a family that cannot state its own lifetime; callers reach it only
    after that family has already backed a decision, so a due date is never invented for a row the server
    would refuse."""
    idle_expires, absolute = _effective_family_bounds(fam, policy=policy)
    return min(idle_expires, absolute)


def _linkage_consistent(row: dict, fam: dict) -> bool:
    """Whether one refresh GENERATION and the family it names agree on every identity field (review
    round 1).

    Rotation mutates state on the strength of this join — it spends a row, creates a successor, bumps a
    family and mints a token — so a pair that contradicts itself is not something to interpret. A
    cross-linked or half-written row could otherwise be treated as a current generation of a family it does
    not belong to, which is how one connection's credential ends up rotating (or revoking) another's.
    Requiring EXACT equality means such a pair mints nothing and revokes nothing: the connection
    reauthorizes, the only safe reading of durable state that disagrees with itself."""
    fam_id = str(row.get("FamilyId") or "")
    if not fam_id or str(fam.get("Handle") or "") != fam_id:
        return False
    for field in ("Subject", "ClientId", "Resource"):
        if str(fam.get(field) or "") != str(row.get(field) or ""):
            return False
    return True


def _family_generation(fam: dict) -> int:
    """The family's GENERATION counter, strictly validated (review round 6).

    This is what every family decision compares the presented credential against, so a family that cannot
    state it exactly backs NOTHING: not an access token, not a credential load, not a rotation, and not an
    entry in the connection listing. RAISES :class:`_LineageCorrupt`; every caller fails closed."""
    return _stored_counter(fam.get("Generation"), "the family's Generation")


def _generation_counters(row: dict, fam: dict) -> tuple[int, int]:
    """``(generation, family_generation)`` for one presented refresh generation joined to the family it
    names — both counters validated (review round 6). RAISES :class:`_LineageCorrupt`."""
    return (_stored_counter(row.get("Generation"), "the generation's Generation"),
            _family_generation(fam))


def _validate_spent_at(row: dict) -> float:
    """WHEN one spent generation was consumed, validated against its own timeline (review round 6).

    The whole reuse decision rests on this timestamp, and the branch it falls into by DEFAULT is the
    destructive one: a missing, non-numeric, NaN or back-dated ``SpentAt`` coerced to ``0.0`` reads as
    "spent long ago" and revokes the entire connection — every generation and every access token — though
    nothing in the row establishes that the replay happened outside the 30-second concurrency window. So
    ``CreatedAt`` and ``SpentAt`` must both be finite stored numbers (no coercion, ``bool`` excluded) and
    the consumption may not PRECEDE the creation. Anything else RAISES and the caller refuses instead of
    revoking."""
    created = row.get("CreatedAt")
    if isinstance(created, bool) or not isinstance(created, (int, float)) or not math.isfinite(created):
        raise _LineageCorrupt("the spent generation cannot state when it was created")
    spent = row.get("SpentAt")
    if isinstance(spent, bool) or not isinstance(spent, (int, float)):
        raise _LineageCorrupt("the spent generation's SpentAt is not a stored number")
    spent = float(spent)
    if not math.isfinite(spent) or spent < float(created):
        raise _LineageCorrupt("the spent generation's SpentAt is not a valid consumption time")
    return spent


def _get_family_row(e, family_id: str):
    if not family_id:
        return None
    try:
        return e.get_one(_TBL, Type="family", Handle=family_id)
    except Exception:
        log.debug("oauth_store: family lookup failed", exc_info=True)
        return None


def _family_backing_valid(e, token: dict) -> bool:
    """Whether the refresh family an access token belongs to still authorizes it RIGHT NOW (review
    round 2).

    An access token is not an independent credential: it is one issuance of a connection, and the family
    row is that connection's FIRST durable revocation barrier. Revocation retires the family before it
    walks the descendants, so a partial revocation — the family retired, a token write injected-failed —
    must not leave a usable bearer token behind an already-severed connection. The same read applies the
    connection's CURRENT effective boundaries, so an administrator tightening the policy past a live
    family's inactivity/absolute limit takes effect on the tokens already in clients' hands rather than
    only on the next rotation.

    Fail-closed by construction: an unreadable family, a family that cannot state its own generation
    counter (review round 6), a family that contradicts the token on owner/client/audience, a non-active
    state, a family whose stored lifetime schema is not valid (review round 5), or a passed boundary all
    return False."""
    fam_row = _get_family_row(e, str(token.get("FamilyId") or ""))
    if fam_row is None:
        return False                       # absent OR unreadable — both refuse
    fam = dict(fam_row.jor)
    try:
        _family_generation(fam)
    except _LineageCorrupt:
        log.warning("oauth_store: token fail-closed (the family's stored counters are not valid)")
        return False
    if fam.get("State") != FAMILY_ACTIVE:
        return False
    if not _linkage_consistent(token, fam):
        return False
    try:
        idle_expires, absolute_expires = _effective_family_bounds(fam)
    except PolicyUnavailable:
        # Distinct from the corrupt case below: the ROW is fine, the server cannot state what is allowed
        # now. Accepting the token would enforce only the family's issued ceiling — exactly the
        # administrator tightening this refuses to drop. Nothing is revoked; recovery restores access.
        log.warning("oauth_store: token fail-closed (browser-connection policy unreadable)")
        return False
    except _FamilyCorrupt:
        log.warning("oauth_store: token fail-closed (the family's stored lifetime schema is not valid)")
        return False
    now = _now()
    return now < idle_expires and now < absolute_expires


def _create_refresh_row(e, *, family_id: str, subject: str, client_id: str, resource: str,
                        generation: int, absolute_expires_at: float) -> Optional[str]:
    """Write one refresh GENERATION + its secret hash; return the raw credential (the only time it
    exists). The row's indexed ``ExpiresAt`` is the family's ABSOLUTE expiry — the point past which a
    replay no longer needs to be recognizable — not the inactivity boundary."""
    cred, handle, secret = _mint_credential(REFRESH_TOKEN_PREFIX)
    key = str(_uuidlib.uuid4())
    e.create(_TBL, key, {
        "Type": "refresh", "Handle": handle, "Subject": subject, "ClientId": client_id,
        "Resource": resource, "FamilyId": family_id, "Generation": int(generation),
        "State": GEN_CURRENT, "ExpiresAt": float(absolute_expires_at),
        "CreatedAt": _now(), "SpentAt": None, "RevokedAt": None,
    })
    try:
        _save_secret_hash(e, key, _sha(secret))
    except Exception:
        try:
            e.delete(_TBL, key)
        except Exception:
            log.debug("oauth_store: refresh rollback delete failed for %s", key, exc_info=True)
        return None                        # no raw credential is returned before its hash is durable
    return cred


def _create_family(e, *, subject: str, client_id: str, resource: str, scopes,
                   policy_id: str, idle_seconds: int,
                   absolute_seconds: int) -> Optional[tuple[str, str, dict]]:
    """Create a NEW refresh family at its generation 0. Returns ``(family_id, refresh_credential,
    family_jor)`` or None (nothing usable created).

    The family row lands FIRST and the credential second: the durable lineage always exists before any
    secret that points at it, so a failure can leave an unreferenced family row (inert, swept) but never
    a usable credential the server does not know about.

    The POLICY is passed in rather than read here (packet 1189, review round 2). The caller must already
    have it, because the ceilings this stamps have to be known before the exchange consumes the code and
    revokes the prior connection — a policy read at this point could fail with the user's old credentials
    already gone."""
    now = _now()
    family_id = _FAMILY_PREFIX + secrets.token_hex(16)
    absolute_expires_at = now + absolute_seconds
    fam = {
        "Type": "family", "Handle": family_id, "Subject": subject, "ClientId": client_id,
        "Resource": resource, "ScopeCeiling": sorted(set(scopes or [])),
        "AuthorizedAt": now, "LastRotatedAt": now,
        "PolicyId": policy_id, "IdleSeconds": int(idle_seconds),
        "AbsoluteExpiresAt": absolute_expires_at, "Generation": 0,
        "State": FAMILY_ACTIVE, "RevokedAt": None,
        "ExpiresAt": absolute_expires_at, "CreatedAt": now,
    }
    key = str(_uuidlib.uuid4())
    try:
        e.create(_TBL, key, fam)
    except Exception:
        log.debug("oauth_store: family create failed", exc_info=True)
        return None
    cred = _create_refresh_row(e, family_id=family_id, subject=subject, client_id=client_id,
                               resource=resource, generation=0,
                               absolute_expires_at=absolute_expires_at)
    if cred is None:
        try:
            e.delete(_TBL, key)
        except Exception:
            log.debug("oauth_store: family rollback delete failed for %s", key, exc_info=True)
        return None
    return family_id, cred, fam


def _retire_row(e, row, body: dict, *, revoked_state_key: str) -> None:
    """Mark one lineage row revoked and back-date its indexed expiry so the bounded sweep reaches it."""
    body[revoked_state_key] = GEN_REVOKED
    body["RevokedAt"] = _now()
    body["ExpiresAt"] = _now() - 1
    e.update(_TBL, row.key, body)


# Revocation ORDER is load-bearing (review round 2). The family row is the FIRST durable barrier: it is
# retired before any descendant is touched, and :func:`_family_backing_valid` makes every access token in
# the lineage fail closed the moment it lands. The per-generation and per-token writes that follow are
# hygiene — they keep the rows self-describing and hand the sweep its back-dated expiry — so a failure
# part-way through can only leave MORE state marked dead than the barrier already enforces, never a live
# credential behind a severed connection.

def _retire_family_row(e, r, body: dict, counts: dict) -> None:
    if body.get("State") != FAMILY_REVOKED:
        _retire_row(e, r, body, revoked_state_key="State")
        counts["families"] += 1


def _retire_descendant(e, r, body: dict, counts: dict) -> None:
    t = body.get("Type")
    if t == "refresh" and body.get("State") != GEN_REVOKED:
        _retire_row(e, r, body, revoked_state_key="State")
        counts["generations"] += 1
    elif t == "token" and not body.get("Revoked"):
        body["Revoked"] = True
        e.update(_TBL, r.key, body)
        counts["tokens"] += 1


def _revoke_family(e, subject: str, family_id: str) -> dict:
    """Revoke ONE family completely: the lineage row FIRST, then every generation in it and every access
    token it minted. Caller holds the critical section. Raises on a write failure — a partial revocation
    must never be reported as a completed one, and the barrier ordering means an interrupted one still
    denies every credential of the connection."""
    counts = {"generations": 0, "tokens": 0, "families": 0}
    if not family_id:
        return counts
    rows = list(e.get_many(_TBL, "Subject", [subject]))
    for r in rows:
        body = dict(r.jor)
        if body.get("Type") == "family" and str(body.get("Handle") or "") == family_id:
            _retire_family_row(e, r, body, counts)
    for r in rows:
        body = dict(r.jor)
        if str(body.get("FamilyId") or "") == family_id:
            _retire_descendant(e, r, body, counts)
    return counts


def _revoke_connection_credentials(e, subject: str, client_id: str, resource: str) -> dict:
    """Revoke EVERY refresh family and EVERY access token for one exact (subject, client, resource)
    connection — families FIRST, then their descendants. Caller holds the critical section.

    A new completed browser authorization calls this before creating its family, so a connection never
    has two active families and never leaves an older access token usable — the exact hole packet 1179's
    live gate observed when one incomplete attempt plus a retry produced two valid access tokens. Other
    clients, other resources and other users are matched out and untouched."""
    counts = {"generations": 0, "tokens": 0, "families": 0}
    rows = [r for r in e.get_many(_TBL, "Subject", [subject])
            if str(r.jor.get("ClientId") or "") == client_id
            and str(r.jor.get("Resource") or "") == resource]
    for r in rows:
        body = dict(r.jor)
        if body.get("Type") == "family":
            _retire_family_row(e, r, body, counts)
    for r in rows:
        _retire_descendant(e, r, dict(r.jor), counts)
    return counts


def load_refresh_credential(cred: str, *, backend=None) -> Optional[dict]:
    """VERIFY a presented refresh credential and return its non-secret record joined to its family, or
    None. Does NOT decide anything and does NOT mutate: a spent or revoked generation still resolves
    here, because the rotation decision (including reuse detection) belongs in :func:`rotate_refresh`
    under the lock. Shape-dispatched — a credential without the refresh prefix returns None WITHOUT
    touching the store, so a manual dotted token or an access token never fans out through here.

    It still REFUSES what no decision could act on: an inconsistent generation/family pair, and a lineage
    whose stored counters or lifetime schema are not valid (review round 6).

    The returned dict carries the generation row under ``refresh`` and the lineage under ``family``; no
    secret, hash or raw credential is ever in it."""
    parts = _split_credential(REFRESH_TOKEN_PREFIX, cred)
    if parts is None:
        return None
    e = _engine(backend)
    if e is None:
        return None
    handle, secret = parts
    try:
        r = e.get_one(_TBL, Type="refresh", Handle=handle)
    except Exception:
        log.debug("oauth_store: refresh lookup failed", exc_info=True)
        return None
    if r is None:
        return None
    stored = _load_secret_hash(e, r.key)
    if not stored or not hmac.compare_digest(stored, _sha(secret)):
        return None                        # a real handle with a wrong secret is NOT a verified match
    fam_row = _get_family_row(e, str(r.jor.get("FamilyId") or ""))
    if fam_row is None:
        return None
    row, fam = dict(r.jor), dict(fam_row.jor)
    if not _linkage_consistent(row, fam):
        # Describing a credential from a family that contradicts it would hand the framework a client id,
        # ceiling and expiry drawn from two records that do not belong together.
        log.warning("oauth_store: refresh credential fail-closed (generation/family linkage inconsistent)")
        return None
    # The COUNTERS are part of that same identity (review round 6): both rows must state their generation
    # exactly. A coerced read of a damaged stamp is what let a retired family look current in the first
    # place, so an unreadable counter refuses rather than being made into a number.
    try:
        _generation_counters(row, fam)
    except _LineageCorrupt as exc:
        log.warning("oauth_store: refresh credential fail-closed (%s)", exc)
        return None
    try:
        # One policy read, and the DUE DATE it produces travels back with the record. The caller
        # describing this credential to the framework would otherwise call reauthorization_due_at()
        # and read the authority a second time for the same request — a second chance to fail, for a
        # number already computed here (found by review).
        due = reauthorization_due_at(fam)
    except _FamilyCorrupt:
        # A row that cannot state its own lifetime would be described with one borrowed from the
        # current policy — the exact non-retroactive loosening the packet forbids (review round 5).
        log.warning("oauth_store: refresh family refused (its stored lifetime schema is not valid)")
        return None
    except PolicyUnavailable:
        # A different fact from the branch above, and the same refusal: the row is fine, but the
        # ``expires_at`` handed to the framework would be bounded only by the family's ISSUED ceiling,
        # ignoring a tightening we cannot currently read (packet 1189). Nothing is revoked.
        log.warning("oauth_store: refresh credential fail-closed (browser-connection policy unreadable)")
        return None
    return {"refresh": row, "family": fam, "_key": r.key, "reauthorization_due_at": due}


def revoke_refresh_credential(cred: str, *, backend=None) -> bool:
    """Client-initiated revocation of a refresh credential (the RFC 7009 endpoint).

    Revoking a refresh credential revokes the WHOLE family — every generation and every access token it
    minted — because the credential IS the connection's authorization, not one disposable token. The
    COMPLETE credential is required: a correct handle with a wrong secret is an inert no-op, so a leaked
    non-secret handle can never revoke someone's connection. Returns False on any lock/store failure or
    an unverified credential."""
    parts = _split_credential(REFRESH_TOKEN_PREFIX, cred)
    if parts is None:
        return False
    e = _engine(backend)
    if e is None:
        return False
    handle, secret = parts
    try:
        with oauth_critical_section():
            try:
                r = e.get_one(_TBL, Type="refresh", Handle=handle)
            except Exception:
                return False
            if r is None:
                return False
            stored = _load_secret_hash(e, r.key)
            if not stored or not hmac.compare_digest(stored, _sha(secret)):
                return False
            _revoke_family(e, str(r.jor.get("Subject") or ""), str(r.jor.get("FamilyId") or ""))
            return True
    except OAuthLockUnavailable:
        log.warning("oauth_store: revoke_refresh_credential fail-closed (lock unavailable)")
        return False
    except Exception:
        log.debug("oauth_store: revoke_refresh_credential failed", exc_info=True)
        return False


def rotate_refresh(cred: str, *, expected_client_id: str, expected_resource: str,
                   requested_scopes=None, backend=None) -> tuple[str, Optional[dict]]:
    """Rotate a refresh credential inside ONE bounded critical section (packet 1183).

    Every successful refresh CONSUMES the presented credential and returns a distinct successor, so the
    old one can never be used successfully again. The whole decision — verify, re-check the live grant,
    enforce both boundaries, mark spent, create the successor, mint the access token — runs under the
    same authority as the code exchange and Disconnect, so those three are strictly ordered: a Disconnect
    that wins finds nothing left to rotate, and a rotation that wins is fully revoked by the Disconnect
    behind it.

    Nothing is mutated until the presented generation and the family it names agree EXACTLY on family id,
    owner, client and audience, and — for the row about to be spent — on the current generation number.
    That counter is read as the exact stored integer it was written as, never through ``int()`` (review
    round 6), and a spent generation must state a usable consumption time before the reuse branch can act
    on it. Durable state that contradicts itself is refused rather than interpreted (see
    :func:`_linkage_consistent`, :func:`_generation_counters`, :func:`_validate_spent_at`).

    Concurrency has exactly one winner. A loser presenting the same credential within
    ``REFRESH_ROTATION_WINDOW_SECONDS`` of it being spent gets ``REFRESH_INVALID`` — nothing minted, the
    winner's family untouched. A verified replay AFTER that window is treated as a compromised
    connection: the whole family and all of its access tokens are revoked
    (``REFRESH_REUSE_REVOKED``). An unknown, malformed, wrong-client or wrong-audience credential fails
    closed WITHOUT revoking anything — family-wide revocation requires a verified stored-hash match.

    Returns ``(status, payload)``; only ``REFRESH_OK`` carries a payload, and only that payload contains
    raw credentials (the single moment they exist)."""
    parts = _split_credential(REFRESH_TOKEN_PREFIX, cred)
    if parts is None:
        return REFRESH_INVALID, None
    e = _engine(backend)
    if e is None:
        return REFRESH_FAILED, None
    handle, secret = parts
    try:
        with oauth_critical_section():
            try:
                r = e.get_one(_TBL, Type="refresh", Handle=handle)
            except Exception:
                log.warning("oauth_store: refresh fail-closed (credential lookup failed)")
                return REFRESH_FAILED, None
            if r is None:
                return REFRESH_INVALID, None
            stored = _load_secret_hash(e, r.key)
            if not stored or not hmac.compare_digest(stored, _sha(secret)):
                return REFRESH_INVALID, None          # unverified → never a revocation trigger
            row = dict(r.jor)
            subject = str(row.get("Subject") or "")
            client_id = str(row.get("ClientId") or "")
            resource = str(row.get("Resource") or "")
            if client_id != str(expected_client_id or "") or resource != str(expected_resource or ""):
                return REFRESH_INVALID, None          # another client's / another audience's lineage
            fam_row = _get_family_row(e, str(row.get("FamilyId") or ""))
            if fam_row is None:
                return REFRESH_INVALID, None
            fam = dict(fam_row.jor)
            # IDENTITY before state: the generation and its family must agree on family id, owner, client
            # and audience exactly. An inconsistent pair is refused here — before the reuse branch — so a
            # cross-linked row can neither mint from, nor revoke, a family that is not its own.
            if not _linkage_consistent(row, fam):
                log.warning("oauth_store: refresh fail-closed (generation/family linkage inconsistent)")
                return REFRESH_INVALID, None
            # LIFETIME SCHEMA before state, for the same reason (review round 5). A family that cannot
            # state the ceilings it was issued under cannot bound anything this rotation would mint, and
            # substituting the current policy would hand a damaged row a longer life than it was granted.
            # Ahead of the reuse branch too: an uninterpretable family is refused, never revoked on the
            # strength of a lifetime nobody can read.
            try:
                # The ONE policy read of this rotation, taken BEFORE the spend and reused for every
                # bound computed below. Reading it again later (where packet 1189 first put it) meant an
                # outage could land after the presented credential was already spent and its successor
                # written but not returned — destroying a working connection over a transient read.
                # REFRESH_FAILED, not INVALID: nothing has been decided, and the credential must still
                # work when the authority returns. Found by review.
                _pid, _cur_idle, _cur_absolute = _current_policy()
            except PolicyUnavailable:
                log.warning("oauth_store: refresh fail-closed (browser-connection policy unreadable)")
                return REFRESH_FAILED, None
            policy = (_cur_idle, _cur_absolute)
            if not _family_lifetime_valid(fam, policy=policy):
                return REFRESH_INVALID, None
            if fam.get("State") != FAMILY_ACTIVE:
                return REFRESH_INVALID, None
            # COUNTER before state, for the same reason (review round 6). The generation number is the
            # monotonic counter this decision turns on, and it was read through ``int()``: a malformed
            # ``Generation`` of ``True``, ``1.5`` or ``"1"`` flattened into a number that could satisfy the
            # check authorizing a rotation. Both rows must now state it exactly. Ahead of the reuse branch:
            # a lineage that cannot place itself in time is refused, never revoked.
            try:
                row_gen, fam_gen = _generation_counters(row, fam)
            except _LineageCorrupt as exc:
                log.warning("oauth_store: refresh fail-closed (%s)", exc)
                return REFRESH_INVALID, None
            state = row.get("State")
            if state == GEN_REVOKED:
                return REFRESH_INVALID, None
            if state == GEN_SPENT:
                # The reuse decision — the one destructive branch in this module — may only be taken on a
                # timestamp that PROVES the replay fell outside the concurrency window. A missing,
                # non-numeric, NaN or back-dated ``SpentAt`` used to coerce to 0.0 and land here as "spent
                # long ago", revoking the whole connection on evidence that does not exist. A timeline that
                # cannot establish it refuses instead: nothing minted, nothing spent, nothing revoked. The
                # comparison is written as "outside the window" rather than its negation so that any value
                # which cannot answer — including a consumption stamped in the future — falls to refusal.
                try:
                    spent_at = _validate_spent_at(row)
                except _LineageCorrupt as exc:
                    log.warning("oauth_store: refresh fail-closed (%s — nothing revoked)", exc)
                    return REFRESH_INVALID, None
                if not (_now() - spent_at > REFRESH_ROTATION_WINDOW_SECONDS):
                    return REFRESH_INVALID, None      # a parallel request lost the race — not a theft
                log.warning("oauth_store: refresh reuse detected — revoking the family")
                try:
                    counts = _revoke_family(e, subject, str(row.get("FamilyId") or ""))
                except Exception:
                    log.warning("oauth_store: family revocation failed", exc_info=True)
                    return REFRESH_FAILED, None
                return REFRESH_REUSE_REVOKED, counts
            if state != GEN_CURRENT:
                return REFRESH_INVALID, None
            # A row MARKED current must also BE the family's current generation. They diverge only when a
            # rotation wrote its successor and then failed before the family caught up, which leaves an
            # orphan `current` row the client was never given. Rotating it would create a second usable
            # lineage inside one family; refusing it means the connection reauthorizes instead. (The spent
            # branch above is deliberately not held to this — a replayed generation is legitimately behind
            # its family, and recognizing it is what makes reuse detectable.) Both numbers were validated
            # above, so this is EXACT equality of two stored integers, not of whatever ``int()`` made of
            # them (review round 6).
            if row_gen != fam_gen:
                log.warning("oauth_store: refresh fail-closed (current generation out of step with family)")
                return REFRESH_INVALID, None

            # ── the live grant decides, re-read under the lock ──
            gates = _owner_gates(subject, backend=backend)
            if gates is None:
                return REFRESH_INVALID, None          # deactivated / deleted owner fails closed at once
            try:
                consent = _find_consent_row_strict(e, subject, client_id, resource)
            except Exception:
                log.warning("oauth_store: refresh fail-closed (consent lookup failed)")
                return REFRESH_FAILED, None
            if consent is None:
                return REFRESH_INVALID, None          # Disconnected / consent removed → reauthorize
            ceiling = set(fam.get("ScopeCeiling") or []) & set(consent.jor.get("Scopes") or [])
            wanted = set(requested_scopes) if requested_scopes else set(ceiling)
            if not wanted.issubset(ceiling):
                return REFRESH_INVALID, None          # refresh can never broaden the consented ceiling

            idle_expires, absolute_expires = _effective_family_bounds(fam, policy=policy)
            now = _now()
            if now >= idle_expires or now >= absolute_expires:
                return REFRESH_INVALID, None          # a boundary was reached → browser sign-in again

            # ── rotate: spend, succeed, then mint ──
            row["State"] = GEN_SPENT
            row["SpentAt"] = now
            e.update(_TBL, r.key, row)                # sole winner under the lock: no second current gen
            generation = fam_gen + 1                  # from the VALIDATED counter, never a coerced one
            successor = _create_refresh_row(
                e, family_id=str(fam.get("Handle") or ""), subject=subject, client_id=client_id,
                resource=resource, generation=generation,
                absolute_expires_at=float(fam.get("AbsoluteExpiresAt") or absolute_expires))
            if successor is None:
                log.warning("oauth_store: refresh successor could not be created — reauthorization required")
                return REFRESH_FAILED, None           # spent and not replaced: nothing usable survives
            fam["Generation"] = generation
            fam["LastRotatedAt"] = now                # advances the INACTIVITY boundary only
            e.update(_TBL, fam_row.key, fam)          # AbsoluteExpiresAt is deliberately untouched
            try:
                new_idle_expires, _abs = _effective_family_bounds(fam, policy=policy)
            except _FamilyCorrupt:
                # The advanced row must satisfy the same schema as the one that was read. It cannot
                # here — but the presented credential is already spent, so the honest outcome is a
                # failure with nothing returned, not a token bounded by a lifetime we cannot compute.
                log.warning("oauth_store: refresh fail-closed (advanced family lifetime is not valid)")
                return REFRESH_FAILED, None
            effective = sorted(wanted & set(gates))
            minted = _create_token_row(
                e, subject=subject, client_id=client_id, resource=resource, scopes=sorted(wanted),
                family_id=str(fam.get("Handle") or ""),
                not_after=min(new_idle_expires, absolute_expires))
            if minted is None:
                return REFRESH_FAILED, None
            try:
                _cleanup_dead_rows(e, CLEANUP_PAGE)   # already inside the section — never re-acquire
            except Exception:
                log.debug("oauth_store: post-rotation cleanup failed", exc_info=True)
            token, expires_at = minted
            return REFRESH_OK, {
                "access_token": token, "expires_at": expires_at, "refresh_token": successor,
                "subject": subject, "client_id": client_id, "resource": resource,
                "scopes": sorted(wanted), "effective_scopes": effective,
                "family_id": str(fam.get("Handle") or ""), "generation": generation,
                "reauthorization_due_at": min(new_idle_expires, absolute_expires),
            }
    except OAuthLockUnavailable:
        log.warning("oauth_store: rotate_refresh fail-closed (lock unavailable)")
        return REFRESH_FAILED, None
    except Exception:
        log.debug("oauth_store: rotate_refresh failed", exc_info=True)
        return REFRESH_FAILED, None


# ── consent grants (user ↔ client ↔ resource ↔ approved scope set) ────────────

def _find_consent_row_strict(e, subject: str, client_id: str, resource: str):
    """The engine (row) for this exact user↔client↔resource consent grant, or None — RAISING on a store
    read failure (packet 1182 review round 4).

    Every DECISION path uses this one. A swallowed read error here is indistinguishable from "the user
    has no consent", and each caller draws a materially wrong conclusion from that: a silent approval
    would report CONSENT_REQUIRED during an outage, an exchange would consume a valid single-use code
    while issuing nothing, and the consent upsert would CREATE a second row for a grant that already
    exists — breaking the one-row-per-(subject, client, resource) uniqueness contract the whole ceiling
    model rests on. "The store did not answer" must reach the caller so it can fail closed WITHOUT
    consuming or creating anything. Caller holds the lock when this backs a write."""
    for r in e.get_many(_TBL, "Subject", [subject]):
        j = r.jor
        if j.get("Type") == "consent" and j.get("ClientId") == client_id and j.get("Resource") == resource:
            return r
    return None


def _find_consent_row(e, subject: str, client_id: str, resource: str):
    """Fail-closed lookup for the PUBLIC READ path: None on a store failure. A read cannot consume or
    create anything, so degrading to "no consent" there costs at most an extra visible consent page."""
    try:
        return _find_consent_row_strict(e, subject, client_id, resource)
    except Exception:
        log.debug("oauth_store: consent lookup failed", exc_info=True)
        return None


def get_consent(subject: str, client_id: str, resource: str, *, backend=None) -> Optional[dict]:
    e = _engine(backend)
    if e is None or not subject or not client_id:
        return None
    r = _find_consent_row(e, subject, client_id, resource)
    return dict(r.jor) if r is not None else None


def _write_consent_row(e, row, subject: str, client_id: str, resource: str, scopes) -> None:
    """Write the grant over ``row`` (an existing consent row read under the lock) or create it when
    ``row`` is None. Split out so a caller that has ALREADY taken the strict read inside its own section
    reuses that answer instead of re-reading — one lookup, one decision, no second failure mode."""
    e_body = {"Type": "consent", "Subject": subject, "ClientId": client_id,
              "Resource": resource, "Scopes": sorted(set(scopes or [])), "GrantedAt": _now()}
    if row is not None:
        e.update(_TBL, row.key, e_body)
    else:
        e.create(_TBL, str(_uuidlib.uuid4()), e_body)


def _save_consent_row(e, subject: str, client_id: str, resource: str, scopes) -> None:
    """Upsert the consent grant. No lock of its own — every caller already holds the critical section,
    so this composes inside the atomic approval. The re-read is STRICT: a store failure raises rather
    than reporting "no row" and duplicating the grant, and the caller fails closed."""
    _write_consent_row(e, _find_consent_row_strict(e, subject, client_id, resource),
                       subject, client_id, resource, scopes)


def save_consent(subject: str, client_id: str, resource: str, scopes, *, backend=None) -> bool:
    """Upsert the consent grant, SERIALIZED cross-process (packet 1179 review §2). The lookup +
    update/create runs inside the same box-wide critical section as the single-use decisions, so two
    concurrent authorization transactions for the same user/client/resource can NEVER create duplicate
    consent rows (which would let ``get_consent`` return an arbitrary stale ceiling). Exactly one row per
    (subject, client, resource); concurrent grants converge on the intended ceiling. Fails closed
    (returns False, issues no authorization code) on any lock/store failure.

    The browser approval path does NOT call this: recording consent has to share one section with the
    transaction consume and the code mint to be ordered against a Disconnect, so that path is
    :func:`approve_authorization`. This stays as the standalone consent-upsert primitive."""
    e = _engine(backend)
    if e is None:
        return False
    try:
        with oauth_critical_section():
            _save_consent_row(e, subject, client_id, resource, scopes)
            return True
    except OAuthLockUnavailable:
        log.warning("oauth_store: save_consent fail-closed (lock unavailable)")
        return False
    except Exception:
        log.debug("oauth_store: save_consent failed", exc_info=True)
        return False


# ── atomic browser approval (packet 1182 review round 3) ──────────────────────
# Completing an approval is FOUR writes that must not be interleaved with a Disconnect: consume the
# transaction, decide against the LIVE grant, persist the consent, mint the code. Run as four separately
# locked calls they left a real hole — a Disconnect could land after the transaction was consumed, delete
# the consent, report success, and then the in-flight approval would RE-CREATE that consent and mint a
# code whose token survives the disconnect. One section over all four closes it.

APPROVE_OK = "approved"                    # consent recorded + code minted; payload carries the redirect
APPROVE_CONSENT_REQUIRED = "consent_required"   # silent path only: the grant is gone → ask the user
APPROVE_TXN_GONE = "txn_gone"              # expired / already used / not this user's transaction
APPROVE_FAILED = "failed"                  # store or lock failure — nothing was issued (fail closed)


def approve_authorization(txn_handle: str, *, subject: str, scopes, require_existing_consent: bool = False,
                          backend=None) -> tuple[str, Optional[dict]]:
    """Complete a browser authorization ATOMICALLY: consume the transaction, check the live grant, record
    the consent and mint the authorization code inside ONE critical section (packet 1182 review round 3).

    ``require_existing_consent`` is the SILENT re-approval path (the user is not shown a consent page
    because an unchanged grant already covers this request). That decision is made from a read taken
    outside the lock, so it is re-verified HERE, under the same authority a Disconnect runs under: if the
    consent row is gone — or no longer covers the requested grant — this returns
    ``APPROVE_CONSENT_REQUIRED`` and touches NOTHING. The transaction is deliberately left unconsumed so
    the caller can fall through to the visible consent page and the user can approve the reconnection
    explicitly. A silent approval can therefore never re-create a grant the user just disconnected.

    The visible path (``require_existing_consent=False``) legitimately creates the grant: the user is
    looking at the consent page and pressing Approve, which is exactly the "reconnection requires consent"
    contract.

    Returns ``(status, payload)``. On ``APPROVE_OK`` the payload carries ``code``, ``redirect_uri``,
    ``state``, ``client_id`` and ``resource`` — everything the redirect needs, read from the transaction
    under the lock rather than from a stale pre-lock copy. Every other status issues nothing.
    """
    e = _engine(backend)
    if e is None:
        return APPROVE_FAILED, None
    if not txn_handle or not subject:
        return APPROVE_TXN_GONE, None
    grant = sorted(set(scopes or []))
    try:
        with oauth_critical_section():
            r, j = _get_txn_row(e, txn_handle)      # re-validated live: unexpired AND unused
            if r is None:
                return APPROVE_TXN_GONE, None
            if str(j.get("Subject") or "") != subject:
                return APPROVE_TXN_GONE, None       # another user's transaction — never consumable here
            client_id = str(j.get("ClientId") or "")
            resource = str(j.get("Resource") or "")
            # ONE strict read serves both paths, and it happens BEFORE the transaction is consumed: a
            # store failure here must leave the transaction live and create nothing, not burn a
            # single-use transaction on an outage. It also feeds the upsert below, so the write cannot
            # duplicate the grant by re-reading through a second (possibly failing) lookup.
            try:
                consent = _find_consent_row_strict(e, subject, client_id, resource)
            except Exception:
                log.warning("oauth_store: approve fail-closed (consent lookup failed)")
                return APPROVE_FAILED, None
            if require_existing_consent:
                covered = consent is not None and set(grant).issubset(set(consent.jor.get("Scopes") or []))
                if not covered:
                    # A Disconnect (or a narrowed ceiling) won the race. Leave the transaction live and
                    # send the user to visible consent — do NOT silently rebuild the grant.
                    return APPROVE_CONSENT_REQUIRED, None
            j["Used"] = True
            e.update(_TBL, r.key, j)                # sole winner under the lock (single use preserved)
            _write_consent_row(e, consent, subject, client_id, resource, grant)
            code = _mint_code_row(
                e, client_id=client_id, subject=subject, scopes=grant,
                code_challenge=str(j.get("CodeChallenge") or ""),
                redirect_uri=str(j.get("RedirectUri") or ""),
                redirect_uri_provided_explicitly=bool(j.get("RedirectUriProvidedExplicitly")),
                resource=resource)
            if not code:
                return APPROVE_FAILED, None
            return APPROVE_OK, {"code": code, "redirect_uri": str(j.get("RedirectUri") or ""),
                                "state": j.get("State"), "client_id": client_id, "resource": resource}
    except OAuthLockUnavailable:
        log.warning("oauth_store: approve_authorization fail-closed (lock unavailable)")
        return APPROVE_FAILED, None
    except Exception:
        log.debug("oauth_store: approve_authorization failed", exc_info=True)
        return APPROVE_FAILED, None


# ── user-owned browser connections (packet 1182) ──────────────────────────────
# ONE browser connection = ONE consent grant (subject ↔ client ↔ resource). Access tokens, codes and
# transactions are protocol machinery UNDER that grant, never separate "sessions": a consent with five
# access-token rows is still one connection the user can disconnect.

_USER_OWNED_TYPES = ("txn", "code", "token", "consent", "refresh", "family")
_HASHED_TYPES = ("code", "token", "refresh")     # the Types whose SecretData container must go with them


def list_connections_for(subject: str, *, backend=None) -> Optional[list[dict]]:
    """This user's browser connections — one non-secret record per consent grant, newest-first.

    Returns ``None`` when the store is UNAVAILABLE and ``[]`` when the user genuinely has none, so the
    account surface never renders an outage as "no connections". Reads jor only: no ``SecretData``
    container is touched, and no other user's rows are visited (one indexed ``Subject`` query).

    ``reauthorization_due_at`` (packet 1183) is the one lifetime fact added: when this connection will
    need browser sign-in again, taken from its ACTIVE refresh family in the same single pass. It is
    ``0.0`` when there is no active family — a connection approved before refresh shipped, one whose
    family was revoked, or one whose family cannot state its own lifetime (review round 5) — never a
    guess."""
    e = _engine(backend)
    if e is None:
        return None
    if not subject:
        return []
    try:
        rows = e.get_many(_TBL, "Subject", [subject])
    except Exception:
        log.debug("oauth_store: list_connections_for failed", exc_info=True)
        return None
    try:
        # ONE policy read for the whole listing, taken before any family is examined. Reading it again
        # per row (as packet 1189 first did) left a race in which the authority could answer for the
        # validity check and then fail for the due date, raising out of a read-only listing that had
        # promised to degrade to a blank date. Found by review.
        _pid, _cur_idle, _cur_absolute = _current_policy()
        policy = (_cur_idle, _cur_absolute)
    except PolicyUnavailable:
        # No due date can be stated for ANY connection. Each is still listed — the grant exists and the
        # user should see it — with a blank date rather than one derived from the issued ceiling alone,
        # which would read LATER than the truth whenever a tightening is in force.
        log.warning("oauth_store: connections listed without due dates (policy unreadable)")
        policy = None
    # An explicit flag, NOT `policy is None`, decides whether dates are computable. Downstream,
    # ``policy=None`` means "read it yourself" — the safe default everywhere else in this module — so
    # reusing it as the unreadable sentinel would make a later edit that drops this guard silently
    # re-read the authority and raise out of a read-only listing.
    dates_computable = policy is not None
    families: dict[tuple[str, str], dict] = {}
    for r in rows:
        if not dates_computable:
            break                              # no due dates are computable; every row lists blank
        j = r.jor
        if j.get("Type") != "family" or j.get("State") != FAMILY_ACTIVE:
            continue
        try:
            _family_generation(dict(j))
        except _LineageCorrupt:
            # A family that cannot state its monotonic counter backs nothing — access validation and
            # rotation both refuse it — so it is not an active family to draw a due date from either
            # (review round 6). The connection is still listed, with no due date.
            continue
        if not _family_lifetime_valid(dict(j), policy=policy):
            # A family that cannot state its own lifetime backs nothing — access validation and
            # rotation both refuse it — so it is not an active family to list either (review round 5).
            # Reporting a due date computed from the current policy would advertise a connection that
            # does not work, at a date it was never granted. The connection still appears, with no due
            # date: the truthful "this needs browser sign-in again" answer.
            continue
        families[(str(j.get("ClientId") or ""), str(j.get("Resource") or ""))] = dict(j)
    out = []
    for r in rows:
        j = r.jor
        if j.get("Type") != "consent" or str(j.get("Subject") or "") != subject:
            continue
        try:
            granted = float(j.get("GrantedAt") or 0)
        except (TypeError, ValueError):
            granted = 0.0
        client_id = str(j.get("ClientId") or "")
        resource = str(j.get("Resource") or "")
        fam = families.get((client_id, resource))
        out.append({
            "connection_id": r.key,
            "client_id": client_id,
            "resource": resource,
            "scopes": [str(s) for s in (j.get("Scopes") or [])],
            "granted_at": granted,
            "reauthorization_due_at": (reauthorization_due_at(fam, policy=policy)
                                       if fam and dates_computable else 0.0),
        })
    out.sort(key=lambda c: c["granted_at"], reverse=True)
    return out


def disconnect(subject: str, connection_id: str, *, backend=None) -> Optional[dict]:
    """Disconnect ONE of this user's browser connections, atomically (packet 1182).

    Ownership is checked in the STORE — ``connection_id`` must name a ``consent`` row whose Subject is
    this caller; a forged or another user's id matches nothing. Inside one critical section (the same
    authority the code exchange runs under, so the two are strictly ordered): revoke every access token
    for that exact Subject/ClientId/Resource, invalidate any live code/transaction that could still
    issue for it, and only THEN remove the consent grant. That order is deliberate — if a step fails we
    raise, having only ever moved toward LESS access, never leaving live tokens behind a removed grant.

    Returns a non-secret result dict, ``None`` when nothing matched (unknown/foreign id, or an already
    disconnected connection — idempotent), and raises :class:`OAuthStoreUnavailable` when the mutation
    could not be completed (never a false success, never an unserialized partial disconnect). The global
    DCR ``client`` registration is NEVER touched: it may be shared with other users."""
    e = _engine(backend)
    if e is None:
        raise OAuthStoreUnavailable("the OAuth store is unavailable")
    if not subject or not connection_id:
        return None
    with oauth_critical_section():          # OAuthLockUnavailable propagates → honest failure
        try:
            rows = e.get_by_keys(_TBL, [connection_id])
        except Exception as exc:
            raise OAuthStoreUnavailable("could not read the connection") from exc
        row = rows[0] if rows else None
        if row is None:
            return None
        j = dict(row.jor)
        if j.get("Type") != "consent" or str(j.get("Subject") or "") != subject:
            return None                     # not a consent row, or not this user's — nothing changes
        client_id = str(j.get("ClientId") or "")
        resource = str(j.get("Resource") or "")
        try:
            owned = e.get_many(_TBL, "Subject", [subject])
        except Exception as exc:
            raise OAuthStoreUnavailable("could not read this connection's credentials") from exc
        revoked = invalidated = 0
        refresh_revoked = families_revoked = 0
        mine = [r for r in owned
                if str(r.jor.get("ClientId") or "") == client_id
                and str(r.jor.get("Resource") or "") == resource]   # another client/resource — untouched
        # Packet 1183: the refresh lineage is part of THIS connection, so it goes with it — the whole
        # family and every generation in it, current and spent alike. The FAMILY ROW GOES FIRST (review
        # round 2): it is the barrier every access token in the lineage is validated against, so the
        # connection is severed by the first write rather than by the last one. Everything here happens
        # before the consent row is removed, keeping the invariant that we only ever move toward LESS
        # access.
        try:
            for r in mine:
                body = dict(r.jor)
                if body.get("Type") == "family" and body.get("State") != FAMILY_REVOKED:
                    _retire_row(e, r, body, revoked_state_key="State")
                    families_revoked += 1
            for r in mine:
                body = dict(r.jor)
                t = body.get("Type")
                if t == "token" and not body.get("Revoked"):
                    body["Revoked"] = True
                    e.update(_TBL, r.key, body)
                    revoked += 1
                elif t in ("code", "txn") and not body.get("Used"):
                    body["Used"] = True
                    e.update(_TBL, r.key, body)
                    invalidated += 1
                elif t == "refresh" and body.get("State") != GEN_REVOKED:
                    _retire_row(e, r, body, revoked_state_key="State")
                    refresh_revoked += 1
        except Exception as exc:
            raise OAuthStoreUnavailable("could not revoke this connection's credentials") from exc
        try:
            e.delete(_TBL, row.key)         # the grant goes last: no live token outlives it
        except Exception as exc:
            raise OAuthStoreUnavailable("could not remove the connection") from exc
        return {"client_id": client_id, "resource": resource,
                "tokens_revoked": revoked, "grants_invalidated": invalidated,
                "refresh_revoked": refresh_revoked, "families_revoked": families_revoked}


def delete_all_for_subject(subject: str, *, backend=None) -> int:
    """Remove every OAuth record OWNED by this subject — txn, code, token and consent rows, and (packet
    1183) every refresh family with each generation in it, secret container included — when the user is
    deleted (packet 1182). Global DCR ``client`` registrations are never removed: a client is
    registration metadata that other users may also have authorized. Returns the number of rows removed;
    raises :class:`OAuthStoreUnavailable` if it could not complete, so the caller can log honestly. The
    user's credentials already fail closed the moment the USER row disappears (owner resolution fails) —
    this is hygiene, not the security boundary."""
    e = _engine(backend)
    if e is None:
        raise OAuthStoreUnavailable("the OAuth store is unavailable")
    if not subject:
        return 0
    with oauth_critical_section():
        try:
            rows = e.get_many(_TBL, "Subject", [subject])
        except Exception as exc:
            raise OAuthStoreUnavailable("could not read the user's OAuth records") from exc
        removed = 0
        failures = 0
        for r in rows:
            j = r.jor
            if j.get("Type") not in _USER_OWNED_TYPES or str(j.get("Subject") or "") != subject:
                continue
            try:
                if j.get("Type") in _HASHED_TYPES:
                    try:
                        e.blob_delete(_TBL, r.key, "SecretData")
                    except Exception:
                        pass
                e.delete(_TBL, r.key)
                removed += 1
            except Exception:
                failures += 1
                log.debug("oauth_store: subject cleanup delete failed for %s", r.key, exc_info=True)
        if failures:
            raise OAuthStoreUnavailable(f"{failures} OAuth record(s) could not be removed")
        return removed


# ── bounded record-lifecycle maintenance (packet 1179 review §6) ─────────────────
# Expired/consumed transactions + codes and expired/revoked access tokens must not accumulate forever.
# This sweep is DEMONSTRABLY CAPPED AND EFFECTIVE — it reads at most ``limit`` rows via ONE indexed page
# ordered OLDEST-EXPIRY-FIRST (filtered to the ephemeral Types on the ``Type`` slot; it never scans an
# unbounded table). The ordering is load-bearing: a dead record has an ExpiresAt in the PAST, so it sorts
# ahead of every newer active record and lands in the first bounded page — it is REACHED, not starved
# behind >200 live records (the failure the old arbitrary-first-page sweep had). It runs INSIDE the same
# cross-process critical section and NEVER touches clients or consent grants. Cleanup is maintenance, not
# authorization: best-effort, its failure authorizes nothing (callers ignore the result for auth
# decisions). Returns the number of records removed (0 on any lock/store failure).

CLEANUP_PAGE = 200                         # hard cap on rows examined per sweep — never unbounded
CLIENT_ABANDONED_SECONDS = 24 * 3600
_EPHEMERAL_TYPES = ("txn", "code", "token", "refresh", "family")
_CLIENT_RELATIONSHIP_TYPES = ("consent", "txn", "code", "token", "refresh", "family")


def _is_dead(j: dict) -> bool:
    t = j.get("Type")
    if t in ("txn", "code"):
        return bool(j.get("Used")) or float(j.get("ExpiresAt", 0)) < _now()
    if t == "token":
        return bool(j.get("Revoked")) or int(j.get("ExpiresAt", 0)) < int(_now())
    if t in ("refresh", "family"):
        # A SPENT generation is deliberately NOT dead: it stays recognizable until the family's absolute
        # expiry so a replay revokes the family instead of reading as an unrelated unknown token. Only
        # revocation (which back-dates ExpiresAt, putting the row at the front of this sweep) or the
        # absolute expiry itself retires one — and both put the row where this ordering reaches it.
        return (j.get("State") in (GEN_REVOKED, FAMILY_REVOKED)
                or float(j.get("ExpiresAt", 0)) < _now())
    return False                            # client / consent are NEVER swept here


def _reap(e, rows) -> int:
    """Delete the dead rows in one already-bounded page."""
    removed = 0
    for r in rows:
        j = r.jor
        if j.get("Type") not in _EPHEMERAL_TYPES:
            continue                       # defensive: never delete a client or consent record
        if not _is_dead(dict(j)):
            continue
        try:
            if j.get("Type") in _HASHED_TYPES:
                try:
                    e.blob_delete(_TBL, r.key, "SecretData")
                except Exception:
                    pass
            e.delete(_TBL, r.key)
            removed += 1
        except Exception:
            log.debug("oauth_store: cleanup delete failed for %s", r.key, exc_info=True)
    return removed


def _cleanup_dead_rows(e, cap: int) -> int:
    """The sweep body. The caller HOLDS the critical section (the lock is not reentrant across
    ``FileLock`` instances, so re-acquiring it here would deadlock the atomic exchange)."""
    try:
        rows, _ = e.page(_TBL, isin={"Type": list(_EPHEMERAL_TYPES)},
                         orderby="ExpiresAt", desc=False, per_page=cap, page=1)
    except Exception:
        log.debug("oauth_store: cleanup page failed", exc_info=True)
        return 0
    return _reap(e, rows)


def cleanup_expired(*, limit: int = CLEANUP_PAGE, backend=None) -> int:
    """Remove dead ephemeral records — consumed/expired txn+code rows, expired/revoked access tokens, and
    retired refresh generations + families — from ONE bounded indexed OLDEST-EXPIRY-FIRST page (up to
    ``limit`` rows). Every way a lineage row dies either back-dates its ``ExpiresAt`` or lets the absolute
    expiry pass, so a dead row always sorts into this page; the second rotating page existed only for rows
    a serving-epoch bump retired while their expiry stayed a year out, and that retirement route is gone
    (packet 1220). Bounded, serialized, fail-closed-to-zero. Clients + consent grants are excluded by
    construction."""
    e = _engine(backend)
    if e is None:
        return 0
    cap = max(1, min(int(limit or CLEANUP_PAGE), CLEANUP_PAGE))
    removed = 0
    try:
        with oauth_critical_section():
            removed = _cleanup_dead_rows(e, cap)
    except OAuthLockUnavailable:
        log.debug("oauth_store: cleanup skipped (lock unavailable)")
        return 0
    except Exception:
        log.debug("oauth_store: cleanup failed", exc_info=True)
        return 0
    return removed


def cleanup_abandoned_clients(*, limit: int = CLEANUP_PAGE, backend=None) -> dict:
    """Review one bounded oldest-first page of DCR clients and remove only proven abandonment.

    ``ExpiresAt`` is a next-review time, not protocol expiry. Any relationship row retains the client
    and moves it out of the oldest window. Any indeterminate read/write aborts visibly; absence is the
    sole deletion authority. Called only after an admitted DCR attempt, so hostile maintenance work is
    bounded by the same 30/hour admission ceiling.
    """
    e = _engine(backend)
    if e is None:
        return {"ok": False, "reviewed": 0, "removed": 0, "error": "OAuth store unavailable"}
    cap = max(1, min(int(limit or CLEANUP_PAGE), CLEANUP_PAGE))
    reviewed = removed = 0
    try:
        with oauth_critical_section():
            rows, _ = e.page(
                _TBL, eq={"Type": "client"}, orderby="ExpiresAt", desc=False,
                per_page=cap, page=1,
            )
            now = _now()
            for row in rows:
                body = dict(row.jor)
                due = float(body.get("ExpiresAt", 0) or 0)
                if due <= 0:
                    created = float(body.get("CreatedAt", 0) or 0)
                    due = (created if created > 0 else now) + CLIENT_ABANDONED_SECONDS
                    body["ExpiresAt"] = due
                    e.update(_TBL, row.key, body)
                if due > now:
                    continue
                reviewed += 1
                cid = str(body.get("ClientId") or body.get("Handle") or "")
                if not cid:
                    # Malformed legacy state is not proof of abandonment; move it out of the hot page.
                    body["ExpiresAt"] = now + CLIENT_ABANDONED_SECONDS
                    e.update(_TBL, row.key, body)
                    continue
                related, _ = e.page(
                    _TBL, eq={"ClientId": cid},
                    isin={"Type": list(_CLIENT_RELATIONSHIP_TYPES)},
                    per_page=1, page=1,
                )
                if related:
                    body["ExpiresAt"] = now + CLIENT_ABANDONED_SECONDS
                    e.update(_TBL, row.key, body)
                    continue
                e.delete(_TBL, row.key)
                removed += 1
        return {"ok": True, "reviewed": reviewed, "removed": removed, "error": ""}
    except Exception as exc:
        log.warning("oauth_store: abandoned-client cleanup failed", exc_info=True)
        return {"ok": False, "reviewed": reviewed, "removed": removed, "error": str(exc)}
