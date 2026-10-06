"""FM-side index-projection assertion — the startup sequence.

Index slots are derived **by FileMaker**, not the app. The app writes only ``JSONOfRecord``
(and ``UUID`` on create); the generic tables' auto-enter CF re-derives every indexed slot on
commit from a projection map the app keeps in the SETTING singleton's JSONOfRecord under the
``Calculations`` key, lowercasing text slots. On every startup CORPUSfm asserts that contract
(the ratified sequence):

    Read the SETTING JSONOfRecord.
      • No record / empty        → write the FULL default template (default settings + the map),
                                    then run the file-wide refresh script (waited on).
      • Record exists            → SETTINGS values may differ (never overwritten); the index
                                    projection map is rewritten on any drift, but the file-wide SWEEP
                                    is gated on the projection VERSION, not the map diff (packet 1060).
          - Calculations differ  → update ONLY the Calculations key (no sweep — additive projections
                                    are free; new records self-project via the auto-enter CF).
          - ProjectionVersion differs (bumped, or not yet stored) → run any conversion this
                                    transition owes, then the refresh script, then stamp the new
                                    version. This is the deliberate "existing data needs conversion"
                                    signal, and since packet 1372-01 it carries an actual conversion:
                                    1 → 2 re-keys every JOB record so its native key, its
                                    ``JobConfig.id`` and the ``UUIDJob`` its artifacts/history/queue
                                    rows carry are one value. The stamp follows BOTH, and is read
                                    back strictly.
          - Neither differs      → nothing to do.

"Run the refresh script" = the FM script ``CFM.SRV.RefreshIndexProjections`` (one OData call,
work stays inside FileMaker; it can lag, so the call BLOCKS until it finishes). If the script is
unavailable it falls back to the OData per-record touch. ``fm_registry.PROJECTION_VERSION`` (an int
the agent bumps) drives the sweep; the map-diff write is the free safety net (a real structural
change still rewrites the map even if a bump is missed — the marker lags, new-record data is never
wrong). The version is stamped only AFTER a successful sweep. Distinct from physical-schema ``Build``.

**The stamp is now a GATE, not just a marker.** Web startup asserts this synchronously before it
starts the QUEUE workers, and the separate scheduler process reads the stored value and fires nothing
while it is absent, behind, malformed or unreadable. Use :func:`conversion_complete` for that
question — never a bare settings read, which cannot tell an outage from an unstamped corpus.

LocalBackend has no slots / no refresh script → ``supported`` is False → every helper is a no-op.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Set True once a startup pass has confirmed the map is asserted, so the catalog can trust
# server-side slot queries. Process-level (single-worker): the boot daemon sets it; request
# threads read it. False until then → callers fall back to the scan (safe).
_asserted_ok = False

# Methods an FM-side-projection-capable backend must expose (only the FM OData backend has them).
_REQUIRED = ("load_fm_settings", "save_fm_settings", "refresh_index_projections")


def supported(backend) -> bool:
    """True when the backend derives indexed slots FM-side (the FM OData backend)."""
    return backend is not None and all(hasattr(backend, m) for m in _REQUIRED)


def ready(backend) -> bool:
    """True ONLY when a startup pass positively confirmed the projection map is asserted — so a
    server-side slot query won't miss rows projected under an older map. False on unsupported
    backends or before the boot assertion completes → the caller uses the scan."""
    return supported(backend) and _asserted_ok


def pending(backend) -> bool:
    """True when the map hasn't yet been confirmed asserted this process. False on unsupported
    backends (fail-open: never block the catalog)."""
    return supported(backend) and not _asserted_ok


# ── The stored version, read strictly (packet 1372-01) ────────────────────────────
# `ProjectionVersion` stopped being only a sweep marker when packet 1372 attached the JOB identity
# conversion to the 1→2 transition. Two processes now branch on it — the web service, which converts
# and stamps, and the scheduler, which must not fire a job until the stamp is there — so it needs a
# reader that cannot confuse "not yet converted" with "I could not tell".
#
# EVERY UNCERTAIN ANSWER IS `None`, and every caller treats `None` as NOT converted. That is the
# opposite of `is_pending`'s deliberate fail-OPEN, and the difference is the consequence: failing
# open there risks bricking a working box, whereas failing open here would run UUID-only job code
# over a JOB table that may still be keyed the old way.

def stored_projection_version(backend):
    """The corpus's applied projection version, or None when it cannot be trusted.

    None covers all four of the states the packet names: absent (never stamped), malformed (a
    non-integer someone hand-edited), unreadable (the SETTING read failed), and — via the caller's
    comparison — behind. `strict=True` is what separates a genuinely empty SETTING from an outage;
    without it an unreachable OData answers `{}` and reads as "version absent", which is a different
    fact with the same shape.
    """
    if not supported(backend):
        return None
    try:
        stored = backend.load_fm_settings(strict=True)
    except Exception:
        logger.debug("projections: strict ProjectionVersion read failed", exc_info=True)
        return None
    value = (stored or {}).get("ProjectionVersion")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def conversion_complete(backend) -> bool:
    """True when this corpus may run ordinary JOB work.

    An UNSUPPORTED backend is True **unless this installation is published with a composed corpus**.
    The dev/test LocalBackend path has no SETTING singleton, no projection map and no conversion to
    perform, and gating it would stop every developer's Queue worker for a corpus that does not
    exist. But an installation that OWNS a corpus and handed us a backend that cannot even be asked
    the version question is a contradiction, not the dev path, and it answers False — the same
    reasoning `jobs/store.py::_repo()` applies to refusing to serve Jobs from local files beside an
    unused corpus.

    **`fm_storage_active()`, not `is_server_mode()`.** The first draft asked the mode, which is
    wrong twice over: it is a process-global that a single `os.environ` write at import time makes
    true for everything after it (measured — eight unrelated tests went red), and more importantly
    the mode says what KIND of install this is, while the question here is whether a corpus exists to
    read. `fm_storage_active()` is the published-manifest authority for exactly that, and it is
    tri-state, so "nothing is published" stays distinguishable from "published with no corpus".

    **The unpublished-tree variant is deliberately NOT gated.** A corrupt `install.yaml` fails closed
    to `"server"` for the mode while `read_install_config()` returns `{}` and sends `get_backend()`
    down its LocalBackend branch — but a published installation raises rather than degrading, so that
    pair is reachable only on a development tree, where refusing would break the local path this
    branch exists to serve.

    On the FM backend it is strictly the stamped version equalling the one this build requires —
    never "at least", because a corpus ahead of this build is not something this build has any
    business serving either.
    """
    if not supported(backend):
        from corpusfm.lifecycle import runtime_storage
        try:
            return not runtime_storage.fm_storage_active()
        except Exception:
            logger.debug("projections: could not read the published storage authority", exc_info=True)
            return False        # published-but-unreadable is never "nothing to convert"
    from corpusfm.storage import fm_registry as reg
    return stored_projection_version(backend) == reg.PROJECTION_VERSION


def _default_template() -> dict:
    """The full default SETTING JSONOfRecord: default team settings + the projection map."""
    from corpusfm.app.app_config import AppConfig, settings_to_fm_dict
    from corpusfm.storage import fm_registry as reg
    return {**settings_to_fm_dict(AppConfig()), **reg.generate_setting_calculations()}


def _refresh(backend) -> str:
    """Run the file-wide FM refresh script and WAIT; fall back to the OData per-record touch.
    Returns 'script', 'reproject:<n>', or '' on total failure."""
    try:
        if backend.refresh_index_projections():   # blocks until the FM script completes
            return "script"
    except Exception:
        logger.debug("projections: refresh script raised", exc_info=True)
    if hasattr(backend, "reproject_all_records"):
        try:
            return f"reproject:{backend.reproject_all_records()}"
        except Exception:
            # Total OR partial failure — reproject_all_records raises when any row/table failed
            # transiently (packet 1000 P2). Either way the sweep is INCOMPLETE, so return '' and let
            # assert_projection decline to stamp the version (retry next boot) rather than mark stale
            # rows as converted.
            logger.warning("projections: OData reproject fallback did not fully complete — the "
                           "projection version will NOT be advanced; retrying next startup", exc_info=True)
    return ""


# ── The universal no-secret-in-jor rule (packet 1007) ─────────────────────────────
# Every secret is a CONTAINER blob — never a JSONOfRecord key in ANY table. This is the table-wide
# generalization of the old SETTING-only fence: the app writes only NON-secret metadata to jor
# (indexed slots + display fields); reversible secrets and one-way hashes live in Corpus-Key-encrypted
# containers (JOB.CredentialData, USER.SecretData, SETTING.AiKeys). A key appearing here in a
# record's jor is a bug — the guard test (tests/test_secret_fence.py) fails the build, and the runtime
# SETTING strip below is defense-in-depth against a hand-copied old config.
SECRET_JOR_KEYS = frozenset({
    "password", "password_hash", "salt",
    "mcp_token_hash", "token_secret_hash", "token_secret",
    "private_key_enc", "private_pem",
    "account", "credential", "fm_password",
    "CORPUSFM_AI_API_KEY", "ai_summary_api_key", "api_key",
    "token_enc", "ssh_key_enc",   # git-export credential secrets (packet 1009/S1-B/C) → SecretData container
    "client_secret", "oidc_client_secret",  # external-auth secrets (packet 1065) → SETTING.OidcSecret container
    "ldap_bind_password", "bind_password",
})


def jor_secret_keys(jor: dict) -> list:
    """Any SECRET_JOR_KEYS present in a record body — [] when clean. The one predicate the fence uses.

    Recurses into nested dicts/lists so a secret buried under a config sub-dict (e.g. a future
    `external_auth.oidc.client_secret`) can't evade the top-level scan (packet 1000 P1 defense-in-depth;
    today no code nests one — secrets ride the Corpus Key containers)."""
    found: list = []

    def _walk(obj) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in SECRET_JOR_KEYS:
                    found.append(k)
                _walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                _walk(v)

    _walk(jor or {})
    return found


def strip_secret_keys(value):
    """A copy of ``value`` with every :data:`SECRET_JOR_KEYS` key removed at EVERY dictionary depth.

    **The counterpart of** :func:`jor_secret_keys`, and it exists because the two had drifted apart
    (packet 1361-01, round 5). The detector recurses into nested dicts and into dicts inside
    lists/tuples; the cleanup was a single top-level comprehension. So a secret buried one level
    down — ``{"config": {"client_secret": "…"}}`` — was DETECTED, written back unchanged, and then
    reported as removed. That is the worst of the three possible outcomes: the credential survives
    and the fence says it is gone.

    One transformation, used by every cleanup path, so the pair cannot drift again. Everything that
    is not a forbidden KEY is preserved exactly: neighbouring keys, their values, their order,
    nesting depth, and list/tuple container types. Scalars are returned unchanged.
    """
    if isinstance(value, dict):
        return {k: strip_secret_keys(v) for k, v in value.items() if k not in SECRET_JOR_KEYS}
    if isinstance(value, list):
        return [strip_secret_keys(v) for v in value]
    if isinstance(value, tuple):
        return tuple(strip_secret_keys(v) for v in value)
    return value


def _as_document(raw):
    """The write response's ``JSONOfRecord`` as a dict, or ``None`` when it is not usable.

    A confirmed write returns the committed record, and that body is the cheapest authoritative
    answer to "is the secret gone". It is only usable when it is actually there and actually parses
    into an object; anything else — no response record, a non-JSON body, a JSON scalar or array —
    is UNUSABLE, and the caller rereads rather than assuming.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (str, bytes, bytearray)):
        import json as _json
        try:
            doc = _json.loads(raw)
        except Exception:                                           # noqa: BLE001
            return None
        return doc if isinstance(doc, dict) else None
    return None


def _authoritative_after_write(eng, logical: str, key: str, written):
    """The record as the substrate now holds it, or ``None`` when that could not be established.

    Two sources, in order: the full record the write RETURNED, and — when that is missing or
    unusable — one STRICT keyed reread. ``None`` means inconclusive, which the fence treats as a
    write failure rather than as success: a strip nobody could confirm has not been confirmed.

    **A FOUND RECORD IS NOT AUTOMATICALLY A USABLE ONE** (packet 1361-01, round 6). This returned
    ``row.jor if isinstance(row.jor, dict) else {}``, so a reread that located the record but came
    back with a ``None``, a scalar, a list or an unparseable body was converted into an EMPTY
    OBJECT — and an empty object contains no forbidden key, so the fence read it as proof the secret
    was gone. That is the same false-success shape round 5 removed from the transformation, one
    layer along: the least trustworthy input producing the most reassuring answer.

    A reread verifies a cleanup only when it yields a usable JSON **object**. ``row.jor`` is tried
    first because it is the parsed authoritative body; a row that also exposes the raw JSON is
    allowed as a second source, and malformed or non-object raw stays inconclusive. Everything else
    — absent, scalar, array, unparseable — answers ``None``.

    A usable EMPTY object is a real and successful answer, and it is distinct from every case above:
    the record genuinely holds ``{}``, which is a document the substrate returned rather than one
    this function invented.
    """
    doc = _as_document(getattr(written, "raw", None) if written is not None else None)
    if doc is not None:
        return doc
    rows = eng.get_by_keys(logical, [key])
    for row in rows or ():
        if row.key != key:
            continue
        doc = _as_document(row.jor)
        if doc is not None:
            return doc
        # The parsed body was unusable. A row that carries the substrate's own raw JSON gets one
        # more chance, on the same terms — an object, or nothing.
        return _as_document(getattr(row, "raw", None))
    return None


def assert_no_setting_secrets(backend) -> dict:
    """Runtime arm of the universal no-secret-in-jor fence (packet 1007, generalizing packet 085 §8).

    Secrets never belong in any table's jor — they ride Corpus-Key-encrypted containers. Fresh installs
    never write one, so this is a defense-in-depth strip against a hand-copied old config (not a
    migration). Checks the SETTING singleton (via its dedicated strip method) AND scans the USER,
    GITREG, SERVER and MCPTOKEN tables (few rows) for stray secret keys.

    Returns ``{"ok", "removed", "read_failed", "write_failed", "reason"}``. It still never raises —
    but it no longer SWALLOWS (packet 1361-01, round 4). It used to answer ``ok: True`` whatever
    happened, so a fence that could not read SETTING and a fence that could not strip a secret it had
    found both reported success. Neither is a fence: the first asserted nothing, and the second left
    a secret in a record's jor while telling the caller it was gone. Both are database failures and
    the startup authority stops the attempt on either.

    **Every cleanup write is VERIFIED against the authoritative record** (round 5) — from the record
    the write returned when that is usable, and from a strict keyed reread when it is not. A write
    the substrate accepted is not a secret that is gone, and the fence's whole value is the claim
    that it IS gone. An unusable response followed by a failed or inconclusive reread is a
    ``write_failed``; so is a record that still carries the key. Startup stays paused on either.

    A backend that exposes neither the SETTING strip methods nor an engine has nothing to check; that
    is a structural local fact and stays a clean ``ok: True``.

    **One deliberate non-goal, stated so it is not rediscovered as a finding.** The SETTING path
    detects the narrower :data:`~corpusfm.app.app_config.SETTING_SECRET_KEYS` at the TOP LEVEL only,
    matching exactly what ``remove_fm_settings_keys`` is able to drop. Detection and cleanup agree
    there, so that path makes no false removal claim — which is the defect round 5 exists to fix, and
    it is a defect the SETTING path never had. Broadening its detection to the recursive walk would
    find a nested key the backend's strip method cannot remove, and the honest outcome would then be
    a permanent ``write_failed``. The OIDC client secret and the LDAP bind password live in the
    Corpus-Key-encrypted ``SETTING.OidcSecret`` container, not in this record, so no shipped path
    nests one. Widening it is a change to ``remove_fm_settings_keys`` first, and a decision for the
    developer.
    """
    from corpusfm.app.app_config import SETTING_SECRET_KEYS
    out = {"ok": False, "removed": [], "read_failed": False, "write_failed": False,
           "verified_present": False, "reason": ""}
    removed_all: list = out["removed"]
    # SETTING singleton strip — FM-backend only (its dedicated method); skipped on the dev mirror.
    if hasattr(backend, "remove_fm_settings_keys") and hasattr(backend, "load_fm_settings"):
        try:
            stored = backend.load_fm_settings()
        except Exception as exc:                                    # noqa: BLE001
            out["read_failed"] = True
            out["reason"] = f"SETTING could not be read: {type(exc).__name__}: {exc}"
            logger.warning("projections: the SETTING secret fence could not READ; nothing was "
                           "asserted", exc_info=True)
            return out
        present = [k for k in SETTING_SECRET_KEYS if k in (stored or {})]
        if present:
            logger.warning("projections: legacy secret keys in SETTING, stripping: %s", present)
            try:
                backend.remove_fm_settings_keys(present)
            except Exception as exc:                                # noqa: BLE001
                out["write_failed"] = True
                out["reason"] = (f"a legacy secret was found in SETTING and could NOT be stripped: "
                                 f"{type(exc).__name__}: {exc}")
                logger.error("projections: a legacy secret in SETTING could not be stripped; it is "
                             "STILL THERE", exc_info=True)
                return out
            # VERIFY FROM THE AUTHORITATIVE RECORD, never from the call returning (round 5).
            # `remove_fm_settings_keys` answers a list of key NAMES, not a record — and it is
            # documented "best-effort: never raises", so it returns an empty list for a missing
            # record and for an absent `@editLink` just as it does for a clean one. The old code
            # then credited `present` anyway (`… or present`) and reported a removal nobody
            # performed. There is no usable returned record here, so this is always the strict
            # keyed reread; `strict=True` is what separates a genuinely empty SETTING from an
            # outage that answers `{}`.
            try:
                after = backend.load_fm_settings(strict=True)
            except Exception as exc:                                # noqa: BLE001
                out["write_failed"] = True
                out["reason"] = ("the SETTING secret strip could not be verified — the record could "
                                 f"not be reread: {type(exc).__name__}: {exc}")
                logger.error("projections: the SETTING secret strip is UNCONFIRMED; treating it as "
                             "not performed", exc_info=True)
                return out
            still = [k for k in SETTING_SECRET_KEYS if k in (after or {})]
            if still:
                out["write_failed"] = True
                # VERIFIED PRESENT (round 7): the strip completed and a STRICT reread — a read that
                # SUCCEEDED — shows the key is still there. That is a decided fact about the record,
                # not a database that went away, so it is deterministic and repeating cannot change
                # it. Contrast the two branches above, where the strip raised or could not be
                # reread: those are outages and stay transient.
                out["verified_present"] = True
                out["reason"] = (f"the SETTING record still holds {still} after the strip; the "
                                 "secret is STILL THERE")
                logger.error("projections: %s", out["reason"])
                return out
            # Credit only what the authoritative record proves is gone.
            removed_all += [k for k in present if k not in (after or {})]
    # USER + GITREG + SERVER + MCPTOKEN scans (bounded — accounts + credentials are few): a secret key
    # in a row's jor is a bug; strip it. Every one of these tables keeps its real secrets in
    # Corpus-Key-encrypted containers.
    eng = getattr(backend, "engine", None)
    if eng is not None:
        for logical in ("USER", "GITREG", "SERVER", "MCPTOKEN"):
            try:
                rows = list(eng.list_all(logical))
            except Exception as exc:                                # noqa: BLE001
                out["read_failed"] = True
                out["reason"] = f"{logical} could not be read: {type(exc).__name__}: {exc}"
                logger.warning("projections: the %s secret fence could not READ; nothing was "
                               "asserted", logical, exc_info=True)
                return out
            for r in rows:
                bad = jor_secret_keys(r.jor)
                if not bad:
                    continue
                logger.warning("projections: secret keys in %s jor %s, stripping: %s",
                               logical, r.key, bad)
                # RECURSIVE, matching the detector (round 5). This was
                # `{k: v for k, v in r.jor.items() if k not in SECRET_JOR_KEYS}` — top level only —
                # so a nested secret was found, written back untouched, and counted as removed.
                cleaned = strip_secret_keys(r.jor)
                try:
                    written = eng.update(logical, r.key, cleaned)
                except Exception as exc:                            # noqa: BLE001
                    out["write_failed"] = True
                    out["reason"] = (f"a secret in {logical}/{r.key} could NOT be stripped: "
                                     f"{type(exc).__name__}: {exc}")
                    logger.error("projections: a secret in %s/%s could not be stripped; it is "
                                 "STILL THERE", logical, r.key, exc_info=True)
                    return out
                # VERIFY, from the record the write RETURNED when it is usable and from a strict
                # keyed reread when it is not. A write that was accepted is not a secret that is
                # gone: the substrate may have committed a different document, an intermediary may
                # have dropped the body, and the strip itself may have missed something.
                try:
                    after = _authoritative_after_write(eng, logical, r.key, written)
                except Exception as exc:                            # noqa: BLE001
                    out["write_failed"] = True
                    out["reason"] = (f"the strip of {logical}/{r.key} could not be verified — the "
                                     f"record could not be reread: {type(exc).__name__}: {exc}")
                    logger.error("projections: the %s/%s secret strip is UNCONFIRMED; treating it "
                                 "as not performed", logical, r.key, exc_info=True)
                    return out
                if after is None:
                    out["write_failed"] = True
                    out["reason"] = (f"the strip of {logical}/{r.key} returned no usable record and "
                                     "a strict reread did not find it; the result is unconfirmed")
                    logger.error("projections: %s", out["reason"])
                    return out
                remaining = jor_secret_keys(after)
                if remaining:
                    out["write_failed"] = True
                    out["verified_present"] = True          # see the SETTING branch above
                    out["reason"] = (f"{logical}/{r.key} still holds {sorted(set(remaining))} after "
                                     "the strip; the secret is STILL THERE")
                    logger.error("projections: %s", out["reason"])
                    return out
                removed_all += bad
    out["ok"] = True
    return out


def assert_conversion_complete(backend) -> dict:
    """The STARTUP form of :func:`conversion_complete`: a read failure is REPORTED, never folded into
    "not converted" (packet 1361-01, round 4).

    Both answers stop a startup attempt, so this is not a behaviour change at the gate — it is an
    honesty change in the record and the log. "This corpus has not been converted" and "I could not
    read whether it has" want different actions from an administrator, and the second is an outage
    that will clear itself.

    Returns ``{"ok", "read_failed", "reason"}``. Never raises.
    """
    out = {"ok": False, "read_failed": False, "structural": False, "reason": ""}
    if not supported(backend):
        from corpusfm.lifecycle import runtime_storage
        try:
            active = runtime_storage.fm_storage_active()
        except Exception as exc:                                    # noqa: BLE001
            out["read_failed"] = True
            out["reason"] = ("the published storage authority could not be read: "
                             f"{type(exc).__name__}: {exc}")
            return out
        # Nothing published → the dev/test path, which has no corpus and no conversion to perform.
        # Published WITH a corpus, handed a backend that cannot be asked the version question, is a
        # contradiction rather than the dev path.
        out["ok"] = not active
        if active:
            out["reason"] = ("this installation owns a corpus but was handed a backend that cannot "
                             "be asked its projection version")
            # STRUCTURAL, and therefore DETERMINISTIC (packet 1361-01, round 7). The published
            # authority was read SUCCESSFULLY and says a corpus exists; the backend this process
            # composed cannot be asked the question at all. Neither fact can change while the
            # process runs, so retrying is a repeat of a decided answer, not a second chance.
            out["structural"] = True
        return out
    from corpusfm.storage import fm_registry as reg
    try:
        stored = backend.load_fm_settings(strict=True)
    except Exception as exc:                                        # noqa: BLE001
        out["read_failed"] = True
        out["reason"] = f"the SETTING record could not be read: {type(exc).__name__}: {exc}"
        return out
    value = (stored or {}).get("ProjectionVersion")
    if isinstance(value, bool) or not isinstance(value, int):
        value = None
    out["ok"] = value == reg.PROJECTION_VERSION
    if not out["ok"]:
        out["reason"] = (f"the stored ProjectionVersion is {value!r}; this build requires "
                         f"{reg.PROJECTION_VERSION}, so the JOB identity conversion has not "
                         "completed")
    return out


def _convert_job_identity(backend) -> dict:
    """The 1 → 2 tenant of the conversion seam: move every job to its own UUID.

    Returns `{"ok": bool, ...}` rather than raising, because `assert_projection` is documented never
    to raise. `ok: False` is enough to stop the caller stamping the version, and the reason is
    carried out for the startup report and the log — an administrator reading "jobs are unavailable"
    must be able to find which record refused.

    Named "the 1 -> 2 tenant" because that is the transition that introduced it; the seam runs it on
    EVERY version mismatch, deliberately, for the reason given at the call site.
    """
    from corpusfm.storage import job_identity_conversion as conv

    engine = getattr(backend, "engine", None)
    if engine is None:
        return {"ok": False, "result": conv.UNAVAILABLE,
                "detail": f"{type(backend).__name__} exposes no storage engine to convert."}
    try:
        outcome = conv.convert(engine)
    except conv.ConversionRefused as exc:
        logger.error("job identity conversion REFUSED this corpus; nothing was changed and jobs "
                     "stay unavailable: %s", exc)
        return {"ok": False, "result": conv.REFUSED, "detail": str(exc)}
    except conv.JobStoreUnreadable as exc:
        logger.error("job identity conversion could not read the JOB table: %s", exc)
        return {"ok": False, "result": conv.UNAVAILABLE, "detail": str(exc)}
    except conv.ConversionIncomplete as exc:
        logger.error("job identity conversion stopped part-way; the projection version stays "
                     "behind and the next start resumes it: %s", exc)
        return {"ok": False, "result": conv.INCOMPLETE, "detail": str(exc)}
    except Exception as exc:                                   # noqa: BLE001
        logger.error("job identity conversion failed", exc_info=True)
        return {"ok": False, "result": conv.INCOMPLETE, "detail": f"{type(exc).__name__}: {exc}"}
    logger.info("job identity conversion %s: %d job(s), %d adopted, %d re-keyed",
                outcome["result"], outcome["jobs"], outcome["adopted"], outcome["rekeyed"])
    return {"ok": True, **outcome}


def assert_projection(backend) -> dict:
    """Assert the SETTING projection contract at startup (the sequence above). Writes the map only
    when it's missing or drifted, and refreshes (waited-on) only when it wrote. Settings values are
    never overwritten. Sets the process ready flag on success. Never raises — a projection hiccup
    must not take down startup (the caller runs it in the boot daemon thread)."""
    global _asserted_ok
    if not supported(backend):
        return {"ok": True, "skipped": True, "reason": "unsupported backend"}

    from corpusfm.storage import fm_registry as reg
    try:
        code_map = reg.generate_setting_calculations()          # {"Calculations": {...}}
        # STRICT (packet 1400-01): a read that FAILS must not look like an empty table. The permissive
        # read answered {} whenever SETTING could not be read at startup (e.g. FileMaker still opening
        # the file after a reboot), and the branch below then merged the full default template over
        # every live setting.
        stored = backend.load_fm_settings(strict=True)          # {} only if no record / empty
    except Exception:
        logger.warning("projections.assert: could not read SETTING", exc_info=True)
        return {"ok": False, "reason": "read failed"}

    out: dict = {"ok": True}
    need_refresh = False
    stamp_version = False
    try:
        if not stored:
            # No record / empty → write the full default template (defaults + map). The version is
            # NOT seeded here; it is stamped only AFTER the fresh-install sweep succeeds (below), so a
            # refresh that fails on a brand-new box re-sweeps next boot instead of silently settling.
            backend.save_fm_settings(_default_template())
            out["wrote"] = "default_template"
            need_refresh = True
            stamp_version = True
        else:
            # Map write on ANY map diff — but a map diff ALONE no longer triggers a sweep (packet
            # 1060). Additive projections are free: the map lands, new records pick the new slot up via
            # the auto-enter CF, existing rows are untouched-but-correct-for-new-writes. Settings values
            # are never overwritten.
            if stored.get("Calculations") != code_map["Calculations"]:
                backend.save_fm_settings(code_map)              # merge → only the Calculations key
                out["wrote"] = "projection_map"
            else:
                out["wrote"] = "none"
            # The SWEEP is version-gated: a bumped PROJECTION_VERSION (or a stored record with no
            # version yet) is the deliberate "existing data needs conversion" signal → refresh + stamp.
            if stored.get("ProjectionVersion") != reg.PROJECTION_VERSION:
                need_refresh = True
                stamp_version = True
    except Exception:
        logger.warning("projections.assert: writing the map failed", exc_info=True)
        return {"ok": False, "reason": "write failed"}

    if need_refresh:
        # ── Version-keyed conversion seam (packet 1060; first used by packet 1372-01) ──
        # This is the hook packet 1060 reserved, now carrying its first tenant: the JOB identity
        # conversion, introduced by the 1 → 2 transition. It runs BEFORE the file-wide sweep and long
        # before the stamp, so a refusal or a partial run leaves the stored version behind — which is
        # exactly what holds the Queue workers and the scheduler off an unconverted corpus.
        #
        # IT RUNS ON EVERY TRANSITION, NOT ONLY 1 → 2, and that is deliberate rather than an
        # oversight in the keying. The one-UUID invariant is not a one-off repair, it is a property
        # the product now requires, and the conversion is idempotent — an already-converted corpus
        # costs one JOB enumeration and answers `already_current`. Re-asserting it on a later bump is
        # therefore nearly free and catches a regression that reintroduced a two-UUID row, which a
        # version-pair table would silently wave through.
        #
        # A FRESH INSTALL TAKES THIS PATH TOO (`stored` was empty, so `stamp_version` is set). That
        # is correct and cheap: the planner enumerates an empty JOB table and returns
        # `already_current`. It also means the invariant is asserted on every new box rather than
        # assumed.
        conv_out = _convert_job_identity(backend)
        out["job_identity"] = conv_out
        if not conv_out.get("ok"):
            out["ok"] = False
            return out
        out["refreshed"] = _refresh(backend)
        if not out["refreshed"]:
            out["ok"] = False       # a needed refresh failed → not asserted; retried next startup
            return out
        if stamp_version:
            # Stamp the new version ONLY after a successful sweep — a failed refresh must NOT advance
            # the stored version (it must retry next boot). Merge-writes just the sibling key.
            try:
                backend.save_fm_settings({"ProjectionVersion": reg.PROJECTION_VERSION})
            except Exception:
                logger.warning("projections.assert: version stamp failed", exc_info=True)
                out["ok"] = False
                return out
            # READ IT BACK, STRICTLY (packet 1372-01). The stamp is now the signal two processes
            # use to decide whether jobs may run at all, and `save_fm_settings` dispatches a merge
            # whose failure is ambiguous by construction — it can raise after committing, and it can
            # return after not committing. Asserting activation on the write alone would let the
            # scheduler read a version that was never stored, or hold it off one that was.
            written = stored_projection_version(backend)
            if written != reg.PROJECTION_VERSION:
                logger.warning("projections.assert: stamped ProjectionVersion %s but read back %r",
                               reg.PROJECTION_VERSION, written)
                out["ok"] = False
                return out
            out["projection_version"] = reg.PROJECTION_VERSION

    _asserted_ok = True
    return out
