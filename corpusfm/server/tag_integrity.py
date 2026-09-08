"""The tag subsystem's own startup integrity pass (packet 1361-01).

**Why this is not in the catalog.** The catalog is a read model. It observes; it does not police,
repair, delete, or repeatedly report a database record. An earlier round had it derive a
"broken User Tag link" report on every index build and offer a Tags-page button to delete what the
report listed — which put a destructive action behind a read-time inference that could be wrong
(a record whose JSON was momentarily unreadable, or one written out of process seconds earlier,
reads exactly like a record that is gone). The developer's ruling separates the two concerns: the
subsystem that OWNS the data owns its integrity, it runs once at startup, and it deletes only what
it can establish authoritatively.

What this pass deletes, and nothing else: a ``Type="User Tag"`` STORAGELINK row whose

* ``UUIDTag`` or ``UUIDStorage`` is **absent** (blank — the row cannot ever name anything), or
* referenced TAG / STORAGE record is **authoritatively absent** — proven by a CHUNKED, fully paged
  keyed read of those exact records, never inferred from a listing and never from a request a server
  could have truncated. If any chunk or any page of a chunk does not complete, this pass deletes
  nothing at all.

What it never touches:

* **any other link Type.** STORAGELINK is the generic relationship surface; a link this subsystem
  does not own is not its business (the "Latest Artifact" promotion has its own repair, in
  ``server.latest``);
* **a malformed endpoint.** A record whose ``JSONOfRecord`` cannot be parsed still EXISTS. It is
  ignored here, deliberately — "I cannot read it" is not "it is gone";
* **anything at all when a read failed.** A partial picture is exactly the state in which a repair
  deletes something real, so an incomplete read aborts the whole pass without writing;
* **an empty named TAG row.** A tag with no members is a valid, deliberately persisted state.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_LINK = "STORAGELINK"
_TAG = "TAG"
_STORAGE = "STORAGE"

USER_TAG_LINK = "User Tag"


def _present(eng, logical: str, keys: list) -> set:
    """The subset of ``keys`` the substrate AUTHORITATIVELY holds.

    It goes through ``engine.keys_present``, not ``get_by_keys``, and the difference is the whole
    safety of this module (packet 1361-01). ``get_by_keys`` builds ONE un-paged request naming every
    key: for a large link set that is a URL a server may refuse and a response a server may page —
    and a short answer here does not read as an error, it reads as *absent*, which is a deletion.
    ``keys_present`` chunks the key set into bounded requests and follows every ``@odata.nextLink``
    of every chunk, so absence is proven only after every chunk finished completely and any
    incomplete page RAISES instead of shrinking the answer."""
    if not keys:
        return set()
    return eng.keys_present(logical, list(dict.fromkeys(keys)))


def repair_user_tag_links(backend) -> dict:
    """Delete genuinely broken ``User Tag`` links. Idempotent, bounded, best-effort, never raises.

    Returns ``{"ok", "examined", "removed", "reason"}``. ``ok`` is False with a reason whenever the
    pass declined to act — which is the honest outcome, not a failure to report."""
    out = {"ok": False, "examined": 0, "removed": 0, "reason": "",
           "read_failed": False, "write_failed": False}
    eng = getattr(backend, "engine", None)
    if eng is None:
        out["reason"] = "no storage engine"
        return out
    try:
        links = eng.list_where(_LINK, eq={"Type": USER_TAG_LINK})
    except Exception as exc:                                       # noqa: BLE001
        out["reason"] = f"{type(exc).__name__}: {exc}"
        out["read_failed"] = True
        logger.warning("tag integrity: could not read STORAGELINK — nothing was changed",
                       exc_info=True)
        return out

    candidates = []          # (link_key, tag_uuid, storage_uuid)
    blank = []
    for r in links:
        jor = r.jor if isinstance(r.jor, dict) else None
        if jor is None:
            continue         # a malformed link row is not something to delete on
        tag_uuid = jor.get("UUIDTag")
        art_uuid = jor.get("UUIDStorage")
        if not isinstance(tag_uuid, str) or not isinstance(art_uuid, str):
            continue         # minimal type check only — a wrong-shaped value is ignored, not judged
        if not tag_uuid.strip() or not art_uuid.strip():
            blank.append(r.key)          # an endpoint is ABSENT — this row can never name anything
            continue
        candidates.append((r.key, tag_uuid, art_uuid))
    out["examined"] = len(links)

    try:
        live_tags = _present(eng, _TAG, [t for _k, t, _a in candidates])
        live_records = _present(eng, _STORAGE, [a for _k, _t, a in candidates])
    except Exception as exc:                                       # noqa: BLE001
        out["reason"] = f"{type(exc).__name__}: {exc}"
        out["read_failed"] = True
        logger.warning("tag integrity: endpoint verification read failed — nothing was changed",
                       exc_info=True)
        return out

    doomed = list(blank)
    doomed += [k for k, t, a in candidates
               if t not in live_tags or a not in live_records]
    if not doomed:
        out["ok"] = True
        return out

    from corpusfm.server import catalog
    for key in doomed:
        try:
            eng.delete(_LINK, key)
        except Exception as exc:                                   # noqa: BLE001
            # A DELETE THAT FAILED IS A DATABASE FAILURE, NOT A SKIPPED ROW (packet 1361-01, round
            # 4). This used to be a debug line and the pass still answered `ok: True`, so a run that
            # removed nothing at all reported success — which is the same lie as reporting a repair
            # it did not perform. It stops at the first failure: the substrate is not answering, and
            # the remaining deletes are more failures rather than more chances. What was already
            # removed stays removed; the pass is idempotent and the next attempt re-derives the set.
            out["write_failed"] = True
            out["reason"] = (f"the broken link {key} could not be deleted: "
                             f"{type(exc).__name__}: {exc}")
            logger.error("tag integrity: %s — the pass stops here after removing %d of %d",
                         out["reason"], out["removed"], len(doomed), exc_info=True)
            return out
        catalog.publish_deleted(backend, catalog.TABLE_LINK, key)
        out["removed"] += 1
    out["ok"] = True
    logger.info("tag integrity: removed %d broken user-tag link(s) of %d examined",
                out["removed"], out["examined"])
    return out
