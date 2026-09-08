"""Tag registry — user-defined labels on artifact records (by product, client, status…).

Tags are **strictly per-record**: a record carries only its own labels — versions,
SaveAsXML/Addon companions, and FileMaker clones sharing a ``root_uuid`` do NOT inherit each
other's tags. Keys are the record UUID (the canonical artifact address, packet 085 U3f); storage
is the normalized TAG/STORAGELINK tables via the per-record surface (``tags_store``) over the backend's
StorageEngine — FM OData in production, LocalBackend's SQLite mirror in dev/test.

The tags.yaml fallback and the legacy SETTINGS-blob path are RETIRED (Phase 4 tags fold,
packet 084): the engine is the only tag store. Without a live engine (an engine-less test
double, or a pending storage migration) reads return empty and writes are refused — there is
no shadow store to fall back to.

This generalizes the former single-valued "Solution" field (one name per file) to multi-valued
tags. The authoritative "which files form one FM solution" grouping is derivable separately
from the files' external data sources (the intrinsic connector — see the cross-file
reconstruction work), so the manual labels are free to be general-purpose.

Public API (READS come from the persistent catalog; WRITES go to FileMaker — packet 1361-01):
    set_record_tags(rel_path, tags) -> None     # per-record set; [] clears
    parse_tags(text) -> list[str]               # comma-separated string → clean list
    rename_tag(old, new) -> int                 # assignments updated
    delete_tag(name) -> int                     # assignments removed
    commit_tag(original_name, name, members) -> dict
    list_tag_names() -> list[str]               # distinct, sorted (incl. named-but-empty)
    validate_tag_name(name) -> (normalized, error)
"""

from __future__ import annotations

# System-tag namespaces a user tag may NOT masquerade as (auto-managed; case-insensitive).
_RESERVED_NAMESPACES = ("type:", "fm:", "job:", "origin:")
_RESERVED_FLAGS = ("has-",)


def validate_tag_name(name: str) -> tuple[str, str]:
    """Validate + normalize a user tag name. Returns (normalized_name, error). On success
    error is ''; on failure normalized_name is ''. Lowercases; rejects blank + reserved
    system namespaces (type:/fm:/job:/origin: + has-* flags) so a user tag can't pose as system."""
    n = (name or "").strip().lower()
    if not n:
        return "", "Tag name is required."
    if any(n.startswith(p) for p in _RESERVED_NAMESPACES) or any(n.startswith(f) for f in _RESERVED_FLAGS):
        return "", f"'{n}' uses a reserved system-tag namespace."
    return n, ""


def _v2_backend():
    """The backend when the normalized TAGS/TAGASSIGN tables are live (an engine-bearing
    backend + the new schema in place), else None. There is no fallback store."""
    try:
        from corpusfm.storage import get_backend
        from corpusfm.server import tags_store
        b = get_backend()
        return b if tags_store.tables_available(b) else None
    except Exception:
        return None


def parse_tags(text: str) -> list[str]:
    """Split a comma-separated label string into a clean, de-duplicated, order-preserving list.

    Tag names are case-insensitive, so they are forced lowercase (dedup runs after
    lowering, collapsing case variants). Comma is the ONLY separator — a space is not —
    so multi-word tags survive; no other character is restricted.
    """
    out: list[str] = []
    for part in (text or "").split(","):
        t = part.strip().lower()
        if t and t not in out:
            out.append(t)
    return out


def _coerce(value) -> list[str]:
    """Normalize a value to a tag list (lowercased; tolerates a single comma-separated string)."""
    if isinstance(value, str):
        return parse_tags(value)
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            if isinstance(v, str):
                t = v.strip().lower()
                if t and t not in out:
                    out.append(t)
        return out
    return []


# `get_tags()` is GONE (packet 1361-01, final ruling). Its one caller was the download envelope,
# and reading the catalog per artifact made an N-member bundle N lookups — each of which could
# become the sweep leader and pay a three-table read on a path that is only ever best-effort
# portable metadata. A download now takes ONE already-published snapshot and reuses its tag map
# (`routes/api/library.download_tag_map`), and never falls back to the database for tags.


def set_record_tags(artifact_uuid: str, tags) -> None:
    """Replace the USER tag set for the ONE artifact record identified by its UUID (packet 085
    U3f; strictly per-record — siblings sharing a root_uuid are untouched). An empty list clears
    it. `tags` may be a list or a comma-separated string. No-op when the tables aren't live."""
    if not artifact_uuid:
        return
    v2 = _v2_backend()
    if v2 is None:
        return
    tag_list = parse_tags(tags) if isinstance(tags, str) else _coerce(tags)
    from corpusfm.server import tags_store
    tags_store.set_record_tags(v2, artifact_uuid, tag_list)


def tags_available() -> bool:
    """True when the tag tables are usable right now. The bulk endpoint checks this FIRST and
    refuses by name — ``set_record_tags``'s silent no-op is acceptable for a single-record save,
    not for a bulk apply that would then report success over nothing (packet 1280)."""
    return _v2_backend() is not None


def adjust_record_tags(artifact_uuid: str, add, remove):
    """Delta-adjust ONE record's user tags (packet 1280). Returns the store's
    ``{"added", "removed", "tags"}`` result, or ``None`` when tag storage is unavailable —
    the caller refuses; this layer never converts unavailability into a silent no-op."""
    if not artifact_uuid:
        return None
    v2 = _v2_backend()
    if v2 is None:
        return None
    from corpusfm.server import tags_store
    return tags_store.adjust_artifact_tags(v2, artifact_uuid, _coerce(add), _coerce(remove))


def rename_tag(old_name: str, new_name: str) -> int:
    """Rename a tag across every record that carries it. Returns assignments updated."""
    new_name = (new_name or "").strip().lower()
    old_name = (old_name or "").strip().lower()
    if not new_name or not old_name or old_name == new_name:
        return 0
    v2 = _v2_backend()
    if v2 is None:
        return 0
    from corpusfm.server import tags_store
    return tags_store.rename_tag(v2, old_name, new_name)


def delete_tag(name: str) -> int:
    """Remove a tag from every record that carries it. Returns assignments removed."""
    name = (name or "").strip().lower()
    if not name:
        return 0
    v2 = _v2_backend()
    if v2 is None:
        return 0
    from corpusfm.server import tags_store
    return tags_store.delete_tag(v2, name)


def commit_tag(original_name: str, name: str, members) -> dict:
    """Declarative tag commit (create / rename + reconcile membership to EXACTLY `members`).

    `original_name`=='' creates; `original_name`!=`name` renames (rename-into-existing merges).
    Membership reconciles to `members` (rel_paths); an emptied tag PERSISTS (never reaped — only
    an explicit delete removes it). Validates + lowercases `name`. Returns {ok, name, count} or
    {ok:False, error}."""
    norm, err = validate_tag_name(name)
    if err:
        return {"ok": False, "error": err}
    v2 = _v2_backend()
    if v2 is None:
        return {"ok": False, "error": "Tag storage is unavailable."}
    orig = (original_name or "").strip().lower()
    members = [m for m in (members or []) if isinstance(m, str) and m.strip()]
    from corpusfm.server import tags_store
    return tags_store.commit_tag(v2, orig, norm, members)


def list_tag_names() -> list[str]:
    """Distinct USER tag names, sorted — from the persistent catalog's TAG records, so
    named-but-empty tags (persisted by commit_tag) are included (packet 1361-01)."""
    v2 = _v2_backend()
    if v2 is None:
        return []
    from corpusfm.server import catalog
    view = catalog.view(v2)
    return view.tag_names if view.servable else []
