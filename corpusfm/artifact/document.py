"""The externalized artifact document — one portable thing (packet 1226).

A user downloading an artifact gets ONE file, whatever its type: *"If I download the artifact I really
mean I want just one thing."* The document is **assembled at download** from the stored artifact plus its
record row — nothing is stored in this form, so no record is reingested and no blob is rewritten.

Its purpose is LEGIBILITY, not capability: a user hands the file to an AI, and the AI can open it, work
out what it is, and talk about it. The server's MCP tools remain the way to go further.

**The key set never varies by artifact type** — every document carries `document_version`,
`artifact_type`, `record`, `step_catalog` and `payload`. Only what sits under `payload` differs: the
canonical artifact for a schema type, the stored text for a deliverable. Capability differences live in
the content, never in the container.

**CARRIES is not RESTORES, for most fields.** The document carries the full ruled field set; re-import
restores name/description/memory/tags — *"the artifact should take everything with it, but have no
expectation of coming back to the same corpus."* Fields like `analyzer_failed` travel as evidence a
reader can use, not as state a receiving corpus adopts.

**The three ADDON PRESENTATION fields are the exception** (packet 1254, document version 2): `icon_b64`,
`addon_version` and `addon_locale` are restored, because an add-on that arrives in a new corpus without
its own face is not the same artifact to look at. They are the presentation an add-on carries about
ITSELF, not an address in the corpus it came from — which is what separates them from `analyzer_failed`
and from the `has_*` flags below.

The content boundary is expected to move again, so both lists below are data, and `DOCUMENT_VERSION`
exists to tell the forms apart.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Optional

DOCUMENT_VERSION = 2

# Record fields that travel. Identity, curation, and facts that stay true anywhere.
_RECORD_FIELDS: tuple[str, ...] = (
    "file_name",        # identity
    "root_uuid",
    "schema_version",   # how to interpret it
    "fm_version",
    "timestamp",        # when it was ingested — a fact about the artifact, not the corpus
    "name",             # curation: authored, not derivable, lost forever if it does not travel
    "description",
    "memory",
    "origin",           # how it came to exist; meaningful as history without resolving anything
    "analyzer_failed",  # self-honesty: nothing recomputes which miners crashed
    "acceptance_state",  # fmClip — whether FileMaker actually accepted the paste
    "xml_bytes",        # how big the original export was
    "addon_version",
    "addon_locale",
)

# Deliberately absent, with the reason, so a later reader can argue rather than guess:
#   path, uuid, job_uuid, run_uuid, acceptance_batch — origin-corpus addresses nothing can resolve.
#   enc_bytes                                        — legacy, already 0 on record-store backends.
#   summarizable_count                               — computable from the artifact's own items.
#   gap_issues, gap_count_version, gap_unmapped      — DERIVED from the artifact's completeness_profile,
#       which travels inside the payload. Carrying them too would make two copies that can disagree.
#   has_name_map, has_summaries, has_source, has_icon — presence flags for containers in the ORIGIN
#       corpus, none of which travel. Actively misleading: `has_source: true` invites a recipient to
#       look for a source that is not in the file and cannot be fetched.
#       `has_icon` stays out even though the ICON now travels (packet 1254), and the distinction is the
#       point: a flag pointing at content that cannot travel misleads, while content that CAN travel
#       should just travel. `has_icon` is DERIVED from the bytes (`storage/artifact_record.py`), so
#       carrying it too would be a second copy that can disagree.


@lru_cache(maxsize=8)
def _step_catalog_dict(schema_version: str) -> dict:
    """The WHOLE shipped step catalog for `schema_version`, not the observed slice.

    Cached: the catalog is shipped data that cannot change while the process runs, and building it
    costs ~33 ms — which a multi-artifact download bundle would otherwise pay once PER artifact for
    an identical result. **Treat the returned dict as read-only** (the one caller serialises it).

    An AI discussing the file needs to recognise steps the user asks about or that it might suggest,
    not only the ones already present — a catalog of what happens to be in this file cannot answer
    "could you use Loop here?". The artifact's own `steps_observed` / `steps_unknown` stay beside it as
    facts about this file.
    """
    from corpusfm.core.schemas.registry import _available_versions, load_structure_catalog
    version = (schema_version or "").strip()
    if not version:
        # A deliverable may carry no schema version. The newest shipped catalog is the honest default:
        # it is a superset (FM schema is additive), and the document records which one was used.
        available = _available_versions("structure_catalog.yaml")
        version = available[-1] if available else "2.2.3.0"
    catalog, _warning = load_structure_catalog(version)
    return catalog.to_dict()


def encode_payload(payload: Any) -> tuple[Any, str]:
    """Return (payload, payload_encoding) — ``json``, ``text``, or ``base64``.

    A deliverable's stored bytes ARE its content, and for an fmClip the project's whole emitter
    discipline rests on those bytes being exact. So the decode is STRICT: bytes that are not UTF-8
    travel base64 rather than being run through ``errors="replace"``, which would replace them with
    U+FFFD and hand back a corrupted clip that still looks like a clip.

    The key is always present, whatever the type, so the document's shape does not vary.
    """
    if isinstance(payload, (dict, list)):
        return payload, "json"
    if isinstance(payload, bytes):
        try:
            return payload.decode("utf-8"), "text"
        except UnicodeDecodeError:
            import base64
            return base64.b64encode(payload).decode("ascii"), "base64"
    return payload, "text"


def decode_payload(document: dict) -> Any:
    """Inverse of `encode_payload` — the payload as stored, honouring `payload_encoding`."""
    payload = document.get("payload")
    if document.get("payload_encoding") == "base64" and isinstance(payload, str):
        import base64
        return base64.b64decode(payload.encode("ascii"))
    return payload


def build_document(meta, payload: Any, tags: Optional[list] = None, icon_b64: str = "") -> dict:
    """Assemble the externalized document. `payload` is the canonical artifact dict (schema types) or
    the stored bytes/text (deliverables); this function does not care which.

    `tags` and `icon_b64` are passed IN rather than read off `meta`, because neither is on it: tags are
    a separate table, and `meta` carries only the derived `has_icon` flag, never the bytes. Both keys
    are always present — an empty list and an empty string when absent — because the key set must not
    vary by artifact type."""
    record = {f: getattr(meta, f, None) for f in _RECORD_FIELDS}
    record["tags"] = list(tags or [])
    record["icon_b64"] = icon_b64 or ""
    for k, v in record.items():
        if isinstance(v, (list, tuple)):
            record[k] = list(v)
        elif v is None:
            record[k] = ""
    body, encoding = encode_payload(payload)
    return {
        "document_version": DOCUMENT_VERSION,
        "artifact_type": getattr(meta, "artifact_type", "") or "",
        "record": record,
        "step_catalog": _step_catalog_dict(getattr(meta, "schema_version", "")),
        "payload_encoding": encoding,
        "payload": body,
    }


def is_document(d: Any) -> bool:
    """Is this parsed JSON an externalized artifact document (as opposed to a bare stored artifact)?"""
    return (isinstance(d, dict)
            and isinstance(d.get("document_version"), int)
            and "payload" in d
            and isinstance(d.get("record"), dict))
