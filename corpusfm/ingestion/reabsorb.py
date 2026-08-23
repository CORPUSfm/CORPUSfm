"""Reabsorb — re-import a previously-downloaded CORPUSfm artifact, no re-ingestion (packet 033).

A downloaded artifact is a ZIP holding ``<base>.artifact`` — the canonical artifact
(items + per-object xml_sources + rendered layers), NOT the source FM XML. Reabsorb is the SECOND
import path (vs raw-FM-source ingestion): we VALIDATE the incoming artifact and store it AS-IS —
identity/bytes preserved, no destructive re-parse.

The understandability gate (the dev's doctrine, 2026-06-29): if we can't understand an artifact in
a useful way, reject it; if we can, accept it (and heal-on-load brings derived layers current).
No dedup (packet 085): reabsorbing an artifact already in the catalog stores a SECOND record —
duplicates are surfaced in the Related tab (same root file), never prevented. root_uuid stays
filter-only. See the packet-033 build notes.
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass, field
from typing import Optional, Tuple

from corpusfm.artifact import Artifact, is_known_type
from corpusfm.artifact.capabilities import DELIVERABLE_TYPES, DELIVERABLE_EXT
from corpusfm.artifact.document import decode_payload, is_document

# Decompression-bomb guard (mirrors the .fmaddon / XAR caps in core/addon/package.py): the upload
# byte-cap bounds the COMPRESSED size, so a tiny, highly-compressible `.artifact` zip can still
# expand to many gigabytes. The `.artifact` JSON for a large solution is tens of MB, so a 512 MB
# ceiling on the single decompressed member is generous against real artifacts yet refuses a bomb;
# the member count is capped so a zip stuffed with members can't exhaust resources either.
_MAX_MEMBER_DECOMPRESSED = 512 * 1024 * 1024
_MAX_MEMBERS = 10_000


# parse_uploaded_artifact (schema-only) was RETIRED by packet 1064 — the sole reabsorb parser is now
# parse_uploaded_envelope (below), which handles BOTH schema artifacts and deliverable envelopes. A
# schema-only caller takes ``payload.artifact`` when ``payload.kind == "schema"``.


def validate_for_reabsorb(artifact: Artifact) -> Tuple[bool, str]:
    """The understandability + integrity gate. Returns (ok, reason_if_not)."""
    tval = getattr(artifact.type, "value", artifact.type)
    if not is_known_type(artifact.type):
        return False, f"unknown artifact type {tval!r} — cannot reabsorb (define the type or reject)"
    if not artifact.is_current_format():
        # We only accept formats we currently understand (no migration logic yet).
        return False, f"artifact format {artifact.artifact_version!r} is not understood by this version"
    return True, ""


# ── Portable artifact (packets 1034 + 1226): works for DELIVERABLES (fmClip/PatchXML/fmScript/
#    fmCalc) as well as schema artifacts. Current downloads are ONE document; the older sidecar
#    shape is still read. ────────────────────────────────────────────────────────────────────────

@dataclass
class ReabsorbPayload:
    """One reabsorb-able unit parsed from a downloaded artifact — either a schema Artifact or a
    deliverable's raw bytes — plus the record fields to restore on the new record.

    Restored: name/description/memory/tags, plus the three ADDON PRESENTATION fields (packet 1254).
    The document carries more than that, deliberately: the rest travels as evidence for a reader, not
    as state a receiving corpus adopts. See `corpusfm.artifact.document`."""
    kind: str                                       # "schema" | "deliverable"
    artifact: Optional[Artifact] = None
    deliverable_type: str = ""
    raw: bytes = b""
    name: str = ""
    description: str = ""
    memory: str = ""
    tags: list = field(default_factory=list)
    icon_b64: str = ""                              # addon presentation; empty for every other type
    addon_version: str = ""
    addon_locale: str = ""


def _bounded_member(z, info) -> Optional[bytes]:
    if info.file_size > _MAX_MEMBER_DECOMPRESSED:
        return None
    with z.open(info) as fh:
        b = fh.read(_MAX_MEMBER_DECOMPRESSED + 1)
    return None if len(b) > _MAX_MEMBER_DECOMPRESSED else b


def is_artifact_envelope(filename: str, data: bytes) -> bool:
    """Is this upload a CORPUSfm artifact envelope? Decided by CONTENT, not by its extension.

    Two forms are accepted and must stay accepted:
      • **current** (packet 1226) — one ``*.artifact`` document holding the record fields, the
        step catalog and the payload, served as ``<name>.artifact.zip``;
      • **legacy** — a ``meta.json`` sidecar beside a separate payload member, served for a while as a
        plain ``.zip`` and before that as ``.artifact``. Real files in real downloads.

    A bare ``.zip`` is not enough on its own — a user can drop any zip on the page — so the test is the
    zip's own contents.

    **The name still carries weight for ONE shape, and only after inspection.** A pre-sidecar
    deliverable envelope holds nothing but its payload (``My Clip.fmclip``) — no ``meta.json``, no
    ``*.artifact`` — so content alone genuinely cannot identify it, and dropping the name would
    stop those files importing. What the name may no longer do is *substitute* for looking: the old
    first branch returned True for anything called ``.artifact``, with no inspection at all (packet
    1226 / Codex R6), so a JPEG renamed ``x.artifact`` was accepted here and failed later, somewhere
    the reason was much harder to see. Now the file must at least BE a zip.
    """
    if data[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = [i.filename for i in z.infolist()[:_MAX_MEMBERS]]
    except Exception:
        return False
    if any(n.rsplit("/", 1)[-1] == "meta.json" or n.endswith(".artifact") for n in names):
        return True
    return bool(names) and (filename or "").lower().endswith(".artifact")


def parse_uploaded_envelope(filename: str, data: bytes) -> Optional[ReabsorbPayload]:
    """Parse a downloaded artifact (schema OR deliverable) into a ReabsorbPayload.

    Reads both forms: the current single document (record fields inside it) and the older
    `meta.json` sidecar beside a separate payload. Returns None when the upload is not a CORPUSfm
    artifact. Decompression is bounded (bomb guard), as in parse_uploaded_artifact."""
    name = (filename or "").lower()
    if not (name.endswith(".artifact") or data[:2] == b"PK"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) > _MAX_MEMBERS:
                return None
            # meta.json sidecar (optional — an old `.artifact` predates it).
            side = {"name": "", "description": "", "memory": "", "tags": [], "type": "",
                    "icon_b64": "", "addon_version": "", "addon_locale": ""}
            m_info = next((i for i in infos if i.filename.rsplit("/", 1)[-1] == "meta.json"), None)
            if m_info is not None:
                mb = _bounded_member(z, m_info)
                if mb is not None:
                    try:
                        md = json.loads(mb.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        md = None
                    if isinstance(md, dict):
                        side["name"] = str(md.get("name") or md.get("PrimaryName") or "")
                        side["description"] = str(md.get("description") or "")
                        side["memory"] = str(md.get("memory") or "")
                        side["tags"] = [t for t in (md.get("tags") or []) if isinstance(t, str)]
                        side["type"] = str(md.get("artifact_type") or md.get("Type") or "")
            # `*.artifact` — the current single document, or a legacy bare stored artifact.
            art_info = next((i for i in infos if i.filename.endswith(".artifact")), None)
            if art_info is not None:
                blob = _bounded_member(z, art_info)
                if blob is None:
                    return None
                try:
                    d = json.loads(blob.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return None
                if is_document(d):
                    # Current form: the record fields live INSIDE the document, not in a sidecar.
                    # Restored: name/description/memory/tags + the addon presentation (packet 1254).
                    # The rest travelled as evidence for a reader — the stated contract, not a shortfall.
                    rec = d.get("record") or {}
                    side["name"] = str(rec.get("name") or "")
                    side["description"] = str(rec.get("description") or "")
                    side["memory"] = str(rec.get("memory") or "")
                    side["tags"] = [t for t in (rec.get("tags") or []) if isinstance(t, str)]
                    dtype = str(d.get("artifact_type") or "")
                    # Addon presentation, restored only for an AddonXML artifact (developer, 2026-08-14):
                    # no other type displays an icon, so bytes claimed by any other type are ignored
                    # rather than stored where nothing can show them.
                    if dtype == "AddonXML":
                        side["icon_b64"] = str(rec.get("icon_b64") or "")
                        side["addon_version"] = str(rec.get("addon_version") or "")
                        side["addon_locale"] = str(rec.get("addon_locale") or "")
                    payload = decode_payload(d)
                    if dtype in DELIVERABLE_TYPES:
                        raw = payload if isinstance(payload, bytes) else \
                            payload.encode("utf-8") if isinstance(payload, str) else b""
                        if not raw:
                            return None
                        return ReabsorbPayload(kind="deliverable", deliverable_type=dtype, raw=raw,
                                               name=side["name"], description=side["description"],
                                               memory=side["memory"], tags=side["tags"])
                    d = payload if isinstance(payload, dict) else None
                    if d is None:
                        return None
                if not (isinstance(d, dict) and "artifact_version" in d and "type" in d and "items" in d):
                    return None
                try:
                    art = Artifact.from_dict(d)
                except Exception:
                    return None
                return ReabsorbPayload(kind="schema", artifact=art, name=side["name"],
                                       description=side["description"], memory=side["memory"],
                                       tags=side["tags"], icon_b64=side["icon_b64"],
                                       addon_version=side["addon_version"],
                                       addon_locale=side["addon_locale"])
            # Deliverable payload: the raw file whose extension matches the meta type.
            dtype = side["type"]
            if dtype in DELIVERABLE_TYPES:
                ext = DELIVERABLE_EXT.get(dtype, "")
                others = [i for i in infos if i.filename.rsplit("/", 1)[-1] != "meta.json"]
                raw_info = next((i for i in others if ext and i.filename.endswith("." + ext)), None)
                if raw_info is None and len(others) == 1:
                    raw_info = others[0]                       # single non-meta member → the payload
                if raw_info is None:
                    return None
                raw = _bounded_member(z, raw_info)
                if not raw:
                    return None
                return ReabsorbPayload(kind="deliverable", deliverable_type=dtype, raw=raw,
                                       name=side["name"], description=side["description"],
                                       memory=side["memory"], tags=side["tags"])
            return None
    except (zipfile.BadZipFile, KeyError, UnicodeDecodeError, OSError):
        return None


def validate_reabsorb_payload(payload: ReabsorbPayload) -> Tuple[bool, str]:
    """Understandability gate for a ReabsorbPayload (schema OR deliverable)."""
    if payload.kind == "schema":
        if payload.artifact is None:
            return False, "no artifact found in the envelope"
        return validate_for_reabsorb(payload.artifact)
    if payload.deliverable_type not in DELIVERABLE_TYPES:
        return False, f"unknown deliverable type {payload.deliverable_type!r} — cannot reabsorb"
    if not payload.raw:
        return False, "empty deliverable payload — nothing to reabsorb"
    return True, ""


# find_duplicate was retired by packet 085 (no dedup anywhere — duplicates are
# surfaced in the Related tab, never prevented).
