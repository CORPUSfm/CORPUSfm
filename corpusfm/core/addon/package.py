"""Addon package parsing: locale name resolution and metadata extraction.

Supported input shapes:
  parse_addon_xar(Path)      — .fmaddon XAR archive
  parse_addon_folder(Path)   — extracted addon folder on disk (internal/programmatic use)
"""

from __future__ import annotations

import io
import json
import logging
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from corpusfm.core import safe_xml as ET

_log = logging.getLogger(__name__)

# Matches the per-locale record-data files FM embeds in .fmaddon archives.
# These can be hundreds of MB each and contain no schema information.
_RECORDS_PAT = re.compile(r"^records_[a-zA-Z0-9_-]+\.xml$", re.IGNORECASE)

# ── XAR extraction safety caps ────────────────────────────────────────────────
# A .fmaddon is an externally-supplied compressed archive (XAR with zlib-compressed TOC + per-file
# zlib/"gzip" entries). The upload byte-cap bounds the COMPRESSED size, not the decompressed size, so
# a tiny, highly-compressible archive can still expand to many gigabytes (a decompression bomb). The
# records_*.xml data files are skipped before they're ever decompressed, but template.xml itself is a
# decompression target, so every decompress is bounded and the file/entry counts are capped. Limits
# are generous against real addons (measured ceilings: TOC ~30 KB, ~28 entries, template.xml ~107 MB,
# total non-records ~240 MB) yet tight enough to refuse a bomb. Extraction is in-memory only (no disk
# writes), so a path-traversal entry can't escape — but such names are still rejected as a red flag.
_MAX_TOC_DECOMPRESSED = 128 * 1024 * 1024      # TOC is metadata XML; real ones are tens of KB
_MAX_FILE_ENTRIES = 10_000                     # real addons carry a few dozen file nodes
_MAX_FILE_DECOMPRESSED = 512 * 1024 * 1024     # any single extracted file (template.xml is the big one)
_MAX_TOTAL_DECOMPRESSED = 1024 * 1024 * 1024   # sum across all extracted (non-records) files


class AddonPackageError(ValueError):
    """A .fmaddon archive is malformed or exceeds a safety cap. Subclasses ValueError so existing
    callers that catch ValueError keep working; the message is safe to show a user."""


def _zlib_decompress_capped(data: bytes, cap: int, what: str) -> bytes:
    """zlib-decompress `data`, refusing output beyond `cap` bytes (a decompression-bomb guard).

    Uses a bounded decompressobj call: asking for cap+1 bytes means any leftover input
    (``unconsumed_tail``) or an over-cap length proves the stream expands past the limit."""
    dobj = zlib.decompressobj()
    out = dobj.decompress(data, cap + 1)
    if len(out) > cap or dobj.unconsumed_tail:
        raise AddonPackageError(
            f"{what} exceeds the {cap // (1024 * 1024)} MB decompressed limit (possible bomb).")
    out += dobj.flush()
    if len(out) > cap:
        raise AddonPackageError(
            f"{what} exceeds the {cap // (1024 * 1024)} MB decompressed limit (possible bomb).")
    return out


def _reject_unsafe_name(name: str) -> None:
    """Refuse a XAR file/dir name that looks like path traversal. Extraction is in-memory, so this
    can't escape to disk — but a `..`/absolute/separator-bearing name is a tamper signal, so fail
    loudly rather than silently key it into the result dict."""
    if name in ("", ".", "..") or name.startswith(("/", "\\")) \
            or "/" in name or "\\" in name or "\x00" in name:
        raise AddonPackageError(f"Refusing unsafe archive entry name: {name!r}")


@dataclass
class AddonPackage:
    xml_bytes: bytes
    name_map: dict[str, str] = field(default_factory=dict)
    addon_title: str = ""
    addon_version: str = ""
    addon_guid: str = ""
    addon_locale: str = ""
    icon_bytes: bytes = b""


def _locale_text(el: ET.Element) -> str:
    """Reconstruct full text from a SourceText/TargetText element.

    FM's locale XML represents newlines and tabs as child elements (<CR/>, <TAB/>)
    rather than literal whitespace.  element.text only returns text before the
    first child, so we must walk children and concatenate their tail text too.

    Do NOT strip: leading/trailing spaces here are content, not indentation. FM
    encodes structural whitespace as <CR/>/<TAB/>, so a literal space is always
    real — e.g. a calc string literal "SELECT " whose trailing space matters.
    Stripping silently broke every addon calc fragment with edge whitespace.
    """
    parts = [el.text or ""]
    for child in el:
        if child.tag == "CR":
            parts.append("\n")
        elif child.tag == "TAB":
            parts.append("\t")
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def parse_locale_xml(raw: bytes) -> dict[str, str]:
    """Parse a FM addon locale file (e.g. en.xml) into {StringID: display_name}.

    The locale file is a series of bare <DynamicTemplateString> elements — no
    single root element — so we wrap in <root>…</root> before parsing.
    Use TargetText as display name; fall back to SourceText when absent or empty.
    """
    try:
        root = ET.fromstring(b"<root>" + raw + b"</root>")
    except ET.ParseError:
        return {}
    result: dict[str, str] = {}
    for dts in root.findall("DynamicTemplateString"):
        sid_el = dts.find("StringID")
        src_el = dts.find("SourceText")
        tgt_el = dts.find("TargetText")
        if sid_el is None or src_el is None:
            continue
        sid = (sid_el.text or "").strip()
        if not sid:
            continue
        target = _locale_text(tgt_el) if tgt_el is not None else ""
        source = _locale_text(src_el)
        result[sid] = target if target else source
    return result


def _parse_metadata(info_bytes: bytes | None, info_en_bytes: bytes | None) -> tuple[str, str, str]:
    """Return (title, version, guid) from info.json + info_en.json.

    **The version key is ``Version``, capitalised, because that is what FileMaker writes.** This read
    used the lowercase ``version`` from the day it was written, so ``addon_version`` came back empty for
    every add-on this product has ever ingested — including its own, whose ``info.json`` has always
    carried ``"Version": "1.0"``. The defect survived because the tests built their own ``info.json``
    with the lowercase key, so reader and fixture agreed with each other and both disagreed with the
    format (packet 1256)."""
    title = version = guid = ""
    if info_bytes:
        try:
            d = json.loads(info_bytes)
            guid = str(d.get("GUID", ""))
            version = str(d.get("Version", ""))
        except Exception:
            pass
    if info_en_bytes:
        try:
            d = json.loads(info_en_bytes)
            title = str(d.get("Title", ""))
        except Exception:
            pass
    return title, version, guid


def strip_addon_records(xml_bytes: bytes) -> bytes:
    """Remove <Record> and <DataList> elements from addon XML bytes.

    Fast-path returns the original object unchanged when neither element type
    is present (the common case — record data lives in separate files in real
    .fmaddon archives).  Logs a warning with the count when elements are removed.
    """
    is_utf16 = xml_bytes[:2] in (b"\xff\xfe", b"\xfe\xff")
    try:
        text = xml_bytes.decode("utf-16" if is_utf16 else "utf-8", errors="replace")
    except Exception:
        return xml_bytes

    if "<Record" not in text and "<DataList" not in text:
        return xml_bytes

    root = ET.fromstring(xml_bytes)
    count = 0
    for parent in root.iter():
        for child in list(parent):
            if child.tag in ("Record", "DataList"):
                parent.remove(child)
                count += 1

    if count == 0:
        return xml_bytes

    _log.warning("strip_addon_records: removed %d element(s) (<Record>/<DataList>)", count)
    enc = "utf-16" if is_utf16 else "utf-8"
    return ET.tostring(root, encoding=enc, xml_declaration=True)


def _xar_read(fobj: io.RawIOBase, include_only_basenames: "set[str] | None" = None, *,
              include_records: bool = False,
              dirs_out: "list[str] | None" = None) -> dict[str, bytes]:
    """Extract all files from a XAR archive, skipping records_*.xml data files.

    Uses seeking so only the requested files are read — the records files can
    be hundreds of MB each and are never touched.  When include_only_basenames
    is provided, only files whose basename is in that set are extracted (useful
    for metadata-only reads that skip the large template.xml).

    The two keyword-only flags switch this ANALYSIS reader into a REDISTRIBUTION reader, and both
    default to today's behavior so every existing caller is unchanged by construction:

    ``include_records`` keeps ``records_*.xml`` instead of skipping them. Analysis never wants record
    data; redistributing a package that silently dropped it would ship an incomplete add-on.
    ``dirs_out`` collects directory paths (including empty ones), which the dict of files cannot
    represent — a ZIP must carry the hierarchy, an in-memory parse does not care.

    Redistribution additionally REFUSES what analysis can afford to ignore: a duplicate final path, a
    file/directory collision, and any XAR entry type that is neither file nor directory (symlink,
    hardlink, fifo, device). Representing a symlink as a regular file would hand the user a package
    that differs from the source, which is worse than refusing."""
    header = fobj.read(28)
    if len(header) < 28 or header[:4] != b"xar!":
        raise AddonPackageError("Not a XAR archive (bad magic bytes)")

    hdr_size = struct.unpack_from(">H", header, 4)[0]
    toc_compressed_len = struct.unpack_from(">Q", header, 8)[0]

    if hdr_size > 28:
        fobj.read(hdr_size - 28)

    toc_raw = fobj.read(toc_compressed_len)
    toc_xml = _zlib_decompress_capped(toc_raw, _MAX_TOC_DECOMPRESSED, "archive table-of-contents")
    heap_start = hdr_size + toc_compressed_len

    toc_root = ET.fromstring(toc_xml)
    toc_node = toc_root.find("toc")
    if toc_node is None:
        toc_node = toc_root

    result: dict[str, bytes] = {}
    counters = {"entries": 0, "total": 0}
    seen_dirs: set[str] = set()
    redistributing = include_records or dirs_out is not None

    def walk(node: ET.Element, prefix: str) -> None:
        for f in node.findall("file"):
            counters["entries"] += 1
            if counters["entries"] > _MAX_FILE_ENTRIES:
                raise AddonPackageError(
                    f"Archive has too many entries (> {_MAX_FILE_ENTRIES}).")
            name_el = f.find("name")
            type_el = f.find("type")
            if name_el is None:
                continue
            fname = (name_el.text or "").strip()
            _reject_unsafe_name(fname)
            ftype = (type_el.text or "file").strip() if type_el is not None else "file"
            path = prefix + fname

            if ftype == "directory":
                if dirs_out is not None:
                    if path in seen_dirs or path in result:
                        raise AddonPackageError(f"Refusing duplicate archive entry: {path!r}")
                    seen_dirs.add(path)
                    dirs_out.append(path)
                walk(f, path + "/")
                continue

            if redistributing and ftype not in ("file", ""):
                # symlink / hardlink / fifo / character-special / block-special. Analysis can ignore
                # these; redistribution cannot represent them faithfully in a ZIP, so it refuses.
                raise AddonPackageError(f"Unsupported archive entry type {ftype!r} for {path!r}")

            if redistributing and (path in result or path in seen_dirs):
                raise AddonPackageError(f"Refusing duplicate archive entry: {path!r}")

            if _RECORDS_PAT.match(fname) and not include_records:
                continue

            if include_only_basenames is not None and fname not in include_only_basenames:
                continue

            data_el = f.find("data")
            if data_el is None:
                # An absent <data> node is how XAR encodes a ZERO-BYTE FILE — the writer drops the
                # property when it archives nothing. So this is a legitimate empty file, not damage:
                # redistribution carries it as an empty member (refusing it would reject a valid
                # package), while analysis keeps skipping it exactly as before.
                if redistributing:
                    result[path] = b""
                continue
            offset_el = data_el.find("offset")
            length_el = data_el.find("length")
            enc_el = data_el.find("encoding")
            if offset_el is None or length_el is None:
                # A <data> node that omits offset/length IS damage — the entry claims content and
                # then does not say where it is. Analysis shrugs; redistribution must not silently
                # drop a file and hand back a valid-looking but incomplete ZIP.
                if redistributing:
                    raise AddonPackageError(f"Archive entry {path!r} has no offset/length.")
                continue

            offset = int(offset_el.text or "0")
            length = int(length_el.text or "0")
            enc = (enc_el.get("style", "") if enc_el is not None else "").lower()

            fobj.seek(heap_start + offset)
            chunk = fobj.read(length)
            if redistributing and len(chunk) != length:
                # A short read means the heap is truncated: the declared bytes are not there.
                raise AddonPackageError(
                    f"Archive entry {path!r} is truncated ({len(chunk)} of {length} bytes).")
            if "gzip" in enc:
                chunk = _zlib_decompress_capped(chunk, _MAX_FILE_DECOMPRESSED, f"file {fname!r}")
            counters["total"] += len(chunk)
            if counters["total"] > _MAX_TOTAL_DECOMPRESSED:
                raise AddonPackageError(
                    f"Archive total content exceeds the "
                    f"{_MAX_TOTAL_DECOMPRESSED // (1024 * 1024)} MB decompressed limit.")
            result[path] = chunk

    walk(toc_node, "")
    return result


def parse_addon_xar(source: "Path | str | bytes", locale: str = "en") -> AddonPackage:
    """Build an AddonPackage from a .fmaddon XAR archive.

    Pass a Path for large archives (the extractor seeks directly to each file,
    so multi-GB records data is never loaded).  Passing bytes wraps in BytesIO
    and works correctly but loads the full archive into memory.
    """
    if isinstance(source, (str, Path)):
        fobj: io.IOBase = open(source, "rb")
        close_after = True
    else:
        fobj = io.BytesIO(source)
        close_after = False

    try:
        files = _xar_read(fobj)
    finally:
        if close_after:
            fobj.close()

    template_key = next(
        (k for k in files if k.endswith("/template.xml") or k == "template.xml"),
        None,
    )
    if template_key is None:
        raise ValueError(".fmaddon archive does not contain template.xml")

    xml_bytes = strip_addon_records(files[template_key])
    prefix = template_key[: -len("template.xml")]  # e.g. "PTLaunchPad/"

    def _read(name: str) -> bytes | None:
        return files.get(prefix + name)

    name_map, actual_locale = _resolve_locale_bytes(locale, _read)
    title, version, guid = _parse_metadata(_read("info.json"), _read("info_en.json"))
    icon_bytes = _read("icon.png") or b""

    return AddonPackage(
        xml_bytes=xml_bytes,
        name_map=name_map,
        addon_title=title,
        addon_version=version,
        addon_guid=guid,
        addon_locale=actual_locale,
        icon_bytes=icon_bytes,
    )


def parse_addon_folder(path: Path, locale: str = "en") -> AddonPackage:
    """Build an AddonPackage from an extracted addon folder on disk.

    Accepts the addon folder itself or a parent directory containing a single
    addon subfolder. Locale falls back to 'en' when the requested locale is absent.
    """
    path = Path(path)
    template_path = path / "template.xml"
    if not template_path.exists():
        for sub in path.iterdir():
            if sub.is_dir():
                candidate = sub / "template.xml"
                if candidate.exists():
                    template_path = candidate
                    path = sub
                    break
    if not template_path.exists():
        raise FileNotFoundError(f"template.xml not found in {path}")

    xml_bytes = strip_addon_records(template_path.read_bytes())
    name_map, actual_locale = _resolve_locale(
        path, locale, lambda p: p.read_bytes() if p.exists() else None
    )

    def _read(name: str) -> bytes | None:
        p = path / name
        return p.read_bytes() if p.exists() else None

    title, version, guid = _parse_metadata(_read("info.json"), _read("info_en.json"))
    icon_bytes = _read("icon.png") or b""

    return AddonPackage(
        xml_bytes=xml_bytes,
        name_map=name_map,
        addon_title=title,
        addon_version=version,
        addon_guid=guid,
        addon_locale=actual_locale,
        icon_bytes=icon_bytes,
    )


def inspect_addon_xar(source: "Path | str | bytes") -> tuple[str, str]:
    """Metadata-only read of a .fmaddon: return (title, guid) without parsing template.xml.

    Drives the intake pre-scan — we only need the addon's internal display name.
    Extracts just info.json + info_en.json from the XAR (the large template.xml
    and records files are never touched).
    """
    if isinstance(source, (str, Path)):
        fobj: io.IOBase = open(source, "rb")
        close_after = True
    else:
        fobj = io.BytesIO(source)
        close_after = False
    try:
        files = _xar_read(fobj, include_only_basenames={"info.json", "info_en.json"})
    finally:
        if close_after:
            fobj.close()

    def _read(name: str) -> bytes | None:
        return next((v for k, v in files.items() if k.endswith(name) or k == name), None)

    title, _version, guid = _parse_metadata(_read("info.json"), _read("info_en.json"))
    return title, guid


# ── Internal helpers ──────────────────────────────────────────────────────────

def _resolve_locale(
    folder: Path, locale: str, reader  # reader: Path -> bytes | None
) -> tuple[dict[str, str], str]:
    for try_locale in _locale_candidates(locale):
        raw = reader(folder / f"{try_locale}.xml")
        if raw is not None:
            return parse_locale_xml(raw), try_locale
    return {}, ""


def _resolve_locale_bytes(
    locale: str, reader  # reader: name -> bytes | None
) -> tuple[dict[str, str], str]:
    for try_locale in _locale_candidates(locale):
        raw = reader(f"{try_locale}.xml")
        if raw is not None:
            return parse_locale_xml(raw), try_locale
    return {}, ""


def _locale_candidates(locale: str) -> list[str]:
    """Return locale candidates in preference order: requested first, 'en' fallback."""
    candidates = [locale]
    if locale != "en":
        candidates.append("en")
    return candidates


# ── redistribution: XAR → portable ZIP ────────────────────────────────────────────

# A fixed, valid DOS timestamp for every generated entry (1980-01-01 00:00:00 — the ZIP epoch).
# Determinism is the point: the same source bytes must yield the same ZIP bytes on every request and
# on every platform, so nothing about the serving host leaks into a downloaded file and nothing
# changes between two downloads of an unchanged add-on.
# ── retired: xar_addon_to_zip (packet 1257) ──────────────────────────────────────────────────
# The `.fmaddon` → single-folder ZIP conversion is gone with the assumption it encoded: that the
# download is ONE top-level folder re-derived by extracting the XAR. The distribution is now a
# PAIR — the byte-exact `.fmaddon` plus the add-on folder as committed — assembled from placed
# bytes in `app/web/routes/api/addons.py`. Re-deriving the folder here would have served
# something that merely resembles the committed one.
#
# The XAR READER stays: `_xar_read` / `parse_addon_xar` / `parse_addon_folder` / `inspect_addon_xar`
# are what ingestion uses to read an add-on a user uploads. Only the redistribution writer went.
