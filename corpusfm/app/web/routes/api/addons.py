"""Addon download API — serves the paired CORPUSfm_ADDON distribution as one portable ZIP.

Filesystem addon discovery/import was removed with the standalone surface (co-located,
MCP-centric product); addons are imported through the normal upload path.

**The download carries BOTH halves of the distribution** (packet 1257), because a recipient needs
both and they are two different things:

- ``CORPUSfm_ADDON.fmaddon`` — the package FileMaker installs, served byte-exact from the bytes the
  installer placed. It is a XAR archive, which Windows Explorer and macOS Finder cannot open.
- ``CORPUSfm_ADDON/`` — the uncompressed add-on folder FileMaker Pro loads from the workstation's
  ``AddonModules`` directory, shipped as committed rather than re-derived.

Both are placed under ``<install root>/assets/addon`` by the installer from the pinned asset
repository; this route only assembles them. It deliberately does NOT extract the ``.fmaddon`` to
produce the folder — the folder is a committed artifact with its own bytes, and re-deriving it here
would serve something that merely resembles it.
"""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from corpusfm.app.web.auth import require_auth

log = logging.getLogger("corpusfm.addons")
router = APIRouter()

_ADDON_SOURCE_NAME = "CORPUSfm_ADDON.fmaddon"
_ADDON_ROOT_DIR = "CORPUSfm_ADDON"
_ADDON_DOWNLOAD_NAME = "CORPUSfm_ADDON.zip"

# The ZIP carries exactly these two top-level members. Stated once, asserted by the route and by its
# tests, so "what a correct download looks like" has one definition.
REQUIRED_TOP_LEVEL = (_ADDON_SOURCE_NAME, _ADDON_ROOT_DIR)

# Deterministic ZIP fields — the same placed bytes always produce the same download, so a served
# package can be digest-compared against the one the release gate inspected.
_FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)


def _addon_dir() -> Path:
    """``<install root>/assets/addon`` — the ONE place the distribution is read from.

    Resolved through the lifecycle authority that names the install root, rather than a second
    heuristic. There is deliberately NO fallback to a copy under the web-static tree, and none to
    the checkout: a second independently-replaceable source is exactly how the old download came to
    serve a stale add-on carrying a different GUID from the one in the repository.

    It read the CHECKOUT's ``addon/`` until packet 1257 moved the payload out of ``src/``, because
    installer-placed assets inside a Git checkout are untracked content that a privileged update
    refuses."""
    from corpusfm.lifecycle import app_paths
    return app_paths.assets_dir() / "addon"


def _paired_sources(base: Path) -> "tuple[Path, Path] | None":
    """(package, folder) when BOTH halves are present, else None — never a partial download."""
    package = base / _ADDON_SOURCE_NAME
    folder = base / _ADDON_ROOT_DIR
    if package.is_file() and folder.is_dir():
        return package, folder
    return None


def build_paired_zip(package: Path, folder: Path) -> bytes:
    """The paired distribution: the byte-exact ``.fmaddon`` plus every file of the add-on folder.

    Sorted and fixed-stamped so the bytes are reproducible. Files only — the folder is flat plus
    whatever FileMaker emitted, and directory entries carry no content a recipient needs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        members = [(_ADDON_SOURCE_NAME, package)]
        members += sorted(
            ((f"{_ADDON_ROOT_DIR}/{p.relative_to(folder).as_posix()}", p)
             for p in folder.rglob("*") if p.is_file()),
            key=lambda t: t[0],
        )
        for name, src in members:
            info = zipfile.ZipInfo(name, date_time=_FIXED_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 0
            z.writestr(info, src.read_bytes())
    return buf.getvalue()


@router.get("/addon/download", dependencies=[Depends(require_auth)])
async def download_addon():
    sources = _paired_sources(_addon_dir())
    if sources is None:
        return JSONResponse({"error": "Addon distribution not found."}, status_code=404)
    try:
        data = await run_in_threadpool(lambda: build_paired_zip(*sources))
    except Exception:
        # A partial ZIP is never served — a package missing files would fail confusingly inside
        # FileMaker rather than here. The detail goes to the log, not to the response.
        log.exception("addon download: paired package assembly failed")
        return JSONResponse({"error": "The add-on package could not be assembled."}, status_code=500)
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{_ADDON_DOWNLOAD_NAME}"'})
