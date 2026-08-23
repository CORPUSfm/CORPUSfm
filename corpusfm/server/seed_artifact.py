"""Seed the default example artifacts — CORPUSfm's own infrastructure schemas.

A fresh catalog has nothing for MCP, testing, or a demo to operate on. This ships pre-built ``.artifact``
files of CORPUSfm's own FileMaker files — the storage DB and the addon — and reabsorbs them on startup
ONLY when the catalog is empty of all artifacts. Each is a SaveAsXML artifact, deliberately WITHOUT
summaries or a vector index.

- **Empty-catalog gate** — the seed fills a *fresh* catalog only; a catalog with any other artifact is
  left untouched, so deleting a seed while keeping other work never makes it return.
- **Self-healing** — a truly empty catalog is re-seeded on the next restart (a reliable fixture).
- **origin="Seed"** — identifiable in the catalog; no enrichment.

The reabsorb path (``parse_uploaded_envelope`` → ``validate_reabsorb_payload`` → store) is reused unchanged,
so a seed goes through the same validation as any user-imported ``.artifact``.
"""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("corpusfm.seed_artifact")

# Each seed = (asset-root-relative dir, filename, display label). All are CORPUSfm's own files,
# placed by the installer. The four default artifacts: the storage-DB schema, plus the addon in its
# three lenses (SaveAsXML / AddonXML / MergedXML — same root, distinguished by type). The label is
# the PRIMARY name; the type badge disambiguates the three addon lenses.
_SEED_ARTIFACTS = (
    ("db", "CORPUSfm_DB.artifact", "CORPUSfm_DB"),
    ("addon", "CORPUSfm_ADDON_SaveAsXML.artifact", "CORPUSfm_ADDON"),
    ("addon", "CORPUSfm_ADDON_AddonXML.artifact", "CORPUSfm_ADDON"),
    ("addon", "CORPUSfm_ADDON_MergedXML.artifact", "CORPUSfm_ADDON"),
)


def _asset_root() -> Path:
    """``<install root>/assets`` from the lifecycle authority — never derived from this package.

    It used to be the CHECKOUT root (`corpusfm.__file__`'s grandparent), which is what put the
    payload inside `src/` and made a privileged update refuse it as untracked content. Asking the
    installation where its assets are keeps one answer: the manifest names the install root, and
    the asset tree is a fixed sibling of the checkout beneath it.
    """
    from corpusfm.lifecycle import app_paths
    return app_paths.assets_dir()


def seed_artifact_paths() -> "list[tuple[Path, str]]":
    """[(path, label), …] for every shipped seed artifact, resolved against the asset root."""
    root = _asset_root()
    return [(root / d / fn, label) for (d, fn, label) in _SEED_ARTIFACTS]


def catalog_is_empty(backend) -> bool:
    """True only if the catalog holds NO artifacts. One bounded engine read (top-1, under the
    Type visibility fence) on an engine backend — never a full STORAGE scan at boot;
    engine-less doubles keep the listing. Runs once per startup, not per request. Raises on a
    read failure so the caller can fail SAFE (never seed a catalog it couldn't inspect)."""
    eng = getattr(backend, "engine", None)
    if eng is not None:
        from corpusfm.artifact.capabilities import VISIBLE_TYPES
        rows, _ = eng.page("STORAGE", isin={"Type": sorted(VISIBLE_TYPES)}, per_page=1)
        return not rows
    return backend.count_artifacts() == 0


def _reabsorb_one(backend, path: Path, label: str) -> str:
    """Reabsorb one shipped seed file. Returns its rel_path, or "" if skipped (missing/invalid)."""
    if not path.exists():
        log.debug("seed artifact not shipped at %s — skipping", path)
        return ""
    from corpusfm.ingestion.reabsorb import parse_uploaded_envelope, validate_reabsorb_payload
    payload = parse_uploaded_envelope(path.name, path.read_bytes())
    if payload is None or payload.kind != "schema" or payload.artifact is None:
        log.warning("seed artifact %s could not be read as a CORPUSfm artifact — skipping", path.name)
        return ""
    ok, reason = validate_reabsorb_payload(payload)
    if not ok:
        log.warning("seed artifact %s failed reabsorb validation (%s) — skipping", path.name, reason)
        return ""
    meta = backend.store_artifact(payload.artifact, label=label, origin="Seed")
    log.info("seeded default artifact %s -> %s", label, meta.uuid)
    return meta.uuid


def seed_default_artifacts(backend) -> "list[str]":
    """Reabsorb every shipped seed artifact — but ONLY when the catalog is empty of all artifacts.

    Returns the rel_paths seeded (possibly empty). NEVER raises — a seed failure must not break startup.
    """
    try:
        # Empty-catalog gate — the only reason to seed. Fail SAFE on a read error (don't seed).
        try:
            if not catalog_is_empty(backend):
                return []
        except Exception:
            log.debug("seed: catalog readability check failed — skipping", exc_info=True)
            return []
        seeded = []
        for path, label in seed_artifact_paths():
            try:
                rel = _reabsorb_one(backend, path, label)
                if rel:
                    seeded.append(rel)
            except Exception:
                log.warning("seeding %s failed (non-fatal)", label, exc_info=True)
        return seeded
    except Exception:
        log.warning("seeding the default artifacts failed (non-fatal)", exc_info=True)
        return []
