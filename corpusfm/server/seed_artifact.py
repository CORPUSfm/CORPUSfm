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


def _prepare_one(path: Path, label: str):
    """The LOCAL half of seeding one shipped file: read the bytes, parse the envelope, validate it.

    Returns the reabsorb payload, or ``None`` when this seed DECLINES for a local/data reason — the
    asset is not shipped, its bytes cannot be read, it is not a CORPUSfm artifact, or it fails
    reabsorb validation. Every one of those is a fact about a file on this machine and requires no
    successful database assertion, which is precisely what makes them nonfatal (packet 1361-01,
    round 4). It performs no database operation of any kind, so nothing it swallows can be one.
    """
    from corpusfm.ingestion.reabsorb import parse_uploaded_envelope, validate_reabsorb_payload
    try:
        if not path.exists():
            log.debug("seed artifact not shipped at %s — skipping", path)
            return None
        raw = path.read_bytes()
    except OSError:
        log.warning("seed artifact %s could not be read from disk — skipping", path, exc_info=True)
        return None
    try:
        payload = parse_uploaded_envelope(path.name, raw)
    except Exception:                                       # noqa: BLE001 - a malformed bundled file
        log.warning("seed artifact %s could not be parsed — skipping", path.name, exc_info=True)
        return None
    if payload is None or payload.kind != "schema" or payload.artifact is None:
        log.warning("seed artifact %s could not be read as a CORPUSfm artifact — skipping", path.name)
        return None
    try:
        ok, reason = validate_reabsorb_payload(payload)
    except Exception:                                       # noqa: BLE001 - a malformed bundled file
        log.warning("seed artifact %s could not be validated — skipping", path.name, exc_info=True)
        return None
    if not ok:
        log.warning("seed artifact %s failed reabsorb validation (%s) — skipping", path.name, reason)
        return None
    return payload


def _reabsorb_one(backend, path: Path, label: str) -> str:
    """Reabsorb one shipped seed file. Returns its uuid, or "" when the seed DECLINED locally.

    **The store call is deliberately unguarded** (packet 1361-01, round 4): a write that FAILS is a
    database failure, not a skipped seed, and the caller stops the startup attempt on it. Every
    local/data condition is decided by :func:`_prepare_one` before a byte reaches the substrate.
    """
    payload = _prepare_one(path, label)
    if payload is None:
        return ""
    meta = backend.store_artifact(payload.artifact, label=label, origin="Seed")
    log.info("seeded default artifact %s -> %s", label, meta.uuid)
    return meta.uuid


def seed_default_artifacts(backend) -> dict:
    """Reabsorb every shipped seed artifact — but ONLY when the catalog is empty of all artifacts.

    Returns ``{"ok", "seeded", "declined", "read_failed", "write_failed", "reason"}``, and it still
    never raises. What changed in packet 1361-01 round 4 is that it no longer LIES: it used to answer
    ``[]`` for every outcome, so "the catalog already has artifacts", "the assets are not shipped",
    "I could not read STORAGE" and "I could not write the seed" were one answer. The last two are
    database failures and the startup authority stops the attempt on either; the first two are local
    facts and stay nonfatal.

    * ``read_failed`` — the empty-catalog gate could not be established. It must NOT seed on that
      (an unreadable catalog is not an empty one, and seeding into a corpus that already has work is
      the outcome the gate exists to prevent), and it must not report success either.
    * ``write_failed`` — a prepared, validated seed could not be stored. Seeding STOPS there rather
      than trying the next file: the substrate is not answering, and three more writes against it
      are three more failures, not three more chances.
    * ``declined`` — the local/data conditions listed on :func:`_prepare_one`.
    """
    out = {"ok": False, "seeded": [], "declined": [], "read_failed": False,
           "write_failed": False, "reason": ""}
    try:
        paths = seed_artifact_paths()
    except Exception as exc:                                # noqa: BLE001 - the asset root is local
        out["ok"] = True
        out["reason"] = f"the seed asset root could not be resolved: {type(exc).__name__}: {exc}"
        log.warning("seed: %s — nothing to seed", out["reason"])
        return out

    # Empty-catalog gate — the only reason to seed, and the one read this function performs.
    try:
        empty = catalog_is_empty(backend)
    except Exception as exc:                                # noqa: BLE001
        out["read_failed"] = True
        out["reason"] = f"the empty-catalog gate could not be read: {type(exc).__name__}: {exc}"
        log.warning("seed: the catalog could not be inspected; nothing was seeded", exc_info=True)
        return out
    if not empty:
        out["ok"] = True
        out["reason"] = "the catalog already holds artifacts"
        return out

    for path, label in paths:
        try:
            uuid = _reabsorb_one(backend, path, label)
        except Exception as exc:                            # noqa: BLE001
            out["write_failed"] = True
            out["reason"] = f"seeding {label} could not be stored: {type(exc).__name__}: {exc}"
            log.error("seed: %s — seeding STOPS here", out["reason"], exc_info=True)
            return out
        if uuid:
            out["seeded"].append(uuid)
        else:
            out["declined"].append(str(path))
    out["ok"] = True
    return out
