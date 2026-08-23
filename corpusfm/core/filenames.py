"""Canonical FM file-name normalization.

FileMaker is loose about the `.fmp12` suffix — the same file is referenced sometimes
as ``Foo`` and sometimes as ``Foo.fmp12`` (root File= attribute, external data source
paths, cross-file script references). The project standard is to normalize UP: an FM
file name ALWAYS carries the suffix. Filling in the blank for every FM file we encounter
makes every file-to-file comparison match regardless of how FM happened to store it, and
introduces no new conflict (a name collision would exist with or without the suffix).

Use :func:`ensure_fmp12` wherever a value is known to be an FM file name (the file's own
identity, a resolved external-data-source target, a cross-file Perform Script target).
Do NOT apply it to arbitrary path strings from script steps or calculations that we
can't confirm are FileMaker files — those pass through unchanged.
"""
from __future__ import annotations

_SUFFIX = ".fmp12"


def ensure_fmp12(name: str) -> str:
    """The canonical form of an FM file name — always with the .fmp12 suffix.

    Idempotent and case-insensitive on the existing suffix. Empty stays empty (so a
    missing/absent name is never turned into a bare ".fmp12")."""
    n = (name or "").strip()
    if not n:
        return n
    return n if n.lower().endswith(_SUFFIX) else n + _SUFFIX


def strip_fmp12(name: str) -> str:
    """The bare FM file name without a trailing .fmp12 — the inverse of ensure_fmp12.

    Kept for the rare consumer that needs a suffix-free basename; ensure_fmp12 is the
    standard for anything user-facing or used as a match key."""
    n = (name or "").strip()
    return n[: -len(_SUFFIX)] if n.lower().endswith(_SUFFIX) else n


def primary_name_from_filename(name: str) -> str:
    """The artifact PRIMARY name = a filename's bare stem (the final suffix dropped).

    The naming doctrine (2026-06-29): the primary/headline name is the SOURCE FILENAME with
    its suffix removed — ``Contacts.xml`` → ``Contacts``, ``foo.artifact`` → ``foo``,
    ``Pkg.fmaddon`` → ``Pkg``, ``Sales.fmp12`` → ``Sales``. This is extrinsic metadata stored
    in storage meta (never in the artifact bytes / content hash).

    DISTINCT from :func:`ensure_fmp12` (the INTRINSIC internal-name normalizer that keeps/adds
    .fmp12) — NEVER cross them: the stem rule is the primary-name rule only. A name with no
    extension passes through unchanged; an empty name stays empty.

    **One COMPOUND suffix is recognised: ``.artifact.zip``** (packet 1226). Dropping only the final
    suffix would stem ``Contacts.artifact.zip`` to ``Contacts.artifact``, so re-importing a
    downloaded artifact would name the record ``Contacts.artifact`` — breaking the round trip the
    doctrine exists to hold (download names by the primary; re-import reads the primary back). It is
    special-cased rather than generalised to "drop every suffix" because a real FileMaker name may
    legitimately contain dots."""
    n = (name or "").strip()
    if not n:
        return n
    if n.lower().endswith(".artifact.zip"):
        return n[:-len(".artifact.zip")]
    dot = n.rfind(".")
    # Only strip a real trailing extension (a dot that isn't the first char and has chars after).
    if 0 < dot < len(n) - 1:
        return n[:dot]
    return n
