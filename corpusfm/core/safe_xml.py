"""Hardened XML parsing — a drop-in for ``xml.etree.ElementTree``.

FM schema XML, addon XAR payloads, and pasted FMObjectList clips are externally
supplied input. Raw ElementTree parsing is exposed to entity-expansion ("billion
laughs") and external-entity (XXE) attacks — a few-KB file can expand to gigabytes
of memory, and a size cap on the upload does NOT defend against it. ``defusedxml``
forbids internal/external entity expansion at parse time, which closes both vectors.

Use this module anywhere XML is *parsed*: ``from corpusfm.core import safe_xml as ET``.
The whole stdlib ElementTree surface is re-exported unchanged (``Element``,
``SubElement``, ``tostring``, ``register_namespace``, …) — building XML is not a
parsing risk — and only the parsers (``fromstring``/``parse``/``iterparse``/``XML``)
are swapped for the hardened forms. FM exports never declare DTDs or custom entities,
so this is transparent for every real input (the golden corpus validates that).

``defusedxml`` is pinned in requirements, so its absence is exceptional. Because XML parsing
is now part of the security boundary, **server mode fails closed** if it is missing — every
process that imports this module (web, scheduler, MCP, CLI) refuses to start rather than run
unhardened in production (a worse failure than refusing to start). A dev / standalone run
degrades to the stdlib parsers with a loud warning, which is humane for from-source work.
Re-running ``install.sh`` rebuilds the venv from ``requirements-server.txt``, so a deployed box
should never reach the fallback.
"""

from __future__ import annotations

# Re-export the full stdlib surface (builders, classes, helpers, ParseError).
from xml.etree.ElementTree import *  # noqa: F401,F403

try:
    # Hardened parsers: forbid_entities/forbid_external default True ⇒ billion-laughs and
    # XXE are rejected at parse time. forbid_dtd stays False (FM XML has no DTD anyway).
    from defusedxml.ElementTree import (  # noqa: F401
        fromstring,
        parse,
        iterparse,
        XML,
        EntitiesForbidden,
        DTDForbidden,
        ExternalReferenceForbidden,
    )

    XML_HARDENED = True
except Exception:  # pragma: no cover - defusedxml is a pinned dependency
    from xml.etree.ElementTree import fromstring, parse, iterparse, XML  # noqa: F401

    XML_HARDENED = False
    _MSG = (
        "defusedxml is unavailable — XML parsing is NOT hardened against entity-expansion/XXE. "
        "It is pinned in requirements; reinstall it (re-running install.sh rebuilds the venv)."
    )
    # Fail-closed in server mode: refuse to run unhardened in production. The config import lives
    # here (the exceptional path only) so the normal hardened path stays import-light and cycle-free.
    try:
        from corpusfm.config import is_server_mode as _is_server_mode

        _server = _is_server_mode()
    except Exception:
        _server = False
    if _server:
        raise RuntimeError("FAIL-CLOSED: " + _MSG)
    import logging as _logging

    _logging.getLogger(__name__).warning(_MSG)
