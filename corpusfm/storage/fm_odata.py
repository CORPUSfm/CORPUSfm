"""FileMaker OData v4 storage backend — generic-substrate edition.

The FM file is a frozen generic substrate (see :mod:`corpusfm.storage.fm_registry`):
identical tables ``TABLE0``–``TABLE9`` + infra ``SETTING``/``GLOBAL``/``CORPUSfm``.
Logical entities (STORAGE, JOB, QUEUE, TAG, STORAGELINK, HISTORY) map onto those
generic tables via the registry; nothing in this file hardcodes a physical table
name except through :meth:`_phys`.

All data is written via ``JSONOfRecord`` (one editable text field per record) — the
canonical payload. Fields we ``$filter``/``$orderby`` on server-side are ALSO
written into stored+indexed typed slots (``TextFieldN``/``NumberFieldN``), projected
from ``JSONOfRecord`` by the registry — JSONOfRecord itself is opaque and not
indexable. The FM graph is empty by design: a related row is found by MATCHING SLOTS at query time,
composed in Python from keyed/indexed reads. (This line said "``$crossjoin`` on slots" until packet
1210 measured that nothing has ever issued one — see ``fm_registry``'s header for why the slot design
still stands and what ``$crossjoin`` would cost.)

Read pattern:  GET ?$select=UUID,JSONOfRecord → json.loads → JSONOfRecord dict.
  The ``RecordAsJSON`` wrapper calc was REMOVED from the schema (2026-06-21): it was a
  per-row calc (~20× slower than the raw field — live 14ms vs 298ms / 500 rows) that only
  re-wrapped JSONOfRecord, so every read selects the raw stored field directly.
  Filtering/sorting uses the indexed slots. (``_parse_jor`` still accepts a RecordAsJSON
  wrapper defensively, though the schema no longer emits one.)
Write pattern: PATCH/POST {UUID, JSONOfRecord: json.dumps(data), <indexed slots>}

Container fields — raw binary, NOT base64-in-JSON:
  Download: GET   /<table>('{uuid}')/{Field}/$value          → response body bytes
  Upload:   PATCH /<table>('{uuid}')/{Field}/$value (octet-stream + short filename)
  (base64-text in a container makes FM reflect the blob into the Content-Disposition
  filename header on read, overflowing Apache's 8 KB ResponseFieldSize → 502.)
"""
from __future__ import annotations

import io
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import threading

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import quote as _quote

from corpusfm.artifact.capabilities import VISIBLE_TYPES as _VISIBLE_TYPES
from corpusfm.storage import fm_registry as reg
from corpusfm.storage.local import ArtifactMeta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# (connect, read) seconds injected on EVERY FM OData call that doesn't set its own. Without a timeout a
# stalled FMS/proxy connection blocks the calling thread FOREVER — which wedged an import-queue worker
# (multi-threaded FM writes) with no recovery and no logged error (packet 055 live debugging). `read` is
# the max inactivity between bytes, NOT total transfer, so a large-but-progressing store (a 146 MB source
# XML takes ~40s) is unaffected; only a truly stalled socket trips it.
_FM_HTTP_TIMEOUT = (15, 300)


class SettingsWriteNotDispatched(RuntimeError):
    """A SETTING write failed BEFORE any request that could change the record was sent (packet
    1190-02) — the fetch failed, or the record carries no ``@editLink``. This is the ONLY proof of
    non-commit available on this path: once a PATCH/POST is dispatched, a failure here cannot
    distinguish "never landed" from "landed and the response was lost", so the caller rereads."""


class _TimeoutSession(requests.Session):
    """A requests.Session that injects a default timeout on every request. All get/post/patch/delete
    funnel through Session.request(), so one override covers the whole backend's ~40 call sites."""

    def request(self, method, url, **kwargs):  # type: ignore[override]
        kwargs.setdefault("timeout", _FM_HTTP_TIMEOUT)
        return super().request(method, url, **kwargs)


def _fm_retry() -> Retry:
    """Transient-failure retry for the FM OData channel — dev/staging boxes and a co-located FMS get
    502/503/504 blips (we saw a 502 live). Retried methods are PURE READS ONLY (GET/HEAD/OPTIONS): a
    POST/PATCH/DELETE must NEVER auto-retry on a received response — a 502 *after* the write landed would
    double-write (packet 056 HARD CONSTRAINT). Write idempotency is the app's job (
    upsert); a failed write surfaces cleanly and the user/job re-runs it."""
    return urllib3.util.retry.Retry(
        total=3, connect=3, read=3, status=3, backoff_factor=0.5,
        status_forcelist=(502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        raise_on_status=False,
    )


def _build_session(auth, verify_ssl: bool) -> _TimeoutSession:
    """One FM OData session: default timeout + a read-only retry adapter + a pool sized for the worker
    pool. Built PER THREAD (see `FileMakerODataBackend._session`) so concurrent import/enrich/web callers
    never share a single `requests.Session` — which is not safe for concurrent use and wedged the import
    queue in packet 055."""
    s = _TimeoutSession()
    s.auth = auth
    s.verify = verify_ssl
    s.headers.update({"Accept": "application/json"})
    adapter = HTTPAdapter(max_retries=_fm_retry(), pool_connections=16, pool_maxsize=16)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def _slot_lit(value) -> str:
    """A text-SLOT `$filter` literal: LOWERCASED + single-quote-doubled. Slot values are
    CF-lowercased and FM's `eq`/`ne` are case-sensitive (FQL semantics, box-proven
    2026-07-04), so every handwritten text-slot comparison must lower its comparand — a
    mixed-case literal silently matches nothing (and `ne` over-matches). NOT for the native
    ``UUID`` record-key field (not a slot, not CF-processed — compare exact)."""
    return str(value).lower().replace("'", "''")


def _parse_jor(record: dict, *, strict: bool = False) -> tuple[str, dict]:
    """Return (uuid_str, jor_dict) from a raw OData record.

    Prefers the raw ``JSONOfRecord`` field (``$select=UUID,JSONOfRecord``) — a plain
    stored Text field, cheap to read. ``RecordAsJSON`` (a per-row wrapper calc) was
    REMOVED from the schema; the wrapper form is still accepted defensively as a fallback.
    ``JSONOfRecord`` may arrive as a JSON string or an already-parsed dict.

    ``strict`` RAISES on a payload that is PRESENT but does not yield a record, instead of yielding
    ``{}``. Without it a malformed blob is indistinguishable from a legitimately empty one — and the
    caller that needs the difference (an authoritative settings read, packet 1189) cannot recover it
    afterwards, because ``json.dumps({})`` and a corrupt string both arrive as a non-empty str and both
    leave as ``{}``.

    "Does not yield a record" is deliberately WIDER than "json.loads threw" (review round 3): valid JSON
    that is not an object — ``[]``, ``null``, ``"text"``, ``42`` — is just as unreadable as a syntax
    error, and an earlier version silently turned each into ``{}`` and therefore into "absent". The
    ``RecordAsJSON`` wrapper is held to the same rule; it too used to swallow its own parse failure.
    """
    def _as_dict(v):
        if isinstance(v, str):
            if not v.strip():
                return {}          # never written, or blanked — absent, not malformed
            try:
                parsed = json.loads(v)
            except Exception:
                if strict:
                    raise
                return {}
            if isinstance(parsed, dict):
                return parsed
            if strict:
                raise ValueError(f"payload parsed to {type(parsed).__name__}, not an object")
            return {}
        if isinstance(v, dict):
            return v
        if strict and v is not None:
            raise ValueError(f"payload is a {type(v).__name__}, not an object")
        return {}

    if "JSONOfRecord" in record:
        return record.get("UUID", ""), _as_dict(record.get("JSONOfRecord"))

    outer: dict = {}
    raw_wrapper = record.get("RecordAsJSON")
    if strict and raw_wrapper is not None and not isinstance(raw_wrapper, (str, dict)):
        # `or ""` below erases a FALSY non-object wrapper (False, 0, []) before any check could see
        # it, so those resolved to "absent" — i.e. Standard — under strict (review round 4). Type
        # first, coercion after.
        raise ValueError(f"RecordAsJSON wrapper is a {type(raw_wrapper).__name__}, not an object")
    raw = raw_wrapper or ""
    if isinstance(raw, dict):
        outer = raw
    elif raw:
        try:
            outer = json.loads(raw)
        except Exception:
            if strict:
                raise
        if not isinstance(outer, dict):
            if strict:
                raise ValueError("RecordAsJSON wrapper is not an object")
            outer = {}
    record_uuid = outer.get("UUID") or record.get("UUID", "")
    return record_uuid, _as_dict(outer.get("JSONOfRecord", {}))


class FileMakerODataBackend:
    """StorageBackend implementation backed by a FileMaker database via OData v4."""

    def __init__(
        self,
        host: str,
        database: str,
        username: str,
        password: str,
        *,
        verify_ssl: bool = False,
    ) -> None:
        self._base_url = f"https://{host}/fmi/odata/v4/{database}"
        self._auth = (username, password)
        self._verify_ssl = verify_ssl
        # One requests.Session PER THREAD. The single shared Session used before packet 056 was not safe
        # for the concurrent import/enrich/web callers and wedged the import queue; a thread-local session
        # gives each worker its own connection pool + retry adapter with no lock and no shared mutable state.
        self._thread_local = threading.local()

    @property
    def _session(self) -> _TimeoutSession:
        s = getattr(self._thread_local, "session", None)
        if s is None:
            s = _build_session(self._auth, self._verify_ssl)
            self._thread_local.session = s
        return s

    @property
    def archive_dir(self) -> "Path":
        """Local directory for DERIVED, best-effort files on the server path — summary sidecars, the
        discovery/apply-metrics logs, generated history HTML. Nothing authoritative lives here: the
        durable copies are FM containers (packet 085/086 — patches and clips are STORAGE deliverables),
        so a summary sidecar is a cache `load_summaries` rebuilds on demand.

        On a published installation this is `<state_dir>/archive` and nothing else (packet
        1246-03-01). A configured `archive_dir` is honoured **in development only** — a stored
        setting that moves machine-owned state on a real box is an alternate path authority, and it
        worked even when the installation's own record could not be read.

        Two bugs lived here until 2026-07-15, and both are worth not re-introducing:
          * it hardcoded `Path.home()/"src"/"archive"` — a path related to nothing, and the only
            non-`.corpusfm` home path in the codebase.
          * it **mkdir()'d inside the getter**, so merely READING the attribute created a directory. A
            network-free unit test (test_storage_parity) was therefore writing real files into the
            developer's home on every suite run — found by the dev spotting a stray directory, not by the
            suite. Creation now belongs to the WRITERS; reading this is free of side effects.

        NB `LocalBackend`'s default is deliberately different (`<project>/archive`): that is the dev/test
        path, where the project dir IS the working dir. This one is the server path, where the project
        dir can be inside site-packages.
        """
        from pathlib import Path
        from corpusfm.lifecycle import app_paths
        from corpusfm.storage.local import load_settings

        # DEVELOPMENT ONLY (packet 1246-03-01). A stored setting is an override like any other: on a
        # published installation the FileMaker archive/cache is machine-owned state and lives under
        # the published state directory. `expanduser()` made it worse — a stored `~/...` reached a
        # home directory by a second route, on a box that has no home-directory answer.
        configured = app_paths.development_override(
            "the stored archive_dir setting",
            lambda: (load_settings() or {}).get("archive_dir"),
            what="the FileMaker archive location")
        if configured:
            return Path(configured).expanduser()
        return app_paths.state_dir() / "archive"

    # ── Internal helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _phys(name: str) -> str:
        """Physical table occurrence for a logical entity (e.g. 'STORAGE' → 'TABLE0').

        Infra tables (SETTING/GLOBAL/CORPUSfm) and already-physical names pass through.
        """
        return reg.TABLE.get(name, name)

    def _url(self, path: str) -> str:
        return f"{self._base_url}/{path}"

    def _post_json(self, url: str, payload: dict) -> requests.Response:
        return self._session.post(
            url,
            data=json.dumps(payload, ensure_ascii=False),
            headers={"Content-Type": "application/json"},
        )

    def _patch_json(self, url: str, payload: dict) -> requests.Response:
        return self._session.patch(
            url,
            data=json.dumps(payload, ensure_ascii=False),
            headers={"Content-Type": "application/json"},
        )

    def _jor_payload(self, logical: str, jor: dict, *, record_uuid: Optional[str] = None) -> dict:
        """A write payload = JSONOfRecord (canonical) + UUID on create.

        FM-side projection (unified-artifacts §1/§8): the app writes ONLY the canonical
        ``JSONOfRecord`` (and ``UUID`` on create). The generic tables' auto-enter CF
        (CFM.TOOLS.AutoenterCalculation) re-derives every indexed slot from the pushed
        SETTING ``Calculations`` map on each commit (``alwaysEvaluate`` + ``overwriteExisting``),
        lowercasing text slots. The app has NO write access to slot fields — do not add slot
        keys here. The map must be present in SETTING (asserted at startup by storage.projections)
        before the first write, or the CF finds no calc and leaves slots empty.
        """
        payload = {"JSONOfRecord": json.dumps(jor, ensure_ascii=False)}
        if record_uuid is not None:
            payload["UUID"] = record_uuid
        return payload

    def _get_record_by_uuid(self, ref: str) -> Optional[dict]:
        """The STORAGE record ({UUID, JSONOfRecord}) for a record UUID — the canonical address
        (packet 085 U3f). A direct native-key read (rename-stable); the FileName/Timestamp rel_path
        is retired as an address (aliases resolve to a UUID at the web/MCP edge)."""
        if not ref:
            return None
        url = (
            self._url(self._phys("STORAGE"))
            + "?$filter=" + _quote(f"UUID eq '{str(ref).replace(chr(39), chr(39) * 2)}'", safe="'")
            + "&$select=UUID,JSONOfRecord&$top=1"
        )
        try:
            resp = self._session.get(url)
            resp.raise_for_status()
            values = resp.json().get("value", [])
            return values[0] if values else None
        except Exception:
            logger.debug("FM OData: _get_record_by_uuid failed for %s", ref, exc_info=True)
            return None

    def _download_container(self, record_uuid: str, field: str, table: str = "STORAGE") -> Optional[bytes]:
        """Return raw bytes from a container field, or None if empty/absent.

        ``field`` is a logical container name (ArtifactData/SourceXML/NameMapData)
        mapped to the generic ContainerFieldN per the registry; a physical name passes through.
        """
        field = reg.container_field(table, field)
        url = self._url(f"{self._phys(table)}('{record_uuid}')/{field}/$value")
        try:
            resp = self._session.get(url)
            if resp.status_code == 404 or not resp.content:
                return None
            resp.raise_for_status()
            return resp.content
        except Exception:
            logger.debug("FM OData: container download failed %s/%s", record_uuid, field, exc_info=True)
            return None

    def _upload_container(self, record_uuid: str, field: str, data: bytes, table: str = "STORAGE") -> None:
        """Upload raw binary to a container field via PATCH to /$value.

        Raw octet-stream + a fixed short filename. Must NOT use base64-in-JSON: FM then
        serves the blob back as the Content-Disposition filename, overflowing Apache's
        8 KB ResponseFieldSize → 502 on read.

        ``field`` is a logical container name mapped to the generic ContainerFieldN.
        """
        field = reg.container_field(table, field)
        url = self._url(f"{self._phys(table)}('{record_uuid}')/{field}/$value")
        resp = self._session.patch(
            url,
            data=data,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Disposition": 'attachment; filename="data.bin"',
            },
        )
        resp.raise_for_status()

    def _encrypt_blobs(self) -> bool:
        """Whether new container blobs should be Fernet-encrypted (encrypt_blobs setting)."""
        from corpusfm.app.app_config import load_app_config
        return bool(load_app_config().encrypt_blobs)

    def _meta_from_record(self, record: dict) -> ArtifactMeta:
        from corpusfm.storage.artifact_record import meta_from_jor
        record_uuid, jor = _parse_jor(record)
        return meta_from_jor(jor, uuid=record_uuid)

    @property
    def engine(self):
        """The StorageEngine view of this backend (repos + engine-keyed reads). Thin — delegates
        transport back to this backend; safe to construct per access."""
        from corpusfm.storage.engine import FMEngine
        return FMEngine(self)

    # ── StorageBackend protocol ──────────────────────────────────────────────────

    def iter_artifact_metas(self) -> "list[ArtifactMeta]":
        """Flat list of every VISIBLE_TYPES artifact meta (packet 1021 — the targeted-enumeration
        replacement for list_artifacts()'s file_name-grouped dict; the mutable/non-unique file_name is
        never a grouping key here). No grouping.

        Goes through ``engine.list_where`` (packet 1210), which fixes TWO defects this method had, and
        its old docstring claim of "one bounded $select scan" was wrong about both:

        1. **It was not filtered.** The whole of STORAGE crossed the wire so that queue and
           mid-landing rows could be discarded in Python. ``Type`` is an indexed slot, and
           ``count_artifacts`` DIRECTLY BELOW already asked the server this exact question.
        2. **It was not bounded, and it silently truncated.** It read ``resp.json()["value"]`` once
           and never followed ``@odata.nextLink``, so against a paging FM server it returned the
           first page while promising every record — the catalog would simply be missing artifacts,
           with nothing anywhere reporting a problem. This is the same defect packet 1210 fixed in
           ``list_all``; this method was missed because it issues its own request instead of using the
           engine. Using the engine is what stops that from recurring.

        The Python fence is retained as the authority on what is visible: the slot is CF-lowercased
        while ``VISIBLE_TYPES`` is mixed-case, so the query is the transport narrowing and must never
        become the definition."""
        try:
            rows = self.engine.list_where("STORAGE", isin={"Type": sorted(_VISIBLE_TYPES)})
        except Exception:
            logger.error("FM OData: iter_artifact_metas failed", exc_info=True)
            return []
        from corpusfm.storage.artifact_record import meta_from_jor
        out = [meta_from_jor(r.jor, uuid=r.key) for r in rows]
        return [m for m in out if m.artifact_type in _VISIBLE_TYPES]

    def count_artifacts(self) -> int:
        """Count of VISIBLE_TYPES artifact records (packet 1021) — a server-side indexed $count, not a
        materialized scan."""
        try:
            _, total = self.engine.page("STORAGE", isin={"Type": sorted(_VISIBLE_TYPES)},
                                        per_page=1, count=True)
            return max(0, total)
        except Exception:
            return len(self.iter_artifact_metas())

    def _delete_record_best_effort(self, record_uuid: str) -> None:
        """Compensating delete of a just-created STORAGE record when a follow-up container upload failed
        (packet 064). Best-effort — logs on failure (a failed compensate leaves a narrow orphan window,
        far better than an unconditional orphan)."""
        try:
            self._session.delete(
                self._url(f"{self._phys('STORAGE')}('{record_uuid}')")
            ).raise_for_status()
        except Exception:
            logger.error("FM OData: compensating delete failed for orphan record %s", record_uuid,
                         exc_info=True)

    def store_artifact(
        self,
        artifact,
        xml_bytes: Optional[bytes] = None,
        *,
        label: str = "",
        origin: str = "Import",
        job_uuid: str = "",
        run_uuid: str = "",
        addon_package=None,
        keep_source_xml: bool = False,
    ) -> ArtifactMeta:
        # Shared engine write path (artifact_store): staged-create → blobs → one visibility
        # commit — the publish-after-blob invariant (077-E). Supersedes the packet-064
        # compensating-delete-only model: the record is INVISIBLE until its blobs land, so a
        # mid-upload crash can no longer leave a catalog-visible row with no ArtifactData.
        from corpusfm.storage.artifact_store import store_artifact as _store
        return _store(self, artifact, xml_bytes, label=label, origin=origin,
                      job_uuid=job_uuid, run_uuid=run_uuid, addon_package=addon_package,
                      keep_source_xml=keep_source_xml)

    def store_deliverable(
        self,
        xml_bytes: bytes,
        *,
        artifact_type: str,
        origin: str,
        name: str,
        description: str = "",
        memory: str = "",
        record_uuid: str = "",
    ) -> ArtifactMeta:
        """Store a degenerate deliverable (a patch or clip) as a STORAGE record.

        ``record_uuid`` may be pre-supplied (packet 086 — the QUEUE deliverable path pre-generates it
        so the enqueue-and-wait caller knows the produced address without a post-hoc lookup).

        Canonical artifact-record/2 in JSONOfRecord + the raw XML (encrypted) in the
        shared content container (ArtifactData slot); a DELIVERABLE_TYPES member — the
        Type says it all. Synthetic identity (patch:<sha>/clip:<sha> + timestamp). See
        unified-artifacts plan §6.
        """
        import hashlib
        from corpusfm.core.crypto import compress, encode_blob

        # Prefix follows the deliverable type so fmScript/fmCalc aren't mislabeled `clip:`
        # (root_uuid is filter-only, never identity).
        _prefix = {"PatchXML": "patch", "fmClip": "clip",
                   "fmScript": "fmscript", "fmCalc": "fmcalc"}.get(artifact_type, "clip")
        digest = hashlib.sha256(xml_bytes).hexdigest()[:16]
        root_uuid = f"{_prefix}:{digest}"

        raw = (name or "").replace(".fmp12", "").strip() or _prefix
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)
        file_name = safe.strip("._-") or _prefix
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S_%f")   # UTC (packet 1005/064)
        supplied = bool(record_uuid)     # the QUEUE deliverable path pre-generates a stable uuid
        record_uuid = record_uuid or str(uuid.uuid4())
        if supplied:
            # Re-run safety (packet 1002/B): a pre-supplied uuid is stable across a Restart, so a
            # re-run must REPLACE its prior output, not 500 on the duplicate key. Drop any prior
            # attempt first (best-effort no-op when absent) — one QUEUE record → one STORAGE artifact.
            self._delete_record_best_effort(record_uuid)

        jor = {
            "Type": artifact_type,
            "PrimaryName": name,
            "FileName": file_name,
            "Origin": origin,
            "RootUUID": root_uuid,
            "ArtifactTimestamp": timestamp,
            "IsLatest": True,
            "HasSummaries": False,
            "Description": description,
            "Memory": memory,
            "FMVersion": "",
            "schema_version": "",
            "has_name_map": False,
            "gap_issues": 0,
            "gap_unmapped": [],
            "xml_bytes": len(xml_bytes),
        }
        self._post_json(
            self._url(self._phys("STORAGE")),
            self._jor_payload("STORAGE", jor, record_uuid=record_uuid),
        ).raise_for_status()

        # Raw XML into the shared content container (encoded per encrypt_blobs; reuses the
        # ArtifactData slot). Compensating delete on upload failure (packet 064) — no orphan record.
        try:
            self._upload_container(
                record_uuid, "ArtifactData",
                encode_blob(compress(xml_bytes), encrypt_on=self._encrypt_blobs()),
            )
        except Exception:
            self._delete_record_best_effort(record_uuid)
            raise

        return ArtifactMeta(
            uuid=record_uuid,
            file_name=file_name,
            timestamp=timestamp,
            path=Path(f"{file_name}/{timestamp}"),
            name=name,
            schema_version="",
            fm_version="",
            origin=origin,
            description=description,
            memory=memory,
            xml_bytes=len(xml_bytes),
            enc_bytes=0,
            root_uuid=root_uuid,
            artifact_type=artifact_type,
        )

    def load_deliverable_xml(self, record_uuid: str) -> Optional[bytes]:
        """Return a deliverable's raw XML bytes from the content container, or None. Addressed by the
        RECORD UUID (packet 085 U3f) — a rel_path resolves to nothing and returns None silently."""
        from corpusfm.core.crypto import decompress, decode_blob
        record = self._get_record_by_uuid(record_uuid)
        if record is None:
            return None
        raw = self._download_container(record["UUID"], "ArtifactData")
        if raw is None:
            return None
        try:
            return decompress(decode_blob(raw))
        except Exception:
            logger.debug("FM OData: load_deliverable_xml failed for %s", record_uuid, exc_info=True)
            return None

    # ── QUEUE workspace source staging (packet 086) ──────────────────────────────
    # An import is a [upload, land] laundry-list record (server/queue_handlers.enqueue_import) whose
    # SourceXML container holds the staged source bytes. STORAGE holds only LANDED records; the land
    # worker reads the staged source and lands it (artifact_store.land_artifact, moving the source
    # container FM-internally via CFM.SRV.MoveContainerData). The backend supplies the source READ.

    def load_staged_source(self, queue_id: str) -> Optional[bytes]:
        """Return the staged source bytes, ``None`` if genuinely absent/empty, or RAISE
        ``StagedSourceUnavailable`` on a transient transport error. The worker must be able to tell a
        transient read failure (keep + retry) from a truly-missing source (age-gate then drop), so this
        does its own transport-error-aware container read (packet 077-B)."""
        from corpusfm.core.crypto import decode_blob, decompress
        from corpusfm.storage import StagedSourceUnavailable
        cfield = reg.container_field("QUEUE", "SourceXML")
        curl = self._url(f"{self._phys('QUEUE')}('{queue_id}')/{cfield}/$value")
        try:
            cresp = self._session.get(curl)
            if cresp.status_code == 404:
                return None  # container/row absent
            cresp.raise_for_status()
            raw = cresp.content
        except Exception as exc:
            raise StagedSourceUnavailable(
                f"staged source read failed for {queue_id}: {exc}") from exc
        if not raw:
            return None  # container empty — blob not uploaded yet (in-flight) or genuinely empty
        try:
            return decompress(decode_blob(raw))
        except Exception:
            # A corrupt/undecodable blob is NOT transient — the stored bytes are bad. Return None so the
            # worker age-gates it (an aged-out unreadable row is dropped with a failure notice).
            logger.debug("FM OData: load_staged_source decode failed for %s", queue_id, exc_info=True)
            return None

    def move_container(self, src_logical: str, src_key: str, src_field: str,
                       dst_logical: str, dst_key: str, dst_field: str) -> bool:
        """Move an (already-encoded) container blob between two records FM-INTERNALLY via the
        transactional ``CFM.SRV.MoveContainerData`` script — no bytes travel through the app. The
        script clears the source and writes the target atomically (rollback on any FATAL); the app
        then VERIFIES (blob_exists on the target), per the auto-enter incident's standing rule.
        Returns True only on script Success + a present target blob."""
        import json as _json
        param = {
            "source": {"table": self._phys(src_logical), "uuid": src_key,
                       "field": reg.container_field(src_logical, src_field)},
            "target": {"table": self._phys(dst_logical), "uuid": dst_key,
                       "field": reg.container_field(dst_logical, dst_field)},
        }
        try:
            resp = self._session.post(
                self._url(f"Script.{self._MOVE_CONTAINER_SCRIPT}"),
                json={"scriptParameterValue": _json.dumps(param)},
                headers={"Content-Type": "application/json"},
                timeout=self._MOVE_TIMEOUT,
            )
            resp.raise_for_status()
            body = resp.json() if resp.content else {}
        except Exception:
            logger.warning("FM OData: MoveContainerData call failed", exc_info=True)
            return False
        sr = body.get("scriptResult") or {}
        code = str(sr.get("code", "") or "")
        result = str(sr.get("resultParameter", "") or "")
        if code not in ("", "0") or not result.startswith("Success"):
            logger.warning("FM OData: MoveContainerData did not succeed (code=%s result=%s)",
                           code, result[:160])
            return False
        # App-side verify (auto-enter lesson): a definite absence contradicts the reported Success.
        if self.engine.blob_exists(dst_logical, dst_key, dst_field) is False:
            logger.error("FM OData: MoveContainerData reported Success but the target blob is absent")
            return False
        return True

    def delete_artifact(self, rel_path: str) -> None:
        # Cascade: drop the artifact's HISTORY event mentions first (085 U3c — "no artifact,
        # no history").
        from corpusfm.server.history import purge_history_for_artifact
        purge_history_for_artifact(self, rel_path)
        record = self._get_record_by_uuid(rel_path)
        if record is None:
            return
        url = self._url(f"{self._phys('STORAGE')}('{record['UUID']}')")
        try:
            self._session.delete(url).raise_for_status()
        except Exception:
            logger.error("FM OData: delete_artifact failed for %s", rel_path, exc_info=True)
            raise

    def delete_source(self, rel_path: str) -> bool:
        """Packet 059: clear the retained compressed source XML (the SourceXML container) + flip the
        has_source JOR flag. The derived artifact is untouched. Idempotent — True if source was present."""
        record = self._get_record_by_uuid(rel_path)
        if record is None:
            return False
        uuid = record["UUID"]
        _, jor = _parse_jor(record)
        had = bool(jor.get("has_source", False))
        field = reg.container_field("STORAGE", "SourceXML")
        try:
            self._session.delete(
                self._url(f"{self._phys('STORAGE')}('{uuid}')/{field}/$value")
            ).raise_for_status()
        except Exception:
            logger.debug("FM OData: clearing SourceXML failed for %s", rel_path, exc_info=True)
        jor["has_source"] = False
        try:
            self._patch_json(self._url(f"{self._phys('STORAGE')}('{uuid}')"),
                             {"JSONOfRecord": json.dumps(jor, ensure_ascii=False)}).raise_for_status()
        except Exception:
            logger.error("FM OData: delete_source JOR patch failed for %s", rel_path, exc_info=True)
            raise
        return had

    def get_artifact_meta(self, rel_path: str) -> Optional[ArtifactMeta]:
        record = self._get_record_by_uuid(rel_path)
        if record is None:
            return None
        return self._meta_from_record(record)

    def load_record_jor(self, rel_path: str) -> dict:
        """The raw stored record dict (JSONOfRecord) — cheap, no blob; carries fields not on
        ArtifactMeta. Uniform with LocalBackend.load_record_jor."""
        record = self._get_record_by_uuid(rel_path)
        if record is None:
            return {}
        _, jor = _parse_jor(record)
        return jor or {}

    def update_record(self, rel_path: str, fields: dict) -> None:
        """Merge editable fields ({name, description, memory}) into the record's full
        JSONOfRecord (read-merge-write). FM re-projects the slots; containers untouched."""
        # Map the canonical lowercase field names to their JSONOfRecord keys. merge_parent_refs
        # is an unprojected JOR key (no slot) — preserved on read-merge-write; the merged detail
        # reads it cheaply AND resolves parents by record UUID instead of downloading the blob.
        key_map = {"name": "PrimaryName", "description": "Description", "memory": "Memory",
                   "merge_parent_refs": "MergeParentRefs",
                   # gap-badge self-heal write-back (packet 014 #5)
                   "gap_issues": "gap_issues", "gap_count_version": "gap_count_version",
                   # FileName is repair-editable (user-possessions principle): the stored name is
                   # how OTHER files' cross-file references FIND this artifact.
                   "file_name": "FileName",
                   # analyzer status re-stamp on heal (packet 1121) + the additive acceptance-case record
                   # (a dict; the JOR is opaque JSON on FM too, so nested keys ride unprojected — no slot).
                   "analyzer_failed": "analyzer_failed",
                   "acceptance_case": "AcceptanceCase"}
        editable = {key_map[k]: fields[k] for k in key_map if k in fields}
        if not editable:
            return
        record = self._get_record_by_uuid(rel_path)
        if record is None:
            return
        record_uuid, jor = _parse_jor(record)
        jor.update(editable)
        self._patch_json(
            self._url(f"{self._phys('STORAGE')}('{record_uuid}')"),
            self._jor_payload("STORAGE", jor),
        ).raise_for_status()

    def load_artifact(self, record_uuid: str):
        """Load Artifact from ArtifactData container (encrypted artifact.json.gz). Addressed by the
        RECORD UUID (packet 085 U3f)."""
        from corpusfm.artifact.types import Artifact
        from corpusfm.core.crypto import decode_blob
        record = self._get_record_by_uuid(record_uuid)
        if record is None:
            raise FileNotFoundError(f"No STORAGE record found for {record_uuid!r}")
        raw = self._download_container(record["UUID"], "ArtifactData")
        if raw is None:
            raise FileNotFoundError(f"No ArtifactData for {record_uuid!r}")
        artifact = Artifact.load_gz(io.BytesIO(decode_blob(raw)))
        # Load-time self-heal was RETIRED by packet 1062 — a stored artifact refreshes its derived
        # layers via RE-INGESTION (the canonical pipeline, from retained source), not a lazy on-load
        # re-render. Fast reads, no phantom-diff risk.
        return artifact

    def load_raw_xml(self, record_uuid: str) -> Optional[bytes]:
        """Return raw FM XML bytes from SourceXML container, or None if not stored. Addressed by the
        RECORD UUID (packet 085 U3f). A rel_path returns None SILENTLY, which reads as "no source
        retained" rather than as a bad address — pass ``meta.uuid``, never ``meta.rel_path``."""
        from corpusfm.core.crypto import decode_blob, decompress
        record = self._get_record_by_uuid(record_uuid)
        if record is None:
            return None
        raw = self._download_container(record["UUID"], "SourceXML")
        if raw is None:
            return None
        try:
            return decompress(decode_blob(raw))
        except Exception:
            logger.debug("FM OData: load_raw_xml failed for %s", record_uuid, exc_info=True)
            return None

    def load_icon(self, rel_path: str) -> Optional[bytes]:
        """The addon icon bytes (icon_b64 in the record), or None."""
        import base64
        record = self._get_record_by_uuid(rel_path)
        if record is None:
            return None
        _, jor = _parse_jor(record)
        b64 = jor.get("icon_b64", "")
        if not b64:
            return None
        try:
            return base64.b64decode(b64)
        except Exception:
            return None

    def load_name_map(self, rel_path: str) -> dict:
        """Load addon name_map from NameMapData container; returns {} when absent."""
        from corpusfm.core.crypto import decode_blob, decompress
        record = self._get_record_by_uuid(rel_path)
        if record is None:
            return {}
        raw = self._download_container(record["UUID"], "NameMapData")
        if raw is None:
            return {}
        try:
            return json.loads(decompress(decode_blob(raw)))
        except Exception:
            return {}

    def reencode_all_blobs(self, target_encrypt: bool, progress_cb=None) -> int:
        """Re-encode every STORAGE record's container blobs (ArtifactData / SourceXML /
        NameMapData) to the target form (plaintext gzip vs Fernet(gzip)). Idempotent;
        tolerates absent/empty containers. progress_cb(done, total) after each record.

        Raises ``ReencodeIncomplete`` if the listing fails or any blob could not be converted, so a
        normal return means what the caller reports it means (packet 1208)."""
        from corpusfm.core.crypto import blob_is_encrypted, decode_blob, encode_blob, is_real_blob
        from corpusfm.storage.backend import ReencodeIncomplete

        try:
            records = self.list_fm_artifact_records()
        except Exception:
            # NOT an empty successful run. Nothing was converted, and reporting "0 blobs, no error"
            # is how the setting and the store came to disagree in silence (packet 1208).
            logger.warning("FM OData: reencode_all_blobs listing failed", exc_info=True)
            raise ReencodeIncomplete(converted=0, failed=0, total=0, listed=False)

        total = len(records)
        done = 0
        converted = 0
        failed = 0
        fields = ("ArtifactData", "SourceXML", "NameMapData")
        for rec in records:
            record_uuid = rec.get("uuid", "")
            if record_uuid:
                for field in fields:
                    try:
                        raw = self._download_container(record_uuid, field)
                        # Skip absent / empty-stub containers and blobs already in target form;
                        # only real payload blobs (gzip or Fernet) get re-encoded.
                        if not is_real_blob(raw) or blob_is_encrypted(raw) == target_encrypt:
                            continue
                        payload = decode_blob(raw)
                        self._upload_container(
                            record_uuid, field, encode_blob(payload, encrypt_on=target_encrypt)
                        )
                        converted += 1
                    except Exception:
                        # Keep going — one unreadable container must not strand every later record
                        # in the old form — but COUNT it, and refuse to end normally.
                        failed += 1
                        logger.warning(
                            "FM OData: reencode_all_blobs failed on %s/%s",
                            record_uuid, field, exc_info=True,
                        )
            done += 1
            if progress_cb is not None:
                try:
                    progress_cb(done, total)
                except Exception:
                    pass
        if failed:
            raise ReencodeIncomplete(converted=converted, failed=failed, total=total)
        return converted

    # ── FM SETTING (singleton) ───────────────────────────────────────────────────

    def _get_settings_record(self, *, strict: bool = False) -> Optional[dict]:
        """Fetch the SETTING singleton record, or None if the table is empty.

        Selects the raw stored ``JSONOfRecord`` (no UUID — the singleton has no UUID
        column; writes go via ``@editLink``). RecordAsJSON was removed from the schema,
        so reads must not select it.

        ``strict`` re-raises a READ FAILURE instead of returning None, so a caller can tell it apart
        from an empty table (packet 1189). Both still return/mean None-vs-{} the same way when the
        table is genuinely empty."""
        try:
            resp = self._session.get(self._url(reg.SETTING_TABLE) + "?$select=JSONOfRecord")
            resp.raise_for_status()
            values = resp.json().get("value", [])
            if not values:
                return None                  # genuinely no record — an ANSWER
            if strict and not isinstance(values[0], dict):
                # A null or otherwise non-entity row is NOT an empty table, and returning None here
                # made the two indistinguishable — the strict caller would read "absent" and settle on
                # Standard (review round 4).
                raise ValueError("SETTING returned a row that is not an entity")
            return values[0]
        except Exception:
            if strict:
                raise
            logger.debug("FM OData: _get_settings_record failed", exc_info=True)
            return None

    def load_fm_settings(self, *, strict: bool = False) -> dict:
        """Return SETTING JSONOfRecord as a dict (snake_case AppConfig keys), or {} if absent.

        ``strict`` separates two facts this method otherwise conflates, which is the whole of packet
        1189: an ABSENT setting (an empty SETTING table — a fresh install) still returns ``{}``, but an
        UNAVAILABLE authority (the read failed, or the record is there and unparseable) RAISES instead of
        degrading to ``{}``. A security ceiling read as "absent" during an outage silently becomes the
        loosest documented default; a caller that cannot tolerate that asks for ``strict``.

        Default False on purpose — every existing consumer keeps today's swallow-and-default behavior.
        Only the browser-connection policy path opts in."""
        try:
            record = self._get_settings_record(strict=strict)
            if record is None:
                return {}                    # genuinely absent — an answer, not a failure
            # Parse STRICTLY under strict: a malformed payload raises here rather than arriving as an
            # empty dict and walking past the gate into the YAML/default fall-through — the fail-open
            # this flag exists to close. An earlier fix inferred "malformed" from an empty parse result
            # plus a non-empty raw value, which wrongly condemned the legitimate serialized empty object
            # ``"{}"`` (found by review). Parsing is the fact; emptiness is not evidence of anything.
            _, jor = _parse_jor(record, strict=strict)
            return jor
        except Exception:
            if strict:
                raise
            logger.debug("FM OData: load_fm_settings failed", exc_info=True)
            return {}

    def save_fm_settings(self, data: dict) -> None:
        """MERGE ``data`` into the SETTING singleton's JSONOfRecord via @editLink.

        Merge (not replace) so independent writers share the one record: AppConfig owns
        its snake_case keys, tags own the "tags" key.

        Failures BEFORE anything reaches the wire raise :class:`SettingsWriteNotDispatched` (packet
        1190-02). That distinction is the only proof of non-commit this method can ever offer: once a
        PATCH or POST has been dispatched its failure is ambiguous by construction — the write can
        commit on the server and still raise here — so the caller must reread rather than assume.
        """
        try:
            resp = self._session.get(self._url(reg.SETTING_TABLE))
            resp.raise_for_status()
            values = resp.json().get("value", [])
        except Exception as exc:
            logger.error("FM OData: save_fm_settings — could not fetch SETTING", exc_info=True)
            raise SettingsWriteNotDispatched(f"SETTING fetch failed: {exc}") from exc

        # Everything from here to the PATCH/POST is still PRE-DISPATCH, so a failure in it is provable
        # non-commit and must say so rather than land in the caller's ambiguous branch (packet 1190-02,
        # Codex finding 5): the merge, the serialization and the @editLink lookup all happen locally.
        try:
            if values:
                # Merge base from the stored JSONOfRecord (the no-$select GET above returns it
                # alongside @editLink). RecordAsJSON was removed from the schema — reading the
                # base from it would yield {} and CLOBBER sibling keys (tags/file_tracking/…).
                _, existing = _parse_jor(values[0])
                existing.update(data)
                jor_str = json.dumps(existing, ensure_ascii=False)
                edit_link = values[0].get("@editLink")
                if not edit_link:
                    raise SettingsWriteNotDispatched(
                        "FM OData: SETTING record has no @editLink — cannot patch.")
            else:
                jor_str = json.dumps(data, ensure_ascii=False)
                edit_link = None
        except SettingsWriteNotDispatched:
            raise
        except Exception as exc:
            raise SettingsWriteNotDispatched(f"SETTING payload could not be prepared: {exc}") from exc

        if edit_link is not None:
            resp = self._patch_json(edit_link, {"JSONOfRecord": jor_str})
        else:
            resp = self._post_json(self._url(reg.SETTING_TABLE), {"JSONOfRecord": jor_str})
        resp.raise_for_status()
        logger.debug("FM OData: save_fm_settings OK")

    def remove_fm_settings_keys(self, keys) -> list:
        """Delete ``keys`` from the SETTING JSONOfRecord (packet 085 §8 secret fence).

        save_fm_settings only merges (can't drop a key), so this reads the record, pops any of
        ``keys`` present, and PATCHes the pruned JSONOfRecord back. Returns the keys actually
        removed ([] if none / no record). Best-effort: never raises (a startup fence must not
        break boot)."""
        removed: list = []
        try:
            resp = self._session.get(self._url(reg.SETTING_TABLE))
            resp.raise_for_status()
            values = resp.json().get("value", [])
            if not values:
                return removed
            _, existing = _parse_jor(values[0])
            for k in keys:
                if k in existing:
                    existing.pop(k, None)
                    removed.append(k)
            if not removed:
                return removed
            edit_link = values[0].get("@editLink")
            if not edit_link:
                return removed
            jor_str = json.dumps(existing, ensure_ascii=False)
            self._patch_json(edit_link, {"JSONOfRecord": jor_str}).raise_for_status()
            logger.info("FM OData: stripped legacy secret keys from SETTING: %s", removed)
        except Exception:
            logger.debug("FM OData: remove_fm_settings_keys failed", exc_info=True)
        return removed

    # ── SETTING singleton containers ───────────────────────────────────────────────
    # The singleton has no UUID column (§_get_settings_record), so its containers are addressed
    # via the record's ``@editLink`` (the same handle SETTING JSON writes use). Raw octet-stream,
    # never encode_blob-wrapped: each payload is already a self-describing ciphertext, read only
    # by its own owner (never by decode_blob / a catalog read).

    def _setting_container_url(self, field: str = "SealData") -> Optional[str]:
        """Full URL of the SETTING singleton's container ``/$value``, via @editLink, or None."""
        try:
            resp = self._session.get(self._url(reg.SETTING_TABLE))
            resp.raise_for_status()
            values = resp.json().get("value", [])
            if not values:
                return None
            edit_link = values[0].get("@editLink")
            if not edit_link:
                return None
            phys = reg.container_field(reg.SETTING_TABLE, field)
            base = edit_link if str(edit_link).startswith("http") else self._url(edit_link)
            return f"{base}/{phys}/$value"
        except Exception:
            logger.debug("FM OData: _setting_container_url failed", exc_info=True)
            return None

    def _clear_setting_container(self, field: str, filename: str) -> None:
        """Empty a SETTING singleton container via an empty-octet-stream PATCH (best-effort).

        NEVER a ``DELETE .../$value`` — box-proven (packet 1009 blob_delete data-loss): FileMaker OData
        treats a container-property DELETE as deleting the whole RECORD, which on the SETTING singleton
        would wipe every team setting + the projection map + every other container. The empty PATCH is
        the box-verified clear (200, the row survives, only the blob is emptied)."""
        url = self._setting_container_url(field)
        if not url:
            return
        try:
            self._session.patch(
                url, data=b"",
                headers={"Content-Type": "application/octet-stream",
                         "Content-Disposition": f'attachment; filename="{filename}"'},
            ).raise_for_status()
        except Exception:
            logger.debug("FM OData: clear SETTING.%s failed", field, exc_info=True)

    def seal_residue_state(self) -> str:
        """`present` · `absent` · `error`. The bytes are never returned, parsed or acted on.

        A failure to reach the container answers `error`, not `absent` — a probe that could not ask
        has established nothing, and reporting that as "empty" is how an unchecked assumption gets
        laundered into a fact.
        """
        url = self._setting_container_url()
        if not url:
            return "error"
        try:
            resp = self._session.get(url)
            if resp.status_code == 404:
                return "absent"
            resp.raise_for_status()
        except Exception:
            logger.debug("FM OData: seal residue probe failed", exc_info=True)
            return "error"
        return "absent" if not resp.content else "present"

    # ── SETTING AiKeys container (AI provider secrets, packet 1007) ────────────────
    # App-scoped → rides the SETTING singleton's AiKeys container so it TRAVELS with the .fmp12,
    # Corpus-Key-encrypted (the caller does the crypto). Same @editLink addressing as the others.
    def read_ai_keys(self) -> Optional[bytes]:
        url = self._setting_container_url("AiKeys")
        if not url:
            return None
        try:
            resp = self._session.get(url)
            if resp.status_code == 404 or not resp.content:
                return None
            resp.raise_for_status()
            from corpusfm.core.crypto import is_real_blob
            return resp.content if is_real_blob(resp.content) else None
        except Exception:
            logger.debug("FM OData: read_ai_keys failed", exc_info=True)
            return None

    def write_ai_keys(self, data: bytes) -> None:
        url = self._setting_container_url("AiKeys")
        if not url:
            raise RuntimeError("FM OData: SETTING singleton not found — cannot write AiKeys.")
        resp = self._session.patch(
            url, data=data,
            headers={"Content-Type": "application/octet-stream",
                     "Content-Disposition": 'attachment; filename="aikeys.bin"'},
        )
        resp.raise_for_status()

    def clear_ai_keys(self) -> None:
        self._clear_setting_container("AiKeys", "aikeys.bin")

    # ── SETTING NotifySecret container (SMTP password, packet 1009) ────────────────
    # The monitor SMTP password is app-scoped → rides the SETTING singleton's NotifySecret container
    # so it TRAVELS with the .fmp12, Corpus-Key-encrypted (the caller does the crypto). Same @editLink
    # addressing as AiKeys. The non-secret monitor config lives in the SETTING JSON blob.
    def read_notify_secret(self) -> Optional[bytes]:
        url = self._setting_container_url("NotifySecret")
        if not url:
            return None
        try:
            resp = self._session.get(url)
            if resp.status_code == 404 or not resp.content:
                return None
            resp.raise_for_status()
            from corpusfm.core.crypto import is_real_blob
            return resp.content if is_real_blob(resp.content) else None
        except Exception:
            logger.debug("FM OData: read_notify_secret failed", exc_info=True)
            return None

    def write_notify_secret(self, data: bytes) -> None:
        url = self._setting_container_url("NotifySecret")
        if not url:
            raise RuntimeError("FM OData: SETTING singleton not found — cannot write NotifySecret.")
        resp = self._session.patch(
            url, data=data,
            headers={"Content-Type": "application/octet-stream",
                     "Content-Disposition": 'attachment; filename="notify.bin"'},
        )
        resp.raise_for_status()

    def clear_notify_secret(self) -> None:
        self._clear_setting_container("NotifySecret", "notify.bin")

    # ── SETTING OidcSecret container (external-auth secrets, packet 1065) ──────────
    # The OIDC client_secret + LDAP bind password are app-scoped → they ride the SETTING singleton's
    # OidcSecret container so they TRAVEL with the .fmp12, Corpus-Key-encrypted (the caller does the crypto).
    # Same @editLink addressing as AiKeys/NotifySecret. Non-secret OIDC/LDAP config lives in
    # the SETTING JSON blob; the fence keeps the secret out of jor.
    def read_oidc_secret(self) -> Optional[bytes]:
        url = self._setting_container_url("OidcSecret")
        if not url:
            return None
        try:
            resp = self._session.get(url)
            if resp.status_code == 404 or not resp.content:
                return None
            resp.raise_for_status()
            from corpusfm.core.crypto import is_real_blob
            return resp.content if is_real_blob(resp.content) else None
        except Exception:
            logger.debug("FM OData: read_oidc_secret failed", exc_info=True)
            return None

    def write_oidc_secret(self, data: bytes) -> None:
        url = self._setting_container_url("OidcSecret")
        if not url:
            raise RuntimeError("FM OData: SETTING singleton not found — cannot write OidcSecret.")
        resp = self._session.patch(
            url, data=data,
            headers={"Content-Type": "application/octet-stream",
                     "Content-Disposition": 'attachment; filename="oidc.bin"'},
        )
        resp.raise_for_status()

    def clear_oidc_secret(self) -> None:
        self._clear_setting_container("OidcSecret", "oidc.bin")

    # FM-internal transactional container move (packet 085; docs/move-container-data-script.md).
    _MOVE_CONTAINER_SCRIPT = "CFM.SRV.MoveContainerData"
    _MOVE_TIMEOUT = (15, 900)   # synchronous; a large blob move can lag — wait, don't trip 300s.

    _REFRESH_PROJECTIONS_SCRIPT = "CFM.SRV.RefreshIndexProjections"
    # The refresh loops every record file-wide, so it can lag. FileMaker OData runs the script
    # SYNCHRONOUSLY — the POST returns only when it completes — so a generous read-inactivity budget
    # (15 min) lets us WAIT for it rather than trip the default 300s timeout on a large catalog.
    _REFRESH_TIMEOUT = (15, 900)

    def refresh_index_projections(self) -> bool:
        """Refresh every indexed slot file-wide by running the FM script
        ``CFM.SRV.RefreshIndexProjections`` over OData. The script re-fires the projection
        across all records INSIDE FileMaker — one HTTP call, the work stays server-side — so it's
        far cheaper than the OData per-record touch (:meth:`reproject_all_records`). The call BLOCKS
        until the script finishes (FM OData runs scripts synchronously). Requires the map already
        present in SETTING (the projection CF reads it). Returns True when the script ran cleanly;
        False (never raises) when it's absent/errors, so the caller falls back to the OData reproject."""
        try:
            resp = self._session.post(
                self._url(f"Script.{self._REFRESH_PROJECTIONS_SCRIPT}"),
                data="{}", headers={"Content-Type": "application/json"},
                timeout=self._REFRESH_TIMEOUT,
            )
            if not resp.ok:
                logger.debug("FM OData: refresh-projections script HTTP %s", resp.status_code)
                return False
            body = resp.json() if resp.content else {}
            code = str((body.get("scriptResult") or {}).get("code", "") or "")
            if code and code != "0":
                logger.warning("FM OData: refresh-projections script returned code %s", code)
                return False
            return True
        except Exception:
            logger.debug("FM OData: refresh-projections script call failed", exc_info=True)
            return False

    _REPROJECT_NONCE_KEY = "_rp"

    def reproject_all_records(self) -> int:
        """Force every record of every slotted table to re-project through the FM-side CF.

        Touches each record (read JSONOfRecord → bump a ``_rp`` nonce → PATCH back) so the
        commit re-fires the ``alwaysEvaluate``/``overwriteExisting`` auto-enter CF, which
        re-derives (and lowercases) every indexed slot from the pushed ``Calculations`` map.
        The nonce guarantees the JSONOfRecord differs so FM registers a modification (an
        identical PATCH may be a no-op that never commits). ``_rp`` is an opaque top-level key
        ignored by every record loader (``Artifact.from_dict`` reads only named keys). Idempotent;
        returns the number of records re-projected. Per-record PATCH — fine at fresh-install scale;
        a grown catalog is the point to switch this to an OData ``$batch``."""
        nonce = datetime.now(timezone.utc).isoformat(timespec="seconds")
        total = 0
        failed = 0   # transient list/PATCH errors — NOT poison-row skips (a re-sweep can't fix those)
        for logical in reg.SLOTS:
            phys = self._phys(logical)
            try:
                resp = self._session.get(self._url(phys) + "?$select=UUID,JSONOfRecord")
                resp.raise_for_status()
            except Exception:
                logger.warning("FM OData: reproject skipping %s — list failed", logical, exc_info=True)
                failed += 1
                continue
            for rec in resp.json().get("value", []):
                record_uuid, jor = _parse_jor(rec)
                # Poison-row guard (packet 064): a truncated/corrupt read makes _parse_jor return {}
                # even though the stored field was non-empty. PATCHing {} back would WIPE that row's
                # JSONOfRecord. Skip + log; the row keeps its payload and the next pass retries.
                raw = rec.get("JSONOfRecord")
                if not jor and isinstance(raw, str) and raw.strip() not in ("", "{}"):
                    logger.warning("FM OData: reproject skipping %s row %s — JSONOfRecord did not "
                                   "parse (not wiping it)", logical, record_uuid)
                    continue
                if not record_uuid:
                    continue
                jor[self._REPROJECT_NONCE_KEY] = nonce
                try:
                    self._patch_json(
                        self._url(f"{phys}('{record_uuid}')"),
                        self._jor_payload(logical, jor),
                    ).raise_for_status()
                    total += 1
                except Exception:
                    logger.warning("FM OData: reproject failed for %s row %s", logical, record_uuid,
                                   exc_info=True)
                    failed += 1
        if failed:
            # Partial completion is NOT success: signal incompleteness so the caller does NOT advance
            # ProjectionVersion (packet 1000 P2). Version-gating decoupled the sweep from the map diff
            # (packet 1060), so a silently-stamped partial pass would strand the failed rows on stale
            # slots until the NEXT version bump. Raising → _refresh returns "" → no stamp → retry next boot.
            raise RuntimeError(
                f"reproject incomplete: {total} reprojected, {failed} failed (transient list/PATCH "
                "errors); ProjectionVersion not advanced — will retry on next startup.")
        return total

    # (FILETRACK retired in packet 085 U3b — CORPUSfm persists nothing about a file it has no
    # job for; the Files page composes live FMS observation + the JOBS read.)
    # (git_targets moved OFF the SETTING singleton onto each STORAGE record's own jor in packet
    # 1009/S3 — see server/git_targets.py; SETTING JSON is app-settings + the projection map only.)

    def load_fm_build(self) -> str:
        """The SETTING.Build stamp (a calc literal — the DB's schema-version marker)."""
        try:
            resp = self._session.get(self._url(reg.SETTING_TABLE) + "?$select=Build")
            resp.raise_for_status()
            values = resp.json().get("value", [])
            return str(values[0].get("Build", "")) if values else ""
        except Exception:
            logger.debug("FM OData: load_fm_build failed", exc_info=True)
            return ""

    # ── Artifact lineage / latest view ───────────────────────────────────────────

    @staticmethod
    def _artifact_record_from_jor(record_uuid: str, jor: dict) -> dict:
        # The canonical converter lives in artifact_record (shared with the engine-read
        # paths — audit #2 FETCH-ONCE: the dict carries the full meta from the same parse).
        from corpusfm.storage.artifact_record import record_from_jor
        return record_from_jor(record_uuid, jor)

    def list_fm_artifact_records(self) -> list[dict]:
        """STORAGE records as {uuid, root_uuid, file_name, job_uuid, run_uuid, timestamp, …} —
        the identity/lineage fields the tag carry-forward + latest-flag joins need (by uuid).
        Also carries ``name`` (free — same JSONOfRecord parse) so a caller that
        already has these records can resolve display names without a second STORAGE scan."""
        resp = self._session.get(self._url(self._phys("STORAGE")) + "?$select=UUID,JSONOfRecord")
        resp.raise_for_status()
        out: list[dict] = []
        for rec in resp.json().get("value", []):
            record_uuid, jor = _parse_jor(rec)
            # Type-driven visibility (packet 085): a Type-less mid-landing row is not a catalog
            # artifact — exclude it from the lineage / latest-flag / tag-carry-forward / facet source.
            if jor.get("Type") not in _VISIBLE_TYPES:
                continue
            out.append(self._artifact_record_from_jor(record_uuid, jor))
        return out

    def set_storage_is_latest(self, record_uuid: str, is_latest: bool) -> None:
        """Set IsLatest inside a STORAGE record's JSONOfRecord (read-merge-write) AND its
        indexed slot, so the latest-view $filter re-points."""
        resp = self._session.get(
            self._url(f"{self._phys('STORAGE')}('{record_uuid}')?$select=UUID,JSONOfRecord"))
        resp.raise_for_status()
        values = resp.json().get("value")
        rec = values[0] if isinstance(values, list) and values else resp.json()
        _, jor = _parse_jor(rec)
        if bool(jor.get("IsLatest", False)) == bool(is_latest):
            return
        jor["IsLatest"] = bool(is_latest)
        self._patch_json(
            self._url(f"{self._phys('STORAGE')}('{record_uuid}')"),
            self._jor_payload("STORAGE", jor),
        ).raise_for_status()

    def _filtered_recent(self, filters: list, limit: int) -> list[ArtifactMeta]:
        """Bounded newest-first STORAGE read for an AND-list of documented-OData ``$filter`` clauses
        (built from registry slots): ``$orderby ArtifactTimestamp desc`` + ``$top``. No full scan."""
        ts_slot = reg.slot("STORAGE", "ArtifactTimestamp")
        parts = ["$select=UUID,JSONOfRecord", f"$orderby={ts_slot} desc", f"$top={max(1, int(limit))}"]
        if filters:
            # FM Server's OData parser rejects a URL-ENCODED comma (%2C) inside function args
            # (e.g. contains(field,'x')) — it wants the comma LITERAL (live-verified). It DOES
            # accept encoded spaces/quotes/parens. So keep ( ) , ' literal and let the trailing
            # space→%20 pass handle spaces.
            parts.append("$filter=" + _quote(" and ".join(filters), safe="(),'"))
        url = self._url(self._phys("STORAGE")) + "?" + "&".join(parts).replace(" ", "%20")
        resp = self._session.get(url)
        resp.raise_for_status()
        return [m for m in (self._meta_from_record(r) for r in resp.json().get("value", [])) if m.file_name]

    def _count_storage(self) -> int:
        """Total VISIBLE STORAGE rows via documented OData ``$count`` — one tiny request, no
        scan. Carries the Type visibility fence so mid-landing/queue rows never count."""
        from corpusfm.artifact.capabilities import VISIBLE_TYPES
        ty = reg.slot("STORAGE", "Type")
        fence = " or ".join(f"({ty} eq '{t.lower()}')" for t in sorted(VISIBLE_TYPES))
        url = (self._url(self._phys("STORAGE"))
               + "?$count=true&$top=1&$select=UUID&$filter="
               + _quote(f"({fence})", safe="(),'")).replace(" ", "%20")
        resp = self._session.get(url)
        resp.raise_for_status()
        p = resp.json()
        return int(p.get("@odata.count", p.get("@count", 0)) or 0)

    def recent_artifact_buckets(self, *, limit: int = 10) -> dict:
        """Server-side Overview buckets — bounded reads on the indexed Type/Origin/ArtifactTimestamp
        slots (documented OData ``$filter`` + ``$orderby`` + ``$top`` + ``$count``), NOT a full
        unfiltered artifact scan. Returns ``{"imports":[meta], "merges":[meta],
        "patches":[meta], "total": int}`` (each bucket newest-first, ≤ ``limit``). Raises on any
        OData error so the route falls back to the scan."""
        from corpusfm.artifact.capabilities import VISIBLE_TYPES
        ty, og = reg.slot("STORAGE", "Type"), reg.slot("STORAGE", "Origin")
        merges = self._filtered_recent([f"{ty} eq 'mergedxml'"], limit)
        patches = self._filtered_recent([f"(({ty} eq 'patchxml') or ({og} eq 'patch (isv)'))"], limit)
        # The imports bucket = the visible types minus merges/patches (Type-driven; an untyped
        # mid-landing row is outside the fence by construction).
        import_types = sorted(VISIBLE_TYPES - {"MergedXML", "PatchXML"})
        fence = " or ".join(f"({ty} eq '{t.lower()}')" for t in import_types)
        imports = self._filtered_recent([f"({fence})", f"{og} ne 'patch (isv)'"], limit)
        return {"imports": imports, "merges": merges, "patches": patches, "total": self._count_storage()}

    # ── Generic SQL passthrough (QUERY table) ────────────────────────────────────

    def query(self, sql: str, *, columns: bool = False) -> list:
        """Run an arbitrary read-only ``ExecuteSQL`` via the QUERY table in one OData call.

        POSTs ``{Query: sql}``; the unstored ``Result`` calc (= ``ExecuteSQL(Query)``)
        evaluates into the POST response. Returns the rows split on FM's row delimiter
        (CR). With ``columns=True`` each row is further split on FM's column delimiter
        (comma) into a list; otherwise each row is the raw row string (ideal for a
        single-column ``SELECT UUID …``).

        This is the generic query engine: joins/filters/sorts/aggregates with no FM
        relationship graph and no per-query OData URL building. ``ExecuteSQL`` is
        READ-ONLY (cannot modify data), so composed SQL is safe. Mind FM's ~1M-char
        result cap: SELECT bounded/keyed results (UUIDs + small fields) and hydrate full
        records/containers via the normal OData paths — never bulk rows or blobs here.
        """
        resp = self._post_json(self._url(reg.QUERY_TABLE), {"Query": sql})
        resp.raise_for_status()
        result = (resp.json().get("Result") or "").rstrip("\r")
        rows = result.split("\r") if result else []
        return [r.split(",") for r in rows] if columns else rows


    # The bespoke TAGS/TAGASSIGN record methods are RETIRED (packet 084 Phase 4 tags fold) —
    # tags_store drives the tables through the StorageEngine (``self.engine``).

    # The migrate-into-new-file data engine (export_table / import_table_record /
    # upload_container / legacy_export_table / legacy_download_container) is RETIRED —
    # packet 085 is fresh-install-only (no in-place migration; a stale DB is handled by
    # storage_migration's build-mismatch gate). The generic single-container read wrapper
    # stays for callers that need one blob by (table, field).

    def download_container(self, record_uuid: str, field: str, table: str) -> Optional[bytes]:
        return self._download_container(record_uuid, field, table=table)

    # ── FM JOBS CRUD ─────────────────────────────────────────────────────────────

    # The bespoke JOBS config/state methods are RETIRED (packet 084 Phase 4 jobs fold) —
    # server/jobs/store.py + state.py drive the JOBS table through storage.repos.JobsRepo
    # over the StorageEngine (``self.engine``).

    # ── Pruning ───────────────────────────────────────────────────────────────────

    def _prune_snapshots(self, file_name: str, max_keep: int) -> None:
        if max_keep <= 0:
            return
        fn = _slot_lit(file_name)
        filter_str = f"{reg.slot('STORAGE', 'FileName')} eq '{fn}'"
        url = (
            self._url(self._phys("STORAGE"))
            + "?$filter=" + _quote(filter_str)
            + "&$select=UUID,JSONOfRecord"
        )
        try:
            resp = self._session.get(url)
            resp.raise_for_status()
            raw_records = resp.json().get("value", [])
        except Exception:
            return

        def _ts(r: dict) -> str:
            _, jor = _parse_jor(r)
            return jor.get("ArtifactTimestamp", "")

        records = sorted(raw_records, key=_ts, reverse=True)
        for rec in records[max_keep:]:
            try:
                self._session.delete(
                    self._url(f"{self._phys('STORAGE')}('{rec['UUID']}')")
                ).raise_for_status()
                _, jor = _parse_jor(rec)
                logger.debug("FM OData: pruned %s/%s", file_name, jor.get("ArtifactTimestamp"))
            except Exception:
                logger.debug("FM OData: prune failed for %s", rec.get("UUID"))

    def overlimit_job_artifacts(self, job_uuid: str, max_keep: int) -> list[str]:
        """The uuids of a job's artifacts BEYOND the newest ``max_keep`` (oldest-first tail), for
        retention. Selection only — the removal cascade (deindex + history + cache + repromote) runs
        at the server layer via ``artifact_delete.prune_job_artifacts`` (packet 1054), never a raw
        backend delete (which is what leaked index entries + skipped history here)."""
        if max_keep <= 0 or not job_uuid:
            return []
        ju = _slot_lit(job_uuid)
        filter_str = f"{reg.slot('STORAGE', 'UUIDJob')} eq '{ju}'"
        url = (
            self._url(self._phys("STORAGE"))
            + "?$filter=" + _quote(filter_str)
            + "&$select=UUID,JSONOfRecord"
        )
        try:
            resp = self._session.get(url)
            resp.raise_for_status()
            raw_records = resp.json().get("value", [])
        except Exception:
            return []

        def _ts(r: dict) -> str:
            _, jor = _parse_jor(r)
            return jor.get("ArtifactTimestamp", "")

        records = sorted(raw_records, key=_ts, reverse=True)
        return [rec["UUID"] for rec in records[max_keep:]]

    # ── AI summaries blob (packet 054) ───────────────────────────────────────────
    # Durable copy lives in the SummariesData container (survives an archive wipe / db move). A local
    # sidecar is ALSO written as a derived cache so the catalog's summarized scan + index reads keep
    # working unchanged; the blob is the source of truth and lazy-migrates a stray sidecar.

    def _summaries_sidecar_for(self, jor: dict):
        """The derived summaries.json path for a record, laid out by FileName/Timestamp (the natural
        key the catalog's `summarized` scan + index reads use) — NOT by the record UUID, so the
        on-disk layout is unchanged by the U3f address flip. None when the pair is missing."""
        fn, ts = jor.get("FileName", ""), jor.get("ArtifactTimestamp", "")
        if not fn or not ts:
            return None
        return self.archive_dir / fn / ts / "summaries.json"

    def store_summaries(self, ref: str, summaries: dict) -> None:
        import gzip
        from corpusfm.core.crypto import encode_blob
        record = self._get_record_by_uuid(ref)
        if record is None:
            return
        _ruuid, jor = _parse_jor(record)
        try:
            record_uuid = record["UUID"]
            blob = encode_blob(
                gzip.compress(json.dumps(summaries, ensure_ascii=False).encode("utf-8")),
                encrypt_on=self._encrypt_blobs())
            self._upload_container(record_uuid, "SummariesData", blob)
            # Set the indexed HasSummaries flag (whole-JOR PATCH, like update_record).
            jor["HasSummaries"] = bool(summaries)   # slotted bool — one JOR representation
            self._patch_json(
                self._url(f"{self._phys('STORAGE')}('{record_uuid}')"),
                self._jor_payload("STORAGE", jor, record_uuid=record_uuid),
            ).raise_for_status()
        except Exception:
            logger.debug("FM OData: store_summaries failed for %s", ref, exc_info=True)
        # Derived local cache (best-effort) — keeps the catalog scan + index reads working.
        try:
            sp = self._summaries_sidecar_for(jor)
            if sp is not None:
                sp.parent.mkdir(parents=True, exist_ok=True)
                sp.write_text(json.dumps(summaries, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            logger.debug("FM OData: store_summaries sidecar failed for %s", ref, exc_info=True)

    def load_summaries(self, ref: str) -> dict:
        import gzip
        from corpusfm.core.crypto import decode_blob
        record = self._get_record_by_uuid(ref)
        if record is None:
            return {}
        _ruuid, jor = _parse_jor(record)
        # Prefer the durable blob.
        try:
            raw = self._download_container(record["UUID"], "SummariesData")
            if raw:
                data = json.loads(gzip.decompress(decode_blob(raw)).decode("utf-8"))
                if data:
                    try:  # ensure the derived sidecar exists for the scan/index path
                        sp = self._summaries_sidecar_for(jor)
                        if sp is not None and not sp.exists():
                            sp.parent.mkdir(parents=True, exist_ok=True)
                            sp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                    except Exception:
                        pass
                    return data
        except Exception:
            logger.debug("FM OData: load_summaries (blob) failed for %s", ref, exc_info=True)
        # Lazy migration: a pre-054 local sidecar with no blob → read it, write it into the blob.
        try:
            sp = self._summaries_sidecar_for(jor)
            if sp is not None and sp.exists():
                data = json.loads(sp.read_text(encoding="utf-8"))
                if data:
                    self.store_summaries(ref, data)
                return data or {}
        except Exception:
            logger.debug("FM OData: load_summaries (sidecar) failed for %s", ref, exc_info=True)
        return {}
