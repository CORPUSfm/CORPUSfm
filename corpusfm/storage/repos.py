"""Repositories — entity logic over the StorageEngine (backend-agnostic).

The remaster's middle layer. A repo takes a StorageEngine and
exposes entity-shaped verbs returning **shaped views** (only the fields a surface needs), so routes
never touch OData/SQL and a list read never carries detail-only fields. Reads are keyed/indexed by
default via the engine; the repo just knows WHICH slots and how to shape the result.

The STORAGE repo this module started with is retired (packet 1361-01); the persistent catalog
is that table's reader now. `QueueRepo` is the template the rest follow.
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass
from typing import Optional

from corpusfm.artifact.capabilities import SCHEMA_TYPES, VISIBLE_TYPES, is_schema_type
from corpusfm.storage import fm_registry as reg
from corpusfm.storage.engine import Row, StorageEngine

_STORAGE = "STORAGE"

# The 4 fields the catalog/picker `q` searches (contains, OR-ed) — all indexed slots.
_SEARCH_KEYS = ("PrimaryName", "FileName", "Description", "Memory")


def _rel(jor: dict) -> str:
    return f"{jor.get('FileName', '')}/{jor.get('ArtifactTimestamp', '')}"


def _bool(v) -> bool:
    return v in (True, 1, "1", "true")


# `ArtifactsRepo` / `artifacts_repo()` are GONE (packet 1361-01). They were the entity-shaped
# STORAGE reader behind the catalog's direct-FileMaker pager (`_try_db_page`) and the Related tab's
# per-request `same_root()`. Both callers now read the one synchronized persistent catalog, which
# answers the same questions from resident, intersected indexes — so the repo had no production
# caller left, and every one of its reads carried an `IsLatest` predicate that no longer exists.
# The other repos (queue/jobs/alerts) are untouched: they front tables the catalog does not hold.



_JOBS = "JOB"

# The JOBS record's last-run state keys (ride the same jor the config lives in — audit #4:
# one read serves (cfg, state); a per-job state re-fetch is N+1 waste on the poll path).
_JOB_STATE_KEYS = ("LastRunTS", "LastStatus", "LastError", "LastDuration")

# Per-job credential + verification jor keys (packet 085 U3b). The credential VALUE never rides
# jor — only its presence flag + the display account name; the secret lives in the CredentialData
# container. Preserved across a config save() so editing a job never drops its credential/verify.
_JOB_CRED_KEYS = ("AccountName", "HasCredential", "IsVerified", "VerifyReason")


class AlertReadUnavailable(RuntimeError):
    """The ALERT table could not be read — raised only for a caller that asked to hear about it.

    The counterpart to `JobReadUnavailable`, and it exists for the same reason: an empty alert
    history and an unreadable one are different facts, and a poller that reports the second as
    "no alerts" tells the browser everything is fine while storage is down.
    """


class JobReadUnavailable(RuntimeError):
    """The JOB table could not be read — raised only for a caller that asked to hear about it.

    The default `[]` stays, because the 10-second notification poll and the monitor rows genuinely
    prefer a degraded empty render to an exception. A surface that PAINTS the job list cannot afford
    that trade: "no jobs" and "could not ask" are different facts, and answering the second with the
    first is an authoritative-looking lie (packet 1369).
    """


#: Job identity is a UUID and nothing else. Enforced at `save()`, which is where an id ENTERS the
#: store — a read or delete simply misses on anything else, and both engines are injection-safe
#: (`engine._clause` escapes for FM; SQLite is parameterised), so there is nothing for a
#: read-side check to protect. Stated precisely because an earlier version of this comment claimed
#: the regex guarded every path, which it never did.
_SOUND_UUID = _re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                          r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class JobIdentityInvalid(ValueError):
    """A job was addressed, or offered for saving, without a sound UUID identity."""


class JobsRepo:
    """JOB, entity-shaped: JobConfig + JobState over the engine.

    **UUID-ONLY (packet 1372-02).** Every operation addresses a record by its native key, which after
    the 1372-01 conversion is also `JobConfig.id` and the `UUIDJob` its artifacts, history and queue
    rows carry. `Name` is never queried to identify a row and is never required to be unique —
    duplicate names, including case variants, are ordinary. That is the whole cutover: a job's
    identity is a UUID a user cannot edit, not a label they can.

    The config YAML lives in the record's ``ConfigJSON``. Jobs are a server feature — the local
    dev/test path stays on the YAML files in jobs/ (see server/jobs/store.py), so this repo only ever
    runs over a live install's engine.
    """

    def __init__(self, engine: StorageEngine):
        self._e = engine

    def _row(self, job_uuid: str) -> Optional[Row]:
        """One record by its native key. `None` is a definite miss; a read failure RAISES.

        A mutation must distinguish a definite miss from an unreadable store: `save(overwrite=True)`
        performs this lookup after the caller already holds the job, and turning a transient
        second-read failure into `None` would create a second row instead of updating the first.
        Poll/list degradation stays at `list()`/`list_with_state()`, where `[]` is an explicit UI
        contract.
        """
        if not job_uuid:
            return None
        rows = self._e.get_by_keys(_JOBS, [job_uuid])
        return rows[0] if rows else None

    @staticmethod
    def _config(jor: dict):
        from corpusfm.server.jobs.config import JobConfig
        return JobConfig.from_yaml(jor.get("ConfigJSON", ""))

    @staticmethod
    def _state(jor: dict):
        from corpusfm.server.jobs.state import JobState
        return JobState(
            last_run_ts=jor.get("LastRunTS") or None,
            last_status=jor.get("LastStatus") or None,
            last_error=jor.get("LastError") or None,
            last_duration=jor.get("LastDuration") or None,
        )

    def list(self) -> list:
        """(JobConfig | None, error | None) pairs, sorted by name; an unreadable store is []
        (the poll routes render an empty list, not a 500 — matches the retired FM method)."""
        try:
            rows = self._e.list_all(_JOBS)
        except Exception:
            import logging
            logging.getLogger(__name__).error("JobsRepo.list failed", exc_info=True)
            return []
        result = []
        for r in rows:
            try:
                result.append((self._config(r.jor), None))
            except Exception as exc:
                result.append((None, f"{r.jor.get('Name', '?')}: {exc}"))
        return sorted(result, key=lambda pair: (pair[0].name if pair[0] else ""))

    @staticmethod
    def _credentials(jor: dict) -> dict:
        """The per-job credential/verification OVERLAY, from the jor the caller already holds.

        These four values are the only credential facts that live in jor at all — the secret itself
        rides the CredentialData container and is never projected here. Reading them back one job at
        a time (`has_credential` / `account_name` / `verify_state`) is three indexed re-reads of a
        record the enumeration already returned (packet 1368).
        """
        return {
            "has_credential": bool(jor.get("HasCredential")),
            "account": jor.get("AccountName", "") or "",
            "verified": bool(jor.get("IsVerified")),
            "verify_reason": jor.get("VerifyReason", "") or "",
        }

    def list_with_overlay(self, *, strict: bool = False) -> list:
        """(JobConfig | None, JobState, credential-overlay) triples from ONE read.

        The single derivation: config, last-run state and the credential/verification overlay all
        come from the same `JSONOfRecord`. `list_with_state()` is this without the third element.
        """
        try:
            rows = self._e.list_all(_JOBS)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error("JobsRepo.list_with_overlay failed", exc_info=True)
            if strict:
                raise JobReadUnavailable(
                    "The job list could not be read from storage "
                    f"({type(exc).__name__}). See the CORPUSfm server log for detail.") from exc
            return []
        result = []
        for r in rows:
            state = self._state(r.jor)
            cred = self._credentials(r.jor)
            try:
                result.append((self._config(r.jor), state, cred))
            except Exception:
                result.append((None, state, cred))
        return sorted(result, key=lambda triple: (triple[0].name if triple[0] else ""))

    def list_with_state(self, *, strict: bool = False) -> list:
        """(JobConfig | None, JobState) pairs from ONE read (audit #4) — the state fields
        ride the same jor the config parse already read.

        ``strict=True`` raises `JobReadUnavailable` instead of degrading an unreadable store to `[]`.
        """
        return [(cfg, state) for cfg, state, _cred in self.list_with_overlay(strict=strict)]

    def load(self, job_uuid: str):
        row = self._row(job_uuid)
        if row is None:
            raise KeyError(f"No job with id {job_uuid!r} in the JOB store.")
        return self._config(row.jor)

    def save(self, cfg, overwrite: bool = False) -> None:
        """Create or update a job AT ITS OWN ID. On update the state and credential keys survive.

        **The record is created at `cfg.id`, not at a fresh uuid4.** That single line is what packet
        1372 exists to fix: `save()` used to mint its own key while the caller minted `cfg.id`, so
        most jobs carried two uuids and every artifact, run and queue row linked to the one the
        record did not live at.

        A missing or malformed id is REFUSED rather than repaired. There is nowhere left to guess
        from — names are not identity any more and may legitimately collide — so a caller that has
        not decided what job this is has not finished making the request.
        """
        job_uuid = (getattr(cfg, "id", "") or "").strip()
        if not _SOUND_UUID.match(job_uuid):
            raise JobIdentityInvalid(
                f"job {cfg.name!r} carries id {getattr(cfg, 'id', None)!r}, which is not a UUID. "
                "A job is identified by its UUID; the name is a label and may collide.")
        existing = self._row(job_uuid)
        if existing is not None and not overwrite:
            raise ValueError(f"A job with id {job_uuid} already exists. Pass overwrite=True to replace.")
        jor = {
            "Name": cfg.name,
            "FileName": getattr(cfg, "file", "") or "",   # the hosted-file binding (indexed slot)
            "ConfigJSON": cfg.to_yaml(),
            "IsActive": 1 if getattr(cfg, "active", True) else 0,
            "SourceType": getattr(getattr(cfg, "source", None), "source_type", ""),
            "Schedule": getattr(cfg, "schedule", "") or "",
        }
        if existing is not None:
            for k in (*_JOB_STATE_KEYS, *_JOB_CRED_KEYS):
                if k in existing.jor:
                    jor[k] = existing.jor[k]
            self._e.update(_JOBS, job_uuid, jor)
        else:
            self._e.create(_JOBS, job_uuid, jor)

    def delete(self, job_uuid: str) -> bool:
        row = self._row(job_uuid)
        if row is None:
            return False
        self._e.delete(_JOBS, row.key)
        return True

    def read_state(self, job_uuid: str):
        from corpusfm.server.jobs.state import JobState
        row = self._row(job_uuid)
        return self._state(row.jor) if row is not None else JobState()

    def update_state(self, job_uuid: str, run) -> None:
        """Merge last-run state into the job's jor after a run.

        An unresolved id is a legitimate no-op — the state lives ON the job record and is deleted
        with it, so a run that outlives its job has nothing to update (its HISTORY row is written
        regardless, and that is the durable account). It is logged rather than silent, because
        'half the write landed' is otherwise invisible (packet 1149)."""
        row = self._row(job_uuid)
        if row is None:
            import logging
            logging.getLogger(__name__).info(
                "job state not updated — no JOB record with id %r (deleted mid-run?); the run's "
                "HISTORY row is unaffected", job_uuid)
            return
        duration_s = getattr(run, "duration_s", None)
        jor = dict(row.jor)
        jor["LastRunTS"] = run.ts or ""
        jor["LastStatus"] = run.status or ""
        jor["LastError"] = run.error or ""
        jor["LastDuration"] = str(duration_s) if duration_s is not None else ""
        self._e.update(_JOBS, row.key, jor)

    # ── per-job credential (packet 085 U3b) ─────────────────────────────────────
    # The FM account + password for THIS job's pull. The secret rides ONLY the CredentialData
    # container (always box-key encrypted, independent of the encrypt_blobs setting), never jor —
    # so it never appears in a config read, a list, a snapshot, or a log. Only presence (a flag)
    # + the display account name live in jor. Extinguished with the job (delete cascades the
    # container). "The security price of making a job is knowing the credentials."

    def set_credential(self, job_uuid: str, account: str, password: str) -> bool:
        """Set or REPLACE this job's credential. There is no standalone removal here.

        THE ADAPTER DOES NOT POLICE JOB POLICY (developer ruling, packet 1372 waterfall correction).
        An earlier version refused a blank half from down here, on the reasoning that a retained job
        must never be left credentialless. Both halves of that were wrong: a credentialless job is a
        valid incomplete draft, and whether a submitted credential is coherent is a question for the
        entry boundary that accepted it — `POST /api/files/{name}/jobs` makes exactly that check.
        This layer's job is to store what it is given and to describe accurately what it holds.
        """
        import json as _json
        from corpusfm.core.crypto import compress, encode_blob
        row = self._row(job_uuid)
        if row is None:
            return False
        blob = encode_blob(
            compress(_json.dumps({"account": account, "password": password},
                                 ensure_ascii=False).encode("utf-8")),
            encrypt_on=True)   # ALWAYS encrypted — a credential is a secret, not a bulk blob
        self._e.blob_put(_JOBS, row.key, "CredentialData", blob)
        jor = dict(row.jor)
        jor["AccountName"] = account
        jor["HasCredential"] = True
        jor["IsVerified"] = False        # a new credential invalidates the prior verification
        jor["VerifyReason"] = ""
        self._e.update(_JOBS, row.key, jor)
        return True

    def get_credential(self, job_uuid: str) -> "Optional[dict]":
        """{account, password} for a run-time pull, or None. Reads the container explicitly —
        never rides an ordinary job read."""
        import json as _json
        from corpusfm.core.crypto import decode_blob, decompress
        row = self._row(job_uuid)
        if row is None:
            return None
        raw = self._e.blob_get(_JOBS, row.key, "CredentialData")
        if not raw:
            return None
        try:
            data = _json.loads(decompress(decode_blob(raw)).decode("utf-8"))
        except Exception:
            return None
        if not data.get("account") or not data.get("password"):
            return None
        return {"account": data["account"], "password": data["password"]}

    def has_credential(self, job_uuid: str) -> bool:
        row = self._row(job_uuid)
        return bool(row and row.jor.get("HasCredential"))

    def account_name(self, job_uuid: str) -> str:
        row = self._row(job_uuid)
        return (row.jor.get("AccountName", "") if row else "") or ""

    # `delete_credential` is RETIRED (packet 1372-02). It was the only way to leave a retained job
    # without the credential it needs, and the browser route that called it is gone. Deleting the
    # JOB still cascades its container; that is the supported way to extinguish a credential.

    def set_verified(self, job_uuid: str, verified: bool, reason: str = "") -> None:
        """Record the per-job verification verdict (IsVerified validates the exact
        job/file/credential/script combination; it dies with the job)."""
        row = self._row(job_uuid)
        if row is None:
            return
        jor = dict(row.jor)
        jor["IsVerified"] = bool(verified)
        jor["VerifyReason"] = reason or ""
        self._e.update(_JOBS, row.key, jor)

    def verify_state(self, job_uuid: str) -> "tuple[bool, str]":
        row = self._row(job_uuid)
        if row is None:
            return False, ""
        return bool(row.jor.get("IsVerified")), (row.jor.get("VerifyReason", "") or "")


def jobs_repo(backend) -> Optional[JobsRepo]:
    """The JobsRepo over a backend's engine, or None for a backend without one."""
    eng = getattr(backend, "engine", None)
    return JobsRepo(eng) if eng is not None else None


# ── QUEUE workspace (packet 086 / Ruling B) ──────────────────────────────────────

_QUEUE = "QUEUE"
# QUEUE holds only in-flight + parked-failure rows (short-lived), so a listing is bounded; this caps a
# single read defensively. A worker claims via next_for (indexed Type+IsFailed → few rows), so the cap
# never hides a claimable record — only a pathological backlog of >1000 same-key rows would truncate a
# *listing*, and failed_count/active_count use an indexed COUNT (exact regardless of the cap).
_QUEUE_PAGE_CAP = 1000


class QueueRepo:
    """The unified QUEUE workspace over the engine — persistence for the pure state machine in
    :mod:`corpusfm.storage.queue_record`. One record per unit of work walks a laundry list; ``Type``
    is the cursor AND the owning FIFO worker. This repo never decides transitions — it reads the
    record, asks ``queue_record`` for the next jor, and writes it. FIFO order is a Python sort on the
    jor ``created_at`` (QUEUE has no timestamp slot); the ``Type``/``IsFailed`` filters are indexed.

    Additive (packet 086 brick 2): the legacy ingestion + enrich-queue paths are untouched until the
    producer migration (brick 4)."""

    def __init__(self, engine: StorageEngine):
        self._e = engine

    # -- write ---------------------------------------------------------------
    def enqueue(self, steps, *, payload=None, owner: str = "", uuid_job: str = "",
                uuid_storage: str = "", created_at: str = "", push_token_hash: str = "") -> str:
        """Create a QUEUE record for a laundry list; returns its record UUID (the address a sync
        caller polls). ``Type`` is the first step. ``created_at`` defaults to now (µs precision so
        FIFO is stable); tests may pass an explicit stamp. ``push_token_hash`` (packet 1015) keys a
        pending-push record for ``/api/upload`` resolution."""
        import uuid as _uuidlib
        from corpusfm.storage import queue_record
        if not created_at:
            from datetime import datetime, timezone
            created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        key = str(_uuidlib.uuid4())
        jor = queue_record.build(steps, payload=payload, owner=owner, created_at=created_at,
                                 uuid_job=uuid_job, uuid_storage=uuid_storage,
                                 push_token_hash=push_token_hash)
        self._e.create(_QUEUE, key, jor)
        return key

    def find_pending_push(self, push_token_hash: str) -> Optional[Row]:
        """Resolve the WAITING push record for a one-time token hash (packet 1015 / 1142): a non-failed
        record still on its ``acquire`` step whose ``PushTokenHash`` slot matches. The push acquire
        handler sets the hash and fires the trigger, then BLOCKS on that same record — so when FM POSTs
        its DDR back mid-call, /api/upload resolves the exact acquiring record here and deposits into it.
        Returns None for an empty hash or no match — which is how a used/expired/unknown token is
        rejected (once the record advances off ``acquire`` it can no longer be resolved, making the
        token one-time)."""
        if not push_token_hash:
            return None
        from corpusfm.storage import queue_record
        rows = self._by({"Type": queue_record.ACQUIRE, "IsFailed": False,
                         "PushTokenHash": push_token_hash})
        return rows[0] if rows else None

    def get(self, queue_id: str) -> Optional[Row]:
        rows = self._e.get_by_keys(_QUEUE, [queue_id])
        return rows[0] if rows else None

    def advance_or_delete(self, queue_id: str) -> Optional[str]:
        """After a step SUCCEEDS: move the cursor to the next step, or DELETE the record when the list
        is exhausted (deletion is the only success). Returns the new ``Type``, or None if the record
        was deleted or is missing."""
        from corpusfm.storage import queue_record
        row = self.get(queue_id)
        if row is None:
            return None
        nxt = queue_record.advanced(row.jor)
        if nxt is None:
            self._e.delete(_QUEUE, queue_id)
            return None
        self._e.update(_QUEUE, queue_id, nxt)
        return nxt["Type"]

    def set_push_token(self, queue_id: str, push_token_hash: str) -> None:
        """Stamp the one-time push-token HASH onto a record already in flight (packet 1142): the acquire
        handler mints the token, records its hash here, THEN fires the trigger — so a push arriving at
        /api/upload mid-call resolves this exact acquiring record via ``find_pending_push``. No-op if the
        record is gone. Never stores the raw token (secret discipline — only the hash is a lookup key)."""
        row = self.get(queue_id)
        if row is None:
            return
        jor = dict(row.jor)
        jor["PushTokenHash"] = push_token_hash or ""
        self._e.update(_QUEUE, queue_id, jor)

    def clear_source(self, queue_id: str) -> None:
        """CLEANUP for a failed acquire (packet 1142): drop any bytes a partial/failed fetch deposited
        into the record's SourceXML container, so a Restart re-fires the trigger and produces ONE
        artifact, not two. No-op if the record is gone or carried no source. Best-effort."""
        row = self.get(queue_id)
        if row is None:
            return
        try:
            self._e.blob_delete(_QUEUE, queue_id, "SourceXML")
        except Exception:
            pass

    def anchor_storage(self, queue_id: str, storage_uuid: str) -> None:
        """Anchor the STORAGE artifact a producing step just committed onto the QUEUE record's
        ``UUIDStorage`` slot (packet 1002/B — generalizes the land anchor to pull). Lets a
        crash-recovery re-claim detect 'this record already produced its artifact' and skip a
        duplicate. No-op if the record is gone."""
        row = self.get(queue_id)
        if row is None:
            return
        jor = dict(row.jor)
        jor["UUIDStorage"] = storage_uuid or ""
        self._e.update(_QUEUE, queue_id, jor)

    def set_failed(self, queue_id: str, outcome: str) -> None:
        """After a step FAILS: stamp ``Outcome`` + ``IsFailed`` (cursor unchanged — it rests for a
        human). No-op if the record is gone."""
        from corpusfm.storage import queue_record
        row = self.get(queue_id)
        if row is not None:
            self._e.update(_QUEUE, queue_id, queue_record.failed(row.jor, outcome))

    def restart(self, queue_id: str) -> bool:
        """Human **Restart**: clear the failure so the worker re-runs the current step. Returns True
        if it acted (record present)."""
        from corpusfm.storage import queue_record
        row = self.get(queue_id)
        if row is None:
            return False
        self._e.update(_QUEUE, queue_id, queue_record.restarted(row.jor))
        return True

    def delete(self, queue_id: str) -> None:
        """Human **Delete** / abandon: remove the whole record (the remaining list is dropped)."""
        self._e.delete(_QUEUE, queue_id)

    # -- read ----------------------------------------------------------------
    def _by(self, eq: dict) -> list[Row]:
        rows, _ = self._e.page(_QUEUE, eq=eq, per_page=_QUEUE_PAGE_CAP, count=False)
        rows.sort(key=lambda r: r.jor.get("created_at", ""))    # FIFO (no timestamp slot on QUEUE)
        return rows

    def list_by_type(self, step_type: str, *, include_failed: bool = False) -> list[Row]:
        """Records currently on a step type, oldest-first. Non-failed only by default (what a worker
        drains); ``include_failed`` also returns that type's parked failures."""
        eq: dict = {"Type": step_type}
        if not include_failed:
            eq["IsFailed"] = False
        return self._by(eq)

    def next_for(self, step_type: str) -> Optional[Row]:
        """The oldest non-failed record on a step type — the worker's next claim (None if idle). The
        ``IsFailed=False`` filter is indexed, so a wall of parked failures never hides a claimable
        row."""
        rows = self.list_by_type(step_type, include_failed=False)
        return rows[0] if rows else None

    def list_failed(self) -> list[Row]:
        """Every parked failure (``IsFailed=1``), oldest-first — the Queue-page failed surface."""
        return self._by({"IsFailed": True})

    def list_all(self) -> list[Row]:
        """Every live record (any step, failed or not), oldest-first — the record-centric Queue view
        (packet 1018). Short-lived records make this cheap; parked failures are the only durable rows."""
        return self._by({})

    def failed_count(self) -> int:
        """Indexed count of parked failures (the red nav badge)."""
        _, total = self._e.page(_QUEUE, eq={"IsFailed": True}, per_page=1, count=True)
        return total

    def active_count(self) -> int:
        """Non-failed rows across all types — 'work still in flight'."""
        _, total = self._e.page(_QUEUE, eq={"IsFailed": False}, per_page=1, count=True)
        return total


def queue_repo(backend) -> Optional[QueueRepo]:
    """The QueueRepo over a backend's engine, or None for a backend without one."""
    eng = getattr(backend, "engine", None)
    return QueueRepo(eng) if eng is not None else None


_ALERT = "ALERT"
_ALERT_HISTORY_CAP = 500   # keep the newest N event rows; older are trimmed on append


def _suppress_key(condition: str, job_name) -> str:
    return f"{condition}:{job_name or ''}"


class AlertsRepo:
    """Monitor alert history + suppressions over the engine (packet 1019). ONE ``ALERT`` table; the
    ``Type`` slot discriminates ``event`` (append-only history) from ``suppress`` (one row per
    ``<condition>:<job uuid>`` key, carrying an ``until`` in jor). Plain dicts in/out — the monitor
    layer owns the ``AlertEvent`` dataclass, so the storage layer never imports it (no layering cycle).
    Moves alert state off the local ``monitor/`` files so it travels with the DB like every other table."""

    def __init__(self, engine: StorageEngine):
        self._e = engine

    # -- history --------------------------------------------------------------
    def append_event(self, *, ts: str, condition: str, severity: str, message: str,
                     job_name: Optional[str] = None) -> None:
        import uuid as _uuidlib
        self._e.create(_ALERT, str(_uuidlib.uuid4()), {
            "Type": "event", "Timestamp": ts or "", "SuppressKey": "",
            "condition": condition, "severity": severity, "message": message, "job_name": job_name or "",
        })
        self._trim_history()

    def list_history(self, limit: int = 50) -> list[dict]:
        rows, _ = self._e.page(_ALERT, eq={"Type": "event"}, orderby="Timestamp", desc=True,
                               per_page=max(1, limit), count=False)
        return [{"ts": r.jor.get("Timestamp", ""), "condition": r.jor.get("condition", ""),
                 "severity": r.jor.get("severity", "warning"), "message": r.jor.get("message", ""),
                 "job_name": r.jor.get("job_name") or None} for r in rows]

    def _trim_history(self) -> None:
        rows, _ = self._e.page(_ALERT, eq={"Type": "event"}, orderby="Timestamp", desc=True,
                               per_page=_ALERT_HISTORY_CAP + 200, count=False)
        for r in rows[_ALERT_HISTORY_CAP:]:
            self._e.delete(_ALERT, r.key)

    # -- suppression ----------------------------------------------------------
    def set_suppress(self, condition: str, scope, until_iso: str, *, job_name=None) -> None:
        """``scope`` is the identity the suppression is keyed on — the job's UUID (packet 1149),
        resolved by the monitor layer. ``job_name`` rides jor for display only."""
        key = _suppress_key(condition, scope)
        jor = {"Type": "suppress", "Timestamp": "", "SuppressKey": key,
               "condition": condition, "job_name": (job_name if job_name is not None else scope) or "",
               "until": until_iso}
        row = self._e.get_one(_ALERT, SuppressKey=key)
        if row is not None:
            self._e.update(_ALERT, row.key, jor)
        else:
            import uuid as _uuidlib
            self._e.create(_ALERT, str(_uuidlib.uuid4()), jor)

    def is_suppressed(self, condition: str, scope) -> bool:
        from datetime import datetime, timezone
        row = self._e.get_one(_ALERT, SuppressKey=_suppress_key(condition, scope))
        until_str = row.jor.get("until", "") if row is not None else ""
        if not until_str:
            return False
        try:
            until = datetime.fromisoformat(until_str)
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) < until
        except Exception:
            return False


def alerts_repo(backend) -> Optional[AlertsRepo]:
    """The AlertsRepo over a backend's engine, or None for a backend without one."""
    eng = getattr(backend, "engine", None)
    return AlertsRepo(eng) if eng is not None else None
