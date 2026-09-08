"""Offline JOB identity conversion — move every job to its own UUID (packet 1372-01).

**The defect.** `JobsRepo.save()` mints a fresh `uuid4` for the JOB record key, independently of
`JobConfig.id`, which the browser create route mints separately. So most browser-created jobs carry
TWO uuids: the key the record lives at, and the id every STORAGE lineage, HISTORY run and QUEUE work
record already links to. The shipped CLI create path supplies no id at all, and `JobConfig.to_dict()`
omits a falsy one — so an id-less JOB is reachable product state, and a scheduled id-less job writes
a blank `UUIDJob`: no cron-overrun protection, job-less artifacts, and history its own UUID cannot
find. The runner's apparent lazy repair is dead (it re-saves with `overwrite=False`, both engines
refuse the already-present name, and the failure is swallowed).

**The conversion.** One UUID, three meanings::

    JOB native record key == JobConfig.id == the related UUIDJob

Related records already point at `JobConfig.id`, so this is a **JOB-table re-key with cross-table
verification** — not a rewrite of every related row.

**What it refuses to guess.** Nothing here consults a name. A nonblank malformed id, two configs
claiming one id, an occupied target key that is not our own half-finished replacement, or a record
whose `ConfigJSON` will not parse BLOCKS the whole run before the first write, with an
administrator-facing reason. Blank `UUIDJob` on a related record legitimately means job-less work,
so it is left exactly as it is.

**Order is the safety property.** For a re-key: read the attached bytes, create the replacement at
the target key with the original record's `JSONOfRecord`, copy those bytes unchanged, read BOTH back
and compare, and only then delete the old record. The attachment is OPAQUE — this conversion moves
recorded identity and never inspects, validates or requires what is attached. No container delete
is used anywhere — FileMaker OData's container `DELETE` removes the whole record (box-verified), so
a copy that "tidied up" the source could destroy the job it was migrating.

**Restartable without a journal, because the state is derivable.** Old row only means unstarted; old
row plus a target that matches it means the copy or its verification can resume; a target alone at
the correct key means the re-key finished; old row plus a target that is a DIFFERENT job blocks.

**Not a schema change, and not installer work.** The FileMaker file, the JOB projection map and
`db_schema_build.txt` are untouched. Only which key a job lives at changes — which is what
`SETTING.ProjectionVersion` exists to signal, so activation is its 1 -> 2 increment
(`projections.assert_projection`), stamped only after this conversion AND the incumbent file-wide
refresh both succeed. This module never stamps it: converting is half the transition.
"""

from __future__ import annotations

import os as _os
import re
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

_JOBS = "JOB"
_CREDENTIAL = "CredentialData"

#: The tables whose records already link to a job by `JobConfig.id`. Verified per converted identity
#: rather than by enumerating the catalog: the reachability claim is per job, and STORAGE is the
#: largest table in the corpus.
_RELATED = ("STORAGE", "HISTORY", "QUEUE")

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Plan actions.
CURRENT = "current"   # key == id already; nothing to write
ADOPT = "adopt"       # id-less: the record adopts the key it already lives at
REKEY = "rekey"       # a sound id that differs from the key: create at the id, verify, delete old
RESUME = "resume"     # a prior run created the replacement; finish and delete the old row

# Outcome words.
ALREADY_CURRENT = "already_current"
CONVERTED = "converted"
REFUSED = "refused"
INCOMPLETE = "incomplete"
UNAVAILABLE = "unavailable"


class ConversionRefused(RuntimeError):
    """The plan found a blocking class. Nothing was written."""


class ConversionIncomplete(RuntimeError):
    """A write or its verification failed part-way. `ProjectionVersion` is NOT advanced."""


class JobStoreUnreadable(RuntimeError):
    """The JOB table could not be enumerated, so no plan can be built."""


def is_sound_uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.match(value.strip()))


def new_job_id() -> str:
    return str(_uuid.uuid4())


# ── config document handling ──────────────────────────────────────────────────────────
# The stored `ConfigJSON` is edited as a YAML DOCUMENT, never round-tripped through `JobConfig`.
# `JobConfig.to_dict()` deliberately re-emits the STRUCTURED trigger shape, so re-serializing here
# would migrate a legacy `cron:` trigger as a side effect of a re-key — a semantic change this
# conversion has no mandate to make, in the one operation that must preserve meaning exactly. It
# would also silently drop any key a future build adds and this one does not know.

def parse_config_doc(config_json: str) -> dict:
    """The stored config as a plain dict.

    Raises `ValueError` for BOTH failure modes — text YAML cannot parse, and text that parses to
    something other than a mapping. They are one fact to every caller ("this configuration cannot be
    read"), and letting the parser's own exception type escape meant a caller catching the documented
    one still crashed on the commoner case.
    """
    try:
        data = yaml.safe_load(config_json or "")
    except yaml.YAMLError as exc:
        raise ValueError(f"the stored job configuration is not readable YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("the stored job configuration is not a YAML mapping")
    return data


def config_doc_with_id(config_json: str, job_id: str) -> str:
    """The same document with `id` set — every other key preserved verbatim."""
    data = parse_config_doc(config_json)
    data["id"] = job_id
    return yaml.dump(data, allow_unicode=True, sort_keys=False)


def _doc_id(data: dict) -> Any:
    return data.get("id")


def _display_name(jor: dict) -> str:
    """For prose only. A name never identifies a record here."""
    return str(jor.get("Name", "") or "?")


# ── semantic comparison ───────────────────────────────────────────────────────────────

def semantic_jor_equal(a: dict, b: dict) -> bool:
    """Records are equal when every ordinary key matches and the configs mean the same thing.

    `ConfigJSON` is compared as a PARSED document, not as text: a re-read may come back with
    different YAML formatting for the identical configuration, and a byte comparison there would
    report a successful copy as a failure. The attached container bytes, by contrast, are compared
    byte for byte — those are opaque, so formatting is not a question that arises.
    """
    keys = set(a) | set(b)
    for key in keys:
        if key == "ConfigJSON":
            continue
        if a.get(key) != b.get(key):
            return False
    try:
        return parse_config_doc(a.get("ConfigJSON", "")) == parse_config_doc(b.get("ConfigJSON", ""))
    except Exception:
        return a.get("ConfigJSON") == b.get("ConfigJSON")


# ── the plan ──────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class JobPlanEntry:
    key: str                 # where the record lives now
    target: str              # where it must live
    action: str
    name: str                # display only


@dataclass(frozen=True)
class ConversionPlan:
    entries: tuple[JobPlanEntry, ...] = ()
    blocking: tuple[str, ...] = ()
    #: The number of distinct job identities — the record count the JOB table must hold once the
    #: plan has been applied. On a blocked plan it is the raw row count, which nothing acts on.
    total: int = 0
    #: Pre-conversion reference counts, `{job_id: {table: count}}`, captured before any write so the
    #: post-conversion check compares against measured fact rather than against itself.
    references: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return bool(self.blocking)

    @property
    def work(self) -> tuple[JobPlanEntry, ...]:
        return tuple(e for e in self.entries if e.action != CURRENT)

    @property
    def already_current(self) -> bool:
        return not self.blocking and not self.work


def _unattributable_job_runs(engine) -> list:
    """QUEUE Job Runs carrying a blank `UUIDJob` — live work whose owner cannot be determined.

    A blank `UUIDJob` on a STORAGE or HISTORY row is left alone: it legitimately means job-less work
    (a browser upload), and attaching it by name is exactly the guess this cutover ends. A QUEUE Job
    Run is different because it is **live work**. After the cutover a run is dispatched by the UUID
    it carries, so a blank one is not merely unattributed — it is unrunnable. It blocks, and the
    administrator's remedy is stated: let the run finish, or delete it from the Queue page.

    A Job Run is discriminated the way the shipped readers discriminate it today — a producing step
    plus a `Payload.job_name` — because that is still the only discriminator in the product; 1372-02
    replaces it with an explicit run kind. Failed rows are included deliberately: they are durable,
    and a durable run nobody can attribute is precisely what must not be carried across.
    """
    from corpusfm.server.jobs.run_queue import _RUN_ACTIVE_STEPS

    out = []
    for step in _RUN_ACTIVE_STEPS:
        for row in engine.list_where("QUEUE", eq={"Type": step}):
            payload = row.jor.get("Payload", {}) or {}
            if not payload.get("job_name"):
                continue                                   # a browser import is not a Job Run
            if not (row.jor.get("UUIDJob") or "").strip():
                out.append(row.key)
    return out


def _reference_counts(engine, job_id: str) -> dict:
    """How many related records in each table point at this identity. One counted page per table."""
    out = {}
    for logical in _RELATED:
        _rows, total = engine.page(logical, eq={"UUIDJob": job_id}, per_page=1, count=True)
        out[logical] = int(total)
    return out


def plan(engine) -> ConversionPlan:
    """Classify EVERY job before anything is written.

    The whole set is read and classified first because a blocking class anywhere means the run may
    not start: converting the readable half of a corpus and then refusing would leave an
    administrator with a partially re-keyed JOB table and no marker explaining it.
    """
    try:
        rows = engine.list_all(_JOBS)
    except Exception as exc:
        raise JobStoreUnreadable(
            f"the JOB table could not be read ({type(exc).__name__}); no conversion can be "
            "planned against a store that cannot be enumerated") from exc

    by_key = {r.key: r for r in rows}
    parsed: dict = {}
    blocking: list[str] = []

    for row in rows:
        try:
            parsed[row.key] = parse_config_doc(row.jor.get("ConfigJSON", ""))
        except Exception as exc:
            blocking.append(
                f"job record {row.key} ({_display_name(row.jor)}) has an unreadable configuration: "
                f"{exc}. Repair or remove the record; the conversion will not guess its identity.")

    if blocking:
        return ConversionPlan(blocking=tuple(sorted(blocking)), total=len(rows))

    # Malformed nonblank ids block. A blank id is the ADOPT class, not an error.
    for key, doc in parsed.items():
        raw = _doc_id(doc)
        if raw in (None, "") or (isinstance(raw, str) and not raw.strip()):
            continue
        if not is_sound_uuid(raw):
            blocking.append(
                f"job record {key} ({_display_name(by_key[key].jor)}) declares id {raw!r}, which is "
                "not a UUID. It is not repaired by name or by ordering.")

    # Duplicate ids block: two configs claiming one identity cannot both be right, and choosing
    # between them by first/last/order/case is exactly what this cutover exists to end.
    #
    # ONE SHAPE IS NOT A DUPLICATE, and missing that was a real defect this suite caught: an
    # interrupted re-key leaves the original AND its replacement, both declaring the same id, which
    # is the resumable state the packet describes. It is recognised only when the pair is exactly
    # two records, one of them living AT the claimed id, and the two are semantically identical —
    # a copy of one record, not two jobs. `replacements` holds the replacement halves so the entry
    # loop below does not also emit them as jobs of their own.
    claimed: dict = {}
    for key, doc in parsed.items():
        raw = _doc_id(doc)
        if isinstance(raw, str) and is_sound_uuid(raw):
            claimed.setdefault(raw.strip(), []).append(key)

    replacements: set = set()
    for job_id, keys in sorted(claimed.items()):
        if len(keys) == 1:
            continue
        others = [k for k in keys if k != job_id]
        if (len(keys) == 2 and job_id in keys
                and semantic_jor_equal(by_key[job_id].jor, by_key[others[0]].jor)):
            replacements.add(job_id)
            continue
        blocking.append(
            f"job id {job_id} is claimed by {len(keys)} records ({', '.join(sorted(keys))}). "
            "The conversion will not choose one.")

    if blocking:
        return ConversionPlan(blocking=tuple(sorted(blocking)), total=len(rows))

    entries: list[JobPlanEntry] = []
    for key in sorted(by_key):
        if key in replacements:
            continue                    # covered by its source row's RESUME entry
        row = by_key[key]
        doc = parsed[key]
        raw = _doc_id(doc)
        name = _display_name(row.jor)

        if raw in (None, "") or (isinstance(raw, str) and not raw.strip()):
            # R2: an id-less row adopts the key it ALREADY lives at. That invents no relationship —
            # an id-less job wrote blank UUIDJob, so nothing points anywhere to be reconciled.
            entries.append(JobPlanEntry(key=key, target=key, action=ADOPT, name=name))
            continue

        job_id = raw.strip()
        if job_id == key:
            entries.append(JobPlanEntry(key=key, target=key, action=CURRENT, name=name))
            continue

        occupant = by_key.get(job_id)
        if occupant is None:
            entries.append(JobPlanEntry(key=key, target=job_id, action=REKEY, name=name))
            continue

        # The target key is occupied. It is OURS only if it is the same record: a prior interrupted
        # run created the replacement and did not reach the delete. Anything else is a conflict.
        if semantic_jor_equal(occupant.jor, row.jor):
            entries.append(JobPlanEntry(key=key, target=job_id, action=RESUME, name=name))
        else:
            blocking.append(
                f"job record {key} ({name}) must move to {job_id}, which is already occupied by a "
                f"different job record ({_display_name(occupant.jor)}). The conversion will not "
                "overwrite it.")

    if blocking:
        return ConversionPlan(blocking=tuple(sorted(blocking)), total=len(rows))

    # A re-key retires the OLD record key. Every measured related record links by `JobConfig.id`, so
    # nothing should reference the key we are about to free — but if anything does, the conversion
    # would silently orphan it, and that is a data-linkage loss no later read could explain.
    for run_key in _unattributable_job_runs(engine):
        blocking.append(
            f"queue record {run_key} is a Job Run with no UUIDJob, so the job that owns it cannot "
            "be determined and will not be guessed from its name. Let the run finish, or delete it "
            "on the Queue page, then re-start CORPUSfm.")

    if blocking:
        return ConversionPlan(blocking=tuple(sorted(blocking)), total=len(rows))

    references: dict = {}
    for entry in entries:
        references[entry.target] = _reference_counts(engine, entry.target)
        if entry.action in (REKEY, RESUME):
            stale = _reference_counts(engine, entry.key)
            held = {t: n for t, n in stale.items() if n > 0}
            if held:
                blocking.append(
                    f"job record {entry.key} ({entry.name}) must move to {entry.target}, but "
                    f"{', '.join(f'{n} {t} record(s)' for t, n in sorted(held.items()))} still link "
                    f"to the old key. Re-keying would orphan them.")

    if blocking:
        return ConversionPlan(blocking=tuple(sorted(blocking)), total=len(rows))

    # `total` is the number of distinct job IDENTITIES, which is also the record count the table
    # must hold afterwards. It is NOT `len(rows)`: an interrupted re-key currently occupies two rows
    # for one job, and the second is deleted by the resumption.
    return ConversionPlan(entries=tuple(entries), blocking=(), total=len(entries),
                          references=references)


# ── execution ─────────────────────────────────────────────────────────────────────────

def _blob(engine, key: str) -> Optional[bytes]:
    """The attached bytes, or None. Never decoded, never interpreted.

    `None` here is AMBIGUOUS and must never be read as "there is nothing attached" — see
    `_source_attachment`, which is the only caller allowed to act on it.
    """
    raw = engine.blob_get(_JOBS, key, _CREDENTIAL)
    return raw or None


def _source_attachment(engine, key: str, name: str) -> Optional[bytes]:
    """The attached record data to carry across, or a refusal. Never a guess.

    **This conversion converts recorded identity. It does not inspect what is attached.**
    `CredentialData` is opaque bytes belonging to the record: copy them when present, verify the
    copy, and say nothing about what they mean. Nothing here reads `AccountName`, `HasCredential`,
    `IsVerified` or the plaintext behind the container, and no decision depends on whether a job is
    "supposed to" have one. Those are 1372-02's questions.

    **What it does guard is the record copy.** `blob_get` cannot express failure: the shipped
    `FileMakerODataBackend._download_container` swallows every exception and returns `None`, so a
    transport failure is byte-for-byte indistinguishable from an empty container. Reading `None` as
    absence meant the replacement was created without the attachment, the byte comparison compared
    `None` with `None` and passed, and the original — the only copy — was deleted.

    `blob_exists` is the primitive that CAN say "I do not know", and its own docstring states the
    rule: *callers must never treat uncertainty as absence*. So:

    - bytes in hand      -> carry them, and prove them copied;
    - `exists is False`  -> a CONFIRMED absence. Nothing is attached, nothing to carry, and the copy
      is complete without it;
    - anything else      -> refuse before the delete. `exists is True` with no bytes, `exists is
      None`, or a raising probe all mean the record copy would be INCOMPLETE, and an incomplete copy
      never authorises removing the original.

    THIS IS ONLY AS GOOD AS `blob_exists`' ABILITY TO SAY `False`, which is where it first went
    wrong on a live box: FileMaker answers `204 No Content` for an empty container, that status was
    unlisted, and so every ordinary credentialless JOB arrived here as `None` and stopped the whole
    conversion. The rule below did not change; the primitive under it was taught to state an absence
    it had been measuring all along. `TestBlobExistsStatusMapping` pins that mapping.
    """
    raw = _blob(engine, key)
    if raw is not None:
        return raw
    exists = engine.blob_exists(_JOBS, key, _CREDENTIAL)
    if exists is False:
        return None
    raise ConversionIncomplete(
        f"the data attached to job record {key} ({name}) could not be read "
        f"(container present: {exists!r}). Refusing to move THIS job: the record copy would be "
        "incomplete, and an incomplete copy must not authorise deleting the original. This job is "
        "untouched; jobs converted earlier in the run have already moved, which is safe and is "
        "resumed rather than repeated. Re-run once storage is healthy.")


def _apply_adopt(engine, entry: JobPlanEntry) -> None:
    rows = engine.get_by_keys(_JOBS, [entry.key])
    if not rows:
        raise ConversionIncomplete(f"job record {entry.key} disappeared before it could adopt its key")
    jor = dict(rows[0].jor)
    jor["ConfigJSON"] = config_doc_with_id(jor.get("ConfigJSON", ""), entry.key)
    engine.update(_JOBS, entry.key, jor)
    back = engine.get_by_keys(_JOBS, [entry.key])
    if not back or not semantic_jor_equal(back[0].jor, jor):
        raise ConversionIncomplete(
            f"job record {entry.key} did not read back as written after adopting its key")


def _apply_rekey(engine, entry: JobPlanEntry) -> None:
    """Move one job: copy the record and its attached bytes, prove both, then delete the original."""
    rows = engine.get_by_keys(_JOBS, [entry.key])
    if not rows:
        raise ConversionIncomplete(f"job record {entry.key} disappeared before it could be moved")
    source = rows[0]
    attached = _source_attachment(engine, entry.key, entry.name)

    existing = engine.get_by_keys(_JOBS, [entry.target])
    if not existing:
        engine.create(_JOBS, entry.target, dict(source.jor))
    elif not semantic_jor_equal(existing[0].jor, source.jor):
        # Re-checked at execution: the plan was built from an earlier read, and creating over a
        # record that has since become a different job is the one mistake with no way back.
        raise ConversionIncomplete(
            f"the target key {entry.target} is occupied by a different job record; refusing to "
            "overwrite it")

    if attached is not None:
        engine.blob_put(_JOBS, entry.target, _CREDENTIAL, attached)

    back = engine.get_by_keys(_JOBS, [entry.target])
    if not back or not semantic_jor_equal(back[0].jor, source.jor):
        raise ConversionIncomplete(
            f"the replacement job record at {entry.target} did not read back as written; the "
            f"original at {entry.key} is untouched")
    if attached is not None and _blob(engine, entry.target) != attached:
        raise ConversionIncomplete(
            f"the data attached to job record {entry.key} did not copy byte-for-byte to "
            f"{entry.target}; the original is untouched")

    # Both halves proven, so the old row may go. Deleting it is what makes the identity single. The
    # `is not None` guard is load-bearing: comparing None with None would "pass" for bytes that were
    # never read, which is exactly how an unreadable attachment once authorised its own deletion.
    engine.delete(_JOBS, entry.key)


def _verify(engine, plan_: ConversionPlan) -> None:
    """Whole-set verification. Anything short of every claim below leaves `ProjectionVersion` behind."""
    rows = engine.list_all(_JOBS)
    if len(rows) != plan_.total:
        raise ConversionIncomplete(
            f"the JOB table holds {len(rows)} record(s) after the conversion but held "
            f"{plan_.total} before it")

    by_key = {r.key: r for r in rows}
    ids: dict = {}
    for row in rows:
        doc = parse_config_doc(row.jor.get("ConfigJSON", ""))
        job_id = _doc_id(doc)
        if not is_sound_uuid(job_id) or job_id.strip() != row.key:
            raise ConversionIncomplete(
                f"job record {row.key} carries id {job_id!r}; the one-UUID invariant is not met")
        if job_id in ids:
            raise ConversionIncomplete(f"job id {job_id} is carried by more than one record")
        ids[job_id] = row.key

    for entry in plan_.entries:
        row = by_key.get(entry.target)
        if row is None:
            raise ConversionIncomplete(
                f"job {entry.name} is not present at {entry.target} after the conversion")
        if entry.action in (REKEY, RESUME) and entry.key in by_key:
            raise ConversionIncomplete(
                f"the old job record {entry.key} still exists beside its replacement "
                f"{entry.target}")
        # NOTHING ABOUT THE ATTACHMENT IS ASSERTED HERE. `_apply_rekey` proved the copied bytes
        # before it deleted anything, which is the point at which it mattered, and every ordinary
        # jor key — `HasCredential` and `AccountName` among them — is covered by the record
        # comparison it already made. Re-deriving a credential claim at this distance would be
        # validating attached content, which this conversion does not do.
        if entry.target not in plan_.references:
            # Defaulting to the post-conversion reading would make this check compare a measurement
            # with itself and pass regardless — the exact shape of guard that stops guarding.
            raise ConversionIncomplete(
                f"no pre-conversion reference count was captured for job {entry.name}; the "
                "reachability of its related records cannot be verified")
        after = _reference_counts(engine, entry.target)
        before = plan_.references[entry.target]
        if after != before:
            raise ConversionIncomplete(
                f"related records for job {entry.name} changed during the conversion "
                f"(before {before}, after {after})")


def convert(engine, *, plan_: Optional[ConversionPlan] = None) -> dict:
    """Plan, execute, verify. Returns a structured outcome; raises for a refusal or a partial run.

    The caller advances `ProjectionVersion` ONLY on a clean return — activation follows verification,
    and an exception here means startup must not begin JOB work over this corpus.
    """
    plan_ = plan_ if plan_ is not None else plan(engine)
    if plan_.blocked:
        raise ConversionRefused("; ".join(plan_.blocking))

    counts = {ADOPT: 0, REKEY: 0, RESUME: 0, CURRENT: 0}
    for entry in plan_.entries:
        if entry.action == ADOPT:
            _apply_adopt(engine, entry)
        elif entry.action in (REKEY, RESUME):
            _apply_rekey(engine, entry)
        counts[entry.action] += 1

    _verify(engine, plan_)
    return {
        "result": ALREADY_CURRENT if plan_.already_current else CONVERTED,
        "jobs": plan_.total,
        "adopted": counts[ADOPT],
        "rekeyed": counts[REKEY] + counts[RESUME],
        "resumed": counts[RESUME],
        "unchanged": counts[CURRENT],
    }


# ── local development jobs directory ──────────────────────────────────────────────────
# The unpublished dev/test path keeps jobs as YAML files, and those documents had the same identity
# defect twice over: a file written by the CLI create path carries no `id`, and the FILENAME was an
# encoding of the user's NAME — so two case-variant names shared one file and renaming a job orphaned
# its state sidecar. This gives an id-less fixture a sound id and moves both files to `<job_uuid>`,
# verifying the new state before removing the old (R5). Packet 1372-02 made `store`/`state` read that
# layout, so the two land together.

# `plan_jobs_dir` and `convert_jobs_dir` are DELETED (packet 1361-01). They converted a directory of
# `<job_uuid>.yaml` documents to UUID-keyed filenames — the local job store, which is gone. The JOB
# table is the only store now, on every install and in development alike, and `plan`/`convert` above
# are its converters. Converting files nothing can read is not a migration.



__all__ = [
    "ADOPT", "ALREADY_CURRENT", "CONVERTED", "CURRENT", "INCOMPLETE", "REFUSED", "REKEY",
    "RESUME", "UNAVAILABLE", "ConversionIncomplete", "ConversionPlan", "ConversionRefused",
    "JobPlanEntry", "JobStoreUnreadable", "config_doc_with_id", "convert",
    "is_sound_uuid", "new_job_id", "parse_config_doc", "plan",
    "semantic_jor_equal",
]
