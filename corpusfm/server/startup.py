"""Startup readiness — ONE retryable prerequisite state machine (packet 1361-01, rounds 3-4).

**What this replaces.** The prerequisite chain used to live inline in the web lifespan, and every
step carried its own ``try/except`` that logged a warning and let the boot continue. That produced a
box that could open the readiness gate on the strength of a catalog scan alone, with the projection
assert, the JOB identity conversion, the tag-link integrity pass or the promotion repair having
failed moments earlier — a partially operational state, which the governing ruling says does not
exist:

    CORPUSfm is either database-ready or paused. There is no partially operational state.

So the chain is an ATTEMPT, not a sequence of independent best-effort steps, and this module is its
authority. Three properties define it:

1. **Every attempt runs the chain from its beginning.** The steps are idempotent by construction —
   an already-asserted projection writes nothing, an already-repaired lineage repoints nothing, an
   already-converted corpus answers ``already_current`` — so restarting from the top is the cheap,
   honest retry rather than a resumable state machine nobody can prove correct.
2. **A database availability/read failure STOPS the attempt.** It does not log-and-continue, and the
   gate does not open because a later step succeeded. The failure closes the gate (arming the
   recovery coordinator) and the coordinator runs the whole chain again on its bounded cadence.
3. **Safe, explicitly defined LOCAL/DATA "declined to act" outcomes are NONFATAL.** They are named
   one by one below, never inferred, and round 4 narrowed what qualifies: a decline is valid only
   when it rests on a fact that needs no successful database assertion — a backend that structurally
   has no SETTING singleton or no storage engine, a seed asset that is not shipped, a bundled file
   that is malformed. Anything a database refused to read or write is a FAILURE, whatever the helper
   used to call it.

**THE HELPERS OWE THIS AUTHORITY THE TRUTH (round 4).** The chain can only stop on what it is told,
and five helpers were still folding database failures into ordinary values — `[]`, `False`, `None`,
"skipped", "declined", or an `ok: True` that had removed nothing. A stage that logs a warning and
answers success is indistinguishable here from one that succeeded, so the swallow, not the chain,
decided whether the box opened. Every helper the chain calls now reports `read_failed` /
`write_failed`, or lets the exception out:

===================================  ==================================================================
helper                               what it used to swallow
===================================  ==================================================================
`assert_no_setting_secrets`          an unreadable SETTING/USER/GITREG/SERVER/MCPTOKEN read, and a
                                     found secret it could not strip — both answered `ok: True`
`seed_default_artifacts`             an unreadable empty-catalog gate and an unstorable seed — both
                                     answered `[]`, the same value as "nothing to do"
`conversion_complete`                an unreadable SETTING and an unreadable published-storage
                                     authority — both answered `False`, i.e. "not converted"
`latest_available`                   an unreadable `is_pending` probe — answered `False`, i.e.
                                     "promotions are not usable here"
`convert_and_repair`                 every failed delete/upsert inside the walk — the pass still
                                     answered `ok: True` over half-converted lineages
`repair_user_tag_links`              every failed delete — the pass still answered `ok: True`
`migrate_job_callbacks_to_servers`   a failed SERVER write — recorded as a "conflict", which is a
                                     deliberate decline and the opposite of what happened
===================================  ==================================================================

**Stopping means stopping.** The attempt raises out of the stage loop on the first failure, so no
later stage runs and no further FileMaker call is made during that attempt. `prerequisites_satisfied`
is never reached, the interlock stays armed, readiness stays closed, and the coordinator reruns the
whole chain from its beginning on the bounded cadence.

**Once per process.** The chain's MUTATIONS — the projection assert and its conversion seam, the
tag-link repair, the promotion conversion/repair, the callback migration, the seed — are boot-once
conversions. After the process has completed startup, a later runtime outage is recovered by ONE
complete catalog validation and nothing else: :func:`recover` is what the recovery coordinator calls,
and it makes exactly that distinction.

**The interlock.** :func:`attempt` calls ``availability.begin_startup()`` first, which holds the gate
shut for the duration, and ``availability.prerequisites_satisfied()`` only once the whole chain has
passed. That is what stops a synchronizer's or a coordinator's successful scan from opening a box
whose prerequisites failed — the ordering alone would not, because a validation pass is reachable
from more than one thread.
"""

from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_complete = False


def prerequisites_complete() -> bool:
    """Has this process completed startup readiness at least once?"""
    with _lock:
        return _complete


def reset_for_testing() -> None:
    """Forget that startup completed (process shutdown and the test seam).

    Called by ``availability.reset()``, so the one fixture that returns a test process to the startup
    state returns this record with it.
    """
    global _complete
    with _lock:
        _complete = False


class _Stopped(Exception):
    """A prerequisite stage could not establish its own precondition. The attempt stops here.

    ``blocking`` is the TYPED retry classification (packet 1361-01, round 7). False — the default —
    means the coordinator retries the whole chain at its bounded cadence. True means the refusal is
    deterministic: its inputs were read successfully, the answer is decided, and repeating it
    unchanged cannot alter it. The coordinator then stays paused with an intervention-required
    explanation instead of running an expensive chain every few seconds forever.
    """

    def __init__(self, stage: str, reason: str, blocking: bool = False) -> None:
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason
        self.blocking = blocking


def _stop(stage: str, reason: str, *, blocking: bool = False):
    raise _Stopped(stage, reason, blocking)


# ── the stages ────────────────────────────────────────────────────────────────────────────────────

def _stage_schema_probe(be, out: dict) -> None:
    """The build-mismatch probe, moved into the startup authority. AN UNREADABLE PROBE MUST NOT FAIL
    OPEN (packet 1361-01, round 3).

    ``is_pending`` swallows every exception and answers "no mismatch", which on a box whose
    FileMaker was unreachable at boot is the one answer that is certainly unfounded: it is not
    evidence the schema matches, it is the absence of evidence either way. The probe RAISES on an
    unreadable Build, and the attempt stops — the same outcome any other unreadable prerequisite
    gets.

    A Build that reads back EMPTY is a different thing and stays indeterminate: a fresh corpus has
    no stamp yet, and refusing to boot on it would brick every new install.

    **A successfully read, non-empty Build that DIFFERS is a DETERMINISTIC refusal** (packet
    1361-01, round 11, developer ruling). Rounds 7-10 let it record a mismatch and carry on to
    functional readiness, on the reasoning that a ``/build-mismatch`` page is "a product state with
    its own page and its own recovery, not an outage". That was wrong on the first half and
    irrelevant on the second: the probe read the live build successfully, the expected build is a
    shipped constant, and they differ — a typed, authoritative fact whose answer no repetition can
    change. Continuing past it publishes a READY box over a database this build was not made for,
    and then builds a catalog from it, starts a scheduler against it and lets queue workers write to
    it. Packet 085 is fresh-install-only: there is no in-place migration for the chain to reach.

    So it stops the attempt with ``blocking=True``. Nothing after this stage runs, the gate stays
    closed, and the administrator gets the guidance on the local paused supervisory page — the only
    build-mismatch surface there is (round 12 retired the unreachable ``/build-mismatch`` route).

    **ONE live-Build read** (round 12). The probe returns the facts it established, and both the
    classification and the guidance are composed from that single result rather than from a verdict
    plus a second read of the same field.
    """
    from corpusfm.storage import storage_migration
    try:
        probe = storage_migration.probe_build(be)
    except Exception as exc:                                        # noqa: BLE001
        logger.warning("startup: the build/schema probe could not be read", exc_info=True)
        _stop("schema_probe", f"{type(exc).__name__}: {exc}")
    out["build_mismatch"] = probe.mismatch
    if probe.mismatch:
        _stop("schema_probe", _build_mismatch_guidance(probe.live, probe.expected), blocking=True)


def _build_mismatch_guidance(live: str, target: str) -> str:
    """The administrator-facing sentence for a proven build mismatch. Composed here, from facts the
    probe already read, so the paused page can render it without touching the database.

    It keeps the DIRECTION distinction that is the whole point of the guidance: a database OLDER than
    the code needs a fresh install, while a database NEWER than the code means the wrong (older) code
    is deployed and it is the CODE that must move. That distinction used to live in the retired
    `/build-mismatch` template; this is now its only home.
    """
    def _n(b):
        try:
            return int(str(b).strip().lstrip("."))
        except Exception:
            return -1

    both = f"the installed database is at build {live or 'unknown'} and this CORPUSfm expects " \
           f"{target or 'unknown'}"
    if _n(live) >= 0 and _n(target) >= 0 and _n(live) > _n(target):
        return (f"{both}. The database is NEWER than this code, so an older CORPUSfm has been "
                "deployed over it — upgrade the code rather than touching the database.")
    return (f"{both}. There is no in-place migration: run the CORPUSfm installer on this machine "
            "to complete a fresh installation of the storage database.")


def _stage_projection(be, out: dict) -> None:
    """Assert the FM-side index-projection contract BEFORE any record is written, and carry the
    version-keyed conversion seam that makes the JOB table safe for UUID-addressed code to read.

    ``assert_projection`` never raises; every ``ok`` False it reports is a database read, write,
    conversion, refresh or stamp that did not happen, and each stops the attempt. The one nonfatal
    outcome is ``skipped`` — an unsupported backend has no SETTING singleton and no contract to
    assert.
    """
    from corpusfm.config import is_server_mode
    if not is_server_mode():
        out["projection"] = "local"
        return
    from corpusfm.storage import projections
    res = projections.assert_projection(be)
    if res.get("skipped"):
        out["projection"] = "skipped"
        return
    if not res.get("ok"):
        # TYPED classification, from the conversion's own result constant — never from the text of
        # an exception (round 7). `REFUSED` is the planner's word for "I found a blocking class and
        # wrote nothing"; it read the JOB table successfully and decided. `UNAVAILABLE` (the table
        # could not be enumerated) and `INCOMPLETE` (a write or its verification failed part-way)
        # are outages and stay transient, as does every other `ok` False this stage reports —
        # a failed SETTING read, a failed map write, a refresh that did not complete, a stamp that
        # did not read back.
        from corpusfm.storage import job_identity_conversion as conv
        identity = res.get("job_identity") or {}
        blocking = identity.get("result") == conv.REFUSED
        _stop("projection",
              str(res.get("reason") or identity.get("detail") or "assert failed"),
              blocking=blocking)
    out["projection"] = res.get("wrote") or "ok"


def _stage_conversion(be, out: dict) -> None:
    """ONE ProjectionVersion / conversion check, here and nowhere else (packet 1361-01, round 3).

    It used to be asked twice on every box and never in the same breath as readiness: once per
    scheduler cycle, from a second process that could not see this one's gate, and once inside the
    queue-worker resume. Both were FileMaker reads on a repeating clock, and the scheduler's ran
    while the process was paused. The question is a STARTUP question — "may this build address this
    corpus at all" — so it is asked once, before the scheduler and the queue workers exist.

    An unconverted corpus therefore leaves the process PAUSED rather than half-serving. That is the
    ruling's own consequence, and it is self-healing: the recovery coordinator reruns this chain, and
    the projection stage above is what performs the conversion.
    """
    from corpusfm.storage import projections
    res = projections.assert_conversion_complete(be)
    if res.get("read_failed"):
        _stop("conversion", str(res.get("reason") or "the projection version could not be read"))
    if not res.get("ok"):
        # `structural` is the typed deterministic case: the published authority was READ and says a
        # corpus exists, and this process's backend cannot be asked the version question at all.
        # A corpus that is merely BEHIND is transient — the projection stage above converts it, and
        # the next attempt is a genuine second chance.
        _stop("conversion",
              str(res.get("reason") or "the JOB identity conversion has not completed"),
              blocking=bool(res.get("structural")))
    out["conversion"] = "current"


def _stage_secret_fence(be, out: dict) -> None:
    """Strip any legacy AI key a hand-copied config may have carried (packet 085 §8 / 1007).

    **It is no longer nonfatal** (packet 1361-01, round 4), and the previous entry's reasoning was
    exactly backwards: "it swallows its own read failures, so a fence that could not run has removed
    nothing and asserted nothing" is an argument for STOPPING, not for continuing. A fence that
    asserted nothing has not established the property the boot claims to have established, and a
    fence that FOUND a secret and could not strip it has left it in place while reporting success.

    Both are database failures now, reported as `read_failed` / `write_failed`. A backend with
    neither the SETTING strip methods nor an engine has nothing to check, which is a local
    structural fact and stays clean.
    """
    from corpusfm.config import is_server_mode
    if not is_server_mode():
        return
    from corpusfm.storage import projections
    res = projections.assert_no_setting_secrets(be)
    if res.get("read_failed") or res.get("write_failed") or not res.get("ok"):
        # `verified_present` is the typed deterministic case: the cleanup write COMPLETED and an
        # authoritative reread — a read that succeeded — still shows the forbidden key. Nothing a
        # repeat can do changes that; an administrator must. A write that raised, or one that could
        # not be reread because FileMaker disappeared, is an outage and stays transient.
        _stop("secret_fence", str(res.get("reason") or "the secret fence did not complete"),
              blocking=bool(res.get("verified_present")))
    out["secret_fence"] = len(res.get("removed") or [])


def _stage_tag_integrity(be, out: dict) -> None:
    """Delete a ``User Tag`` link only for a blank endpoint or one proven absent by a chunked, fully
    paged keyed read.

    ``read_failed`` and ``write_failed`` are the pass's own words for "a database operation did not
    complete", and either stops the attempt — a delete that failed leaves a broken link the pass
    reported as removed. The only remaining ``ok`` False is the DECLINED-TO-ACT outcome the module
    documents — no storage engine on this backend, a structural local fact — and it is nonfatal: the
    pass changed nothing and claimed nothing.
    """
    from corpusfm.server.tag_integrity import repair_user_tag_links
    res = repair_user_tag_links(be)
    if res.get("read_failed") or res.get("write_failed"):
        _stop("tag_integrity", str(res.get("reason") or "a database operation failed"))
    if not res.get("ok"):
        logger.info("startup: tag-link integrity declined to act (%s)",
                    res.get("reason") or "unknown")
        out["tag_integrity"] = "declined"
        return
    out["tag_integrity"] = res.get("removed", 0)


def _stage_latest(be, out: dict) -> None:
    """Bring every job lineage to exactly one resolvable promotion, converting the retired per-record
    flag on the way.

    Correct BECAUSE OF THIS POSITION: it is a read-modify-write over the whole lineage picture, and
    nothing that promotes — no queue worker, no scheduler, no request — exists yet.

    **The availability check is made from facts this attempt already established** (packet 1361-01,
    round 4), not from ``latest.latest_available``. That helper answers a bare bool and swallows the
    `is_pending` read behind it, so a box whose FileMaker had just gone away reported "promotions are
    not usable" — a decline — for what was an outage. The two facts it combines are already in hand:
    the engine's presence is structural, and whether the storage migration is pending was measured
    STRICTLY by the schema probe in stage 1. Reusing them removes a swallowed read and a duplicate
    database call in one move.

    ``read_failed`` and ``write_failed`` both stop the attempt: a repair that could not complete its
    writes leaves lineages half-converted, which is the state this pass exists to remove.
    """
    from corpusfm.server import latest as _latest
    if "build_mismatch" not in out:
        # An INTERNAL consistency guard, not a database condition: this stage borrows the schema
        # probe's verdict, so a chain reordered such that the probe has not run yet would silently
        # read "no mismatch" from an absent key and repair against a schema nobody checked.
        _stop("latest", "the schema probe's verdict is not available; the prerequisite chain ran "
                        "out of order")
    if getattr(be, "engine", None) is None:
        out["latest"] = "declined"          # structural: this backend has no promotion links
        return
    if out["build_mismatch"]:
        out["latest"] = "declined"          # unreachable since round 11: a mismatch stops the chain
        return
    res = _latest.convert_and_repair(be)
    if res.get("read_failed") or res.get("write_failed"):
        _stop("latest", str(res.get("reason") or "a database operation failed"))
    if not res.get("ok"):
        logger.info("startup: promotion repair declined to act (%s)", res.get("reason") or "unknown")
        out["latest"] = "declined"
        return
    out["latest"] = {k: res.get(k) for k in ("lineages", "converted", "repointed", "deduped",
                                             "removed")}


def _stage_callbacks(be, out: dict) -> None:
    """Promote any pre-1219 per-job callback onto its SERVER record. Idempotent and bounded.

    A conflict (the server already carries a different callback) is REPORTED and left alone, because
    resolving it invisibly is the one outcome the migration exists to prevent. A failure to read the
    JOB table stops the attempt.
    """
    from corpusfm.server.remote_servers import migrate_job_callbacks_to_servers
    try:
        promoted, conflicts = migrate_job_callbacks_to_servers()
    except Exception as exc:                                        # noqa: BLE001
        logger.warning("startup: the job-callback migration could not read JOB", exc_info=True)
        _stop("callbacks", f"{type(exc).__name__}: {exc}")
        return
    if promoted:
        logger.info("packet 1219: promoted %d job callback(s) onto their server records", promoted)
    for job, value, why in conflicts:
        logger.warning("packet 1219: job %r kept a callback %r that was NOT promoted (%s) — set it "
                       "on the server under Settings if it is still wanted", job, value, why)
    out["callbacks"] = promoted


def _stage_seed(be, out: dict) -> None:
    """The default example artifacts, so a fresh catalog always has something for MCP/demo/testing.

    Fills an EMPTY catalog only, and is self-healing.

    **Its database halves are fatal** (packet 1361-01, round 4). The previous entry called this
    "explicitly nonfatal" because the helper swallowed everything into `[]` — which is the defect,
    not the justification. Two of its outcomes are database failures: an unreadable empty-catalog
    gate establishes nothing (and must not seed, because an unreadable catalog is not an empty one),
    and a prepared, validated seed that could not be STORED is a failed write.

    What stays nonfatal is the genuinely local half, and it is the model case for the rule: a seed
    asset that is not shipped, whose bytes cannot be read, that is not a CORPUSfm artifact, or that
    fails reabsorb validation. Those are facts about files on this machine, they require no
    successful database assertion, and a box with no seed assets is a correct empty corpus.
    """
    from corpusfm.config import is_server_mode
    if not is_server_mode():
        return
    from corpusfm.server.seed_artifact import seed_default_artifacts
    res = seed_default_artifacts(be)
    if res.get("read_failed") or res.get("write_failed"):
        _stop("seed", str(res.get("reason") or "a database operation failed"))
    if not res.get("ok"):
        _stop("seed", str(res.get("reason") or "the seed did not complete"))
    out["seeded"] = len(res.get("seeded") or [])
    if res.get("declined"):
        out["seed_declined"] = len(res["declined"])


_STAGES = (
    ("schema_probe", _stage_schema_probe),
    ("projection", _stage_projection),
    ("conversion", _stage_conversion),
    ("secret_fence", _stage_secret_fence),
    ("tag_integrity", _stage_tag_integrity),
    ("latest", _stage_latest),
    ("callbacks", _stage_callbacks),
    ("seed", _stage_seed),
)


# ── the attempt ───────────────────────────────────────────────────────────────────────────────────

def attempt(backend) -> dict:
    """Run the whole idempotent prerequisite chain, then ONE complete catalog validation.

    Returns ``{"ok", "stage", "reason", "detail"}``. ``ok`` True means the process is now READY: the
    gate opened, the resume callback ran, and startup is marked complete for the life of the process.
    ``ok`` False names the stage that stopped it and leaves the process PAUSED with the recovery
    coordinator armed. It never raises — a startup failure is a state, not an exception for a caller
    to handle.
    """
    global _complete
    from corpusfm.server import availability, catalog

    out: dict = {"ok": False, "stage": "", "reason": "", "blocked": False, "detail": {}}
    detail = out["detail"]
    # Hold the gate shut for the duration: a validation pass reached from another thread must not
    # open a process whose chain has not finished (or has already failed).
    availability.begin_startup()
    try:
        for name, fn in _STAGES:
            out["stage"] = name
            fn(backend, detail)
    except _Stopped as stopped:
        out["stage"] = stopped.stage
        out["reason"] = stopped.reason
        out["blocked"] = stopped.blocking
        if stopped.blocking:
            logger.error("STARTUP BLOCKED at the %s prerequisite (%s). This is a DETERMINISTIC "
                         "refusal: its inputs were read successfully and repeating it cannot change "
                         "the answer, so CORPUSfm stays PAUSED and does NOT retry. Correct the "
                         "condition and restart the service.", stopped.stage, stopped.reason)
            # `schema_probe` is the one blocking stage whose remedy is not "read the log": it is
            # "run the installer", and the reason string IS the guidance. Its own close reason
            # selects the build-mismatch copy on the paused page.
            reason_word = ("build_mismatch" if stopped.stage == "schema_probe" else "intervention")
            availability.close(reason_word, stopped.reason)
            return out
        logger.error("STARTUP STOPPED at the %s prerequisite (%s). CORPUSfm is PAUSED — "
                     "database-dependent surfaces refuse, the QUEUE claims nothing, the scheduler "
                     "is not started, and the whole prerequisite chain is retried every %.0fs.",
                     stopped.stage, stopped.reason, availability.RECOVERY_INTERVAL_S)
        availability.close("startup", f"{stopped.stage}: {stopped.reason}")
        return out
    except Exception as exc:                                        # noqa: BLE001
        out["reason"] = f"{type(exc).__name__}: {exc}"
        logger.error("STARTUP STOPPED: the %s prerequisite raised. CORPUSfm is PAUSED.",
                     out["stage"], exc_info=True)
        availability.close("startup", f"{out['stage']}: {out['reason']}")
        return out

    # The chain passed. Only now may a complete validation open the process.
    availability.prerequisites_satisfied()
    out["stage"] = "catalog"
    res = catalog.validate_now(backend)
    detail["catalog"] = {k: res.get(k) for k in ("duration_s", "counts", "raw_bytes")}
    if not res.get("ok"):
        out["reason"] = str(res.get("error") or "the initial complete read did not succeed")
        logger.error("CATALOG NOT BUILT: the complete read of STORAGE/TAG/STORAGELINK did not "
                     "succeed (%s). CORPUSfm is PAUSED — recovery retries every %.0fs.",
                     out["reason"], availability.RECOVERY_INTERVAL_S)
        return out
    if availability.shutting_down():
        # THE VALIDATION SUCCEEDED AND ITS RESULT IS NOT PUBLISHABLE (packet 1361-01, round 9).
        # Shutdown began while this attempt was in flight, so the gate refused to open on it — and
        # an attempt whose readiness was suppressed must not be reported as successful, nor mark
        # startup complete. `_complete` is the once-per-process record that makes a LATER recovery
        # skip the boot conversions; setting it here would hand that skip to a process that never
        # actually came up.
        out["reason"] = "shutdown began before readiness could be published"
        logger.info("startup: a complete validation finished after shutdown began; readiness was "
                    "NOT published and initialization is NOT marked complete.")
        return out
    with _lock:
        _complete = True
    out["ok"] = True
    out["stage"] = "ready"
    logger.info("startup readiness COMPLETE in %.2fs: %s (%s raw bytes)",
                res.get("duration_s", 0.0), res.get("counts"), res.get("raw_bytes"))
    return out


def recover(backend) -> dict:
    """ONE recovery attempt, for the availability coordinator.

    The distinction the ruling draws, in one place: a process that has NOT completed startup owes the
    whole prerequisite chain from its beginning; one that has owes a complete catalog validation and
    nothing else. Boot conversions and repairs are never rerun after a runtime outage.
    """
    if prerequisites_complete():
        from corpusfm.server import catalog
        return catalog.validate_now(backend)
    return attempt(backend)
