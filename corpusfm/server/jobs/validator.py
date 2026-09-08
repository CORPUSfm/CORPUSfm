"""JobConfig validation.

Public API:
    validate_job(cfg) -> list[str]   — returns list of error strings; [] means valid
"""

from __future__ import annotations

import re

from corpusfm.server.jobs.config import JobConfig

# Every job pulls from a hosted FileMaker file. `local_file` is gone (packet 1361-01) — a path on
# disk is ingestion, not an automation unit with a schedule, a credential and a pull method.
_VALID_SOURCE_TYPES = frozenset({"fms_local", "fms_save_to_documents",
                                 "fms_save_to_file_path", "fms_push"})
_VALID_TRIGGER_TYPES = frozenset({"manual", "schedule", "webhook"})
# Job names may contain spaces + general punctuation (they double as a filesystem filename via the
# injective `store._safe_name` percent-encoder, and as an encodeURIComponent'd URL segment). Forbid
# only path separators + control chars; the pathological `.`/`..`/blank cases are handled separately.
_NAME_FORBIDDEN = re.compile(r"[\x00-\x1f/\\]")


def validate_job(cfg: JobConfig) -> list[str]:
    """Validate a JobConfig. Returns a list of human-readable error strings.

    An empty list means the config is valid.
    """
    errors: list[str] = []

    # Name
    if not cfg.name or not cfg.name.strip():
        errors.append("name: must not be empty")
    elif cfg.name != cfg.name.strip():
        errors.append("name: must not have leading or trailing whitespace")
    elif cfg.name in (".", ".."):
        errors.append("name: '.' and '..' are reserved")
    elif _NAME_FORBIDDEN.search(cfg.name):
        errors.append("name: must not contain slashes, backslashes, or control characters")

    # Source
    if not cfg.source:
        errors.append("source: missing")
    else:
        stype = (cfg.source.type or "").strip()
        if not stype:
            errors.append("source.type: must not be empty")
        elif stype not in _VALID_SOURCE_TYPES:
            errors.append(
                f"source.type: '{stype}' is not a valid type "
                f"(valid: {', '.join(sorted(_VALID_SOURCE_TYPES))})"
            )
        else:
            if stype.startswith("fms_"):
                if not cfg.file:
                    errors.append("file: required for every FileMaker job")
                # A REMOTE fms_push (packet 1015) resolves its server URL + OData credential from the
                # SERVER record named by `server_ref` at run time, so it carries neither an inline
                # `server` URL nor a server-config credential name.
                is_remote_push = (stype == "fms_push"
                                  and (cfg.source.server_ref or "") not in ("", "local"))
                if not cfg.source.server and not is_remote_push:
                    errors.append("source.server: required for FMS source types")
                # The pull target IS the job's owner file (packet 086 — no stored database list;
                # `databases` is derived from `file`). Legacy jobs adopted their databases[0] as
                # `file` on load, so this covers both.
                if stype == "fms_push" and not cfg.source.script:
                    errors.append("source.script: required for fms_push (FM script to trigger, e.g. CFM.TOOLS.ExportSchemaXML.PostToServer)")

    # Triggers
    if not cfg.triggers:
        errors.append("triggers: at least one trigger is required")
    else:
        has_webhook_trigger = False
        for i, t in enumerate(cfg.triggers):
            ttype = (t.type or "").strip()
            if not ttype:
                errors.append(f"triggers[{i}].type: must not be empty")
            elif ttype not in _VALID_TRIGGER_TYPES:
                errors.append(
                    f"triggers[{i}].type: '{ttype}' is not valid "
                    f"(valid: {', '.join(sorted(_VALID_TRIGGER_TYPES))})"
                )
            if ttype == "schedule":
                errors.extend(_schedule_errors(i, t))
            if ttype == "webhook":
                has_webhook_trigger = True

        if has_webhook_trigger and not cfg.webhook_token:
            errors.append(
                "webhook_token: required when a webhook trigger is configured "
                "(use generate_token() to create one)"
            )

    # File-job: a job attached to a tracked file carries exactly one trigger.
    if cfg.file and cfg.triggers and len(cfg.triggers) != 1:
        errors.append("file-job: must have exactly one trigger")

    # Process — optional but validate if present
    if cfg.process and cfg.process.git_export:
        ge = cfg.process.git_export
        if not ge.registrations:
            errors.append("process.git_export.registrations: must list at least one registration")
        for mode in ge.modes:
            if mode not in ("structured", "rendered"):
                errors.append(
                    f"process.git_export.modes: '{mode}' is not valid "
                    "(valid: structured, rendered)"
                )

    return errors


def _schedule_errors(i: int, t) -> list:
    """A schedule trigger's problems, in the structured model's own words (packet 1185).

    A trigger carrying only a legacy cron expression is NOT an error — it is a record written before
    the model changed, and validation is not the place to reject data the migration handles. What is
    reported is an expression the migration could not translate, because that job will not fire and
    the user has to be told which one and why.
    """
    from corpusfm.server.jobs import schedule as _sched
    s = t.resolved_schedule()
    if s is None:
        return [f"triggers[{i}]: a schedule trigger needs a schedule"]
    if s.needs_update:
        return [f"triggers[{i}]: '{s.legacy_cron}' cannot be expressed as a one-time or recurring "
                "schedule — open the job and set a new one"]
    return [f"triggers[{i}].schedule: {e}" for e in _sched.validate(s)]
