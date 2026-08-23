"""Job configuration dataclasses and YAML serialization.

A Job is a named, reusable automation unit: where to pull FM DDR XML from,
what to do with it, and what fires it.

Public API:
    JobConfig, JobSource, JobProcess, JobGitExport, JobTrigger
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import yaml

from corpusfm.server.jobs.schedule import Schedule as _Schedule
from corpusfm.server.jobs import schedule as _schedule_mod


def _trigger_to_dict(t) -> dict:
    d: dict = {"type": t.type}
    s = t.resolved_schedule()
    if s is not None:
        d["schedule"] = s.to_dict()
    elif t.cron is not None:
        d["cron"] = t.cron           # a non-schedule trigger that somehow carries one; kept verbatim
    return d


def _trigger_from_dict(t: dict) -> "JobTrigger":
    sched = t.get("schedule")
    return JobTrigger(
        type=t.get("type", ""),
        cron=t.get("cron"),
        schedule=_schedule_mod.from_dict(sched) if isinstance(sched, dict) else None,
    )


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class JobSource:
    type: str  # local_file | fms_local | fms_save_to_documents | fms_save_to_file_path | fms_push
    path: Optional[str] = None            # local_file: filesystem path to XML
    server: Optional[str] = None          # fms_*: FMS server base URL (host derived from the SERVER record for remote jobs)
    databases: Optional[list] = None      # runtime pull target, derived from the tracked file
    script: Optional[str] = None          # fms_*: the FM export script (method) to call — an addon script constant
    server_ref: Optional[str] = None      # which server to run against — a SERVER record uuid, or the sentinel "local" (co-located). None == local (packet 1015)
    file_path: Optional[str] = None       # SaveToFilePath (method option): the filesystem path FM writes the export to (readable by CORPUSfm for a local/shared-fs job)
    export_timeout_s: Optional[int] = None  # packet 1142 §H: MAX seconds ONE export (the acquire step's blocking script call) may take. None/blank = DEFAULT_EXPORT_TIMEOUT_SECS. Source-agnostic — bounds the export, not the HTTP mechanism; the watchdog is derived from it.


def _coerce_timeout(v) -> Optional[int]:
    """A stored/authored export_timeout_s → a positive int, or None (use the default). An empty
    string, 0, or a non-numeric value all mean 'default' (never require a number at job creation)."""
    if v is None or v == "":
        return None
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def effective_export_timeout_s(source: "JobSource") -> float:
    """The effective per-export bound (packet 1142 §H): the job's own ``export_timeout_s`` when set,
    else the packaged default. One resolver so the trigger call and the watchdog derive from the SAME
    number."""
    from corpusfm.server.queue_workers import DEFAULT_EXPORT_TIMEOUT_SECS
    v = _coerce_timeout(getattr(source, "export_timeout_s", None))
    return float(v) if v else float(DEFAULT_EXPORT_TIMEOUT_SECS)


@dataclass
class JobGitExport:
    registrations: list = field(default_factory=list)
    modes: list = field(default_factory=lambda: ["structured", "rendered"])
    repo: str = ""   # target repo for this job's exports; overrides each registration's default repo


@dataclass
class JobProcess:
    git_export: Optional[JobGitExport] = None
    index_on_ingest: bool = True
    summarize_on_ingest: bool = True   # packet 1153: per-job AI-summary switch, symmetric with
                                       # index_on_ingest (gated AND provider_ready at run time)
    enable_artifact_limit: bool = False
    max_artifacts: int = 10
    # Packet 059: keep the compressed source XML for this job's imports. Default True (global default),
    # but automated pulls run often and can balloon storage, so a job can opt out — its imports then drop
    # the source right after the artifact is created (the "Job" delete election).
    keep_source_xml: bool = True


@dataclass
class JobTrigger:
    type: str               # manual | schedule | webhook
    # The structured schedule (packet 1185). `cron` survives only as the wire name a stored record
    # may still carry: it is read once, translated by `schedule.from_cron`, and never written back
    # except as unrepresentable residue. Nothing interprets it at run time.
    cron: Optional[str] = None
    schedule: Optional["_Schedule"] = None

    def resolved_schedule(self):
        """This trigger's schedule, migrating a legacy cron expression on the spot.

        Migration lives here rather than in a one-shot script because a job record can arrive from a
        YAML file, the FileMaker JOBS table, or an MCP caller — three doors into one shape. Doing it
        at the shape means no door can let an un-migrated schedule through.
        """
        from corpusfm.server.jobs import schedule as _sched
        if self.type != "schedule":
            return None
        # An explicitly supplied schedule IS the schedule, valid or not — otherwise a half-filled
        # one falls through to the cron branch and the validator can only say "needs a schedule"
        # instead of naming the field that is wrong. A record with no `schedule` key at all still
        # carries None here, so legacy migration is unaffected.
        if self.schedule is not None:
            return self.schedule
        if self.cron:
            migrated = _sched.from_cron(self.cron)
            # Unrepresentable: keep the original verbatim as evidence and stop firing it. A wrong
            # guess about when a job runs is harder to notice than a job that asks for attention.
            return migrated or _sched.Schedule(legacy_cron=self.cron)
        return None


# The co-located pull a tracked-file job always uses (the readiness probe proves it works):
# FM's SaveToDocumentsFolder export, read off the local Documents folder. No result-size cap.
CO_LOCATED_PULL = "fms_save_to_documents"

# ── Export methods (packet 1015 redesign) ────────────────────────────────────────
# Every job = one server + one file + one account + one script METHOD. The Jobs page offers the
# methods valid for the selected server context; the FIRST is the default:
#   Local  → SaveToDocumentsFolder (default) · SaveToFilePath
#   Remote → PostToServer (default)          · SaveToFilePath
from corpusfm.core.addon.scripts import (  # noqa: E402
    POST_TO_SERVER, SAVE_TO_DOCUMENTS, SAVE_TO_FILE_PATH,
)

LOCAL_METHODS = [SAVE_TO_DOCUMENTS, SAVE_TO_FILE_PATH]
REMOTE_METHODS = [POST_TO_SERVER, SAVE_TO_FILE_PATH]

# Export method (addon script constant) → the JobSource.type that runs it.
_METHOD_SOURCE_TYPE = {
    SAVE_TO_DOCUMENTS: "fms_save_to_documents",
    SAVE_TO_FILE_PATH: "fms_save_to_file_path",
    POST_TO_SERVER: "fms_push",
}


def default_method(is_remote: bool) -> str:
    """The default export method for a server context (first option in the list)."""
    return POST_TO_SERVER if is_remote else SAVE_TO_DOCUMENTS


def source_type_for_method(script: str, *, is_remote: bool) -> str:
    """Map an export method to the JobSource.type that runs it. An unknown/blank method falls back to
    the server-context default (PostToServer for remote, SaveToDocumentsFolder for local)."""
    return _METHOD_SOURCE_TYPE.get(script) or ("fms_push" if is_remote else "fms_save_to_documents")

# Git-export content choice — a single UI token ↔ the underlying ExportConfig.modes list.
# "both" is the historical default (structured + rendered .txt per object).
_CONTENT_TOKENS = {
    "both": ["structured", "rendered"],
    "rendered": ["rendered"],
    "structured": ["structured"],
}


def modes_for_content(token: str) -> list:
    """Map a UI content token (both | rendered | structured) to an ExportConfig.modes list."""
    return list(_CONTENT_TOKENS.get((token or "").strip(), _CONTENT_TOKENS["both"]))


def content_for_modes(modes) -> str:
    """Reverse of modes_for_content: derive the UI token from a modes list. Unknown → 'both'."""
    s = set(modes or [])
    if s == {"rendered"}:
        return "rendered"
    if s == {"structured"}:
        return "structured"
    return "both"


def file_job_source(file_name: str, server: str) -> "JobSource":
    """Build the derived source for a tracked-file job — the credential is NOT carried here
    (file-jobs resolve it from the JOB.CredentialData container at run time; packet 085 U3b)."""
    return JobSource(type=CO_LOCATED_PULL, server=server, databases=[file_name])


@dataclass
class JobConfig:
    name: str
    source: JobSource
    process: JobProcess
    triggers: list          # list[JobTrigger] — exactly ONE for a file-job
    webhook_token: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list] = None   # job-tags (Tag v2): user-authored, union-applied each run
    file: Optional[str] = None    # parent tracked file (file-centric model); credential is per-job (JOB.CredentialData)
    id: Optional[str] = None      # stable job uuid — the ONLY thing artifacts/runs link to (never the name)

    # ── Convenience ────────────────────────────────────────────────────

    @property
    def trigger(self) -> Optional[JobTrigger]:
        """The single trigger (file-jobs carry exactly one). None if unset."""
        return self.triggers[0] if self.triggers else None

    # ── YAML round-trip ───────────────────────────────────────────────

    def to_dict(self) -> dict:
        src = {"type": self.source.type}
        for k in ("path", "server", "script", "server_ref",
                  "file_path", "export_timeout_s"):
            v = getattr(self.source, k)
            if v is not None:
                src[k] = v
        # The owner file is the pull target; databases are never an authored list.

        proc: dict = {}
        if self.process.git_export is not None:
            ge = self.process.git_export
            proc["git_export"] = {
                "registrations": list(ge.registrations),
                "modes": list(ge.modes),
            }
            if ge.repo:
                proc["git_export"]["repo"] = ge.repo
        if not self.process.index_on_ingest:
            proc["index_on_ingest"] = False
        if not self.process.summarize_on_ingest:
            proc["summarize_on_ingest"] = False
        if self.process.enable_artifact_limit:
            proc["enable_artifact_limit"] = True
            proc["max_artifacts"] = self.process.max_artifacts
        if not self.process.keep_source_xml:
            proc["keep_source_xml"] = False

        d: dict = {
            "name": self.name,
            "source": src,
            "process": proc,
            # A write emits the STRUCTURED shape. That is what makes the migration a one-time event
            # rather than a permanent translation layer: every record that is saved after this
            # change stops carrying cron, and an unrepresentable one keeps it only inside
            # `legacy_cron`, where nothing reads it as a schedule.
            "triggers": [_trigger_to_dict(t) for t in self.triggers],
        }
        if self.id:
            d["id"] = self.id
        if self.file:
            d["file"] = self.file
        if self.description is not None:
            d["description"] = self.description
        if self.webhook_token is not None:
            d["webhook_token"] = self.webhook_token
        if self.tags:
            d["tags"] = list(self.tags)
        return d

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), allow_unicode=True, sort_keys=False)

    @classmethod
    def from_dict(cls, data: dict) -> "JobConfig":
        src = data.get("source") or {}
        file_name = data.get("file")
        _dbs = [file_name] if file_name else None
        source = JobSource(
            type=src.get("type", ""),
            path=src.get("path"),
            server=src.get("server"),
            databases=_dbs,
            script=src.get("script"),
            server_ref=src.get("server_ref"),
            file_path=src.get("file_path"),
            export_timeout_s=_coerce_timeout(src.get("export_timeout_s")),
        )

        proc_data = data.get("process") or {}
        ge_data = proc_data.get("git_export")
        git_export = (
            JobGitExport(
                registrations=ge_data.get("registrations", []),
                modes=ge_data.get("modes", ["structured", "rendered"]),
                repo=ge_data.get("repo", ""),
            )
            if ge_data
            else None
        )
        process = JobProcess(
            git_export=git_export,
            index_on_ingest=proc_data.get("index_on_ingest", True),
            summarize_on_ingest=proc_data.get("summarize_on_ingest", True),
            enable_artifact_limit=proc_data.get("enable_artifact_limit", False),
            max_artifacts=int(proc_data.get("max_artifacts", 10)),
            keep_source_xml=bool(proc_data.get("keep_source_xml", True)),
        )

        triggers = [_trigger_from_dict(t) for t in (data.get("triggers") or [])]

        _tags = data.get("tags")
        return cls(
            name=data.get("name", ""),
            source=source,
            process=process,
            triggers=triggers,
            webhook_token=data.get("webhook_token"),
            description=data.get("description"),
            tags=list(_tags) if _tags else None,
            file=file_name,
            id=data.get("id"),
        )

    @classmethod
    def from_yaml(cls, text: str) -> "JobConfig":
        return cls.from_dict(yaml.safe_load(text))
