"""FileMaker Jobs — named automation units.

A Job describes where to pull FM DDR XML from, what to do with it, and what fires it.

**A job is identified by its UUID and by nothing else (packet 1372-02).** Names are editable labels
that may collide, including by case; no operation resolves a job from one. On a server install the
store is the JOB table keyed by that UUID; on the unpublished dev/test path it is one
`<job_uuid>.yaml` per job in the jobs/ directory, with the name inside the document.

Core API:
    JobConfig, JobSource, JobProcess, JobGitExport, JobTrigger  (config.py)
    save_job, load_job(job_uuid), list_jobs, delete_job(job_uuid), generate_token  (store.py)
    validate_job                                                 (validator.py)
    run_job                                                      (runner.py)
    RunRecord, record_run, list_runs_for                         (history.py)
    JobState, read_state(job_uuid), update_state(job_uuid)       (state.py)
    pull_source                                                   (sources.py)
    webhook_url, make_handler, DEFAULT_PORT                      (webhook.py)
"""

from corpusfm.server.jobs.config import (
    JobConfig,
    JobGitExport,
    JobProcess,
    JobSource,
    JobTrigger,
)
from corpusfm.server.jobs.history import RunRecord, list_runs_for, record_run
from corpusfm.server.jobs.runner import run_job
from corpusfm.server.jobs.sources import pull_source
from corpusfm.server.jobs.state import JobState, read_state, update_state
from corpusfm.server.jobs.store import (
    delete_job,
    generate_token,
    list_jobs,
    load_job,
    save_job,
)
from corpusfm.server.jobs.validator import validate_job
from corpusfm.server.jobs.webhook import DEFAULT_PORT, make_handler, webhook_url

__all__ = [
    # config
    "JobConfig", "JobSource", "JobProcess", "JobGitExport", "JobTrigger",
    # store
    "save_job", "load_job", "list_jobs", "delete_job", "generate_token",
    # validator
    "validate_job",
    # runner
    "run_job",
    # history
    "RunRecord", "record_run", "list_runs_for",
    # state
    "JobState", "read_state", "update_state",
    # sources
    "pull_source",
    # webhook
    "webhook_url", "make_handler", "DEFAULT_PORT",
]
