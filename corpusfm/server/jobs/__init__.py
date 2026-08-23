"""FileMaker Jobs — named automation units.

A Job describes where to pull FM DDR XML from, what to do with it, and what
fires it. Stored as YAML files in the jobs/ directory.

Core API:
    JobConfig, JobSource, JobProcess, JobGitExport, JobTrigger  (config.py)
    save_job, load_job, list_jobs, delete_job, generate_token  (store.py)
    validate_job                                                 (validator.py)
    run_job                                                      (runner.py)
    RunRecord, record_run, list_runs_for                         (history.py)
    JobState, read_state, update_state                           (state.py)
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
    default_history_dir,
    default_jobs_dir,
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
    "default_jobs_dir", "default_history_dir",
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
