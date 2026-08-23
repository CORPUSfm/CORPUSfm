"""Job readiness probe (packet 085 U3b: per-JOB, was per-file).

A job is *verifiable* when a real schema pull would succeed: the CORPUSfm addon is installed
in its file, the job's OWN credential is valid, and OData is reachable. One probe — the
SaveToDocumentsFolder export script — proves all three at once. classify_probe maps the raw
probe outcome to a (status, reason); verify_job runs it for a job and records the verdict on
the JOB record (IsVerified). On-demand only (no background sweep). IsVerified validates the
exact job/file/credential/script combination and dies with the job.

Reasons:
    ok               — verifiable
    no_credential    — no account stored for this job yet
    bad_creds        — auth rejected (401/403)
    no_addon         — export script absent (404) → addon not installed in the file
    odata_unreachable— connection failed (OData off / host down)
    script_disabled  — script ran but returned a non-"ok:" result (guard not toggled)
    error            — anything else

Public API:
    classify_probe(probe) -> (status, reason)
    verify_job(job_name, *, host=None, verify_ssl=None) -> dict
"""

from __future__ import annotations

from typing import Optional

# status values
PROVABLE = "provable"
BLOCKED = "blocked"


def classify_probe(probe: dict) -> tuple[str, str]:
    """Map probe_export_script's structured result to (status, reason). Pure."""
    if probe.get("ok"):
        return PROVABLE, "ok"
    status = probe.get("http_status")
    if status is None:
        return BLOCKED, "odata_unreachable"
    if status in (401, 403):
        return BLOCKED, "bad_creds"
    if status == 404:
        return BLOCKED, "no_addon"
    if status == 200:
        # ran but didn't return "ok:" → the addon's guard Exit Script wasn't toggled off
        return BLOCKED, "script_disabled"
    return BLOCKED, "error"


def _probe_transport(server_ref: str | None):
    from corpusfm.server.fms_transport import for_server_ref
    return for_server_ref(server_ref)


def verify_job(job_name: str, *, host: Optional[str] = None,
               verify_ssl: Optional[bool] = None) -> dict:
    """Probe one JOB's readiness (its own credential against its file), record the verdict on
    the JOB record (IsVerified), and return {status, reason}. No credential → blocked/
    no_credential without any network call."""
    from corpusfm.server.jobs.store import get_job_credential, load_job, set_job_verified

    try:
        cfg = load_job(job_name)
    except Exception:
        return {"status": BLOCKED, "reason": "error"}
    file_name = getattr(cfg, "file", "") or ""

    cred = get_job_credential(job_name)
    if not cred or not cred.get("account") or not cred.get("password"):
        set_job_verified(job_name, False, "no_credential")
        return {"status": BLOCKED, "reason": "no_credential"}

    try:
        transport = _probe_transport(getattr(cfg.source, "server_ref", None))
    except Exception:
        set_job_verified(job_name, False, "odata_unreachable")
        return {"status": BLOCKED, "reason": "odata_unreachable"}
    if verify_ssl is None:
        verify_ssl = transport.verify_ssl

    from corpusfm.server.fms_client import probe_export_script
    probe = probe_export_script(
        host or transport.host,
        file_name,
        {"username": cred["account"], "password": cred["password"]},
        verify_ssl=verify_ssl,
    )
    status, reason = classify_probe(probe)
    set_job_verified(job_name, status == PROVABLE, reason)
    return {"status": status, "reason": reason}
