"""Job readiness probe (packet 085 U3b: per-JOB, was per-file).

A job is *verifiable* when a real schema pull would succeed: the CORPUSfm addon is installed
in its file, the job's OWN credential is valid, and OData is reachable. One probe — the
SaveToDocumentsFolder export script — proves all three at once. classify_probe maps the raw
probe outcome to a (status, reason); verify_job runs it for a job and records the verdict on
the JOB record (IsVerified). On-demand only (no background sweep). IsVerified validates the
exact job/file/credential/script combination and dies with the job.

Reasons (packet 1330-02 rewrote these from MEASUREMENT, not from HTTP status):
    ok                 — verifiable
    no_credential      — no account stored for this job yet
    bad_creds          — FileMaker said so: FM 212 "Invalid account/password"
    script_not_found   — FM -1029. FileMaker's own words. NOT "addon not installed": an access
                         problem can hide a script that exists, so the cause is not claimed
    file_closed        — the file is closed on the server (from the Admin API inventory)
    odata_not_enabled  — `fmodata` is absent from the file's extended privileges
    not_hosted         — the file is not hosted on this server
    no_access          — FM 802 with the file hosted, open and OData-enabled: the account cannot open
                         it. Password or privileges — honestly ambiguous, and it says so
    file_unreachable   — FM 802 and the inventory could not be read, so the cause is unknown
    odata_unreachable  — connection failed (OData off / host down)
    script_disabled    — script ran but returned a non-"ok:" result (guard not toggled)
    error              — anything else

WHY THE ADMIN API IS CONSULTED HERE. FM 802 is returned for four different situations and the HTTP
status cannot tell them apart — measured. Only the server's inventory can. The developer authorized
ONE sequential Admin API session as part of the user-invited Verify operation (ruling, 2026-08-26,
option A), scoped to THIS path: Verify is rare and explicitly asked for, so it has a different cost
profile from a page load. Nothing here authorizes an extra Admin session on a page load, a background
sweep, or the gallery. When that inventory read fails, the reason degrades honestly to
`file_unreachable` rather than guessing.

Public API:
    classify_probe(probe) -> (status, reason)
    verify_job(job_uuid, *, host=None, verify_ssl=None) -> dict
"""

from __future__ import annotations

from typing import Optional

# status values
PROVABLE = "provable"
BLOCKED = "blocked"


def classify_probe(probe: dict, inventory: "dict | None" = None) -> tuple[str, str]:
    """Map probe_export_script's structured result to (status, reason). Pure.

    `inventory` is the contemporaneous Admin API view of this file — ``{"hosted", "open",
    "odata_enabled"}`` — or None when it could not be read. It is consulted ONLY for FM 802, which is
    the one outcome the HTTP status cannot discriminate.
    """
    if probe.get("ok"):
        return PROVABLE, "ok"
    status = probe.get("http_status")
    fm_code = str(probe.get("fm_code") or "")
    if status is None:
        return BLOCKED, "odata_unreachable"
    if fm_code == "212":
        return BLOCKED, "bad_creds"          # FileMaker states it outright; not a guess
    if fm_code == "-1029":
        return BLOCKED, "script_not_found"   # missing OR invisible to this account — cause not claimed
    if fm_code == "802":
        if inventory is None:
            return BLOCKED, "file_unreachable"
        if not inventory.get("hosted", False):
            return BLOCKED, "not_hosted"
        if inventory.get("open") is False:
            return BLOCKED, "file_closed"
        if inventory.get("open") is None:
            # FMS reported no runtime status, so "open" is unknown. `no_access` is a STRONGER claim —
            # it says the account cannot open a file that is otherwise fine — and an omitted status is
            # not evidence for it (Codex review, 2026-08-26).
            return BLOCKED, "file_unreachable"
        if not inventory.get("odata_enabled", True):
            return BLOCKED, "odata_not_enabled"
        return BLOCKED, "no_access"
    if status in (401, 403):
        return BLOCKED, "bad_creds"
    if status == 404:
        return BLOCKED, "script_not_found"
    if status == 200:
        # ran but didn't return "ok:" → the addon's guard Exit Script wasn't toggled off
        return BLOCKED, "script_disabled"
    return BLOCKED, "error"


def read_inventory(file_name: str, server_ref: "str | None" = None) -> "dict | None":
    """This file's contemporaneous Admin API facts, or None when the read failed.

    ONE sequential Admin API session, released in a `finally` — authorized for the user-invited Verify
    path only (developer ruling, 2026-08-26). None is returned rather than raising: a failed inventory
    read must degrade the REASON honestly, never fail the Verify.

    `server_ref` names WHICH server the job targets. A remote job diagnosed from the co-located box's
    inventory would answer about the wrong machine — a confidently wrong diagnosis, which is worse than
    none (Codex review, 2026-08-26). A remote reference returns None: the remote Admin credential path
    is a different authority and is not claimed here."""
    if server_ref not in (None, "", "local"):
        return None                      # a remote job: this authority does not speak for that box
    try:
        from corpusfm.server import fms_admin_pki as pki
        from corpusfm.server.admin_api_identity import admin_api_identity
        identity = admin_api_identity()
        if not identity.available:
            return None
        cfg = identity.config
        token = pki.authenticate(cfg["host"], cfg["name"], cfg["private_pem"])
        try:
            records = pki.list_hosted_databases(cfg["host"], token)
        finally:
            try:
                pki.logout(cfg["host"], token)
            except Exception:
                pass
    except Exception:
        return None
    bare = file_name[:-6] if file_name.lower().endswith(".fmp12") else file_name
    for rec in records:
        if rec.name.lower() == bare.lower():
            return {"hosted": True, "open": rec.open,
                    "odata_enabled": "fmodata" in (rec.ext_privileges or ())}
    return {"hosted": False, "open": None, "odata_enabled": False}


def _probe_transport(server_ref: str | None):
    from corpusfm.server.fms_transport import for_server_ref
    return for_server_ref(server_ref)


def verify_job(job_uuid: str, *, host: Optional[str] = None,
               verify_ssl: Optional[bool] = None) -> dict:
    """Probe one JOB's readiness (its own credential against its file), record the verdict on
    the JOB record (IsVerified), and return {status, reason}. No credential → blocked/
    no_credential without any network call."""
    from corpusfm.server.jobs.store import get_job_credential, load_job, set_job_verified

    try:
        cfg = load_job(job_uuid)
    except Exception:
        return {"status": BLOCKED, "reason": "error"}
    file_name = getattr(cfg, "file", "") or ""

    cred = get_job_credential(job_uuid)
    if not cred or not cred.get("account") or not cred.get("password"):
        set_job_verified(job_uuid, False, "no_credential")
        return {"status": BLOCKED, "reason": "no_credential"}

    try:
        transport = _probe_transport(getattr(cfg.source, "server_ref", None))
    except Exception:
        set_job_verified(job_uuid, False, "odata_unreachable")
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
    # FM 802 is the one outcome the transport cannot explain, so — and only then — ask the server.
    inventory = None
    if str(probe.get("fm_code") or "") == "802":
        inventory = read_inventory(file_name, getattr(cfg.source, "server_ref", None))
    status, reason = classify_probe(probe, inventory)
    set_job_verified(job_uuid, status == PROVABLE, reason)
    return {"status": status, "reason": reason}
