"""Two regressions from the generation-5 run on fms-server, 2026-08-08.

**One.** After the lifecycle storage provider composed, finalized and discarded generation 5, a
legacy tail ran and was a SECOND authority for the same things — it deployed the database,
provisioned the sandbox, bootstrapped the service account, attempted its own password rotation and
wrote the storage credential into `install.yaml` and `server_configs.yaml`. It read a 401 as
"accessible" (401 because the provider had already rotated the credential and this path held a
different one), then failed its rotation with `FM script error 212`. Same shape as the retired proxy
helper one phase earlier.

**Two.** `server_configs.yaml` lives at the PROJECT ROOT, which on an installed box is
`/opt/CORPUSfm/src` — root-owned 0750 so the service can traverse into the code it runs. Its writer
asked `secure_fs` to tighten the parent to 0700, and every `sudo -u <service> … python -m corpusfm.*`
afterwards failed with `ModuleNotFoundError: No module named 'corpusfm'`, which is where the install
stopped. The file must stay private; the directory is not its to change.
"""

from __future__ import annotations

import re
from application_checkout import APPLICATION_ROOT

from tests.test_installer_provider_walks import SH, code

#: Every name that only the retired storage publisher had. `run_bootstrap` fuses SETTINGS
#: initialization, rotation, two credential writes and backend activation; `upsert_server_config`
#: and `write_fm_backend_config` are the two legacy storage-authority writes; the sandbox belongs to
#: the patch-compartment provider, which owns and records it at phase 16.
RETIRED = (
    "run_bootstrap",
    "write_fm_backend_config",
    "activate_fm_backend",
    "upsert_server_config",
    "fm_deploy_template",
    "CORPUSfm_Sandbox",
)


def _after_storage(text: str) -> str:
    """The script from the storage provider's discard to the end — comments stripped."""
    marker = "lc_discard_provider storage"
    body = code(text)
    assert marker in body, "the storage provider no longer discards its journal"
    return body[body.index(marker):]


def test_NO_LEGACY_STORAGE_PUBLISHER_SURVIVES_THE_PROVIDER():
    """The rule: once generation 5 is composed, nothing else in the run touches storage."""
    tail = _after_storage(SH.read_text(encoding="utf-8"))
    found = sorted({name for name in RETIRED if name in tail})
    assert found == [], (
        "a retired storage publisher is still reachable after the lifecycle provider composed "
        f"generation 5: {found}")


def test_the_installer_NEVER_ROTATES_THE_AUTOMATION_CREDENTIAL():
    """The provider holds the credential. A second rotation cannot succeed and cannot be undone."""
    body = code(SH.read_text(encoding="utf-8"))
    for needle in ("ChangeAutomationPassword", "reset_automation_password"):
        assert needle not in body, f"the installer still attempts its own rotation ({needle})"


def test_SERVICE_RENDERING_still_follows(tmp_path):
    """The tail was deleted, not the phases after it — otherwise nothing would install the services
    and this file would be guarding an installer that never starts CORPUSfm."""
    tail = _after_storage(SH.read_text(encoding="utf-8"))
    assert "service_identity" in tail or "Rendering final service definitions" in \
        SH.read_text(encoding="utf-8"), "the service definitions are no longer rendered"
    assert "systemctl" in tail, "no service is installed or started after storage composes"


# ── the retired src-mode producer ───────────────────────────────────────────────────

def test_the_legacy_server_configs_writer_is_absent():
    """Packet 1268 deleted the writer instead of retaining a second static storage authority.

    Parent-mode tests for that deleted writer were preserving an implementation the product no
    longer supports. The surviving invariant is stronger: installed runtime code cannot write the
    retired project-root `server_configs.yaml` at all.
    """
    retired = APPLICATION_ROOT / "corpusfm/server/jobs/server_configs.py"
    assert not retired.exists()
    for path in (APPLICATION_ROOT / "corpusfm").rglob("*.py"):
        assert "server.jobs.server_configs" not in path.read_text(encoding="utf-8"), path


# ── the same rule on Windows (packet 1246-10-04) ─────────────────────────────────────────────────
#
# The Windows installer carried the identical second publisher: it deployed the database, registered
# PKI, ran `run_bootstrap` to rotate the automation password, called `activate_fm_backend` and wrote
# a legacy `server_configs` record — all after phase 18 had composed exactly that storage and stored
# its credential. Deleted on the developer's ruling of 2026-08-09, mirroring both the Linux storage
# deletion above and the Windows proxy deletion of the same day.

from tests.test_installer_provider_walks import PS1                       # noqa: E402


def _after_windows_storage() -> str:
    text = PS1.read_text(encoding="ascii")
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    marker = "Lc-DiscardProvider 'storage'"
    assert marker in body, "the Windows storage provider no longer discards its journal"
    return body[body.index(marker):]


def test_NO_LEGACY_STORAGE_PUBLISHER_SURVIVES_THE_PROVIDER_ON_WINDOWS():
    tail = _after_windows_storage()
    found = sorted({name for name in RETIRED if name in tail})
    assert found == [], (
        "a retired storage publisher is still reachable after the Windows provider composed: "
        f"{found}")


def test_WINDOWS_NEVER_DEPLOYS_THE_DATABASE_OR_ROTATES_THE_CREDENTIAL_ITSELF():
    tail = _after_windows_storage()
    for needle in ("fmsadmin.exe", "rotate_password", "ChangeAutomationPassword",
                   "CORPUSfm_DB.fmp12", "_bootstrap.py", "_pki.py"):
        assert needle not in tail, f"the Windows installer still acts on storage itself ({needle})"


def test_WHAT_CONSUMES_THE_COMPOSITION_STILL_RUNS_ON_WINDOWS():
    """The tail was deleted, not the phases after it. Projection backfill reads the composed
    backend and phase 19 handles the first administrator; neither publishes storage authority."""
    tail = _after_windows_storage()
    assert "backfill-storage-projections" in tail, "the projection backfill went with the tail"
    assert "PHASE 19" in PS1.read_text(encoding="ascii")
    assert "PHASE 21" in tail or "PHASE 21" in PS1.read_text(encoding="ascii")


def test_THE_FMS_ADMIN_CREDENTIAL_IS_CLEARED_AFTER_ITS_LAST_CONSUMER():
    """It was verified at phase 7 and handed to the providers through the credential frame; with the
    inline tail gone nothing after storage needs it, so it does not stay in the process. Cleared,
    never logged."""
    text = PS1.read_text(encoding="ascii")
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    tail = _after_windows_storage()
    assert "$FmAdminPass = $null" in tail and "$FmAdminUser = $null" in tail
    assert "Remove-Item Env:\\FM_ADMIN_PASS" in tail

    after_clear = tail[tail.index("$FmAdminPass = $null"):]
    for line in after_clear.splitlines():
        for match in re.finditer(r"\b(Write-Host|Ok|Info|Warn|Cfm-Logline)\b(.*)$", line):
            assert "$FmAdminPass" not in match.group(2), line.strip()
