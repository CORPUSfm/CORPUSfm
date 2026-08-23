"""The storage `AttributeError` measured on fms-server, 2026-08-08 — reproduced and fenced.

`installer/linux/install.sh` phase 14 runs a read-only `storage observe`. On the box it returned:

    {"code": "AttributeError", "detail": "the storage operation did not complete: AttributeError"}

with `result: manual_action_required`. The broad `except Exception` in the CLI turned a type error
into a vocabulary word, so the transcript recorded the symptom and lost the cause. The cause:

    storage_identity_ops.observe    → rec.evidence(..., layout=lifecycle_layout)
    storage_identity_recovery.read  → pinned_secrets_dir(..., layout=layout)
    admin_identity_store.validated_secrets_dir → Path(resolved_layout.secrets_dir)
    AttributeError: 'LifecycleLayout' object has no attribute 'secrets_dir'

**Two different layout types.** `LifecycleLayout` carries lock/journal/locator; `OsLayout` carries
config/state/secrets/log/run. Forty-eight `rec.*`/`store.*` calls forwarded the first where the
second is required.

**It never surfaced in tests** because they monkeypatch `os_layout.platform_os_layout` and pass
`lifecycle_layout=None` — so the wrong-typed argument was never the one consulted. Only a real
installation, which passes `platform_layout()`, reached it.

**E3**, against the real parser and the real operation, with the exact production request.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from corpusfm.lifecycle import cli, os_layout  # noqa: E402
from corpusfm.lifecycle import storage_identity_ops as ops  # noqa: E402
from corpusfm.lifecycle.journal import Journal  # noqa: E402
from corpusfm.lifecycle.layout import LifecycleLayout  # noqa: E402


#: The EXACT request `install.sh:lc_storage_request` emits at phase 14, with the values the box
#: actually sent. Reconstructed from the preserved transcript rather than invented.
PRODUCTION_REQUEST = {
    "schema_version": 1,
    "actor": "installer",
    "installation_id": "9bd80ab5-6617-46fc-b347-a1fe2ccd6657",
    "install_dir": "/opt/CORPUSfm",
    "fms_root": "/opt/FileMaker/FileMaker Server",
    "fms_database_dir": "/opt/FileMaker/FileMaker Server/Data/Databases",
    "secrets_dir": "/var/lib/corpusfm/secrets",
    "host": "localhost",
    "mode": "fresh_install",
    "expected_generation": 1,
}


def test_the_two_layout_types_are_genuinely_different():
    """The premise. If `LifecycleLayout` ever grows a `secrets_dir`, this fix needs rethinking."""
    lifecycle = LifecycleLayout(kind="posix", lock_file=Path("/x"), journal_file=Path("/y"))
    assert not hasattr(lifecycle, "secrets_dir")
    assert hasattr(os_layout.posix_os_layout(), "secrets_dir")


def test_the_EXACT_production_request_no_longer_raises(tmp_path, monkeypatch):
    """Real parser, real operation, real adapter — the call install.sh makes at phase 14."""
    layout = os_layout.OsLayout(
        flavour="posix",
        config_dir=tmp_path / "config", state_dir=tmp_path / "state",
        secrets_dir=tmp_path / "secrets", log_dir=tmp_path / "log", run_dir=tmp_path / "run")
    layout.secrets_dir.mkdir(parents=True)
    monkeypatch.setattr(os_layout, "platform_os_layout", lambda: layout)

    request = dict(PRODUCTION_REQUEST, secrets_dir=str(layout.secrets_dir))
    inputs = cli._st_inputs(request)                       # the REAL parser
    lifecycle = cli.platform_layout()                      # exactly what the CLI passes
    assert isinstance(lifecycle, LifecycleLayout)

    report = ops.observe(inputs, adapter=cli._st_adapter(inputs),
                         lifecycle_layout=lifecycle, journal=Journal(lifecycle))

    assert report.result != "manual_action_required", report
    assert not any(f.to_dict().get("code") == "AttributeError" for f in report.findings), report


def test_CONTROL_forwarding_the_LIFECYCLE_layout_reproduces_the_exact_exception(tmp_path,
                                                                                monkeypatch):
    """The discriminating half: the old behaviour, and the exception by name and message.

    It calls the store boundary directly, because that is where the type error was raised — the
    reproduction must not depend on the broad `except` that hid it.
    """
    from corpusfm.lifecycle import admin_identity_store as store

    layout = os_layout.OsLayout(
        flavour="posix",
        config_dir=tmp_path / "config", state_dir=tmp_path / "state",
        secrets_dir=tmp_path / "secrets", log_dir=tmp_path / "log", run_dir=tmp_path / "run")
    layout.secrets_dir.mkdir(parents=True)
    monkeypatch.setattr(os_layout, "platform_os_layout", lambda: layout)

    lifecycle = LifecycleLayout(kind="posix", lock_file=tmp_path / "l", journal_file=tmp_path / "j")
    with pytest.raises(AttributeError) as raised:
        store.validated_secrets_dir(layout.secrets_dir, layout=lifecycle)
    assert "secrets_dir" in str(raised.value)
    assert "LifecycleLayout" in str(raised.value)


def test_the_conversion_helper_passes_a_REAL_os_layout_through(tmp_path):
    """A test override must still reach the store; only the wrong type is dropped."""
    real = os_layout.posix_os_layout(tmp_path)
    assert ops._secrets_layout(real) is real

    lifecycle = LifecycleLayout(kind="posix", lock_file=tmp_path / "l", journal_file=tmp_path / "j")
    assert ops._secrets_layout(lifecycle) is None
    assert ops._secrets_layout(None) is None


def test_NO_call_site_still_forwards_the_lifecycle_layout_as_an_os_layout():
    """The fence. 48 call sites were wrong the same way; a 49th must not be added."""
    import re

    body = (REPO / "corpusfm" / "lifecycle" / "storage_identity_ops.py").read_text(encoding="utf-8")
    stray = re.findall(r"(?<![_\w])layout=lifecycle_layout", body)
    assert not stray, f"{len(stray)} call site(s) forward the lifecycle layout as an OS layout"
    assert "layout=_secrets_layout(lifecycle_layout)" in body
