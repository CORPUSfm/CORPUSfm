"""Packet 1277: proofs bound to the proxy executors Series 2 actually installs.

The application repository owns rendering. These tests do not import it; they use the documented
known-answer values that its renderer independently pins. That makes agreement transitive without
creating a cross-repository runtime or test dependency.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parent.parent
LINUX_EXECUTOR = ROOT / "installer/linux/cfm-proxy-exec.sh"
WINDOWS_EXECUTOR = ROOT / "installer/windows/cfm-proxy-exec.ps1"

NOISY_BLOCK = (
    "\ufeff# CORPUSFM\r\n"
    '    include "/x/corpusfm_https.conf";\r\n'
    "# CORPUSFM\r\n\r\n"
)
NOISY_INCLUDE = (
    "location = /x {\r\n"
    "    proxy_pass http://127.0.0.1:8533;\r\n"
    "}\r\n\r\n"
)
CANONICAL_DIGEST = "53733009c6c351f1b20c92af7eb5bc83bb5dc93339305857e9164d7e1432cc12"
FAMILY_DIGEST = "7cef2850c8368cbae8da8386aa0261ac5fe772804392cbaabf198dbc8c925a59"


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, **kwargs)


def _parts_file(tmp_path: Path) -> Path:
    block = tmp_path / "block.txt"
    include = tmp_path / "include.txt"
    block.write_bytes(NOISY_BLOCK.encode("utf-8"))
    include.write_bytes(NOISY_INCLUDE.encode("utf-8"))
    parts = tmp_path / "parts.txt"
    parts.write_text(f"include={include}\nblock={block}\n", encoding="utf-8")
    return parts


def test_linux_executor_matches_the_fixed_renderer_vectors(tmp_path):
    canonical = _run(["bash", str(LINUX_EXECUTOR), "digest"], input=NOISY_BLOCK)
    assert canonical.returncode == 0, canonical.stderr
    assert canonical.stdout.strip() == CANONICAL_DIGEST

    family = _run(
        ["bash", str(LINUX_EXECUTOR), "family-digest", "--parts-file", str(_parts_file(tmp_path))]
    )
    assert family.returncode == 0, family.stderr
    assert family.stdout.strip() == FAMILY_DIGEST


def test_windows_executor_matches_the_fixed_renderer_vectors(tmp_path):
    pwsh = os.environ.get("CFM_PWSH") or shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("PowerShell is unavailable; set CFM_PWSH to exercise the Windows executor")

    canonical = _run(
        [pwsh, "-NoProfile", "-File", str(WINDOWS_EXECUTOR), "-Verb", "digest"],
        input=NOISY_BLOCK,
    )
    assert canonical.returncode == 0, canonical.stderr
    assert canonical.stdout.strip() == CANONICAL_DIGEST

    family = _run(
        [
            pwsh,
            "-NoProfile",
            "-File",
            str(WINDOWS_EXECUTOR),
            "-Verb",
            "family-digest",
            "-PartsFile",
            str(_parts_file(tmp_path)),
        ]
    )
    assert family.returncode == 0, family.stderr
    assert family.stdout.strip() == FAMILY_DIGEST


def test_linux_publish_refuses_an_incomplete_nginx_family_before_change(tmp_path):
    root = tmp_path / "FileMaker Server"
    conf_dir = root / "NginxServer/conf"
    conf_dir.mkdir(parents=True)
    conf = conf_dir / "fms_nginx.conf"
    original = "http {\n    server {\n        listen 443 ssl;\n    }\n}\n"
    conf.write_text(original, encoding="utf-8")

    block = tmp_path / "block.txt"
    block.write_text(
        '# CORPUSFM\n    include "missing-rendered-include.conf";\n# CORPUSFM',
        encoding="utf-8",
    )
    result = _run(
        [
            "bash",
            str(LINUX_EXECUTOR),
            "publish",
            "fms-nginx",
            "--fms-root",
            str(root),
            "--block-file",
            str(block),
        ]
    )

    assert result.returncode == 2, result.stdout + result.stderr
    outcome = json.loads(result.stdout)
    assert outcome["ok"] is False
    assert "--include-file is required" in outcome["detail"]
    assert conf.read_text(encoding="utf-8") == original
    assert not list(conf_dir.glob("*.cfmbak")), "refusal crossed the before-image boundary"
    assert not (conf_dir / "corpusfm_https.conf").exists()
