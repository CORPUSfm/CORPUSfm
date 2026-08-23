"""Verified installer packages may move an installation forward, never backward.

OP-036 was a Linux parity defect: the package path verified an exact payload and then used
``reset --hard`` without first proving that the deployed HEAD was its ancestor.  Windows already
had that pre-quiesce proof.  These tests exercise Linux's real relation classifier against Git
histories and pin the ordering boundary on both platforms.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest


ROOT = pathlib.Path(__file__).resolve().parent.parent
LINUX = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
WINDOWS = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")


def _git(path: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


def _commit(path: pathlib.Path, name: str) -> str:
    (path / "history.txt").write_text(name + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "history.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "user.name=Test", "-c",
         "user.email=test@example.invalid", "commit", "-qm", name], check=True
    )
    return _git(path, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path: pathlib.Path) -> dict[str, object]:
    repo = tmp_path / "history"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    a = _commit(repo, "a")
    b = _commit(repo, "b")
    subprocess.run(["git", "-C", str(repo), "checkout", "-qb", "left", a], check=True)
    left = _commit(repo, "left")
    subprocess.run(["git", "-C", str(repo), "checkout", "-qb", "right", a], check=True)
    right = _commit(repo, "right")
    return {"repo": repo, "a": a, "b": b, "left": left, "right": right}


def _classify(tmp_path: pathlib.Path, repo: pathlib.Path, deployed: str, package: str) -> str:
    deployed_root = tmp_path / ("deployed-" + deployed[:8])
    package_root = tmp_path / ("package-" + package[:8])
    subprocess.run(["git", "clone", "-q", str(repo), str(deployed_root)], check=True)
    subprocess.run(["git", "clone", "-q", str(repo), str(package_root)], check=True)
    subprocess.run(["git", "-C", str(deployed_root), "checkout", "-q", deployed], check=True)
    subprocess.run(["git", "-C", str(package_root), "checkout", "-q", package], check=True)

    start = LINUX.index("classify_package_source_relation()")
    end = LINUX.index("\n}\n\nCFM_DEPLOYED_HEAD_BEFORE", start) + 3
    function = LINUX[start:end]
    script = f'''set -euo pipefail
REPO_DIR={str(package_root)!r}
DEPLOYED_ROOT={str(deployed_root)!r}
gitsu() {{ git -C "$DEPLOYED_ROOT" "$@"; }}
{function}
classify_package_source_relation {deployed!r} {package!r}
'''
    return subprocess.check_output(["bash", "-c", script], text=True).strip()


@pytest.mark.skipif(
    os.name == "nt",
    reason="the Linux shell classifier is executed by the Linux contract job",
)
@pytest.mark.parametrize(
    ("deployed_key", "package_key", "expected"),
    [
        ("b", "b", "same"),
        ("a", "b", "forward"),
        ("b", "a", "stale"),
        ("left", "right", "diverged"),
    ],
)
def test_linux_classifies_exact_git_relationships(
    tmp_path: pathlib.Path,
    history: dict[str, object],
    deployed_key: str,
    package_key: str,
    expected: str,
) -> None:
    assert _classify(
        tmp_path, history["repo"], history[deployed_key], history[package_key]  # type: ignore[arg-type]
    ) == expected


@pytest.mark.skipif(
    os.name == "nt",
    reason="the Linux shell version resolver is executed by the Linux contract job",
)
def test_linux_package_display_prefers_public_release_identity(
    tmp_path: pathlib.Path,
) -> None:
    repo = tmp_path / "versions"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    private_head = _commit(repo, "private")
    (repo / "release-build.txt").write_text("2656\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "release-build.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=Test", "-c",
         "user.email=test@example.invalid", "commit", "-qm", "public"],
        check=True,
    )
    public_head = _git(repo, "rev-parse", "HEAD")

    start = LINUX.index("source_build_for_commit()")
    end = LINUX.index("\n}\n\npreflight_package_source_advance", start) + 3
    function = LINUX[start:end]
    script = f'''set -euo pipefail
{function}
printf '%s\\n' "$(source_build_for_commit {str(repo)!r} {private_head!r})"
printf '%s\\n' "$(source_build_for_commit {str(repo)!r} {public_head!r})"
'''
    assert subprocess.check_output(["bash", "-c", script], text=True).splitlines() == ["1", "2656"]


def test_linux_refuses_stale_or_divergent_package_before_quiescence() -> None:
    call = LINUX.index("\npreflight_package_source_advance\n")
    quiesce = LINUX.index("# ═══ PHASE 9 — QUIESCE UPDATE")
    reset = LINUX.index('reset -q --hard "$_cfm_source_head"')
    assert call < quiesce < reset
    preflight = LINUX[LINUX.index("preflight_package_source_advance() {"):call]
    assert 'stale)' in preflight and 'this installer never downgrades an installation' in preflight
    assert 'CFM_DEPLOYED_HEAD_BEFORE="$deployed_head"' in preflight


def test_windows_retains_its_existing_pre_quiesce_fast_forward_guard() -> None:
    guard = WINDOWS.index("merge-base --is-ancestor $deployedHead $seedHead")
    call = WINDOWS.index("Prepare-ExternalSourceAdvance $Src", guard)
    quiesce = WINDOWS.index("# === PHASE 9 - QUIESCE UPDATE")
    reset = WINDOWS.index("reset --hard $ExternalSourceHead")
    assert guard < call < quiesce < reset
