"""Minimal fakes for installer-snippet simulation."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def make_fake_bin(d: Path, scripts: dict[str, str]) -> Path:
    """Create executable fake commands in `d`. Each value is a POSIX sh body. A shared $FAKE_LOG (set
    by the caller's env) lets fakes append "<name> <args>" lines the test can assert on."""
    d.mkdir(parents=True, exist_ok=True)
    for name, body in scripts.items():
        p = d / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(0o755)
    return d


def extract_sh_func(name: str, sh_path: Path | None = None) -> str:
    """Return the source text of a top-level shell function `name() { ... }` from a script."""
    text = (sh_path or (ROOT / "installer/linux/install.sh")).read_text(encoding="utf-8")
    m = re.search(r"^%s\(\)\s*\{.*?^\}" % re.escape(name), text, re.S | re.M)
    if not m:
        raise AssertionError(f"function {name}() not found")
    return m.group(0)


def run_bash(script: str, env: dict, fake_bin: Path) -> subprocess.CompletedProcess:
    """Run a bash script with `fake_bin` prepended to PATH."""
    e = dict(os.environ)
    e.update(env)
    e["PATH"] = f"{fake_bin}:{e.get('PATH','')}"
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e)
