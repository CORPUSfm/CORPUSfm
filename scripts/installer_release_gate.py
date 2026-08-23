#!/usr/bin/env python3
"""Installer release-gate runner (packet 019 spec; executed in packet 030).

Makes the v0.1018 validate-before-tag pattern repeatable and hard to forget: build the bundle locally,
fresh-install -> anonymous public source + health checks -> clean uninstall on BOTH FMS boxes, and
produce a report with a FIXED section shape every run. **This is a GATE, never a releaser** — it does
not tag, publish, or cut a release. That stays a separate, deliberate human step after the gate passes.

SAFE BY DEFAULT. With no flags it runs `--plan`: checks prerequisites and writes the report skeleton,
touching NO box. Live install/uninstall on the boxes happens ONLY under `--live` AND the explicit
`--yes-mutate-boxes` acknowledgement, and only after each box is verified REACHABLE and CLEAN (no
existing CORPUSfm install) — so the runner can't clobber an unknown deployment or hit the wrong host.

    python scripts/installer_release_gate.py                         # plan: prereqs + skeleton (safe)
    CFM_GATE_FM_ADMIN_PASS=… CFM_GATE_CFM_ADMIN_PASS=… \
      python scripts/installer_release_gate.py --live --yes-mutate-boxes \
        --linux-host fms-server --windows-host winfms2026            # full live gate (mutating)

Secrets come from the environment (CFM_GATE_FM_ADMIN_PASS = FMS admin pw; CFM_GATE_CFM_ADMIN_PASS =
the first CORPUSfm web-admin pw), NEVER argv — and every captured command output is redacted before it
reaches stdout or the report. The CHECK DEFINITIONS below are the source of truth for "what a release
must prove"; docs/installer-release-gate.md is the manual command form.
"""
from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The report has these sections EVERY run (packet 019 Batch 4).
REPORT_SECTIONS = [
    "bundle built",
    "Linux fresh install proof",
    "Linux anonymous public source-update proof",
    "Linux health proof",
    "Linux uninstall proof",
    "Windows fresh install proof",
    "Windows anonymous public source-update proof",
    "Windows health proof",
    "Windows uninstall proof",
    "release tag/publish result",
    "residual risks / skips",
]

# What each proof must establish (the v0.1018 lessons; mirror Linux/Windows).
PUBLIC_SOURCE_CHECKS = [
    "no source deploy-key file (~/.ssh/id_ed25519 / .ssh\\id_ed25519)",
    "no 'Arm the in-app Updates button' banner in install output",
    "origin is plain HTTPS (no git@…, no x-access-token in the URL)",
    "no core.sshCommand on the app checkout",
    "anonymous public origin works HEADLESS as the service user (git ls-remote origin succeeds)",
    "no source credential helper/store, GCM, wincredman, prompt, or token-in-origin is needed",
    "no legacy source credential artifact remains installed",
]
HEALTH_CHECKS = [
    "storage backend = FileMakerODataBackend",
    "readiness Tier 2",
    "first admin exists and verify_login succeeds",
    "loopback login at http://127.0.0.1:8533/login (NOT the /corpusfm prefix; proxy strips it) -> 302",
    "remote /corpusfm/login through the proxy authenticates (302 -> authed)",
    "MCP POST without bearer fails closed (HTTP 401)",
    "storage DB present after install",
]
CLEANLINESS_CHECKS = [
    "install root absent after uninstall",
    "services absent after uninstall",
    "storage DB absent after uninstall",
    "reverse proxy removed",
    "PKI deregistered (or clear manual remediation recorded)",
]

# This runner NEVER runs any of these — it is a gate, not a releaser. A guard test asserts the live
# orchestration source invokes none of them. (Building the bundle locally is part of the gate and is
# NOT a release; tagging / publishing / pushing are the deliberate human step AFTER the gate passes.)
FORBIDDEN_RELEASE_TOKENS = ("git tag", "gh release", "git push")

# Secrets are read from these env vars only — never argv (which `ps`/shell history would leak).
ENV_FM_ADMIN_PASS = "CFM_GATE_FM_ADMIN_PASS"
ENV_CFM_ADMIN_PASS = "CFM_GATE_CFM_ADMIN_PASS"


# ── secret-safe command execution ─────────────────────────────────────────────────

class Secrets:
    """Holds the live-mode secret values so output can be redacted before it's ever shown/written."""

    def __init__(self, values: list[str]):
        self._values = [v for v in values if v]

    def redact(self, text: str) -> str:
        out = text or ""
        for v in self._values:
            if v:
                out = out.replace(v, "***")
                out = out.replace(base64.b64encode(v.encode()).decode(), "***")
        return out


def sh(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return 1, repr(exc)


def check_prereqs(linux_host: str, windows_host: str) -> list[tuple[str, bool, str]]:
    """Non-mutating prerequisite probes for a release gate."""
    out: list[tuple[str, bool, str]] = []
    rc, _ = sh(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    out.append(("git repo present", rc == 0, ""))
    rc, o = sh(["git", "-C", str(ROOT), "status", "--porcelain"])
    dirty = [l for l in o.splitlines() if l and not any(x in l for x in (".codex/", "dist/", ".claude/"))]
    out.append(("working tree clean (tracked)", not dirty, "\n".join(dirty[:3])))
    out.append(("package-installer.sh present", (ROOT / "installer/package-installer.sh").exists(), ""))
    rc, o = sh(["gh", "auth", "status"])
    out.append(("gh authenticated (for the SEPARATE publish step)", rc == 0, o.splitlines()[0] if o else ""))
    for label, host in (("linux", linux_host), ("windows", windows_host)):
        rc, o = sh(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, "echo ok"])
        out.append((f"{label} box reachable ({host})", rc == 0 and "ok" in o, o.splitlines()[-1] if o else ""))
    return out


def write_skeleton(report: Path, version: str) -> None:
    lines = [f"# Installer Release Gate — report\n",
             f"Version: {version} · mode: PLAN (no box touched)\n"]
    for s in REPORT_SECTIONS:
        lines.append(f"## {s}\n\n_PENDING — run with --live --yes-mutate-boxes to populate._\n")
    lines.append("\n## Checks encoded\n")
    lines.append("\n**Anonymous public source-update proof (per box):**\n" + "".join(f"- {c}\n" for c in PUBLIC_SOURCE_CHECKS))
    lines.append("\n**Health proof (per box):**\n" + "".join(f"- {c}\n" for c in HEALTH_CHECKS))
    lines.append("\n**Cleanliness proof (per box):**\n" + "".join(f"- {c}\n" for c in CLEANLINESS_CHECKS))
    report.write_text("\n".join(lines), encoding="utf-8")


# ── live orchestration (executed; safe-guarded) ────────────────────────────────────

def _live_module():
    """Import the live orchestrator lazily so plan mode + tests never need ssh/paramiko-ish deps."""
    import importlib.util
    path = ROOT / "scripts" / "_release_gate_live.py"
    spec = importlib.util.spec_from_file_location("_release_gate_live", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser(description="Installer release gate (safe plan by default; never releases).")
    ap.add_argument("--live", action="store_true",
                    help="MUTATING: fresh-install/validate/uninstall on both boxes (for a release).")
    ap.add_argument("--yes-mutate-boxes", action="store_true",
                    help="Required WITH --live: explicit acknowledgement that real boxes are mutated.")
    ap.add_argument("--linux-host", default="fms-server")
    ap.add_argument("--windows-host", default="winfms2026")
    ap.add_argument("--report", default="docs/installer-release-gate-report.md")
    args = ap.parse_args()

    try:
        release_build = (ROOT / "release-build.txt").read_text(encoding="utf-8").strip()
    except OSError:
        release_build = ""
    version = (f"0.{release_build}" if release_build.isdigit()
               and not release_build.startswith("0") else "0.?")

    if not args.live:
        print(f"Installer release gate — PLAN (version {version}; no box touched)\n")
        ok = True
        for name, passed, detail in check_prereqs(args.linux_host, args.windows_host):
            print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not passed else ""))
            ok = ok and passed
        report = ROOT / args.report
        write_skeleton(report, version)
        print(f"\nReport skeleton written: {report}")
        print(f"Report sections ({len(REPORT_SECTIONS)}): " + " · ".join(REPORT_SECTIONS))
        print("\nPrereqs " + ("OK — ready to run the live gate (--live --yes-mutate-boxes)."
                              if ok else "INCOMPLETE — resolve the FAILs before a release."))
        return 0 if ok else 1

    # ── live mode: explicit acknowledgement + secrets-from-env, both mandatory ──
    if not args.yes_mutate_boxes:
        print("REFUSED: --live mutates real FMS boxes (install + uninstall). Re-run with "
              "--yes-mutate-boxes to acknowledge.", file=sys.stderr)
        return 2
    fm_pw = os.environ.get(ENV_FM_ADMIN_PASS, "")
    cfm_pw = os.environ.get(ENV_CFM_ADMIN_PASS, "")
    if not fm_pw or not cfm_pw:
        print(f"REFUSED: set {ENV_FM_ADMIN_PASS} and {ENV_CFM_ADMIN_PASS} in the environment "
              "(never on argv). No box was touched.", file=sys.stderr)
        return 2

    live = _live_module()
    return live.run_live_gate(
        root=ROOT, version=version, linux_host=args.linux_host, windows_host=args.windows_host,
        report=ROOT / args.report, secrets=Secrets([fm_pw, cfm_pw]),
        fm_pw=fm_pw, cfm_pw=cfm_pw,
        sections=REPORT_SECTIONS, pat_checks=PUBLIC_SOURCE_CHECKS, health_checks=HEALTH_CHECKS,
        cleanliness_checks=CLEANLINESS_CHECKS,
    )


if __name__ == "__main__":
    sys.exit(main())
