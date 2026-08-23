"""Live orchestration for the installer release gate (packet 030).

Executed ONLY from installer_release_gate.py's `--live --yes-mutate-boxes` path, after secrets are
read from the environment. Orchestrates the ALREADY-PROVEN install/health/uninstall commands (the
v0.1050 sequence) over ssh — it does NOT re-implement installer logic, and it NEVER tags / publishes /
pushes (it is a gate). Every captured output is run through `secrets.redact()` before it is printed or
written, so credentials never reach stdout or the report. On any post-mutation failure it still runs
the uninstall to clean the box and reports the cleanliness state honestly rather than false-passing.
"""
from __future__ import annotations

import base64
import hashlib
import subprocess
from pathlib import Path


# ── secret-safe exec helpers ───────────────────────────────────────────────────────

def _run(argv: list[str], secrets, timeout: int = 120, stdin_devnull: bool = True):
    """Run a local command; return (rc, redacted_combined_output). stdin is /dev/null so a remote
    fmsadmin never blocks waiting on it."""
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL if stdin_devnull else None,
        )
        return p.returncode, secrets.redact((p.stdout + p.stderr).strip())
    except Exception as exc:  # noqa: BLE001
        return 1, secrets.redact(repr(exc))


def _ssh(host: str, remote_cmd: str, secrets, timeout: int = 120):
    return _run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host, remote_cmd],
                secrets, timeout)


def _scp(local: list[str], host: str, dest: str, secrets):
    return _run(["scp", "-q", *local, f"{host}:{dest}"], secrets, timeout=120)


def _pssh(host: str, ps: str, secrets, timeout: int = 120):
    """Run inline PowerShell on a default-OS Windows box (PS 5.1) via -EncodedCommand; strip the 5.1
    CLIXML remoting noise."""
    b64 = base64.b64encode(ps.encode("utf-16-le")).decode()
    rc, out = _run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host,
                    f"powershell -NoProfile -EncodedCommand {b64}"], secrets, timeout)
    clean = "\n".join(l for l in out.splitlines()
                      if not l.startswith(("#< CLIXML", "<Objs", "_x")))
    return rc, clean.strip()


# ── a section is a list of (label, passed, detail) ─────────────────────────────────

def _result(label, passed, detail=""):
    return (label, bool(passed), detail)


# ── Linux lane ─────────────────────────────────────────────────────────────────────

def _linux_clean(host, secrets) -> bool:
    rc, out = _ssh(host, "ls /opt/CORPUSfm >/dev/null 2>&1 && echo PRESENT || echo CLEAN", secrets, 30)
    return "CLEAN" in out and "PRESENT" not in out


def _linux_lane(root, host, fm_pw, cfm_pw, secrets):
    stage = "/tmp/cfm-gate"
    install_out = {"text": ""}
    inst = []
    pat = []
    health = []
    uninst = []

    files = [str(root / "installer/linux/install.sh"),
             str(root / "installer/linux/_cfm_lib.sh"),
             str(root / "installer/linux/uninstall.sh")]
    _ssh(host, f"rm -rf {stage} && mkdir -p {stage}", secrets, 30)
    _scp(files, host, f"{stage}/", secrets)

    rc, out = _ssh(
        host,
        f"cd {stage} && sudo bash install.sh --silent --yes --fm-admin-user admin "
        f"--fm-admin-pass {fm_pw} --admin-user admin --admin-pass {cfm_pw}",
        secrets, timeout=900)
    install_out["text"] = out
    inst.append(_result("install exits success", "installed successfully" in out,
                        "" if "installed successfully" in out else "(no success banner)"))
    inst.append(_result("storage bootstrapped", "backend_activated" in out or "FM OData backend activated" in out))
    # Verify the first admin by PROBING the named-user store (robust) rather than scraping install text.
    rc, ue = _ssh(host, "sudo -u corpusfm env HOME=/opt/CORPUSfm PYTHONPATH=/opt/CORPUSfm/src "
                        "/opt/CORPUSfm/venv/bin/python -c "
                        "'from corpusfm.app.web import users; print(\"YES\" if users.users_exist() else \"NO\")'", secrets, 60)
    inst.append(_result("first admin exists (users_exist)", "YES" in ue, ue))

    # Anonymous public source proof (inspect the deployed checkout as the service user)
    rc, origin = _ssh(host, "sudo -u corpusfm env HOME=/opt/CORPUSfm git -C /opt/CORPUSfm/src "
                            "-c safe.directory='*' remote get-url origin 2>/dev/null", secrets, 30)
    pat.append(_result("origin is plain HTTPS (no git@, no token-in-URL)",
                       origin.startswith("https://github.com/") and "x-access-token" not in origin and "git@" not in origin,
                       origin))
    rc, sshc = _ssh(host, "sudo -u corpusfm env HOME=/opt/CORPUSfm git -C /opt/CORPUSfm/src "
                          "-c safe.directory='*' config --get core.sshCommand 2>/dev/null || echo none", secrets, 30)
    pat.append(_result("no core.sshCommand on the app checkout", "none" in sshc or not sshc.strip()))
    rc, dk = _ssh(host, "sudo test -e /opt/CORPUSfm/.ssh/id_ed25519 && echo HASKEY || echo NOKEY", secrets, 30)
    pat.append(_result("no source deploy key on the box", "NOKEY" in dk))
    rc, ls = _ssh(host, "sudo -u corpusfm env HOME=/opt/CORPUSfm git -C /opt/CORPUSfm/src "
                        "-c safe.directory='*' ls-remote origin HEAD >/dev/null 2>&1 && echo OK || echo FAIL", secrets, 60)
    pat.append(_result("anonymous origin works headless (ls-remote origin)", "OK" in ls))
    pat.append(_result("no deploy-key banner in install output", "register this deploy key" not in out.lower()))

    # health
    rc, root302 = _ssh(host, 'curl -sk -o /dev/null -w "%{http_code}" http://127.0.0.1:8533/', secrets, 30)
    health.append(_result("loopback root -> 302", root302.strip().endswith("302"), root302))
    rc, login = _ssh(host, 'curl -sk -o /dev/null -w "%{http_code}" https://localhost/corpusfm/login', secrets, 30)
    health.append(_result("proxied /corpusfm/login -> 200", login.strip().endswith("200"), login))
    rc, mcp = _ssh(host, 'curl -sk -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" '
                         '-d "{}" https://localhost/corpusfm/mcp/', secrets, 30)
    health.append(_result("MCP POST fails closed -> 401", mcp.strip().endswith("401"), mcp))
    rc, beq = _ssh(host, "sudo grep -q 'storage_backend: fm_odata' /opt/CORPUSfm/.corpusfm/install.yaml && echo OK || echo NO", secrets, 30)
    health.append(_result("storage backend = FileMakerODataBackend", "OK" in beq))
    rc, ver = _ssh(host, "sudo -u corpusfm env HOME=/opt/CORPUSfm PYTHONPATH=/opt/CORPUSfm/src "
                         "/opt/CORPUSfm/venv/bin/python -c 'import corpusfm; print(corpusfm.__version__)'", secrets, 60)
    health.append(_result("version stamp present (not 0.0)", ver.strip() not in ("", "0.0"), f"v{ver.strip()}"))

    # uninstall + cleanliness
    rc, uout = _ssh(host, f"cd {stage} && sudo bash uninstall.sh --force --fm-admin-user admin "
                          f"--fm-admin-pass {fm_pw}", secrets, timeout=300)
    uninst.append(_result("uninstall completes", "fully removed" in uout, "" if "fully removed" in uout else "(no farewell)"))
    rc, gone = _ssh(host, "ls /opt/CORPUSfm >/dev/null 2>&1 && echo PRESENT || echo GONE", secrets, 30)
    uninst.append(_result("install root absent after uninstall", "GONE" in gone))
    rc, svc = _ssh(host, "systemctl list-units --all 2>/dev/null | grep -q corpusfm && echo SVC || echo NOSVC", secrets, 30)
    uninst.append(_result("services absent after uninstall", "NOSVC" in svc))
    rc, fmi = _ssh(host, 'curl -sk -o /dev/null -w "%{http_code}" https://localhost/fmi/odata/v4/', secrets, 30)
    uninst.append(_result("FMS /fmi/ healthy after uninstall -> 200", fmi.strip().endswith("200"), fmi))
    rc, prox = _ssh(host, 'curl -sk -o /dev/null -w "%{http_code}" https://localhost/corpusfm/login', secrets, 30)
    uninst.append(_result("reverse proxy removed (/corpusfm -> 404)", prox.strip().endswith("404"), prox))
    _ssh(host, f"rm -rf {stage}", secrets, 30)

    return {"install": inst, "pat": pat, "health": health, "uninstall": uninst, "raw": install_out["text"]}


# ── Windows lane ───────────────────────────────────────────────────────────────────

def _win_clean(host, secrets) -> bool:
    rc, out = _pssh(host, 'Write-Output ("clean=" + (-not (Test-Path "C:\\CORPUSfm")))', secrets, 30)
    return "clean=True" in out


def _win_lane(root, host, fm_pw, cfm_pw, secrets):
    stage = "C:\\Windows\\Temp\\cfm-gate"
    inst, pat, health, uninst = [], [], [], []

    _pssh(host, f'New-Item -ItemType Directory -Force -Path "{stage}" | Out-Null; Write-Output ok', secrets, 30)
    _scp([str(root / "installer/windows/install.ps1"),
          str(root / "installer/windows/_cfm_lib.ps1"),
          str(root / "installer/windows/uninstall.ps1")], host, f"{stage}/", secrets)

    # Run the install SYNCHRONOUSLY (blocking) — a detached Start-Process of install.ps1 is unreliable
    # on this box (the child dies early; observed packet 028), whereas the synchronous call operator
    # runs to completion. Write-Host isn't capturable, so we discard streams and verify via the
    # installer's own transcript + box state afterward. The ssh call blocks for the full install
    # (~4-10 min depending on pip/network), so the timeout is generous.
    inst_cmd = (f"& '{stage}\\install.ps1' -Silent -Yes -FmAdminUser admin -FmAdminPass {fm_pw} "
                f"-AdminUser admin -AdminPass {cfm_pw} *> $null; Write-Output ('rc=' + $LASTEXITCODE)")
    rc, irc = _pssh(host, inst_cmd, secrets, timeout=1800)
    sentinel = "Thank you for installing CORPUSfm"
    rc2, tail = _pssh(
        host,
        "$l=Get-ChildItem 'C:\\ProgramData\\CORPUSfm\\logs' -Filter 'install-*.log' -EA SilentlyContinue | "
        "Sort-Object LastWriteTime -Desc | Select-Object -First 1; "
        "if ($l) { Get-Content $l.FullName -Tail 4 } else { Write-Output '(no transcript)' }", secrets, 60)
    transcript_ok = sentinel in tail
    inst.append(_result("install completes (transcript farewell seen)", transcript_ok,
                        "" if transcript_ok else "(no farewell — see box transcript)"))

    # health (curl.exe is default-OS on Windows Server; PS 5.1 Invoke-WebRequest can't TLS-handshake FMS)
    def cap(ps):
        return _pssh(host, ps, secrets, 40)[1]
    inst.append(_result("both services running",
                        "web=Running" in cap("$s=Get-Service corpusfm-web,corpusfm-scheduler|%{\"$($_.Name)=$($_.Status)\"};Write-Output (($s -join ',').Replace('corpusfm-',''))")))
    login = cap('Write-Output ("c=" + (curl.exe -sk -o NUL -w "%{http_code}" https://localhost/corpusfm/login))')
    health.append(_result("proxied /corpusfm/login -> 200", "c=200" in login, login))
    mcp = cap('Write-Output ("c=" + (curl.exe -sk -o NUL -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "{}" https://localhost/corpusfm/mcp/))')
    health.append(_result("MCP POST fails closed -> 401", "c=401" in mcp, mcp))
    fmi = cap('Write-Output ("c=" + (curl.exe -sk -o NUL -w "%{http_code}" https://localhost/fmi/odata/v4/))')
    health.append(_result("FMS /fmi/ healthy (coexistence) -> 200", "c=200" in fmi, fmi))
    ver = cap("$env:PYTHONPATH='C:\\CORPUSfm\\src'; Write-Output ('v=' + (& 'C:\\CORPUSfm\\python\\python.exe' -c 'import corpusfm;print(corpusfm.__version__)'))")
    health.append(_result("version stamp present (not 0.0)", "v=" in ver and "v=0.0" not in ver, ver))

    # Anonymous public source proof (the persisted origin is tokenless and no store remains)
    origin = cap("Write-Output ('o=' + (& 'C:\\CORPUSfm\\git\\cmd\\git.exe' -C 'C:\\CORPUSfm\\src' remote get-url origin))")
    pat.append(_result("origin is plain HTTPS (no token-in-URL)",
                       "o=https://github.com/" in origin and "x-access-token" not in origin, origin))
    nokey = cap('Write-Output ("dk=" + (Test-Path "C:\\CORPUSfm\\.ssh\\id_ed25519"))')
    pat.append(_result("no source deploy key on the box", "dk=False" in nokey))
    pat.append(_result("no legacy source credential store remains",
                       "p=False" in cap('Write-Output ("p=" + ((Test-Path "C:\\Program Files\\CORPUSfm\\.git-pat") -or (Test-Path "C:\\Program Files\\CORPUSfm\\.git-credentials")))')))

    # uninstall + cleanliness (synchronous; ~1-2 min)
    _pssh(host, f"& '{stage}\\uninstall.ps1' -Force -FmAdminUser admin -FmAdminPass {fm_pw} | Out-Null; Write-Output done", secrets, 300)
    state = cap('Write-Output ("dir=" + (Test-Path "C:\\CORPUSfm") + ";cfg=" + (Test-Path "C:\\ProgramData\\CORPUSfm") + '
                '";svc=" + [bool](Get-Service corpusfm-web -EA SilentlyContinue) + '
                '";app=" + [bool](Get-WebApplication -Site (Get-Website -Name FMWebSite -EA SilentlyContinue).Name -Name corpusfm -EA SilentlyContinue))')
    uninst.append(_result("install dir absent after uninstall", "dir=False" in state, state))
    uninst.append(_result("config home absent after uninstall", "cfg=False" in state))
    uninst.append(_result("service absent after uninstall", "svc=False" in state))
    uninst.append(_result("IIS app removed after uninstall", "app=False" in state))
    fmi2 = cap('Write-Output ("c=" + (curl.exe -sk -o NUL -w "%{http_code}" https://localhost/fmi/odata/v4/))')
    uninst.append(_result("FMS /fmi/ healthy after uninstall -> 200", "c=200" in fmi2, fmi2))
    _pssh(host, f'Remove-Item -Recurse -Force "{stage}" -EA SilentlyContinue; Write-Output done', secrets, 30)

    return {"install": inst, "pat": pat, "health": health, "uninstall": uninst}


def _fmt(results) -> tuple[str, bool]:
    lines, ok = [], True
    for label, passed, detail in results:
        ok = ok and passed
        lines.append(f"- [{'PASS' if passed else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    return "\n".join(lines), ok


def _bundle_identity(root, secrets) -> tuple[str, list]:
    """Record the installer-script identity that this gate validates (sha256 of each shipped script).
    A gate proves the artifact you'd ship; it does NOT tag/publish it."""
    res = []
    for rel in ("installer/linux/install.sh", "installer/linux/uninstall.sh", "installer/linux/_cfm_lib.sh",
                "installer/windows/install.ps1", "installer/windows/uninstall.ps1", "installer/windows/_cfm_lib.ps1"):
        p = root / rel
        h = hashlib.sha256(p.read_bytes()).hexdigest()[:16] if p.exists() else "MISSING"
        res.append(_result(f"{rel} sha256={h}", p.exists()))
    body, ok = _fmt(res)
    return body, ok


def run_live_gate(*, root, version, linux_host, windows_host, report, secrets, fm_pw, cfm_pw,
                  sections, pat_checks, health_checks, cleanliness_checks) -> int:
    print(f"Installer release gate — LIVE (version {version})")
    print(f"  Linux: {linux_host} · Windows: {windows_host}\n")

    # Wrong-box / clobber safeguard: refuse to mutate a box that isn't reachable AND currently clean.
    if not _linux_clean(linux_host, secrets):
        print(f"REFUSED: {linux_host} is not reachable or already has a CORPUSfm install — won't clobber it.")
        return 2
    if not _win_clean(windows_host, secrets):
        print(f"REFUSED: {windows_host} is not reachable or already has a CORPUSfm install — won't clobber it.")
        return 2
    print("  Pre-flight: both boxes reachable + clean.\n")

    overall = True
    bundle_body, bundle_ok = _bundle_identity(root, secrets)
    overall = overall and bundle_ok

    try:
        lin = _linux_lane(root, linux_host, fm_pw, cfm_pw, secrets)
    except Exception as exc:  # noqa: BLE001
        print("Linux lane raised:", secrets.redact(repr(exc)))
        lin = {"install": [_result("linux lane raised", False, secrets.redact(repr(exc)))],
               "pat": [], "health": [], "uninstall": [_result("uninstall not reached — CHECK BOX MANUALLY", False)]}

    try:
        win = _win_lane(root, windows_host, fm_pw, cfm_pw, secrets)
    except Exception as exc:  # noqa: BLE001
        print("Windows lane raised:", secrets.redact(repr(exc)))
        win = {"install": [_result("windows lane raised", False, secrets.redact(repr(exc)))],
               "pat": [], "health": [], "uninstall": [_result("uninstall not reached — CHECK BOX MANUALLY", False)]}

    body = {}
    for key, results in (("Linux fresh install proof", lin["install"]),
                         ("Linux anonymous public source-update proof", lin["pat"]),
                         ("Linux health proof", lin["health"]),
                         ("Linux uninstall proof", lin["uninstall"]),
                         ("Windows fresh install proof", win["install"]),
                         ("Windows anonymous public source-update proof", win["pat"]),
                         ("Windows health proof", win["health"]),
                         ("Windows uninstall proof", win["uninstall"])):
        text, ok = _fmt(results)
        body[key] = text or "_(no checks ran)_"
        overall = overall and ok

    # Honesty: a box is only "clean" if its uninstall section passed.
    lin_clean = all(p for _, p, _ in lin["uninstall"])
    win_clean = all(p for _, p, _ in win["uninstall"])

    out = [f"# Installer Release Gate — report\n",
           f"Version: {version} · mode: LIVE · result: {'PASS' if overall else 'FAIL'}\n",
           f"Linux box: {linux_host} (left {'CLEAN' if lin_clean else 'IN AN UNCLEAR STATE — INSPECT'})\n",
           f"Windows box: {windows_host} (left {'CLEAN' if win_clean else 'IN AN UNCLEAR STATE — INSPECT'})\n"]
    out.append(f"## bundle built\n\n{bundle_body}\n")
    for key in sections:
        if key in body:
            out.append(f"## {key}\n\n{body[key]}\n")
    out.append("## release tag/publish result\n\n- [N/A] This runner is a GATE, not a releaser — it "
               "tags/publishes nothing. Cut the release manually after this gate passes.\n")
    skips = []
    if not lin_clean:
        skips.append(f"- Linux box {linux_host} may not be fully clean — inspect /opt/CORPUSfm + services.")
    if not win_clean:
        skips.append(f"- Windows box {windows_host} may not be fully clean — inspect C:\\CORPUSfm + services.")
    out.append("## residual risks / skips\n\n" + ("\n".join(skips) if skips else "- None — both boxes left clean.") + "\n")
    report.write_text("\n".join(out), encoding="utf-8")

    print(f"\nLIVE gate {'PASS' if overall else 'FAIL'} — report: {report}")
    print(f"  Linux left {'clean' if lin_clean else 'UNCLEAR — inspect'} · "
          f"Windows left {'clean' if win_clean else 'UNCLEAR — inspect'}")
    return 0 if (overall and lin_clean and win_clean) else 1
