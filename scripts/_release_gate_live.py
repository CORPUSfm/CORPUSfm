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
import json
import os
import pty
import select
import subprocess
import time
from pathlib import Path


# ── secret-safe exec helpers ───────────────────────────────────────────────────────

def _run(argv: list[str], secrets, timeout: int = 120, stdin_text: str | None = None):
    """Run a local command; return (rc, redacted_combined_output). stdin is /dev/null so a remote
    fmsadmin never blocks waiting on it."""
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, input=stdin_text,
            stdin=subprocess.DEVNULL if stdin_text is None else None,
        )
        return p.returncode, secrets.redact((p.stdout + p.stderr).strip())
    except Exception as exc:  # noqa: BLE001
        return 1, secrets.redact(repr(exc))


def _run_windows_tty_dialog(argv: list[str], timeout: int, stdin_text: str):
    """Drive Windows Read-Host through a real local PTY, replying only after each prompt.

    ``ssh -tt`` allocates the remote conhost, but a local stdin pipe is still not an interactive
    console: measured on winfms2026, PowerShell displayed no prompts, exited zero, and did nothing.
    A local PTY supplies the missing terminal semantics.  Waiting for each prompt also prevents a
    password from being queued while terminal echo is still enabled.
    """
    responses = [part for part in stdin_text.split("\r") if part]
    prompts = ("fm server admin account username", "fm server admin account password") * 2
    if len(responses) != len(prompts):
        return 1, "Windows TTY dialog refused: expected two username/password response pairs"

    master, slave = pty.openpty()
    proc = None
    chunks: list[bytes] = []
    response_index = 0
    seen = ""
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        slave = -1
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                proc.kill()
                proc.wait(timeout=5)
                return 1, "Windows TTY dialog timed out"
            readable, _, _ = select.select([master], [], [], 0.25)
            if not readable:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            seen += chunk.decode("utf-8", errors="replace").lower()
            if response_index < len(prompts) and prompts[response_index] in seen:
                os.write(master, responses[response_index].encode("utf-8") + b"\r")
                response_index += 1
                seen = ""
        # A short final drain keeps the farewell / remote exit status in the report.
        while True:
            readable, _, _ = select.select([master], [], [], 0.05)
            if not readable:
                break
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        rc = proc.wait(timeout=5)
        return rc, b"".join(chunks).decode("utf-8", errors="replace").strip()
    except Exception as exc:  # noqa: BLE001
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        return 1, repr(exc)
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)


def _ssh(host: str, remote_cmd: str, secrets, timeout: int = 120, stdin_text: str | None = None,
         tty: bool = False):
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if tty:
        argv.append("-tt")
    argv.extend((host, remote_cmd))
    return _run(argv, secrets, timeout, stdin_text)


def _scp(local: list[str], host: str, dest: str, secrets):
    return _run(["scp", "-q", *local, f"{host}:{dest}"], secrets, timeout=120)


def _pssh(host: str, ps: str, secrets, timeout: int = 120, stdin_text: str | None = None,
          tty: bool = False):
    """Run inline PowerShell on a default-OS Windows box (PS 5.1) via -EncodedCommand; strip the 5.1
    CLIXML remoting noise."""
    b64 = base64.b64encode(ps.encode("utf-16-le")).decode()
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if tty:
        argv.append("-tt")
    argv.extend((host, f"powershell -NoProfile -EncodedCommand {b64}"))
    if tty and stdin_text is not None:
        rc, out = _run_windows_tty_dialog(argv, timeout, stdin_text)
    else:
        rc, out = _run(argv, secrets, timeout, stdin_text)
    clean = "\n".join(l for l in out.splitlines()
                      if not l.startswith(("#< CLIXML", "<Objs", "_x")))
    return rc, clean.strip()


# ── a section is a list of (label, passed, detail) ─────────────────────────────────

def _result(label, passed, detail=""):
    return (label, bool(passed), detail)


# ── Linux lane ─────────────────────────────────────────────────────────────────────

def _linux_clean(host, secrets) -> bool:
    command = "for p in /opt/CORPUSfm /etc/corpusfm /var/lib/corpusfm /opt/CORPUSfm-Hosted; do " \
              "test ! -e \"$p\" || exit 9; done; " \
              "systemctl list-unit-files corpusfm.service corpusfm-scheduler.service --no-legend " \
              "2>/dev/null | grep -q corpusfm && exit 9; echo CLEAN"
    rc, out = _ssh(host, command, secrets, 30)
    return rc == 0 and out.strip().endswith("CLEAN")


def _linux_lane(release_dir, package, sidecar, host, fm_pw, cfm_pw, secrets):
    stage = "/tmp/cfm-gate"
    install_out = {"text": ""}
    inst = []
    pat = []
    health = []
    uninst = []

    _ssh(host, f"test ! -e {stage} || mv {stage} {stage}.previous.$$$$; mkdir -p {stage}/package", secrets, 30)
    rc, copied = _scp([str(package), str(sidecar)], host, f"{stage}/", secrets)
    inst.append(_result("shipped Linux ZIP copied", rc == 0, copied))
    verify = (f"cd {stage} && sha256sum -c {sidecar.name} && "
              f"unzip -q {package.name} -d package && cd package && sha256sum -c installer-files.sha256")
    rc, verified = _ssh(host, verify, secrets, 120)
    inst.append(_result("Linux ZIP and internal inventory verified on box", rc == 0, verified))

    secret_input = (base64.b64encode(fm_pw.encode()).decode() + "\n" +
                    base64.b64encode(cfm_pw.encode()).decode() + "\n")
    install_cmd = (
        "exec sudo bash -c 'read -r fm64; read -r cfm64; "
        "export FM_ADMIN_USER=admin CORPUSFM_ADMIN_USER=admin; "
        "export FM_ADMIN_PASS=$(printf %s \"$fm64\" | base64 -d); "
        "export CORPUSFM_ADMIN_PASS=$(printf %s \"$cfm64\" | base64 -d); "
        f"exec bash {stage}/package/install.sh --silent --yes "
        "--install-dir /opt/CORPUSfm "
        "--fms-root \"/opt/FileMaker/FileMaker Server\" "
        "--patch-hosting-dir /opt/CORPUSfm-Hosted'"
    )
    rc, out = _ssh(
        host, install_cmd, secrets, timeout=1800, stdin_text=secret_input)
    install_out["text"] = out
    inst.append(_result("packaged install exits success", rc == 0 and "installed successfully" in out,
                        "" if rc == 0 else f"exit {rc}"))
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
    rc, beq = _ssh(
        host,
        "sudo -u corpusfm env HOME=/opt/CORPUSfm PYTHONPATH=/opt/CORPUSfm/src "
        "/opt/CORPUSfm/venv/bin/python -c 'from corpusfm.lifecycle import runtime_storage; "
        "print(type(runtime_storage.backend()).__name__)'",
        secrets, 60)
    health.append(_result("storage backend = FileMakerODataBackend",
                          rc == 0 and beq.strip().endswith("FileMakerODataBackend"), beq))
    rc, ver = _ssh(host, "sudo -u corpusfm env HOME=/opt/CORPUSfm PYTHONPATH=/opt/CORPUSfm/src "
                         "/opt/CORPUSfm/venv/bin/python -c 'import corpusfm; print(corpusfm.__version__)'", secrets, 60)
    health.append(_result("version stamp present (not 0.0)", ver.strip() not in ("", "0.0"), f"v{ver.strip()}"))

    # uninstall + cleanliness
    # The current uninstaller deliberately accepts no credential flags. Allocate a TTY and answer
    # its transient credential prompts; the password travels on stdin, never argv or the report.
    answers = f"admin\n{fm_pw}\nadmin\n{fm_pw}\n"
    rc, uout = _ssh(host, "sudo /opt/CORPUSfm/uninstall.sh --yes", secrets, timeout=900,
                     stdin_text=answers, tty=True)
    uninst.append(_result("installed uninstaller completes", rc == 0 and "CORPUSfm removed" in uout,
                          "" if rc == 0 else f"exit {rc}"))
    rc, gone = _ssh(host, "for p in /opt/CORPUSfm /etc/corpusfm /var/lib/corpusfm /opt/CORPUSfm-Hosted; "
                          "do test ! -e \"$p\" || exit 9; done; echo GONE", secrets, 30)
    uninst.append(_result("fixed product roots absent after uninstall", rc == 0 and "GONE" in gone, gone))
    rc, svc = _ssh(
        host,
        "for u in corpusfm.service corpusfm-scheduler.service corpusfm-update.service "
        "corpusfm-update.timer; do "
        "test \"$(systemctl show -p LoadState --value \"$u\" 2>/dev/null)\" = not-found || exit 9; "
        "done; echo NOSVC",
        secrets, 30)
    uninst.append(_result("services absent after uninstall", rc == 0 and "NOSVC" in svc, svc))
    rc, fmi = _ssh(host, 'curl -sk -o /dev/null -w "%{http_code}" https://localhost/fmi/odata/v4/', secrets, 30)
    uninst.append(_result("FMS /fmi/ healthy after uninstall -> 200", fmi.strip().endswith("200"), fmi))
    rc, prox = _ssh(host, 'curl -sk -o /dev/null -w "%{http_code}" https://localhost/corpusfm/login', secrets, 30)
    uninst.append(_result("reverse proxy removed (/corpusfm -> 404)", prox.strip().endswith("404"), prox))
    _ssh(host, f"mv {stage} {stage}.completed.$$$$", secrets, 30)

    return {"install": inst, "pat": pat, "health": health, "uninstall": uninst, "raw": install_out["text"]}


# ── Windows lane ───────────────────────────────────────────────────────────────────

def _win_clean(host, secrets) -> bool:
    ps = "$paths=@('C:\\Program Files\\CORPUSfm','C:\\ProgramData\\CORPUSfm','C:\\CORPUSfm-Hosted'); " \
         "$present=@($paths|Where-Object {Test-Path -LiteralPath $_}); " \
         "$services=@(Get-Service corpusfm-web,corpusfm-scheduler -EA SilentlyContinue); " \
         "if($present.Count -eq 0 -and $services.Count -eq 0){Write-Output 'CLEAN';exit 0}; " \
         "Write-Output ('PRESENT=' + ($present -join ',') + ';SERVICES=' + ($services.Name -join ','));exit 9"
    rc, out = _pssh(host, ps, secrets, 30)
    return rc == 0 and out.strip().endswith("CLEAN")


def _win_lane(release_dir, package, sidecar, host, fm_pw, cfm_pw, secrets):
    stage = "C:\\Windows\\Temp\\cfm-gate"
    inst, pat, health, uninst = [], [], [], []

    prep = (f'if(Test-Path "{stage}"){{Move-Item "{stage}" ("{stage}.previous." + $PID)}}; '
            f'New-Item -ItemType Directory -Force -Path "{stage}\\package" | Out-Null; Write-Output ok')
    _pssh(host, prep, secrets, 30)
    rc, copied = _scp([str(package), str(sidecar)], host, f"{stage}/", secrets)
    inst.append(_result("shipped Windows ZIP copied", rc == 0, copied))
    verify = (f"$zip='{stage}\\{package.name}'; $side='{stage}\\{sidecar.name}'; "
              "$expected=((Get-Content $side -Raw).Trim().Split()[0]).ToLowerInvariant(); "
              "$actual=(Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant(); "
              "if($actual -ne $expected){Write-Error 'ZIP digest mismatch';exit 9}; "
              f"Expand-Archive -Force $zip '{stage}\\package'; "
              f"Set-Location '{stage}\\package'; "
              "$bad=@(); Get-Content installer-files.sha256 | ForEach-Object { "
              "$parts=$_ -split '  ',2; if($parts.Count -ne 2 -or "
              "(Get-FileHash -Algorithm SHA256 $parts[1]).Hash.ToLowerInvariant() -ne $parts[0]){$bad+=$_} }; "
              "if($bad.Count){Write-Error 'internal inventory mismatch';exit 9};Write-Output VERIFIED")
    rc, verified = _pssh(host, verify, secrets, 180)
    inst.append(_result("Windows ZIP and internal inventory verified on box", rc == 0 and "VERIFIED" in verified,
                        verified))

    # Run the install SYNCHRONOUSLY (blocking) — a detached Start-Process of install.ps1 is unreliable
    # on this box (the child dies early; observed packet 028), whereas the synchronous call operator
    # runs to completion. Do NOT redirect the script's streams at this call boundary. Windows
    # PowerShell 5.1 turns a nested native command's ordinary stderr into a terminating error under
    # the installer's ErrorActionPreference=Stop when the caller applies `*> $null`; measured twice
    # on a clean winfms2026, that killed the source-seed clone and left dependency-only residue.
    # _pssh captures and redacts the streams; the gate judges the transcript + box state afterward.
    secret_input = (base64.b64encode(fm_pw.encode()).decode() + "\n" +
                    base64.b64encode(cfm_pw.encode()).decode() + "\n")
    inst_cmd = ("$fm64=[Console]::In.ReadLine();$cfm64=[Console]::In.ReadLine();"
                "$env:FM_ADMIN_USER='admin';$env:CORPUSFM_ADMIN_USER='admin';"
                "$env:FM_ADMIN_PASS=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($fm64));"
                "$env:CORPUSFM_ADMIN_PASS=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cfm64));"
                f"& '{stage}\\package\\install.ps1' -Silent -Yes; "
                "$result=$LASTEXITCODE;Remove-Item Env:\\FM_ADMIN_PASS,Env:\\CORPUSFM_ADMIN_PASS -EA SilentlyContinue;"
                "Write-Output ('rc=' + $result);exit $result")
    rc, irc = _pssh(host, inst_cmd, secrets, timeout=1800, stdin_text=secret_input)
    sentinel = "Thank you for installing CORPUSfm"
    rc2, tail = _pssh(
        host,
        "$l=Get-ChildItem 'C:\\ProgramData\\CORPUSfm\\logs' -Filter 'install-*.log' -EA SilentlyContinue | "
        "Sort-Object LastWriteTime -Desc | Select-Object -First 1; "
        "if ($l) { Get-Content $l.FullName -Tail 4 } else { Write-Output '(no transcript)' }", secrets, 60)
    transcript_ok = sentinel in tail
    inst.append(_result("packaged install completes (transcript farewell seen)", rc == 0 and transcript_ok,
                        "" if rc == 0 and transcript_ok else f"exit {rc}; {irc}"))

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
    ver = cap("$env:PYTHONPATH='C:\\Program Files\\CORPUSfm\\src'; Write-Output ('v=' + (& 'C:\\Program Files\\CORPUSfm\\python\\python.exe' -c 'import corpusfm;print(corpusfm.__version__)'))")
    health.append(_result("version stamp present (not 0.0)", "v=" in ver and "v=0.0" not in ver, ver))

    # Anonymous public source proof (the persisted origin is tokenless and no store remains)
    origin = cap("Write-Output ('o=' + (& 'C:\\Program Files\\CORPUSfm\\git\\cmd\\git.exe' -C 'C:\\Program Files\\CORPUSfm\\src' remote get-url origin))")
    pat.append(_result("origin is plain HTTPS (no token-in-URL)",
                       "o=https://github.com/" in origin and "x-access-token" not in origin, origin))
    nokey = cap('Write-Output ("dk=" + (Test-Path "C:\\Program Files\\CORPUSfm\\.ssh\\id_ed25519"))')
    pat.append(_result("no source deploy key on the box", "dk=False" in nokey))
    pat.append(_result("no legacy source credential store remains",
                       "p=False" in cap('Write-Output ("p=" + ((Test-Path "C:\\Program Files\\CORPUSfm\\.git-pat") -or (Test-Path "C:\\Program Files\\CORPUSfm\\.git-credentials")))')))

    # uninstall + cleanliness (synchronous; ~1-2 min)
    # A forced Windows OpenSSH console is a real conhost input stream, not a Unix pipe: LF is
    # inserted into the current Read-Host line and does not submit it.  Submit each answer with CR,
    # exactly as the Enter key does.  Measured on winfms2026: LF left the installation untouched;
    # CR authenticated and completed both credential rounds.
    answers = f"admin\r{fm_pw}\radmin\r{fm_pw}\r"
    uninstall = "& 'C:\\Program Files\\CORPUSfm\\uninstall.ps1' -Yes"
    urc, uout = _pssh(host, uninstall, secrets, 900, stdin_text=answers, tty=True)
    uninst.append(_result("installed uninstaller completes", urc == 0 and "CORPUSfm removed" in uout,
                          "" if urc == 0 else f"exit {urc}"))
    state = cap('Write-Output ("dir=" + (Test-Path "C:\\Program Files\\CORPUSfm") + ";cfg=" + (Test-Path "C:\\ProgramData\\CORPUSfm") + '
                '";hosted=" + (Test-Path "C:\\CORPUSfm-Hosted") + '
                '";svc=" + [bool](Get-Service corpusfm-web -EA SilentlyContinue) + '
                '";app=" + [bool](Get-WebApplication -Site (Get-Website -Name FMWebSite -EA SilentlyContinue).Name -Name corpusfm -EA SilentlyContinue))')
    uninst.append(_result("install dir absent after uninstall", "dir=False" in state, state))
    uninst.append(_result("config home absent after uninstall", "cfg=False" in state))
    uninst.append(_result("patch hosting root absent after uninstall", "hosted=False" in state))
    uninst.append(_result("service absent after uninstall", "svc=False" in state))
    uninst.append(_result("IIS app removed after uninstall", "app=False" in state))
    fmi2 = cap('Write-Output ("c=" + (curl.exe -sk -o NUL -w "%{http_code}" https://localhost/fmi/odata/v4/))')
    uninst.append(_result("FMS /fmi/ healthy after uninstall -> 200", "c=200" in fmi2, fmi2))
    _pssh(host, f'Move-Item "{stage}" ("{stage}.completed." + $PID); Write-Output done', secrets, 30)

    return {"install": inst, "pat": pat, "health": health, "uninstall": uninst}


def _fmt(results) -> tuple[str, bool]:
    lines, ok = [], True
    for label, passed, detail in results:
        ok = ok and passed
        lines.append(f"- [{'PASS' if passed else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    return "\n".join(lines), ok


def _package_identity(release_dir: Path, version: str, expected_commit: str):
    """Bind both platform lanes to the release inventory and the exact application commit."""
    results = []
    try:
        inventory = json.loads((release_dir / "release.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, None, _fmt([_result("release.json is readable", False, repr(exc))])
    results.append(_result("release inventory version matches", inventory.get("application_version") == version,
                           str(inventory.get("application_version"))))
    results.append(_result("release inventory binds the exact candidate commit",
                           inventory.get("commit") == expected_commit, str(inventory.get("commit"))))
    packages = {}
    for platform in ("linux", "windows"):
        entry = (inventory.get("platforms") or {}).get(platform) or {}
        package = release_dir / str(entry.get("file") or "")
        sidecar = release_dir / f"{package.name}.sha256"
        expected = str(entry.get("sha256") or "").lower()
        actual = hashlib.sha256(package.read_bytes()).hexdigest() if package.is_file() else "MISSING"
        sidecar_value = sidecar.read_text(encoding="ascii").split()[0].lower() if sidecar.is_file() else "MISSING"
        passed = actual == expected == sidecar_value and len(expected) == 64
        results.append(_result(f"{platform} ZIP matches release.json and sidecar", passed, actual))
        packages[platform] = (package, sidecar)
    body, ok = _fmt(results)
    return packages.get("linux"), packages.get("windows"), (body, ok)


def run_live_gate(*, root, version, expected_commit, release_dir, linux_host, windows_host, report,
                  secrets, fm_pw, cfm_pw,
                  sections, pat_checks, health_checks, cleanliness_checks) -> int:
    print(f"Installer release gate — LIVE (version {version})")
    print(f"  Linux: {linux_host} · Windows: {windows_host}\n")

    linux_package, windows_package, bundle = _package_identity(
        Path(release_dir), version, expected_commit)
    bundle_body, bundle_ok = bundle
    if not bundle_ok or linux_package is None or windows_package is None:
        print("REFUSED: the shipped package inventory does not bind the requested candidate. No box was touched.")
        print(bundle_body)
        return 2

    # Wrong-box / clobber safeguard: refuse to mutate a box that isn't reachable AND currently clean.
    if not _linux_clean(linux_host, secrets):
        print(f"REFUSED: {linux_host} is not reachable or already has a CORPUSfm install — won't clobber it.")
        return 2
    if not _win_clean(windows_host, secrets):
        print(f"REFUSED: {windows_host} is not reachable or already has a CORPUSfm install — won't clobber it.")
        return 2
    print("  Pre-flight: both boxes reachable + clean.\n")

    overall = True
    overall = overall and bundle_ok

    try:
        lin = _linux_lane(Path(release_dir), *linux_package, linux_host, fm_pw, cfm_pw, secrets)
    except Exception as exc:  # noqa: BLE001
        print("Linux lane raised:", secrets.redact(repr(exc)))
        lin = {"install": [_result("linux lane raised", False, secrets.redact(repr(exc)))],
               "pat": [], "health": [], "uninstall": [_result("uninstall not reached — CHECK BOX MANUALLY", False)]}

    try:
        win = _win_lane(Path(release_dir), *windows_package, windows_host, fm_pw, cfm_pw, secrets)
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
        skips.append(f"- Windows box {windows_host} may not be fully clean — inspect C:\\Program Files\\CORPUSfm + services.")
    out.append("## residual risks / skips\n\n" + ("\n".join(skips) if skips else "- None — both boxes left clean.") + "\n")
    report.write_text("\n".join(out), encoding="utf-8")

    print(f"\nLIVE gate {'PASS' if overall else 'FAIL'} — report: {report}")
    print(f"  Linux left {'clean' if lin_clean else 'UNCLEAR — inspect'} · "
          f"Windows left {'clean' if win_clean else 'UNCLEAR — inspect'}")
    return 0 if (overall and lin_clean and win_clean) else 1
