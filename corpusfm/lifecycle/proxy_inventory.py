"""What proxy fronts this box actually has — discovery only (packet 1246-06 §5, §6.2).

**This module observes. It decides nothing and mutates nothing.** That separation is the packet's,
and it is load-bearing: the helper this replaces resolved a single `front` by probing `:443` and then
acted on it, so "which front is serving" and "which fronts exist" were one answer. They are not, and
collapsing them is how a dormant-but-installed Apache became invisible.

**Two rules this module exists to enforce:**

**Detection is bounded to the VERIFIED FMS ROOT.** A system Apache or nginx is never detected and
never edited. The old probe — ``ss -ltnp | grep -E ':443 .*(httpd|apache2)'`` — matches *any* listener
on the box, and the old validator resolved ``command -v apachectl``, which finds a system binary. Under
"configure every installed front" that stops being an edge case and becomes the normal one, so
ownership is decided by PATH under the FMS root, never by what happens to hold a port.

**`installed` and `active` are separate, and `active=None` is not `False`.** `None` means *cannot be
determined* — an honest third answer that a boolean cannot carry.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path

from .schema import PROXY_TYPES

# ── the four types, as PATHS under a verified FMS root ────────────────────────────────────────
#
# Every one of these is relative to the FMS root the caller verified. Nothing here is an absolute
# system path, which is the mechanical form of "a system Apache is never detected".
FMS_NGINX_CONF = ("NginxServer", "conf", "fms_nginx.conf")
FMS_APACHE_CONF = ("HTTPServer", "conf", "extra", "httpd-proxy.conf")
FMS_APACHE_BIN = ("HTTPServer", "bin", "httpd")
FMS_NGINX_BIN = ("NginxServer", "nginx")

CORPUSFM_INCLUDE_NAME = "corpusfm_https.conf"
MARKER = "CORPUSFM"

# The owned-block states. `drifted` and `invalid` are distinct on purpose: the first is an edit we can
# see and describe, the second is a marker structure we refuse to reason about at all.
BLOCK_ABSENT = "absent"
BLOCK_CURRENT = "current"
BLOCK_DRIFTED = "drifted"
BLOCK_INVALID = "invalid"
OWNED_BLOCK_STATES: tuple[str, ...] = (BLOCK_ABSENT, BLOCK_CURRENT, BLOCK_DRIFTED, BLOCK_INVALID)


@dataclass(frozen=True)
class ProxyObservation:
    """One front, as observed. A value: it carries no decision and no permission."""

    proxy_type: str
    installed: bool
    active: bool | None                 # None = cannot be determined. NEVER coerced to False.
    config_location: str | None
    owned_block: str                    # one of OWNED_BLOCK_STATES
    detail: str = ""
    fingerprint: str | None = None      # digest of the owned block as it is on disk, when readable


@dataclass(frozen=True)
class PlatformProbe:
    """Everything this module would otherwise learn from the machine, in one injectable value.

    A seam, not an authority: production builds it from the verified FMS root and the real platform.
    It carries observations only — no path a caller could redirect a WRITE through, because this
    module performs none.
    """

    is_windows: bool
    fms_root: Path | None
    # Windows only: whether the Claris nginx front is the selected one, and whether IIS is present.
    claris_nginx_active: bool | None = None
    iis_available: bool | None = None
    iis_app_present: bool | None = None
    # Linux only: which FMS-bundled front is serving, when it can be established.
    linux_active_front: str | None = None      # "fms-nginx" | "apache" | None
    extra: dict = field(default_factory=dict)


def _marker_state(text: str) -> str:
    """EXACTLY zero markers, or EXACTLY one balanced pair. Anything else is `invalid`.

    Horizontal whitespace only, so the pattern can never consume a physical newline. This mirrors the
    Windows helper's `Get-CfmMarkerState`, and it is the reason Linux gains a refusal it did not have:
    the shell `awk` skip-toggle flips on the first marker and, with no closing marker, never flips
    back — deleting from there to end of file.
    """
    count = len(re.findall(rf"^[ \t]*#+[ \t]*{MARKER}[ \t]*$", text, flags=re.MULTILINE))
    if count == 0:
        return "none"
    if count == 2:
        return "one"
    return "invalid"


def owned_block_of(text: str) -> tuple[str, str | None]:
    """(state, block-text). `invalid` when the markers are not zero or one balanced pair."""
    state = _marker_state(text)
    if state == "invalid":
        return BLOCK_INVALID, None
    if state == "none":
        return BLOCK_ABSENT, None
    lines = text.splitlines()
    marker = re.compile(rf"^[ \t]*#+[ \t]*{MARKER}[ \t]*$")
    idx = [i for i, line in enumerate(lines) if marker.match(line)]
    return BLOCK_CURRENT, "\n".join(lines[idx[0]:idx[1] + 1])


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _observe_marked_file(proxy_type: str, conf: Path, *, active: bool | None,
                         include: Path | None = None) -> ProxyObservation:
    """A front whose CORPUSfm artifact is a marked block inside an FMS-owned config file.

    **This function does not decide DRIFT, and an earlier version's attempt to was dead code.** It
    took an `expected` rendering to compare against — but rendering belongs to the OS-native
    executors, so no caller here had one to pass, both call sites passed `None`, and
    `BLOCK_DRIFTED` was unreachable in production while a test constructed it by hand. The whole
    §4 drift rule was described and never enforced.

    Drift is decided where both facts exist: `proxy_policy.decide` compares the digest reported here
    against the `config_fingerprint` the manifest recorded for the last SUCCESSFULLY APPLIED
    rendering. That is what §4 means by *recomputed, never stored*.
    """
    text = _read(conf)
    if text is None:
        return ProxyObservation(proxy_type, installed=True, active=active,
                                config_location=str(conf), owned_block=BLOCK_ABSENT,
                                detail="config present but unreadable by this process")
    state, block = owned_block_of(text)
    return ProxyObservation(
        proxy_type, installed=True, active=active, config_location=str(conf),
        owned_block=state, fingerprint=_family_of(block, include),
        detail="" if state != BLOCK_INVALID else
        f"the ###{MARKER} markers are neither absent nor one balanced pair",
    )


def _family_of(block: str | None, include: Path | None) -> str | None:
    """The observed FAMILY digest — block, plus the include body for an nginx front (ruling 3).

    Hashing the block alone was measured wrong: an nginx marked block is one `include` directive
    naming a path, and the prefix, the port and every MCP metadata route live in the include BODY.
    An operator could rewrite the whole routing and the observed digest would not move.

    An nginx front whose include is MISSING has no family, so it has no digest — reporting the
    block's digest for a broken installation would let planning call it current.
    """
    from .proxy_render import family_digest

    if block is None:
        return None
    if include is None:
        return family_digest({"block": block})
    body = _read(include)
    if body is None:
        return None
    return family_digest({"block": block, "include": body})


def digest_of(text: str | None) -> str | None:
    import hashlib

    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _absent(proxy_type: str, detail: str = "") -> ProxyObservation:
    return ProxyObservation(proxy_type, installed=False, active=None, config_location=None,
                            owned_block=BLOCK_ABSENT, detail=detail)


_SS_PID = re.compile(r"pid=(\d+)")


def _ss_local_port(line: str) -> str | None:
    """The numeric local port from one ``ss -ltnp`` row, never a substring match."""
    fields = line.split()
    if len(fields) < 4:
        return None
    _address, separator, port = fields[3].rpartition(":")
    return port if separator else None


@dataclass(frozen=True)
class ListenerProcess:
    """One `:443` listener, as three bounded reads. `None` fields mean *could not be read*."""

    pid: int
    exe: Path | None
    cmdline: tuple[str, ...] | None
    ppid: int | None


def nginx_config_argument(cmdline: tuple[str, ...] | None) -> str | None:
    """The effective `nginx -c` argument, or None. **Two shapes, both measured, both handled.**

    A freshly executed process carries a proper argv vector, NUL-separated, so `-c` and its value are
    separate fields. nginx then REWRITES its own argv into one blob — measured on fms-server
    2026-08-08::

        b'nginx: master process /usr/sbin/nginx -c /opt/FileMaker/FileMaker Server/NginxServer/conf/fms_nginx.conf\x00'

    So the retitled form is a single field and the value cannot be found by splitting on whitespace:
    **the real configuration path contains a space** (`FileMaker Server`). It is taken as everything
    after the LAST `" -c "`, which is safe because the caller compares the result to one exact path —
    a mis-parse yields a non-matching string and therefore *unknown*, never a false match.

    Text here is DATA. Nothing read from another process's memory is executed, expanded, globbed or
    passed to a shell.
    """
    if not cmdline:
        return None
    fields = [f for f in cmdline if f]
    for index, field_text in enumerate(fields):
        if field_text == "-c" and index + 1 < len(fields):
            return fields[index + 1] or None
    for field_text in fields:
        marker = " -c "
        if marker in field_text:
            value = field_text.rsplit(marker, 1)[1].strip()
            return value or None
    return None


def _canonical_text(path: str) -> str:
    """Normalised, WITHOUT touching the filesystem. `..` collapses; symlinks are not followed.

    Resolution is deliberately not used: this compares an argument another process was started with,
    which may name a path this process cannot stat, and a failed stat must not become a match.
    """
    return os.path.normpath(path)


def attribute_listener(proc: ListenerProcess, root: Path) -> str | None:
    """Which FMS front this one process proves, or None when it proves nothing.

    **The containment rule alone is wrong on Linux, and that is what this function corrects.** It
    used to require the executable to resolve canonically beneath the FMS root, on the premise that a
    system nginx "is not ours". Measured on fms-server: FileMaker Server drives the DISTRIBUTION's
    nginx —

        nginx: master process /usr/sbin/nginx -c <FMS root>/NginxServer/conf/fms_nginx.conf

    — and there is no nginx binary beneath the FMS root at all (`find … -name nginx -type f` returns
    nothing). So the premise could never hold, the active front was always unknown, and phase 17
    refused on every Linux box. The identity that actually distinguishes FMS's front from a stranger's
    is the CONFIGURATION it was started with, so that is now a second accepted proof — an exact,
    absolute one, never a prefix and never a name.
    """
    if proc.exe is None:
        return None
    name = proc.exe.name.lower()
    if "nginx" in name:
        if _within(proc.exe, root):
            return "fms-nginx"
        argument = nginx_config_argument(proc.cmdline)
        if not argument or not os.path.isabs(argument):
            return None                       # a relative -c names nothing we can verify
        expected = _canonical_text(str(Path(root, *FMS_NGINX_CONF)))
        return "fms-nginx" if _canonical_text(argument) == expected else None
    if ("httpd" in name or "apache" in name) and _within(proc.exe, root):
        # UNCHANGED. The bundled Apache really does live under the FMS root
        # (`HTTPServer/bin/httpd`), so containment is a true statement about it. Widening this to an
        # argument-based identity without evidence that a real deployment needs it would be a change
        # made on speculation.
        return "apache"
    return None


def decide_active_front(processes) -> str | None:
    """Aggregate EVERY listener before answering. First-wins would depend on `ss` output order.

    **nginx workers carry no configuration, and `ss` reports them all** — measured on fms-server, the
    six `:443` PIDs are one master whose command line names the FMS config and five workers whose
    command line is exactly `nginx: worker process`. Treating those five as "indeterminate" would make
    every real box unknown, and treating them as nothing at all would let a foreign nginx hide among
    them. So a worker corroborates its PARENT: an nginx process with a readable command line, no `-c`
    of its own, and a parent that is itself attributed, inherits that parent's answer.

    Anything else unattributed is INDETERMINATE, and indeterminate beside attributed still answers
    None — an unreadable listener is not a listener we may act on.
    """
    known = {p.pid: p for p in processes}
    attributed: dict[int, str] = {}
    unattributed = []
    for proc in processes:
        front = proc.front
        if front is not None:
            attributed[proc.pid] = front
        else:
            unattributed.append(proc)

    for proc in unattributed:
        process = proc.process
        parent_front = attributed.get(process.ppid) if process.ppid is not None else None
        inherits = (
            parent_front is not None
            and process.exe is not None
            and "nginx" in process.exe.name.lower()
            and process.cmdline is not None
            and nginx_config_argument(process.cmdline) is None
            and process.ppid in known
        )
        if not inherits:
            return None                       # indeterminate evidence beside anything else
        attributed[process.pid] = parent_front

    fronts = set(attributed.values())
    if len(fronts) != 1:
        return None                           # nothing proved, or two fronts proved at once
    return fronts.pop()


@dataclass(frozen=True)
class _Attributed:
    process: ListenerProcess
    front: str | None

    @property
    def pid(self) -> int:
        return self.process.pid


#: The Windows installer's `-FmsRoot` contract — and therefore the generation-1 manifest — records the
#: **Database Server directory**, `…\FileMaker Server\Database Server`, not the installation root.
#: Every nginx artifact lives under the ENCLOSING root: `NginxServer\conf\fms_nginx.conf` and
#: CORPUSfm's own include beside it. Reconciling those two facts is this function's whole job.
_WINDOWS_DATABASE_SERVER = "Database Server"

#: What proves a directory is the FileMaker Server installation root rather than something merely
#: named like one. Presence of either is enough; both are FMS-owned.
_FMS_ROOT_EVIDENCE = ("NginxServer", "Database Server")


def fms_installation_root(fms_root: Path | str | None) -> Path | None:
    """The ENCLOSING FileMaker Server root, from whatever the manifest recorded.

    **The manifest contract is preserved, not reinterpreted** (packet 1252): `fms_root` keeps naming
    the Database Server directory on Windows, and this derivation happens inside the proxy lifecycle —
    before inventory, before rendering, and before the executor is invoked — so nothing downstream
    has to know which of the two a caller meant.

    Why it is needed, measured on `winfms2026` 2026-08-13: with `fms_root =
    `.../FileMaker Server/Database Server`, `Path(root, "NginxServer", "conf", "fms_nginx.conf")` does
    not exist, so `_observe_claris_nginx` reported the front ABSENT — while six nginx processes were
    serving the box and IIS was stopped. The published record said `claris-nginx detected=false` and
    `iis active=true`; both were false. The installed executor builds the same path from its own
    `-FmsRoot`, so it would have denied *"no FMS nginx configuration at …"* had it been reached.

    **Evidence, never the basename.** A directory called "Database Server" proves nothing; the parent
    is accepted only when it carries an FMS-owned artifact. A root that already looks like the
    installation root is returned unchanged, so POSIX — where the manifest records the real root — is
    untouched by construction.
    """
    if fms_root is None:
        return None
    root = Path(fms_root)
    try:
        if any((root / marker).is_dir() for marker in _FMS_ROOT_EVIDENCE):
            return root                      # already the installation root (every POSIX box)
        parent = root.parent
        # The evidence must be something OTHER THAN THE CANDIDATE ITSELF. The first version accepted
        # any `…/Database Server` whose parent contained a directory named "Database Server" — which
        # is the candidate, so every lookalike adopted its parent and the check was basename-based
        # after all, the exact thing this function's docstring forbids. Caught by its own control.
        if root.name == _WINDOWS_DATABASE_SERVER and any(
                (parent / marker).is_dir() and (parent / marker) != root
                for marker in _FMS_ROOT_EVIDENCE):
            return parent
    except OSError:
        return root                          # an unreadable candidate is not a licence to guess
    return root


def linux_active_front(fms_root: Path | None, *, runner=None, exe_of=None,
                       proc_reader=None) -> str | None:
    """Which FMS-BUNDLED front is serving, or None when it cannot be established.

    `ss -ltnp` prints a process NAME and PID, never a path, so every listener is resolved through
    `/proc/<pid>/exe` and `/proc/<pid>/cmdline`. `proc_reader` is the injection point for both, at
    the boundary where the real reads happen — so the RULE is testable on a machine with no `/proc`,
    which is the only reason the correction above could be written off box at all.
    """
    if fms_root is None:
        return None
    run = runner or (lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=10))
    read = proc_reader or _read_listener
    resolve = exe_of
    try:
        proc = run(["ss", "-ltnp"])
    except Exception:
        return None

    root = Path(fms_root).resolve()
    pids: list[int] = []
    for line in (proc.stdout or "").splitlines():
        if _ss_local_port(line) != "443":
            continue
        for match in _SS_PID.finditer(line):
            pid = int(match.group(1))
            if pid not in pids:
                pids.append(pid)
    if not pids:
        return None

    observed = []
    for pid in pids:
        listener = read(pid)
        if resolve is not None:
            # BACKWARD-COMPATIBLE SEAM. `exe_of` predates this correction and several suites inject
            # it; honouring it keeps them measuring what they were written to measure.
            listener = replace(listener, exe=resolve(pid))
        observed.append(_Attributed(listener, attribute_listener(listener, root)))
    return decide_active_front(observed)


def _read_listener(pid: int) -> ListenerProcess:  # pragma: no cover - /proc is Linux-only
    """Three bounded reads for one pid. Every failure becomes None, never an exception."""
    exe = _exe_of_pid(pid)
    cmdline: tuple[str, ...] | None
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        cmdline = tuple(part.decode("utf-8", "replace") for part in raw.split(b"\x00"))
    except OSError:
        cmdline = None
    ppid = None
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("PPid:"):
                ppid = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        ppid = None
    return ListenerProcess(pid=pid, exe=exe, cmdline=cmdline, ppid=ppid)


def _exe_of_pid(pid: int) -> Path | None:  # pragma: no cover - /proc is Linux-only
    try:
        return Path(os.readlink(f"/proc/{pid}/exe")).resolve()
    except OSError:
        return None


def _within(candidate: Path, root: Path) -> bool:
    """Canonical containment. `str.startswith` would accept `/opt/FileMaker Server-evil`."""
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def inventory(*, platform_probe: PlatformProbe | None = None) -> tuple[ProxyObservation, ...]:
    """Observe every supported type. Never mutates, never decides, never raises for absence."""
    probe = platform_probe or _real_probe()
    root = probe.fms_root
    out: list[ProxyObservation] = []

    if probe.is_windows:
        out.append(_observe_iis(probe))
        out.append(_observe_claris_nginx(probe))
        out.append(_absent("fms-nginx", "Linux-only front"))
        out.append(_absent("apache", "Linux-only front"))
    else:
        out.append(_observe_linux(probe, "fms-nginx", FMS_NGINX_CONF))
        out.append(_observe_linux(probe, "apache", FMS_APACHE_CONF))
        out.append(_absent("iis", "Windows-only front"))
        out.append(_absent("claris-nginx", "Windows-only front"))

    by_type = {o.proxy_type: o for o in out}
    assert set(by_type) == set(PROXY_TYPES), by_type       # every supported type is answered for
    return tuple(by_type[t] for t in PROXY_TYPES)


def _observe_linux(probe: PlatformProbe, proxy_type: str, rel: tuple[str, ...]) -> ProxyObservation:
    root = probe.fms_root
    if root is None:
        return _absent(proxy_type, "no verified FileMaker Server root")
    conf = Path(root, *rel)
    if not conf.is_file():
        return _absent(proxy_type, f"no FMS-bundled config at {conf}")
    front = probe.linux_active_front
    active = None if front is None else (front == proxy_type)
    include = Path(root, "NginxServer", "conf", CORPUSFM_INCLUDE_NAME) \
        if proxy_type == "fms-nginx" else None
    return _observe_marked_file(proxy_type, conf, active=active, include=include)


def _observe_iis(probe: PlatformProbe) -> ProxyObservation:
    """`iis` is CORPUSfm's OWN application, pool and routing artifacts — not IIS itself.

    So `installed` asks whether IIS is available to host them, and the owned block is whether our
    application is mounted. CORPUSfm never claims ownership of IIS, only of what it mounted there.
    """
    if probe.iis_available is None:
        # UNKNOWN is not ABSENT (ruling 3). `installed=True, active=None` is the honest reading:
        # something may be there and we could not establish it, which the policy layer turns into a
        # refusal rather than a silent skip. Reporting it absent would let a reconcile pass over a
        # live IIS front reporting success.
        return ProxyObservation("iis", installed=True, active=None, config_location=None,
                                owned_block=BLOCK_ABSENT,
                                detail="IIS availability could not be established")
    if not probe.iis_available:
        return _absent("iis", "IIS is not available on this machine")
    present = probe.iis_app_present
    if present is None:
        return ProxyObservation("iis", installed=True, active=None, config_location=None,
                                owned_block=BLOCK_ABSENT,
                                detail="the CORPUSfm IIS application family is partially present or "
                                       "could not be read")
    return ProxyObservation(
        "iis", installed=True,
        # IIS hosts the isolated application the moment it is mounted; it is "active" whenever the
        # Claris nginx front is NOT the selected one (that front bypasses the IIS apps).
        active=(None if probe.claris_nginx_active is None else not probe.claris_nginx_active),
        config_location=str(probe.extra.get("iis_app_path") or "") or None,
        owned_block=(BLOCK_CURRENT if present else BLOCK_ABSENT),
        # The observed FAMILY digest the probe read back: pool, every application definition with
        # its physical path and pool assignment, and every owned web.config (ruling 3). Without it
        # an IIS observation carried no fingerprint at all, so drift there was undetectable.
        fingerprint=(probe.extra.get("iis_fingerprint") if present else None),
        detail="" if present else "the CORPUSfm IIS application is not mounted",
    )


def _observe_claris_nginx(probe: PlatformProbe) -> ProxyObservation:
    root = probe.fms_root
    if root is None:
        return _absent("claris-nginx", "no verified FileMaker Server root")
    conf = Path(root, *FMS_NGINX_CONF)
    installed = probe.extra.get("claris_installed")
    if installed is None and not conf.is_file():
        return _absent("claris-nginx", "FMS does not ship an nginx front on this machine")
    if installed is False:
        return _absent("claris-nginx", "FMS does not ship an nginx front on this machine")
    # The Windows probe reports the family digest it read back; when it could not, fall back to
    # reading the two files here — the include is part of the family either way.
    reported = probe.extra.get("claris_fingerprint")
    observation = _observe_marked_file(
        "claris-nginx", conf, active=probe.claris_nginx_active,
        include=Path(root, "NginxServer", "conf", CORPUSFM_INCLUDE_NAME))
    if reported:
        observation = replace(observation, fingerprint=reported)
    return observation


def windows_probe(root: Path | None, *, prefix: str, iis_app_dir, metadata_dir,
                  runner=None, script=None) -> dict:
    """Read-only Windows observation, delegated to the executor's `probe` verb (ruling 2).

    **Why this exists at all.** The production Windows probe used to be
    `PlatformProbe(is_windows=True, fms_root=root)` and nothing else, so every Windows field stayed
    `None` — and `None` is falsy. Measured consequence: `iis.installed` was always False, so IIS
    could never be configured; and `mechanism_for` read `MECH_UNAVAILABLE if obs.active else
    MECH_NONE`, so an ACTIVE Claris nginx front resolved to `none` and §6.4's refusal never fired in
    production. The whole rail was proven against injected observations and never against the thing
    that produces them — the same defect as the unreachable drift state, one layer down.

    The detection itself lives in the PowerShell executor because that is where the Windows tools
    are (`appcmd.exe`, `Get-NetTCPConnection`), addressed absolutely. This function is the seam that
    carries its answer back, and every field it cannot establish stays `None`.
    """
    import json
    import subprocess as sp

    if root is None or script is None:
        return {}
    # No -ExecutionPolicy Bypass (packet 1380-02 D20): the executor is an installed local file with
    # no Mark of the Web, which RemoteSigned permits unaided, and under AllSigned the organization's
    # deployed publisher leaf is what admits it. CORPUSfm never overrides execution policy.
    argv = ["powershell", "-NoProfile", "-File", str(script),
            "-Verb", "probe", "-Type", "iis", "-FmsRoot", str(root), "-Prefix", prefix,
            "-IisAppDir", str(iis_app_dir or ""), "-MetadataDir", str(metadata_dir or "")]
    run = runner or (lambda a: sp.run(a, capture_output=True, text=True, timeout=120))
    try:
        proc = run(argv)
    except Exception:
        return {}                       # unreadable -> every field stays UNKNOWN
    for line in reversed((proc.stdout or "").strip().splitlines()):
        try:
            answer = json.loads(line)
        except ValueError:
            continue
        if isinstance(answer, dict):
            return answer
    return {}


def probe_from_windows_report(root: Path | None, report: dict) -> PlatformProbe:
    """Turn the executor's read-only report into a `PlatformProbe`, preserving every UNKNOWN.

    `report.get(k)` returning `None` — the key absent, or explicitly null — must stay `None`. That
    is the whole of ruling 3's premise: an unknown activation state is not an inactive one.
    """
    return PlatformProbe(
        is_windows=True, fms_root=root,
        claris_nginx_active=report.get("claris_active"),
        iis_available=report.get("iis_available"),
        iis_app_present=report.get("iis_apps_present"),
        extra={"selected_front": report.get("selected_front"),
               "claris_installed": report.get("claris_installed"),
               "iis_fingerprint": report.get("iis_fingerprint"),
               "iis_app_path": report.get("iis_app_path"),
               "claris_fingerprint": report.get("claris_fingerprint")},
    )


def _real_probe(*, prefix: str = "/corpusfm", iis_app_dir=None, metadata_dir=None,
                script=None, fms_root=None) -> PlatformProbe:
    """The real machine, assembled from the AUTHORITATIVE FMS root and platform observation.

    `fms_root` is supplied by the caller — from the integrator's request or the published manifest
    (ruling 1). `_verified_fms_root()` remains only as the last resort for a caller that genuinely
    has none, and no authority path takes it.
    """
    is_windows = os.name == "nt"
    fms_root = fms_installation_root(fms_root)
    if not fms_root:
        # NO FALLBACK (ruling 8). `_verified_fms_root()` guesses at two hard-coded locations, and an
        # authority caller that cannot say where FileMaker Server is has not established enough to
        # observe it — let alone to change it. `_verified_fms_root` survives only for the
        # unprivileged, best-effort case that has no caller in this component.
        raise ValueError(
            "a verified FileMaker Server root is required to observe this machine; it comes from "
            "the integrator's request or the published manifest, and is never discovered")
    root = Path(fms_root)
    if is_windows:
        return probe_from_windows_report(
            root, windows_probe(root, prefix=prefix, iis_app_dir=iis_app_dir,
                                metadata_dir=metadata_dir, script=script))
    return PlatformProbe(is_windows=False, fms_root=root,
                         linux_active_front=linux_active_front(root))


def _verified_fms_root() -> Path | None:  # pragma: no cover - platform-specific
    """The FMS root, verified by the presence of an FMS-owned artifact under it.

    A path that merely exists is not a verified root: the point of this function is that everything
    downstream is confined to what it returns.
    """
    candidates = [Path("/opt/FileMaker/FileMaker Server"),
                  Path(r"C:\Program Files\FileMaker\FileMaker Server")]
    for cand in candidates:
        if (cand / "Database Server").is_dir() or (cand / "NginxServer").is_dir():
            return cand
    return None


__all__ = [
    "BLOCK_ABSENT", "BLOCK_CURRENT", "BLOCK_DRIFTED", "BLOCK_INVALID", "OWNED_BLOCK_STATES",
    "ListenerProcess", "PlatformProbe", "ProxyObservation", "attribute_listener",
    "decide_active_front", "digest_of", "fms_installation_root", "inventory", "linux_active_front",
    "nginx_config_argument",
    "owned_block_of", "probe_from_windows_report", "windows_probe",
]
