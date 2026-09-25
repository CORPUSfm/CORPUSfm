"""Production-shaped walks over the requests BOTH installers actually generate (1246-04-04, H).

**Why this module exists.** Every earlier installer test read the scripts as text. A text test can
say "the request names `expected_generation`"; it cannot say whether the shipped parser would accept
the document the script builds. It did not — *every one of the seven provider requests was refused
by the shipped schemas* (finding B3), while the guards were green. So this module does not read the
installers for strings. It **runs their request builders** in the real shell, takes the JSON they
emit, and feeds that JSON to the **real production parser** for the verb it was built for.

**What is real here, and what is a double — stated exactly, because the distinction is the evidence.**

* REAL: the installer's own builder text, executed by `bash` / `pwsh`; the shipped request parsers
  (`cli._REQUEST_KEYS` path, `_px_read_request`, `_ai_read_request`, `_st_read_request`,
  `_co_read_request`) with their key, value, mode, transport and canonical-path rules; the shipped
  exit-code maps; the shipped journal/subsystem vocabulary.
* DOUBLED: the OS and FileMaker effects the installer would have — `lc_run` / `Lc-Run` never invoke
  the CLI here, `_stat_refusal` is neutralised because a test does not run as root, and no service,
  scheduled task, DACL, listener, systemd unit or FileMaker Server is touched.

**This claims fixture/policy-through-doubles evidence and nothing more.** No live systemd, IIS, DACL,
FileMaker, listener, scheduled-task or recovery execution is claimed or performed.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from corpusfm.lifecycle import cli
from application_checkout import APPLICATION_ROOT

REPO = Path(__file__).resolve().parents[1]
SH = REPO / "installer" / "linux" / "install.sh"
PS1 = REPO / "installer" / "windows" / "install.ps1"

INST = "3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"
OP = "8c7b6a55-4d3e-4f21-9a80-1b2c3d4e5f60"

pwsh = shutil.which("pwsh") or shutil.which("powershell")
needs_pwsh = pytest.mark.skipif(pwsh is None, reason="no PowerShell on this host")


@pytest.fixture
def unroot(monkeypatch):
    """A privileged request must be root-owned and a test suite does not run as root.

    ONLY the ownership predicate is neutralised — the rule itself is exercised directly below, so it
    keeps a test of its own while these reach the schema.
    """
    monkeypatch.setattr(cli, "_stat_refusal", lambda st, what: None)


def test_the_ownership_rule_this_module_neutralises_still_refuses():
    class NotRoot:
        st_uid = 501
        st_mode = 0o600

    assert "root-owned" in (cli._stat_refusal(NotRoot(), "/etc/req.json") or "")


def write_request(tmp_path, body, name="request.json"):
    p = tmp_path / name
    p.write_text(json.dumps(body))
    os.chmod(p, 0o600)
    return p


# ── extracting the shipped builders, and running them ─────────────────────────────────


def _bash_function(source: str, name: str) -> str:
    """One shell function, verbatim, from `^name() {` to the `}` in column 0 that closes it."""
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", source, re.S | re.M)
    assert match, f"{name} is not defined in install.sh"
    return match.group(0)



def _must_substitute(text: str, old: str, new: str) -> str:
    """Replace, and REFUSE if the target was not there.

    The harness swaps the installer's real lifecycle invocation for a probe. When the entry-point
    spelling moved from `corpusfm.lifecycle.cli` to `corpusfm.lifecycle` (packet 1246-10-04), a
    silent `str.replace` stopped matching and these tests began exercising the REAL module — which
    is how a deadlock guard ends up measuring nothing.
    """
    if old not in text:
        raise AssertionError(f"the harness no longer finds {old!r} to substitute")
    return text.replace(old, new)

def _ps_function(source: str, name: str) -> str:
    r"""One PowerShell function, verbatim, ended by BRACE COUNTING.

    Not by a line-anchored closing brace. `Lc-Json` is a one-liner whose closing brace is not on a line of its own, so a
    line-anchored pattern ran past it and swallowed the next twenty lines — including
    `$script:CfmConfigDir = ''`, which then BLANKED the values the caller had set. The Windows
    requests came out carrying empty `secrets_dir` and `storage_dirs`, passed the real parsers on
    the strength of key membership, and satisfied a truthiness assertion with a list of empty
    strings. The harness was proving less than it reported, which is the one failure a walk of this
    kind must not have.
    """
    start = re.search(rf"^function {re.escape(name)}\b", source, re.M)
    assert start, f"{name} is not defined in install.ps1"
    i = source.index("{", start.start())
    depth = 0
    for j in range(i, len(source)):
        if source[j] == "{":
            depth += 1
        elif source[j] == "}":
            depth -= 1
            if depth == 0:
                return source[start.start():j + 1]
    raise AssertionError(f"{name} is never closed")


def test_the_powershell_extractor_stops_at_the_functions_own_closing_brace():
    """The control for the helper above — a one-liner and a multi-liner, both bounded exactly."""
    source = PS1.read_text(encoding="ascii")
    one_liner = _ps_function(source, "Lc-Json")
    assert one_liner.count("\n") == 0, f"the one-liner capture ran on: {one_liner[:120]!r}"
    assert "$script:CfmConfigDir" not in one_liner
    multi = _ps_function(source, "Lc-PatchRequest")
    assert multi.startswith("function Lc-PatchRequest") and multi.rstrip().endswith("}")
    assert "function Lc-ProxyRequest" not in multi


#: The values the installer would hold at phase 14. Every one is a fact it classified earlier, and
#: the OS directories are the real `posix_os_layout()` / `windows_os_layout()` answers.
LINUX_WORLD = {
    "INSTALLATION_ID": INST,
    "INSTALL_DIR": "/opt/CORPUSfm",
    "FMS_ROOT": "/opt/FileMaker/FileMaker Server",
    "FM_DB_DIR": "/opt/FileMaker/FileMaker Server/Data/Databases",
    "HOSTING_DIR": "/opt/CORPUSfm-Hosted",
    "SERVICE_USER": "corpusfm",
    "FMS_SERVICE_USER": "fmserver",
    "CFM_FMS_HOST": "localhost",
    "WEB_PORT": "8533",
    "WEB_PREFIX": "/corpusfm",
    "CFM_CONFIG_DIR": "/etc/corpusfm",
    "CFM_STATE_DIR": "/var/lib/corpusfm/state",
    "CFM_SECRETS_DIR": "/var/lib/corpusfm/secrets",
    "CFM_LOG_DIR": "/var/log/corpusfm",
    "CFM_RUN_DIR": "/run/corpusfm",
    # The installer-owned asset tree beside the checkout (packet 1257). Both platforms carry the
    # same directory name, and `app_paths.ASSETS_DIRNAME` must agree with it.
    "CFM_ASSETS_DIRNAME": "assets",
    # A VERIFIED FMS ADMINISTRATOR IS HELD, which is what phase 7 establishes before phase 16 runs.
    # `lc_fms_transport` therefore answers `stdin`; the `absent` half is exercised separately.
    "FM_ADMIN_USER": "admin",
    "FM_ADMIN_PASS": "held-not-sent",
}

WINDOWS_WORLD = {
    "InstallationId": INST,
    "InstallDir": r"C:\Program Files\CORPUSfm",
    "FmsBin": r"C:\Program Files\FileMaker\FileMaker Server",
    "FmDbDir": r"C:\Program Files\FileMaker\FileMaker Server\Data\Databases",
    "PatchHostingDir": r"C:\CORPUSfm-Hosted",
    "Src": r"C:\Program Files\CORPUSfm\src",
    "WebServiceAccount": r"NT SERVICE\corpusfm-web",
    "FmsServiceAccount": r"NT AUTHORITY\SYSTEM",
    "CfmFmsHost": "localhost",
    "WebPort": "8533",
    "WebPrefix": "/corpusfm",
    "CfmConfigDir": r"C:\ProgramData\CORPUSfm\config",
    "CfmStateDir": r"C:\ProgramData\CORPUSfm\state",
    "CfmSecretsDir": r"C:\ProgramData\CORPUSfm\secrets",
    "CfmLogDir": r"C:\ProgramData\CORPUSfm\logs",
    "CfmRunDir": r"C:\ProgramData\CORPUSfm\run",
    "CfmAssetsDirName": "assets",
    "FmAdminUser": "admin",
    "FmAdminPass": "held-not-sent",
}


def linux_request(builder_call: str, *, generation: int = 1, mode: str = "fresh_install",
                  extra: str = "") -> dict:
    """Run one of `install.sh`'s own request builders and return what it emitted, parsed."""
    source = SH.read_text(encoding="utf-8")
    preamble = "\n".join(f'{k}="{v}"' for k, v in LINUX_WORLD.items())
    script = "\n".join([
        "set -euo pipefail",
        preamble,
        f'CFM_GENERATION={generation}',
        f'CFM_MODE="{mode}"',
        f'CFM_STORAGE_MODE="{mode}"',
        "CFM_PROXY_TYPES=(fms-nginx apache)",
        extra,
        _bash_function(source, "lc_fms_transport"),
        _bash_function(source, "lc_json_array"),
        _bash_function(source, "lc_patch_request"),
        _bash_function(source, "lc_proxy_request"),
        _bash_function(source, "lc_admin_identity_request"),
        _bash_function(source, "lc_storage_request"),
        builder_call,
    ])
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def windows_request(builder_call: str, tmp_path, *, generation: int = 1,
                    mode: str = "fresh_install") -> dict:
    """Run one of `install.ps1`'s own request builders and return what it emitted, parsed.

    Executed from a real .ps1 FILE, not `-Command`. The builders read `$script:InstallDir` and
    friends, which is what production's top-level assignments populate; `-Command` has no script
    scope to populate, so every one of those reads came back empty and the exercise proved nothing
    about the builder. Writing a file makes the scope the same one production has.
    """
    source = PS1.read_text(encoding="ascii")
    preamble = "\n".join(f"${k} = '{v}'" for k, v in WINDOWS_WORLD.items())
    script = "\n".join([
        preamble,
        f"$CfmGeneration = {generation}",
        f"$CfmMode = '{mode}'",
        "$CfmProxyTypes = @('iis','claris-nginx')",
        _ps_function(source, "Lc-Json"),
        _ps_function(source, "Lc-FmsTransport"),
        _ps_function(source, "Lc-PatchRequest"),
        _ps_function(source, "Lc-ProxyRequest"),
        _ps_function(source, "Lc-AdminIdentityRequest"),
        _ps_function(source, "Lc-StorageRequest"),
        builder_call,
    ])
    probe = tmp_path / "builder.ps1"
    probe.write_text(script, encoding="ascii")
    out = subprocess.run([pwsh, "-NoProfile", "-File", str(probe)],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_patch_apply_receives_the_classified_mode_on_both_platforms():
    linux = SH.read_text(encoding="utf-8")
    windows = PS1.read_text(encoding="ascii")
    linux_call = next(line for line in linux.splitlines()
                      if 'lc_provider_run "patch compartment apply"' in line)
    linux_tail = linux[linux.index(linux_call):linux.index(linux_call) + 220]
    assert '--mode "$CFM_MODE"' in linux_tail
    windows_call = windows[windows.index('Lc-ProviderRun "patch compartment apply"'):
                           windows.index('Lc-ProviderRun "patch compartment apply"') + 260]
    assert "'--mode',$CfmMode" in windows_call


# ── every clean request passes its REAL parser ────────────────────────────────────────

LINUX_CLEAN = [
    ("patch-compartment inspect", "Lc-Json (Lc-PatchRequest)", "lc_patch_request"),
    ("proxy status", "Lc-Json (Lc-ProxyRequest 'status')", "lc_proxy_request status"),
    ("proxy reconcile", "Lc-Json (Lc-ProxyRequest 'reconcile')", "lc_proxy_request reconcile"),
    ("admin-identity observe", "Lc-Json (Lc-AdminIdentityRequest 'absent')",
     "lc_admin_identity_request absent"),
    ("admin-identity reconcile", "Lc-Json (Lc-AdminIdentityRequest 'prompt')",
     "lc_admin_identity_request prompt"),
    ("storage observe", "Lc-Json (Lc-StorageRequest $CfmMode)", "lc_storage_request fresh_install"),
    ("storage bootstrap", "Lc-Json (Lc-StorageRequest $CfmMode)", "lc_storage_request fresh_install"),
]


def _parse(verb_group: str, verb: str, path: str):
    """The REAL parser for that verb group. No shared wrapper — each is a different authority."""
    if verb_group == "patch-compartment":
        return cli._read_request(path)
    if verb_group == "proxy":
        return cli._px_read_request(path, verb)
    if verb_group == "admin-identity":
        return cli._ai_read_request(path, verb)
    if verb_group == "storage":
        return cli._st_read_request(path, verb)
    return cli._co_read_request(path, verb)


@pytest.mark.parametrize("label,_ps,sh_call", LINUX_CLEAN, ids=[c[0] for c in LINUX_CLEAN])
def test_every_LINUX_request_passes_its_real_production_parser(unroot, tmp_path, label, _ps, sh_call):
    group, verb = label.split(" ", 1)
    body = linux_request(sh_call)
    parsed = _parse(group, verb, str(write_request(tmp_path, body)))
    assert parsed is not None


#: THREE WINDOWS REQUESTS CANNOT BE PARSED END TO END ON A POSIX HOST, and the reason is the host,
#: not the builder. `os.path.isabs(r"C:\\Program Files\\CORPUSfm")` is False here and True on Windows,
#: so `_px_read_request`'s absolute-path rule refuses a value that is correct on the target; and
#: `Join-Path` on a `C:` path raises *"A drive with the name 'C' does not exist"* under pwsh on macOS,
#: so `seed` comes back null. For these three, KEY-SET and platform-neutral VALUE conformance is
#: proven and the path rules are proven on Linux only. **Stated rather than papered over: this is not
#: claimed as end-to-end Windows evidence.**
_WINDOWS_HOST_LIMITED = {"patch-compartment inspect", "proxy status", "proxy reconcile"}


@needs_pwsh
@pytest.mark.parametrize("label,ps_call,_sh", LINUX_CLEAN, ids=[c[0] for c in LINUX_CLEAN])
def test_every_WINDOWS_request_passes_its_real_production_parser(unroot, tmp_path, label,
                                                                 ps_call, _sh):
    group, verb = label.split(" ", 1)
    body = windows_request(ps_call, tmp_path)
    if label in _WINDOWS_HOST_LIMITED:
        if group == "proxy":
            assert set(body) == set(cli._PX_REQUEST_KEYS[verb])
            assert body["mcp_metadata"] is True and body["port"] == 8533
            assert body["prefix"] == WINDOWS_WORLD["WebPrefix"]
            assert body["install_dir"] == WINDOWS_WORLD["InstallDir"]
            assert body["types"] and all(x in ("iis", "claris-nginx") for x in body["types"])
        else:
            assert set(body) == set(cli._REQUEST_KEYS)
            assert body["flavour"] == "windows"
            for which in ("service_identity", "fms_identity"):
                assert set(body[which]) == {"flavour", "account", "role"}
            assert body["storage_dirs"] == [WINDOWS_WORLD["CfmStateDir"],
                                            WINDOWS_WORLD["CfmSecretsDir"]]
            assert body["protected_dirs"] == [WINDOWS_WORLD["CfmConfigDir"],
                                              WINDOWS_WORLD["CfmLogDir"],
                                              WINDOWS_WORLD["CfmRunDir"]]
            assert body["install_dir"] == WINDOWS_WORLD["InstallDir"]
            assert body["fms_root"] == WINDOWS_WORLD["FmsBin"]
            assert body["requested"] == WINDOWS_WORLD["PatchHostingDir"]
            assert body["fms_database_dir"] == WINDOWS_WORLD["FmDbDir"]
        return
    for key, expected in (("secrets_dir", WINDOWS_WORLD["CfmSecretsDir"]),
                          ("install_dir", WINDOWS_WORLD["InstallDir"]),
                          ("host", WINDOWS_WORLD["CfmFmsHost"])):
        if key in body:
            assert body[key] == expected, f"{key} came back {body[key]!r}"
    parsed = _parse(group, verb, str(write_request(tmp_path, body)))
    assert parsed is not None


def test_the_two_platforms_build_the_SAME_KEY_SETS(tmp_path):
    """Same contract, two languages. A key present on one platform and absent on the other is a
    divergence no per-platform test could see, because each is green against its own script."""
    if pwsh is None:
        pytest.skip("no PowerShell on this host")
    for _label, ps_call, sh_call in LINUX_CLEAN:
        assert set(linux_request(sh_call)) == set(windows_request(ps_call, tmp_path)), _label


# ── the adversaries: missing, extra and inapplicable keys ─────────────────────────────


def test_a_MISSING_key_refuses(unroot, tmp_path):
    body = linux_request("lc_storage_request fresh_install")
    del body["secrets_dir"]
    with pytest.raises(cli._RequestRefused, match="missing"):
        cli._st_read_request(str(write_request(tmp_path, body)), "observe")


def test_an_EXTRA_key_refuses(unroot, tmp_path):
    body = linux_request("lc_proxy_request reconcile")
    body["operation_id"] = OP
    with pytest.raises(cli._RequestRefused, match="does not accept"):
        cli._px_read_request(str(write_request(tmp_path, body)), "reconcile")


@pytest.mark.parametrize("verb,call,group", [
    ("status", "lc_proxy_request reconcile", "proxy"),
    ("finalize", "lc_proxy_request status", "proxy"),
    ("finalize", "lc_admin_identity_request absent", "admin-identity"),
    ("finalize", "lc_storage_request fresh_install", "storage"),
])
def test_a_request_built_for_ANOTHER_VERB_refuses(unroot, tmp_path, verb, call, group):
    """The inapplicable-key adversary. Every one of these documents is a VALID request — for a
    different verb. That is exactly the mistake the installers were making."""
    body = linux_request(call)
    with pytest.raises(cli._RequestRefused):
        _parse(group, verb, str(write_request(tmp_path, body)))


def test_the_FINALIZE_requests_carry_committed_generation_and_no_path_or_generation_alias(unroot,
                                                                                          tmp_path):
    """All three finalizes take `actor · committed_generation · installation_id · operation_id ·
    schema_version`. The installers sent `generation` and `install_dir`, which are refused twice
    over — one unknown key and one missing key."""
    good = {"schema_version": 1, "operation_id": OP, "installation_id": INST,
            "committed_generation": 3, "actor": "installer"}
    for group, verb in (("proxy", "finalize"), ("admin-identity", "finalize"),
                        ("storage", "finalize")):
        assert _parse(group, verb, str(write_request(tmp_path, good)))
    for alias in ("generation", "install_dir"):
        bad = dict(good)
        bad.pop("committed_generation")
        bad[alias] = 3 if alias == "generation" else "/opt/CORPUSfm"
        with pytest.raises(cli._RequestRefused):
            cli._px_read_request(str(write_request(tmp_path, bad)), "finalize")


def test_committed_generation_of_ZERO_refuses(unroot, tmp_path):
    """`finalize` proves a manifest WAS written, and a written manifest is at least generation 1."""
    body = {"schema_version": 1, "operation_id": OP, "installation_id": INST,
            "committed_generation": 0, "actor": "installer"}
    with pytest.raises(cli._RequestRefused, match="positive"):
        cli._st_read_request(str(write_request(tmp_path, body)), "finalize")


def test_the_DISCARD_request_both_installers_build_passes_the_real_parser(unroot, tmp_path):
    """Correction A's boundary, reached from a shell. Until it existed there was no verb that
    retired a journal record, and both installers CLAIMED to have done it."""
    body = {"schema_version": 1, "provider": "storage", "operation_id": OP,
            "installation_id": INST, "actor": "installer"}
    assert cli._co_read_request(str(write_request(tmp_path, body)), "discard-provider") == body
    for alias in ("install_dir", "generation", "candidate"):
        bad = {**body, alias: 1}
        with pytest.raises(cli._RequestRefused):
            cli._co_read_request(str(write_request(tmp_path, bad)), "discard-provider")


# ── value rules the parsers enforce beyond key membership ─────────────────────────────


def test_the_proxy_request_names_no_type_this_platform_cannot_have(unroot, tmp_path):
    """`inventory()` answers `iis` / `claris-nginx` as `Windows-only front` and `fms-nginx` /
    `apache` as `Linux-only front`. Asking a box about a front it structurally cannot present is a
    question with no honest answer."""
    assert set(linux_request("lc_proxy_request reconcile")["types"]) == {"fms-nginx", "apache"}
    if pwsh is not None:
        assert set(windows_request("Lc-Json (Lc-ProxyRequest 'reconcile')", tmp_path)["types"]) == {
            "iis", "claris-nginx"}


def test_ALL_is_never_a_request_value(unroot, tmp_path):
    body = linux_request("lc_proxy_request reconcile")
    body["types"] = ["all"]
    with pytest.raises(cli._RequestRefused, match="PUBLIC selector"):
        cli._px_read_request(str(write_request(tmp_path, body)), "reconcile")


def test_mcp_metadata_is_exactly_true(unroot, tmp_path):
    assert linux_request("lc_proxy_request reconcile")["mcp_metadata"] is True
    body = linux_request("lc_proxy_request reconcile")
    body["mcp_metadata"] = False
    with pytest.raises(cli._RequestRefused, match="exactly true"):
        cli._px_read_request(str(write_request(tmp_path, body)), "reconcile")


def test_the_repair_option_selects_a_MODE_THE_PARSER_ACCEPTS(unroot, tmp_path):
    """G. `--repair-storage-access` / `-RepairStorageAccess` set a variable nothing read.
    `repair_storage_access` is a real member of `storage_identity.MODES`, so the option now drives a
    mode the shipped parser accepts — and `repair` is a real verb."""
    from corpusfm.lifecycle.storage_identity import MODES

    assert "repair_storage_access" in MODES
    body = linux_request("lc_storage_request repair_storage_access")
    assert body["mode"] == "repair_storage_access"
    assert cli._st_read_request(str(write_request(tmp_path, body)), "repair")


def test_admin_identity_has_NO_repair_mode_and_refuses_one(unroot, tmp_path):
    """The two providers' mode sets are genuinely different, and the installer must not send storage's
    repair mode to admin-identity just because one option is set."""
    body = linux_request("lc_admin_identity_request absent", mode="repair_storage_access")
    with pytest.raises(cli._RequestRefused, match="mode must be one of"):
        cli._ai_read_request(str(write_request(tmp_path, body)), "observe")


@pytest.mark.parametrize("transport", ["absent", "prompt", "stdin", "fd:7"])
def test_the_credential_is_a_TRANSPORT_TOKEN_and_a_value_refuses(unroot, tmp_path, transport):
    body = linux_request(f"lc_admin_identity_request {transport}")
    assert cli._ai_read_request(str(write_request(tmp_path, body)), "observe")
    body["credential_input"] = "hunter2"
    with pytest.raises(cli._RequestRefused, match="credential_input must be"):
        cli._ai_read_request(str(write_request(tmp_path, body)), "observe")


def test_NO_REQUEST_ANY_INSTALLER_BUILDS_CARRIES_A_CREDENTIAL_VALUE():
    """The blanket property. Every generated request is scanned for a value that is not one of the
    four transports, under any key whose name is about a secret."""
    transports = {"absent", "prompt", "stdin"}
    #: `secrets_dir` names a DIRECTORY and is not one of these — the rule is about the two keys that
    #: carry credential AUTHORITY, and a substring scan over key names cannot tell them apart.
    carriers = {"credential_input", "admin_credential_input"}
    for _label, _ps, sh_call in LINUX_CLEAN:
        body = linux_request(sh_call)
        for key in carriers & set(body):
            value = body[key]
            assert isinstance(value, str)
            assert value in transports or value.startswith("fd:"), f"{key}={value!r}"
        # …and no OTHER key may carry a value that looks like a secret rather than a path or a fact.
        for key, value in body.items():
            if key in carriers or not isinstance(value, str):
                continue
            assert not re.search(r"(pass|pw|token|pat)\s*[:=]", value, re.I), f"{key}={value!r}"


# ── the sequence: generations, protocols, discards ────────────────────────────────────


def code(body: str) -> str:
    """The body with its COMMENTS removed.

    Load-bearing, and this project has made the mistake three times: a guard that forbids a word has
    to exclude the prose explaining why the word is forbidden, or it reports its own rationale as the
    violation. Both installers' phase 3 now carries a paragraph naming `requires_recovery` to say it
    is dead.
    """
    out = []
    for line in body.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def _phases(source: str, marker: str) -> dict:
    marks = [(int(m.group(1)), m.end()) for m in re.finditer(marker, source, re.M)]
    out = {}
    for i, (n, end) in enumerate(marks):
        stop = marks[i + 1][1] if i + 1 < len(marks) else len(source)
        out[n] = source[end:stop]
    return out


def linux_phases() -> dict:
    return _phases(SH.read_text(encoding="utf-8"), r"^# ═══ PHASE (\d+) —[^\n]*\n")


def windows_phases() -> dict:
    return _phases(PS1.read_text(encoding="ascii"), r"^# === PHASE (\d+) -[^\n]*\n")


#: THE RULED PROVIDER ORDER, phase → provider. Stated ONCE here because it moved (ruling
#: 2026-08-08: the admin identity comes first, since the patch compartment authenticates to the FMS
#: Admin API with the identity that provider publishes) and five tests in this file had hard-coded
#: the old one independently — so the reorder landed in both installers with this suite red and
#: nobody reading it. A future reorder edits this line.
RULED_ORDER = {15: "admin_identity", 16: "patch", 17: "proxy", 18: "storage"}
PHASE_OF = {provider: phase for phase, provider in RULED_ORDER.items()}
PROTOCOL_P_PHASE = PHASE_OF["patch"]
PROTOCOL_F_PHASES = tuple((PHASE_OF[p], p) for p in ("admin_identity", "proxy", "storage"))


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_PROTOCOL_P_never_finalizes(phases):
    """patch-compartment resolves its own journal entry, so there is no finalize verb to call. A
    finalize in its phase would be a request for an operation that is already resolved."""
    body = code(phases()[PROTOCOL_P_PHASE])
    assert "finalize" not in body, "the Protocol P provider finalizes"
    assert re.search(r"(lc_discard_provider|Lc-DiscardProvider)\s+'?patch", body), (
        "the Protocol P provider does not discard its journal"
    )


@pytest.mark.parametrize("phases,phase,provider", [
    (walker, phase, provider)
    for walker in (linux_phases, windows_phases)
    for phase, provider in PROTOCOL_F_PHASES
])
def test_PROTOCOL_F_finalizes_BEFORE_it_discards(phases, phase, provider):
    """The order is the protocol. A discard before the finalize would retire the record the finalize
    needs to find, and a finalize is what proves the composed candidate is the published one."""
    body = code(phases()[phase])
    fin = body.find("finalize")
    disc = max(body.find("lc_discard_provider"), body.find("Lc-DiscardProvider"))
    assert fin >= 0, f"{provider} never finalizes"
    assert disc >= 0, f"{provider} never discards its journal"
    assert fin < disc, f"{provider} discards before it finalizes"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_every_provider_DISCARDS_BEFORE_THE_NEXT_ONE_BEGINS(phases):
    """Storage answers `foreign_open` on the PRESENCE of any journal record, so a record left behind
    stops the NEXT provider before it starts. Each phase must therefore close its own."""
    body = {n: code(b) for n, b in phases().items()}
    for phase in (15, 16, 17, 18):
        assert re.search(r"(lc_discard_provider|Lc-DiscardProvider)", body[phase]), (
            f"phase {phase} leaves its journal record in place for the next provider"
        )


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_operation_id_FLOWS_FROM_THE_PROVIDER_into_commit_finalize_and_discard(phases):
    """B, stated as a property. No phase may mint an operation id: the provider does, and returns it.
    A minted id names an operation nothing has ever performed."""
    body = {n: code(b) for n, b in phases().items()}
    for phase in (15, 16, 17, 18):
        text = body[phase]
        assert "uuid" not in text.lower() and "NewGuid" not in text, (
            f"phase {phase} mints its own operation id"
        )
        # RE-EXPRESSED with correction R5. Phase 18 no longer uses the `lc_provider_run` wrapper:
        # its exit code must be READ before it is dispatched, so it reads the same two fields off
        # the same result itself. The rule is unchanged — the id comes from the PROVIDER — so it is
        # now stated as that rather than as the name of one helper.
        assert re.search(r"(lc_provider_run|Lc-ProviderRun)", text) or re.search(
            r"(lc_json_field \"\$LC_RAW_OUT\" operation_id|Lc-Field \$LcRawOut 'operation_id')",
            text), f"phase {phase} does not take the operation id from the provider's own result"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_FRESH_publishes_generation_1_and_UPDATE_reads_the_real_one(phases):
    """D. The old update branch set the generation to 1 unconditionally — on a box at 5 every
    provider then committed against an inspected generation the manifest had left behind years ago,
    and the compare-and-swap refused. So an update must READ it."""
    body = code(phases()[11])
    # THE UPDATE BRANCH SPECIFICALLY. An earlier version of this test matched anywhere in the phase,
    # and the FRESH branch reads a generation too — so it was satisfied by the half it does not
    # name, and would have passed against the hard-coded 1 it exists to forbid.
    update = body[body.index("else"):]
    assert re.search(r"(lc_json_field|Lc-Field)[^\n]*generation", update), (
        "the update branch never reads `generation` out of the status result"
    )
    assert re.search(r"(CFM_GENERATION|\$CfmGeneration)\s*=", update), (
        "the update branch never assigns the generation it read"
    )
    assert not re.search(r"(CFM_GENERATION|\$CfmGeneration)\s*=\s*(\[int\])?1\b", update), (
        "the update branch hard-codes generation 1"
    )
    assert "locator" in body, "fresh-vs-update is not decided by the published record"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_each_provider_advances_the_generation_by_EXACTLY_ONE(phases):
    """Read from the commit helper, which is the only place the generation moves. Relative, never
    absolute: `inspected + 1` holds for a fresh 1→2→3→4→5 and for an update N→N+1→…"""
    source = SH.read_text(encoding="utf-8") if phases is linux_phases \
        else PS1.read_text(encoding="ascii")
    helper = re.search(r"(lc_commit_provider\(\) \{.*?^\}|function Lc-CommitProvider.*?^\})",
                       source, re.S | re.M)
    assert helper, "the commit helper is gone"
    assert re.search(r"(gen \+ 1|inspectedGeneration \+ 1|inspectedGeneration\] \+ 1)",
                     helper.group(0)), "the commit does not require exactly one generation"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_four_providers_run_in_the_ruled_order(phases):
    body = {n: code(b) for n, b in phases().items()}
    for phase, provider in sorted(RULED_ORDER.items()):
        assert re.search(rf"(lc_commit_provider|Lc-CommitProvider) '?{provider}\b", body[phase]), (
            f"phase {phase} does not compose {provider}"
        )


# ── stopping safely ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_PRIOR_RECOVERY_ENDS_THE_INVOCATION(phases):
    """C. A recoverable record routes to its own protocol and stops; it never becomes work this run
    performs on the way to installing something else."""
    body = code(phases()[3])
    for state in ("open", "checkpointed", "needs_recovery"):
        assert state in body, f"{state} is not routed"
    assert re.search(r"\b(die|Die)\b", body), "the routing does not end the invocation"
    assert "requires_recovery" not in body, "the dead key is back"


def test_every_lifecycle_exit_code_including_4_stops_the_run():
    """Exit 4 is `the installer built a request this build does not accept`. It is a DEFECT, not a
    box condition, and it must stop — the installers' seven refused requests were invisible because
    nothing looked at the code."""
    sh = SH.read_text(encoding="utf-8")
    ps1 = PS1.read_text(encoding="ascii")
    for rc in sorted(set(cli._CO_EXIT_CODES.values()) | {cli._CO_BAD_REQUEST}):
        assert re.search(rf"^\s*{rc}\)", sh, re.M), f"install.sh does not handle exit {rc}"
        assert re.search(rf"^\s*{rc} \{{", ps1, re.M), f"install.ps1 does not handle exit {rc}"
    assert "installer defect" in sh and "installer defect" in ps1


def test_a_FAILED_DISCARD_stops_the_run_rather_than_continuing(unroot, tmp_path):
    """The discard is not tidy-up. Its exit code goes through the same dispatcher as everything
    else, so a refused discard stops before the next provider meets the record it left."""
    sh = SH.read_text(encoding="utf-8")
    ps1 = PS1.read_text(encoding="ascii")
    assert "lc_run \"$prov journal discard\"" in sh, (
        "install.sh's discard bypasses the exit-code dispatcher"
    )
    assert 'Lc-Run "$provider journal discard"' in ps1, (
        "install.ps1's discard bypasses the exit-code dispatcher"
    )


def test_a_STALE_GENERATION_is_refused_by_the_commit_helper():
    """The read-back is the check: a commit that did not move the manifest by exactly one is not a
    commit this run can continue from."""
    sh = SH.read_text(encoding="utf-8")
    ps1 = PS1.read_text(encoding="ascii")
    assert "refusing to continue" in sh and "refusing to continue" in ps1


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_a_FOREIGN_RECORD_refuses_before_any_provider_runs(phases):
    """D's identity half. A published record naming another install directory is not this
    installation, and composing into it would move somebody else's manifest."""
    body = code(phases()[11])
    assert re.search(r"(install_dir|recordedDir)", body), "the recorded install dir is never read"
    assert re.search(r"another installation", body), (
        "a record naming another installation is not refused"
    )


def test_the_WINDOWS_SEED_is_derived_from_the_installation_not_the_checkout():
    """The one `Lc-PatchRequest` value a POSIX host cannot compute (see `_WINDOWS_HOST_LIMITED`),
    asserted on the builder's own text instead of on a null it produced off-platform.

    RE-EXPRESSED for packet 1257. This pinned the literal `Join-Path $script:Src 'db\\...'`, and the
    rule it was defending was that the seed is DERIVED from this installation rather than guessed or
    left null. The derivation survives; its base moved out of the Git checkout, because installer
    assets under `src\\` are untracked content that the update-eligibility gate refuses. So the
    assertion is now the property — derived from the install root and the shared asset directory
    name, and NOT from `$script:Src`.
    """
    source = PS1.read_text(encoding="ascii")
    builder = _ps_function(source, "Lc-PatchRequest")
    assert "$script:InstallDir" in builder and "$script:CfmAssetsDirName" in builder
    assert "CORPUSfm_DB.fmp12" in builder
    assert "$script:Src" not in builder, "the seed must not come from the deployed checkout"


# ── the verbs the installers invoke must EXIST ────────────────────────────────────────


def test_every_lifecycle_verb_either_installer_invokes_is_a_REAL_verb():
    """The hole `proxy add` fell through, closed.

    Both installers ran `corpusfm.lifecycle.cli proxy add <type>` for `--proxy-policy-add`. `proxy`
    is the INTEGRATOR subparser and declares only status/reconcile/finalize/abort; `add` and
    `ignore` are on `proxy-public`. Argparse exits 2 and the installer dies — at phase 16, AFTER
    generation 3 has been committed and the proxy journal discarded.

    Nothing could see it: the PowerShell AST guard resolves POWERSHELL command names, not argparse
    sub-verbs, and Linux had no equivalent at all. So this resolves each invocation against the real
    parser, by parsing it — not by running it, which would touch the machine.
    """
    import argparse
    import contextlib
    import io

    parser = cli._build_parser() if hasattr(cli, "_build_parser") else None
    invocations = set()
    for source, pattern in (
        (SH.read_text(encoding="utf-8"), r'CFM_LIFECYCLE\[@\]\}"\s+([a-z-]+)\s+([a-z-]+)'),
        (SH.read_text(encoding="utf-8"), r'lc_run "[^"]*" ([a-z-]+) ([a-z-]+)'),
        (SH.read_text(encoding="utf-8"), r'lc_provider_run "[^"]*" \S+ ([a-z-]+) ([a-z-]+)'),
        # Packet 1398: `la_lc_run <intent> <prior> "<what>" <verb...>` records the call in a
        # fresh-install attempt and otherwise IS `lc_run`; its verbs must resolve the same way.
        (SH.read_text(encoding="utf-8"), r'la_lc_run \S+ \S+ "[^"]*" ([a-z-]+) ([a-z-]+)'),
        # ONLY where the array is the argv of a lifecycle call. `@('web','scheduler')` is a service
        # name list, not an invocation, and a pattern that cannot tell them apart reports it.
        (PS1.read_text(encoding="ascii"), r"@\('([a-z-]+)','([a-z-]+)','--request'"),
        (PS1.read_text(encoding="ascii"), r"@\('([a-z-]+)',\$\w+,'--request'"),
        # `-m corpusfm.lifecycle.cli <group> <verb>` only. `from corpusfm.lifecycle.cli import x`
        # is a PYTHON import inside an embedded probe, not an invocation, and a pattern that cannot
        # tell them apart reports `import` as a missing verb.
        (PS1.read_text(encoding="ascii"), r"-m corpusfm\.lifecycle\.cli ([a-z-]+) ([a-z-]+)"),
    ):
        for found in re.findall(pattern, source):
            pair = found if isinstance(found, tuple) else (found, None)
            group, verb = (pair + (None,))[:2] if len(pair) < 2 else pair[:2]
            if group in ("python", "corpusfm") or verb is None:
                continue
            # A FLAT verb (`provision-keys --request <f>`) is not a group and a subverb. The second
            # token being an OPTION is what says so, and resolving the pair would ask argparse for
            # `provision-keys --request --help` — an error about a missing argument, reported as a
            # missing verb. Record the flat verb alone and resolve it alone.
            invocations.add((group, None) if verb.startswith("-") else (group, verb))
    assert invocations, "no lifecycle invocation was found in either installer"

    bad = []
    for group, verb in sorted(invocations, key=lambda pair: (pair[0], pair[1] or "")):
        argv = [group, "--help"] if verb is None else [group, verb, "--help"]
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
                cli.main(argv)
        except SystemExit as exc:
            # `--help` exits 0; an unknown group or verb exits 2 with argparse's usage message.
            if exc.code not in (0, None):
                bad.append((group, verb, buf.getvalue().strip().splitlines()[-1:]))
        except (argparse.ArgumentError, Exception):     # noqa: BLE001 — any other outcome is fine
            pass
    assert not bad, f"the installers invoke verbs this build does not have: {bad}"

    # THE CONTROL. Without it this passes for a resolver that accepts everything — and the defect it
    # was written for is exactly one verb on exactly one group.
    def _refused(*argv):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
                cli.main([*argv, "--help"])
        except SystemExit as exc:
            return exc.code not in (0, None)
        return False

    assert _refused("proxy", "add"), "the resolver does not refuse the verb this test exists for"
    assert not _refused("proxy-public", "add"), "the resolver refuses the verb that IS correct"
    assert ("proxy-public", "add") in invocations, (
        "no installer records the policy option through the surface that owns it"
    )
    # THE FLAT-VERB HALF of the same control. Accepting a flat verb widened what this guard lets
    # through, so it has to be shown to still refuse one that does not exist — otherwise a typo in a
    # top-level invocation resolves to nothing and passes.
    assert _refused("provision-keyz"), "a flat verb this build does not have is not refused"
    assert not _refused("provision-keys"), "the flat verb the installers invoke is not a real verb"
    assert ("provision-keys", None) in invocations, (
        "neither installer provisions the keys through the privileged lifecycle operation"
    )


# ── R5: the ONE exit-5 result an installer may advance over ───────────────────────────
#
# A FRESH install's `storage bootstrap` legitimately ends `incomplete_safe`: storage succeeded and
# composed a candidate, and what is missing is the first administrator — which phase 19 creates
# AFTER the candidate is committed and finalized. Refusing it made a correct fresh install die at
# phase 18 with every service stopped. Accepting exit 5 generally would let a genuinely interrupted
# operation walk on. So the answer is a conjunction, decided by ONE shipped boundary both installers
# ask, and every member of it is load-bearing.

_FRESH_OK = {
    "result": "incomplete_safe",
    "awaiting_composition": True,
    "operation_id": OP,
    "findings": [{"code": "first_administrator_owed", "detail": "no administrator yet"}],
    "candidate": {"storage": {"database_name": "CORPUSfm_DB"},
                  "inspected_generation": 4,
                  "inspected_installation_id": INST},
}


def _composable(payload=None, **over):
    body = {**_FRESH_OK, **(payload or {})}
    kwargs = {"installation_id": INST, "expected_generation": 4, "mode": "fresh_install"}
    kwargs.update(over)
    return cli.storage_fresh_success_is_composable(body, **kwargs)


def test_the_exact_fresh_conjunction_is_composable():
    """THE CLEAN CONTROL. Without it every refusal below is satisfied by a predicate that always
    says no — which is exactly the defect this correction removes."""
    ok, reason = _composable()
    assert ok, reason
    assert "first administrator" in reason


@pytest.mark.parametrize("member,mutation", [
    ("result", {"result": "completed"}),
    ("result", {"result": "incomplete"}),
    ("awaiting_composition", {"awaiting_composition": False}),
    ("awaiting_composition truthiness", {"awaiting_composition": 1}),
    ("awaiting_composition", {"awaiting_composition": "true"}),
    ("candidate", {"candidate": None}),
    ("candidate shape", {"candidate": {"inspected_generation": 4,
                                       "inspected_installation_id": INST}}),
    ("candidate storage block", {"candidate": {"storage": "not-a-mapping",
                                               "inspected_generation": 4,
                                               "inspected_installation_id": INST}}),
    ("operation_id", {"operation_id": None}),
    ("operation_id canonical", {"operation_id": "op-1"}),
    ("operation_id canonical", {"operation_id": OP.upper()}),
    ("findings", {"findings": []}),
    ("findings", {"findings": [{"code": "storage_unreachable"}]}),
    ("findings shape", {"findings": "first_administrator_owed"}),
    ("installation", {"candidate": {**_FRESH_OK["candidate"],
                                    "inspected_installation_id": "other"}}),
    ("generation", {"candidate": {**_FRESH_OK["candidate"], "inspected_generation": 3}}),
])
def test_REMOVING_ANY_ONE_MEMBER_refuses_independently(member, mutation):
    """Each member alone. A conjunction nobody probes member-by-member is a conjunction that has
    only ever been tested as a whole, and one member could be doing nothing."""
    ok, reason = _composable(mutation)
    assert not ok, f"{member} was not load-bearing: {mutation}"
    assert reason and reason != "", "a refusal must say which member failed"


@pytest.mark.parametrize("mode", ["forward_update", "repair_storage_access", "uninstall", ""])
def test_only_a_FRESH_INSTALL_can_owe_a_first_administrator(mode):
    ok, reason = _composable(mode=mode)
    assert not ok and "fresh install" in reason


@pytest.mark.parametrize("payload", [None, "a string", 42, []])
def test_a_MALFORMED_RESULT_is_never_composable(payload):
    ok, _reason = cli.storage_fresh_success_is_composable(
        payload, installation_id=INST, expected_generation=4, mode="fresh_install")
    assert not ok


def test_the_predicate_takes_only_DATA():
    """It decides whether an exit code may be survived. If it could also be told WHICH installation
    it is talking about by reading one, a caller could aim it — so it reads nothing."""
    import inspect

    params = set(inspect.signature(cli.storage_fresh_success_is_composable).parameters)
    assert params == {"payload", "installation_id", "expected_generation", "mode"}
    source = inspect.getsource(cli.storage_fresh_success_is_composable)
    body = source[source.index('"""', source.index('"""') + 3):]
    for forbidden in ("open(", "Path(", "platform_layout", "locator_for", "ManifestStore",
                      "os.environ", "subprocess"):
        assert forbidden not in body, f"the predicate reaches for {forbidden}"


@pytest.mark.parametrize("phases,marker", [
    (linux_phases, "lc_provider_run"),
    (windows_phases, "Lc-ProviderRun"),
])
def test_both_installers_ask_the_SAME_SHIPPED_BOUNDARY(phases, marker):
    """Both installers submit storage results to the shared disposition boundary.

    The old shell-specific fresh-success helpers duplicated one application predicate. The shared
    classifier now owns every provider result, including storage's incomplete-safe result.
    """
    source = SH.read_text(encoding="utf-8") if phases is linux_phases \
        else PS1.read_text(encoding="ascii")
    assert marker in source
    assert "installer_disposition" in source
    assert code(phases()[18]).count(marker) == 1


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_GENERIC_EXIT_5_STILL_STOPS_EVERY_OTHER_OPERATION(phases):
    """No phase interprets provider exit 5; every provider uses the shared classifier."""
    body = {n: code(b) for n, b in phases().items()}
    provider = "lc_provider_run" if phases is linux_phases else "Lc-ProviderRun"
    for phase in (15, 16, 17, 18):
        assert provider in body[phase], f"phase {phase} bypasses shared provider disposition"
        assert "incomplete_safe" not in body[phase]
    source = SH.read_text(encoding="utf-8") if phases is linux_phases \
        else PS1.read_text(encoding="ascii")
    helper = "lc_provider_disposition" if phases is linux_phases else "Lc-ProviderDisposition"
    assert helper in source and "installer_disposition" in source


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_FIRST_ADMIN_CREATION_FOLLOWS_storage_commit_finalize_and_discard(phases):
    """Order is the contract. Creating the administrator first would put a row in a store whose
    composition the installation record does not yet acknowledge."""
    body = {n: code(b) for n, b in phases().items()}
    assert "create-first-admin" not in body[18], "the administrator is created inside phase 18"
    assert "create-first-admin" in body[19], "phase 19 does not create the administrator"
    commit = re.search(r"(lc_commit_provider|Lc-CommitProvider) '?storage", body[18])
    discard = re.search(r"(lc_discard_provider|Lc-DiscardProvider) '?storage", body[18])
    assert commit and discard and body[18].index("finalize") < discard.start()
    assert commit.start() < body[18].index("finalize")


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_storage_JOURNAL_IS_PROVEN_RESOLVED_THEN_ABSENT(phases):
    """`Journal.discard` refuses an unresolved record, and storage answers `foreign_open` on the
    PRESENCE of any record — so both ends are read back rather than assumed."""
    body = code(phases()[18])
    assert "resolved" in body, "the journal is discarded without proving it resolved"
    assert re.search(r"(none|'none')", body), "the journal is not proven absent after the discard"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_a_REFUSED_ACCOUNT_CREATION_leaves_the_box_incomplete_and_stopped(phases):
    """A box nobody can sign in to is not a completed install, and phase 21 is what starts things."""
    body = code(phases()[19])
    assert re.search(r"(die|Die)", body), "a failed account creation does not stop the run"
    assert "STOPPED" in body
    assert "completed" in body and "no_change" in body, (
        "the result word is not what decides; only `completed` and a PROVEN `no_change` may pass"
    )


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_admin_PASSWORD_travels_on_STDIN_and_never_in_the_request(phases):
    body = code(phases()[19])          # COMMENTS EXCLUDED: the prose here explains the rule
    assert "stdin" in body, "the credential transport is not stdin"
    schema = re.search(r"admin_credential_input[\"\'= :]+[\"\']?(\w+(?::\d+)?)", body)
    assert schema and schema.group(1) == "stdin", (
        f"admin_credential_input is given {schema.group(1) if schema else None!r}"
    )
    for holder in ("CFM_ADMIN_PASS", "AdminPass"):
        assert not re.search(rf'"{holder}"|\$\{{?{holder}\b[^|]*--request', body), (
            "the administrator password reaches the request"
        )


# ── R6: candidate-bearing vs candidate-free no-change, in the installers ──────────────

@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_installers_DISCRIMINATE_candidate_bearing_from_candidate_free_no_change(phases):
    """A candidate-free `no_change` consumes no generation and opens no journal, so committing it
    would call `commit-provider` with no matching journal authority — the exact `ProviderMismatch`
    R6 removes. A candidate WITHOUT `awaiting_composition`, or the reverse, is contradictory."""
    body = code(phases()[PHASE_OF["admin_identity"]])
    helper = "lc_provider_run" if phases is linux_phases else "Lc-ProviderRun"
    compose_flag = "LC_COMPOSE" if phases is linux_phases else "LcCompose"
    assert helper in body, "the admin-identity phase bypasses shared provider disposition"
    assert compose_flag in body, "the admin-identity phase commits without the disposition verdict"
    # The commit, the finalize and the discard are all INSIDE the compose arm — a discard left
    # outside would retire a journal record that was never opened.
    compose = body[body.index(compose_flag):]
    for step in ("commit_provider" if phases is linux_phases else "CommitProvider",
                 "finalize",
                 "discard_provider" if phases is linux_phases else "DiscardProvider"):
        assert step in compose.split("else")[0], f"{step} runs outside the compose arm"
    # …and the shared provider runner reads BOTH halves from the provider result before asking the
    # application classifier for a compose verdict.
    source = SH.read_text(encoding="utf-8") if phases is linux_phases \
        else PS1.read_text(encoding="ascii")
    body_of_helper = source[source.index(helper + ("() {" if phases is linux_phases else "(")):]
    body_of_helper = body_of_helper[:body_of_helper.index("\n}")]
    assert re.search(r"(LC_CANDIDATE|LcCandidate)", body_of_helper)
    assert re.search(r"(LC_AWAITING|LcAwaiting)", body_of_helper)
    disposition = "lc_provider_disposition" if phases is linux_phases else "Lc-ProviderDisposition"
    assert disposition in body_of_helper
    assert "awaiting_composition" in source, "nothing reads awaiting_composition at all"


def test_commit_provider_REFUSES_an_operation_with_no_matching_journal(tmp_path):
    """The mechanism behind R6, exercised directly: a candidate offered with no operation behind it
    cannot be composed, whatever the installer does with it."""
    from corpusfm.lifecycle import composition
    from corpusfm.lifecycle.journal import Journal
    from corpusfm.lifecycle.layout import posix_layout

    layout = posix_layout(tmp_path)
    layout.journal_file.parent.mkdir(parents=True, exist_ok=True)
    with pytest.raises(composition.ProviderMismatch):
        composition._require_matching_entry(Journal(layout), "admin_identity", OP, INST)


# ── C1: storage is routed by the OBSERVED STATE, never by the flag alone ──────────────

def _obs(state, expectation="expects_corpus"):
    return {"state": state, "facts": {"manifest_expectation": expectation}}


def _route(state, *, mode, repair=False, expectation="expects_corpus"):
    return cli.storage_route_for_observation(_obs(state, expectation), mode=mode,
                                             repair_requested=repair)


def test_a_HEALTHY_GENERATION_N_UPDATE_calls_no_storage_verb_at_all():
    """THE RC4 THIS CLOSES. Every update invoked `storage bootstrap` with `mode=forward_update`,
    which `proven_fresh` rejects — so the run died at phase 18 with every service stopped by phase 9,
    and the installer's own advice (*re-run to resume*) walked into the same wall."""
    verb, reason = _route("existing_corpus_reachable", mode="forward_update")
    assert verb == cli.ST_ROUTE_SKIP, reason


def test_a_DEFAULT_CREDENTIAL_UPDATE_calls_repair_and_never_bootstrap():
    verb, _ = _route("existing_corpus_on_default", mode="forward_update")
    assert verb == cli.ST_ROUTE_REPAIR


def test_EXPLICIT_REPAIR_calls_repair_and_never_bootstrap():
    for state in ("existing_corpus_on_default", "existing_corpus_reachable"):
        verb, _ = _route(state, mode="repair_storage_access", repair=True)
        assert verb == cli.ST_ROUTE_REPAIR
    # …and never over a machine with no published corpus to repair.
    verb, reason = _route("existing_corpus_on_default", mode="repair_storage_access", repair=True,
                          expectation="no_expectation")
    assert verb is None and "nothing to repair" in reason


def test_a_FRESH_INSTALL_calls_bootstrap_and_only_from_proven_fresh():
    verb, _ = _route("proven_fresh", mode="fresh_install", expectation="no_expectation")
    assert verb == cli.ST_ROUTE_BOOTSTRAP


@pytest.mark.parametrize("state", [
    "prerequisite_required", "fms_absent", "fms_unreachable", "conflicting_evidence",
    "indeterminate", "existing_corpus_unreadable", "candidate_proven",
    "existing_corpus_uninitialized", "existing_corpus_reachable", "existing_corpus_on_default",
])
def test_a_FRESH_INSTALL_refuses_every_state_but_proven_fresh(state):
    """A fresh install has exactly two destinations, and this is the first one's fence: over a
    record that already publishes a corpus, only `proven_fresh` routes. The second destination —
    `adopt`, over an existing corpus the record does NOT publish — is fenced in
    `tests/test_storage_adoption.py`, which owns its evidence."""
    verb, reason = _route(state, mode="fresh_install")
    assert verb is None and "proven-fresh" in reason


@pytest.mark.parametrize("state", [
    "prerequisite_required", "fms_absent", "fms_unreachable", "conflicting_evidence",
    "indeterminate", "existing_corpus_unreadable", "candidate_proven",
    "existing_corpus_uninitialized", "proven_fresh",
])
def test_an_UPDATE_refuses_every_state_it_has_no_route_for(state):
    """Absent, unreadable, uninitialized, conflicting, indeterminate and unreachable all refuse
    BEFORE any storage mutation — and so does `proven_fresh`, which on an update means the machine
    lost the corpus its record claims."""
    verb, reason = _route(state, mode="forward_update")
    assert verb is None and reason


@pytest.mark.parametrize("state", ["existing_corpus_reachable"])
def test_an_UPDATE_refuses_a_corpus_the_RECORD_DOES_NOT_PUBLISH(state):
    """A missing published StorageBlock is a mismatch between the machine and its own record, and
    UPDATING over it would move a manifest that disowns the corpus it is about.

    **`existing_corpus_on_default` left this set (developer ruling, 2026-08-09).** That pair —
    default credential, no published storage — is not a mismatch to refuse but the ADOPTION case,
    and refusing it is what stranded a box whose generation had advanced through admin identity,
    patch and proxy while its storage was still unowned. A REACHABLE corpus the record disowns is
    still refused: nothing there identifies which corpus this installation should take over.
    """
    verb, reason = _route(state, mode="forward_update", expectation="no_expectation")
    assert verb is None and "does not publish" in reason


def test_A_DEFAULT_CREDENTIAL_CORPUS_THE_RECORD_DISOWNS_IS_ADOPTED_NOT_REFUSED():
    """The counterpart, on both ordinary modes: one situation, one route, whatever the shell calls
    the invocation."""
    from corpusfm.lifecycle.cli import ST_ROUTE_ADOPT

    for mode in ("fresh_install", "forward_update"):
        verb, reason = _route("existing_corpus_on_default", mode=mode,
                              expectation="no_expectation")
        assert verb == ST_ROUTE_ADOPT, (mode, verb, reason)


@pytest.mark.parametrize("payload", [None, "a string", 42, [], {}, {"state": "proven_fresh"},
                                     {"state": "nonsense", "facts": {}},
                                     {"state": "proven_fresh", "facts": {}},
                                     {"state": "proven_fresh",
                                      "facts": {"manifest_expectation": "??"}}])
def test_an_UNREADABLE_OBSERVATION_never_routes(payload):
    verb, _reason = cli.storage_route_for_observation(payload, mode="fresh_install",
                                                      repair_requested=False)
    assert verb is None


def test_BOOTSTRAP_IS_REACHABLE_FROM_EXACTLY_ONE_INPUT():
    """`never reinterpret a failed bootstrap as an update plan`, made structural. Exhaustive over
    every state × every mode × both flag values: only one combination yields `bootstrap`."""
    from corpusfm.lifecycle.storage_identity import MODES, ManifestExpectation, StorageState

    reaching = []
    for state in (s.value for s in StorageState):
        for mode in MODES:
            for expectation in (e.value for e in ManifestExpectation):
                for repair in (False, True):
                    verb, _ = cli.storage_route_for_observation(
                        _obs(state, expectation), mode=mode, repair_requested=repair)
                    if verb == cli.ST_ROUTE_BOOTSTRAP:
                        reaching.append((state, mode, expectation, repair))
    assert {(s, m, r) for s, m, _e, r in reaching} == {("proven_fresh", "fresh_install", False)}


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_RESTORING_THE_UNCONDITIONAL_UPDATE_BOOTSTRAP_is_caught(phases):
    """The mutation control, expressed against the installers: the verb may not be chosen from the
    repair flag. The retired line was `if $REPAIR…; then verb=repair; else verb=bootstrap; fi`."""
    body = code(phases()[18])
    assert not re.search(r"(_lc_st_verb|\$stVerb)\s*=\s*'?bootstrap'?", body), (
        "the installer chooses `bootstrap` for itself instead of routing"
    )
    marker = "lc_storage_route" if phases is linux_phases else "Lc-StorageRoute"
    assert marker in body, "phase 18 does not route from the observation"
    assert "storage_route_for_observation" in (
        SH.read_text(encoding="utf-8") if phases is linux_phases else PS1.read_text(encoding="ascii")
    ), "the installer does not ask the shipped routing boundary"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_storage_OBSERVATION_IS_KEPT_and_captured_apart_from_stderr(phases):
    """The routing authority is an observation this run captured, with stderr kept out of it.

    **It is captured in phase 18, not phase 14 (packet 1246-10-04).** Phase 14 runs before phase 15
    publishes the Admin-API machine identity, so `list_databases()` cannot answer there and the
    database-known and hosted axes are UNKNOWN by construction — every box classifies
    `indeterminate` and nothing routes. Measured on fms-server 2026-08-08.
    """
    body = code(phases()[18])
    holder = "CFM_STORAGE_OBSERVATION" if phases is linux_phases else "CfmStorageObservation"
    assert holder in body, "phase 18 captures no observation, so routing has no authority"
    assert "storage" in body and "observe" in body, "phase 18 does not observe before it routes"
    assert re.search(r"2>>?[\"$]?\$?(CFM_LOG|null)", body) or "2>$null" in body, (
        "stderr is merged into the observation, which would make it unparseable"
    )


# ── C2: a candidate-free no-change is not automatically a published one ───────────────

_AI_SKIP_OK = {"result": "no_change", "candidate": None, "awaiting_composition": False,
               "operation_id": None, "findings": [{"code": "no_publication_owed"}]}


def test_the_exact_published_result_skips():
    ok, reason = cli.admin_identity_skip_is_genuine(_AI_SKIP_OK)
    assert ok, reason


@pytest.mark.parametrize("state_finding", [
    "diagnose_before_replacing",          # REJECTED
    "fms_authority_required",             # UNKNOWN, authority never granted
    "recovery_evidence_not_clear",
    "generation_divergence",
])
def test_a_REFUSAL_STATE_wearing_the_same_result_word_does_NOT_skip(state_finding):
    """LOCAL_UNUSABLE, both UNKNOWN flavours and REJECTED all return a candidate-free `no_change`
    and all exit 0. Skipping on the absence of a candidate reported every one as "already
    published" — a loud stop traded for a false success."""
    payload = {**_AI_SKIP_OK, "findings": [{"code": state_finding}]}
    ok, reason = cli.admin_identity_skip_is_genuine(payload)
    assert not ok
    assert state_finding in reason, "the refusal does not carry the state's own reason"


def test_a_STATE_WITH_NO_FINDINGS_AT_ALL_does_not_skip():
    """`LOCAL_UNUSABLE` and the terminal `UNKNOWN` add no finding at all — the commonest shape of
    the defect, and the one an "is there a finding?" check would miss."""
    ok, _ = cli.admin_identity_skip_is_genuine({**_AI_SKIP_OK, "findings": []})
    assert not ok


def test_REMOVING_ONLY_THE_FINDING_breaks_the_skip():
    """The single-member control for the member that carries the whole rule."""
    payload = dict(_AI_SKIP_OK)
    payload["findings"] = [{"code": "something_else"}]
    assert not cli.admin_identity_skip_is_genuine(payload)[0]
    assert cli.admin_identity_skip_is_genuine(_AI_SKIP_OK)[0]


@pytest.mark.parametrize("mutation", [
    {"result": "completed"}, {"candidate": {"pki": {}}}, {"awaiting_composition": True},
    {"awaiting_composition": None}, {"operation_id": OP},
])
def test_a_CONTRADICTORY_admin_identity_result_refuses(mutation):
    assert not cli.admin_identity_skip_is_genuine({**_AI_SKIP_OK, **mutation})[0]


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_both_installers_ask_the_SAME_skip_predicate(phases):
    source = SH.read_text(encoding="utf-8") if phases is linux_phases \
        else PS1.read_text(encoding="ascii")
    body = code(phases()[PHASE_OF["admin_identity"]])
    marker = "lc_provider_run" if phases is linux_phases else "Lc-ProviderRun"
    assert marker in body
    assert "installer_disposition" in source
    assert "LC_COMPOSE" in body or "LcCompose" in body


# ── C3: the FMS credential frame ──────────────────────────────────────────────────────

def test_neither_installer_asks_the_LIFECYCLE_LAYER_to_prompt():
    """`prompt` reads `input()` + `getpass`, which a `--silent` run cannot answer — it hangs rather
    than refusing. The installers already acquired and VERIFIED this account at phase 7."""
    for source, name, transport in (
        (SH.read_text(encoding="utf-8"), "linux", "lc_fms_transport"),
        (PS1.read_text(encoding="ascii"), "windows", "Lc-FmsTransport"),
    ):
        body = _bash_function(source, transport) if name == "linux" else _ps_function(source, transport)
        assert '"prompt"' not in body and "'prompt'" not in body, (
            f"{name}: an ordinary provider still asks the lifecycle layer to prompt"
        )


def test_the_transport_is_stdin_when_held_and_absent_when_not(tmp_path):
    """`absent` is not a fallback for a missing credential — it is the honest statement that none is
    held, and the provider then refuses any operation that needs one BEFORE mutating."""
    for held, expected in ((True, "stdin"), (False, "absent")):
        world = dict(LINUX_WORLD)
        if not held:
            world["FM_ADMIN_USER"] = ""
            world["FM_ADMIN_PASS"] = ""
        source = SH.read_text(encoding="utf-8")
        script = "\n".join([
            "set -euo pipefail",
            "\n".join(f'{k}="{v}"' for k, v in world.items()),
            _bash_function(source, "lc_fms_transport"),
            "lc_fms_transport",
        ])
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        assert out.returncode == 0 and out.stdout == expected, (held, out.stdout, out.stderr)


@pytest.mark.parametrize("account,password", [
    ("admin", "hunter2"),
    ("admín", "pä ss\twörd"),                 # UTF-8 on both sides
    ("a" * 300, "b" * 5000),                  # a length no single byte could encode
    ("admin", "trailing "),                   # a password of spaces is a password
])
def test_the_LINUX_FRAME_round_trips_through_the_REAL_reader(account, password):
    """Built by the installer's own function, read by `CredentialLease.from_frame` — the production
    parser, not a re-implementation of it here."""
    from corpusfm.lifecycle.admin_identity_ops import CredentialLease

    source = SH.read_text(encoding="utf-8")
    fn = _bash_function(source, "lc_fms_frame")
    script = "\n".join(["set -euo pipefail", "INSTALL_DIR=/unused",
                        f"LC_RUNTIME_PY={shlex.quote(sys.executable)}",
                        f"FM_ADMIN_USER={shlex.quote(account)}",
                        f"FM_ADMIN_PASS={shlex.quote(password)}", fn, "lc_fms_frame"])
    out = subprocess.run(["bash", "-c", script], capture_output=True)
    assert out.returncode == 0, out.stderr
    lease = CredentialLease.from_frame(out.stdout)
    assert (lease._user, lease._password) == (account, password)


@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"\x00\x00\x00\x05ab", "truncated field"),
    (b"\x00\x00\x00\x02ab", "only one field"),
    (b"\x00\x00\x00\x02ab\x00\x00\x00\x02cd\x00", "trailing byte"),
    (b"\x00\x00\x00\x02ab\x00\x00\x00\x02cd\n", "text newline appended"),
    (b"admin\npassword\n", "text framed"),
    (b"\x00\x00\x00\x00\x00\x00\x00\x00", "two empty fields"),
])
def test_a_MALFORMED_FRAME_is_refused_by_the_real_reader(raw, why):
    """Including the two the PowerShell object pipeline would produce — a re-encoded text form and a
    trailing line terminator. That is why Windows writes to `StandardInput.BaseStream`."""
    from corpusfm.lifecycle.admin_identity_ops import CredentialFrameRefused, CredentialLease

    with pytest.raises(CredentialFrameRefused):
        CredentialLease.from_frame(raw)


def test_WINDOWS_writes_the_frame_as_BYTES_not_through_the_object_pipeline():
    ps1 = PS1.read_text(encoding="ascii")
    body = "\n".join(l for l in ps1.splitlines() if not l.lstrip().startswith("#"))
    assert "StandardInput.BaseStream" in body, (
        "the frame goes through the PowerShell pipeline, which re-encodes and appends a terminator"
    )
    assert "IsLittleEndian" in body, "the four-byte length is not written big-endian"
    assert "ProcessStartInfo" in body


def test_the_credential_reaches_NO_argv_NO_environment_and_NO_request():
    """The three places a secret must never be: a world-readable process list, an environment every
    child inherits, and a request file that outlives the call."""
    sh, ps1 = SH.read_text(encoding="utf-8"), PS1.read_text(encoding="ascii")
    for source, name in ((sh, "linux"), (ps1, "windows")):
        body = "\n".join(l for l in source.splitlines() if not l.lstrip().startswith("#"))
        for holder in ("FM_ADMIN_PASS", "FmAdminPass"):
            for line in body.splitlines():
                if holder not in line:
                    continue
                assert not re.search(rf"(export|env)\s+\w*{holder}", line), f"{name}: {line[:90]}"
                assert "--request" not in line, f"{name}: a credential shares a request line"
    # …and it is not a value in any request schema either.
    for _label, _ps, sh_call in LINUX_CLEAN:
        body = linux_request(sh_call)
        assert "held-not-sent" not in json.dumps(body), f"the password reached {_label}'s request"


# ── R6: the Linux updater's administrator-owned files ────────────────────────────────

def test_LINUX_installs_the_updaters_administrator_owned_library_and_entry_points():
    """The renderer emits `<install>/bin/tree_inspection.py`, `<install>/bin/publish_outcome.py` and
    `<install>/lib`. **Linux created none of them**, so the rendered updater refused on every trigger
    and the in-app update path was installed and inert."""
    body = code(linux_phases()[13])
    for owned in ("$INSTALL_DIR/lib", "bin/tree_inspection.py", "bin/publish_outcome.py"):
        assert owned in body, f"phase 13 never installs {owned}"
    # …from the checkout being installed, and OUTSIDE it.
    assert "$INSTALL_DIR/src/corpusfm" in body
    from corpusfm.lifecycle import update_boundary as _ub

    assert _ub.LIBRARY_DIRNAME != _ub.CHECKOUT_DIRNAME
    assert _ub.HELPER_DIRNAME != _ub.CHECKOUT_DIRNAME


def test_the_LINUX_installed_authority_is_staged_then_replaced_and_read_back():
    body = code(linux_phases()[13])
    assert "lib.staging" in body, "the library is copied into place rather than staged"
    assert body.index("lib.staging") < body.index("render_linux_updater")
    assert "stat -c '%U'" in body and "root" in body, "ownership is not read back"
    assert "-perm /022" in body, "writability is not read back"
    assert body.index("stat -c '%U'") < body.index("render_linux_updater"), (
        "the read-back happens after the artifact is rendered"
    )


def test_RESTORING_THE_RENDERER_ONLY_LINUX_BLOCK_is_caught():
    """The mutation control: the retired phase 13 did `mkdir -p bin` and rendered. If the install of
    the three owned paths were removed, these markers would go with it."""
    body = code(linux_phases()[13])
    for marker in ("lib.staging", "tree_inspection.py", "publish_outcome.py", "stat -c '%U'"):
        assert marker in body, f"the owned-authority install lost {marker!r}"
    # THE ORDERING is what the retired block got wrong by omission: everything above must happen
    # BEFORE the render, because the renderer bakes these paths into a script that runs as root.
    render = body.index("render_linux_updater")
    for marker in ("lib.staging", "publish_outcome.py", "stat -c '%U'", "-perm /022"):
        assert body.index(marker) < render, f"{marker!r} happens after the artifact is rendered"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_updater_LOADS_ITS_JUDGE_FROM_OUTSIDE_THE_CHECKOUT(phases):
    """R7b: both updaters used to put the checkout on PYTHONPATH and run the tree inspector from it,
    so a modified helper in a modified tree declared that tree clean."""
    from corpusfm.lifecycle import update_boundary as _ub

    for helper in (_ub.helper_path, _ub.publisher_path, _ub.library_path):
        rendered = str(helper("/opt/CORPUSfm"))
        assert not rendered.startswith(f"/opt/CORPUSfm/{_ub.CHECKOUT_DIRNAME}/")
    # …and the SHIPPED UPDATER — the artifact that actually runs as root — invokes the INSTALLED
    # helper and publisher rather than a module inside the checkout. Asserted on the template, which
    # is where the runtime behaviour lives; phase 13's own Python invocation legitimately imports
    # from the checkout, because rendering the artifact is not running it.
    template = (REPO / "installer" / ("linux/corpusfm-update.sh" if phases is linux_phases
                                      else "windows/corpusfm-update.ps1")).read_text(
        encoding="utf-8" if phases is linux_phases else "ascii")
    body_lines = [l for l in template.splitlines() if not l.lstrip().startswith("#")]
    for line in body_lines:
        assert "-m corpusfm.lifecycle.tree_inspection" not in line, (
            f"the updater runs the tree inspector as a module from a path it does not control: "
            f"{line.strip()[:100]}"
        )
    # WHERE that authority lives now differs by platform (packet 1380-02). Linux still renders the
    # three locations in; the Windows updater is static and signed, so it takes them from the layout it
    # derives from the fixed locator (test_windows_updater_paths proves that layout equals the
    # application's). The rule is unchanged - the judge comes from installation authority, never from
    # the checkout - so the assertion follows the authority instead of pinning one spelling onto both.
    if phases is linux_phases:
        assert "@@HELPER@@" in template and "@@PUBLISHER@@" in template and "@@LIB_DIR@@" in template
    else:
        for assignment in ("$Helper = $UpdaterLayout.Helper", "$Publisher = $UpdaterLayout.Publisher",
                           "$LibDir = $UpdaterLayout.LibDir"):
            assert assignment in template, (
                f"the Windows updater no longer takes {assignment.split()[0]} from its derived layout"
            )
        assert "@@HELPER@@" not in template, (
            "a rendered seam is back in an artifact that must be installed byte-for-byte"
        )


# ── R7: the phase-3 gate fails closed ────────────────────────────────────────────────

@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_recovery_gate_DOES_NOT_DEPEND_ON_THE_INTERPRETER(phases):
    """A box with an OPEN JOURNAL and a broken interpreter used to walk straight past its own
    unresolved operation, because the whole block was gated on the interpreter existing."""
    body = code(phases()[3])
    holder = "CFM_JOURNAL_FILE" if phases is linux_phases else "CfmJournalFile"
    assert holder in body, "the journal's fixed path is never consulted"
    assert re.search(r"(die|Die)", body)
    # The refusal must be reachable from "journal present, interpreter absent".
    assert re.search(r"(lifecycle journal|holds a CORPUSfm lifecycle journal)", body)


def test_the_journal_path_each_installer_names_IS_the_platform_layouts():
    """A literal that drifts from `lifecycle/layout.py` silently stops guarding the file it names."""
    from corpusfm.lifecycle.layout import posix_layout, windows_layout

    sh = SH.read_text(encoding="utf-8")
    assert re.search(rf"CFM_JOURNAL_FILE={re.escape(str(posix_layout().journal_file))}\b", sh), (
        "the Linux installer names a journal path the platform layout does not"
    )
    ps1 = PS1.read_text(encoding="ascii")
    tail = str(windows_layout().journal_file).replace("C:\\ProgramData/CORPUSfm/", "").replace(
        "/", "\\")
    assert tail in ps1, f"the Windows installer does not name {tail}"


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_the_status_read_is_STRICT(phases):
    """stdout apart from stderr, the exit status kept, and exactly one parseable JSON object with
    the required fields. An unresolved status legitimately exits non-zero AND carries valid JSON, so
    the parsed STATE routes — never the exit code, and never "non-zero means nothing to see"."""
    # WHERE the read happens moved on Windows and the rule did not: phase 2 now classifies from
    # the same observation phase 3 routes from, so the read, its exit code and its strict
    # validation live in the one function both call. Scoped to whichever block PERFORMS the read,
    # so this keeps failing if that validation is ever dropped — which is what it defends.
    body = code(phases()[3])
    if phases is not linux_phases:
        ps1 = PS1.read_text(encoding="ascii")
        reader = ps1[ps1.index("function Get-LcState"):ps1.index("# === PHASE 1 -")]
        assert "Get-LcState" in body, "phase 3 no longer routes from the shared observation"
        # ONE read in the pre-mutation window — where classification and routing both look, and
        # where two answers could disagree about the same unchanged box. Later phases re-observe
        # deliberately, after they have changed something, and memoizing those would be the defect.
        # The INVOCATION, not the word: advisory messages tell an administrator to run the same
        # command by hand, and those are not detection paths.
        before_mutation = ps1[:ps1.index("# === PHASE 4 -")]
        assert before_mutation.count("& $Py -m corpusfm.lifecycle status --json") == 1, (
            "a second status read can disagree with the one that was validated"
        )
        body = reader
    assert "one parseable JSON object" in body or "parseable JSON object" in body, (
        "the status output is read field-by-field without ever being validated as a document"
    )
    assert re.search(r"(_lc_rc|lcStatusRc|\$rc = \$LASTEXITCODE)", body), (
        "the status exit code is discarded"
    )
    assert re.search(r"(2>>\"?\$CFM_LOG|2>\$null)", body), "stderr is merged into stdout"
    assert "journal" in body and "locator" in body


def test_the_STRICT_STATUS_PROBE_refuses_exactly_what_it_should():
    """Executed, not scanned: the same probe text both installers embed, run over each bad shape."""
    sh = SH.read_text(encoding="utf-8")
    probe = sh[sh.index("'import json, sys\nraw = sys.stdin.read()"):]
    probe = probe[1:probe.index("raise SystemExit(1)'") + len("raise SystemExit(1)")]
    good = json.dumps({"journal": "none", "locator": "missing"})
    cases = [(good, 0), ("", 1), ("not json", 1), ("[]", 1), ('{"journal":"none"}', 1),
             (good + "\n" + good, 1), ('warning: something\n' + good, 1),
             (json.dumps({"locator": "missing"}), 1)]
    for payload, expected in cases:
        out = subprocess.run([sys.executable, "-c", probe], input=payload, text=True,
                             capture_output=True)
        assert out.returncode == expected, (payload[:40], out.returncode, out.stderr[:80])


@pytest.mark.parametrize("phases", [linux_phases, windows_phases], ids=["linux", "windows"])
def test_a_RESOLVED_journal_is_terminal_residue_not_silently_settled(phases):
    body = code(phases()[3])
    assert "resolved" in body
    assert ("lc_discard_provider" in body or "Lc-DiscardProvider" in body)


@pytest.mark.parametrize("path,function_start,function_end", [
    (SH, "lc_discard_provider() {", "\n}\n\n# Ask the application-owned"),
    (PS1, "function Lc-DiscardProvider", "\n}\n\nfunction Lc-CommitProvider"),
], ids=["linux", "windows"])
def test_proxy_artifacts_are_retired_before_the_generic_journal(path, function_start, function_end):
    source = path.read_text(encoding="utf-8")
    body = source[source.index(function_start):]
    body = body[:body.index(function_end)]
    provider_retire = (body.index("proxy retire") if "proxy retire" in body
                       else body.index("'proxy','retire'"))
    generic_discard = body.index("discard-provider")
    assert provider_retire < generic_discard


# ── F2–F5: the PRODUCTION PowerShell bodies, EXECUTED ─────────────────────────────────
#
# Every one of F2–F5 was a stream or a host API asserted as a substring in this very file while the
# production path was broken. So these run the real function bodies under pwsh. That is
# **policy-through-doubles on macOS**: the SHELL is real and the function bodies are verbatim, but
# Windows PowerShell 5.1 on .NET Framework is a different host and remains a 1246-10 live gate —
# nothing below is evidence about 5.1 itself.

def _ps_literal(value: str) -> str:
    """A PowerShell SINGLE-QUOTED literal. Not `json.dumps`.

    JSON escaping and PowerShell escaping are different languages: `json.dumps("back\\slash")`
    yields `"back\\\\slash"`, and a PowerShell double-quoted string does not process backslashes —
    so the child received TWO where the test meant one, and every backslash case measured the
    harness rather than the encoder. A single-quoted PowerShell literal is verbatim; only `'` needs
    doubling.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _pwsh(script: str, tmp_path, name="probe.ps1"):
    probe = tmp_path / name
    probe.write_text(script, encoding="utf-8")
    return subprocess.run([pwsh, "-NoProfile", "-File", str(probe)], capture_output=True, text=True)


_PS_STUBS = """
$script:Py = '{python}'
$env:PYTHONPATH = '{application_root}'
$script:CfmStorageMode = 'forward_update'
$script:RepairStorageAccess = $false
$script:LcFramedTimeoutMs = {timeout}
function Cfm-Logline($t) {{ }}
function Die($m) {{ Write-Error $m; exit 9 }}
function Ok($m) {{ }}
function Info($m) {{ }}
function Warn($m) {{ }}
function Lc-Dispatch($code, $what) {{ if ($code -ne 0) {{ Die "$what exit $code" }} }}
"""


def _ps_stubs(timeout=600000):
    return _PS_STUBS.format(
        python=sys.executable, application_root=str(APPLICATION_ROOT), timeout=timeout)


@needs_pwsh
@pytest.mark.parametrize("route", ["skip", "repair", "bootstrap"])
def test_F2_each_ROUTE_SURVIVES_a_probe_that_also_writes_to_stderr(tmp_path, route):
    """THE DEFECT, executed. The shipped probe writes its REASON to stderr and the VERB to stdout.
    Captured with `2>&1` the return value was "<reason>`n<verb>" and never equalled a route word, so
    `$stVerb` became the reason text and `storage <garbage>` exited 2 — every Windows install and
    update, at phase 18, after generations 2-4 were committed."""
    ps1 = PS1.read_text(encoding="ascii")
    fn = _ps_function(ps1, "Lc-StorageRoute")
    # The SHIPPED helper, not a stub: the probe is written to a file and executed directly, and a
    # stub here would let the harness pass while the real mechanism was broken.
    helper = _ps_function(ps1, "New-CfmProbeFile")
    # The real probe text is inside the function; only the payload it reads is supplied here.
    mode = "fresh_install" if route == "bootstrap" else "forward_update"
    script = "\n".join([_ps_stubs(), f"$script:CfmStorageMode = '{mode}'", helper, fn,
                        f"$r = Lc-StorageRoute '{json.dumps(_route_payload(route))}'",
                        "Write-Output ('[' + $r + ']')"])
    out = _pwsh(script, tmp_path)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == f"[{route}]", (out.stdout, out.stderr)


def _route_payload(route):
    if route == "bootstrap":
        return {"state": "proven_fresh", "facts": {"manifest_expectation": "no_expectation"}}
    if route == "repair":
        return {"state": "existing_corpus_on_default",
                "facts": {"manifest_expectation": "expects_corpus"}}
    return {"state": "existing_corpus_reachable",
            "facts": {"manifest_expectation": "expects_corpus"}}


@needs_pwsh
def test_F2_a_MUTATION_RESTORING_2_TO_1_fails(tmp_path):
    """The mutation control: put the streams back together and the route stops matching."""
    ps1 = PS1.read_text(encoding="ascii")
    fn = _ps_function(ps1, "Lc-StorageRoute")
    mutated = fn.replace("2>$errFile", "2>&1")
    assert mutated != fn, "the merge this control restores is no longer there to restore"
    script = "\n".join([_ps_stubs(), mutated,
                        f"$r = Lc-StorageRoute '{json.dumps(_route_payload('skip'))}'",
                        "Write-Output ('[' + $r + ']')"])
    out = _pwsh(script, tmp_path, name="mutated.ps1")
    assert out.stdout.strip() != "[skip]" or out.returncode != 0, (
        "merging stderr into the route value no longer changes the answer — the control is inert"
    )


@needs_pwsh
@pytest.mark.parametrize("stdout_text,ok", [
    ('{"result":"completed","candidate":null}', True),
    ("", False),
    ("not json", False),
    ("[1,2]", False),
    ('"scalar"', False),
    ('{"a":1}\n{"b":2}', False),
])
def test_F4_the_RAW_RUNNER_requires_exactly_one_json_object(tmp_path, stdout_text, ok):
    """Executed against the production `Lc-IsOneJsonObject`. Two concatenated documents and a JSON
    array both come back from `ConvertFrom-Json` as an ARRAY, which is why the check is by type and
    not by "did it parse"."""
    ps1 = PS1.read_text(encoding="ascii")
    fn = _ps_function(ps1, "Lc-IsOneJsonObject")
    # Fed as a raw string, exactly as the runner holds it.
    script = "\n".join([_ps_stubs(), fn,
                        f"$t = {_ps_literal(stdout_text)}",
                        "if (Lc-IsOneJsonObject $t) { 'YES' } else { 'NO' }"])
    out = _pwsh(script, tmp_path, name="onejson.ps1")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ("YES" if ok else "NO"), (stdout_text, out.stdout)


@needs_pwsh
def test_F4_a_STDERR_DIAGNOSTIC_does_not_reach_the_parser(tmp_path):
    """A child that writes a diagnostic AND a valid result must still be read as one object."""
    ps1 = PS1.read_text(encoding="ascii")
    fn = _ps_function(ps1, "Lc-RunRaw") + "\n" + _ps_function(ps1, "Lc-IsOneJsonObject")
    child = ('import sys; sys.stderr.write("a benign diagnostic\\n"); '
             'sys.stdout.write(\'{"result":"completed"}\')')
    script = "\n".join([
        _ps_stubs(),
        f"$script:Py = '{sys.executable}'",
        _must_substitute(fn, "-m corpusfm.lifecycle @LcArgs", "-c $script:Child"),
        f"$script:Child = {_ps_literal(child)}",
        "Lc-RunRaw @()",
        "Write-Output ('[' + $script:LcRawOut.Trim() + ']')",
    ])
    out = _pwsh(script, tmp_path, name="rawstderr.ps1")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == '[{"result":"completed"}]', out.stdout


@needs_pwsh
@pytest.mark.parametrize("argv", [
    ["plain"], [""], ["with space"], ['with"quote'], ["back\\slash"], ["trail\\"],
    ["a\\\\b"], ['c:\\path with space\\'], ['say "hi"'], ["unicode-\u00e9\u00fc"],
    ["tab\there"], ['\\"odd'], ["a\\\\\\\"b"],
])
def test_F3_the_ARGV_ENCODER_round_trips_through_a_real_child(tmp_path, argv):
    """`ProcessStartInfo.ArgumentList` is .NET Core 2.1+; the target host is Windows PowerShell 5.1
    on .NET Framework, where it does not exist — so the framed launch could not run on the only
    platform it is for. Every token is now encoded once, here, by CreateProcess rules.

    Compared as EXACT ARRAYS against what the child actually received.

    **THE LIMIT, unchanged and load-bearing.** This proves the **pwsh/macOS child path and the
    encoder's output**, and nothing else. It is *not* evidence about Windows `CreateProcess`
    argument splitting or about Windows PowerShell 5.1 on .NET Framework — the host F3 exists for.
    Those remain **1246-10 live gates**. The CreateProcess *rules* the encoder implements are
    asserted on its output next door, in `test_F3_the_ENCODER_implements_CREATEPROCESS_QUOTING`.
    """
    ps1 = PS1.read_text(encoding="ascii")
    fns = "\n".join(_ps_function(ps1, n) for n in ("Encode-WindowsArgv", "Encode-WindowsCommandLine"))
    echoer = tmp_path / "echo_argv.py"
    echoer.write_text("import json,sys; print(json.dumps(sys.argv[1:]))")
    script = "\n".join([
        _ps_stubs(), fns,
        f"$argv = @({','.join(_ps_literal(a) for a in argv)})",
        f"$psi = New-Object System.Diagnostics.ProcessStartInfo",
        f"$psi.FileName = '{sys.executable}'",
        f"$psi.Arguments = Encode-WindowsCommandLine (@('{echoer}') + $argv)",
        "$psi.RedirectStandardOutput = $true; $psi.UseShellExecute = $false",
        "$p = [System.Diagnostics.Process]::Start($psi)",
        "$o = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()",
        "Write-Output $o",
    ])
    out = _pwsh(script, tmp_path, name="argv.ps1")
    assert out.returncode == 0, out.stderr
    # EXACT ARRAY COMPARISON. This asserted only that stdout was non-empty, which is not the claim
    # its name makes: an encoder that dropped or merged a token would have passed.
    received = json.loads(out.stdout.strip().splitlines()[-1])
    assert received == argv, f"child received {received!r}, not {argv!r}"


def test_F3_the_STANDALONE_UPDATER_uses_the_same_ARGV_ENCODER():
    """The SYSTEM updater cannot source the installer, so its required copy may not drift."""
    install = PS1.read_text(encoding="ascii")
    updater = (REPO / "installer/windows/corpusfm-update.ps1").read_text(encoding="ascii")

    def code(body: str) -> str:
        return "\n".join(line.strip() for line in body.splitlines()
                         if line.strip() and not line.lstrip().startswith("#"))

    for name in ("Encode-WindowsArgv", "Encode-WindowsCommandLine"):
        assert code(_ps_function(updater, name)) == code(_ps_function(install, name)), name


@needs_pwsh
@pytest.mark.parametrize("value,expected", [
    ("plain", "plain"),
    ("", '""'),
    ("with space", '"with space"'),
    ('with"quote', '"with\\"quote"'),
    ("back\\slash", "back\\slash"),
    ("trail\\", "trail\\"),
    ('c:\\path with space\\', '"c:\\path with space\\\\"'),
    ('a\\"b', '"a\\\\\\"b"'),
])
def test_F3_the_ENCODER_implements_CREATEPROCESS_QUOTING(tmp_path, value, expected):
    """The rules themselves, asserted on the encoder's output: a backslash run doubles only before a
    quote or the closing quote; an embedded quote is escaped; an empty argument becomes `""`; a
    value with no space, tab or quote is passed through untouched."""
    ps1 = PS1.read_text(encoding="ascii")
    fn = _ps_function(ps1, "Encode-WindowsArgv")
    script = "\n".join([_ps_stubs(), fn,
                        f"Write-Output ('[' + (Encode-WindowsArgv {_ps_literal(value)}) + ']')"])
    out = _pwsh(script, tmp_path, name="enc.ps1")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == f"[{expected}]", (value, out.stdout.strip(), expected)


def test_F3_the_LIFECYCLE_ARGUMENT_VECTOR_encodes_as_separate_tokens(tmp_path):
    """The real vector, with a request path carrying spaces, an apostrophe, a quote and a trailing
    backslash — the four shapes that break naive quoting."""
    if pwsh is None:
        pytest.skip("no PowerShell on this host")
    ps1 = PS1.read_text(encoding="ascii")
    fns = "\n".join(_ps_function(ps1, n) for n in ("Encode-WindowsArgv", "Encode-WindowsCommandLine"))
    path = 'C:\\Program Files\\CORPUSfm\\it\'s "run"\\req\\'
    script = "\n".join([
        _ps_stubs(), fns,
        f"$v = @('-m','corpusfm.lifecycle.cli','admin-identity','reconcile','--request',{_ps_literal(path)})",
        "Write-Output (Encode-WindowsCommandLine $v)",
    ])
    out = _pwsh(script, tmp_path, name="vector.ps1")
    assert out.returncode == 0, out.stderr
    line = out.stdout.strip()
    assert line.startswith("-m corpusfm.lifecycle.cli admin-identity reconcile --request ")
    encoded = line.split("--request ", 1)[1]
    assert encoded.startswith('"') and encoded.endswith('"')
    assert encoded.endswith('\\\\"'), "the trailing backslash run does not double before the quote"


@needs_pwsh
def test_F3_the_framed_launch_uses_ARGUMENTS_not_ARGUMENTLIST():
    ps1 = PS1.read_text(encoding="ascii")
    body = _ps_function(ps1, "Lc-RunFramedRaw")
    assert "ArgumentList" not in body, "the .NET Core-only API is back"
    assert "$psi.Arguments = Encode-WindowsCommandLine" in body
    # COMMENTS EXCLUDED: the prose explaining why there is no shell names the very things it
    # forbids, and a scan that reads it reports the rationale as the violation.
    code_only = "\n".join(l for l in ps1.splitlines() if not l.lstrip().startswith("#"))
    assert "Invoke-Expression" not in code_only and "cmd.exe" not in code_only
    assert "RedirectStandardInput" in body and "does not provide ProcessStartInfo" in body


@needs_pwsh
@pytest.mark.parametrize("child,expect_rc", [
    # writes a lot of stderr BEFORE reading stdin — the classic sequential-read deadlock
    ("import sys\nsys.stderr.write('x'*200000)\nsys.stderr.flush()\n"
     "sys.stdin.buffer.read()\nsys.stdout.write('{\"result\":\"completed\"}')", 0),
    # fills BOTH pipes beyond capacity, concurrently
    ("import sys\nsys.stdin.buffer.read()\nsys.stderr.write('e'*200000)\n"
     "sys.stdout.write('{\"result\":\"completed\",\"pad\":\"' + 'p'*200000 + '\"}')", 0),
    # ordinary success
    ("import sys\nsys.stdin.buffer.read()\nsys.stdout.write('{\"result\":\"completed\"}')", 0),
])
def test_F5_the_FRAMED_RUNNER_does_not_DEADLOCK(tmp_path, child, expect_rc):
    """Executed against children that fill a pipe before reading, and that fill both concurrently.
    Reading stdout to the end and only then stderr blocks on both."""
    ps1 = PS1.read_text(encoding="ascii")
    fn = "\n".join(_ps_function(ps1, n) for n in
                   ("Encode-WindowsArgv", "Encode-WindowsCommandLine", "Lc-RunFramedRaw"))
    script = "\n".join([
        _ps_stubs(),
        f"$script:Child = {_ps_literal(child)}",
        _must_substitute(fn, "(@('-m','corpusfm.lifecycle') + $LcArgs)", "@('-c', $script:Child)"),
        "$o = Lc-RunFramedRaw 'probe' @() 'admin' 'secret'",
        "Write-Output ('[' + $o.Trim() + ']')",
    ])
    out = _pwsh(script, tmp_path, name="framed.ps1")
    assert out.returncode == expect_rc, (out.returncode, out.stderr[:300])
    assert '"result":"completed"' in out.stdout, out.stdout[:200]


@needs_pwsh
def test_F5_a_CHILD_THAT_WAITS_FOREVER_is_terminated_and_refused(tmp_path):
    """Bounded, and the child is killed rather than left behind. Without the timeout the installer
    hangs with the services stopped and no way to report why."""
    ps1 = PS1.read_text(encoding="ascii")
    fn = "\n".join(_ps_function(ps1, n) for n in
                   ("Encode-WindowsArgv", "Encode-WindowsCommandLine", "Lc-RunFramedRaw"))
    child = "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(600)"
    script = "\n".join([
        _ps_stubs(timeout=3000),
        f"$script:Child = {_ps_literal(child)}",
        _must_substitute(fn, "(@('-m','corpusfm.lifecycle') + $LcArgs)", "@('-c', $script:Child)"),
        "Lc-RunFramedRaw 'probe' @() 'admin' 'secret'",
    ])
    out = _pwsh(script, tmp_path, name="hang.ps1")
    assert out.returncode == 9, (out.returncode, out.stdout, out.stderr[:200])
    assert "did not complete within" in out.stderr


@needs_pwsh
def test_F5_the_CREDENTIAL_IS_WIPED_on_every_path(tmp_path):
    body = _ps_function(PS1.read_text(encoding="ascii"), "Lc-RunFramedRaw")
    assert "finally" in body
    tail = body[body.index("} finally {"):]
    for cleared in ("[Array]::Clear", "$account = $null", "$password = $null", "$bytes = $null"):
        assert cleared in tail, f"{cleared} does not happen on the failure path"
    assert "Cfm-Logline $bytes" not in body and "Write-Host $password" not in body


@needs_pwsh
def test_F5_a_NONZERO_CHILD_WITH_A_REFUSAL_RESULT_is_preserved_for_disposition(tmp_path):
    ps1 = PS1.read_text(encoding="ascii")
    fn = "\n".join(_ps_function(ps1, n) for n in
                   ("Lc-IsOneJsonObject", "Encode-WindowsArgv",
                    "Encode-WindowsCommandLine", "Lc-RunFramedRaw"))
    child = ("import sys\nsys.stdin.buffer.read()\n"
             "sys.stdout.write('{\"result\":\"failed_before_change\"}')\nsys.exit(1)")
    script = "\n".join([
        _ps_stubs(),
        f"$script:Child = {_ps_literal(child)}",
        _must_substitute(fn, "(@('-m','corpusfm.lifecycle') + $LcArgs)", "@('-c', $script:Child)"),
        "$o = Lc-RunFramedRaw 'probe' @() 'admin' 'secret'",
        "Write-Output ('rc=' + $script:LcRawRc)",
        "Write-Output $o",
    ])
    out = _pwsh(script, tmp_path, name="refuse.ps1")
    assert out.returncode == 0
    assert "rc=1" in out.stdout and '"result":"failed_before_change"' in out.stdout


# ── F6 / F7: the PRODUCTION Linux blocks, EXECUTED ───────────────────────────────────

def test_F7_fms_present_IS_DEFINED_BEFORE_ITS_FIRST_CALL():
    """Bash defines functions in execution order, so a call above the definition exits 127 and
    `if fms_present` reads that as FALSE. The OData preflight — whose whole purpose is to fail early
    on an OData-disabled box — never ran on any install."""
    sh = SH.read_text(encoding="utf-8")
    definition = sh.index("fms_present() {")
    first_call = min(m.start() for m in re.finditer(r"^\s*if fms_present;", sh, re.M))
    assert definition < first_call, "fms_present is still called before it is defined"
    assert sh.count("fms_present() {") == 1, "there is more than one definition"


@pytest.mark.parametrize("fmsadmin,helper,expected", [
    (True, True, 0), (False, True, 1), (True, False, 1), (False, False, 1),
])
def test_F7_fms_present_EXECUTES_with_stubbed_fmsadmin_and_systemctl(tmp_path, fmsadmin, helper,
                                                                     expected):
    """The real function body, with the two commands it consults replaced by stubs."""
    sh = SH.read_text(encoding="utf-8")
    fn = _bash_function(sh, "fms_present")
    binroot = tmp_path / "bin"
    binroot.mkdir()
    if fmsadmin:
        (binroot / "fmsadmin").write_text("#!/bin/sh\nexit 0\n")
        (binroot / "fmsadmin").chmod(0o755)
    (binroot / "systemctl").write_text(f"#!/bin/sh\nexit {0 if helper else 3}\n")
    (binroot / "systemctl").chmod(0o755)
    script = "\n".join([f'PATH="{binroot}:/usr/bin:/bin"', fn,
                        "if fms_present; then exit 0; else exit 1; fi"])
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == expected, (fmsadmin, helper, out.returncode, out.stderr)


def test_F7_a_MUTATION_MOVING_THE_DEFINITION_BELOW_THE_CALL_is_caught(tmp_path):
    """The control: bash really does exit 127, and `if` really does read that as false."""
    sh = SH.read_text(encoding="utf-8")
    fn = _bash_function(sh, "fms_present")
    script = "\n".join(['PATH="/usr/bin:/bin"',
                        "if fms_present; then echo PRESENT; else echo ABSENT; fi", fn])
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.stdout.strip() == "ABSENT"
    assert "command not found" in out.stderr or "not found" in out.stderr


@pytest.mark.parametrize("published,expected", [
    ("https://fms.example.test/corpusfm", "https://fms.example.test/corpusfm"),
    ("", "https://<your-fms-host>/corpusfm"),
])
def test_F6_the_DISPLAY_BASE_is_defined_under_set_u(tmp_path, published, expected):
    """`CFM_BASE` was read three times and assigned nowhere, so `set -u` aborted the final summary —
    AFTER phase 21 had started the services. The install worked and reported a crash.

    Executed with the real derivation block and a stub interpreter, under `set -u`."""
    sh = SH.read_text(encoding="utf-8")
    start = sh.index('CFM_BASE="$(PYTHONPATH=')
    end = sh.index("\n", sh.index('[[ -n "${CFM_BASE:-}" ]] || CFM_BASE='))
    block = sh[start:end]
    stub_dir = tmp_path / "venv" / "bin"
    stub_dir.mkdir(parents=True)
    (stub_dir / "python").write_text(f"#!/bin/sh\nprintf '%s' {published!r}\n")
    (stub_dir / "python").chmod(0o755)
    script = "\n".join(["set -euo pipefail", f'INSTALL_DIR="{tmp_path}"', 'WEB_PREFIX=/corpusfm',
                        block, 'printf "%s" "$CFM_BASE"'])
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout == expected, (out.stdout, expected)


def test_F6_the_PLACEHOLDER_is_never_consumed_by_configuration():
    """It is a display string. A routing or configuration path that read it would be taking a
    literal `<your-fms-host>` as authority."""
    sh = SH.read_text(encoding="utf-8")
    for line in sh.splitlines():
        if "CFM_BASE" not in line or line.lstrip().startswith("#"):
            continue
        assert re.search(r"(CFM_BASE=|echo |printf )", line), (
            f"CFM_BASE is consumed outside the operator display: {line.strip()[:100]}"
        )
    assert "<your-fms-host>" in sh
    # …and it is derived BEFORE the first line that displays it.
    assert sh.index('CFM_BASE="$(PYTHONPATH=') < sh.index('echo "  Web UI:    ${CFM_BASE}/')
