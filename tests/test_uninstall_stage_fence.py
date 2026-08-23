"""The stage fence for packet 1246-09, enforced structurally.

Stages 1-3 shipped **authority, observation, planning and durable evidence**. Nothing in them may
delete, stop, register, deregister, or ask for a credential — and the reason to enforce that with a
test rather than with care is that the fence's whole value is being true *while the executor stages
are being written*, by someone who did not read this packet.

**Stage 4 added the two executors and stage 5 added the resume driver**, so neither is forbidden —
but the line moved rather than disappearing, and it has moved twice now. What it still holds:
`uninstall_inventory` and `uninstall_plan` observe and decide and do nothing else; `uninstall_pending`
may remove exactly ONE file — its own record, through `discard`, which re-establishes five conditions
first; the executors may not retire their own authority; and **neither shipped uninstaller may reach
any of it**, because stage 6 owns the launchers.

**Two things this guard must not do**, both learned from guards in this repository that got them
wrong:

* it must exclude COMMENTS from its scan, because the modules it polices necessarily explain in
  prose what they do not do — a guard that reports its own rationale as a violation is noise;
* it must fail if the modules it polices go missing, so deleting the subject cannot pass the test.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from application_checkout import APPLICATION_ROOT

ROOT = Path(__file__).resolve().parent.parent
LIFECYCLE = APPLICATION_ROOT / "corpusfm" / "lifecycle"

#: The modules that decide and observe and must never act. `uninstall_pending` LEFT this set at
#: stage 5: `discard` removes the record, which is a destructive call, and a fence that forbade it
#: would have to be either disabled or lied to. It is policed by its own narrower guard below
#: instead — one that says exactly which removal is permitted — because "this module removes nothing"
#: and "this module removes exactly its own record and nothing else" are different claims and only
#: the second one is now true.
FENCED = ("uninstall_inventory.py", "uninstall_plan.py")

#: The record module, and the ONE unlink it is allowed. Anything else destructive here is a module
#: that has grown a second capability while nobody was looking.
RECORD_MODULE = "uninstall_pending.py"

#: Stage 4 added exactly these two, and no more. Named so the fence is a statement about what the
#: stage produced rather than a wildcard that would stop noticing a third.
EXECUTOR_MODULES = ("uninstall_exec_posix.py", "uninstall_exec_windows.py")

#: Stage 5's deliverable. It existed as a prohibition until stage 5 executed; the prohibition is now
#: its opposite, so that deleting the driver cannot pass the guard that used to forbid it.
RESUME_MODULE = "uninstall_resume.py"

#: Calls that delete, mutate a service, reach FileMaker Server, or acquire a credential. Matched on
#: the CALLED NAME in the AST, so a mention in a docstring or a comment is invisible to it.
FORBIDDEN_CALLS = {
    "rmtree", "unlink", "rmdir", "remove", "removedirs",
    "getpass", "askpass",
    "check_call", "check_output", "Popen", "run", "call",
    # Added after a blind review pointed out the obvious hole: `os` is legitimately imported here,
    # so `os.system("rm -rf ...")` was structurally invisible to a guard whose whole purpose is
    # catching a destructive call added by someone who never read this packet.
    "system", "popen", "exec", "eval", "compile",
    "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp",
    "spawnv", "spawnve", "spawnl", "spawnle", "spawnvp", "posix_spawn", "fork", "forkpty",
}

#: Names whose mere appearance in CODE would mean this layer had grown a capability it must not have.
FORBIDDEN_NAMES = {"shutil", "subprocess", "fmsadmin", "winreg"}

#: The retired vocabulary. Relocation was designed out, not recovered from; if the word comes back,
#: so has the torn-relocation window.
RETIRED_VOCABULARY = ("relocate", "relocation")

#: (receiver, name) pairs that share a forbidden name and are not the forbidden thing.
_INNOCENT = {("re", "compile"), ("json", "load"), ("json", "loads")}


def _module_source(name: str) -> str:
    path = LIFECYCLE / name
    assert path.exists(), f"{name} is fenced by this guard and is missing; deleting the subject of a guard must not pass it"
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", FENCED)
def test_a_fenced_module_performs_no_destructive_or_privileged_call(name):
    tree = ast.parse(_module_source(name))
    offences = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if called in FORBIDDEN_CALLS:
                # `os.remove` deletes; `str.remove` does not exist; a local helper named `run` would
                # be a false positive, so the receiver is reported for a human to read.
                receiver = getattr(getattr(func, "value", None), "id", "?")
                # `re.compile` is a regex, not code execution. The forbidden `compile`/`exec`/`eval`
                # are the BUILTINS — a receiver-blind match reported the module's own UUID pattern
                # as a violation, which is the noise that gets a guard deleted.
                if (receiver, called) in _INNOCENT:
                    continue
                offences.append(f"{name}:{node.lineno} calls {receiver}.{called}")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_NAMES:
                    offences.append(f"{name}:{node.lineno} imports {alias.name}")
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in FORBIDDEN_NAMES:
                offences.append(f"{name}:{node.lineno} imports from {node.module}")
    assert not offences, offences


def test_stage_5_added_the_resume_driver():
    assert (LIFECYCLE / RESUME_MODULE).exists(), (
        f"{RESUME_MODULE} is stage 5's deliverable and is missing")


def test_the_record_module_removes_ITS_OWN_RECORD_and_nothing_else():
    """`discard` earns one `os.unlink`, of `pending_path(layout)`. The guard is narrow on purpose:
    the module went from *removes nothing* to *removes exactly one thing*, and the second claim is
    only worth having if something checks the *exactly*."""
    tree = ast.parse(_module_source(RECORD_MODULE))
    removals = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if called in FORBIDDEN_CALLS and (
                    getattr(getattr(func, "value", None), "id", "?"), called) not in _INNOCENT:
                removals.append((node.lineno, called))
    assert [c for _line, c in removals] == ["unlink"], removals
    source = _module_source(RECORD_MODULE)
    assert "os.unlink(str(path))" in source
    assert "path = pending_path(layout)" in source, (
        "the removal target must be derived from the layout, never from a caller")


def test_the_record_module_still_imports_no_privileged_capability():
    """The half of the old fence that did not move: no shell, no subprocess, no registry, no
    credential prompt. Removing one file did not make this a module that runs things."""
    tree = ast.parse(_module_source(RECORD_MODULE))
    offences = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_NAMES:
                    offences.append(f"{RECORD_MODULE}:{node.lineno} imports {alias.name}")
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in FORBIDDEN_NAMES:
                offences.append(f"{RECORD_MODULE}:{node.lineno} imports from {node.module}")
        if isinstance(node, ast.Call):
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if called in {"getpass", "askpass", "system", "popen", "exec", "eval"} and (
                    getattr(getattr(func, "value", None), "id", "?"), called) not in _INNOCENT:
                offences.append(f"{RECORD_MODULE}:{node.lineno} calls {called}")
    assert not offences, offences


@pytest.mark.parametrize("name", EXECUTOR_MODULES)
def test_stage_4_added_exactly_the_two_executors(name):
    assert (LIFECYCLE / name).exists(), f"{name} is stage 4's deliverable and is missing"


def test_the_executors_retire_nothing_and_finalize_nothing():
    """**Stage 5 owns the tail**, and the guard is structural rather than a promise in prose: the
    executors may not discard the pending record, remove the locator, resolve the journal, or
    checkpoint. An executor that could retire its own authority is the RC4 this packet exists to
    prevent, and it is one plausible-looking line away at every call site."""
    forbidden = {"discard", "checkpoint", "publish", "resolve", "remove_locator"}
    for name in EXECUTOR_MODULES:
        tree = ast.parse(_module_source(name))
        offences = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if called in forbidden:
                    offences.append(f"{name}:{node.lineno} calls {called}")
        assert not offences, offences


@pytest.mark.parametrize("name", FENCED)
def test_the_retired_relocation_vocabulary_does_not_return(name):
    """Scanned over CODE ONLY. The modules explain in prose that relocation was designed out, and a
    guard that flagged its own rationale would be deleted by the next person who read it."""
    tree = ast.parse(_module_source(name))
    code_strings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            code_strings.append(node.id)
        elif isinstance(node, ast.Attribute):
            code_strings.append(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            code_strings.append(node.name)
    offenders = [s for s in code_strings
                 if any(word in s.lower() for word in RETIRED_VOCABULARY)]
    assert not offenders, offenders


#: The two launchers, and the ONE boundary either of them may reach.
LAUNCHERS = ("installer/linux/uninstall.sh", "installer/windows/uninstall.ps1")

#: **The fence, INVERTED at stage 6.** Until the launchers existed, the rule was that neither could
#: reach any of this packet's modules — they were the retired implementation and had to stay out of
#: the way. Now they are the launchers, and the rule is the other way round: the ONLY lifecycle
#: surface either may name is the shipped CLI, because everything a launcher could reach past it is
#: a decision it has no business making.
FORBIDDEN_TO_LAUNCHERS = ("uninstall_inventory", "uninstall_plan", "uninstall_pending",
                          "uninstall_exec_posix", "uninstall_exec_windows", "uninstall_resume",
                          "uninstall_runtime",
                          "service_binding", "proxy_transaction", "storage_identity",
                          "admin_identity", "patch_compartment", "composition")

#: Vocabulary that can only be there because a launcher started ACTING again. Each one names a
#: capability §H classified as RC5 or RC3 in the retired scripts, or an authority the CLI owns.
#:
#: **The retired OPTION NAMES are deliberately not on this list.** Windows declares them so it can
#: refuse them by name, which is the behaviour stage 6 wants — an option that is silently ignored
#: reports success on terms it never honoured. They are checked for REFUSAL below instead, which is
#: the rule; their absence would be a spelling.
LAUNCHER_MUST_NOT_ACT = (
    "removed_by_fms",           # RC5: a recursive name search inside FMS's own recovery folder
    "userdel",                  # direct account removal
    "systemctl", "sc.exe",      # direct service control
    "ufw",                      # direct firewall mutation
    ".fmp12",                   # a database name, or a search for one
    "additionaldatabasefolder", # the folder slot; the CLI deregisters it
)

#: The only thing a launcher may remove: the temporary request material it created itself. A removal
#: line that does not name one of these is a removal aimed at the installation.
LAUNCHER_MAY_REMOVE = ("lc_req_dir", "lcreqdir", "request", "errfile")


@pytest.mark.parametrize("script", LAUNCHERS)
def test_a_launcher_reaches_ONLY_the_shipped_uninstall_cli(script):
    """**The inverted fence.** A launcher may name `corpusfm.lifecycle` and nothing else in this
    package: every module behind it decides what may be removed, and a shell script that imported one
    of them would be re-acquiring exactly the authority stage 6 took away.
    """
    text = (ROOT / script).read_text(encoding="utf-8", errors="replace")
    assert "-m corpusfm.lifecycle" in text, f"{script} must call the shipped CLI"
    assert "-m corpusfm.lifecycle.cli" not in text, \
        f"{script} calls the import-only cli.py instead of the runnable package"
    for module in FORBIDDEN_TO_LAUNCHERS:
        assert module not in text, f"{script} reaches {module}; a launcher may reach only the CLI"


@pytest.mark.parametrize("script", LAUNCHERS)
def test_a_launcher_carries_NO_DELETION_and_NO_TARGET_AUTHORITY(script):
    """Every never-owned-resource invariant, held where it can be held statically.

    **Comments are excluded from the scan**, and that exclusion is load-bearing here more than
    anywhere: these two files explain at length what they no longer do, so a guard that read its own
    subject's rationale as a violation would be noise — the mistake this repository has made twice.
    """
    code = _executable_lines(ROOT / script)
    body = "\n".join(code).lower()
    for word in LAUNCHER_MUST_NOT_ACT:
        assert word not in body, f"{script} still contains {word!r} in executable code"
    # **The removal verbs, and what they are aimed at.** A launcher genuinely does remove one thing —
    # the temporary request material it created — so a blanket ban would be a rule nobody could
    # follow. Every removal must name that material and nothing else.
    for line in code:
        lowered = line.lower()
        if any(verb in lowered for verb in ("rm -rf", "rm -f", "remove-item")):
            assert any(allowed in lowered for allowed in LAUNCHER_MAY_REMOVE), (
                f"{script} removes something that is not its own request material: {line.strip()!r}")


def _executable_lines(path) -> list:
    """The file's code, with comments removed.

    **Excluding comments is load-bearing here more than anywhere**: these two files explain at length
    what they no longer do, so a guard that read its own subject's rationale as a violation would be
    noise — the mistake this repository has made twice and written down both times.
    """
    lines = []
    in_block = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if path.suffix == ".ps1":
            if stripped.startswith("<#"):
                in_block = True
            if in_block:
                if "#>" in stripped:
                    in_block = False
                continue
        if stripped.startswith("#"):
            continue
        lines.append(line.split("#")[0] if "#" in line else line)
    return lines


@pytest.mark.parametrize("script", LAUNCHERS)
def test_a_launcher_accepts_ONLY_the_four_options(script):
    """`--yes` · `--force` · `--silent` · `--verbose`, and every retired option refused as unknown.

    Two of the retired ones were RC5 in the scripts they came from: `-InstallRoot` and `-ConfigHome`
    reached a recursive `Remove-Item` from free-form argv.
    """
    text = (ROOT / script).read_text(encoding="utf-8", errors="replace")
    code = _executable_lines(ROOT / script)
    kept = ("--yes", "--force", "--silent", "--verbose") if script.endswith(".sh") \
        else ("$Yes", "$Force", "$Silent", "$VerbosePreference")
    for option in kept:
        assert option in text, f"{script} must accept {option}"

    if script.endswith(".sh"):
        # A `case` with a catch-all that DIES. Anything not in the four arms is unknown, so the
        # retired options need no enumeration to be refused — and none is declared.
        joined = "\n".join(code)
        assert "Unknown option" in joined and "die " in joined
        for retired in ("--keep-data", "--fm-admin-user", "--fm-admin-pass", "--install-root",
                        "--config-home"):
            assert f"{retired})" not in joined, f"{script} still has a case arm for {retired}"
    else:
        # PowerShell binds an unknown parameter with its own error and a positional value binds
        # silently, so the retired ones are DECLARED in order to be refused. Every executable line
        # that mentions one must be either its declaration or the refusal that collects it.
        # The refusal REGION: everything between collecting the retired options and refusing them.
        # A mention outside it, and outside the param block, is a USE.
        opens = [i for i, line in enumerate(code) if "$retired = @()" in line]
        closes = [i for i, line in enumerate(code) if "$retired.Count" in line]
        assert opens and closes and closes[0] > opens[0], f"{script} has no refusal region"
        region = range(opens[0], closes[0] + 1)
        for retired in ("$KeepData", "$InstallRoot", "$ConfigHome", "$FmAdminPass",
                        "$FmAdminUser", "$Site", "$FmsRoot"):
            mentions = [i for i, line in enumerate(code) if retired in line]
            assert mentions, f"{script} must declare {retired} so it can refuse it"
            for index in mentions:
                stripped = code[index].strip()
                is_declaration = stripped.startswith("[string]") or stripped.startswith("[switch]")
                assert is_declaration or index in region, (
                    f"{script} USES {retired} at {stripped!r}; it may only refuse it")
        assert "Unknown option(s)" in "\n".join(code)


@pytest.mark.parametrize("script", LAUNCHERS)
def test_a_launcher_holds_only_a_plan_requested_transient_credential(script):
    """Current launchers validate the one-use credential named by the typed plan, frame it to one
    lifecycle process, and wipe it. They never persist it or accept it through argv."""
    text = (ROOT / script).read_text(encoding="utf-8", errors="replace")
    assert "credential_transport" in text
    assert "credential_required" in text
    assert "used for this run only" in text
    assert "lc_fms_frame" in text or "Lc-InvokeFramed" in text
    assert "FM_ADMIN_PASS=" in text or "$planPass" in text or "$script:LcCredentialPass" in text
    assert ("unset FM_ADMIN_PASS" in text or "$planPass = ''" in text
            or "$script:LcCredentialPass = ''" in text)


def test_discard_still_refuses_without_the_authority_it_now_requires():
    """`discard` used to be an interface that raised. It is implemented now, and what replaced the
    refusal is not permission — it is five conditions, the first of which is the held lock. Called
    with no authority at all it must still refuse, or the fence has simply been removed."""
    from corpusfm.lifecycle import uninstall_pending
    from corpusfm.lifecycle.lock import LockNotHeld

    source = _module_source(RECORD_MODULE)
    assert "def discard(" in source
    with pytest.raises(LockNotHeld):
        uninstall_pending.discard(object(), operation_id="x", installation_id="y",
                                  lock=object())


def test_neither_executor_nor_the_record_module_finalizes_on_its_own():
    """The tail belongs to the driver. An executor or the record module reaching the locator would
    be the RC4 this packet exists to prevent, one plausible-looking line at a time."""
    for name in EXECUTOR_MODULES + (RECORD_MODULE,):
        source = _module_source(name)
        assert "locator_for" not in source, f"{name} reaches the locator"
        assert "remove_locator" not in source
