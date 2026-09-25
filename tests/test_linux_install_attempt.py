"""Packet 1398 — the Linux installer's fresh-install attempt: writer, wrappers, routing.

**What is real.** The attempt-record writer is the exact `LA_WRITER` text embedded in
`installer/linux/install.sh`, executed by a real Python interpreter against a real temporary
container; the records it writes are read back by the APPLICATION's own validator and classifier
(`corpusfm.lifecycle.install_attempt`). The shell wrappers and the rerun router are the exact
functions from `install.sh`, executed by `bash`.

**What is doubled.** The container lives under a temporary root owned by this test's uid instead of
root; the lifecycle CLI the router talks to is a fake that answers fixed JSON; `/run` request
directories are redirected into the temporary root. No systemd unit, firewall rule, package, account
or FileMaker Server is touched.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from corpusfm.lifecycle import install_attempt as ia
from corpusfm.lifecycle.errors import RecordInvalid

from tests.installer_sim.harness import extract_sh_func

REPO = Path(__file__).resolve().parents[1]
SH = REPO / "installer" / "linux" / "install.sh"
TEXT = SH.read_text(encoding="utf-8")
_WRITER = re.search(r"IFS= read -r -d '' LA_WRITER <<'PY' \|\| true\n(.*?)\nPY\n", TEXT, re.S)
assert _WRITER, "install.sh carries no LA_WRITER block"
WRITER = _WRITER.group(1)
ATTEMPT = "11111111-2222-4333-8444-555555555555"
INSTALLATION = "6f1d0d2a-2f1e-4c3b-9a77-1b2c3d4e5f60"
UID = os.getuid()


def code(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


class Box:
    def __init__(self, root: Path):
        self.root = root
        (root / "etc").mkdir(mode=0o755)
        os.chmod(root / "etc", 0o755)
        # The fixed parents a real Ubuntu box always has; the attempt never records them.
        for parent in ("opt", "var/lib", "var/log", "run", "usr/local"):
            (root / parent).mkdir(parents=True, exist_ok=True)
        self.container = root / "etc" / "corpusfm-attempt"
        fms = root / "opt" / "FileMaker" / "FileMaker Server"
        self.paths = {
            "install_dir": str(root / "opt" / "CORPUSfm"),
            "patch_hosting_dir": str(root / "opt" / "CORPUSfm-Hosted"),
            "fms_root": str(fms), "fms_database_dir": str(fms / "Data" / "Databases"),
            "config_dir": str(root / "etc" / "corpusfm"),
            "state_dir": str(root / "var" / "lib" / "corpusfm" / "state"),
            "secrets_dir": str(root / "var" / "lib" / "corpusfm" / "secrets"),
            "log_dir": str(root / "var" / "log" / "corpusfm"),
            "run_dir": str(root / "run" / "corpusfm"),
        }
        self.storage_target = str(fms / "Data" / "Databases" / "CORPUSfm" / "CORPUSfm_DB.fmp12")

    def run(self, *args, stdin=None, check=True):
        proc = subprocess.run([sys.executable, "-I", "-c", WRITER, *map(str, args)],
                              input=stdin, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise AssertionError(f"writer {args[0]} failed: {proc.stderr}")
        return proc

    def begin(self, package="null"):
        return self.run("begin", self.container, UID, ATTEMPT, INSTALLATION,
                        json.dumps(self.paths), package)

    def step(self, kind, intent, extra, *targets):
        out = self.run("step", self.container, UID, kind, intent, extra, *targets).stdout.split()
        return [int(s) for s in out]

    def result(self, state, extra, seqs):
        if seqs:
            self.run("result", self.container, UID, state, extra, *seqs)

    def post(self, intent, rc, output=""):
        return self.run("provider-post", intent, rc, '["fms-nginx","apache"]', stdin=output).stdout

    def raw(self):
        return json.loads((self.container / "attempt.json").read_text())

    def record(self):
        return ia.read_record(_Layout(self.root), ia.Protection(posix_owner_uid=UID))


class _Layout:
    """Just enough of a POSIX lifecycle layout for `attempt_paths`."""

    kind = "posix"

    def __init__(self, root):
        self.locator_dir = root / "etc" / "corpusfm"


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


# ── vocabulary, refuse-first set and interpreter parity ──────────────────────────


def _literal(name):
    tree = ast.parse(WRITER)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(name)


def test_the_writer_vocabulary_is_exactly_the_applications_posix_vocabulary():
    writer = {kind: set(intents) for kind, intents in _literal("KINDS").items()}
    app = {kind: set(intents) for kind, intents in ia.LEDGER_VOCABULARY.items()}
    windows_or_application_only = {"service", "task", "iis_setting", "journal"}
    expected = {kind: intents - {"set_acl"} for kind, intents in app.items()
                if kind not in windows_or_application_only}
    assert writer == expected


def test_the_writer_runs_on_the_oldest_supported_system_interpreter():
    """Ubuntu 20.04's fixed `/usr/bin/python3` is 3.8 — the writer may use nothing newer."""
    ast.parse(WRITER, feature_version=(3, 8))
    assert "removeprefix" not in WRITER and "match " not in WRITER


def test_the_refuse_first_set_is_the_packet_list(box):
    for relative in ("opt/CORPUSfm", "etc/corpusfm/install.yaml",
                     "etc/systemd/system/corpusfm.service",
                     "etc/systemd/system/corpusfm-update.service", "usr/local/bin/corpusfm",
                     "etc/sudoers.d/corpusfm-db-helper", "etc/sudoers.d/corpusfm-update",
                     "etc/tmpfiles.d/corpusfm.conf"):
        target = box.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.mkdir() if relative == "opt/CORPUSfm" else target.write_text("x")
    refused = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert refused.returncode == 3
    assert len(refused.stdout.split("\n")) - 1 == 8
    moved = box.run("refuse-check", json.dumps(box.paths), "true", check=False)
    assert box.paths["install_dir"] not in moved.stdout and len(moved.stdout.split("\n")) - 1 == 7
    assert not box.container.exists(), "a refuse-first check creates nothing"


# ── the write-ahead ledger, read back by the application ──────────────────────────


def test_a_walk_over_every_linux_entry_validates_and_classifies_in_the_application(box):
    Path(box.paths["log_dir"]).mkdir()                              # the transcript's own directory
    box.begin()
    sha = "0" * 64

    def do(kind, intent, extra, *targets, mutate=None, state="done", post_extra="-"):
        seqs = box.step(kind, intent, extra, *targets)
        if mutate:
            mutate()
        box.result(state, post_extra, seqs)
        return seqs

    etc = do("dir", "ensure", "-", box.paths["config_dir"],
             mutate=lambda: Path(box.paths["config_dir"]).mkdir())
    state = do("dir", "ensure", "-", box.paths["state_dir"],
               mutate=lambda: Path(box.paths["state_dir"]).mkdir(parents=True))
    assert len(etc) == 1 and len(state) == 2, "the implicit /var/lib/corpusfm parent is recorded"
    assert do("dir", "ensure", "-", box.paths["secrets_dir"],
              mutate=lambda: Path(box.paths["secrets_dir"]).mkdir()) == [], "contained"
    logs = do("dir", "ensure", "-", box.paths["log_dir"])
    shim = str(box.root / "usr" / "local" / "bin" / "corpusfm")

    def write_shim():
        Path(shim).parent.mkdir()
        Path(shim).write_text("#!/bin/sh\n")

    do("file", "ensure", "-", shim, mutate=write_shim)
    do("account", "create", "-", "corpusfm-attempt-test-nobody", state="failed")
    do("package_set", "install_packages", '{"packages":{"rsync":false}}', "apt",
       post_extra='{"packages":{"rsync":true}}')
    git = str(box.root / "root" / ".gitconfig")
    do("git_config_entry", "append", '{"values":[]}', git, post_extra='{"values":["/tmp/x"]}')
    unit = str(box.root / "etc" / "systemd" / "system" / "corpusfm.service")

    def write_unit():
        Path(unit).parent.mkdir(parents=True)
        Path(unit).write_text("[Unit]\n")

    do("unit", "ensure", "-", unit, mutate=write_unit)
    do("unit", "enable", '{"enabled":false}', unit, post_extra='{"enabled":true}')
    do("firewall_rule", "delete", '{"rule":"allow 8533/tcp","exists":true}', "allow 8533/tcp",
       post_extra='{"rule":"allow 8533/tcp","exists":false}')
    assert box.step("file", "delete", "-", str(box.root / "etc" / "absent")) == []
    hosting = do("dir", "ensure", "-", box.paths["patch_hosting_dir"],
                 mutate=lambda: Path(box.paths["patch_hosting_dir"]).mkdir(parents=True))
    for intent, prior, output in (
            ("foundation", '{"locator":false,"manifest":false}', '{"generation":1}'),
            ("provision_keys", '{"corpus_key":false,"machine_key":false,"session_secret":false}',
             '{"result":"completed","keys":[{"name":"corpus.key","action":"generated"}]}'),
            ("admin_identity_reconcile", '{"observe":"NOT_INSTALLED"}', '{"result":"completed"}'),
            ("patch_apply", json.dumps({"hosting_dir_seq": hosting[-1]}), "not json"),
            ("proxy_reconcile", '{"blocks":{"fms-nginx":"BLOCK_ABSENT"}}', "{}")):
        do("provider_op", intent, prior, intent, post_extra=box.post(intent, 0, output))
    storage = box.step("file", "ensure", "-", box.storage_target)
    target_seq = storage[-1]
    provider = box.step("provider_op", "storage_bootstrap",
                        json.dumps({"observe": "proven_fresh", "route": "bootstrap",
                                    "target_seq": target_seq}), "storage")
    Path(box.storage_target).parent.mkdir(parents=True)
    Path(box.storage_target).write_bytes(b"fmp12")
    box.result("done", box.post("storage_bootstrap", 0, '{"result":"completed"}'), provider)
    box.result("done", "-", storage)
    do("provider_op", "backfill_storage_projections",
       json.dumps({"target_seq": target_seq, "route": "bootstrap"}), "storage",
       state="failed", post_extra=box.post("backfill_storage_projections", 1))
    do("provider_op", "create_first_admin", '{"users_exist":false}', "first_admin",
       post_extra=box.post("create_first_admin", 0, '{"result":"completed"}'))
    do("provider_op", "retire_scheduler_authority", "{}", "a001",
       post_extra=box.post("retire_scheduler_authority", 0, '{"result":"no_change"}'))

    record = box.record()                      # protected read + closed validation, by the app
    classify = lambda target, kind: ia.classify_target(record, target, kind)[0]
    assert classify(box.paths["config_dir"], "dir") == ia.CLASS_CREATED
    assert classify(str(Path(box.paths["state_dir"]).parent), "dir") == ia.CLASS_CREATED
    assert classify(box.paths["secrets_dir"], "dir") == ia.CLASS_CREATED
    assert classify(box.paths["log_dir"], "dir") == ia.CLASS_MODIFIED
    assert classify(shim, "file") == ia.CLASS_CREATED
    assert classify(unit, "unit") == ia.CLASS_CREATED
    assert classify(box.storage_target, "file") == ia.CLASS_CREATED
    patch = [e for e in record.ledger if e.intent == "patch_apply"][0]
    assert patch.post["settled"] is True, "unreadable patch facts never authorize removal"
    backfill = [e for e in record.ledger if e.intent == "backfill_storage_projections"][0]
    assert (backfill.state, backfill.post) == ("failed", {"result": "incomplete_safe"})
    assert logs and ia.manual_commands(record, _Layout(box.root))[-1].endswith("attempt.json'")


def test_refuse_first_happens_at_step_one_and_publishes_no_intent(box):
    shim = box.root / "usr" / "local" / "bin" / "corpusfm"
    shim.parent.mkdir(parents=True)
    shim.write_text("foreign")
    box.begin()
    refused = box.run("step", box.container, UID, "file", "ensure", "-", shim, check=False)
    assert refused.returncode == 3 and "REFUSE-FIRST" in refused.stderr
    assert box.raw()["ledger"] == []


def test_a_root_the_attempt_created_is_not_refused_when_touched_again(box):
    box.begin()
    seqs = box.step("dir", "ensure", "-", box.paths["install_dir"])
    Path(box.paths["install_dir"]).mkdir(parents=True)
    box.result("done", "-", seqs)
    again = box.step("dir", "ensure", "-", box.paths["install_dir"])
    assert [box.raw()["ledger"][s - 1]["intent"] for s in again] == ["set_owner_mode"]
    assert ia.classify_target(box.record(), box.paths["install_dir"], "dir")[0] == ia.CLASS_CREATED


def test_a_move_aside_records_the_prior_root_and_the_new_root_is_created(box):
    old = Path(box.paths["install_dir"])
    old.mkdir(parents=True)
    (old / "unrelated.txt").write_text("keep")
    box.begin()
    aside = str(old) + ".replaced-1"
    seqs = box.step("dir", "move_aside", "-", str(old))
    old.rename(aside)
    box.result("done", json.dumps({"moved_to": aside}), seqs)
    created = box.step("dir", "ensure", "-", str(old))
    old.mkdir()
    box.result("done", "-", created)
    record = box.record()
    assert record.ledger[0].post == {"exists": False, "moved_to": aside}
    assert ia.classify_target(record, str(old), "dir")[0] == ia.CLASS_CREATED


def test_an_interrupted_step_leaves_an_intended_entry_the_application_accepts(box):
    box.begin()
    box.step("dir", "ensure", "-", box.paths["install_dir"])       # the process dies here
    Path(box.paths["install_dir"]).mkdir(parents=True)
    record = box.record()
    assert record.ledger[0].state == "intended"
    assert ia.classify_target(record, box.paths["install_dir"], "dir")[0] == ia.CLASS_CREATED


def test_unreadable_proxy_facts_report_every_front_as_preexisting(box):
    post = json.loads(box.post("proxy_reconcile", 3, "Traceback: nothing useful"))
    assert post["result"] == "manual_action_required"
    assert set(post["prior_family"]) == {"fms-nginx", "apache"}
    assert all(f["pool_existed"] and f["app_existed"] for f in post["prior_family"].values())


@pytest.mark.parametrize("prepare", [
    lambda c: (c.mkdir(mode=0o755), os.chmod(c, 0o755)),
    lambda c: (c.mkdir(mode=0o700), (c / "note.txt").write_text("?")),
    lambda c: (c.mkdir(mode=0o700), (c / "attempt.json").write_text("{}")),
    lambda c: (c.parent.joinpath("elsewhere").mkdir(mode=0o700),
               c.symlink_to(c.parent / "elsewhere")),
])
def test_begin_refuses_a_container_it_cannot_adopt(box, prepare):
    prepare(box.container)
    refused = box.run("begin", box.container, UID, ATTEMPT, INSTALLATION, json.dumps(box.paths),
                      "null", check=False)
    assert refused.returncode == 3


def test_begin_adopts_an_empty_protected_container_with_staging_residue(box):
    box.container.mkdir(mode=0o700)
    (box.container / ".attempt.json.abc.tmp").write_text("partial")
    box.begin()
    assert sorted(os.listdir(box.container)) == ["attempt.json"]
    assert box.record().phase == ia.PHASE_INSTALLING


# ── the shell wrappers ────────────────────────────────────────────────────────────

WRAPPERS = ("la_py", "la_fatal", "la_step", "la_result", "la_do", "la_enabled_json",
            "la_unit_toggle", "la_ufw_present", "la_ufw_delete", "la_packages_json", "la_packages",
            "la_git_global_file", "la_git_global_append", "la_provider_begin", "la_provider_end",
            "la_lc_run", "la_begin", "la_end", "la_seq_of", "la_created")


def sh_func(name: str) -> str:
    """One function's text; a one-line `name() { …; }` is taken from its own line."""
    one_line = re.search(r"^%s\(\) \{.*\}$" % re.escape(name), TEXT, re.M)
    return one_line.group(0) if one_line else extract_sh_func(name)


def shell(body: str, *, attempt: bool, box: Box | None, tmp_path: Path, extra_bin=None):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    # A recording "python" proves the ordinary path never reaches the writer at all.
    (fake_bin / "recording-python").write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 99\n')
    (fake_bin / "recording-python").chmod(0o755)
    for name, text in (extra_bin or {}).items():
        (fake_bin / name).write_text("#!/bin/sh\n" + text + "\n")
        (fake_bin / name).chmod(0o755)
    funcs = "\n".join(sh_func(name) for name in WRAPPERS)
    script = f"""set -euo pipefail
exec 9>&2
die() {{ printf 'DIE: %s\\n' "$*" >&2; exit 1; }}
lc_json_array() {{ printf '["fms-nginx"]'; }}
CFM_PROXY_TYPES=(fms-nginx)
IFS= read -r -d '' LA_WRITER <<'PY' || true
{WRITER}
PY
CFM_ATTEMPT={'true' if attempt else 'false'}
CFM_ATTEMPT_DIR={box.container if box else '/nonexistent'}
CFM_ATTEMPT_UID={UID}
CFM_ATTEMPT_PY={sys.executable if attempt else fake_bin / 'recording-python'}
LA_SEQS=""; LA_PROVIDER_SEQS=""; LA_PROVIDER_TARGET_SEQS=""
{funcs}
{body}
"""
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    return proc, (log.read_text() if log.exists() else "")


def test_every_wrapper_is_a_pass_through_without_an_attempt(tmp_path):
    body = r"""
out="$(la_do dir ensure - /x -- printf '%s|' a 'b c')"; [[ "$out" == "a|b c|" ]]
la_do file delete - /x /y -- false && exit 10 || rc=$?; [[ "$rc" -eq 1 ]]
la_unit_toggle enable web -- true
la_ufw_delete added "allow 1/tcp" -- true
la_packages rsync curl -- true
la_git_global_append safe.directory -- true
la_begin file ensure - /x; la_end 0 ""
la_provider_begin foundation "" foundation; la_provider_end foundation 1 "x"
lc_run() { printf 'LC:%s' "$*"; return 3; }
out="$(la_lc_run foundation '{}' "what" composition foundation)" || rc=$?
[[ "$out" == "LC:what composition foundation" && "$rc" -eq 3 ]]
echo SURVIVED
"""
    proc, calls = shell(body, attempt=False, box=None, tmp_path=tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "SURVIVED" in proc.stdout
    assert calls == "", "the ordinary path invoked the attempt writer"


def test_a_failing_wrapped_command_still_stops_the_installer_under_set_e(tmp_path):
    proc, _ = shell("la_do dir ensure - /x -- false\necho CONTINUED", attempt=False, box=None,
                    tmp_path=tmp_path)
    assert proc.returncode == 1 and "CONTINUED" not in proc.stdout
    proc, _ = shell("la_begin file ensure - /x\ncat /nonexistent > /dev/null <<X && rc=0 || rc=$?\n"
                    "X\nla_end \"$rc\" \"\"\necho CONTINUED", attempt=False, box=None,
                    tmp_path=tmp_path)
    assert proc.returncode != 0 and "CONTINUED" not in proc.stdout


def test_an_attempt_publishes_intent_then_the_result_even_when_the_command_fails(box, tmp_path):
    box.begin()
    target = box.paths["install_dir"]
    body = f"""
la_do dir ensure - "{target}" -- mkdir -p "{target}"
la_do file ensure - "{target}/../elsewhere" -- false || echo FAILED-AS-EXPECTED
"""
    proc, _ = shell(body, attempt=True, box=box, tmp_path=tmp_path)
    assert proc.returncode == 0, proc.stderr
    ledger = box.raw()["ledger"]
    assert [(e["intent"], e["state"]) for e in ledger] == [("create", "done"), ("create", "failed")]
    assert ledger[1]["post"] == {"exists": False}


def test_a_ledger_refusal_cannot_be_swallowed_by_a_callers_redirect(box, tmp_path):
    shim = box.root / "usr" / "local" / "bin" / "corpusfm"
    shim.parent.mkdir(parents=True)
    shim.write_text("foreign")
    box.begin()
    proc, _ = shell(f'la_do file ensure - "{shim}" -- touch "{shim}" 2>/dev/null || true\necho CONTINUED',
                    attempt=True, box=box, tmp_path=tmp_path)
    assert proc.returncode == 1 and "CONTINUED" not in proc.stdout
    assert "REFUSE-FIRST" in proc.stderr
    assert box.raw()["ledger"] == []


def test_a_firewall_rule_that_was_not_observed_is_never_deleted_in_an_attempt(box, tmp_path):
    box.begin()
    fake = {"ufw": 'if [ "$1" = show ]; then echo "ufw allow 8533/tcp"; exit 0; fi\n'
                   f'echo "$@" >> {tmp_path}/ufw.log'}
    body = """
la_ufw_delete added "allow 8501/tcp" -- ufw delete allow 8501/tcp
la_ufw_delete added "allow 8533/tcp" -- ufw delete allow 8533/tcp
"""
    proc, _ = shell(body, attempt=True, box=box, tmp_path=tmp_path, extra_bin=fake)
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "ufw.log").read_text() == "delete allow 8533/tcp\n"
    ledger = box.raw()["ledger"]
    assert [(e["target"], e["prior"], e["post"]) for e in ledger] == [
        ("allow 8533/tcp", {"rule": "allow 8533/tcp", "exists": True},
         {"rule": "allow 8533/tcp", "exists": True})]
    box.record()


def test_a_unit_toggle_records_enabled_state_before_and_after(box, tmp_path):
    box.begin()
    fake = {"systemctl": f'if [ "$1" = is-enabled ]; then [ -f {tmp_path}/enabled ]; exit $?; fi\n'
                         f'touch {tmp_path}/enabled'}
    proc, _ = shell("la_unit_toggle enable corpusfm -- systemctl enable corpusfm",
                    attempt=True, box=box, tmp_path=tmp_path, extra_bin=fake)
    assert proc.returncode == 0, proc.stderr
    entry = box.raw()["ledger"][0]
    assert (entry["kind"], entry["intent"], entry["target"]) == (
        "unit", "enable", "/etc/systemd/system/corpusfm.service")
    assert entry["prior"]["enabled"] is False and entry["post"]["enabled"] is True


# ── the installer text: placement, coverage, rerun routing ────────────────────────


def test_the_attempt_begins_after_consent_and_before_the_first_mutation():
    body = code(TEXT)
    begin = body.index("\n    la_begin_attempt\n")
    assert body.index('cfm_confirm "Proceed?"') < begin < body.index("apt-get update -qq")
    assert body.index("if ! $IS_UPGRADE && ! $PUBLISHED_HERE; then\n    la_begin_attempt") > 0


def test_the_attempt_is_routed_before_prior_operation_routing_and_completed_last():
    body = code(TEXT)
    assert body.index("la_route_existing_attempt first") < body.index("CFM_JOURNAL_FILE=/var/lib")
    assert body.index("la_route_existing_attempt final") < body.index("PUBLISHED_HERE=false")
    complete = body.index("attempt complete --request \"$_la_req\"")
    assert body.index('ok "Post-install verification passed"') < complete
    assert complete < body.index('cfm_section "Next steps"')


#: The Linux mutation sites §5.2 names, spelled as they are executed. Every executable line that
#: performs one must go through an attempt wrapper.
MUTATIONS = [
    r"\buseradd\b", r"apt-get (update|install)", r"ufw delete", r"systemctl (enable|disable) ",
    r"git config --global --add safe\.directory",
    r"install -d .*(/etc/corpusfm|/var/lib/corpusfm|/var/log/corpusfm|/run/corpusfm)",
    r"install -d .*(HOSTING_DIR|SUPPORT_DIR|update-inbox|update-outcome)",
    r"install .*/etc/sudoers\.d/", r"install .*\"\$SUDOERS_DST\"", r"chmod 2775",
    r"rm -f .*(/etc/sudoers\.d|_sched_unit_file|MCP_SERVICE|_mcp_env)",
    r"cat > /(usr|etc)/", r"systemd/system/\$_unit\.service\" \"\$INSTALL_DIR\" <<'RENDER'",
    r"composition foundation --request", r"provision-keys --request",
    r"retire-scheduler-authority --request \"\$req\"", r"backfill-storage-projections",
    r"storage create-first-admin", r"install -m 0600 .* \"\$INSTALL_YAML\"",
]


def test_every_named_linux_mutation_site_is_wrapped():
    lines = code(TEXT).splitlines()
    unwrapped = []
    for index, line in enumerate(lines):
        for pattern in MUTATIONS:
            if not re.search(pattern, line):
                continue
            if line.lstrip().startswith(("die ", "warn ", "info ", "ok ", "|| die")):
                continue
            window = "\n".join(lines[max(0, index - 6):index + 1])
            if re.search(r"\bla_(do|begin|unit_toggle|ufw_delete|packages|git_global_append|lc_run|"
                         r"provider_begin)\b", window) or "IS_UPGRADE" in window \
                    or "_cfm_ufw_delete_numbered() {" in line:
                continue
            unwrapped.append(line.strip())
    assert not unwrapped, "\n".join(unwrapped)


def test_the_discard_flag_is_parsed_documented_and_every_discard_exits():
    assert "--discard-incomplete-attempt) DISCARD_INCOMPLETE_ATTEMPT=true; shift ;;" in TEXT
    assert "#   --discard-incomplete-attempt" in TEXT
    discard = extract_sh_func("la_attempt_discard")
    assert discard.count("exit 0") == 1 and "die " in discard
    assert "la_begin_attempt" not in discard and "la_step" not in discard


# ── rerun routing, executed ────────────────────────────────────────────────────────

ROUTER = ("la_container_is_empty", "la_json_get", "la_attempt_request", "la_attempt_inspect", "la_attempt_discard",
          "la_attempt_menu", "la_route_existing_attempt")


def route(tmp_path, status: dict, *, silent=True, flag=False, start_rc=0, journal="none",
          answers=""):
    runs = tmp_path / "run"
    runs.mkdir(exist_ok=True)
    calls = tmp_path / "lifecycle.log"
    status = dict(status, journal=journal)
    (tmp_path / "status.json").write_text(json.dumps(status))
    lifecycle = tmp_path / "lifecycle"
    lifecycle.write_text(f"""#!/bin/sh
echo "$*" >> {calls}
case "$1 $2" in
  "status --json") cat {tmp_path}/status.json ;;
  "attempt inspect") echo '{{"state":"pre_foundation","attempt_id":"a","installation_id":"i","ledger":[],"manual_commands":["rm -rf -- /opt/CORPUSfm"]}}' ;;
  "attempt complete") echo '{{"result":"no_change"}}' ;;
  "uninstall plan") echo '{{"operations":[{{"resource":"install_dir"}}]}}' ;;
  "uninstall start") cat "$4" >> {calls}; echo '{{"result":"completed","reason":"","detail":"done"}}'; exit {start_rc} ;;
esac
""")
    lifecycle.chmod(0o755)
    funcs = "\n".join(sh_func(n) for n in ROUTER).replace("/run/", f"{runs}/")
    zip_root = tmp_path / "runtime"
    zip_root.mkdir(exist_ok=True)
    (zip_root / "corpusfm-recovery-source.zip").write_text("zip")
    script = f"""set -euo pipefail
die() {{ printf 'DIE: %s\\n' "$*" >&2; exit 1; }}
ok() {{ echo "OK: $*"; }}; warn() {{ echo "WARN: $*"; }}; info() {{ echo "INFO: $*"; }}
prepare_package_recovery_runtime() {{ LC_RUNTIME_KIND=package; }}
lc_fms_frame() {{ printf 'frame'; }}
CFM_ATTEMPT_DIR=/etc/corpusfm-attempt; CFM_LOG={tmp_path}/install.log
CFM_INSTALLER_SERIES=series-2; CFM_INSTALLER_VERSION=v; CFM_PACKAGE_COMMIT=c
CFM_RUNTIME_ROOT={zip_root}; LC_RUNTIME_KIND=installed; LC_RUNTIME_PY={sys.executable}
LC_RUNTIME_SOURCE={tmp_path}/src
INSTALL_DIR={tmp_path}/opt; CFM_LIFECYCLE=(env "PYTHONPATH={tmp_path}/src" {lifecycle})
SILENT={'true' if silent else 'false'}; DISCARD_INCOMPLETE_ATTEMPT={'true' if flag else 'false'}
FM_ADMIN_USER=""; FM_ADMIN_PASS=""; LA_LEFTOVER_EMPTY=false; LA_ROUTE_DEFERRED=false
{funcs}
la_route_existing_attempt first
echo "ROUTED leftover=$LA_LEFTOVER_EMPTY deferred=$LA_ROUTE_DEFERRED runtime=$LC_RUNTIME_KIND"
"""
    proc = subprocess.run(["bash", "-c", script], input=answers, capture_output=True, text=True)
    return proc, (calls.read_text() if calls.exists() else "")


def _attempt(state, **extra):
    return {"fresh_attempt": dict({"state": state, "attempt_id": ATTEMPT,
                                   "installation_id": INSTALLATION}, **extra)}


def test_a_silent_rerun_refuses_with_the_inspect_summary_and_the_flag_name(tmp_path):
    proc, calls = route(tmp_path, _attempt("pre_foundation"))
    assert proc.returncode == 1
    assert "--discard-incomplete-attempt" in proc.stderr and "failed_before_change" in proc.stderr
    assert "Attempt:" in proc.stdout and "Discard would remove or restore: install_dir" in proc.stdout
    assert "uninstall start" not in calls
    assert "rm -rf" not in proc.stdout, "no manual command while verified cleanup can run"


def test_the_flag_discards_through_the_package_runtime_and_ends_the_invocation(tmp_path):
    proc, calls = route(tmp_path, _attempt("post_foundation"), flag=True)
    assert proc.returncode == 0, proc.stderr
    assert "ROUTED" not in proc.stdout, "a discard never continues into installation"
    assert "Run the installer again to start a fresh installation." in proc.stdout
    request = json.loads(re.search(r'\{"schema_version":2[^}]*\}', calls).group(0))
    assert request["installation_id"] == INSTALLATION and request["force"] is False
    assert request["credential_transport"] == "none" and request["schema_version"] == 2


@pytest.mark.parametrize("state", ["discarding", "terminal_pending", "terminal_done",
                                   "bookkeeping_only", "foundation_window"])
def test_every_unfinished_state_resumes_through_the_same_menu(tmp_path, state):
    proc, calls = route(tmp_path, _attempt(state), silent=False, answers="i\nq\n")
    assert proc.returncode == 0 and "Quit - nothing changed." in proc.stdout
    assert "attempt inspect" in calls and "uninstall start" not in calls


def test_a_refused_discard_is_reported_and_changes_nothing_else(tmp_path):
    proc, calls = route(tmp_path, _attempt("pre_foundation"), flag=True, start_rc=1)
    assert proc.returncode == 1 and "The discard refused" in proc.stderr
    assert "rm -rf" not in proc.stdout


def test_an_undecidable_attempt_refuses_without_commands(tmp_path):
    proc, calls = route(tmp_path, {"fresh_attempt": {"state": "undecidable",
                                                     "reason": "install_attempt_record_unprotected",
                                                     "detail": "group-writable"}}, flag=True)
    assert proc.returncode == 1 and "install_attempt_record_unprotected" in proc.stderr
    assert "attempt inspect" not in calls and "uninstall" not in calls


def test_an_empty_container_is_left_for_the_run_to_adopt_or_remove(tmp_path):
    proc, _ = route(tmp_path, {"fresh_attempt": {"state": "leftover_empty_container"}})
    assert proc.returncode == 0 and "ROUTED leftover=true deferred=false" in proc.stdout


def test_a_stale_completion_record_is_retired_and_the_run_continues(tmp_path):
    proc, calls = route(tmp_path, _attempt("complete_stale_record"))
    assert proc.returncode == 0 and "attempt complete" in calls
    assert "runtime=installed" in proc.stdout, "the recovery runtime outlived the stale-record retirement"


def test_an_empty_container_is_recognised_without_preparing_a_runtime(tmp_path):
    container = tmp_path / "corpusfm-attempt"
    container.mkdir(mode=0o700)
    (container / ".attempt.json.x.tmp").write_text("partial")
    funcs = "\n".join(sh_func(n) for n in ("la_container_is_empty",))
    script = f"""set -euo pipefail
CFM_ATTEMPT_DIR={container}
{funcs}
la_container_is_empty && echo EMPTY
touch {container}/attempt.json
la_container_is_empty || echo POPULATED
"""
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert proc.stdout.split() == ["EMPTY", "POPULATED"], proc.stderr


def test_a_published_attempt_with_an_open_provider_journal_defers_to_recover_first(tmp_path):
    proc, calls = route(tmp_path, _attempt("post_foundation"), flag=True, journal="open")
    assert proc.returncode == 0 and "ROUTED leftover=false deferred=true" in proc.stdout
    assert "uninstall start" not in calls


# ── ruling 7: a nested patch hosting folder refuses before the container exists ─────


def _begin(tmp_path, hosting_relative, *, install_exists=False):
    install = tmp_path / "opt" / "CORPUSfm"
    if install_exists:
        install.mkdir(parents=True)
        (install / "foreign.txt").write_text("x")
    container = tmp_path / "etc" / "corpusfm-attempt"
    (tmp_path / "etc").mkdir(exist_ok=True)
    hosting = tmp_path / hosting_relative
    script = f"""set -euo pipefail
die() {{ printf 'DIE: %s\\n' "$*" >&2; exit 1; }}
ok() {{ :; }}
install_root_state() {{ printf 'foreign'; }}
IFS= read -r -d '' LA_WRITER <<'PY' || true
{WRITER}
PY
CFM_ATTEMPT=false; CFM_ATTEMPT_DIR={container}; CFM_ATTEMPT_UID={UID}; CFM_ATTEMPT_PY={sys.executable}
INSTALL_DIR={install}; HOSTING_DIR={hosting}; FMS_ROOT={tmp_path}/fms; FM_DB_DIR={tmp_path}/fms/Data/Databases
REPLACE_EXISTING_INSTALL=false; LA_LEFTOVER_EMPTY=false
CFM_INSTALLER_SERIES=""; CFM_INSTALLER_VERSION=""; CFM_PACKAGE_COMMIT=""
{sh_func("la_py")}
{sh_func("la_begin_attempt")}
la_begin_attempt
"""
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return proc, container


@pytest.mark.parametrize("hosting", ["opt/CORPUSfm", "opt/CORPUSfm/hosted", "opt/CORPUSfm/./a/../hosted"])
def test_a_nested_patch_hosting_folder_refuses_before_the_container_exists(tmp_path, hosting):
    proc, container = _begin(tmp_path, hosting)
    assert proc.returncode == 1 and "--patch-hosting-dir" in proc.stderr, proc.stderr
    assert not container.exists(), "the refusal came after an attempt mutation"


@pytest.mark.parametrize("hosting", ["opt/CORPUSfm-Hosted", "opt/CORPUSfm/../CORPUSfm-Hosted"])
def test_a_sibling_patch_hosting_folder_passes_the_nested_check(tmp_path, hosting):
    """The control: a sibling folder - including one spelled through the root with `..` - reaches the next
    preflight (refuse-first), still before the container. The relationship is judged NORMALIZED."""
    proc, container = _begin(tmp_path, hosting, install_exists=True)
    assert proc.returncode == 1 and "REFUSE-FIRST" in proc.stderr and "--patch-hosting-dir" not in proc.stderr
    assert not container.exists()


def test_a_development_discard_names_its_execution_requirement_not_authority():
    discard = sh_func("la_attempt_discard")
    assert "Deletion authority is the protected attempt" in discard
    assert "rerun a complete private package" in discard
    assert "with-commands" in discard[:discard.index("die ")]
