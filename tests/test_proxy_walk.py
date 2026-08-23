"""The production-shaped composed walk (Codex ruling 2).

**Why this file exists.** Every other proxy test injects the engine, so the wiring BETWEEN the CLI,
the engine and the executor was never exercised — and that is precisely where the defect lived:
`_px_engine`, `intent_record` and `build_run_result` were each called through their old signatures,
so the durable record carried none of the paths, no route, no executor identity and no evidence
binding. Unit-testing `build_run_result()` directly could not have seen it, because the arguments
it was never given are the arguments the test supplied itself.

So this walk uses:

* the **real** CLI integration code (`_proxy_integrator`, no stubs of its internals);
* the **real** `ProxyEngine`;
* the **actual Linux executor**, run as a process against a fixture FMS root;
* injected only at the two boundaries that are genuinely privileged or OS-level — the `fmsadmin`
  activator, the HTTPS health check, and the root-ownership predicates a test cannot satisfy.

And it reads the durable record back **in a fresh Python process**, because "a later process can
recover this" is the claim, and a process that still holds the objects in memory cannot test it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests import proxy_exec_materialize as mz
from application_checkout import APPLICATION_ROOT

from corpusfm.lifecycle import cli
from corpusfm.lifecycle import proxy_transaction as px

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the walk drives the Linux executor")


@pytest.fixture(autouse=True)
def _restore_explicit_development_layout():
    """The production walk deliberately clears the development seam; do not leak that state into
    application tests when installer and application suites share one consolidated public process."""
    yield
    from corpusfm.lifecycle import app_paths
    app_paths.use_development_layout(lambda: Path.home() / ".corpusfm")

NGINX_CONF = (
    "http {\n"
    "    server {\n"
    "        listen 80;\n"
    "        server_name _;\n"
    "    }\n"
    "    server {\n"
    "        listen 443 ssl;\n"
    '        include "fms_fac.conf";\n'
    "    }\n"
    "}\n"
)

# `timeout` is how the nginx validator bounds its foreground start; macOS ships none. The shim runs
# the real command — it does not stand in for it.
TIMEOUT_SHIM = """#!/bin/sh
secs="$1"; shift
"$@" &
p=$!
( sleep "$secs"; kill $p 2>/dev/null ) >/dev/null 2>&1 &
w=$!
wait $p 2>/dev/null; rc=$?
kill $w 2>/dev/null
[ $rc -gt 128 ] && exit 124
exit $rc
"""

# A bundled nginx that answers the way a live box does: the config PARSED, only the bind to the
# already-served :443 failed.
# NGINX_STUB was removed with the bundled-validator fixtures (2026-08-08): FMS ships no nginx
# under its root, so a stub there modelled nothing real.

APACHE_CONF = "# FMS proxy config\n<VirtualHost *:443>\n</VirtualHost>\n"


class Machine:
    """A whole fixture box: an FMS root, an install directory with the executor installed where
    ruling 7 requires it, and a published (or deliberately unpublished) installation."""

    def __init__(self, tmp_path, monkeypatch, *, publish=True):
        from corpusfm.lifecycle import app_paths, layout as layout_mod
        from corpusfm.lifecycle.schema import (
            InstallationManifest, LocatorRecord, PathsBlock, WebBlock,
        )

        app_paths.clear_development_layout()
        self.base = tmp_path
        self._fds: list[int] = []
        self.layout = layout_mod.posix_layout(tmp_path / "machine")
        monkeypatch.setattr(layout_mod, "platform_layout", lambda: self.layout)
        monkeypatch.setattr(cli, "platform_layout", lambda: self.layout)

        self.install_dir = tmp_path / "opt" / "CORPUSfm"
        (self.install_dir / "bin").mkdir(parents=True)
        self.executor = self.install_dir / "bin" / "cfm-proxy-exec.sh"
        # The real executor with ONLY its two validators swapped for a deterministic VALID answer.
        # Its validators run `/usr/sbin/nginx` and `/usr/sbin/apache2` and require them root-owned
        # inside a root-owned directory — correct in production and impossible for this suite, which
        # is unprivileged and not on Linux. `proxy_exec_materialize` refuses the copy unless every
        # other byte is the shipped file, so what this walk drives is still the shipped transaction.
        mz.materialize(self.executor, outcome=mz.VALID)

        self.fms_root = tmp_path / "opt" / "FileMaker" / "FileMaker Server"
        conf = self.fms_root / "NginxServer" / "conf"
        conf.mkdir(parents=True)
        (conf / "fms_nginx.conf").write_text(NGINX_CONF, encoding="utf-8")
        (self.fms_root / "Database Server").mkdir(parents=True)
        apache_conf = self.fms_root / "HTTPServer" / "conf" / "extra"
        apache_conf.mkdir(parents=True)
        (apache_conf / "httpd-proxy.conf").write_text(APACHE_CONF, encoding="utf-8")
        # NO bundled nginx or httpd is planted: measured on fms-server, FMS ships neither and
        # drives the distribution binaries. Planting them modelled a deployment that does not exist.

        self.shim = tmp_path / "shim"
        self.shim.mkdir()
        (self.shim / "timeout").write_text(TIMEOUT_SHIM, encoding="utf-8")
        (self.shim / "timeout").chmod(0o755)
        monkeypatch.setenv("PATH", f"{self.shim}:{os.environ['PATH']}")

        Path(self.layout.journal_file).parent.mkdir(parents=True, exist_ok=True)
        locator_dir = Path(self.layout.locator_dir)
        locator_dir.mkdir(parents=True, exist_ok=True)
        self.installation_id = "11111111-2222-3333-4444-555555555555"
        record = LocatorRecord(installation_id=self.installation_id,
                               install_dir=str(self.install_dir))
        self.locator_file = locator_dir / "locator.json"
        self.manifest_file = self.install_dir / record.manifest_relative_path

        if publish:
            process_dirs = {k: tmp_path / "machine" / k for k in
                            ("config_dir", "state_dir", "secrets_dir", "log_dir", "run_dir")}
            for directory in process_dirs.values():
                directory.mkdir(parents=True, exist_ok=True)
            (process_dirs["secrets_dir"] / "secret.key").write_bytes(
                b"3Xk2fVQzq0d8bqR9tJ5wWm1sYcN7uHgPzE4aLrTiVbo=")
            self.locator_file.write_text(json.dumps(record.to_dict()), encoding="utf-8")
            manifest = InstallationManifest(
                installation_id=self.installation_id, generation=4,
                paths=PathsBlock(install_dir=str(self.install_dir), fms_root=str(self.fms_root),
                                 **{k: str(v) for k, v in process_dirs.items()}),
                web=WebBlock(prefix="/corpusfm", internal_port=8533),
                created_utc="2026-08-04T00:00:00+00:00",
                updated_utc="2026-08-04T00:00:00+00:00",
            )
            self.manifest_file.parent.mkdir(parents=True, exist_ok=True)
            self.manifest_file.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

    def credential_fd(self) -> int:
        """A pipe holding two length-prefixed UTF-8 fields, user then password, then EOF."""
        read_fd, write_fd = os.pipe()
        payload = b""
        for value in (b"svc-lifecycle", b"not-a-real-password"):
            payload += len(value).to_bytes(4, "big") + value
        os.write(write_fd, payload)
        os.close(write_fd)
        self._fds.append(read_fd)
        return read_fd

    @property
    def conf(self) -> Path:
        return self.fms_root / "NginxServer" / "conf" / "fms_nginx.conf"

    @property
    def apache_conf(self) -> Path:
        return self.fms_root / "HTTPServer" / "conf" / "extra" / "httpd-proxy.conf"

    @property
    def include(self) -> Path:
        return self.fms_root / "NginxServer" / "conf" / "corpusfm_https.conf"

    def request(self, verb, **overrides):
        common = {"schema_version": 1, "installation_id": self.installation_id,
                  "actor": "installer"}
        if verb in ("status", "reconcile"):
            payload = dict(common, expected_generation=4, prefix="/corpusfm", port=8533,
                           mcp_metadata=True, types=["fms-nginx"],
                           install_dir=str(self.install_dir), fms_root=str(self.fms_root))
            if verb == "reconcile":
                payload["disposition"] = px.COMPOSED_CANDIDATE
                # A REAL credential frame through a REAL inherited pipe — the production transport,
                # exercising §7.1's length-prefixed framing rather than standing in for it. The
                # front is active here, so the plan genuinely needs one.
                payload["credential_input"] = f"fd:{self.credential_fd()}"
        elif verb == "finalize":
            payload = dict(common, operation_id=overrides.pop("operation_id"),
                           committed_generation=overrides.pop("committed_generation", 5))
        else:
            # §9.4: aborting previously ACTIVATED Linux routing needs a NEW lease — the one the
            # reconcile held was never persisted and did not survive. A fresh pipe, as production
            # would supply.
            payload = dict(common, operation_id=overrides.pop("operation_id"),
                           credential_input=f"fd:{self.credential_fd()}")
        payload.update(overrides)
        path = self.base / f"{verb}-request.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)


class Args:
    def __init__(self, verb, request):
        self.px_verb = verb
        self.request = request
        self.selector = None
        self.json = False


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A fixture box with only the unavoidable boundaries stood down."""
    # A test cannot create root-owned files; the ownership predicates have their own controls.
    monkeypatch.setattr(cli, "_stat_refusal", lambda st, what: None)
    monkeypatch.setattr(px, "posix_executor_refusal", lambda **_kwargs: None)
    monkeypatch.setattr(px, "posix_directory_refusal", lambda **_kwargs: None)
    # `fmsadmin`, the HTTPS front, and the listener probe are the genuinely privileged/OS-level
    # boundaries. The third reads `ss -ltnp` and `/proc/<pid>/exe`, neither of which exists on this
    # machine — so it is answered here rather than left to report UNKNOWN, which would make every
    # verb refuse for a reason that has nothing to do with the wiring under test. Its own rule has
    # its own controls in `test_proxy_inventory`.
    from corpusfm.lifecycle import proxy_inventory as inv

    monkeypatch.setattr(px, "real_activator", lambda **_kwargs: (lambda _u, _p: True))
    monkeypatch.setattr(px, "real_health_check", lambda **_kwargs: (lambda _w: True))
    monkeypatch.setattr(inv, "linux_active_front", lambda _root, **_kwargs: "fms-nginx")
    return Machine(tmp_path, monkeypatch)


def run(verb, machine, capsys, **overrides):
    code = cli._proxy_integrator(Args(verb, machine.request(verb, **overrides)))
    return code, json.loads(capsys.readouterr().out)


# ── the walk ──────────────────────────────────────────────────────────────────

def read_record_in_a_fresh_process(machine) -> dict:
    """Read the durable record from a NEW interpreter.

    "A later process can recover this" is the claim, and a process still holding the objects cannot
    test it. This one imports nothing from the test — it takes the path and parses the file through
    the production reader.
    """
    script = (
        "import json, sys\n"
        "sys.path.insert(0, %r)\n"
        "from corpusfm.lifecycle.proxy_transaction import RecoveryRecord\n"
        "raw = json.load(open(%r))\n"
        "record = RecoveryRecord.from_dict(raw)\n"
        "print(json.dumps(record.to_dict()))\n"
    ) % (str(APPLICATION_ROOT), str(px.recovery_path(machine.layout)))
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_status_then_reconcile_then_a_fresh_process_can_abort(machine, capsys):
    """status → reconcile → read the record in a fresh process → abort. No manifest is consulted by
    the abort, and none needs to be."""
    code, status = run("status", machine, capsys)
    assert code == cli._PX_OK
    assert "fms-nginx" in status["mutation_needed"], status

    code, composed = run("reconcile", machine, capsys)
    assert code == cli._PX_OK, composed
    assert composed["result"] == "completed", composed

    # The real executor really wrote it, inside the 443 server block.
    text = machine.conf.read_text(encoding="utf-8")
    assert text.count("# CORPUSFM") == 2
    assert machine.include.exists()
    lines = text.splitlines()
    marks = [i for i, line in enumerate(lines) if line.strip() == "# CORPUSFM"]
    open443 = next(i for i, line in enumerate(lines) if "listen 443" in line)
    assert open443 < marks[0], "the block is inside the 443 server block"

    # EVERY bound field is populated — the whole point of ruling 1.
    record = read_record_in_a_fresh_process(machine)
    assert record["operation_id"] == composed["operation_id"]
    assert record["installation_id"] == machine.installation_id
    assert record["flavour"] == "posix"
    assert record["install_dir"] == str(machine.install_dir)
    assert record["fms_root"] == str(machine.fms_root)
    assert record["web_prefix"] == "/corpusfm"
    assert record["web_internal_port"] == 8533
    assert record["executor_path"] == str(machine.executor)
    assert record["executor_digest"] == px.executor_digest(machine.executor)
    assert record["phase"] == "mutated"
    assert record["evidence"]["fms-nginx"]["path"].endswith(
        f"cfm-fms-nginx-before-{composed['operation_id']}.json")
    assert len(record["evidence"]["fms-nginx"]["sha256"]) == 64
    assert [e["proxy_type"] for e in record["per_type"]] == ["fms-nginx"]

    # RECOVERY WITH THE LOCATOR AND MANIFEST ABSENT — the pre-manifest case 1246-04 actually hits.
    machine.locator_file.unlink()
    machine.manifest_file.unlink()

    code, aborted = run("abort", machine, capsys, operation_id=composed["operation_id"])
    assert code in (cli._PX_OK, cli._PX_ROLLED_BACK), aborted
    assert aborted["result"] in ("rolled_back", "no_change"), aborted
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF, "the bytes are back"
    assert not machine.include.exists(), "the include CORPUSfm created is gone"


def test_the_same_walk_can_finalize_instead(machine, capsys):
    """The other disposition of the same evidence."""
    from corpusfm.lifecycle.schema import InstallationManifest, ProxyPolicyEntry

    _code, composed = run("reconcile", machine, capsys)
    assert composed["result"] == "completed"

    # 1246-04's one composed write lands, carrying exactly the candidate.
    manifest = json.loads(machine.manifest_file.read_text(encoding="utf-8"))
    manifest["generation"] = 5
    manifest["proxy_policy"] = composed["candidates"]
    machine.manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    code, done = run("finalize", machine, capsys, operation_id=composed["operation_id"],
                     committed_generation=5)
    assert code == cli._PX_OK, done
    assert done["result"] == "completed"
    with pytest.raises(px.RecoveryEvidenceInvalid):
        px.read_recovery(machine.layout)
    assert machine.conf.read_text(encoding="utf-8").count("# CORPUSFM") == 2, "routing survives"


def test_the_record_written_BEFORE_the_mutation_already_binds_every_path(machine, capsys, tmp_path):
    """The intent record must not need the outcome to become executable.

    A crash between the two leaves whatever the FIRST write said — so if the paths appeared only in
    the second, the window this record exists to cover would be exactly the window it fails in.
    """
    seen = {}
    real_write = px.write_recovery

    def capture(layout, record, *, lock):
        seen.setdefault("first", record.to_dict())
        return real_write(layout, record, lock=lock)

    import unittest.mock

    with unittest.mock.patch.object(cli.px if hasattr(cli, "px") else px, "write_recovery", capture):
        pass
    # Patch at the module the CLI imports lazily.
    original = px.write_recovery
    px.write_recovery = capture
    try:
        run("reconcile", machine, capsys)
    finally:
        px.write_recovery = original

    first = seen["first"]
    assert first["phase"] == "preparing"
    for field in ("install_dir", "fms_root", "web_prefix", "web_internal_port", "executor_path",
                  "executor_digest", "flavour"):
        assert first[field], f"the FIRST record did not bind {field}"


def test_a_credential_free_abort_of_ACTIVATED_routing_refuses_and_touches_nothing(machine, capsys):
    """§9.4 end to end, through the real executor: the pre-crash lease was never persisted, so an
    abort of activated Linux routing needs a NEW one — and without it, every artifact stays."""
    _code, composed = run("reconcile", machine, capsys)
    published = machine.conf.read_text(encoding="utf-8")
    include = machine.include.read_text(encoding="utf-8")

    code, refused = run("abort", machine, capsys, operation_id=composed["operation_id"],
                        credential_input="absent")

    assert code == cli._PX_REFUSED, refused
    assert refused["findings"][0]["code"] == "abort_credentials_required"
    assert "never persisted" in refused["findings"][0]["detail"]
    assert machine.conf.read_text(encoding="utf-8") == published, "nothing was restored"
    assert machine.include.read_text(encoding="utf-8") == include
    assert px.read_recovery(machine.layout).operation_id == composed["operation_id"]


def test_the_scratch_render_directory_does_not_outlive_the_walk(machine, capsys):
    """Ruling 8, against the real dispatch: one temp tree per publication, forever, is litter."""
    import tempfile

    before = set(Path(tempfile.gettempdir()).glob("cfm-render-*"))
    run("reconcile", machine, capsys)
    after = set(Path(tempfile.gettempdir()).glob("cfm-render-*"))
    assert after <= before, sorted(after - before)


def test_a_tampered_before_image_refuses_the_abort_without_touching_the_box(machine, capsys):
    """Ruling 4: evidence is bound by DIGEST, and the binding is re-verified before restoration."""
    _code, composed = run("reconcile", machine, capsys)
    record = px.read_recovery(machine.layout)
    evidence = Path(record.evidence["fms-nginx"]["path"])

    published = machine.conf.read_text(encoding="utf-8")
    evidence.write_text(evidence.read_text(encoding="utf-8").replace("fms-nginx", "fms-nginx "),
                        encoding="utf-8")

    code, refused = run("abort", machine, capsys, operation_id=composed["operation_id"])
    assert code == cli._PX_REFUSED, refused
    assert "no longer matches the digest" in refused["findings"][0]["detail"]
    assert machine.conf.read_text(encoding="utf-8") == published, "nothing was restored"
    assert px.read_recovery(machine.layout).operation_id == composed["operation_id"]


def test_a_replaced_executor_refuses_the_abort(machine, capsys):
    """Ruling 1: a helper whose digest moved is not the helper that made the change."""
    _code, composed = run("reconcile", machine, capsys)
    published = machine.conf.read_text(encoding="utf-8")
    machine.executor.write_text("#!/bin/bash\n# replaced\n", encoding="utf-8")

    code, refused = run("abort", machine, capsys, operation_id=composed["operation_id"])
    assert code == cli._PX_REFUSED, refused
    assert "has changed since this operation ran" in refused["findings"][0]["detail"]
    assert machine.conf.read_text(encoding="utf-8") == published


def test_a_second_reconcile_is_a_no_change_because_the_family_matches(machine, capsys):
    """Ruling 3, end to end: the composite the executor reads back is the composite planning
    computed, so a converged installation stops changing."""
    _code, first = run("reconcile", machine, capsys)
    assert first["result"] == "completed"

    # Finalize so the next run is not blocked by unresolved evidence, and record the candidate.
    manifest = json.loads(machine.manifest_file.read_text(encoding="utf-8"))
    manifest["generation"] = 5
    manifest["proxy_policy"] = first["candidates"]
    machine.manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    run("finalize", machine, capsys, operation_id=first["operation_id"], committed_generation=5)

    _code, again = run("reconcile", machine, capsys, expected_generation=5)
    by_type = {row["proxy_type"]: row for row in again["per_type"]}
    assert by_type["fms-nginx"]["action"] == "none", again
    assert "matches the intended rendering" in by_type["fms-nginx"]["detail"]


def test_an_operator_edit_to_the_INCLUDE_alone_is_seen(machine, capsys):
    """The measured nginx defect: the prefix, the port and every metadata route live in the include
    body, so a fingerprint over the marked block alone could not see any of them change."""
    _code, first = run("reconcile", machine, capsys)
    manifest = json.loads(machine.manifest_file.read_text(encoding="utf-8"))
    manifest["generation"] = 5
    manifest["proxy_policy"] = first["candidates"]
    machine.manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    run("finalize", machine, capsys, operation_id=first["operation_id"], committed_generation=5)

    # The block is untouched; only the include changes.
    from corpusfm.lifecycle.proxy_inventory import PlatformProbe, inventory

    def observed():
        probe = PlatformProbe(is_windows=False, fms_root=machine.fms_root,
                              linux_active_front="fms-nginx")
        return {o.proxy_type: o for o in inventory(platform_probe=probe)}["fms-nginx"].fingerprint

    before_block = machine.conf.read_text(encoding="utf-8")
    before_fp = observed()
    machine.include.write_text(
        machine.include.read_text(encoding="utf-8").replace("8533", "9999"), encoding="utf-8")
    assert machine.conf.read_text(encoding="utf-8") == before_block, "the BLOCK is untouched"

    # THE OBSERVED FINGERPRINT MOVES. This is the precise rule: an observation that hashed the block
    # alone could not see any of the prefix, port or metadata routes change, because all of them
    # live in the include body. Asserted directly, because the downstream refusal happens either
    # way — for a different reason — and would pass while proving nothing.
    assert observed() != before_fp, "editing only the include did not move the observed digest"

    _code, again = run("reconcile", machine, capsys, expected_generation=5)
    by_type = {row["proxy_type"]: row for row in again["per_type"]}
    assert by_type["fms-nginx"]["action"] == "refuse", again
    assert "edited outside CORPUSfm" in by_type["fms-nginx"]["detail"]


# ── the crash boundary (Codex final check) ───────────────────────────────────
#
# `prepare` captures a before-image and changes NO routing. So an interruption between it and the
# mutation leaves a durable `prepared` record over a completely untouched box — and the abort path
# used to restore blindly, which needs a `.cfmbak` publication never created. It failed, returned
# `manual_action_required`, kept the record, and wedged an installation that had changed nothing.
#
# Every control below drives the REAL Linux executor and performs the recovery in a SEPARATE
# invocation, because the classification has to survive the process that made it.


def crash(machine, capsys, monkeypatch, where):
    """Kill the operation at a named point, the way a real crash would — then carry on in a later
    invocation, which is where the recovery has to work.

    The interruption uses its OWN `MonkeyPatch` context: `monkeypatch.undo()` reverts every patch
    that instance made, and the `machine` fixture's boundaries were applied through the same one —
    so undoing here would silently strip them and the recovery would refuse for an unrelated reason.
    """
    from _pytest.monkeypatch import MonkeyPatch

    killer = MonkeyPatch()
    try:
        if where == "before_prepare":
            killer.setattr(cli, "_px_prepare", _boom("before any before-image was captured"))
        elif where == "after_prepare":
            killer.setattr(px.ProxyEngine, "run", _boom("after prepare, before any mutation"))
        elif where == "after_mutation":
            killer.setattr(px, "build_run_result",
                           _boom("after the mutation, before the outcome record"))
        else:
            raise AssertionError(where)
        with pytest.raises(KeyboardInterrupt):
            cli._proxy_integrator(Args("reconcile", machine.request("reconcile")))
    finally:
        killer.undo()
    capsys.readouterr()
    return px.read_recovery(machine.layout)


def _boom(what: str):
    def raiser(*_a, **_k):
        raise KeyboardInterrupt(f"killed {what}")

    return raiser


def test_a_crash_BEFORE_prepare_recovers_cleanly(machine, capsys, monkeypatch):
    """Case 1. The journal is open and the intent record is durable, but no before-image exists and
    no routing was touched. Recovery must resolve honestly, not demand evidence that was never
    written."""
    record = crash(machine, capsys, monkeypatch, "before_prepare")
    assert record.phase == "preparing"
    assert record.evidence == {}
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF

    code, out = run("abort", machine, capsys, operation_id=record.operation_id,
                    credential_input="absent")
    assert code == cli._PX_OK, out
    assert out["result"] == "no_change", out
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF
    with pytest.raises(px.RecoveryEvidenceInvalid):
        px.read_recovery(machine.layout)


def test_a_crash_AFTER_prepared_but_before_the_mutation_recovers_cleanly(machine, capsys,
                                                                        monkeypatch):
    """Case 2 — the reproduced defect. `prepared` is durable, the evidence is bound, and the live
    configuration is byte-identical to its before-image. That is not something to restore."""
    record = crash(machine, capsys, monkeypatch, "after_prepare")
    assert record.phase == "prepared"
    assert record.evidence["fms-nginx"]["sha256"]
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF, "prepare changed nothing"

    evidence = Path(record.evidence["fms-nginx"]["path"])
    assert evidence.exists()

    code, out = run("abort", machine, capsys, operation_id=record.operation_id,
                    credential_input="absent")

    assert code == cli._PX_OK, out
    assert out["result"] == "no_change", out
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF
    assert not machine.include.exists()
    assert not evidence.exists(), "the operation-specific preparation evidence was retired"
    with pytest.raises(px.RecoveryEvidenceInvalid):
        px.read_recovery(machine.layout)


def test_a_crash_AFTER_the_mutation_still_takes_the_real_restoration_path(machine, capsys,
                                                                         monkeypatch):
    """Case 3, and the reason this cannot simply treat every `prepared` record as `no_change`: the
    same durable phase survives a crash that happened AFTER the routing was written."""
    record = crash(machine, capsys, monkeypatch, "after_mutation")
    assert record.phase == "prepared", "the outcome record never landed"
    assert machine.conf.read_text(encoding="utf-8") != NGINX_CONF, "but the routing DID change"
    assert machine.include.exists()

    code, out = run("abort", machine, capsys, operation_id=record.operation_id)

    assert code in (cli._PX_OK, cli._PX_ROLLED_BACK), out
    assert out["result"] == "rolled_back", out
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF, "the bytes are back"
    assert not machine.include.exists()
    with pytest.raises(px.RecoveryEvidenceInvalid):
        px.read_recovery(machine.layout)


def watch_transport(monkeypatch):
    """Record every touch of the credential CHANNEL — opening it, reading a frame, prompting.

    A tripwire on `prompt_for_credential` alone proves nothing when the request says `absent`:
    `_px_lease("absent")` returns `None` without touching anything, so the control passes whether
    acquisition was deferred or not. These watch the transport itself.
    """
    touched = []
    real_open = px.open_credential_source
    real_frame = px.read_credential_frame

    def open_watched(transport):
        touched.append(f"open:{transport}")
        return real_open(transport)

    def frame_watched(source):
        touched.append("read-frame")
        return real_frame(source)

    def prompt_watched(*_a, **_k):
        touched.append("prompt")
        return px.CredentialLease("svc-lifecycle", "not-a-real-password")

    monkeypatch.setattr(px, "open_credential_source", open_watched)
    monkeypatch.setattr(px, "read_credential_frame", frame_watched)
    monkeypatch.setattr(px, "prompt_for_credential", prompt_watched)
    return touched


def test_a_no_mutation_recovery_never_TOUCHES_a_real_credential_transport(machine, capsys,
                                                                         monkeypatch):
    """Case 4, with a REAL fd rather than `absent`.

    Measured before the fix: `lease_calls=['fd:4']` — the pipe was opened and drained for an
    operation that had changed nothing, because every caller acquired a lease and only then handed
    it to be classified. The request below supplies a genuine, valid transport, so nothing
    short-circuits: if acquisition were still eager, the watcher would see it.
    """
    record = crash(machine, capsys, monkeypatch, "after_prepare")
    assert record.restoration_restart_may_be_required is True, (
        "the flag IS pessimistic here; that is what makes this control meaningful")

    touched = watch_transport(monkeypatch)
    fd = machine.credential_fd()

    code, out = run("abort", machine, capsys, operation_id=record.operation_id,
                    credential_input=f"fd:{fd}")

    assert code == cli._PX_OK, out
    assert out["result"] == "no_change", out
    assert touched == [], f"the credential channel was touched: {touched}"

    # …and the pipe is still full, which is the same fact from the other side: a one-shot transport
    # that was never drained.
    assert os.read(fd, 4), "the transport had already been consumed"


def test_a_no_mutation_PUBLIC_recovery_never_prompts(machine, capsys, monkeypatch):
    """The same rule on the public surface, where the cost is an administrator being asked for a
    password to complete a recovery that needs none."""
    from corpusfm.lifecycle.proxy_inventory import BLOCK_ABSENT

    record = crash(machine, capsys, monkeypatch, "after_prepare")
    touched = watch_transport(monkeypatch)

    handled, code = cli._px_recovery_precondition(
        machine.layout, _px_published(machine), "reconcile")
    capsys.readouterr()

    assert handled is True
    assert code == cli._PX_OK
    assert touched == [], f"the credential channel was touched: {touched}"
    with pytest.raises(px.RecoveryEvidenceInvalid):
        px.read_recovery(machine.layout)


def _px_published(machine):
    from corpusfm.lifecycle.published import read_published_installation

    return read_published_installation()


def test_changed_ACTIVE_routing_acquires_the_credential_BEFORE_the_first_restore(machine, capsys,
                                                                                monkeypatch):
    """The other half of the rule, and the one that must not be lost to laziness: once a
    restoration restart IS required, the credential is obtained before the first restoration
    mutation. A half-restored box with no way to reactivate it is worse than an untouched one."""
    record = crash(machine, capsys, monkeypatch, "after_mutation")
    assert machine.conf.read_text(encoding="utf-8") != NGINX_CONF

    order = []
    real_open = px.open_credential_source
    monkeypatch.setattr(px, "open_credential_source",
                        lambda t: (order.append("credential"), real_open(t))[1])
    real_executor = px.real_executor

    def watched(**kwargs):
        call = real_executor(**kwargs)

        def wrapped(verb, proxy_type, desired=None):
            if verb == "restore":
                order.append("restore")
            return call(verb, proxy_type, desired)

        return wrapped

    monkeypatch.setattr(px, "real_executor", watched)

    activations = []
    monkeypatch.setattr(px, "real_activator",
                        lambda **_k: (lambda u, p: activations.append((u, p)) or True))

    code, out = run("abort", machine, capsys, operation_id=record.operation_id)

    assert out["result"] == "rolled_back", out
    assert order[0] == "credential", f"the credential must come first: {order}"
    assert "restore" in order
    # ONE frame, TWO uses is §7.1's rule; here the restoration activation is the second.
    assert len(activations) == 1
    assert activations[0] == ("svc-lifecycle", "not-a-real-password")


def test_changed_INACTIVE_only_routing_acquires_no_credential(machine, capsys, monkeypatch):
    """The discriminating half of the above: a changed front whose mechanism is `none` needs no
    restart, so it needs no credential — even though the record's flag says one might be."""
    from _pytest.monkeypatch import MonkeyPatch

    # An APACHE-only operation: inactive, mechanism `none`, so its plan needs no credential either.
    killer = MonkeyPatch()
    try:
        killer.setattr(px.ProxyEngine, "run", _boom("after prepare"))
        with pytest.raises(KeyboardInterrupt):
            cli._proxy_integrator(Args("reconcile", machine.request(
                "reconcile", types=["apache"])))
    finally:
        killer.undo()
    capsys.readouterr()
    record = px.read_recovery(machine.layout)

    # Only APACHE differs from its before-image.
    machine.apache_conf.write_text(APACHE_CONF + "# half-finished\n", encoding="utf-8")

    # The watcher goes on immediately before the ACTION UNDER TEST — the setup above legitimately
    # uses the channel, and watching it too would report the fixture as the violation.
    touched = watch_transport(monkeypatch)
    code, out = run("abort", machine, capsys, operation_id=record.operation_id)
    assert touched == [], f"the credential channel was touched: {touched}"


def test_UNKNOWN_active_routing_acquires_a_credential_before_attempting_restoration(machine, capsys,
                                                                                    monkeypatch):
    """Unknown is not unchanged, so it takes the restoring path — and the restoring path for an
    ACTIVE front needs a credential before it begins."""
    record = crash(machine, capsys, monkeypatch, "after_prepare")
    before = machine.conf.read_text(encoding="utf-8")
    evidence_before = Path(record.evidence["fms-nginx"]["path"]).read_bytes()

    real_executor = px.real_executor

    def blind(**kwargs):
        call = real_executor(**kwargs)

        def wrapped(verb, proxy_type, desired=None):
            if verb == "classify":
                return {"ok": False, "detail": "unreadable"}
            return call(verb, proxy_type, desired)

        return wrapped

    monkeypatch.setattr(px, "real_executor", blind)

    # With NO credential supplied, it must refuse before restoring — evidence and artifacts intact.
    code, out = run("abort", machine, capsys, operation_id=record.operation_id,
                    credential_input="absent")
    assert code == cli._PX_REFUSED, out
    assert out["findings"][0]["code"] == "abort_credentials_required"
    assert machine.conf.read_text(encoding="utf-8") == before
    assert Path(record.evidence["fms-nginx"]["path"]).read_bytes() == evidence_before
    assert px.read_recovery(machine.layout).operation_id == record.operation_id


def test_the_direct_commit_failure_path_defers_acquisition_too(machine, capsys, monkeypatch):
    """Case 6. The same ordering at the third caller — reached by failing the manifest write on a
    run that turns out to have changed nothing."""
    def conflicted(*_a, **_k):
        from corpusfm.lifecycle.errors import GenerationConflict

        raise GenerationConflict("manifest generation moved")

    # Settle the installation first, so the public run below finds nothing to change.
    _code, first = run("reconcile", machine, capsys)
    manifest = json.loads(machine.manifest_file.read_text(encoding="utf-8"))
    manifest["generation"] = 5
    manifest["proxy_policy"] = first["candidates"]
    machine.manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    run("finalize", machine, capsys, operation_id=first["operation_id"], committed_generation=5)

    # The watcher goes on immediately before the ACTION UNDER TEST — the reconcile above genuinely
    # needs a credential and legitimately reads one.
    touched = watch_transport(monkeypatch)
    monkeypatch.setattr(cli, "_px_publish_policy", conflicted)
    cli._proxy_public(PublicArgs("reconcile", "apache"))
    capsys.readouterr()

    assert touched == [], f"the credential channel was touched: {touched}"


class PublicArgs:
    def __init__(self, verb, selector):
        self.px_verb = verb
        self.selector = selector
        self.request = None
        self.json = False


def test_a_tampered_before_image_refuses_a_no_mutation_recovery_too(machine, capsys, monkeypatch):
    """Case 5a. The digest binding is checked BEFORE the classification, so evidence that changed
    cannot buy a cheap `no_change` either."""
    record = crash(machine, capsys, monkeypatch, "after_prepare")
    evidence = Path(record.evidence["fms-nginx"]["path"])
    evidence.write_text(evidence.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    code, out = run("abort", machine, capsys, operation_id=record.operation_id,
                    credential_input="absent")

    assert code == cli._PX_REFUSED, out
    assert "no longer matches the digest" in out["findings"][0]["detail"]
    assert evidence.exists(), "the evidence is retained"
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF, "and nothing was touched"
    assert px.read_recovery(machine.layout).operation_id == record.operation_id


def test_a_state_that_cannot_be_classified_takes_the_restoring_path(machine, capsys, monkeypatch):
    """Case 5b. An unreadable before-image is UNKNOWN, and unknown is not `unchanged` — so it goes
    the restoring way and, with nothing to restore from, refuses honestly rather than resolving."""
    record = crash(machine, capsys, monkeypatch, "after_prepare")
    evidence = Path(record.evidence["fms-nginx"]["path"])

    # Bound digest still matches, but the executor can no longer classify from it.
    import unittest.mock

    real = px.real_executor

    def blind(**kwargs):
        call = real(**kwargs)

        def wrapped(verb, proxy_type, desired=None):
            if verb == "classify":
                return {"ok": False, "detail": "the before-image could not be parsed"}
            return call(verb, proxy_type, desired)

        return wrapped

    monkeypatch.setattr(px, "real_executor", blind)

    code, out = run("abort", machine, capsys, operation_id=record.operation_id)
    assert code == cli._PX_MANUAL, out
    assert out["result"] == "manual_action_required"
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF, "still untouched"
    assert px.read_recovery(machine.layout).operation_id == record.operation_id


def test_a_published_type_with_NO_before_image_takes_the_restoring_path(machine, capsys,
                                                                       monkeypatch):
    """A type the record says may have been published, with no evidence to compare against, is
    UNKNOWN — not unchanged. Guessing the cheap answer here would skip a restoration the record
    itself says might be owed."""
    import dataclasses

    record = crash(machine, capsys, monkeypatch, "after_prepare")
    stripped = dataclasses.replace(record, evidence={})
    from corpusfm.lifecycle.lock import LifecycleLock

    with LifecycleLock(machine.layout) as lock:
        px.write_recovery(machine.layout, stripped, lock=lock)

    code, out = run("abort", machine, capsys, operation_id=record.operation_id)
    assert code == cli._PX_MANUAL, out
    assert out["result"] == "manual_action_required"
    assert px.read_recovery(machine.layout).operation_id == record.operation_id


def test_a_change_to_the_INCLUDE_ALONE_classifies_as_changed(machine, capsys, monkeypatch):
    """The include is CORPUSfm's own file and part of the family. A classification that compared
    only the host configuration would call a half-finished mutation 'unchanged' and retire the very
    evidence needed to undo it."""
    record = crash(machine, capsys, monkeypatch, "after_prepare")
    before_conf = machine.conf.read_text(encoding="utf-8")

    # Exactly what a crash midway through publication leaves: the include written, the host
    # configuration not yet touched.
    machine.include.write_text("location /corpusfm/ { proxy_pass http://127.0.0.1:8533/; }\n",
                               encoding="utf-8")
    assert machine.conf.read_text(encoding="utf-8") == before_conf

    engine = cli._px_recovery_engine(record)
    assert cli._px_classify(engine, record) == {"fms-nginx": False}


def test_the_credential_question_is_asked_about_the_CHANGED_types_only(machine, capsys,
                                                                      monkeypatch):
    """The second half of the credential rule, and the one the early return cannot cover.

    A mixed interruption: the ACTIVE nginx front is untouched (so no restart is owed for it) while
    the INACTIVE apache front did change. The record's flag is pessimistically True — it was set
    from a plan containing a restart cohort — but the only type that actually needs restoring
    activates through no mechanism at all. Demanding a credential here would wedge a recovery that
    needs none.
    """
    from corpusfm.lifecycle import proxy_inventory as inv

    # Both fronts in one operation; apache is INACTIVE, so its mechanism is `none`.
    monkeypatch.setattr(inv, "linux_active_front", lambda _r, **_k: "fms-nginx")
    killer_types = ["fms-nginx", "apache"]

    from _pytest.monkeypatch import MonkeyPatch

    killer = MonkeyPatch()
    try:
        killer.setattr(px.ProxyEngine, "run", _boom("after prepare, before any mutation"))
        with pytest.raises(KeyboardInterrupt):
            cli._proxy_integrator(Args("reconcile",
                                       machine.request("reconcile", types=killer_types)))
    finally:
        killer.undo()
    capsys.readouterr()

    record = px.read_recovery(machine.layout)
    assert record.restoration_restart_may_be_required is True, "the flag is pessimistic"
    assert {e["proxy_type"] for e in record.per_type} == {"fms-nginx", "apache"}

    # Only APACHE changed — the front whose mechanism is `none`.
    machine.apache_conf.write_text(APACHE_CONF + "# a half-finished publication\n",
                                   encoding="utf-8")

    def refuse(*_a, **_k):
        raise AssertionError("a credential was requested for a restart nobody needs")

    monkeypatch.setattr(px, "prompt_for_credential", refuse)
    monkeypatch.setattr(px, "open_credential_source", refuse)

    code, out = run("abort", machine, capsys, operation_id=record.operation_id,
                    credential_input="absent")

    # The apache edit is not something this operation can undo — it never published, so there is no
    # backup — and `manual_action_required` is the honest answer. What matters here is HOW it got
    # there: by trying, not by refusing for a credential. With the credential taken from the
    # record's pessimistic flag this would have exited `failed_before_change` without ever looking.
    assert code == cli._PX_MANUAL, out
    assert out["result"] == "manual_action_required", out
    assert machine.conf.read_text(encoding="utf-8") == NGINX_CONF, "the untouched front is untouched"
    assert px.read_recovery(machine.layout).operation_id == record.operation_id


def test_an_acquired_lease_is_wiped_on_every_exit(machine, capsys, monkeypatch):
    """§7.1's terminal point, at the one frame that knows whether a lease was taken at all.

    Both paths: the one that completes a restoration, and the one that fails partway. A credential
    left live in a long-running process is exactly the exposure the lease exists to bound.
    """
    record = crash(machine, capsys, monkeypatch, "after_mutation")

    leases = []
    real_frame = px.read_credential_frame

    def remembering(source):
        lease = real_frame(source)
        leases.append(lease)
        return lease

    monkeypatch.setattr(px, "read_credential_frame", remembering)

    run("abort", machine, capsys, operation_id=record.operation_id)
    assert leases, "a credential was genuinely acquired"
    assert all(lease.wiped for lease in leases), "an acquired lease outlived its operation"


def test_a_lease_is_wiped_even_when_the_restoration_fails(machine, capsys, monkeypatch):
    """The discriminating half: the `finally` is what covers the exceptional exit."""
    record = crash(machine, capsys, monkeypatch, "after_mutation")

    leases = []
    real_frame = px.read_credential_frame
    monkeypatch.setattr(px, "read_credential_frame",
                        lambda src: (leases.append(real_frame(src)), leases[-1])[1])

    real_executor = px.real_executor

    def failing(**kwargs):
        call = real_executor(**kwargs)

        def wrapped(verb, proxy_type, desired=None):
            if verb == "restore":
                return {"ok": False, "restored": False, "restore_verified": False,
                        "detail": "the backup could not be put back"}
            return call(verb, proxy_type, desired)

        return wrapped

    monkeypatch.setattr(px, "real_executor", failing)

    code, out = run("abort", machine, capsys, operation_id=record.operation_id)
    assert out["result"] == "manual_action_required", out
    assert leases and all(lease.wiped for lease in leases)
