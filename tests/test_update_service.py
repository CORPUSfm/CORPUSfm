"""`update_service` — the parts that survive the privileged boundary (packet 1246-03-03).

**Eighteen tests were deleted here, and the reason is the point.** They exercised `apply()`'s
pre-1246 route: fetch, classify, `git pull --ff-only`, import probe, restart — the service rewriting
the checkout it runs from. That route is **deleted, not conditioned**, so those tests have no
subject; keeping them would have meant keeping the code. The rules two of them defended DO survive
and are re-expressed below against the surviving path: single-flight, and the request record's
privacy.

What `apply()` does now: resolve installation authority, require published, require the elevated
one-shot, require exact consent, trigger, and report what root recorded. Everything else about an
update is decided on the far side of the privilege boundary and is tested in
`test_privileged_update_trigger.py` and `test_privileged_updater_behaviour.py`.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from corpusfm import updater
from corpusfm.server import update_service as us


def _cp(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["git"], returncode=returncode, stdout=stdout, stderr=stderr)


def _fake_git(head="a" * 40, origin="b" * 40, count="9999", pull_rc=0, pull_err="", resets=None):
    def fake(repo, *args, timeout=15):
        if args and args[0] == "fetch":
            return _cp(0)
        if args[:1] == ("rev-parse",):
            return _cp(0, stdout=(head if args[1] == "HEAD" else origin))
        if args[:1] == ("pull",):
            return _cp(pull_rc, stdout="Updating aaaa..bbbb", stderr=pull_err)
        if args[:2] == ("rev-list", "--count"):
            return _cp(0, stdout=count)
        if args[:2] == ("reset", "--hard"):
            if resets is not None:
                resets.append(args)
            return _cp(0)
        return _cp(0)
    return fake


@pytest.fixture
def git_repo(tmp_path, monkeypatch):
    """A monkeypatched 'clean git checkout' whose helpers the service calls via the updater module."""
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(updater, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(updater, "verify_origin", lambda repo: (True, "ok"))
    monkeypatch.setattr(updater, "is_dirty", lambda repo: False)
    monkeypatch.setattr(updater, "classify_incoming_changes",
                        lambda repo: updater.ChangeClassification())
    # import probe always loads; version stamp write is a no-op in the sandbox
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _cp(0))
    monkeypatch.setattr("corpusfm.config.is_server_mode", lambda: True)
    return tmp_path


@pytest.fixture
def record_file(tmp_path, monkeypatch):
    p = tmp_path / "update_request.json"
    monkeypatch.setattr(us, "request_record_path", lambda: p)
    return p


# ── exact-head apply ────────────────────────────────────────────────────────────────

def _seed_restart_scheduled(record_file, *, old_v, applied_v, req="upd_test"):
    us._write_record({
        "format": us._RECORD_FORMAT, "request_id": req, "actor": "tester",
        "started_utc": "2026-07-17T00:00:00+00:00", "completed_utc": "2026-07-17T00:00:01+00:00",
        "old_head": "a" * 40, "old_version": old_v, "expected_head": "b" * 40,
        "applied_head": "b" * 40, "applied_version": applied_v, "state": "restart_scheduled",
        "reason_code": "ok", "detail": "", "restart_mode": "server",
        "control_plane_revision": us.CONTROL_PLANE_REVISION,
    })


def test_status_no_request(record_file):
    s = us.status("")
    assert not s.ok and s.reason_code == "no_request"


def test_status_unknown_request(record_file, monkeypatch):
    import corpusfm
    _seed_restart_scheduled(record_file, old_v=corpusfm.__version__, applied_v="0.999999")
    s = us.status("upd_does_not_exist")
    assert not s.ok and s.reason_code == "unknown_request"


def test_status_reconciles_to_restarted_when_running_matches(record_file, monkeypatch):
    import corpusfm
    _seed_restart_scheduled(record_file, old_v="0.1", applied_v="0.777")
    monkeypatch.setattr(corpusfm, "__version__", "0.777")     # running == applied → restarted
    s = us.status("")
    assert s.ok and s.record["state"] == "restarted"
    # idempotent: a second poll stays restarted
    assert us.status("").record["state"] == "restarted"


def test_status_stays_scheduled_when_still_old(record_file, monkeypatch):
    import corpusfm
    _seed_restart_scheduled(record_file, old_v="0.500", applied_v="0.777")
    monkeypatch.setattr(corpusfm, "__version__", "0.500")     # still the pre-restart process
    s = us.status("")
    assert s.ok and s.record["state"] == "restart_scheduled"


def test_status_head_mismatch_is_named_not_silent_success(record_file, monkeypatch):
    import corpusfm
    _seed_restart_scheduled(record_file, old_v="0.500", applied_v="0.777")
    monkeypatch.setattr(corpusfm, "__version__", "0.900")     # neither old nor applied
    s = us.status("")
    assert s.ok and s.record["state"] == "head_mismatch"


# ── completed privileged update: report first, then restart the caller ─────────────────

def test_completed_privileged_update_schedules_the_web_restart(monkeypatch):
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.is_published", lambda: True)
    monkeypatch.setattr(us, "privileged_updater_state", lambda: us.PRIVILEGED_PRESENT)
    monkeypatch.setattr(us, "_trigger_privileged_update", lambda **_k: us.ApplyResult(
        True, "ok", 200, request_id="upd_done"))
    scheduled = []
    monkeypatch.setattr(us, "_default_restart_scheduler", lambda supervised: scheduled.append(supervised))

    result = us.apply(expected_head="b" * 40, actor="tester")

    assert result.ok
    assert scheduled == [True], "the web caller was not scheduled to restart after reporting success"


def test_refused_privileged_update_does_not_restart_the_web_caller(monkeypatch):
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.is_published", lambda: True)
    monkeypatch.setattr(us, "privileged_updater_state", lambda: us.PRIVILEGED_PRESENT)
    monkeypatch.setattr(us, "_trigger_privileged_update", lambda **_k: us.ApplyResult(
        False, "unclean_tree", 409))
    monkeypatch.setattr(us, "_default_restart_scheduler", lambda _supervised: pytest.fail(
        "a refused update scheduled a restart"))

    result = us.apply(expected_head="b" * 40, actor="tester")

    assert not result.ok and result.reason_code == "unclean_tree"


def test_check_reports_heads_and_apply_allowed(git_repo, monkeypatch):
    monkeypatch.setattr(updater, "_run_git", _fake_git(head="a" * 40, origin="b" * 40))

    def fake_cfu(repo=None):
        return updater.UpdateResult(
            update_available=True, latest_version="0.9003", current_version="0.9000",
            checked=True, source="git", behind=3, schema_change=False, installer_change=False)

    monkeypatch.setattr(updater, "check_for_update", fake_cfu)
    res = us.check()
    assert res.current_head == "a" * 40 and res.target_head == "b" * 40
    assert res.behind == 3 and res.update_available is True
    assert res.apply_allowed is True and res.apply_blocked_reason == ""
    pub = res.to_public_dict()
    assert pub["target_head"] == "b" * 40 and pub["apply_allowed"] is True
    assert "error_detail" not in pub                     # raw git tail withheld from the public view


def test_service_does_not_resurrect_retired_topology_or_run_installer():
    """The current MCP is folded into the web process (packet 1124 first gate): the shared authority must
    not revive the retired separate-MCP service / port-reconcile / sudo-broker, nor execute the installer
    or force a hard reset beyond the one tightly-scoped ORIG_HEAD rollback."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "corpusfm/server/update_service.py").read_text()
    # Retired separate-MCP-service / port-reconcile / sudo-broker helpers must never reappear, and the
    # module must not shell out via os.system / a sudo subprocess (sudo + install.sh appear ONLY as the
    # copy-paste operator handoff STRING in operator_command, never executed).
    for banned in ("corpusfm-mcp", "cfm-mcp-ctl", "os.system", 'subprocess.run(["sudo',
                   "subprocess.Popen"):
        assert banned not in src, f"update_service resurrects a retired/forbidden mechanism: {banned!r}"
    # The old rule here was "the only hard reset targets ORIG_HEAD", scanned with a regex. After
    # 1246-03-03 that loop matched NOTHING and passed unconditionally — a guard that has become an
    # assertion about the absence of a mechanism should say so, not iterate over an empty set.
    #
    # The rule is now stronger and stated directly: this module performs no repository mutation of
    # any kind. Every one of these is the elevated operation's, and a service that could run one
    # would have the privilege boundary back.
    for mutating in ('"reset"', '"pull"', '"merge"', '"checkout"', '"fetch"', '"clean"'):
        assert mutating not in src, (
            f"update_service performs a git {mutating} — the service does not touch the checkout"
        )
    # The read-only check still reads a ref, and it may only ever be the updater's fixed one —
    # never a name this module composes. (Asserted against the constant, not against the string
    # "origin/main", which appears in the prose explaining why the elevated side resolves it.)
    assert "updater._REMOTE_BRANCH" in src


# ── same-head build-stamp repair (stale runtime _build.txt on a CURRENT checkout) ────

def _patch_stamp(monkeypatch, *, head_build="1765", written="1765", readback="1765"):
    """Control the git-derived HEAD build number + the write/read-back stamp for repair tests."""
    from corpusfm import buildstamp
    monkeypatch.setattr(buildstamp, "git_build_number", lambda repo=None, timeout=10: head_build)
    monkeypatch.setattr(buildstamp, "write_stamp", lambda repo=None: written)
    monkeypatch.setattr(buildstamp, "read_stamp", lambda: readback)


def _tracking_git(head="a" * 40, origin="a" * 40, count="1765"):
    """A _fake_git that also records every git call — so a test can prove NO pull happened."""
    calls: list = []
    base = _fake_git(head=head, origin=origin, count=count)

    def fake(repo, *args, timeout=15):
        calls.append(args)
        return base(repo, *args, timeout=timeout)

    return fake, calls


def test_check_reports_stamp_repair_on_stale_stamp(git_repo, monkeypatch):
    from corpusfm import buildstamp
    monkeypatch.setattr(updater, "_run_git", _fake_git(head="a" * 40, origin="a" * 40))
    monkeypatch.setattr(updater, "check_for_update",
                        lambda repo=None: updater.UpdateResult(
                            update_available=False, latest_version="0.1765", current_version="0.1745",
                            checked=True, source="git", behind=0))
    monkeypatch.setattr(buildstamp, "git_build_number", lambda repo=None, timeout=10: "1765")
    res = us.check()
    assert res.current_head == "a" * 40 and res.target_head == "a" * 40
    assert res.stamp_repair is True and res.head_build_version == "0.1765"
    assert res.update_available is False
    # NOT described as already_current, and NOT a git-update apply.
    assert res.apply_blocked_reason == "stamp_repair" and res.apply_allowed is False
    pub = res.to_public_dict()
    assert pub["stamp_repair"] is True and pub["head_build_version"] == "0.1765"


def test_check_no_stamp_repair_when_stamp_matches(git_repo, monkeypatch):
    from corpusfm import buildstamp
    monkeypatch.setattr(updater, "_run_git", _fake_git(head="a" * 40, origin="a" * 40))
    monkeypatch.setattr(updater, "check_for_update",
                        lambda repo=None: updater.UpdateResult(
                            update_available=False, latest_version="0.1765", current_version="0.1765",
                            checked=True, source="git", behind=0))
    monkeypatch.setattr(buildstamp, "git_build_number", lambda repo=None, timeout=10: "1765")
    res = us.check()
    assert res.stamp_repair is False and res.apply_blocked_reason == "already_current"


def test_check_apply_blocked_when_installer_required(git_repo, monkeypatch):
    monkeypatch.setattr(updater, "_run_git", _fake_git(head="a" * 40, origin="b" * 40))

    def fake_cfu(repo=None):
        return updater.UpdateResult(
            update_available=True, latest_version="0.9003", current_version="0.9000",
            checked=True, source="git", behind=1, schema_change=False, installer_change=True,
            installer_reason="the dependency lock changed; the runtime must be rebuilt")

    monkeypatch.setattr(updater, "check_for_update", fake_cfu)
    res = us.check()
    assert res.apply_allowed is False and res.apply_blocked_reason == "needs_installer"
    assert res.operator_command
    assert "github.com/CORPUSfm/CORPUSfm/releases" in res.operator_command


def _published_with_updater(monkeypatch):
    """Put this process on the published route with the fixed one-shot present.

    Packet 1251 replaced `os.name == "nt"` with the installation question, so a test that wants the
    privileged route must now say it is an installed service rather than name a platform — which is
    the whole point of the change: both installers ship the same one-shot, and the POSIX trigger was
    always the sudoers-granted `systemctl start`.
    """
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.development_layout_active", lambda: False)
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.is_published", lambda: True)
    monkeypatch.setattr(us, "privileged_updater_state", lambda: us.PRIVILEGED_PRESENT)


def test_an_installed_check_uses_the_privileged_updater_as_a_refusal_only_observer(
        tmp_path, monkeypatch):
    """The web identity never reads the private-repository credential.

    RE-AIMED (packet 1251): this was `test_WINDOWS_check_uses_the_privileged_task…` and selected the
    route by patching `us.os` to `nt`. The rule it defends — an explicit check delegates to the fixed
    privileged observer with an impossible consent, and classifies only what that operation left
    behind — is unchanged and now applies to any published installation. The platform patch is gone
    because the platform no longer decides.
    """
    from corpusfm import updater

    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    _published_with_updater(monkeypatch)
    seen = {}

    def trigger(*, expected_head, actor, audit_outcome):
        seen.update(expected_head=expected_head, actor=actor,
                    audit_outcome=audit_outcome)
        return us.ApplyResult(False, "needs_installer", 409)

    monkeypatch.setattr(us, "_trigger_privileged_update", trigger)
    monkeypatch.setattr(updater, "_repo_root", lambda: repo)
    monkeypatch.setattr(updater, "_git_update", lambda root, *, fetch_remote: updater.UpdateResult(
        True, current_version="0.1", latest_version="0.2", checked=True, behind=1,
        installer_change=True, installer_reason="this update changes layout"))
    monkeypatch.setattr(us, "_rev_parse",
                        lambda _root, ref: "b" * 40 if ref == "HEAD" else "c" * 40)
    monkeypatch.setattr(updater, "is_dirty", lambda _root: False)
    monkeypatch.setattr(us, "is_stamp_stale", lambda *_args: (False, "0.1"))

    result = us.check(refresh=True)

    assert seen == {"expected_head": "0" * 40, "actor": "update_check",
                    "audit_outcome": False}
    assert result.checked and result.target_head == "c" * 40
    assert result.apply_blocked_reason == "needs_installer"
    assert not result.apply_allowed
    assert result.observation == us.OBSERVATION_OBSERVED


def test_WINDOWS_refusal_only_observation_is_not_a_failed_apply_audit(monkeypatch):
    """Refreshing refs writes task correlation evidence, not an UPDATE_APPLIED audit event."""
    from types import SimpleNamespace

    outcome = SimpleNamespace(
        state="refused", detail="consent differs", log_path="", reason_code="target_changed",
        operation_id="op-1", resulting_head="b" * 40, observed_head="a" * 40,
        rolled_back=False,
    )
    monkeypatch.setattr("corpusfm.server.audit.record",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(
                            AssertionError("observation must not emit an apply audit")))

    result = us._outcome_result(outcome, "request-1", actor="update_check",
                                audit_outcome=False)

    assert not result.ok
    assert result.reason_code == "target_changed"


# ── the two rules that SURVIVE the deleted route, re-expressed against the new one ────
#
# `test_single_flight_refuses_concurrent_apply` and `test_record_is_0600_atomic_and_privacy_safe`
# were deleted with the self-pull they drove, but what they defended is unchanged: two updates must
# not run at once, and the request record must not be world-readable or carry a secret. Both are
# asserted here through `apply()`'s surviving path — the rule re-expressed against the new code,
# rather than the old assertion patched until it passed.

def test_two_updates_cannot_run_at_once(monkeypatch, tmp_path):
    """Single-flight, on the trigger path. The second caller is refused, not queued."""
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.is_published", lambda: True)
    monkeypatch.setattr(us, "privileged_updater_state", lambda: us.PRIVILEGED_PRESENT)
    assert us._UPDATE_LOCK.acquire(blocking=False)
    try:
        result = us.apply(expected_head="b" * 40, actor="tester")
    finally:
        us._UPDATE_LOCK.release()
    assert not result.ok
    assert result.reason_code == "update_in_progress"


def test_the_request_the_service_writes_is_private_and_carries_no_secret(tmp_path, monkeypatch):
    """The record's privacy rule, on the request the trigger now writes.

    Three fields, `0600`, and nothing that could select code — the file crosses a privilege
    boundary, so what is in it and who can read it are the same question.
    """
    import json
    import os
    import stat as _stat

    from corpusfm.lifecycle import update_boundary as ub

    state = tmp_path / "state"
    (state / "update-inbox").mkdir(parents=True)
    (state / "update-outcome").mkdir(parents=True)
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.is_published", lambda: True)
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.state_dir", lambda: state)
    monkeypatch.setattr("corpusfm.lifecycle.update_boundary.assert_outcome_authority",
                        lambda *a, **k: None)
    monkeypatch.setattr(us, "privileged_updater_state", lambda: us.PRIVILEGED_PRESENT)
    monkeypatch.setattr(us, "_OUTCOME_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(us, "_OUTCOME_POLL_SECONDS", 0.01)
    seen = {}

    def trigger(*a, **k):
        # Inspected when the updater would read it: an unclaimed request is withdrawn afterwards.
        request = ub.request_path(state)
        seen["mode"] = _stat.S_IMODE(os.stat(request).st_mode)
        seen["payload"] = json.loads(request.read_text())
        return __import__("subprocess").CompletedProcess(a[0] if a else [], 0, "", "")

    monkeypatch.setattr("subprocess.run", trigger)

    us.apply(expected_head="b" * 40, actor="tester")

    assert seen["mode"] == 0o600
    payload = seen["payload"]
    assert set(payload) == {"trigger_id", "expected_head", "actor"}
    from corpusfm.lifecycle.secret_guard import assert_no_secrets
    assert_no_secrets(payload, what="update request")


# ══════════════════════════════════════════════════════════════════════════════════════
# Packet 1251 — Linux update checks go through the privileged observer, and the passive
# callers do not trigger it. The rules below are the ones that would fail SILENTLY: a
# service-side fetch on an installed box "works" on a developer machine and is impossible
# on a real one, and a poll that triggers a root one-shot per browser looks fine until two
# users load a page at once.
# ══════════════════════════════════════════════════════════════════════════════════════

def _installed(monkeypatch, *, updater_state=None):
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.development_layout_active", lambda: False)
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.is_published", lambda: True)
    monkeypatch.setattr(us, "privileged_updater_state",
                        lambda: updater_state or us.PRIVILEGED_PRESENT)


def _no_fetch_allowed(monkeypatch, repo):
    """Make a service-side fetch fail the test rather than merely be unlikely."""
    from corpusfm import updater

    seen = {"fetch_remote": None, "check_for_update": 0}

    def _git_update(root, *, fetch_remote=True):
        seen["fetch_remote"] = fetch_remote
        assert fetch_remote is False, "the web process fetched into the deployed checkout"
        return updater.UpdateResult(False, current_version="0.1", latest_version="0.1",
                                    checked=True, behind=0)

    def _check_for_update(repo_dir=None):
        seen["check_for_update"] += 1
        raise AssertionError("an installed check called the direct fetching path")

    monkeypatch.setattr(updater, "_git_update", _git_update)
    monkeypatch.setattr(updater, "check_for_update", _check_for_update)
    monkeypatch.setattr(updater, "_repo_root", lambda: repo)
    monkeypatch.setattr(us, "_rev_parse", lambda _r, ref: "a" * 40)
    monkeypatch.setattr(updater, "is_dirty", lambda _r: False)
    monkeypatch.setattr(us, "is_stamp_stale", lambda *_a: (False, "0.1"))
    return seen


def test_a_PASSIVE_installed_check_triggers_nothing_and_fetches_nothing(tmp_path, monkeypatch):
    """D2. The sidebar polls this in every authenticated user's browser."""
    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    _installed(monkeypatch)
    seen = _no_fetch_allowed(monkeypatch, repo)
    monkeypatch.setattr(us, "_trigger_privileged_update",
                        lambda **_k: pytest.fail("a passive check triggered the privileged updater"))

    res = us.check()

    assert res.observation == us.OBSERVATION_CLASSIFIED
    assert seen["fetch_remote"] is False and seen["check_for_update"] == 0


def test_an_EXPLICIT_installed_check_triggers_the_observer_and_says_so(tmp_path, monkeypatch):
    """CONTROL for the test above: the same box, the same code, refresh=True — and it DOES trigger.

    Without this half, a `check()` that had quietly stopped observing anything at all would satisfy
    the passive test perfectly.
    """
    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    _installed(monkeypatch)
    _no_fetch_allowed(monkeypatch, repo)
    triggered = []
    monkeypatch.setattr(us, "_trigger_privileged_update",
                        lambda **kw: triggered.append(kw) or us.ApplyResult(
                            False, "target_changed", 409))

    res = us.check(refresh=True)

    assert triggered and triggered[0]["expected_head"] == "0" * 40, \
        "the observation used a consent value that could authorize something"
    assert res.observation == us.OBSERVATION_OBSERVED


@pytest.mark.parametrize("state,reason", [
    (us.PRIVILEGED_ABSENT, "privileged_updater_unavailable"),
    (us.PRIVILEGED_UNKNOWN, "privileged_updater_unavailable"),
])
def test_an_installed_box_without_a_usable_updater_REFUSES(tmp_path, monkeypatch, state, reason):
    """Required behavior 5: fail closed with a specific reason, never a direct fetch.

    `unknown` refuses for the same reason `absent` does — there is no second route, so a probe that
    could not run must not be reported as an installation that has no updater.
    """
    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    _installed(monkeypatch, updater_state=state)
    _no_fetch_allowed(monkeypatch, repo)

    for refresh in (False, True):
        res = us.check(refresh=refresh)
        assert not res.checked and res.error_class == reason, (refresh, res.error_class)


def test_an_INDETERMINATE_installation_refuses_rather_than_fetching(tmp_path, monkeypatch):
    """Neither published nor an explicitly selected development tree is not a licence to fetch."""
    from corpusfm.lifecycle.errors import LifecycleError

    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.development_layout_active", lambda: False)

    def _unclear():
        raise LifecycleError("no readable installation record")

    monkeypatch.setattr("corpusfm.lifecycle.app_paths.is_published", _unclear)
    _no_fetch_allowed(monkeypatch, repo)

    res = us.check()
    assert not res.checked and res.error_class == "installation_state_unclear"


def test_an_EXPLICIT_development_tree_keeps_its_own_direct_path(tmp_path, monkeypatch):
    """Required behavior 6, and the clean half of the refusals above.

    A guard that only proved "installed boxes refuse to fetch" would also pass against a build that
    had broken the development path entirely — which is the path the whole suite runs on.
    """
    from corpusfm import updater

    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr("corpusfm.lifecycle.app_paths.development_layout_active", lambda: True)
    monkeypatch.setattr(us, "_trigger_privileged_update",
                        lambda **_k: pytest.fail("a development check triggered the updater"))
    called = []
    monkeypatch.setattr(updater, "check_for_update",
                        lambda repo_dir=None: called.append(repo_dir) or updater.UpdateResult(
                            False, current_version="0.1", latest_version="0.1", checked=True))
    monkeypatch.setattr(updater, "_repo_root", lambda: repo)
    monkeypatch.setattr(us, "_rev_parse", lambda _r, _ref: "a" * 40)
    monkeypatch.setattr(updater, "is_dirty", lambda _r: False)
    monkeypatch.setattr(us, "is_stamp_stale", lambda *_a: (False, "0.1"))

    res = us.check()
    assert called == [None] and res.observation == us.OBSERVATION_DIRECT


def test_a_DIVERGENT_checkout_is_a_refusal_not_an_available_update(tmp_path, monkeypatch):
    """D3. `behind` is non-zero for a diverged tree as well as a stale one.

    The elevated updater refuses the first with `not_fast_forward` after its own merge-base check, so
    offering it here as an ordinary update invites an authorization that can only be refused — and
    describes a broken checkout as a routine upgrade.
    """
    from corpusfm import updater

    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    _installed(monkeypatch)
    monkeypatch.setattr(updater, "_repo_root", lambda: repo)
    monkeypatch.setattr(updater, "_git_update", lambda root, *, fetch_remote: updater.UpdateResult(
        True, current_version="0.1", latest_version="0.9", checked=True, behind=4))
    monkeypatch.setattr(us, "_rev_parse",
                        lambda _r, ref: ("b" * 40) if ref == "HEAD" else ("c" * 40))
    monkeypatch.setattr(updater, "is_dirty", lambda _r: False)
    monkeypatch.setattr(us, "is_stamp_stale", lambda *_a: (False, "0.1"))
    monkeypatch.setattr(us, "_is_ancestor", lambda *_a: False)

    res = us.check()

    assert res.diverged is True
    assert res.update_available is False, "a divergent checkout was offered as an update"
    assert res.apply_blocked_reason == "not_fast_forward" and not res.apply_allowed
    assert res.error_class == "not_fast_forward"


def test_CONTROL_an_ordinary_behind_checkout_is_still_an_update(tmp_path, monkeypatch):
    """The clean half of D3: the refusal must not swallow the ordinary case it sits next to."""
    from corpusfm import updater

    repo = tmp_path / "src"
    (repo / ".git").mkdir(parents=True)
    _installed(monkeypatch)
    monkeypatch.setattr(updater, "_repo_root", lambda: repo)
    monkeypatch.setattr(updater, "_git_update", lambda root, *, fetch_remote: updater.UpdateResult(
        True, current_version="0.1", latest_version="0.9", checked=True, behind=4))
    monkeypatch.setattr(us, "_rev_parse",
                        lambda _r, ref: ("b" * 40) if ref == "HEAD" else ("c" * 40))
    monkeypatch.setattr(updater, "is_dirty", lambda _r: False)
    monkeypatch.setattr(us, "is_stamp_stale", lambda *_a: (False, "0.1"))
    monkeypatch.setattr(us, "_is_ancestor", lambda *_a: True)

    res = us.check()

    assert res.diverged is False and res.update_available is True
    assert res.apply_blocked_reason == "" and res.apply_allowed


def test_the_ancestry_probe_reads_gits_three_valued_contract(tmp_path, monkeypatch):
    """Exit 1 is "not an ancestor"; 128 is a probe that could not run. Only the first is divergence.

    The first version of `_is_ancestor` returned `rc == 0`, which called every unreadable checkout
    divergent — a confident wrong verdict, caught by a test whose heads are not real objects.
    """
    from corpusfm import updater

    class _R:
        def __init__(self, rc):
            self.returncode = rc

    for rc, expected in ((0, True), (1, False), (128, True)):
        monkeypatch.setattr(updater, "_run_git", lambda *_a, _rc=rc, **_k: _R(_rc))
        assert us._is_ancestor(tmp_path, "a" * 40, "b" * 40) is expected, rc

    def _boom(*_a, **_k):
        raise OSError("git is not installed")

    monkeypatch.setattr(updater, "_run_git", _boom)
    assert us._is_ancestor(tmp_path, "a" * 40, "b" * 40) is True


def test_SETTINGS_consumes_the_shared_authority_and_never_the_direct_fetcher():
    """Required behavior 4, asserted where it can regress silently.

    The Settings route called `updater.check_for_update()` directly, so Settings and MCP could report
    different answers on the same box — and on an installed Linux box that call fetches into
    administrator-owned Git metadata it cannot write, which is not a thing a test on a developer
    machine notices.
    """
    import ast
    import pathlib

    route = (pathlib.Path(__file__).resolve().parents[1]
             / "corpusfm/app/web/routes/api/settings.py").read_text(encoding="utf-8")
    body = route[route.index("def check_update("):route.index("def _upgrade_command(")]
    # COMMENTS EXCLUDED, because this guard's subject has to be named in the code it guards: the
    # route explains why it no longer calls the direct fetcher, and a raw text scan flagged that
    # explanation as the violation. This repo has paid for that mistake twice before.
    code = "\n".join(line.split("#", 1)[0] for line in body.splitlines())
    assert "update_service.check(" in code, "Settings no longer consumes the shared authority"
    assert "check_for_update" not in code, "Settings reached for the direct fetching path again"

    # And the route is honest about which observation it asked for.
    assert "refresh: bool = False" in code and '"observation": res.observation' in code

    tree = ast.parse(route)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "check_update")
    defaults = {a.arg: d for a, d in zip(fn.args.args[-len(fn.args.defaults):], fn.args.defaults)}
    assert "refresh" in defaults and defaults["refresh"].value is False, (
        "the route's default is not passive — a plain GET would trigger a privileged observation, "
        "which is what the all-users sidebar poll sends")


def test_the_PASSIVE_default_is_what_the_sidebar_actually_sends():
    """The other end of the same rule. A passive default is worth nothing if the poller opts in.

    Asserted against the shipped markup rather than reasoned about: the sidebar's fetch must carry no
    `refresh`, and the deliberate button must carry one.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "corpusfm/app/web/templates"
    base = (root / "base.html").read_text(encoding="utf-8")
    start = base.index("async _checkUpdate()")
    poll = base[start:base.index("cfm_upd_ts", start)]
    # A slice that came out EMPTY would satisfy every assertion below. The first version of this
    # guard ended at `_verGt(`, whose first occurrence is ABOVE the poller — so it scanned nothing
    # and would have passed against a poller that asked for a privileged observation on every tick.
    assert "fetch(" in poll, "the sidebar poll could not be located; this guard scanned nothing"
    # Comment lines stripped for the same reason as above — the comment there says "no `refresh`".
    poll_code = "\n".join(l for l in poll.splitlines() if not l.strip().startswith("//"))
    assert "/api/settings/check-update'" in poll_code and "refresh" not in poll_code, \
        "the all-users sidebar poll asks for a privileged observation"

    settings = (root / "settings.html").read_text(encoding="utf-8")
    assert "checkUpdate(true)" in settings, "no deliberate action requests a fresh observation"
    assert "?refresh=true" in settings
