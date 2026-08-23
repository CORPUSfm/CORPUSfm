"""The OS-native executors, EXECUTED (packet 1246-06 §6.5, §14).

Static source-string assertions are insufficient and the packet says so. Every test here runs a real
script against a real fixture tree and reads its real JSON, because the defects these executors exist
to fix are all behavioural: a backup nobody can find, an `awk` toggle that deletes to end of file,
and a validator that could be a system binary.

The FMS root is a fixture directory, so nothing here touches a real FileMaker Server — which is also
what proves an executor is bounded to the root it is given.

**Why the Windows suite is driven from this file** (a deliberate deviation, reported at closure).
The packet names two new executed suites — this one and `tests/ps/cfm-proxy-exec.tests.ps1` — but a
`.ps1` is not collectable by pytest, so without a runner the PowerShell suite would exist and never
run, which this project's own rule calls not enforced at all. The runner lives here rather than in a
sixth new test file so the file set stays exactly what §11.1 lists, and rather than in
`test_windows_nginx_proxy.py`, which §11.1 marks NOT owned and NOT modified.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests import proxy_exec_materialize as mz

ROOT = Path(__file__).resolve().parents[1]
EXEC = ROOT / "installer" / "linux" / "cfm-proxy-exec.sh"
MARK = "CORPUSFM"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the Linux executor is a bash script")

NGINX_CONF = ("NginxServer", "conf", "fms_nginx.conf")
APACHE_CONF = ("HTTPServer", "conf", "extra", "httpd-proxy.conf")

NGINX_BODY = (
    "http {\n"
    "    server {\n"
    "        listen 80;\n"
    "        server_name _;\n"
    "    }\n"
    "    server {\n"
    "        listen 443 ssl;\n"
    '        include "fms_fac.conf";\n'
    "        ###OTTO\n"
    '        include "otto_https.conf";\n'
    "        ###OTTO\n"
    "    }\n"
    "}\n"
)
APACHE_BODY = "# FMS proxy config\n<VirtualHost *:443>\n</VirtualHost>\n"

# A `timeout` shim, kept on PATH DELIBERATELY AND INERT (2026-08-09).
#
# It used to be load-bearing: the bound was `command -v timeout`, macOS ships none, so without this
# every nginx publish rolled back as "cannot validate". The bound is now the fixed `/usr/bin/timeout`
# under the privileged-command policy, so NOTHING here can select this — which is precisely why it
# stays. Every flow below runs with it first on PATH, so a regression that reintroduces a PATH lookup
# would find a shim that answers, and `test_a_system_validator_ON_PATH_is_never_consulted` plants a
# marker-touching `timeout` beside the fake validators to catch it directly.
TIMEOUT_SHIM = """#!/bin/sh
secs="$1"; shift
"$@" &
p=$!
# The watchdog's stdio is closed. `out="$(bounded 8 ...)"` reads until every writer releases the
# pipe, so a watchdog that inherits stdout keeps the substitution blocked for the WHOLE bound even
# after the command exits - eight seconds per publish, for nothing.
( sleep "$secs"; kill $p 2>/dev/null ) >/dev/null 2>&1 &
w=$!
wait $p 2>/dev/null; rc=$?
kill $w 2>/dev/null
[ $rc -gt 128 ] && exit 124
exit $rc
"""


def fms_root(tmp_path, *, validator="ok"):
    """A fixture FMS root.

    **No bundled nginx or httpd is planted any more, because neither exists.** Measured on
    fms-server 2026-08-08: `find "<FMS root>" \\( -name nginx -o -name httpd \\) -type f` returns
    nothing — FileMaker Server drives `/usr/sbin/nginx` and `/usr/sbin/apache2`. Planting them here
    was modelling a deployment that does not exist, and it is what let the executor's dependence on
    them go unnoticed until phase 17 rolled back on a live box.

    `validator` now selects the OUTCOME the instrumented copy returns, not a binary to plant.
    """
    root = tmp_path / "fms"
    for rel, body in ((NGINX_CONF, NGINX_BODY), (APACHE_CONF, APACHE_BODY)):
        path = Path(root, *rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    # The Apache MAIN configuration, which is what the real validator checks — the fragment above is
    # only what gets edited. Present so the fixture models the real layout even though the
    # instrumented copy does not read it.
    main = root / "HTTPServer" / "conf" / "httpd.conf"
    main.parent.mkdir(parents=True, exist_ok=True)
    main.write_text('ServerRoot "${HTTP_ROOT}"\nInclude conf/extra/httpd-proxy.conf\n',
                    encoding="utf-8")

    shim = root / "shim"
    shim.mkdir(parents=True, exist_ok=True)
    (shim / "timeout").write_text(TIMEOUT_SHIM, encoding="utf-8")
    (shim / "timeout").chmod(0o755)
    return root


#: `validator=` values, mapped to what the instrumented validators answer.
_OUTCOME = {"ok": mz.VALID, "bad": mz.INVALID, "missing": mz.UNAVAILABLE}


def rendered(root, proxy_type, *, prefix="/corpusfm", port=8533):
    """The block and include this type would get, rendered by the ONE renderer (ruling 4)."""
    from corpusfm.lifecycle.proxy_render import INCLUDE_NAME, render_block, render_include

    out = root / "rendered"
    out.mkdir(parents=True, exist_ok=True)
    include_path = str(root / "NginxServer" / "conf" / INCLUDE_NAME)
    block = out / "block.txt"
    block.write_text(render_block(proxy_type, prefix=prefix, port=port,
                                  include_path=include_path if "nginx" in proxy_type else None),
                     encoding="utf-8")
    inc = out / "include.txt"
    inc.write_text(render_include(prefix=prefix, port=port), encoding="utf-8")
    return block, inc


def run(root, verb, proxy_type, *, prefix="/corpusfm", port=8533, expect=None, render=True,
        validator="ok"):
    """Drive the TEST-ONLY instrumented copy — the real executor with its two validators swapped.

    Everything else in it is the shipped file, byte for byte, and `proxy_exec_materialize` refuses
    the copy if that is not true. What these tests measure is the TRANSACTION; which binary may
    validate, and what its outcomes mean, is `test_linux_proxy_validators.py`'s subject.
    """
    script = mz.materialize(root / "instrumented" / "cfm-proxy-exec.sh",
                            outcome=_OUTCOME[validator])
    argv = [str(script), verb, proxy_type, "--fms-root", str(root)]
    if verb == "publish" and render:
        block, inc = rendered(root, proxy_type, prefix=prefix, port=port)
        argv += ["--block-file", str(block), "--include-file", str(inc)]
    env = dict(os.environ, PATH=f"{root / 'shim'}:{os.environ['PATH']}")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env)
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    if expect is not None:
        assert proc.returncode == expect, (proc.returncode, proc.stdout, proc.stderr)
    return proc.returncode, payload


def conf_of(root, proxy_type):
    return Path(root, *(NGINX_CONF if proxy_type == "fms-nginx" else APACHE_CONF))


def digest(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def backups_in(path: Path):
    return sorted(p.name for p in path.parent.glob("*.cfmbak*"))


# ── the script is well formed and self-contained ──────────────────────────────

def test_the_script_parses_and_is_executable():
    assert EXEC.exists() and os.access(EXEC, os.X_OK)
    assert subprocess.run(["bash", "-n", str(EXEC)]).returncode == 0


def test_the_executor_performs_no_lifecycle_control_of_any_kind():
    """It owns ONE type's filesystem transaction and nothing else. Activation is one shared restart
    planned by the Python engine, and it is the only thing that touches a credential.

    Comments are stripped before scanning, because this rule's own rationale has to name the
    commands it forbids — a mistake made twice before in this repo's guards.
    """
    code = "\n".join(line for line in EXEC.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    for forbidden in ("fmsadmin", "systemctl", "service ", "nginx -s", "apachectl", "nginx -t"):
        assert forbidden not in code, forbidden


def test_no_validator_is_resolved_through_PATH(tmp_path):
    """RE-EXPRESSED (2026-08-08). The surviving rule is FIXED MEASURED validators, never
    PATH-selected ones.

    It used to also assert `command -v httpd` was absent, which read as "the bundled binary is the
    only acceptable one". That premise is retired: measured on fms-server, FMS ships NO nginx or
    httpd under its root and drives `/usr/sbin/nginx` and `/usr/sbin/apache2`. What was always
    load-bearing — and still is — is that the executable is a fixed absolute constant rather than
    whatever PATH happens to resolve.
    """
    code = "\n".join(line for line in EXEC.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    for lookup in ("command -v nginx", "command -v apachectl", "command -v httpd",
                   "which nginx", "which apache", "which httpd"):
        assert lookup not in code, lookup
    assert 'SYSTEM_NGINX="/usr/sbin/nginx"' in code
    assert 'SYSTEM_APACHE="/usr/sbin/apache2"' in code
    # RE-EXPRESSED (2026-08-09). This used to permit exactly one PATH lookup, for `timeout`, on the
    # grounds that the bound is not a validator. It is, however, the program run AS ROOT with the
    # validator as its argument, so PATH choosing it is the same hazard one layer out. There is no
    # permitted lookup any more, and the bound is a fixed constant like the other two.
    assert code.count("command -v") == 0, "a PATH lookup survives"
    assert 'SYSTEM_TIMEOUT="/usr/bin/timeout"' in code


def test_a_system_validator_ON_PATH_is_never_consulted(tmp_path):
    """RE-EXPRESSED from `…_is_the_fms_bundled_binary_never_a_system_one`.

    The old name asserted a premise that is now false — the correct validator IS a system binary, at
    a fixed absolute path. What the poison still proves is the part that never changed: a validator
    planted on PATH under a plausible name is not consulted, because nothing here searches PATH.
    """
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "SYSTEM-VALIDATOR-RAN"
    # `timeout` is planted with them (2026-08-09). It is not a validator, but it is the program run
    # AS ROOT with the validator as its argument, and it used to be the one thing here PATH could
    # choose — so the poison now covers it and this test proves the whole root-run set, not a subset.
    for name in ("apachectl", "httpd", "nginx", "apache2", "timeout"):
        (fake_bin / name).write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
        (fake_bin / name).chmod(0o755)

    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    before = conf.read_bytes()
    # A RENDERED block, so the run reaches the transaction. The old version passed `--prefix/--port`,
    # which this executor does not accept — it never renders — so it refused before publishing and
    # proved only that nothing ran. Reaching the transaction is what makes the poison meaningful.
    block, inc = rendered(root, "apache")
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")
    proc = subprocess.run(
        [str(EXEC), "publish", "apache", "--fms-root", str(root),
         "--block-file", str(block), "--include-file", str(inc)],
        capture_output=True, text=True, env=env, timeout=60)

    assert not marker.exists(), "a PATH-resolved validator was invoked"
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    # The REAL executor runs here. On this box `/usr/sbin/apache2` is absent, so the validator
    # answers *cannot validate* and the transaction restores — the honest outcome, not a pass
    # smuggled in by a fixture.
    assert payload["ok"] is False
    assert payload["restored"] is True and payload["restore_verified"] is True
    assert conf.read_bytes() == before, "the restoration was not byte-exact"


# ── the unmatched marker ──────────────────────────────────────────────────────

@pytest.mark.parametrize("verb", ["observe", "publish", "remove"])
def test_an_unmatched_marker_refuses_and_the_file_is_byte_identical_afterwards(tmp_path, verb):
    """The `awk` skip-toggle in the old helper flips on the first marker and, with no closing
    marker, never flips back — deleting from there to end of file. This is that case."""
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    conf.write_text(APACHE_BODY + f"# {MARK}\n    ProxyPass /a/ http://x/\n", encoding="utf-8")
    before = digest(conf)

    code, payload = run(root, verb, "apache", expect=2)
    assert payload["ok"] is False
    assert "balanced pair" in payload["detail"]
    assert digest(conf) == before, "the file was modified while refusing"


def test_three_markers_refuse_too(tmp_path):
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    conf.write_text(f"# {MARK}\na\n# {MARK}\nb\n# {MARK}\n", encoding="utf-8")
    before = digest(conf)
    _code, payload = run(root, "observe", "apache", expect=2)
    assert payload["ok"] is False
    assert digest(conf) == before


def test_a_balanced_pair_is_observed_with_a_fingerprint(tmp_path):
    """The discriminating half — otherwise the refusals above could pass by refusing everything."""
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    conf.write_text(APACHE_BODY + f"# {MARK}\n    ProxyPass /a/ http://x/\n# {MARK}\n",
                    encoding="utf-8")
    _code, payload = run(root, "observe", "apache", expect=0)
    assert payload["ok"] is True
    assert payload["fingerprint"]


def test_an_absent_block_observes_cleanly(tmp_path):
    root = fms_root(tmp_path)
    _code, payload = run(root, "observe", "apache", expect=0)
    assert payload["ok"] is True and "no CORPUSfm block" in payload["detail"]


# ── publish, validate, restore ────────────────────────────────────────────────

def test_publish_writes_a_marked_block_and_keeps_a_same_directory_backup(tmp_path):
    """Same-directory, not `mktemp`: a process killed between publish and validate left an edited
    FMS config whose only backup was in /tmp — undiscoverable by a later run, gone at reboot."""
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")

    _code, payload = run(root, "publish", "apache", expect=0)

    assert payload["ok"] is True and payload["fingerprint"]
    text = conf.read_text(encoding="utf-8")
    assert text.count(f"# {MARK}") == 2
    # The external prefix is stripped exactly once at the proxy; the app serves unprefixed routes.
    assert "ProxyPass /corpusfm/ http://127.0.0.1:8533/" in text
    assert backups_in(conf) == ["httpd-proxy.conf.cfmbak"]
    assert payload["backup"], "the backup path is reported so a later process can find it"


def test_a_validation_failure_restores_the_exact_bytes_and_verifies_them(tmp_path):
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    before = conf.read_bytes()

    code, payload = run(root, "publish", "apache", expect=1, validator="bad")
    assert payload["ok"] is False
    assert payload["restored"] is True and payload["restore_verified"] is True
    assert conf.read_bytes() == before, "byte-identical, not merely equivalent"
    assert backups_in(conf) == [], "a consumed backup is not left as residue"


def test_a_second_publish_is_idempotent_and_leaves_exactly_one_block(tmp_path):
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    run(root, "publish", "apache", expect=0)
    run(root, "retire", "apache", expect=0)
    run(root, "publish", "apache", expect=0)
    assert conf.read_text(encoding="utf-8").count(f"# {MARK}") == 2


def test_remove_takes_the_block_out_and_leaves_the_rest_untouched(tmp_path):
    """BYTES, exactly — the `rstrip("\\n")` allowance is gone (2026-08-08).

    That allowance is what let the terminal-newline defect through: the FMS-shipped
    `httpd-proxy.conf` ends WITHOUT a newline, and a comparison that strips trailing newlines from
    both sides cannot tell a faithful restoration from one that added or dropped one. The file this
    fixture writes now ends without a newline for the same reason, so the assertion has something to
    be exact about.
    """
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    conf.write_bytes(APACHE_BODY.rstrip("\n").encode("utf-8"))   # the shipped shape: no terminal \n
    original = conf.read_bytes()
    assert not original.endswith(b"\n"), "this control needs a file with no terminal newline"

    run(root, "publish", "apache", expect=0)
    run(root, "retire", "apache", expect=0)

    _code, payload = run(root, "remove", "apache", expect=0)
    assert payload["ok"] is True
    assert conf.read_bytes() == original, "removal was not byte-exact"


def test_restore_puts_the_previous_bytes_back_and_verifies_them(tmp_path):
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    before = conf.read_bytes()
    run(root, "publish", "apache", expect=0)
    assert conf.read_bytes() != before

    _code, payload = run(root, "restore", "apache", expect=0)
    assert payload["ok"] is True and payload["restore_verified"] is True
    assert conf.read_bytes() == before


def test_restore_without_a_backup_fails_rather_than_reporting_success(tmp_path):
    root = fms_root(tmp_path)
    _code, payload = run(root, "restore", "apache", expect=1)
    assert payload["ok"] is False and payload["restore_verified"] is False


# ── residue is fail-closed ────────────────────────────────────────────────────

def test_an_unresolved_residue_refuses_a_new_mutation(tmp_path):
    """A backup beside the file means an operation is unresolved. Mutating over it would destroy
    the only restore point on the box."""
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    run(root, "publish", "apache", expect=0)               # leaves the backup in place
    before = digest(conf)

    _code, payload = run(root, "publish", "apache", expect=2)
    assert payload["ok"] is False
    assert "residue" in payload["detail"]
    assert digest(conf) == before


def test_retire_clears_the_residue_so_the_next_operation_may_proceed(tmp_path):
    root = fms_root(tmp_path)
    conf = conf_of(root, "apache")
    run(root, "publish", "apache", expect=0)
    _code, payload = run(root, "retire", "apache", expect=0)
    assert payload["ok"] is True
    assert backups_in(conf) == []
    run(root, "publish", "apache", expect=0)


# ── the nginx include is CORPUSfm's own file ──────────────────────────────────

def test_the_nginx_include_is_written_on_publish_and_removed_on_restore(tmp_path):
    root = fms_root(tmp_path)
    include = root / "NginxServer" / "conf" / "corpusfm_https.conf"
    conf = conf_of(root, "fms-nginx")
    before = conf.read_bytes()

    # UNAVAILABLE: the validator could not answer (rc 2). It used to be spelled "no bundled nginx",
    # which modelled a deployment that does not exist; the transaction behaviour under test — an
    # unproven change restores itself — is unchanged.
    _code, payload = run(root, "publish", "fms-nginx", expect=1, validator="missing")
    assert payload["restored"] is True and payload["restore_verified"] is True
    assert conf.read_bytes() == before
    assert not include.exists(), "a leftover include is a live edit nobody agreed to keep"


def test_an_include_that_existed_before_is_put_back_not_deleted(tmp_path):
    root = fms_root(tmp_path)
    include = root / "NginxServer" / "conf" / "corpusfm_https.conf"
    include.write_text("location /old {}\n", encoding="utf-8")

    run(root, "publish", "fms-nginx", expect=1, validator="missing")
    assert include.read_text(encoding="utf-8") == "location /old {}\n"


# ── refusals ──────────────────────────────────────────────────────────────────

def test_an_unknown_type_or_verb_refuses(tmp_path):
    root = fms_root(tmp_path)
    # `render=False`: the renderer legitimately refuses to render an nginx/apache block for `iis`,
    # and the point here is the EXECUTOR's own type check, which must fire before anything else.
    _code, payload = run(root, "publish", "iis", expect=2, render=False)
    assert "not a Linux proxy type" in payload["detail"]
    _code, payload = run(root, "frobnicate", "apache", expect=2)
    assert "not a verb" in payload["detail"]


def test_a_missing_fms_root_refuses_rather_than_searching_the_machine(tmp_path):
    proc = subprocess.run([str(EXEC), "observe", "apache"], capture_output=True, text=True,
                          timeout=60)
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["ok"] is False
    assert "--fms-root is required" in payload["detail"]


def test_a_config_absent_from_the_root_refuses(tmp_path):
    root = fms_root(tmp_path)
    conf_of(root, "apache").unlink()
    _code, payload = run(root, "observe", "apache", expect=2)
    assert "no FMS-bundled configuration" in payload["detail"]


def test_every_verb_emits_exactly_one_json_object(tmp_path):
    """The Python dispatcher reads ONE object. Two would make it read the wrong one."""
    root = fms_root(tmp_path)
    block, inc = rendered(root, "apache")
    for verb, expected in (("prepare", 0), ("classify", 0), ("observe", 0), ("publish", 0),
                           ("restore", 0), ("retire", 0)):
        argv = [str(EXEC), verb, "apache", "--fms-root", str(root),
                "--operation-id", "11111111-2222-3333-4444-555555555555",
                "--evidence-dir", str(root / "ev")]
        if verb == "publish":
            argv += ["--block-file", str(block), "--include-file", str(inc)]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                              env=dict(os.environ, PATH=f"{root / 'shim'}:{os.environ['PATH']}"))
        lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
        assert len(lines) == 1, (verb, proc.stdout)
        parsed = json.loads(lines[0])
        assert set(parsed) == {"ok", "restored", "restore_verified", "detail", "fingerprint",
                               "backup", "evidence", "unchanged"}


# ── ruling 5: the include goes INSIDE the unique 443 server block ─────────────

def nginx_conf(root):
    return Path(root, *NGINX_CONF)


def test_a_real_nginx_publish_lands_inside_the_unique_443_server_block(tmp_path):
    """The defect this replaces made `fms-nginx` unable to publish at all.

    The block was appended to end of file - nginx MAIN context - and the include it pulls in
    contains `location` directives, which nginx accepts only inside a `server` block. Either the
    validator rejected the result or (with no bundled nginx) validation was unprovable; both roll
    back. There was no test of a SUCCESSFUL nginx publish, which is why nothing caught it.

    Asserted STRUCTURALLY: the marked block's line numbers must fall between the opening and
    closing braces of the 443 server block, not merely 'be in the file'.
    """
    root = fms_root(tmp_path)
    conf = nginx_conf(root)

    _code, payload = run(root, "publish", "fms-nginx", expect=0)
    assert payload["ok"] is True

    lines = conf.read_text(encoding="utf-8").splitlines()
    marks = [i for i, line in enumerate(lines) if line.strip() == f"# {MARK}"]
    assert len(marks) == 2

    open443 = next(i for i, line in enumerate(lines) if "listen 443" in line)
    depth, close443 = 0, None
    for i in range(open443, len(lines)):
        code = lines[i].split("#")[0]
        depth += code.count("{") - code.count("}")
        if i > open443 and depth < 0:
            close443 = i
            break
    # the server block opened one line above `listen 443`
    assert close443 is not None
    assert open443 < marks[0] < marks[1] < close443, (open443, marks, close443)


def test_the_published_include_carries_the_location_directives(tmp_path):
    root = fms_root(tmp_path)
    run(root, "publish", "fms-nginx", expect=0)
    include = Path(root, "NginxServer", "conf", "corpusfm_https.conf")
    body = include.read_text(encoding="utf-8")
    assert "location /corpusfm/ {" in body
    # A trailing slash on the bare authority strips the matched external /corpusfm prefix.
    assert "proxy_pass http://127.0.0.1:8533/;" in body
    # ruling 10: every rendering carries the exact metadata routes.
    from corpusfm.lifecycle.proxy_render import metadata_routes
    for route in metadata_routes("/corpusfm"):
        assert f"location = {route} {{" in body


def test_the_published_fingerprint_equals_what_planning_computed(tmp_path):
    """The round trip ruling 4 exists for: what the executor stores is what `decide` compares
    against. These two digests used to be produced by different code hashing different bytes."""
    from corpusfm.lifecycle.proxy_render import INCLUDE_NAME, desired_fingerprint

    root = fms_root(tmp_path)
    _code, payload = run(root, "publish", "fms-nginx", expect=0)
    expected = desired_fingerprint(
        "fms-nginx", prefix="/corpusfm", port=8533,
        include_path=str(Path(root, "NginxServer", "conf", INCLUDE_NAME)))
    assert payload["fingerprint"] == expected


def test_the_otto_managed_region_is_not_written_into(tmp_path):
    """OttoFMS re-injects its block if it sees its ###OTTO region modified, which duplicates the
    /otto/ location and breaks nginx STARTUP - observed live on 2026-06-19. The insertion point is
    after the closing ###OTTO marker: inside the same server block, outside Otto's region."""
    root = fms_root(tmp_path)
    run(root, "publish", "fms-nginx", expect=0)
    lines = nginx_conf(root).read_text(encoding="utf-8").splitlines()
    otto = [i for i, line in enumerate(lines) if line.strip() == "###OTTO"]
    marks = [i for i, line in enumerate(lines) if line.strip() == f"# {MARK}"]
    assert len(otto) == 2
    assert marks[0] > otto[1], "the block was written inside Otto's managed region"


@pytest.mark.parametrize("body,reason", [
    ("http {\n    server {\n        listen 80;\n    }\n}\n", "no server block listens on 443"),
    ("http {\n    server {\n        listen 443;\n    }\n    server {\n        listen 443;\n    }\n}\n",
     "ambiguous"),
    ("http {\n    server {\n        listen 443;\n", "unbalanced"),
])
def test_zero_multiple_and_unbalanced_443_blocks_refuse_without_touching_a_byte(
        tmp_path, body, reason):
    """Poisoned controls for the structure resolver. A refusal must leave the file byte-identical —
    which is only true because the resolution happens BEFORE the backup and the first write."""
    root = fms_root(tmp_path)
    conf = nginx_conf(root)
    conf.write_text(body, encoding="utf-8")
    before = digest(conf)

    _code, payload = run(root, "publish", "fms-nginx", expect=2)
    assert payload["ok"] is False
    assert reason in payload["detail"], payload["detail"]
    assert digest(conf) == before
    assert not Path(root, "NginxServer", "conf", "corpusfm_https.conf").exists()
    assert backups_in(conf) == [], "a refusal leaves no residue"


def test_a_brace_inside_a_comment_does_not_skew_the_resolver(tmp_path):
    """The discriminating half of the unbalanced case: a commented brace is not a brace."""
    root = fms_root(tmp_path)
    conf = nginx_conf(root)
    conf.write_text(
        "http {\n"
        "    server {\n"
        "        # a stray } and { in a comment\n"
        "        listen 443 ssl;\n"
        "    }\n"
        "}\n", encoding="utf-8")
    _code, payload = run(root, "publish", "fms-nginx", expect=0)
    assert payload["ok"] is True


def test_the_block_is_never_written_to_nginx_main_context(tmp_path):
    """Stated as its own control because it is the failure mode, not a side effect: a block after
    the final closing brace is in main context, where nginx rejects the include's `location`."""
    root = fms_root(tmp_path)
    run(root, "publish", "fms-nginx", expect=0)
    text = nginx_conf(root).read_text(encoding="utf-8")
    tail = text[text.rindex("}") + 1:]
    assert MARK not in tail


def test_publish_refuses_without_a_rendered_block(tmp_path):
    """The executor never renders its own text (ruling 4). Asked to publish with nothing supplied,
    it refuses rather than inventing one."""
    root = fms_root(tmp_path)
    before = digest(nginx_conf(root))
    _code, payload = run(root, "publish", "fms-nginx", expect=2, render=False)
    assert "never renders its own block" in payload["detail"]
    assert digest(nginx_conf(root)) == before


def test_a_failed_nginx_validation_restores_the_bytes_and_removes_the_include(tmp_path):
    root = fms_root(tmp_path)
    conf = nginx_conf(root)
    before = conf.read_bytes()

    _code, payload = run(root, "publish", "fms-nginx", expect=1, validator="bad")
    assert payload["restored"] is True and payload["restore_verified"] is True
    assert conf.read_bytes() == before
    assert not Path(root, "NginxServer", "conf", "corpusfm_https.conf").exists()


# ── the Windows executor, driven the same way ─────────────────────────────────

def _find_pwsh():
    return next((p for p in (shutil.which("pwsh"), shutil.which("powershell")) if p), None)


def test_powershell_semantic_suite():
    """`tests/ps/cfm-proxy-exec.tests.ps1`, executed. It exercises the real script as a process.

    Skipped rather than failed where no PowerShell exists: the suite is the authority on the Windows
    executor's behaviour, and a machine that cannot run it has learned nothing either way.
    """
    pwsh = _find_pwsh()
    if not pwsh:
        pytest.skip("no PowerShell (pwsh/powershell) available")
    script = ROOT / "tests" / "ps" / "cfm-proxy-exec.tests.ps1"
    proc = subprocess.run([pwsh, "-NoProfile", "-File", str(script)],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "failure(s)" in proc.stdout
    assert " 0 failure(s)" in proc.stdout


def test_the_windows_executor_is_ascii_only():
    """PS 5.1 reads a BOM-less .ps1 as ANSI, so one non-ASCII byte corrupts the parser. Asserted
    here as well as in the installer guard, because this file is where the executors are proven."""
    for rel in ("installer/windows/cfm-proxy-exec.ps1", "installer/windows/corpusfm-proxy.ps1"):
        raw = (ROOT / rel).read_bytes()
        bad = [(i, b) for i, b in enumerate(raw) if b > 0x7F]
        assert not bad, f"{rel}: {len(bad)} non-ASCII byte(s), first at offset {bad[0][0]}"


def test_the_windows_executor_takes_no_bool_parameter():
    """A `[bool]` parameter cannot be bound through `-File` at all — PowerShell refuses `$true` and
    `1` alike — and `-File` is exactly how the dispatcher invokes it. Measured, not assumed: the
    first version used `[bool]$ClarisNginxActive` and was unreachable from Python."""
    text = (ROOT / "installer/windows/cfm-proxy-exec.ps1").read_text(encoding="utf-8")
    after = text.split("param(", 1)[1]
    # The block ends where it CLOSES, not at the first `)` — every `[ValidateSet(...)]` has one.
    # And comment lines are dropped, because the rule's own rationale inside the block has to name
    # the thing it forbids; scanning them would report the explanation as the violation.
    block = after[:after.index("\n)")]
    param_block = "\n".join(line for line in block.splitlines()
                            if not line.lstrip().startswith("#"))
    assert "[bool]" not in param_block
    assert "[switch]$ClarisNginxActive" in param_block
