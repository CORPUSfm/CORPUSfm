"""Apache publication is BYTE-EXACT, because the file it edits has no terminal newline.

**The defect, measured on fms-server 2026-08-08 (E5).** The FMS-shipped
`HTTPServer/conf/extra/httpd-proxy.conf` ends with `</Location>` and **no `\\n`**. The executor
appended the marked block, so `</Location>` and `# CORPUSFM` landed on one line and Apache refused
the entire configuration::

    Syntax error on line 59 of …/extra/httpd-proxy.conf:
    </Location>#> directive missing closing '>'

Validation then failed, the transaction restored, and the run reported `rolled_back` — on a run where
`fms-nginx` had already published, validated, restarted and **activated** successfully. One missing
byte was the whole of it.

**Why a line-oriented fix is not available.** `strip_block` removes the pair with
`awk NR<a || NR>b`, and awk always emits a terminal newline — so a removal built on it could never
restore a file that had none. Apache therefore gets a byte-exact pair of operations:

    <original bytes, exactly><owned \\n><opening marker>…<closing marker at EOF>

One deliberately owned separator, appended whether or not the original ended with a newline, so the
original bytes are always an exact prefix and removal is always "drop the last N bytes". **nginx is
untouched** — it inserts inside the 443 server block rather than appending.

**E3.** The executor is run as a real process against a fixture tree; only its two validators are
swapped for deterministic outcomes, through the same materializer the rest of the suite uses.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests import proxy_exec_materialize as mz

ROOT = Path(__file__).resolve().parents[1]
EXEC = ROOT / "installer" / "linux" / "cfm-proxy-exec.sh"
MARK = "CORPUSFM"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the Linux executor is a bash script")

APACHE_REL = ("HTTPServer", "conf", "extra", "httpd-proxy.conf")
NGINX_REL = ("NginxServer", "conf", "fms_nginx.conf")

#: Verbatim in shape from the box: a `<Location>` block whose file ends with NO newline.
NO_TRAILING_NEWLINE = (
    "ProxyRequests Off\n"
    "<Proxy *>\n"
    "    Require all granted\n"
    "</Proxy>\n"
    '<Location "/fmi">\n'
    "    ProxyPreserveHost On\n"
    "</Location>"
)
ONE_TRAILING_NEWLINE = NO_TRAILING_NEWLINE + "\n"
EMPTY = ""

NGINX_BODY = (
    "http {\n"
    "    server {\n"
    "        listen 443 ssl;\n"
    '        include "fms_fac.conf";\n'
    "    }\n"
    "}\n"
)

TIMEOUT_SHIM = """#!/bin/sh
secs="$1"; shift
"$@"
"""


def fms_root(tmp_path, *, apache_body=NO_TRAILING_NEWLINE):
    root = tmp_path / "fms"
    apache = Path(root, *APACHE_REL)
    apache.parent.mkdir(parents=True, exist_ok=True)
    apache.write_text(apache_body, encoding="utf-8")
    nginx = Path(root, *NGINX_REL)
    nginx.parent.mkdir(parents=True, exist_ok=True)
    nginx.write_text(NGINX_BODY, encoding="utf-8")
    main = root / "HTTPServer" / "conf" / "httpd.conf"
    main.write_text('ServerRoot "${HTTP_ROOT}"\nInclude conf/extra/httpd-proxy.conf\n',
                    encoding="utf-8")
    shim = root / "shim"
    shim.mkdir(parents=True, exist_ok=True)
    (shim / "timeout").write_text(TIMEOUT_SHIM, encoding="utf-8")
    (shim / "timeout").chmod(0o755)
    return root


def rendered(root, proxy_type):
    from corpusfm.lifecycle.proxy_render import INCLUDE_NAME, render_block, render_include

    out = root / "rendered"
    out.mkdir(parents=True, exist_ok=True)
    include_path = str(root / "NginxServer" / "conf" / INCLUDE_NAME)
    block = out / f"block-{proxy_type}.txt"
    block.write_text(render_block(proxy_type, prefix="/corpusfm", port=8533,
                                  include_path=include_path if "nginx" in proxy_type else None),
                     encoding="utf-8")
    inc = out / "include.txt"
    inc.write_text(render_include(prefix="/corpusfm", port=8533), encoding="utf-8")
    return block, inc


def run(root, verb, proxy_type, *, validator=mz.VALID, expect=None):
    script = mz.materialize(root / "instrumented" / "cfm-proxy-exec.sh", outcome=validator)
    argv = [str(script), verb, proxy_type, "--fms-root", str(root)]
    if verb == "publish":
        block, inc = rendered(root, proxy_type)
        argv += ["--block-file", str(block), "--include-file", str(inc)]
    env = dict(os.environ, PATH=f"{root / 'shim'}:{os.environ['PATH']}")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env)
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    if expect is not None:
        assert proc.returncode == expect, (proc.returncode, proc.stdout, proc.stderr)
    return proc.returncode, payload


def apache_bytes(root):
    return Path(root, *APACHE_REL).read_bytes()


# ── the original bytes are an exact prefix, in all three shapes ──────────────────────

@pytest.mark.parametrize("body,label", [
    (NO_TRAILING_NEWLINE, "no terminal newline"),
    (ONE_TRAILING_NEWLINE, "one terminal newline"),
    (EMPTY, "empty file"),
])
def test_publish_keeps_the_ORIGINAL_BYTES_as_an_exact_prefix(tmp_path, body, label):
    root = fms_root(tmp_path, apache_body=body)
    before = apache_bytes(root)

    run(root, "publish", "apache", expect=0)
    after = apache_bytes(root)

    assert after.startswith(before), f"{label}: the original bytes are not a prefix"
    assert after[len(before):len(before) + 1] == b"\n", \
        f"{label}: the owned separator is not exactly one newline"


@pytest.mark.parametrize("body,label", [
    (NO_TRAILING_NEWLINE, "no terminal newline"),
    (ONE_TRAILING_NEWLINE, "one terminal newline"),
    (EMPTY, "empty file"),
])
def test_publish_produces_SYNTACTICALLY_SEPARATED_content(tmp_path, body, label):
    """The marker must begin its own line. This is the defect, stated directly."""
    root = fms_root(tmp_path, apache_body=body)
    run(root, "publish", "apache", expect=0)
    text = Path(root, *APACHE_REL).read_text(encoding="utf-8")

    marker_lines = [line for line in text.splitlines() if line.strip() == f"# {MARK}"]
    assert len(marker_lines) == 2, f"{label}: {marker_lines}"
    assert "</Location># " not in text, f"{label}: the block was joined to the previous line"
    for line in text.splitlines():
        assert not (line.strip().endswith(">") and MARK in line), \
            f"{label}: a directive and a marker share a line: {line!r}"


# ── the inverse operations restore the original exactly ──────────────────────────────

@pytest.mark.parametrize("body", [NO_TRAILING_NEWLINE, ONE_TRAILING_NEWLINE, EMPTY])
def test_a_VALIDATION_FAILURE_restores_the_exact_bytes(tmp_path, body):
    root = fms_root(tmp_path, apache_body=body)
    before = apache_bytes(root)

    _code, payload = run(root, "publish", "apache", validator=mz.INVALID, expect=1)
    assert payload["restored"] is True and payload["restore_verified"] is True
    assert apache_bytes(root) == before, "the restoration was not byte-exact"


@pytest.mark.parametrize("body", [NO_TRAILING_NEWLINE, ONE_TRAILING_NEWLINE, EMPTY])
def test_PUBLISH_RETIRE_REMOVE_restores_the_exact_bytes(tmp_path, body):
    """The durable backup is GONE after `retire`, so this proves the inverse operation itself.

    A restoration that only works while a backup survives is not an inverse; it is a rescue.
    """
    root = fms_root(tmp_path, apache_body=body)
    before = apache_bytes(root)

    run(root, "publish", "apache", expect=0)
    assert apache_bytes(root) != before
    run(root, "retire", "apache", expect=0)
    assert not list(Path(root, *APACHE_REL).parent.glob("*.cfmbak*")), \
        "a backup survived retire; this control would not prove the inverse"

    run(root, "remove", "apache", expect=0)
    assert apache_bytes(root) == before, "remove did not restore the original bytes"


@pytest.mark.parametrize("body", [NO_TRAILING_NEWLINE, ONE_TRAILING_NEWLINE, EMPTY])
def test_a_SECOND_PUBLISH_is_byte_idempotent_with_one_block(tmp_path, body):
    root = fms_root(tmp_path, apache_body=body)
    run(root, "publish", "apache", expect=0)
    once = apache_bytes(root)
    run(root, "retire", "apache", expect=0)

    run(root, "publish", "apache", expect=0)
    twice = apache_bytes(root)

    assert twice == once, "a second publish did not reproduce the same bytes"
    assert twice.count(f"# {MARK}".encode()) == 2, "more than one block survived"


# ── geometry this executor did not create is REFUSED, unchanged ──────────────────────

def _publish_then(root, mutate):
    run(root, "publish", "apache", expect=0)
    run(root, "retire", "apache", expect=0)
    path = Path(root, *APACHE_REL)
    path.write_bytes(mutate(path.read_bytes()))
    return path.read_bytes()


def test_a_CLOSING_MARKER_NOT_AT_EOF_refuses_and_changes_nothing(tmp_path):
    """An operator appended their own directive after our block. Removing it by line number would
    take their bytes with it, so this refuses instead."""
    root = fms_root(tmp_path)
    before = _publish_then(root, lambda b: b + b"\n# an operator's own line\n")

    _code, payload = run(root, "publish", "apache", expect=2)
    assert payload["ok"] is False
    assert "geometry" in payload["detail"] or "byte-inexactly" in payload["detail"], payload
    assert apache_bytes(root) == before, "a refusal changed the file"
    assert not list(Path(root, *APACHE_REL).parent.glob("*.cfmbak*")), \
        "a refusal created a backup; it must refuse BEFORE any mutation"


def test_a_MISSING_OWNED_SEPARATOR_refuses_and_changes_nothing(tmp_path):
    """The block is present and final, but the newline before it is not ours — so the bytes before
    it are not an original this executor can restore."""
    root = fms_root(tmp_path)

    def strip_separator(raw: bytes) -> bytes:
        marker = f"# {MARK}".encode()
        at = raw.index(marker)
        assert raw[at - 1:at] == b"\n"
        return raw[:at - 1] + raw[at:]

    before = _publish_then(root, strip_separator)

    _code, payload = run(root, "publish", "apache", expect=2)
    assert payload["ok"] is False
    assert apache_bytes(root) == before, "a refusal changed the file"


def test_a_file_that_BEGINS_with_the_block_refuses(tmp_path):
    """No original prefix means nothing to restore, so there is no byte-exact removal to perform.

    This is the REACHABLE half of "there is room for an owned separator". The byte-value check
    beside it is unreachable by construction — a marker only counts when it starts a line, so the
    byte before it is already a newline — and is kept as belt and braces, labelled as such.
    """
    root = fms_root(tmp_path, apache_body=EMPTY)
    run(root, "publish", "apache", expect=0)
    run(root, "retire", "apache", expect=0)
    path = Path(root, *APACHE_REL)
    # Drop the owned separator that sits at offset 0 of an originally-empty file, so the block now
    # begins the file.
    raw = path.read_bytes()
    assert raw.startswith(b"\n")
    path.write_bytes(raw[1:])
    before = path.read_bytes()

    _code, payload = run(root, "publish", "apache", expect=2)
    assert payload["ok"] is False
    assert path.read_bytes() == before, "a refusal changed the file"


def test_a_MALFORMED_separator_refuses(tmp_path):
    """A space where the owned newline should be: present, wrong, and not guessable."""
    root = fms_root(tmp_path)

    def swap_separator(raw: bytes) -> bytes:
        marker = f"# {MARK}".encode()
        at = raw.index(marker)
        return raw[:at - 1] + b" " + raw[at:]

    before = _publish_then(root, swap_separator)
    _code, payload = run(root, "publish", "apache", expect=2)
    assert payload["ok"] is False
    assert apache_bytes(root) == before


# ── nginx is untouched ───────────────────────────────────────────────────────────────

def test_NGINX_BYTES_AND_BEHAVIOUR_are_unchanged(tmp_path):
    """The brace-aware path still inserts INSIDE the 443 server block, and still round-trips."""
    root = fms_root(tmp_path)
    nginx = Path(root, *NGINX_REL)
    before = nginx.read_bytes()

    run(root, "publish", "fms-nginx", expect=0)
    after = nginx.read_text(encoding="utf-8")
    assert after != before.decode()
    # INSIDE the server block: the marker is indented within braces, not appended at EOF.
    assert not after.rstrip().endswith(f"# {MARK}"), "the nginx block was appended at EOF"
    server = after[after.index("server {"):after.index("\n}\n")]
    assert MARK in server, "the nginx block is not inside the 443 server block"

    run(root, "retire", "fms-nginx", expect=0)
    run(root, "remove", "fms-nginx", expect=0)
    assert nginx.read_bytes() == before, "nginx removal is no longer byte-exact"


def test_EACH_FRONT_USES_ITS_OWN_INVERSE_and_the_line_oriented_strip_is_gone():
    """RE-EXPRESSED (2026-08-08). The rule is that Apache's removal is byte-exact — it was
    `strip_block`'s awk, which always emits a terminal newline, that could not be its inverse.

    The nginx half of the old assertion named `strip_block` too, and that is now false for a good
    reason: nginx retires the ATTRIBUTED block ranges (`nginx_strip_owned`) so a retired block and a
    current one can both be removed without touching what sits between them. `strip_block` itself is
    deleted, so neither front can reach it.
    """
    text = EXEC.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "strip_block() {" not in body, "the line-oriented strip is still defined"
    branch = body[body.index('    if [[ -n "$INC" ]]; then'):]
    branch = branch[:branch.index("cat -- \"$tmp\" > \"$CONF\"")]
    assert "nginx_strip_owned" in branch, "nginx does not retire the attributed ranges"
    assert "apache_strip" in branch, "Apache does not use the byte-exact strip"
