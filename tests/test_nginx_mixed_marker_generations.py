"""The live mixed-generation nginx file, and the remove-before-add rule that normalizes it.

**The incident (fms-server, 2026-08-08).** `fms_nginx.conf` ended up carrying an owned block in the
RETIRED marker form and one in the CURRENT form, each including the same file. The running nginx kept
serving its already-loaded configuration, so nothing looked wrong — until FMS stopped it and a fresh
nginx could not load the duplicate include. The web front stayed down until the retired block was
removed by hand.

`marker_count` could not see it: its pattern is `#+`, which matches BOTH forms, so a legacy-only file
counts 2 and passes for current while the mixed file counts 4 and lands in `invalid`.

Four checks, deliberately: the live regression, byte preservation, a malformed refusal, and
idempotence.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests import proxy_exec_materialize as mz

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt", reason="the Linux executor is a bash script")

NGINX_REL = ("NginxServer", "conf", "fms_nginx.conf")

#: Surrounding bytes that must survive untouched — FMS's own directives and an unrelated vendor block.
PREAMBLE = (
    "http {\n"
    "    server {\n"
    "        listen 443 ssl;\n"
    '        include "fms_fac.conf";\n'
    "        ###OTTO\n"
    '        include "otto_https.conf";\n'
    "        ###OTTO\n"
)
POSTAMBLE = "    }\n}\n"


def _block(marker, include_path):
    return f"{marker}\n    include \"{include_path}\";\n{marker}\n"


def fms_root(tmp_path, *, blocks=()):
    root = tmp_path / "fms"
    conf = Path(root, *NGINX_REL)
    conf.parent.mkdir(parents=True, exist_ok=True)
    include_path = str(conf.parent / "corpusfm_https.conf")
    body = PREAMBLE + "".join(_block(m, include_path) for m in blocks) + POSTAMBLE
    conf.write_text(body, encoding="utf-8")
    shim = root / "shim"
    shim.mkdir(parents=True, exist_ok=True)
    (shim / "timeout").write_text("#!/bin/sh\nsecs=\"$1\"; shift\n\"$@\"\n", encoding="utf-8")
    (shim / "timeout").chmod(0o755)
    return root


def run(root, verb, *, expect=None, validator=mz.VALID):
    from corpusfm.lifecycle.proxy_render import INCLUDE_NAME, render_block, render_include

    script = mz.materialize(root / "instrumented" / "cfm-proxy-exec.sh", outcome=validator)
    out = root / "rendered"
    out.mkdir(parents=True, exist_ok=True)
    include_path = str(Path(root, *NGINX_REL).parent / INCLUDE_NAME)
    block = out / "block.txt"
    block.write_text(render_block("fms-nginx", prefix="/corpusfm", port=8533,
                                  include_path=include_path), encoding="utf-8")
    inc = out / "include.txt"
    inc.write_text(render_include(prefix="/corpusfm", port=8533), encoding="utf-8")

    argv = [str(script), verb, "fms-nginx", "--fms-root", str(root),
            "--block-file", str(block), "--include-file", str(inc)]
    env = dict(os.environ, PATH=f"{root / 'shim'}:{os.environ['PATH']}")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env)
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    if expect is not None:
        assert proc.returncode == expect, (proc.returncode, proc.stdout, proc.stderr)
    return proc.returncode, payload


def conf_text(root):
    return Path(root, *NGINX_REL).read_text(encoding="utf-8")


def counts(root):
    text = conf_text(root)
    lines = [line.strip() for line in text.splitlines()]
    return {
        "legacy": lines.count("###CORPUSFM"),
        "current": lines.count("# CORPUSFM"),
        "includes": sum(1 for line in lines if "corpusfm_https.conf" in line),
    }


# ── 1. the exact live shape ──────────────────────────────────────────────────────────

def test_THE_LIVE_MIXED_FILE_normalizes_to_one_current_block(tmp_path):
    """One retired block beside one current one — the state that took the web front down."""
    root = fms_root(tmp_path, blocks=("###CORPUSFM", "# CORPUSFM"))
    assert counts(root) == {"legacy": 2, "current": 2, "includes": 2}

    run(root, "publish", expect=0)

    assert counts(root) == {"legacy": 0, "current": 2, "includes": 1}, conf_text(root)


def test_the_OLD_rule_could_not_normalize_it(tmp_path):
    """The `#+` marker count is why: it sees four markers and calls the file invalid, and on a
    legacy-only file it sees two and mistakes them for a current block."""
    root = fms_root(tmp_path, blocks=("###CORPUSFM", "# CORPUSFM"))
    conf = Path(root, *NGINX_REL)
    import re

    old_pattern = re.compile(r"^[ \t]*#+[ \t]*CORPUSFM[ \t]*$")
    matched = [line for line in conf.read_text().splitlines() if old_pattern.match(line)]
    assert len(matched) == 4, matched            # -> `invalid` under marker_state

    legacy_only = fms_root(tmp_path / "b", blocks=("###CORPUSFM",))
    matched = [line for line in Path(legacy_only, *NGINX_REL).read_text().splitlines()
               if old_pattern.match(line)]
    assert len(matched) == 2, matched            # -> `one`, i.e. mistaken for a current block


@pytest.mark.parametrize("blocks", [(), ("###CORPUSFM",), ("# CORPUSFM",),
                                    ("###CORPUSFM", "# CORPUSFM")])
def test_every_accepted_starting_shape_ends_with_one_current_block(tmp_path, blocks):
    root = fms_root(tmp_path, blocks=blocks)
    run(root, "publish", expect=0)
    assert counts(root) == {"legacy": 0, "current": 2, "includes": 1}, conf_text(root)


# ── 2. surrounding bytes ─────────────────────────────────────────────────────────────

def test_UNRELATED_BYTES_are_preserved(tmp_path):
    """FMS's own directives and the unrelated ###OTTO block are carried through untouched."""
    root = fms_root(tmp_path, blocks=("###CORPUSFM", "# CORPUSFM"))
    run(root, "publish", expect=0)
    text = conf_text(root)

    assert text.startswith(PREAMBLE), "the preamble was rewritten"
    assert text.endswith(POSTAMBLE), "the postamble was rewritten"
    assert text.count("###OTTO") == 2 and 'include "otto_https.conf";' in text, \
        "an unrelated vendor block was consumed"
    assert 'include "fms_fac.conf";' in text, "an FMS directive was consumed"


def test_REMOVE_retires_both_generations_and_keeps_surrounding_bytes(tmp_path):
    root = fms_root(tmp_path, blocks=("###CORPUSFM", "# CORPUSFM"))
    run(root, "remove", expect=0)

    assert counts(root) == {"legacy": 0, "current": 0, "includes": 0}, conf_text(root)
    assert conf_text(root) == PREAMBLE + POSTAMBLE, "removal did not leave the original bytes"


# ── 3. malformed geometry refuses, before any mutation ───────────────────────────────

@pytest.mark.parametrize("blocks,why", [
    (("###CORPUSFM", "###CORPUSFM"), "two retired blocks"),
    (("# CORPUSFM", "# CORPUSFM"), "two current blocks"),
    (("## CORPUSFM",), "an unrecognised marker form"),
])
def test_AMBIGUOUS_geometry_refuses_before_mutation(tmp_path, blocks, why):
    root = fms_root(tmp_path, blocks=blocks)
    before = Path(root, *NGINX_REL).read_bytes()

    _code, payload = run(root, "publish", expect=2)
    assert payload["ok"] is False, why
    assert Path(root, *NGINX_REL).read_bytes() == before, f"{why}: the file was changed"
    assert not list(Path(root, *NGINX_REL).parent.glob("*.cfmbak*")), \
        f"{why}: a backup was created, so it did not refuse before mutation"


def test_an_UNBALANCED_marker_refuses(tmp_path):
    root = fms_root(tmp_path)
    conf = Path(root, *NGINX_REL)
    conf.write_text(conf.read_text().replace("    }\n", "# CORPUSFM\n    }\n"), encoding="utf-8")
    before = conf.read_bytes()

    _code, payload = run(root, "publish", expect=2)
    assert payload["ok"] is False
    assert conf.read_bytes() == before


def test_a_FOREIGN_BODY_between_our_markers_refuses(tmp_path):
    """Markers wearing our name around somebody else's directive are not ours to remove."""
    root = fms_root(tmp_path)
    conf = Path(root, *NGINX_REL)
    conf.write_text(conf.read_text().replace(
        "    }\n", "# CORPUSFM\n    proxy_pass http://example.invalid;\n# CORPUSFM\n    }\n"),
        encoding="utf-8")
    before = conf.read_bytes()

    _code, payload = run(root, "publish", expect=2)
    assert payload["ok"] is False
    assert conf.read_bytes() == before


def test_a_STRAY_INCLUDE_outside_any_block_refuses(tmp_path):
    root = fms_root(tmp_path)
    conf = Path(root, *NGINX_REL)
    include_path = str(conf.parent / "corpusfm_https.conf")
    conf.write_text(conf.read_text().replace(
        "    }\n", f'    include "{include_path}";\n    }}\n'), encoding="utf-8")
    before = conf.read_bytes()

    _code, payload = run(root, "publish", expect=2)
    assert payload["ok"] is False
    assert conf.read_bytes() == before


# ── 4. idempotence ───────────────────────────────────────────────────────────────────

def test_a_SECOND_PUBLICATION_is_idempotent(tmp_path):
    root = fms_root(tmp_path, blocks=("###CORPUSFM", "# CORPUSFM"))
    run(root, "publish", expect=0)
    once = conf_text(root)
    run(root, "retire", expect=0)

    run(root, "publish", expect=0)
    assert conf_text(root) == once, "a second publication changed the file"
    assert counts(root) == {"legacy": 0, "current": 2, "includes": 1}
