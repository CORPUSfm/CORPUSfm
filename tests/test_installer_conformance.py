"""Two cross-cutting guards owned by installer integration (packet 1246-04).

`test_both_installers_render_every_placeholder_and_refuse_a_leftover` reads the two installers and
guards their publication of the updater artifacts.
`test_every_shipped_powershell_script_is_ascii` is the repository-wide PowerShell encoding fence.

The rest of the updater-surface evidence lives in `tests/test_privileged_update_artifacts.py`, which
is wholly 1246-03-03-owned by subject: it covers the updater artifacts, installed trusted helper,
outcome boundary and updater-facing UI/API truth. Ownership does not depend on a test count or on
which particular files an individual test happens to read.

**This does not start 1246-04.** Nothing here is staged or committed for that owner, and its own
installer-integration tests — what the installers create, register and render on a real box — are
still unwritten.

*One thing 1246-04 will want to strengthen and which is deliberately NOT strengthened here:* the
placeholder test asserts only the five placeholders the installers actually render, so it passes
while `@@HELPER@@`, `@@PUBLISHER@@`, `@@LIB_DIR@@` and `@@GIT@@` go unrendered. `render_updater`'s
successor refuses a surviving placeholder, so installation fails closed — but this test does not see
it, and closing that is the installer owner's call.
"""

from __future__ import annotations

import pathlib
import re

INSTALLER = pathlib.Path(__file__).resolve().parent.parent / "installer"


def test_both_installers_render_every_placeholder_and_refuse_a_leftover():
    # RE-EXPRESSED (packet 1246-04-05; §4D.0 asked for five→nine, and correction F went further).
    #
    # The rule is unchanged: **every placeholder the shipped updater carries must be filled, or the
    # installed artifact runs a placeholder as a literal path AS ROOT/SYSTEM.** What changed is who
    # fills them. This asserted five `@@…@@` literals in the INSTALLER text — and Linux rendered
    # exactly those five of nine, so `install.sh` died at phase 13 on every box while this guard
    # stayed green on the five it happened to name. Both installers now call the shipped renderer,
    # which derives all nine from the published record and refuses on any it did not fill.
    from corpusfm.lifecycle import update_boundary as ub

    sh = (INSTALLER / "linux" / "install.sh").read_text(encoding="utf-8")
    ps1 = (INSTALLER / "windows" / "install.ps1").read_text(encoding="utf-8")
    assert "render_linux_updater" in sh and "render_windows_updater" in ps1, (
        "an installer hand-renders the elevated updater instead of calling the shipped renderer"
    )
    for body in (sh, ps1):
        assert not re.search(r"(sed -e \"s\|@@|Replace\('@@)", body), (
            "a hand-rendered placeholder substitution is back"
        )
    # The app renderer receives verified template bytes from this repository; it owns substitutions,
    # not custody of the template.
    for relpath, placeholders in (("linux/corpusfm-update.sh", ub.LINUX_PLACEHOLDERS),
                                  ("windows/corpusfm-update.ps1", ub.WINDOWS_PLACEHOLDERS)):
        template = (INSTALLER / relpath).read_text(encoding="utf-8")
        shipped = {f"@@{n}@@" for n in re.findall(r"@@(\w+)@@", template)}
        assert shipped, f"{relpath} carries no placeholders; this guard would pass vacuously"
        assert shipped <= set(placeholders), (
            f"{relpath}: the renderer knows nothing about {sorted(shipped - set(placeholders))}"
        )
    assert "unrendered placeholders" in sh and "unrendered placeholders" in ps1, (
        "an unrendered placeholder must refuse installation, not ship a broken elevated script"
    )


def test_every_shipped_powershell_script_is_ascii():
    """PowerShell 5.1 reads a BOM-less .ps1 as ANSI.

    The existing guard covered only `_cfm_lib.ps1`, which is a rule enforced where the risk is
    smallest. Every shipped .ps1 has the same exposure, and all of them already comply — so this is
    a fence around current behaviour, not a migration.
    """
    offenders = {}
    for script in sorted((INSTALLER / "windows").glob("*.ps1")):
        bad = [i + 1 for i, line in enumerate(script.read_text(encoding="utf-8").splitlines())
               if not line.isascii()]
        if bad:
            offenders[script.name] = bad[:3]
    assert not offenders, f"non-ASCII lines in shipped PowerShell: {offenders}"
