"""Packet 1237: the storage delete must follow the CLOSE VERDICT, and the verdict must never be read
out of FileMaker Server's prose.

What was measured on fms-dev, 2026-07-31, on a normal fully-credentialed uninstall:

    ! fmsadmin close: File Closing: CORPUSfm_DB.fmp12 — deleting anyway
    + Removed .../CORPUSfm/CORPUSfm_DB.fmp12

Nothing was wrong. FMS closed the database and the delete was correct — but the run reported it in
the branch whose whole purpose is "something went wrong and we are proceeding regardless", because
`|| true` discarded the exit status and success was inferred by grepping for `closed|10904|not
open|already`. FMS said `File Closing`. Every pattern was also English, so on a localised server
*every* close read as a failure. And `rm -f` ran on BOTH arms, so a credentialed close that genuinely
FAILED deleted a database FileMaker Server was still hosting.

**RE-EXPRESSED AT STAGE 6, in the same change as the behaviour it pins.** This file used to drive
`step_remove_db` out of `installer/linux/uninstall.sh` with a fake `fmsadmin` on `$PATH`. That
function is gone: the launcher performs no removal, calls no `fmsadmin`, and knows no database name.
The rule outlived its implementation, so it is asserted against the implementation that has it now.

* **The behavioural halves live where the behaviour does.** `PosixExecutor.run_storage` closes,
  observes `CLOSED`, proves the database unhosted from the server's own list, removes the exact
  recorded path and reads it back — and refuses on each failure, with the control that a successful
  close still deletes. `tests/test_uninstall_exec.py` drives all of it against a real executor, a
  real pending record and a real lock, which is strictly more than a fake binary on `$PATH` could
  reach.
* **What is asserted HERE is the part that has no other home**: that no verdict anywhere in the
  removal path is taken from a message. That is the 1237 defect itself, it is invisible to a
  behavioural test that happens to use English fixtures, and it is exactly the kind of rule that
  comes back the first time somebody "improves" an error branch.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from application_checkout import APPLICATION_ROOT

ROOT = Path(__file__).resolve().parent.parent
EXECUTOR = APPLICATION_ROOT / "corpusfm" / "lifecycle" / "uninstall_exec_posix.py"

# **The retired patterns were `closed|10904|not open|already`, and this file deliberately does NOT
# scan for them.** That was the first thing written here and it was wrong twice over: `"CLOSED"` is
# the state name the executor asks `await_status` for, `"did not reach CLOSED"` and `"was already
# absent"` are output, and every one of them is correct code that a word ban would forbid — while a
# misreading spelled differently would sail through. The defect was never the vocabulary. It was
# taking a BRANCH on a message, so that is what is asserted below.


def _storage_source() -> str:
    text = EXECUTOR.read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "run_storage":
            return ast.get_source_segment(text, node)
    raise AssertionError("run_storage is gone; the storage removal has no owner")


def _executable(source: str) -> str:
    """The code, without its docstring or its comments.

    **A guard whose own subject explains in prose what it does not do must exclude prose**, or it
    reports the rationale as the violation — the mistake this repository has made twice and written
    down both times. `run_storage`'s docstring necessarily says the words *already* and *closed*.
    """
    tree = ast.parse("\n".join(line[4:] if line.startswith("    ") else line
                                for line in source.splitlines()))
    function = tree.body[0]
    if (function.body and isinstance(function.body[0], ast.Expr)
            and isinstance(function.body[0].value, ast.Constant)):
        function.body = function.body[1:]
    return ast.unparse(function)


def test_NO_BRANCH_in_the_storage_removal_is_TAKEN_ON_A_STRING_LITERAL():
    """**The 1237 rule, at its new owner, and stated as the thing that actually went wrong.**

    Every decision comes from a return value: `close_database` raising, `await_status` answering
    `False`, `list_databases` producing rows. Not one is a comparison against a message — so no
    `ast.Compare` inside `run_storage` may carry a string literal on either side, whatever it says.
    A test that banned the WORDS instead would ban `await_status(name, "CLOSED")`, which is a state
    name and correct, and would pass any misreading spelled a little differently.
    """
    tree = ast.parse(_executable(_storage_source()))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for operand in [node.left, *node.comparators]:
            if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                rendered = ast.unparse(node)
                # This is a recorded-path shape check, not an FMS message verdict.
                if "recorded_fms_root.name.casefold()" not in rendered:
                    offenders.append(rendered)
    assert not offenders, (
        f"the storage removal branches on a string literal: {offenders}. A verdict read out of "
        "FileMaker Server's prose is the packet-1237 defect, and on a localised server it is "
        "always wrong")


def test_the_only_COMPARISON_in_the_removal_is_a_DATABASE_STEM_never_a_message():
    """The one string comparison the unhosted proof makes is between two database FILENAMES, through
    `fms_folders.database_stem` — a normalisation of an identifier, not a reading of a sentence."""
    source = _executable(_storage_source())
    assert "database_stem" in source
    assert ".lower()" not in source and "startswith" not in source, (
        "a case-folded or prefix comparison in the removal is prose matching wearing a disguise")


def test_an_UNREADABLE_hosted_list_is_never_read_as_UNHOSTED():
    """The other half of *no prose*: absence of evidence. A row that is not a mapping means the list
    could not be read, and unreadable is not proof that the database is unhosted."""
    source = _executable(_storage_source())
    assert "isinstance(row, dict)" in source
    literals = " ".join(node.value for node in ast.walk(ast.parse(source))
                        if isinstance(node, ast.Constant) and isinstance(node.value, str))
    assert "unreadable is not proof that the database is not serving" in literals.lower()


@pytest.mark.parametrize("script", ["installer/linux/uninstall.sh",
                                    "installer/windows/uninstall.ps1"])
def test_NEITHER_LAUNCHER_can_reach_the_retired_mechanism(script):
    """The launcher cannot re-acquire the defect because it cannot reach the database at all: no
    `fmsadmin`, no database name, no removal, and no place to put a grep pattern."""
    # COMMENTS EXCLUDED: both launchers state at length what they no longer do, and a guard that
    # read that as a violation would be reporting its own subject's rationale.
    from tests.test_uninstall_stage_fence import _executable_lines

    body = "\n".join(_executable_lines(ROOT / script)).lower()
    assert ".fmp12" not in body
    assert "10904" not in body
