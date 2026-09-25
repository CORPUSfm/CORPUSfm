"""Shipped Windows PowerShell must not collect or count a ConvertFrom-Json result inline.

Derived from packet 1380-02 deliverable D-N, and from two live Windows PowerShell 5.1 failures in the
signing lane (runs 34428075417 and 34428715905). The hazard needs two ingredients:

  1. 5.1 emits a parsed JSON array as ONE non-enumerated output object, and
  2. the caller immediately collects that command's output with `@()` or takes `.Count` of it.

Measured, by making PowerShell 7 behave like 5.1 with `Write-Output -NoEnumerate`:
`@(cmdlet)` gives Count=1 with [0] being the array; `$v = cmdlet; @($v)` gives Count=6.

THIS IS A FENCE, NOT A MIGRATION. The D-N audit examined all 23 shipped `ConvertFrom-Json` sites and
found **zero** violations: every one assigns to a variable and reads named fields. The rule therefore
forbids something no shipped script does, and cannot churn correct code.

WHAT THIS DELIBERATELY DOES NOT DO. It does not ban `-Raw | ConvertFrom-Json`. Object-shaped input makes
that form correct and 23 of 23 shipped sites are object-shaped; a blanket ban would churn every one,
bury the real rule, and teach the next reader that the rule is arbitrary. It also does not require a type
test: the audit's "shape laxity" observation is real but version-independent, and folding it in here
would make a 5.1 lint carry a general-robustness opinion it cannot justify.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = sorted((ROOT / "installer/windows").glob("*.ps1")) + [
    ROOT / "installer/bootstrap/windows/bootstrap.ps1"
]

# `@(` ... `ConvertFrom-Json` before the closing paren, on one line.
COLLECTED = re.compile(r"@\(\s*[^)]*ConvertFrom-Json")
# `.Count` taken directly off a parenthesised parse.
COUNTED = re.compile(r"ConvertFrom-Json[^)]*\)\s*\.\s*Count")


def _code_only(text: str) -> str:
    """Strip PowerShell comments, quote-aware.

    A guard whose own docstring and rationale must NAME the forbidden pattern has to exclude comments,
    or it reports its own explanation as a violation - a mistake this repository has made three times.
    """
    out = []
    for line in text.splitlines():
        quote, cut = None, len(line)
        for i, ch in enumerate(line):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "#":
                cut = i
                break
        out.append(line[:cut])
    return "\n".join(out)


def test_the_shipped_script_set_is_what_the_audit_covered():
    """If a new shipped script appears, this lint must be seen to cover it.

    Silence is not a pass: a glob that matched nothing would make every assertion below vacuous.
    """
    assert len(SHIPPED) == 10, [p.name for p in SHIPPED]
    assert all(p.is_file() for p in SHIPPED)
    parsing = [p for p in SHIPPED if "ConvertFrom-Json" in _code_only(p.read_text())]
    assert len(parsing) == 7, [p.name for p in parsing]


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_no_convertfrom_json_result_is_collected_or_counted_inline(path):
    code = _code_only(path.read_text())
    for pattern, why in (
        (COLLECTED, "collected with @() in the same expression"),
        (COUNTED, ".Count taken directly off the parse"),
    ):
        for match in pattern.finditer(code):
            line = code[: match.start()].count("\n") + 1
            raise AssertionError(
                f"{path.name}:{line} — a ConvertFrom-Json result is {why}.\n"
                f"    {code.splitlines()[line - 1].strip()}\n"
                "  On Windows PowerShell 5.1 the cmdlet emits a parsed array as ONE non-enumerated\n"
                "  output object, so this captures a single item - the array itself. Assign it to a\n"
                "  variable first, then normalize that variable:\n"
                "      $parsed = ConvertFrom-Json -InputObject $raw\n"
                "      $rows   = @($parsed)"
            )


def test_the_lint_detects_both_forms_it_forbids():
    """The lint gets its own test, because a pattern that matches nothing passes silently.

    Without this, deleting the regexes would leave every file 'clean'.
    """
    assert COLLECTED.search('$x = @($raw | ConvertFrom-Json)')
    assert COLLECTED.search('$x = @(ConvertFrom-Json -InputObject $raw)')
    assert COUNTED.search('if (($raw | ConvertFrom-Json).Count -eq 0)')
    # ...and does not fire on the correct two-step form, or on an inner property pipeline.
    assert not COLLECTED.search('$p = ConvertFrom-Json -InputObject $raw')
    assert not COLLECTED.search('$rows = @($parsed)')
    assert not COLLECTED.search('$rel.assets | Where-Object { $_.name -eq "x" }')
