"""A TEST-ONLY copy of the real Linux executor, with ONLY its two validators replaced.

**Why this exists.** The validators run `/usr/sbin/nginx` and `/usr/sbin/apache2` — fixed, absolute,
and required to be root-owned inside a root-owned directory. That is the correct production policy
and it is exactly what an unprivileged off-box suite cannot satisfy: it can create neither a
root-owned file nor `/usr/sbin`. So the transaction tests — placement, backups, idempotence,
residue, fingerprints, restoration, the whole walk — had no way to reach past validation, and 21 of
them went red the moment the policy landed.

Codex ruled the seam belongs in the TEST, not the product: no sysroot prefix, no caller- or
environment-supplied validator, no injectable policy answer. So this materializes a copy and swaps
the two validator functions for deterministic outcomes at their explicit boundary. **Production
paths, the `validator_usable` policy and every line of transaction code are copied verbatim.**

**The division of labour, stated so neither suite is mistaken for the other:**

* this materialized copy proves **transaction behaviour** — what the executor does with files;
* `tests/test_linux_proxy_validators.py` proves **command authority and validation semantics** —
  which binary may run, and what its outcomes mean. It never uses this module.

The transformation is guarded rather than trusted: each named function must be found exactly once,
and removing the replaced definitions from the copy must leave a remainder byte-identical to the
source with its originals removed. Anything else raises, so a copy that quietly diverged from the
shipped executor cannot be the thing a green test measured.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REAL_EXECUTOR = ROOT / "installer" / "linux" / "cfm-proxy-exec.sh"

#: The two functions this module may replace, and nothing else.
REPLACEABLE = ("validate_nginx", "validate_apache")

VALID = "valid"
INVALID = "invalid"
UNAVAILABLE = "unavailable"

#: `2` is *cannot validate*, `1` is *proven bad*. Both restore; the caller reports them differently.
_RC = {VALID: 0, INVALID: 1, UNAVAILABLE: 2}


class TransformationRefused(AssertionError):
    """The copy is not the shipped executor with exactly two bodies swapped."""


def _span(text: str, name: str) -> tuple[int, int]:
    header = f"{name}() {{"
    if text.count(header) != 1:
        raise TransformationRefused(
            f"{name} appears {text.count(header)} times in the executor; the transformation "
            "replaces exactly one definition and will not guess which")
    start = text.index(header)
    end = text.index("\n}\n", start) + len("\n}\n")
    return start, end


def materialize(destination: Path, *, outcome: str = VALID, source: Path | None = None) -> Path:
    """Write the instrumented copy to ``destination`` and return it.

    ``outcome`` selects what BOTH validators answer: valid, invalid, or unavailable.
    """
    if outcome not in _RC:
        raise TransformationRefused(f"unknown validator outcome {outcome!r}")
    original = (source or REAL_EXECUTOR).read_text(encoding="utf-8")

    spans = {name: _span(original, name) for name in REPLACEABLE}
    if len({spans[a] for a in spans}) != len(REPLACEABLE):
        raise TransformationRefused("two functions resolved to the same span")

    new = original
    for name in sorted(REPLACEABLE, key=lambda n: spans[n][0], reverse=True):
        start, end = spans[name]
        new = (new[:start]
               + f"{name}() {{\n  # TEST-ONLY: deterministic {outcome}\n  return {_RC[outcome]}\n}}\n"
               + new[end:])

    _assert_nothing_else_changed(original, new)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(new, encoding="utf-8")
    os.chmod(destination, 0o755)
    return destination


def _assert_nothing_else_changed(original: str, new: str) -> None:
    """Remove both definitions from each side; what remains must be byte-identical.

    This is the whole guard. Comparing the two texts directly would only say they differ; comparing
    them with the intended edits excised says WHERE they differ, and that it is nowhere else.
    """
    def stripped(text: str) -> str:
        out = text
        for name in sorted(REPLACEABLE, key=lambda n: _span(text, n)[0], reverse=True):
            start, end = _span(text, name)
            out_start, out_end = _span(out, name)
            out = out[:out_start] + out[out_end:]
        return out

    if stripped(original) != stripped(new):
        raise TransformationRefused(
            "the materialized executor differs from the shipped one outside the two validator "
            "functions; it is not the executor under test")


def instrumented_root(base: Path, *, outcome: str = VALID) -> Path:
    """Convenience: a materialized executor under ``base``, named as it is installed."""
    return materialize(base / "cfm-proxy-exec.sh", outcome=outcome)
