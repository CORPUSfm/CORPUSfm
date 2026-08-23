"""Structural secret fence for lifecycle records and lifecycle output (packet 1246-01).

The packet asks for a *structural* guard, not careful callers: *"Add structural secret-name/value
guards rather than relying only on careful callers."* Two independent halves, because each catches
what the other cannot.

**By name.** Keys are split into tokens on non-alphanumerics and matched whole. Token matching, not
substring matching, is load-bearing: ``pat`` is a denied token and ``path`` and ``patch_hosting_dir``
are legitimate manifest keys — a substring rule would reject the topology this record exists to hold.
A short exact-key allowlist covers the handful of legitimate names that collide (``secrets_dir`` is a
*location*, not a secret).

**By value.** Only unambiguous shapes: a PEM header, a GitHub token prefix, the ``enc:`` marker this
project already uses for Fernet-at-rest, an HTTP bearer credential, and a bare Fernet key. There is
deliberately **no entropy heuristic** — the manifest legitimately carries a PKI public fingerprint
and an installation UUID, and any entropy rule loose enough to spare those is too loose to catch
anything.

``redact`` is the output half of the same fence. It is honest about its reach: it removes values a
caller registered plus the patterns above. It cannot promise that a subprocess never invents a secret
shape nobody has seen, and no claim here should be read that way.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .errors import SecretInLifecycleRecord

_DENIED_NAME_TOKENS: frozenset[str] = frozenset(
    {
        "password",
        "passwords",
        "passwd",
        "passphrase",
        "secret",
        "secrets",
        "token",
        "tokens",
        "pat",
        "credential",
        "credentials",
        "key",
        "keys",
        "keyfile",
        "privatekey",
        "pem",
        "cfmrecovery",
    }
)

# Multi-token names that only read as a secret when adjacent. ``recovery`` and ``file`` are both
# innocent alone; ``recovery_file`` is a path 1246-01 forbids from every schema.
_DENIED_NAME_PHRASES: tuple[tuple[str, ...], ...] = (
    ("recovery", "file"),
    ("private", "key"),
    ("api", "key"),
)

# Names that tokenize into a denied token but denote a LOCATION or an IDENTITY, never a value.
# Exact names only — the TOKEN rule still condemns `keys`, `key`, `keyfile` and the rest. Contents
# are still walked, so the value patterns (a PEM block, a Fernet key, a `.cfmrecovery` path) remain
# in force inside anything allowlisted here.
#   secrets_dir    — where secrets live, not a secret.
#   key_locations  — the key migration's record: a state word, a source kind, two canonical paths.
_ALLOWED_EXACT_KEYS: frozenset[str] = frozenset({"secrets_dir", "key_locations"})

_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("pem block", re.compile(r"-----BEGIN [A-Z ]+-----")),
    ("github token", re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{16,}\b")),
    ("github fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("fernet-at-rest marker", re.compile(r"(?:^|\s)enc:[A-Za-z0-9_\-=]{8,}")),
    ("bearer credential", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{12,}")),
    ("raw fernet key", re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}=(?![A-Za-z0-9_\-=])")),
    # 1246-01 forbids recovery-file paths from every schema. The name half catches a field CALLED
    # one; this catches a path that IS one arriving through a free-form value — an ownership
    # identifier, a journal backup reference, a migration consumer.
    ("recovery file path", re.compile(r"\.cfmrecovery\b", re.IGNORECASE)),
    # An environment-style assignment of a secret-named variable (packet 1246-03). The NAME rules
    # above only see a field's key; this is the shape a secret takes when it arrives inside a
    # free-text VALUE — a detail line, a captured command, an excerpt of `.mcp_env`, which is
    # literally `CORPUSFM_MCP_TOKEN=<hex>` and which this packet now moves between directories.
    (
        "secret assignment",
        re.compile(
            r"\b[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|APIKEY|API_KEY)"
            r"[A-Za-z0-9_]*\s*[=:]\s*\S{8,}",
            re.IGNORECASE,
        ),
    ),
)

_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def _tokens(name: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT.split(name.lower()) if t]


def name_is_secretish(name: str) -> str | None:
    """Return the reason ``name`` reads as a secret, or ``None``."""
    if name in _ALLOWED_EXACT_KEYS:
        return None
    tokens = _tokens(name)
    for token in tokens:
        if token in _DENIED_NAME_TOKENS:
            return f"key token {token!r} names a secret"
    joined = "_".join(tokens)
    for phrase in _DENIED_NAME_PHRASES:
        if "_".join(phrase) in joined:
            return f"key phrase {' '.join(phrase)!r} names a secret"
    return None


def value_is_secretish(value: str) -> str | None:
    """Return the reason ``value`` reads as a secret, or ``None``."""
    for label, pattern in _VALUE_PATTERNS:
        if pattern.search(value):
            return f"value looks like a {label}"
    return None


def scan(obj: Any, *, path: str = "$") -> list[str]:
    """Walk a JSON-shaped object and return every secret finding, deepest first-encountered order."""
    findings: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = f"{path}.{key}"
            if isinstance(key, str):
                reason = name_is_secretish(key)
                if reason:
                    findings.append(f"{here}: {reason}")
            findings.extend(scan(value, path=here))
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            findings.extend(scan(value, path=f"{path}[{index}]"))
    elif isinstance(obj, str):
        reason = value_is_secretish(obj)
        if reason:
            findings.append(f"{path}: {reason}")
    return findings


def assert_no_secrets(obj: Any, *, what: str) -> None:
    """Raise ``SecretInLifecycleRecord`` if anything in ``obj`` reads as a secret."""
    findings = scan(obj)
    if findings:
        raise SecretInLifecycleRecord(
            f"refusing to write {what}: " + "; ".join(findings)
        )


REDACTION = "[redacted]"


def redact(text: str, *, registered: Iterable[str] = ()) -> str:
    """Remove registered secret values and known secret shapes from one line of output.

    Registered values go first and are matched literally, so a caller that knows a concrete secret
    (an FMS password it just prompted for) gets an exact removal rather than a pattern guess.
    """
    out = text
    for value in registered:
        if value and len(value) >= 4 and value in out:
            out = out.replace(value, REDACTION)
    for _label, pattern in _VALUE_PATTERNS:
        out = pattern.sub(REDACTION, out)
    return out
