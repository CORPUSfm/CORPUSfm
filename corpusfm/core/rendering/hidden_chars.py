"""Make invisible characters visible in rendered FM text.

apply(text)  ->  text with hidden characters marked:
  • U+00A0 NBSP              → [NBSP]
  • Trailing spaces          → · (middle dot, one per space)
  • Trailing tabs            → → (rightwards arrow, one per tab)
  • Control chars (non-print) → [U+xxxx]

"Trailing" means at the end of each line and at the end of the string.
Spaces and tabs inside a line are left unchanged — they are intentional
developer whitespace in calculations.
"""

from __future__ import annotations

_NBSP = " "

# Characters that are valid in a calculation but should be flagged:
# everything below 0x20 except \t (0x09), \n (0x0A), \r (0x0D), and 0x7F DEL.
_CONTROL_SAFE = frozenset("\t\n\r")


def _mark_trailing_whitespace(text: str) -> str:
    """Replace trailing spaces/tabs on each line with visible markers."""
    lines = text.split("\n")
    marked = []
    for line in lines:
        stripped = line.rstrip(" \t")
        tail = line[len(stripped):]
        visible = "".join("·" if c == " " else "→" for c in tail)
        marked.append(stripped + visible)
    return "\n".join(marked)


def _mark_control_chars(text: str) -> str:
    """Replace non-printable control characters with [U+xxxx] markers."""
    result = []
    for ch in text:
        cp = ord(ch)
        if (cp < 0x20 and ch not in _CONTROL_SAFE) or cp == 0x7F:
            result.append(f"[U+{cp:04X}]")
        else:
            result.append(ch)
    return "".join(result)


def apply(text: str) -> str:
    """Mark all hidden characters in text. Returns the annotated string."""
    text = text.replace(_NBSP, "[NBSP]")
    text = _mark_trailing_whitespace(text)
    text = _mark_control_chars(text)
    return text
