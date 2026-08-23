"""FM formula lexer.

Produces a flat token stream from a FileMaker formula string.
Strips line comments (// …) and block comments (/* … */) in place.
String literals are emitted with their decoded content ("" → " inside).

Field references (TO::Field) are emitted as a single FIELD_REF token so that
names with embedded spaces are handled correctly.  The algorithm:
  - When reading an identifier, scan ahead speculatively over word-chars and
    spaces.  If :: follows, the whole sequence is the TO name (multi-word OK).
  - After ::, read the field name greedily including spaces, trimming trailing.
  - Emit Token(TT.FIELD_REF, "TO::Field", …) as one unit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto

# FileMaker serializes a deleted/broken reference as "<Table Missing>",
# "<Field Missing>", "<Layout Missing>", etc.  These are not real refs.
_MISSING_MARKER = re.compile(r"<[A-Za-z][A-Za-z ]*Missing>")


class TT(Enum):
    STRING    = auto()  # "..."
    NUMBER    = auto()  # 123 / 1.5
    BOOL      = auto()  # True / False
    IDENT     = auto()  # identifier or keyword
    VAR       = auto()  # $name or $$name
    FIELD_REF = auto()  # TO::Field  (whole reference as one token)
    COMMENT   = auto()  # // … or /* … */  (value includes delimiters)
    LPAREN    = auto()  # (
    RPAREN    = auto()  # )
    LBRACK    = auto()  # [
    RBRACK    = auto()  # ]
    SEMI      = auto()  # ;
    COMMA     = auto()  # ,
    PLUS      = auto()  # +
    MINUS     = auto()  # -
    STAR      = auto()  # *
    SLASH     = auto()  # /
    CARET     = auto()  # ^
    AMP       = auto()  # & (text concat)
    PILCROW   = auto()  # ¶ (paragraph concat)
    EQ        = auto()  # =
    NEQ       = auto()  # ≠ / !=
    LT        = auto()  # <
    GT        = auto()  # >
    LTE       = auto()  # ≤ / <=
    GTE       = auto()  # ≥ / >=
    AND       = auto()  # and
    OR        = auto()  # or
    NOT       = auto()  # not
    XOR       = auto()  # xor
    EOF       = auto()


@dataclass(frozen=True)
class Token:
    type:  TT
    value: str
    line:  int
    col:   int

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, {self.line}:{self.col})"


class LexError(Exception):
    pass


_KEYWORDS: dict[str, TT] = {
    "true":  TT.BOOL,
    "false": TT.BOOL,
    "and":   TT.AND,
    "or":    TT.OR,
    "not":   TT.NOT,
    "xor":   TT.XOR,
}

_SINGLE_OPS: dict[str, TT] = {
    "(": TT.LPAREN,  ")": TT.RPAREN,
    "[": TT.LBRACK,  "]": TT.RBRACK,
    ";": TT.SEMI,    ",": TT.COMMA,
    "+": TT.PLUS,    "-": TT.MINUS,
    "*": TT.STAR,
    "^": TT.CARET,   "&": TT.AMP,
    "¶": TT.PILCROW, "=": TT.EQ,
    "≠": TT.NEQ,     "≤": TT.LTE,
    "≥": TT.GTE,     "<": TT.LT,
    ">": TT.GT,
}

# Characters that can appear inside an FM name (TO or field).  FileMaker permits
# far more than [A-Za-z0-9]: '|' (namespacing, e.g. |SITC|), '.' (dotted names),
# '~' (Let-local convention, e.g. ~lineItem) and '!' (e.g. !CartesianConnector).
# '!' is only a name char when it does NOT begin the '!=' operator — that guard
# lives in _scan_name / the tokenizer, not here.  Spaces inside multi-word names
# are handled separately by the _scan_name boundary algorithm.
_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                        "0123456789_.|~!")

# Keyword operators — a whitespace-delimited occurrence terminates a name.
_KEYWORD_OPS = frozenset({"and", "or", "not", "xor"})
# Two-char operators that may follow a name after a space.
_TWO_CHAR_OPS = frozenset({"!=", "<=", ">=", "<>"})


def _is_name_start(c: str) -> bool:
    return c.isalpha() or c in "_~"


def _is_name_body(c: str) -> bool:
    return c in _NAME_CHARS


def _name_char_at(source: str, k: int, n: int) -> bool:
    """True if source[k] is a name-body char, treating '!' as a name char only
    when it does NOT begin the '!=' operator."""
    c = source[k]
    if c == "!":
        return not (k + 1 < n and source[k + 1] == "=")
    return _is_name_body(c)


def _scan_name(source: str, start: int, n: int) -> int:
    """Return the index just past a TO/field name beginning at `start`.

    Reads name-body chars plus internal single spaces, but STOPS at a space that
    precedes an operator, a structural char, or a keyword operator (and/or/not/
    xor).  So `A::b or C::d` yields field `b`, while `My Table::First Name` keeps
    its embedded space.  Trailing spaces are never included.
    """
    i = start
    while i < n:
        c = source[i]
        if c == " ":
            j = i
            while j < n and source[j] == " ":
                j += 1
            if j >= n:
                break                                   # trailing spaces
            if source[j:j + 2] in _TWO_CHAR_OPS or source[j] in _SINGLE_OPS or source[j] in "/:":
                break                                   # space then an operator/structural char
            if not _name_char_at(source, j, n):
                break
            k = j                                        # space then a word
            while k < n and _name_char_at(source, k, n):
                k += 1
            if source[j:k].lower() in _KEYWORD_OPS:
                break                                    # keyword operator ends the name
            i = k
            continue
        if _name_char_at(source, i, n):
            i += 1
            continue
        break                                            # operator / structural char
    return i


def _read_identifier(source: str, start: int, n: int) -> tuple[str, str | None, int]:
    """Read an identifier, detecting whether it is part of a TO::Field reference.

    Reads the first plain word; then a boundary-aware scan (_scan_name) looks for
    a `::`.  If found, the scanned region is the TO name and the field name is
    read the same way.  Otherwise only the first plain word is returned.

    Returns:
        (name, field_or_None, new_pos)
        field_or_None is not None only when :: was found.
    """
    # Read first plain word (no spaces) — the value returned when there is no ::
    j = start
    while j < n and _name_char_at(source, j, n):
        j += 1
    first_end = j

    # A keyword operator (and/or/not/xor/true/false) is never the start of a TO
    # name — return it as its own token so `A::b or C::d` doesn't read `or C` as
    # a table occurrence.
    if source[start:first_end].lower() in _KEYWORDS:
        return source[start:first_end], None, first_end

    # Boundary-aware scan for a (possibly multi-word) TO name, then look for ::
    end = _scan_name(source, start, n)
    k = end
    while k < n and source[k] == " ":
        k += 1
    if k + 1 < n and source[k] == ":" and source[k + 1] == ":":
        to_name = source[start:end].rstrip()
        k += 2  # consume ::
        while k < n and source[k] == " ":
            k += 1
        # Field name — either ${quoted} for illegal names, or a boundary-aware scan
        if k < n and source[k] == "$" and k + 1 < n and source[k + 1] == "{":
            k += 2  # skip ${
            field_start = k
            while k < n and source[k] != "}":
                k += 1
            field_name = source[field_start:k].rstrip()
            if k < n:
                k += 1  # consume }
        else:
            fend = _scan_name(source, k, n)
            field_name = source[k:fend].rstrip()
            k = fend
        return to_name, field_name, k

    # No :: — emit only the first plain word
    return source[start:first_end], None, first_end


def tokenize(source: str, *, resilient: bool = False) -> list[Token]:
    """Tokenize an FM formula.

    resilient=True never raises: an unexpected character or an unterminated
    string/comment is skipped/consumed rather than aborting.  Used by the
    best-effort ref scan so one odd token cannot lose a whole calc's refs.
    """
    tokens: list[Token] = []
    i = 0
    line = 1
    line_start = 0
    n = len(source)

    def col() -> int:
        return i - line_start + 1

    while i < n:
        c = source[i]

        if c == "\n":
            line += 1
            line_start = i + 1
            i += 1
            continue

        if c in " \t\r":
            i += 1
            continue

        # Line comment — emitted as COMMENT token; value includes "//"
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            sl, sc = line, col()
            i += 2
            j = i
            while j < n and source[j] != "\n":
                j += 1
            tokens.append(Token(TT.COMMENT, "//" + source[i:j], sl, sc))
            i = j
            continue

        # Block comment — emitted as COMMENT token (value = the raw span). FileMaker NESTS block
        # comments: it disables a broken calc by wrapping the WHOLE body — an inner /* … */ doc
        # comment included — in an outer /* … */, so an inner */ must NOT close the outer. Track
        # depth and close only when it returns to 0 (a non-nesting scan closed early and leaked the
        # disabled body's references as if live — packet 1028).
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            sl, sc = line, col()
            start = i
            i += 2
            depth = 1
            while i < n and depth > 0:
                if source[i] == "\n":
                    line += 1
                    line_start = i + 1
                    i += 1
                elif source[i] == "/" and i + 1 < n and source[i + 1] == "*":
                    depth += 1
                    i += 2
                elif source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth > 0 and not resilient:
                raise LexError(f"{sl}:{sc}: unterminated block comment")
            tokens.append(Token(TT.COMMENT, source[start:i], sl, sc))
            continue

        # String literal — "" is an escaped quote inside
        if c == '"':
            sl, sc = line, col()
            i += 1
            buf: list[str] = []
            while i < n:
                ch = source[i]
                if ch == "\\" and i + 1 < n:
                    # FM backslash escape (\" \\ \r \n \t …) — consume both chars so
                    # an escaped quote does not terminate the string.
                    nxt = source[i + 1]
                    buf.append({"r": "\r", "n": "\n", "t": "\t"}.get(nxt, nxt))
                    i += 2
                    continue
                if ch == '"':
                    if i + 1 < n and source[i + 1] == '"':
                        buf.append('"')
                        i += 2
                    else:
                        i += 1
                        break
                elif ch == "\n":
                    line += 1
                    line_start = i + 1
                    buf.append(ch)
                    i += 1
                else:
                    buf.append(ch)
                    i += 1
            else:
                if not resilient:
                    raise LexError(f"{sl}:{sc}: unterminated string")
            tokens.append(Token(TT.STRING, "".join(buf), sl, sc))
            continue

        # Variable ($var / $$var) or quoted identifier (${Bad+Name})
        if c == "$":
            sl, sc = line, col()
            # ${...} — quoted name for TO or field with illegal characters
            if i + 1 < n and source[i + 1] == "{":
                i += 2  # skip ${
                j = i
                while j < n and source[j] != "}":
                    j += 1
                quoted = source[i:j]
                if j < n:
                    j += 1  # consume }
                i = j
                # If :: follows, this is a quoted TO name — read the field part
                if i + 1 < n and source[i] == ":" and source[i + 1] == ":":
                    i += 2  # consume ::
                    while i < n and source[i] == " ":
                        i += 1
                    if i < n and source[i] == "$" and i + 1 < n and source[i + 1] == "{":
                        i += 2  # skip ${
                        fj = i
                        while fj < n and source[fj] != "}":
                            fj += 1
                        field_name = source[i:fj].rstrip()
                        if fj < n:
                            fj += 1
                        i = fj
                    else:
                        fj = i
                        while fj < n and (_is_name_body(source[fj]) or source[fj] == " "):
                            fj += 1
                        field_name = source[i:fj].rstrip()
                        i = fj
                    tokens.append(Token(TT.FIELD_REF, f"{quoted}::{field_name}", sl, sc))
                else:
                    # Standalone ${...} not followed by :: — emit as bare IDENT
                    tt = _KEYWORDS.get(quoted.lower(), TT.IDENT)
                    tokens.append(Token(tt, quoted, sl, sc))
                continue
            # Normal $var or $$var
            i += 1
            prefix = "$$" if (i < n and source[i] == "$") else "$"
            if prefix == "$$":
                i += 1
            j = i
            while j < n and _name_char_at(source, j, n):   # FM var names allow | . etc.
                j += 1
            tokens.append(Token(TT.VAR, prefix + source[i:j], sl, sc))
            i = j
            continue

        # Number
        if c.isdigit() or (c == "." and i + 1 < n and source[i + 1].isdigit()):
            sl, sc = line, col()
            j = i
            while j < n and source[j].isdigit():
                j += 1
            if j < n and source[j] == "." and (j + 1 >= n or source[j + 1] != "."):
                j += 1
                while j < n and source[j].isdigit():
                    j += 1
            tokens.append(Token(TT.NUMBER, source[i:j], sl, sc))
            i = j
            continue

        # Merge field <<TO::Field>> — emit the inner reference as a FIELD_REF.
        if c == "<" and i + 1 < n and source[i + 1] == "<":
            close = source.find(">>", i + 2)
            if close != -1:
                inner = source[i + 2:close].strip()
                sl, sc = line, col()
                if "::" in inner:
                    tokens.append(Token(TT.FIELD_REF, inner, sl, sc))
                i = close + 2
                continue

        # A broken FM reference marker (<Table Missing>, <Field Missing>, …) —
        # consume and skip so the rest of the calc still parses.
        if c == "<":
            mm = _MISSING_MARKER.match(source, i)
            if mm:
                i = mm.end()
                continue

        # Two-char operators before single-char
        if i + 1 < n:
            two = source[i:i + 2]
            if two == "::":
                # Bare :: with no preceding identifier — syntax error but lex it
                tokens.append(Token(TT.FIELD_REF, "::", line, col()))
                i += 2
                continue
            if two == "!=":
                tokens.append(Token(TT.NEQ, "!=", line, col()))
                i += 2
                continue
            if two == "<>":
                tokens.append(Token(TT.NEQ, "<>", line, col()))
                i += 2
                continue
            if two == "<=":
                tokens.append(Token(TT.LTE, "<=", line, col()))
                i += 2
                continue
            if two == ">=":
                tokens.append(Token(TT.GTE, ">=", line, col()))
                i += 2
                continue

        if c == "/" and (i + 1 >= n or source[i + 1] not in "/*"):
            tokens.append(Token(TT.SLASH, "/", line, col()))
            i += 1
            continue

        if c in _SINGLE_OPS:
            tokens.append(Token(_SINGLE_OPS[c], c, line, col()))
            i += 1
            continue

        # Identifier, keyword, or field reference
        if _is_name_start(c):
            sl, sc = line, col()
            name, field, end = _read_identifier(source, i, n)
            if field is not None:
                tokens.append(Token(TT.FIELD_REF, f"{name}::{field}", sl, sc))
            else:
                tt = _KEYWORDS.get(name.lower(), TT.IDENT)
                tokens.append(Token(tt, name, sl, sc))
            i = end
            continue

        if resilient:
            i += 1  # skip the unrecognized character and keep going
            continue
        raise LexError(f"{line}:{col()}: unexpected character {c!r}")

    tokens.append(Token(TT.EOF, "", line, col()))
    return tokens
