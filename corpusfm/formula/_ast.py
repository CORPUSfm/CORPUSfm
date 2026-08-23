"""AST node types for FileMaker formula expressions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Union


@dataclass
class StrLit:
    value: str      # decoded content (escaped quotes resolved)


@dataclass
class NumLit:
    value: str      # original text preserved


@dataclass
class BoolLit:
    value: bool


@dataclass
class PilcrowLit:
    """FileMaker's ¶ constant — a literal carriage return (Char(13)), used as an operand
    (e.g. `$a & ¶ & $b`). A value-position primary, not an operator."""
    pass


@dataclass
class FieldRef:
    table: str
    field: str

    def __str__(self) -> str:
        return f"{self.table}::{self.field}"


@dataclass
class VarRef:
    """A variable reference.

    scope values:
      "$"  — local FM variable ($name)
      "$$" — global FM variable ($$name)
      ""   — let-bound bare name (local to the Let block)
    """
    name:  str
    scope: str = ""


@dataclass
class LetBinding:
    var:   str   # name as written (may include $ or $$)
    value: "Node"


@dataclass
class LetExpr:
    bindings: list[LetBinding]
    body:     "Node"


@dataclass
class WhileExpr:
    """While([ initialVars ]; condition; [ logic ]; result)

    Both bracket blocks use LetBinding — same name = value grammar as Let.
    """
    initial_bindings: list[LetBinding]
    condition:        "Node"
    logic_bindings:   list[LetBinding]
    body:             "Node"


@dataclass
class BracketGroup:
    """A [ expr; expr; ... ] group used as a function argument.

    Covers Substitute's [search; replace] pairs and JSONSetElement's
    [path; value; type] triples.  The contents are ordinary expressions.
    """
    exprs: list["Node"]


@dataclass
class FuncCall:
    name: str          # original case preserved
    args: list["Node"]


@dataclass
class BinOp:
    """Binary operation.

    op values: + - * / ^ & ¶ = ≠ < > ≤ ≥ and or xor
    """
    op:    str
    left:  "Node"
    right: "Node"


@dataclass
class UnaryOp:
    """Unary operation.

    op values: - + not
    """
    op:      str
    operand: "Node"


Node = Union[
    StrLit, NumLit, BoolLit, PilcrowLit,
    FieldRef, VarRef,
    FuncCall, LetExpr, LetBinding, WhileExpr, BracketGroup,
    BinOp, UnaryOp,
]
