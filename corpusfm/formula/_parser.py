"""Recursive-descent parser for FileMaker formula expressions.

Operator precedence (low → high):
  or / xor
  and
  not  (prefix unary)
  = ≠ < > ≤ ≥  (comparison)
  &  ¶          (text concatenation)
  + -            (addition / subtraction)
  * /            (multiplication / division)
  ^              (exponentiation, right-associative)
  - +            (unary sign)
  primary        (literals, field refs, variables, function calls, parentheses)
"""
from __future__ import annotations

from ._ast import (
    BinOp, BoolLit, BracketGroup, FieldRef, FuncCall,
    LetBinding, LetExpr, Node, NumLit, PilcrowLit, StrLit, UnaryOp, VarRef, WhileExpr,
)
from ._lexer import LexError, TT, Token, tokenize  # noqa: F401  (TT re-exported)


class ParseError(Exception):
    pass


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    # ── Token navigation ──────────────────────────────────────────────────────

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        t = self._tokens[self._pos]
        if t.type is not TT.EOF:
            self._pos += 1
        return t

    def _check(self, *types: TT) -> bool:
        return self._peek().type in types

    def _match(self, *types: TT) -> Token | None:
        if self._check(*types):
            return self._advance()
        return None

    def _expect(self, tt: TT, desc: str = "") -> Token:
        t = self._peek()
        if t.type is not tt:
            label = desc or tt.name
            raise ParseError(
                f"{t.line}:{t.col}: expected {label}, got {t.type.name} ({t.value!r})"
            )
        return self._advance()

    # ── Entry point ───────────────────────────────────────────────────────────

    def parse(self) -> Node:
        node = self._or_expr()
        if not self._check(TT.EOF):
            t = self._peek()
            raise ParseError(
                f"{t.line}:{t.col}: unexpected token {t.value!r}"
            )
        return node

    # ── Precedence levels ─────────────────────────────────────────────────────

    def _or_expr(self) -> Node:
        left = self._and_expr()
        while self._check(TT.OR, TT.XOR):
            op = self._advance().value.lower()
            left = BinOp(op, left, self._and_expr())
        return left

    def _and_expr(self) -> Node:
        left = self._not_expr()
        while self._check(TT.AND):
            self._advance()
            left = BinOp("and", left, self._not_expr())
        return left

    def _not_expr(self) -> Node:
        if self._check(TT.NOT):
            self._advance()
            return UnaryOp("not", self._not_expr())
        return self._comparison()

    def _comparison(self) -> Node:
        left = self._concat()
        _CMP = {
            TT.EQ: "=", TT.NEQ: "≠",
            TT.LT: "<", TT.GT: ">",
            TT.LTE: "≤", TT.GTE: "≥",
        }
        while self._check(*_CMP):
            op = _CMP[self._advance().type]
            left = BinOp(op, left, self._concat())
        return left

    def _concat(self) -> Node:
        left = self._add_sub()
        while self._check(TT.AMP, TT.PILCROW):
            op = self._advance().value
            left = BinOp(op, left, self._add_sub())
        return left

    def _add_sub(self) -> Node:
        left = self._mul_div()
        while self._check(TT.PLUS, TT.MINUS):
            op = self._advance().value
            left = BinOp(op, left, self._mul_div())
        return left

    def _mul_div(self) -> Node:
        left = self._exponent()
        while self._check(TT.STAR, TT.SLASH):
            op = self._advance().value
            left = BinOp(op, left, self._exponent())
        return left

    def _exponent(self) -> Node:
        base = self._unary()
        if self._check(TT.CARET):
            self._advance()
            return BinOp("^", base, self._exponent())  # right-associative
        return base

    def _unary(self) -> Node:
        if self._check(TT.MINUS):
            self._advance()
            return UnaryOp("-", self._unary())
        if self._check(TT.PLUS):
            self._advance()
            return UnaryOp("+", self._unary())
        return self._primary()

    def _primary(self) -> Node:
        t = self._peek()

        if t.type is TT.LPAREN:
            self._advance()
            node = self._or_expr()
            self._expect(TT.RPAREN, "')'")
            return node

        if t.type is TT.STRING:
            self._advance()
            return StrLit(t.value)

        if t.type is TT.NUMBER:
            self._advance()
            return NumLit(t.value)

        if t.type is TT.BOOL:
            self._advance()
            return BoolLit(t.value.lower() == "true")

        # ¶ in operand position is FileMaker's carriage-return CONSTANT (e.g. `$a & ¶ & $b`),
        # not an operator — a value-position primary. (_concat still treats a bare `a ¶ b` as
        # lenient concat; this handles the far commoner `& ¶ &` operand form.)
        if t.type is TT.PILCROW:
            self._advance()
            return PilcrowLit()

        if t.type is TT.VAR:
            self._advance()
            scope = "$$" if t.value.startswith("$$") else "$"
            return VarRef(t.value, scope)

        if t.type is TT.FIELD_REF:
            self._advance()
            to, _, field = t.value.partition("::")
            return FieldRef(to, field)

        if t.type is TT.IDENT:
            return self._ident_or_field_or_call()

        # Keyword used in value position — recover as bare name
        if t.type in (TT.AND, TT.OR, TT.NOT, TT.XOR):
            self._advance()
            return VarRef(t.value, "")

        raise ParseError(
            f"{t.line}:{t.col}: unexpected token {t.value!r} in expression"
        )

    def _ident_or_field_or_call(self) -> Node:
        name_tok = self._advance()
        name = name_tok.value

        # Let([bindings]; body) / While([initial]; cond; [logic]; result)
        if name.lower() == "let" and self._check(TT.LPAREN):
            return self._let_expr()
        if name.lower() == "while" and self._check(TT.LPAREN):
            return self._while_expr()

        # name(args…)
        if self._check(TT.LPAREN):
            self._advance()
            args = self._arg_list()
            self._expect(TT.RPAREN, "')'")
            return FuncCall(name, args)

        # Bare let-scoped name
        return VarRef(name, "")

    def _single_binding(self) -> LetBinding:
        """Parse one `name = expr` binding. The name may be a bare identifier (Let-local) or a
        `$var`/`$$global` — FileMaker allows a variable as the binding target."""
        t = self._peek()
        if t.type in (TT.VAR, TT.IDENT):
            var_name = self._advance().value
        else:
            raise ParseError(
                f"{t.line}:{t.col}: expected variable name in binding"
            )
        self._expect(TT.EQ, "'=' in binding")
        return LetBinding(var_name, self._or_expr())

    def _binding_list(self) -> list[LetBinding]:
        """Parse [ var = expr ; var = expr ; ... ] and return the bindings."""
        self._expect(TT.LBRACK, "'['")
        bindings: list[LetBinding] = []
        while not self._check(TT.RBRACK, TT.EOF):
            bindings.append(self._single_binding())
            if not self._match(TT.SEMI):
                break
        self._expect(TT.RBRACK, "']' closing bindings")
        return bindings

    def _let_expr(self) -> Node:
        # FileMaker accepts BOTH `Let ( [ a=1 ; b=2 ] ; body )` and the bracket-less single-binding
        # `Let ( a = 1 ; body )` (the name may be a $var/$$global). Dispatch on the '['.
        self._expect(TT.LPAREN, "'(' after Let")
        bindings = self._binding_list() if self._check(TT.LBRACK) else [self._single_binding()]
        self._expect(TT.SEMI, "';' after Let bindings")
        body = self._or_expr()
        self._expect(TT.RPAREN, "')' closing Let")
        return LetExpr(bindings, body)

    def _while_expr(self) -> Node:
        self._expect(TT.LPAREN, "'(' after While")
        initial = self._binding_list()
        self._expect(TT.SEMI, "';' after While initialVars")
        condition = self._or_expr()
        self._expect(TT.SEMI, "';' after While condition")
        logic = self._binding_list()
        self._expect(TT.SEMI, "';' after While logic")
        body = self._or_expr()
        self._expect(TT.RPAREN, "')' closing While")
        return WhileExpr(initial, condition, logic, body)

    def _bracket_group(self) -> BracketGroup:
        """Parse [ expr ; expr ; ... ] as a generic argument group."""
        self._expect(TT.LBRACK, "'['")
        exprs: list[Node] = []
        while not self._check(TT.RBRACK, TT.EOF):
            exprs.append(self._or_expr())
            if not self._match(TT.SEMI, TT.COMMA):
                break
        self._expect(TT.RBRACK, "']' closing bracket group")
        return BracketGroup(exprs)

    def _arg_list(self) -> list[Node]:
        args: list[Node] = []
        if self._check(TT.RPAREN):
            return args
        # First argument — may be a bracket group
        if self._check(TT.LBRACK):
            args.append(self._bracket_group())
        else:
            args.append(self._or_expr())
        while self._match(TT.SEMI, TT.COMMA):
            if self._check(TT.RPAREN):
                break
            if self._check(TT.LBRACK):
                args.append(self._bracket_group())
            else:
                args.append(self._or_expr())
        return args


def parse(formula: str) -> tuple[Node | None, list[str]]:
    """Parse a FileMaker formula string into an AST.

    Returns (node, errors). On hard failure node is None.
    Errors is a list of human-readable strings.
    """
    try:
        tokens = [t for t in tokenize(formula) if t.type is not TT.COMMENT]
    except LexError as exc:
        return None, [str(exc)]
    # An empty or entirely-commented calc (`// …`, `/* … */`) is valid FileMaker — an empty result,
    # not a parse error. After stripping comments only EOF remains; return cleanly (no phantom refs:
    # the comment body is one COMMENT token, never re-tokenized into its inner references).
    if len(tokens) <= 1:
        return None, []
    try:
        return _Parser(tokens).parse(), []
    except ParseError as exc:
        return None, [str(exc)]
    except RecursionError:
        # A pathologically deep formula (e.g. 20k nested parens) overflows the recursive descent.
        # Honor the (None, errors) contract instead of propagating — callers must never crash a worker.
        return None, ["formula nested too deeply to parse"]
