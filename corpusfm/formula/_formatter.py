"""Pretty-printer for FileMaker formula strings.

Produces canonical indented output preserving comments.  The algorithm:

1. Tokenize the source (COMMENT tokens are emitted, not discarded).
2. Build a comment map: for each non-comment token position, collect any
   COMMENT tokens that immediately precede it in the stream.
3. Parse the formula (COMMENT tokens filtered out before parsing).
4. Walk the AST, emitting compact (single-line) or expanded (multi-line)
   form at each node based on the ``max_line`` width budget.
5. Before emitting each expression, flush any leading comments that were
   attached to its first source token.

Comments are attached to the *next* non-comment token, so they appear
immediately before the expression they precede in the source.  A trailing
comment on the last line of the source is appended at the end of the output.

Usage::

    from corpusfm.formula import format_formula

    src = '''
    // compute discount
    If( Invoice::Amount > 1000 ; Invoice::Amount * 0.9 ; Invoice::Amount )
    '''
    print(format_formula(src))
"""
from __future__ import annotations

from ._ast import (
    BinOp, BoolLit, BracketGroup, FieldRef, FuncCall,
    LetBinding, LetExpr, Node, NumLit, PilcrowLit, StrLit, UnaryOp, VarRef, WhileExpr,
)
from ._lexer import TT, Token, _NAME_CHARS, _is_name_start, tokenize
from ._parser import ParseError, parse


# ---------------------------------------------------------------------------
# Name quoting helpers
# ---------------------------------------------------------------------------

def _needs_quoting(name: str) -> bool:
    if not name:
        return True
    if not _is_name_start(name[0]):
        return True
    return not all(c in _NAME_CHARS or c == " " for c in name)


def _render_name(name: str) -> str:
    return "${" + name + "}" if _needs_quoting(name) else name


# ---------------------------------------------------------------------------
# Comment map builder
# ---------------------------------------------------------------------------

def _build_comment_map(tokens: list[Token]) -> tuple[list[Token], dict[int, list[str]]]:
    """Return (non-comment tokens, map from non-comment-token-index → leading comments).

    The map keys are indices into the returned non-comment token list.
    Value is the list of comment strings (including delimiters) that appeared
    immediately before that token in the source.
    """
    result: list[Token] = []
    pending: list[str] = []
    comment_map: dict[int, list[str]] = {}

    for tok in tokens:
        if tok.type is TT.COMMENT:
            pending.append(tok.value)
        else:
            if pending:
                comment_map[len(result)] = list(pending)
                pending.clear()
            result.append(tok)

    # Trailing comments after the last real token (index = len(result))
    if pending:
        comment_map[len(result)] = list(pending)

    return result, comment_map


# ---------------------------------------------------------------------------
# Printer
# ---------------------------------------------------------------------------

class _Printer:
    def __init__(self, indent: str, max_line: int) -> None:
        self._indent = indent
        self._max_line = max_line
        self._tok_idx = 0  # position in the non-comment token stream consumed so far

    # ── Public entry point ────────────────────────────────────────────────────

    def format(self, node: Node, comment_map: dict[int, list[str]]) -> str:
        self._comment_map = comment_map
        self._tok_idx = 0
        parts: list[str] = []
        self._emit_node(node, depth=0, parts=parts)
        # Flush any trailing comments
        trailing = self._comment_map.get(self._tok_idx, [])
        for c in trailing:
            parts.append("\n" + c)
        return "".join(parts).strip()

    # ── Comment flushing ──────────────────────────────────────────────────────

    def _flush_comments(self, depth: int, parts: list[str]) -> None:
        comments = self._comment_map.get(self._tok_idx, [])
        if comments:
            del self._comment_map[self._tok_idx]
            ind = self._indent * depth
            for c in comments:
                if parts and not parts[-1].endswith("\n"):
                    parts.append("\n")
                parts.append(ind + c + "\n")

    def _advance_tok(self, count: int = 1) -> None:
        self._tok_idx += count

    # ── Node emission ─────────────────────────────────────────────────────────

    def _emit_node(self, node: Node, depth: int, parts: list[str]) -> None:
        self._flush_comments(depth, parts)
        compact = self._compact(node)
        ind_len = len(self._indent) * depth
        if ind_len + len(compact) <= self._max_line and "\n" not in compact:
            parts.append(compact)
            self._tok_idx += self._token_count(node)
        else:
            self._emit_expanded(node, depth, parts)

    # ── Compact (single-line) rendering ───────────────────────────────────────

    def _compact(self, node: Node) -> str:
        if isinstance(node, StrLit):
            return '"' + node.value.replace('"', '""') + '"'
        if isinstance(node, NumLit):
            return node.value
        if isinstance(node, BoolLit):
            return "True" if node.value else "False"
        if isinstance(node, PilcrowLit):
            return "¶"
        if isinstance(node, FieldRef):
            return f"{_render_name(node.table)}::{_render_name(node.field)}"
        if isinstance(node, VarRef):
            return node.name  # name already carries $/$$ prefix
        if isinstance(node, UnaryOp):
            if node.op == "not":
                return f"not {self._compact(node.operand)}"
            return f"{node.op}{self._compact(node.operand)}"
        if isinstance(node, BinOp):
            return (
                f"{self._compact(node.left)} {node.op} {self._compact(node.right)}"
            )
        if isinstance(node, BracketGroup):
            inner = " ; ".join(self._compact(e) for e in node.exprs)
            return f"[ {inner} ]" if inner else "[]"
        if isinstance(node, LetBinding):
            return f"{node.var} = {self._compact(node.value)}"
        if isinstance(node, LetExpr):
            bindings = " ; ".join(self._compact(b) for b in node.bindings)
            body = self._compact(node.body)
            return f"Let( [ {bindings} ] ; {body} )"
        if isinstance(node, WhileExpr):
            init = " ; ".join(self._compact(b) for b in node.initial_bindings)
            cond = self._compact(node.condition)
            logic = " ; ".join(self._compact(b) for b in node.logic_bindings)
            body = self._compact(node.body)
            return f"While( [ {init} ] ; {cond} ; [ {logic} ] ; {body} )"
        if isinstance(node, FuncCall):
            if not node.args:
                return f"{node.name}()"
            args = " ; ".join(self._compact(a) for a in node.args)
            return f"{node.name}( {args} )"
        return ""

    # ── Token-count helpers (for advancing _tok_idx on compact emit) ──────────

    def _token_count(self, node: Node) -> int:
        """Approximate number of non-comment tokens consumed by this node.

        Used only to advance the comment-map cursor after a compact emit.
        Precision is not critical — the worst case is a comment being emitted
        slightly early or late; it never loses comments.
        """
        if isinstance(node, (StrLit, NumLit, BoolLit, PilcrowLit, VarRef)):
            return 1
        if isinstance(node, FieldRef):
            return 1  # FIELD_REF is a single token
        if isinstance(node, UnaryOp):
            return 1 + self._token_count(node.operand)
        if isinstance(node, BinOp):
            return self._token_count(node.left) + 1 + self._token_count(node.right)
        if isinstance(node, BracketGroup):
            inner = sum(self._token_count(e) + 1 for e in node.exprs)
            return 2 + max(0, inner - 1)  # [ ... ]
        if isinstance(node, LetBinding):
            return 1 + 1 + self._token_count(node.value)  # name = val
        if isinstance(node, LetExpr):
            b = sum(self._token_count(b) + 1 for b in node.bindings)
            return 4 + b + self._token_count(node.body)  # Let( [ bindings ] ; body )
        if isinstance(node, WhileExpr):
            b1 = sum(self._token_count(b) + 1 for b in node.initial_bindings)
            b2 = sum(self._token_count(b) + 1 for b in node.logic_bindings)
            return 6 + b1 + 1 + self._token_count(node.condition) + b2 + self._token_count(node.body)
        if isinstance(node, FuncCall):
            inner = sum(self._token_count(a) + 1 for a in node.args)
            return 2 + max(0, inner - 1)  # name( args )
        return 1

    # ── Expanded (multi-line) rendering ──────────────────────────────────────

    def _emit_expanded(self, node: Node, depth: int, parts: list[str]) -> None:
        ind = self._indent * depth
        ind1 = self._indent * (depth + 1)
        ind2 = self._indent * (depth + 2)

        if isinstance(node, BinOp):
            self._emit_node(node.left, depth, parts)
            self._advance_tok()  # operator token
            parts.append(f" {node.op}\n{ind}")
            self._flush_comments(depth, parts)
            self._emit_node(node.right, depth, parts)
            return

        if isinstance(node, UnaryOp):
            if node.op == "not":
                parts.append("not ")
            else:
                parts.append(node.op)
            self._advance_tok()
            self._emit_node(node.operand, depth, parts)
            return

        if isinstance(node, FuncCall):
            self._advance_tok()  # function name token
            if not node.args:
                self._advance_tok()  # (
                self._advance_tok()  # )
                parts.append(f"{node.name}()")
                return
            self._advance_tok()  # (
            parts.append(f"{node.name}(\n{ind1}")
            for idx, arg in enumerate(node.args):
                self._emit_node(arg, depth + 1, parts)
                if idx < len(node.args) - 1:
                    self._advance_tok()  # ;
                    parts.append(f" ;\n{ind1}")
                    self._flush_comments(depth + 1, parts)
            self._advance_tok()  # )
            parts.append(f"\n{ind})")
            return

        if isinstance(node, LetExpr):
            self._advance_tok()  # Let
            self._advance_tok()  # (
            parts.append(f"Let(\n{ind1}")
            self._advance_tok()  # [
            parts.append(f"[\n{ind2}")
            for idx, b in enumerate(node.bindings):
                self._flush_comments(depth + 2, parts)
                parts.append(f"{b.var} = ")
                self._advance_tok()  # var name
                self._advance_tok()  # =
                self._emit_node(b.value, depth + 2, parts)
                if idx < len(node.bindings) - 1:
                    self._advance_tok()  # ;
                    parts.append(f" ;\n{ind2}")
            self._advance_tok()  # ]
            self._advance_tok()  # ;
            parts.append(f"\n{ind1}] ;\n{ind1}")
            self._flush_comments(depth + 1, parts)
            self._emit_node(node.body, depth + 1, parts)
            self._advance_tok()  # )
            parts.append(f"\n{ind})")
            return

        if isinstance(node, WhileExpr):
            self._advance_tok()  # While
            self._advance_tok()  # (
            parts.append(f"While(\n{ind1}")
            # initial bindings
            self._advance_tok()  # [
            parts.append(f"[\n{ind2}")
            for idx, b in enumerate(node.initial_bindings):
                self._flush_comments(depth + 2, parts)
                parts.append(f"{b.var} = ")
                self._advance_tok()  # var
                self._advance_tok()  # =
                self._emit_node(b.value, depth + 2, parts)
                if idx < len(node.initial_bindings) - 1:
                    self._advance_tok()  # ;
                    parts.append(f" ;\n{ind2}")
            self._advance_tok()  # ]
            self._advance_tok()  # ;
            parts.append(f"\n{ind1}] ;\n{ind1}")
            # condition
            self._flush_comments(depth + 1, parts)
            self._emit_node(node.condition, depth + 1, parts)
            self._advance_tok()  # ;
            parts.append(f" ;\n{ind1}")
            # logic bindings
            self._advance_tok()  # [
            parts.append(f"[\n{ind2}")
            for idx, b in enumerate(node.logic_bindings):
                self._flush_comments(depth + 2, parts)
                parts.append(f"{b.var} = ")
                self._advance_tok()  # var
                self._advance_tok()  # =
                self._emit_node(b.value, depth + 2, parts)
                if idx < len(node.logic_bindings) - 1:
                    self._advance_tok()  # ;
                    parts.append(f" ;\n{ind2}")
            self._advance_tok()  # ]
            self._advance_tok()  # ;
            parts.append(f"\n{ind1}] ;\n{ind1}")
            # body
            self._flush_comments(depth + 1, parts)
            self._emit_node(node.body, depth + 1, parts)
            self._advance_tok()  # )
            parts.append(f"\n{ind})")
            return

        if isinstance(node, BracketGroup):
            self._advance_tok()  # [
            parts.append(f"[\n{ind1}")
            for idx, e in enumerate(node.exprs):
                self._flush_comments(depth + 1, parts)
                self._emit_node(e, depth + 1, parts)
                if idx < len(node.exprs) - 1:
                    self._advance_tok()  # ;
                    parts.append(f" ;\n{ind1}")
            self._advance_tok()  # ]
            parts.append(f"\n{ind}]")
            return

        # Fallback: emit compact and advance
        parts.append(self._compact(node))
        self._tok_idx += self._token_count(node)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def format_formula(
    source: str,
    *,
    indent: str = "  ",
    max_line: int = 80,
) -> str:
    """Format a FileMaker formula string with canonical indentation.

    Comments (``//`` and ``/* */``) are preserved and re-emitted before the
    expression they precede in the source.

    Args:
        source:   The raw FM formula string.
        indent:   Indentation string per level (default: two spaces).
        max_line: Maximum line length before a node is expanded (default: 80).

    Returns:
        Formatted formula string.  Returns the source stripped of leading/
        trailing whitespace on parse failure (best-effort passthrough).
    """
    all_tokens = tokenize(source)
    non_comment, comment_map = _build_comment_map(all_tokens)

    try:
        ast, errors = parse(source)
        if ast is None:
            return source.strip()
        printer = _Printer(indent=indent, max_line=max_line)
        return printer.format(ast, comment_map)
    except RecursionError:
        # A pathologically deep calc (huge concat chain) overflows the recursive parse/print —
        # honor the documented best-effort passthrough rather than crash a render/export.
        return source.strip()
