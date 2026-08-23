"""FileMaker formula parser and static analyzer.

Quick start::

    from corpusfm.formula import analyze, parse

    refs = analyze('If(Invoices::Status = "Open"; Invoices::Amount; 0)')
    # refs.field_refs  → [FieldRef("Invoices", "Status"), FieldRef("Invoices", "Amount")]
    # refs.func_calls  → ["If"]

    refs = analyze('ValueListItems(Get(FileName); "Payment Methods")')
    # refs.vl_refs     → ["Payment Methods"]

    refs = analyze('GetField("Invoices::Amount")')
    # refs.dynamic_refs → [DynamicRef("GetField", "Invoices::Amount")]

For access to the raw AST::

    ast, errors = parse(formula_string)
"""
from ._lexer import LexError, TT, Token, tokenize
from ._ast import (
    BinOp, BoolLit, BracketGroup, FieldRef, FuncCall,
    LetBinding, LetExpr, Node, NumLit, PilcrowLit,
    StrLit, UnaryOp, VarRef, WhileExpr,
)
from ._parser import ParseError, parse
from ._analyze import DynamicRef, FormulaRefs, extract_refs
from ._formatter import format_formula

__all__ = [
    # Lexer
    "tokenize", "Token", "TT", "LexError",
    # AST
    "Node", "StrLit", "NumLit", "BoolLit", "PilcrowLit",
    "FieldRef", "VarRef",
    "FuncCall", "LetExpr", "LetBinding", "WhileExpr", "BracketGroup",
    "BinOp", "UnaryOp",
    # Parser
    "parse", "ParseError",
    # Analysis
    "extract_refs", "FormulaRefs", "DynamicRef",
    # Formatter
    "format_formula",
    # Convenience
    "analyze",
]


def analyze(formula: str, *, implicit_to: str | None = None) -> FormulaRefs:
    """Parse and analyze a FileMaker formula string in one call.

    Pass implicit_to (a TableOccurrence name) when the formula comes from a
    calc field, auto-enter, or validation context where FM supplies a
    <TableOccurrenceReference> — bare field names are then resolved to
    FieldRef(implicit_to, name) rather than left as unresolved VarRefs.

    Returns a FormulaRefs with any parse errors in .errors.
    Never raises — errors are collected rather than thrown.

    When the formula does not parse (a construct the grammar does not model), it
    falls back to a best-effort token scan so one odd token cannot lose a whole
    calc's references — the completeness backstop.
    """
    try:
        ast, errors = parse(formula)
        refs = extract_refs(ast, errors, implicit_to=implicit_to)
        if ast is None:
            _scan_refs_from_tokens(formula, refs, implicit_to)
        return refs
    except RecursionError:
        # A pathologically deep calc (huge concat chain) can overflow the recursive parse/walk.
        # analyze() must NEVER raise — fall back to the non-recursive token scan for refs.
        refs = FormulaRefs()
        _scan_refs_from_tokens(formula, refs, implicit_to)
        return refs


def _scan_refs_from_tokens(
    formula: str, refs: FormulaRefs, implicit_to: str | None
) -> None:
    """Best-effort ref recovery when the parser failed: harvest FIELD_REF tokens
    and function-call identifiers straight from a resilient token stream.

    Field references are unambiguous at the token level (a FIELD_REF only ever
    comes from a TO::Field pattern, never a string/comment/let-binding), so this
    is safe; it only runs on formulas that would otherwise yield nothing.
    """
    toks = [t for t in tokenize(formula, resilient=True)
            if t.type not in (TT.COMMENT, TT.EOF)]
    seen = {(f.table, f.field) for f in refs.field_refs}
    for idx, tok in enumerate(toks):
        if tok.type is TT.FIELD_REF and "::" in tok.value:
            table, _, fld = tok.value.partition("::")
            if table.strip() and fld.strip() and (table, fld) not in seen:
                seen.add((table, fld))
                refs.field_refs.append(FieldRef(table, fld))
        elif tok.type is TT.IDENT and idx + 1 < len(toks) and toks[idx + 1].type is TT.LPAREN:
            refs.func_calls.append(tok.value)
