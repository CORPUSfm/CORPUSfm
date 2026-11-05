"""AST walker that extracts references from a parsed FM formula."""
from __future__ import annotations

from dataclasses import dataclass, field

from ._ast import (
    BinOp, BoolLit, BracketGroup, FieldRef, FuncCall, LetExpr,
    Node, NumLit, PilcrowLit, StrLit, UnaryOp, VarRef, WhileExpr,
)

# Functions whose first string argument is a dynamic field/formula reference.
_DYNAMIC_FUNCS = frozenset({
    "getfield",
    "getfieldname",
    "executesql",
    "evaluate",
    "evaluationerror",
    "getlayoutobjectattribute",
})

# ValueListItems(fileName; valueListName) — second arg is a VL name string.
_VL_FUNC = "valuelistitems"

# Arguments from this position on are FileMaker keywords, not expressions, even though they
# parse as bare names: Get ( ScriptParameter ), TextStyleAdd ( x ; Bold ).
_KEYWORD_ARGS_FROM = {"get": 0, "textstyleadd": 1, "textstyleremove": 1}


@dataclass
class DynamicRef:
    """A call that takes a string argument naming an FM object dynamically."""
    function: str   # as written in the formula
    arg:      str   # the string argument, empty if not a literal


@dataclass
class FormulaRefs:
    """All statically-extractable references from a parsed FM formula."""
    field_refs:   list[FieldRef]   = field(default_factory=list)
    func_calls:   list[str]        = field(default_factory=list)  # all function names
    vl_refs:      list[str]        = field(default_factory=list)  # from ValueListItems
    dynamic_refs: list[DynamicRef] = field(default_factory=list)
    errors:       list[str]        = field(default_factory=list)
    # Unscoped names no Let/While binds and no keyword position explains. Only a caller that
    # knows a catalog can say what one is: a zero-argument custom function is written this way.
    bare_names:   list[str]        = field(default_factory=list)


def _walk(
    node: Node,
    refs: FormulaRefs,
    let_bound: set[str],
    implicit_to: str | None = None,
) -> None:
    if node is None:
        return

    if isinstance(node, FieldRef):
        if node.field.strip() and node.table.strip():   # ignore TO::<Field Missing> husks
            refs.field_refs.append(node)

    elif isinstance(node, VarRef):
        # Bare name (scope == "") that is not let-bound may be a same-table field
        # reference when a TableOccurrenceReference supplies the implicit TO context.
        # FileMaker names are case-insensitive, so a binding shadows every casing of its name.
        bound = node.name.lower() in {b.lower() for b in let_bound}
        if implicit_to and node.scope == "" and not bound:
            refs.field_refs.append(FieldRef(implicit_to, node.name))
        if node.scope == "" and not bound:
            refs.bare_names.append(node.name)

    elif isinstance(node, (StrLit, NumLit, BoolLit, PilcrowLit)):
        pass

    elif isinstance(node, LetExpr):
        new_bound = set(let_bound)
        for binding in node.bindings:
            new_bound.add(binding.var)
            _walk(binding.value, refs, new_bound, implicit_to)
        _walk(node.body, refs, new_bound, implicit_to)

    elif isinstance(node, WhileExpr):
        new_bound = set(let_bound)
        for binding in node.initial_bindings:
            new_bound.add(binding.var)
            _walk(binding.value, refs, new_bound, implicit_to)
        _walk(node.condition, refs, new_bound, implicit_to)
        for binding in node.logic_bindings:
            new_bound.add(binding.var)
            _walk(binding.value, refs, new_bound, implicit_to)
        _walk(node.body, refs, new_bound, implicit_to)

    elif isinstance(node, BracketGroup):
        for expr in node.exprs:
            _walk(expr, refs, let_bound, implicit_to)

    elif isinstance(node, FuncCall):
        name_lower = node.name.lower()
        refs.func_calls.append(node.name)

        if name_lower == _VL_FUNC and len(node.args) >= 2:
            vl_arg = node.args[1]
            if isinstance(vl_arg, StrLit):
                refs.vl_refs.append(vl_arg.value)

        elif name_lower in _DYNAMIC_FUNCS:
            first = node.args[0] if node.args else None
            arg_text = first.value if isinstance(first, StrLit) else ""
            refs.dynamic_refs.append(DynamicRef(node.name, arg_text))

        keyword_from = _KEYWORD_ARGS_FROM.get(name_lower)
        for position, arg in enumerate(node.args):
            before = len(refs.bare_names)
            _walk(arg, refs, let_bound, implicit_to)
            if keyword_from is not None and position >= keyword_from:
                del refs.bare_names[before:]

    elif isinstance(node, BinOp):
        # Concat/arithmetic chains are LEFT-nested and can be hundreds deep (a long `a & ¶ & b & …`),
        # which overflows Python's recursion on the left spine. Unroll the spine iteratively, then walk
        # left-to-right (leftmost operand, then each right operand outward) so ref ORDER is preserved.
        spine = []
        chain = node
        while isinstance(chain, BinOp):
            spine.append(chain)
            chain = chain.left
        _walk(chain, refs, let_bound, implicit_to)          # leftmost operand
        for binop in reversed(spine):
            _walk(binop.right, refs, let_bound, implicit_to)

    elif isinstance(node, UnaryOp):
        _walk(node.operand, refs, let_bound, implicit_to)


def extract_refs(
    ast: Node | None,
    errors: list[str] | None = None,
    *,
    implicit_to: str | None = None,
) -> FormulaRefs:
    """Walk a parsed AST and return all statically-resolvable references.

    Pass implicit_to (a TableOccurrence name) to resolve bare field names that
    appear in calc-field / auto-enter / validation formula context where FM
    supplies a <TableOccurrenceReference> as the implicit table.
    """
    refs = FormulaRefs(errors=list(errors or []))
    if ast is not None:
        _walk(ast, refs, set(), implicit_to)
    return refs
