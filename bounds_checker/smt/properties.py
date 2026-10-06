"""
Safety properties discharged against the path condition.

Each property is the negation of an obligation the finding implicitly claims
is unmet.  UNSAT means the obligation holds for every value the unknowns could
take, so the finding is noise; SAT means there is a concrete assignment that
breaks it, which is a witness and not a verdict.  Everything else keeps the
finding.

The four here are the ones decidable from the slice alone.  Properties that
need a buffer size — how big is the destination of this memcpy, how many
entries does this table have — are deliberately absent: they need declaration
data the scanner does not collect, and guessing would convert a sound
suppressor into an unsound one.
"""

from collections import namedtuple

import z3

from kernel_analysis.parsers.c_parser import _walk, node_text
from bounds_checker.parsers.taint_scanner import _comparisons_on
from bounds_checker.smt.encoder import (
    Encoder, Value, build_decl_types, promote, usual_conversions,
)
from bounds_checker.smt.fields import field_types, var_types
from bounds_checker.smt.pathcond import build_path


# `suppresses` is set only when the properties that came back clean are the
# ones Stage 1's verdict rested on; a clean answer to some other question is
# worth reporting but does not retire the finding.
SmtResult = namedtuple('SmtResult', 'verdict prop witness detail suppresses')
SmtResult.__new__.__defaults__ = (False,)

UNMODELLED = SmtResult('not-modelled', '', {}, '')

_ARITH = frozenset({'+', '-', '*', '<<'})


# ---------------------------------------------------------------------------
# Locating the expression a finding is about
# ---------------------------------------------------------------------------

def _nodes_on_line(fn_body, line):
    return [n for n in _walk(fn_body) if n.start_point[0] + 1 == line]


def _mentions(node, name, source):
    return any(n.type == 'identifier' and node_text(n, source) == name
               for n in _walk(node))


def _arg_nodes(call):
    args = call.child_by_field_name('arguments')
    return [c for c in args.children if c.is_named] if args is not None else []


def _sink_expr(finding, fn_body, source):
    """
    The expression whose value the finding is about: the subscript index, the
    size argument, or the assigned value.  None when the category's obligation
    needs information the slice does not carry.
    """
    line = finding['sink_line']
    var  = finding['tainted_var']
    role = finding.get('sink_arg_role', '')
    cat  = finding['category']

    if cat == 'C' or role == 'subscript':
        for n in _nodes_on_line(fn_body, line):
            if n.type == 'subscript_expression':
                idx = n.child_by_field_name('index')
                if idx is not None and _mentions(idx, var, source):
                    return idx
        return None

    if cat == 'H' or role in ('narrowing_assignment', 'narrowed_value'):
        for n in _nodes_on_line(fn_body, line):
            if n.type == 'assignment_expression':
                return n.child_by_field_name('right')
            if n.type == 'init_declarator':
                return n.child_by_field_name('value')
        return None

    if cat == 'B' or role in ('size', 'count', 'size_mul_overflow'):
        want = finding.get('sink_arg_index')
        for n in _nodes_on_line(fn_body, line):
            if n.type != 'call_expression':
                continue
            args = _arg_nodes(n)
            if want is not None and 0 <= want < len(args):
                return args[want]
            for a in args:
                if _mentions(a, var, source):
                    return a
        return None

    return None


def _mul_or_add(node):
    """Outermost * or + inside the expression, which is what can wrap."""
    for n in _walk(node):
        if n.type == 'binary_expression':
            op = next((node_text_raw(c) for c in n.children if not c.is_named), '')
            if op in ('*', '+'):
                return n, op
    return None, ''


def node_text_raw(node):
    return node.text.decode('utf8', 'replace') if node.text else ''


# ---------------------------------------------------------------------------
# Witness extraction
# ---------------------------------------------------------------------------

def _witness(model, path, extra=None, claim=None):
    """
    Values the far side would have to send.  Only the unknowns that stand for
    received data are reported — the rest are the solver's bookkeeping and
    mean nothing to a reader.

    A model assigns every constant the solver ever saw, including the dozens a
    long function contributes to the path condition without the claim ever
    depending on them.  Restricting to what the claim is built from is what
    keeps the witness readable as a scenario.
    """
    out = {}
    wanted = _consts(claim, set()) if claim is not None else None
    for d in model.decls():
        name = d.name()
        if '_val!' not in name and '_ret!' not in name:
            continue
        if wanted is not None and name not in wanted:
            continue
        v = _hex(model[d])
        if v is not None:
            out[name.split('!')[0]] = v
    for label, term in (extra or {}).items():
        v = _hex(model.eval(term, True))
        if v is not None:
            out[label] = v
    return out


def _hex(ref):
    """
    The bit pattern, which is the only reading that survives the question the
    witness is about — z3 hands back a negative integer whenever it picked a
    literal below zero, for a term C would have read as unsigned at the sink.
    """
    try:
        return f'0x{ref.as_long() & ((1 << ref.sort().size()) - 1):x}'
    except (AttributeError, z3.Z3Exception):
        return None


def _consts(expr, out):
    if z3.is_const(expr) and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED:
        out.add(expr.decl().name())
    for c in expr.children():
        _consts(c, out)
    return out


def _opaque_terms(exprs, enc):
    """The distinct constants, among these expressions, that stand for gaps."""
    found, seen = [], set()

    def visit(e):
        if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            name = e.decl().name()
            if name in enc.opaque and name not in seen:
                seen.add(name)
                found.append(e)
        for c in e.children():
            visit(c)

    for e in exprs:
        visit(e)
    return found


def _decide(path, claim, prop, detail, proved, extra=None, timeout_ms=200):
    """
    Check the negation of an obligation; UNSAT is the only clean answer.

    `detail` describes what the claim asserts and so reads correctly only
    where the claim holds; `proved` is the same fact in the direction UNSAT
    establishes, and a verdict carrying the wrong one of the two states the
    opposite of what the solver found.
    """
    s = path.solver(timeout_ms)
    s.add(claim)
    r = s.check()
    if r == z3.unsat:
        return SmtResult('safe', prop, {}, proved)
    if r != z3.sat:
        return SmtResult('unknown', prop, {}, f'undecided: {detail} (solver: {r})')

    # The assignment may exist only because a term the encoder could not model
    # — a struct field, a macro, a callee's return — was free to take whatever
    # value it needed.  Demanding the counterexample hold for every value of
    # those terms is the same bargain the UNSAT direction makes, mirrored: what
    # survives is independent of the gap in the model.  Anything else, including
    # a timeout on the quantified query, keeps the finding without claiming a
    # witness for it.
    assumed = path.assumptions()
    free = _opaque_terms([claim] + assumed, path.enc)
    if free:
        robust = z3.ForAll(free, z3.Implies(z3.And(assumed), claim))
        q = z3.Solver()
        q.set('timeout', timeout_ms)
        q.add(robust)
        if q.check() != z3.sat:
            return SmtResult('unknown', prop, {},
                             f'{detail}; holds only for particular values of '
                             f'unmodelled '
                             f'{", ".join(sorted({t.decl().name().split("!")[0] for t in free}))}')
        s = path.solver(timeout_ms)
        s.add(claim)
        s.add(robust)
        if s.check() != z3.sat:
            return SmtResult('unknown', prop, {}, detail)
    return SmtResult('witness', prop, _witness(s.model(), path, extra, claim),
                     detail)


# ---------------------------------------------------------------------------
# The properties
# ---------------------------------------------------------------------------

def _grounded(val):
    """
    Whether the value's type came from the source rather than from a default.

    Reasoning that is about the type itself — does this fit, can this be
    negative — cannot rest on a width and signedness the encoder picked
    because it could not read the declaration, even though reasoning about
    the *value* still can, since the term stays free either way.  An enum is
    the common case: nothing names its underlying type at the use site, so a
    guess of signed int turns every wire value with the top bit set into a
    counterexample that C would never produce.
    """
    return not val.guessed


def prop_negative(path, expr_node):
    """
    Can the value be negative where it is about to be read as a size_t?

    This is `upper-bound-only-signed` decided rather than asserted, and it
    absorbs the three shapes _max_bits() hand-models: a 16-bit read widened
    into an int, a mask, a right shift of an unsigned are each unsatisfiable
    here without a rule saying so, because the encoding already zero-extends
    them.
    """
    val = promote(path.enc.encode(expr_node))
    if not _grounded(val):
        return UNMODELLED
    if not val.signed:
        return SmtResult('safe', 'negative', {},
                         'value is unsigned at the sink')
    return _decide(path, val.bv < 0, 'negative',
                   'index/size can be negative and converts to size_t',
                   'signed value cannot be negative where it reaches the sink',
                   {'value': val.bv})


def prop_overflow(path, expr_node):
    """Can the size arithmetic wrap before the allocator or copy sees it?"""
    node, op = _mul_or_add(expr_node)
    if node is None:
        return UNMODELLED
    lhs = path.enc.encode(node.child_by_field_name('left'))
    rhs = path.enc.encode(node.child_by_field_name('right'))
    l, r, width, signed = usual_conversions(lhs, rhs)
    if not _grounded(l):
        return UNMODELLED
    if op == '*':
        ok = z3.BVMulNoOverflow(l.bv, r.bv, signed)
        term = l.bv * r.bv
    else:
        ok = z3.BVAddNoOverflow(l.bv, r.bv, signed)
        term = l.bv + r.bv
    if signed:
        ok = z3.And(ok, (z3.BVMulNoUnderflow if op == '*'
                         else z3.BVAddNoUnderflow)(l.bv, r.bv))
    what = 'product' if op == '*' else 'sum'
    return _decide(path, z3.Not(ok), 'overflow',
                   f'{width}-bit {what} can wrap',
                   f'{width}-bit {what} cannot wrap',
                   {'result': term})


def prop_truncation(path, expr_node, dest_width, dest_signed=False):
    """Can the narrowing assignment lose a bit that mattered?"""
    val = path.enc.encode(expr_node)
    if not _grounded(val):
        return UNMODELLED       # the source width is a default, not a type
    if val.width <= dest_width:
        return SmtResult('safe', 'truncation', {},
                         'source is no wider than the destination')
    narrowed = z3.Extract(dest_width - 1, 0, val.bv)
    back = (z3.SignExt if dest_signed else z3.ZeroExt)(
        val.width - dest_width, narrowed)
    return _decide(path, back != val.bv, 'truncation',
                   f'{val.width}-bit value does not survive {dest_width} bits',
                   f'{val.width}-bit value survives {dest_width} bits intact',
                   {'value': val.bv})


_MIRROR = {'<': '>', '>': '<', '<=': '>=', '>=': '<='}
_NEGATE = {'<': '>=', '>=': '<', '>': '<=', '<=': '>'}


def _is_ceiling(op, var_on_left, assume_true):
    """
    Whether the guard, taken in the direction the path went, puts a ceiling on
    the variable.  A floor (`if (len < 4) return;`) is about having enough, and
    a later `len -= 4` failing to preserve it is not a bounds violation.
    """
    if op not in _MIRROR:
        return False
    if not var_on_left:
        op = _MIRROR[op]
    if not assume_true:
        op = _NEGATE[op]
    return op in ('<', '<=')


def prop_guard_transfer(path, var_name, expr_node, source):
    """
    The guard pinned some term; is that still the term the sink uses?

    A ceiling is established on whatever the variable held at the guard, and
    anything between there and the sink — an adjustment in the sink expression
    (`off` checked, `data[off + 1]` used) or a redefinition on the way
    (`len <= 64` then `len += 8`) — can move the value out from under it.
    Substituting what the sink computes for what the guard constrained asks
    whether the bound survived, without needing to know what it meant.

    A guard that already applies arithmetic to the variable has priced the
    adjustment in; substituting there would apply it twice, and a sink that
    is not a constant shift of the guarded value is not an adjustment at all.
    """
    names = {var_name}
    sink = path.enc.encode(expr_node)

    claims = []
    for guard in path.guards:
        held = guard.env.get(var_name)
        for cmp_node, holds, pred in guard.definite:
            cmps = _comparisons_on(cmp_node, names, source)
            if not cmps:
                continue
            op, on_left, in_arith, _ = cmps[0]
            if in_arith:
                return UNMODELLED
            if held is None or not _is_ceiling(op, on_left, holds):
                continue
            at_sink = _match_width(sink, held.bv)
            if not z3.is_bv_value(z3.simplify(at_sink - held.bv)):
                # The sink is not the guarded value moved by some amount but a
                # different computation over it — `num` bounded to 1..4, then
                # `size * num` allocated.  A ceiling in one does not translate
                # into the other, and substituting asks the question in the
                # wrong units.
                return UNMODELLED
            moved = z3.substitute(pred, (held.bv, at_sink))
            if not moved.eq(pred):
                claims.append(moved)

    if not claims:
        return UNMODELLED
    return _decide(path, z3.Not(z3.And(claims)), 'guard-transfer',
                   'the value reaching the sink is not the one the bound covers',
                   'the bound still covers the value reaching the sink',
                   {'at sink': sink.bv})


def _match_width(val, like):
    w = like.size()
    if val.width == w:
        return val.bv
    if val.width < w:
        return (z3.SignExt if val.signed else z3.ZeroExt)(w - val.width, val.bv)
    return z3.Extract(w - 1, 0, val.bv)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# The property that has to come back clean for Stage 1's verdict to be wrong.
# A finding with no entry here rests on something these properties do not
# express — most often a buffer size — so proving them says nothing about it.
_BASIS_BY_KIND = {
    'upper-bound-only-signed': ('negative',),
    'covers-base-not-offset':  ('guard-transfer',),
    'stale-redefinition':      ('guard-transfer',),
}

_BASIS_BY_ROLE = {
    'size_mul_overflow':     ('overflow',),
    'narrowing_assignment':  ('truncation',),
    'narrowed_value':        ('truncation',),
}


def check_finding(finding, fn_body, source, timeout_ms=200, decl_types=None,
                  c_path=None):
    """
    Refine one Stage 1 finding.

    `verdict` is the answer to the properties that could be posed; `suppresses`
    says whether those were the ones the finding actually rested on.  The two
    come apart often: a memcpy length that provably cannot be negative is still
    a memcpy length nobody bounded, and the solver has no way to see the
    destination.

    `c_path` buys struct field types, which is most of what separates a term
    the solver can reason about from a blank.  Resolving them means parsing the
    headers the file reaches, so it is done only for a function that has a
    finding to refine.
    """
    expr = _sink_expr(finding, fn_body, source)
    if expr is None:
        return UNMODELLED

    types = var_map = None
    if c_path:
        types = field_types(c_path)
        var_map = var_types(fn_body.parent or fn_body, fn_body, source)

    path = build_path(fn_body, source, finding['sink_line'], decl_types,
                      types, var_map)
    cat  = finding['category']
    role = finding.get('sink_arg_role', '')
    kind = finding.get('guard_kind', '')

    checks = []
    if cat == 'H' or role in ('narrowing_assignment', 'narrowed_value'):
        width = finding.get('dest_width')
        if not width:
            return UNMODELLED
        checks.append(lambda: prop_truncation(path, expr, width))
    else:
        if role == 'size_mul_overflow' or cat == 'B':
            checks.append(lambda: prop_overflow(path, expr))
        checks.append(lambda: prop_negative(path, expr))
        checks.append(lambda: prop_guard_transfer(
            path, finding['tainted_var'], expr, source))

    results = [r for r in (c() for c in checks) if r.verdict != 'not-modelled']
    if not results:
        return UNMODELLED

    basis = _BASIS_BY_ROLE.get(role) or _BASIS_BY_KIND.get(kind) or ()
    safe = {r.prop for r in results if r.verdict == 'safe'}
    covered = bool(basis) and all(p in safe for p in basis)

    for want in ('witness', 'unknown'):
        hit = next((r for r in results if r.verdict == want), None)
        if hit is not None:
            return hit._replace(suppresses=False)
    return SmtResult('safe', '+'.join(r.prop for r in results), {},
                     '; '.join(r.detail for r in results), covered)
