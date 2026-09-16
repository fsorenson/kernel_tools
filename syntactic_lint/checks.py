"""
Local syntactic bounds checks for kernel C.

Every check here is an invariant over a single function body: no taint table,
no cross-function pass, no LLM.  That is the whole point — these are decidable
from one AST plus the declared types of the locals, so they run over a tree in
seconds at zero token cost, and they fire on defects that carry no taint at all
(a pointer/length pairing error is equally a bug when the buffer is a trusted
local constant).

  ptr-advance  mem*(dst, P + K, LEN) where LEN was computed from the
               un-advanced P.  Also the interposed form, where the advance sits
               between the length computation and the call.
  scan-loop    for (i = K; s[i]; i++) with K > 0, which never tests positions
               0..K-1 for the terminator and has no upper bound of its own.
  narrow-sub   unsigned subtraction into a narrow fixed-width variable whose
               value reaches a size, offset, subscript, or wire field.
  narrow-add   the same for addition and for `acc +=` accumulation in a loop.
"""

from kernel_analysis.parsers.c_parser import (
    _walk, node_text, get_source_line, parse_file, find_functions,
)

CHECKS = ('ptr-advance', 'scan-loop', 'narrow-sub', 'narrow-add')

# ---------------------------------------------------------------------------
# Shared tables
# ---------------------------------------------------------------------------

# name -> (pointer argument indices, length argument index)
_MEM_FNS = {
    'memcpy':           ((0, 1), 2),
    'memmove':          ((0, 1), 2),
    'memcmp':           ((0, 1), 2),
    'memset':           ((0,),   2),
    'strncpy':          ((0, 1), 2),
    'strncat':          ((0, 1), 2),
    'strlcpy':          ((0, 1), 2),
    'strlcat':          ((0, 1), 2),
    'strncmp':          ((0, 1), 2),
    'copy_to_user':     ((0, 1), 2),
    'copy_from_user':   ((0, 1), 2),
    '_copy_to_user':    ((0, 1), 2),
    '_copy_from_user':  ((0, 1), 2),
    '__copy_to_user':   ((0, 1), 2),
    '__copy_from_user': ((0, 1), 2),
}

_ALLOC_FNS = frozenset({
    'kmalloc', 'kzalloc', 'kcalloc', 'kmalloc_array', 'krealloc',
    'kvmalloc', 'kvzalloc', 'vmalloc', 'vzalloc', '__kmalloc',
    'kmalloc_node', 'kzalloc_node', 'devm_kmalloc', 'devm_kzalloc',
})

# Storing into a little/big-endian wire field: a wrapped value is shipped to
# the peer even when nothing in this address space is overrun.
_WIRE_STORE_FNS = frozenset({
    'cpu_to_le16', 'cpu_to_le32', 'cpu_to_le64',
    'cpu_to_be16', 'cpu_to_be32', 'cpu_to_be64',
})

# Arithmetic already checked by the caller — the whole point of these helpers.
_SAFE_ARITH = frozenset({
    'check_add_overflow', 'check_sub_overflow', 'check_mul_overflow',
    'size_add', 'size_sub', 'size_mul', 'array_size', 'array3_size',
    'struct_size', 'saturate_add',
})

# Unsigned fixed-width integer types, by bit width.  Narrow unsigned types are
# the ones worth checking: their wrap is well-defined, silent, and lands far
# from the arithmetic that produced it.
_UNSIGNED_WIDTHS = {
    'u8': 8, '__u8': 8, 'uint8_t': 8, 'unsigned char': 8,
    'u16': 16, '__u16': 16, 'uint16_t': 16, 'unsigned short': 16,
    '__le16': 16, '__be16': 16,
    'u32': 32, '__u32': 32, 'uint32_t': 32, 'unsigned int': 32,
    'unsigned': 32, '__le32': 32, '__be32': 32,
}

_ADVANCE_OPS = ('+=', '-=')
_LOOP_NODES = frozenset({
    'for_statement', 'while_statement', 'do_statement',
})
_BRANCH_NODES = _LOOP_NODES | {'if_statement', 'switch_statement',
                               'conditional_expression'}


# ---------------------------------------------------------------------------
# Small AST helpers
# ---------------------------------------------------------------------------

def _line(node):
    return node.start_point[0] + 1


def _unwrap(node):
    """Strip parentheses and casts from an expression node."""
    while node is not None and node.type in ('parenthesized_expression', 'cast_expression'):
        inner = [c for c in node.children
                 if c.type not in ('(', ')', 'type_descriptor')]
        if not inner:
            return node
        node = inner[-1]
    return node


def _callee(call_node, source):
    fn = call_node.child_by_field_name('function')
    if fn is None or fn.type != 'identifier':
        return None
    return node_text(fn, source)


def _args(call_node):
    lst = call_node.child_by_field_name('arguments')
    if lst is None:
        return []
    return [c for c in lst.children if c.type not in ('(', ')', ',')]


def _int_literal(node, source):
    """Return the integer value of a literal node, or None."""
    node = _unwrap(node)
    if node is None or node.type != 'number_literal':
        return None
    txt = node_text(node, source).rstrip('uUlL')
    try:
        return int(txt, 0)
    except ValueError:
        return None


def _enclosing_call(node, source, names):
    """Walk up from node; return the first ancestor call to one of `names`."""
    cur = node.parent
    while cur is not None and cur.type != 'function_definition':
        if cur.type == 'call_expression' and _callee(cur, source) in names:
            return cur
        cur = cur.parent
    return None


def _is_conditional(node, body):
    """True if node sits inside a branch or loop rather than straight-line code."""
    cur = node.parent
    while cur is not None and cur is not body:
        if cur.type in _BRANCH_NODES:
            return True
        cur = cur.parent
    return False


def _enclosing_loop(node, body):
    cur = node.parent
    while cur is not None and cur is not body:
        if cur.type in _LOOP_NODES:
            return cur
        cur = cur.parent
    return None


def _in_loop(node, body):
    return _enclosing_loop(node, body) is not None


def _identifiers(node, source):
    return {node_text(n, source) for n in _walk(node) if n.type == 'identifier'}


def _finding(check, severity, fn, path, source, line, message, **extra):
    f = {
        'check': check,
        'severity': severity,
        'function': fn,
        'file': str(path),
        'line': line,
        'snippet': get_source_line(source, line),
        'message': message,
    }
    f.update(extra)
    return f


# ---------------------------------------------------------------------------
# Declared widths
# ---------------------------------------------------------------------------

def _declared_unsigned_widths(body, source):
    """
    Return {var: bits} for locals declared with a narrow unsigned fixed-width
    type.  Names declared twice with different widths are dropped — without
    scope tracking there is no safe answer.
    """
    widths, conflicts = {}, set()
    for n in _walk(body):
        if n.type != 'declaration':
            continue
        type_node = n.child_by_field_name('type')
        if type_node is None:
            continue
        bits = _UNSIGNED_WIDTHS.get(node_text(type_node, source).strip())
        if bits is None:
            continue
        for child in n.children:
            name = None
            if child.type == 'identifier':
                name = node_text(child, source)
            elif child.type == 'init_declarator':
                decl = child.children[0] if child.children else None
                if decl is not None and decl.type == 'identifier':
                    name = node_text(decl, source)
            # pointer_declarator and array_declarator are not scalars
            if name is None:
                continue
            if name in widths and widths[name] != bits:
                conflicts.add(name)
            elif name not in conflicts:
                widths[name] = bits
    for name in conflicts:
        widths.pop(name, None)
    return widths


def _declared_pointers(body, source):
    """Return the set of locals declared with a pointer declarator."""
    names = set()
    for n in _walk(body):
        if n.type not in ('declaration', 'parameter_declaration'):
            continue
        for d in _walk(n):
            if d.type != 'pointer_declarator':
                continue
            inner = d.child_by_field_name('declarator')
            while inner is not None and inner.type in ('pointer_declarator',
                                                       'parenthesized_declarator'):
                inner = inner.child_by_field_name('declarator')
            if inner is not None and inner.type == 'identifier':
                names.add(node_text(inner, source))
    return names


# ---------------------------------------------------------------------------
# ptr-advance: pointer offset applied without the matching length adjustment
# ---------------------------------------------------------------------------
#
# The buffer behind `strlen(P)` is valid over [0, strlen(P)] — the NUL at index
# strlen(P) is readable.  A copy of LEN bytes starting at P + K therefore stays
# in bounds exactly when K + LEN <= strlen(P) + 1.  With LEN = strlen(P) + adj
# that reduces to K + adj <= 1, which is the whole test.  Only literal K and adj
# are evaluated; a symbolic advance is left alone rather than guessed at.

def _strlen_length_defs(body, source):
    """
    Return {var: {'base', 'adj', 'line'}} for locals whose value is strlen() of
    some pointer plus a literal adjustment.
    """
    defs = {}
    for n in _walk(body):
        if n.type == 'init_declarator':
            lhs, rhs = n.children[0], n.children[-1]
            if lhs.type != 'identifier':
                continue
            name = node_text(lhs, source)
        elif n.type == 'assignment_expression':
            if len(n.children) < 3 or n.children[1].type != '=':
                continue
            lhs, rhs = n.children[0], n.children[2]
            if lhs.type != 'identifier':
                continue
            name = node_text(lhs, source)
        else:
            continue

        parsed = _parse_strlen_expr(rhs, source)
        if parsed is not None:
            base, adj = parsed
            defs[name] = {'base': base, 'adj': adj, 'line': _line(n)}
    return defs


def _parse_strlen_expr(node, source):
    """
    Parse `strlen(P)`, `strlen(P) + 1`, `strlen(P) - 1`, ... into (P, adj).
    Returns None for anything else, including strnlen (whose result is not
    pinned to the terminator).
    """
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == 'call_expression':
        if _callee(node, source) != 'strlen':
            return None
        args = _args(node)
        if len(args) != 1:
            return None
        arg = _unwrap(args[0])
        if arg is None or arg.type != 'identifier':
            return None
        return node_text(arg, source), 0
    if node.type == 'binary_expression':
        op = node.children[1].type if len(node.children) >= 3 else None
        if op not in ('+', '-'):
            return None
        left = _parse_strlen_expr(node.children[0], source)
        right_val = _int_literal(node.children[2], source)
        if left is None or right_val is None:
            return None
        base, adj = left
        return base, adj + (right_val if op == '+' else -right_val)
    return None


def _parse_advanced_ptr(node, source):
    """
    Parse a pointer argument into (base, literal_offset).  Recognises `P + K`
    and `&P[K]`; a bare `P` yields offset 0.  Returns None when the base is not
    a plain identifier or the offset is not a literal.
    """
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == 'identifier':
        return node_text(node, source), 0
    if node.type == 'binary_expression' and len(node.children) >= 3:
        op = node.children[1].type
        if op not in ('+', '-'):
            return None
        base = _unwrap(node.children[0])
        if base is None or base.type != 'identifier':
            return None
        val = _int_literal(node.children[2], source)
        if val is None:
            return None
        return node_text(base, source), val if op == '+' else -val
    if node.type == 'pointer_expression':     # &p[k]
        inner = _unwrap(node.children[-1])
        if inner is not None and inner.type == 'subscript_expression':
            arr = _unwrap(inner.child_by_field_name('argument'))
            val = _int_literal(inner.child_by_field_name('index'), source)
            if arr is not None and arr.type == 'identifier' and val is not None:
                return node_text(arr, source), val
    return None


def _literal_advances(body, source):
    """
    Return {var: [(line, delta, conditional)]} for pointer advances by a literal
    amount: `p++`, `++p`, `p += K`, `p -= K`.
    """
    out = {}
    for n in _walk(body):
        name = delta = None
        if n.type == 'update_expression':
            arg = _unwrap(n.child_by_field_name('argument'))
            op = next((c.type for c in n.children if c.type in ('++', '--')), None)
            if arg is not None and arg.type == 'identifier' and op:
                name, delta = node_text(arg, source), (1 if op == '++' else -1)
        elif n.type == 'assignment_expression' and len(n.children) >= 3:
            op = n.children[1].type
            lhs = n.children[0]
            if op in _ADVANCE_OPS and lhs.type == 'identifier':
                val = _int_literal(n.children[2], source)
                if val is not None:
                    name = node_text(lhs, source)
                    delta = val if op == '+=' else -val
        if name is not None:
            out.setdefault(name, []).append(
                (_line(n), delta, _is_conditional(n, body))
            )
    return out


def check_ptr_advance(fn, body, source, path):
    findings = []
    length_defs = _strlen_length_defs(body, source)
    if not length_defs:
        return findings
    advances = _literal_advances(body, source)

    for call in (n for n in _walk(body) if n.type == 'call_expression'):
        callee = _callee(call, source)
        spec = _MEM_FNS.get(callee)
        if spec is None:
            continue
        ptr_idxs, len_idx = spec
        args = _args(call)
        if len_idx >= len(args):
            continue
        call_line = _line(call)

        # Resolve the length argument to (base, adj), either via a local whose
        # definition we captured or from an inline strlen expression.
        len_arg = _unwrap(args[len_idx])
        ldef = None
        if len_arg is not None and len_arg.type == 'identifier':
            ldef = length_defs.get(node_text(len_arg, source))
        if ldef is None:
            parsed = _parse_strlen_expr(args[len_idx], source)
            if parsed is not None:
                ldef = {'base': parsed[0], 'adj': parsed[1], 'line': call_line}
        if ldef is None:
            continue

        for idx in ptr_idxs:
            if idx >= len(args):
                continue
            adv = _parse_advanced_ptr(args[idx], source)
            if adv is None:
                continue
            base, offset = adv
            if base != ldef['base']:
                continue    # length measures a different buffer

            interposed = []
            if offset == 0:
                # The advance may sit between the length computation and the
                # call instead of in the argument.
                for aline, delta, cond in advances.get(base, []):
                    if ldef['line'] < aline < call_line:
                        interposed.append((aline, delta, cond))
                if not interposed:
                    continue
                offset = sum(d for _, d, _ in interposed)

            if offset + ldef['adj'] <= 1:
                continue    # copy ends at or before the terminator

            over = offset + ldef['adj'] - 1
            if interposed:
                where = ('advanced by %d at line %s after the length was taken'
                         % (offset, ', '.join(str(l) for l, _, _ in interposed)))
                conditional = any(c for _, _, c in interposed)
            else:
                where = 'advanced by %d in the call argument' % offset
                conditional = False
            findings.append(_finding(
                'ptr-advance', 'high', fn, path, source, call_line,
                f"{callee}() reads {base!r} {where}, but the length came from "
                f"strlen({base}){ldef['adj']:+d} measured at the un-advanced "
                f"base (line {ldef['line']}); the copy runs {over} byte(s) past "
                f"the terminator",
                base=base, advance=offset, length_adjust=ldef['adj'],
                length_line=ldef['line'], overrun=over, arg_index=idx,
                conditional=conditional,
            ))
    return findings


# ---------------------------------------------------------------------------
# scan-loop: traversal starts past the front without establishing the length
# ---------------------------------------------------------------------------

def _terminator_subscript(cond, source):
    """
    If cond is a NUL test on s[i] — bare `s[i]`, `!s[i]`, `s[i] != 0`,
    `s[i] == 0` — return (s, i).  Otherwise None.
    """
    cond = _unwrap(cond)
    if cond is None:
        return None
    if cond.type == 'unary_expression' and any(c.type == '!' for c in cond.children):
        return _terminator_subscript(cond.children[-1], source)
    if cond.type == 'binary_expression' and len(cond.children) >= 3:
        if cond.children[1].type not in ('!=', '=='):
            return None
        left, right = cond.children[0], cond.children[2]
        if _int_literal(right, source) == 0 or node_text(right, source).strip() in ("'\\0'", '0'):
            return _terminator_subscript(left, source)
        return None
    if cond.type == 'subscript_expression':
        arr = _unwrap(cond.child_by_field_name('argument'))
        idx = _unwrap(cond.child_by_field_name('index'))
        if (arr is not None and arr.type == 'identifier'
                and idx is not None and idx.type == 'identifier'):
            return node_text(arr, source), node_text(idx, source)
    return None


def _for_init_start(for_node, source):
    """Return (var, start) for a for-initialiser of the form `i = K` or `int i = K`."""
    init = for_node.child_by_field_name('initializer')
    if init is None:
        for child in for_node.children:
            if child.type in ('assignment_expression', 'declaration'):
                init = child
                break
    if init is None:
        return None
    if init.type == 'declaration':
        for child in init.children:
            if child.type == 'init_declarator' and len(child.children) >= 3:
                name_node, val = child.children[0], child.children[-1]
                if name_node.type == 'identifier':
                    val_i = _int_literal(val, source)
                    if val_i is not None:
                        return node_text(name_node, source), val_i
        return None
    if init.type == 'assignment_expression' and len(init.children) >= 3:
        if init.children[1].type != '=':
            return None
        lhs = init.children[0]
        val_i = _int_literal(init.children[2], source)
        if lhs.type == 'identifier' and val_i is not None:
            return node_text(lhs, source), val_i
    return None


def _increments(for_node, var, source):
    upd = for_node.child_by_field_name('update')
    nodes = [upd] if upd is not None else [
        c for c in for_node.children
        if c.type in ('update_expression', 'assignment_expression')
    ]
    for n in nodes:
        if n is None:
            continue
        for sub in _walk(n):
            if sub.type == 'update_expression':
                arg = _unwrap(sub.child_by_field_name('argument'))
                if (arg is not None and arg.type == 'identifier'
                        and node_text(arg, source) == var
                        and any(c.type == '++' for c in sub.children)):
                    return True
            if sub.type == 'assignment_expression' and len(sub.children) >= 3:
                if (sub.children[0].type == 'identifier'
                        and node_text(sub.children[0], source) == var
                        and sub.children[1].type == '+='
                        and _int_literal(sub.children[2], source) == 1):
                    return True
    return False


def _prior_length_evidence(buf, before_line, body, source):
    """
    Cheap check for anything earlier in the function that would establish the
    buffer is at least as long as the loop's starting index: a strlen/strnlen
    comparison, a strstarts() prefix test, or an explicit index test.
    """
    for n in _walk(body):
        if _line(n) >= before_line:
            continue
        if n.type == 'call_expression':
            callee = _callee(n, source)
            if callee in ('strlen', 'strnlen', 'strstarts', 'strncmp', 'memcmp'):
                if buf in _identifiers(n, source):
                    return True
        if n.type == 'subscript_expression':
            arr = _unwrap(n.child_by_field_name('argument'))
            if (arr is not None and arr.type == 'identifier'
                    and node_text(arr, source) == buf
                    and _int_literal(n.child_by_field_name('index'), source) is not None):
                return True
    return False


def check_scan_loop(fn, body, source, path):
    findings = []
    for for_node in (n for n in _walk(body) if n.type == 'for_statement'):
        init = _for_init_start(for_node, source)
        if init is None:
            continue
        var, start = init
        if start <= 0:
            continue
        cond = for_node.child_by_field_name('condition')
        if cond is None:
            continue
        term = _terminator_subscript(cond, source)
        if term is None:
            continue
        buf, idx = term
        if idx != var or not _increments(for_node, var, source):
            continue

        line = _line(for_node)
        guarded = _prior_length_evidence(buf, line, body, source)
        findings.append(_finding(
            'scan-loop', 'medium' if guarded else 'high', fn, path, source, line,
            f"scan of {buf!r} starts at index {start}, so the terminator is "
            f"never tested for positions 0..{start - 1}; if strlen({buf}) < "
            f"{start} the loop runs off the end of the buffer unbounded",
            buffer=buf, start=start, possibly_guarded=guarded,
        ))
    return findings


# ---------------------------------------------------------------------------
# narrow-sub / narrow-add: fixed-width wrap reaching a size, offset or field
# ---------------------------------------------------------------------------

# Sink roles, worst consequence first.  A variable usually lands in several;
# the finding should name the one that hurts most, not the first one seen.
# The first four put the wrapped value between an allocation and a write; the
# last two only corrupt a request or a caller's arithmetic, which is why SMB1
# request construction (`byte_count = 3 + params + count`, everywhere in
# cifssmb.c) scores below them rather than drowning them out.
_MEMORY_SINKS = (
    'memory-op length',
    'allocation size',
    'array subscript',
    'pointer offset',
)
_SINK_RANK = _MEMORY_SINKS + ('wire field', 'return value')

# An addend the function did not compute itself.
_EXTERNAL_OPERAND = frozenset({
    'call_expression', 'field_expression', 'subscript_expression',
})


def _externally_sourced(node):
    return any(n.type in _EXTERNAL_OPERAND for n in _walk(node))


def _cursor_pointers(body, source):
    """Return {var: set(pointers assigned `base + var`)}."""
    cursors = {}
    for n in _walk(body):
        if n.type == 'init_declarator':
            lhs, rhs = n.children[0], n.children[-1]
        elif n.type == 'assignment_expression' and len(n.children) >= 3:
            lhs, rhs = n.children[0], n.children[2]
        else:
            continue
        if lhs.type != 'identifier':
            continue
        inner = _unwrap(rhs)
        if (inner is None or inner.type != 'binary_expression'
                or len(inner.children) < 3 or inner.children[1].type != '+'):
            continue
        ptr = node_text(lhs, source)
        for side in (inner.children[0], inner.children[2]):
            side = _unwrap(side)
            if side is not None and side.type == 'identifier':
                cursors.setdefault(node_text(side, source), set()).add(ptr)
    return cursors


def _walks_a_record_chain(operands, source, ptrs):
    """
    True when the addend is a length field read through a pointer the
    accumulator itself positioned — `size += le16_to_cpu(pntace->size)` with
    `pntace = acl_base + size`.  That is a walk over length-prefixed records,
    and the sum is bounded by the containing object's own size field, so the
    wrap question belongs to whoever validated the chain rather than here.
    Deliberately requires a field read and not a mere mention of the pointer:
    `nsize += cifs_copy_ace(pnntace, ...)` accumulates bytes written, which is
    the shape this check exists to catch.
    """
    for f in _walk(operands):
        if f.type != 'field_expression':
            continue
        base = _unwrap(f.child_by_field_name('argument'))
        if (base is not None and base.type == 'identifier'
                and node_text(base, source) in ptrs):
            return True
    return False


def _sink_uses(body, source, scalars):
    """
    Return {var: [(line, role)]} for variables appearing in a position where a
    wrapped value does damage.  `scalars` names the known integer locals, used
    to tell `base + off` pointer arithmetic from ordinary integer addition.
    """
    uses = {}

    def record(node, role):
        node = _unwrap(node)
        if node is None:
            return
        for name in _identifiers(node, source):
            uses.setdefault(name, []).append((_line(node), role))

    for n in _walk(body):
        if n.type == 'call_expression':
            callee = _callee(n, source)
            args = _args(n)
            if callee in _ALLOC_FNS and args:
                record(args[0] if callee != 'krealloc' else args[-1], 'allocation size')
            elif callee in _MEM_FNS:
                _, len_idx = _MEM_FNS[callee]
                if len_idx < len(args):
                    record(args[len_idx], 'memory-op length')
            elif callee in _WIRE_STORE_FNS and args:
                record(args[0], 'wire field')
        elif n.type == 'subscript_expression':
            record(n.child_by_field_name('index'), 'array subscript')
        elif n.type == 'binary_expression' and len(n.children) >= 3:
            if n.children[1].type == '+':
                left = _unwrap(n.children[0])
                # Only count this as building a pointer when the base is not
                # itself integer arithmetic — `sizeof(*buf) + plen` is a size
                # computation, `nacl_base + nsize` is an offset into a buffer.
                if (left is not None and left.type == 'identifier'
                        and node_text(left, source) not in scalars):
                    record(n.children[2], 'pointer offset')
        elif n.type == 'return_statement':
            for child in n.children:
                if child.type not in ('return', ';'):
                    record(child, 'return value')
    return uses


def _value_flow(body, source):
    """
    Return {var: set((dest, line))} for plain local assignments: one hop, with
    the line so the caller can require source-order.  `plen` reaching kzalloc
    via `len = sizeof(*buf) + plen` is exactly this shape.  Deliberately not
    closed transitively — with no control flow or SSA to constrain it, the
    closure over a whole function body collapses into one clique and every
    finding then cites an unrelated variable's sink.
    """
    flow = {}
    for n in _walk(body):
        if n.type == 'init_declarator':
            lhs, rhs = n.children[0], n.children[-1]
        elif n.type == 'assignment_expression' and len(n.children) >= 3:
            lhs, rhs = n.children[0], n.children[2]
        else:
            continue
        if lhs.type != 'identifier':
            continue
        dest = node_text(lhs, source)
        for src in _identifiers(rhs, source):
            if src != dest:
                flow.setdefault(src, set()).add((dest, _line(n)))
    return flow


def _relational_guard(var, other_ids, body, source, before_line):
    """
    True if some earlier condition relates var to one of the RHS identifiers,
    which is what a hand-written `if (a < b) return` underflow check looks like.
    """
    for n in _walk(body):
        if n.type != 'binary_expression' or len(n.children) < 3:
            continue
        if n.children[1].type not in ('<', '<=', '>', '>=', '==', '!='):
            continue
        if _line(n) > before_line:
            continue
        ids = _identifiers(n, source)
        if var in ids and (ids & other_ids):
            return True
    return False


def _bounded_after(var, body, source, after_line, sink_line):
    """
    True if some comparison mentioning var sits between the arithmetic and the
    sink.  `ulen = le16_to_cpu(rp->ReparseDataLength) - sizeof(...)` underflows
    for real, then `if (!ulen || uname + ulen > end) goto out` catches it before
    the subscript — the author validated after computing rather than before.
    Unlike _relational_guard this does not require the comparison to mention an
    operand: by this point the wrapped value is the only thing worth testing.
    Demotes rather than suppresses, since the check can still be the wrong one.
    """
    for n in _walk(body):
        if n.type != 'binary_expression' or len(n.children) < 3:
            continue
        if n.children[1].type not in ('<', '<=', '>', '>=', '==', '!='):
            continue
        line = _line(n)
        if after_line < line <= sink_line and var in _identifiers(n, source):
            return True
    return False


def _constant_operand(node, source):
    """Value of an all-literal arithmetic expression, or None."""
    node = _unwrap(node)
    if node is None:
        return None
    lit = _int_literal(node, source)
    if lit is not None:
        return lit
    if node.type == 'binary_expression' and len(node.children) >= 3:
        a = _constant_operand(node.children[0], source)
        b = _constant_operand(node.children[2], source)
        op = node.children[1].type
        if a is None or b is None:
            return None
        return {'+': a + b, '-': a - b, '*': a * b,
                '<<': a << b, '>>': a >> b}.get(op)
    return None


def _constant_lower_bound(var, body, source, before_line):
    """
    Greatest K for which an earlier condition establishes `var >= K`, or None.
    Unlike _relational_guard this is decidable rather than suggestive: against
    a constant subtrahend it settles the question, so it suppresses outright
    instead of demoting.  `!var` counts — an early `if (!ulen) goto out` is how
    a decrement-by-one is usually protected.
    """
    best = None
    for n in _walk(body):
        if _line(n) > before_line:
            continue
        bound = None
        if n.type == 'unary_expression' and len(n.children) == 2 \
                and n.children[0].type == '!':
            operand = _unwrap(n.children[1])
            if operand is not None and operand.type == 'identifier' \
                    and node_text(operand, source) == var:
                bound = 1
        elif n.type == 'binary_expression' and len(n.children) >= 3:
            op = n.children[1].type
            left, right = _unwrap(n.children[0]), _unwrap(n.children[2])
            if left is not None and left.type == 'identifier' \
                    and node_text(left, source) == var:
                c = _constant_operand(right, source)
                if c is not None:
                    bound = {'>': c + 1, '>=': c, '!=': 1 if c == 0 else None,
                             '==': c}.get(op)
            elif right is not None and right.type == 'identifier' \
                    and node_text(right, source) == var:
                c = _constant_operand(left, source)
                if c is not None:
                    bound = {'<': c + 1, '<=': c, '!=': 1 if c == 0 else None,
                             '==': c}.get(op)
        if bound is not None and (best is None or bound > best):
            best = bound
    return best


def _undoes_overflow_check(node, var, source):
    """
    True for the rollback arm of `if (check_add_overflow(a, b, &a)) a -= b;`.
    The helper has already stored the wrapped sum, so the subtraction restores
    the pre-add value — it is an undo, not arithmetic on a live quantity.
    """
    cur = node.parent
    while cur is not None:
        if cur.type == 'if_statement':
            cond = cur.child_by_field_name('condition')
            if cond is not None:
                for c in _walk(cond):
                    if (c.type == 'call_expression'
                            and _callee(c, source) in _SAFE_ARITH
                            and var in _identifiers(c, source)):
                        return True
        cur = cur.parent
    return False


def _narrow_arith(fn, body, source, path, check, ops, max_bits):
    findings = []
    declared = _declared_unsigned_widths(body, source)
    widths = {v: b for v, b in declared.items() if b <= max_bits}
    if not widths:
        return findings
    sinks = _sink_uses(body, source, set(declared))
    flow = _value_flow(body, source)
    cursors = _cursor_pointers(body, source)
    pointers = _declared_pointers(body, source)

    compound = ops['compound']
    binary_op = ops['binary']

    hits = {}

    for n in _walk(body):
        if n.type != 'assignment_expression' or len(n.children) < 3:
            continue
        lhs, op, rhs = n.children[0], n.children[1].type, n.children[2]
        if lhs.type != 'identifier':
            continue
        var = node_text(lhs, source)
        bits = widths.get(var)
        if bits is None:
            continue

        if op == compound:
            operands = rhs
        elif op == '=':
            inner = _unwrap(rhs)
            if (inner is None or inner.type != 'binary_expression'
                    or len(inner.children) < 3
                    or inner.children[1].type != binary_op):
                continue
            operands = inner
        else:
            continue

        line = _line(n)
        if _enclosing_call(n, source, _SAFE_ARITH) is not None:
            continue
        if _undoes_overflow_check(n, var, source):
            continue
        # `max_non_overlap = dp_addr - dp_back_addr` is a distance between two
        # pointers into the same object, not a decrement: whoever ordered them
        # ordered them, and there is no narrow quantity being spent down.
        if op == '=' and check == 'narrow-sub' and all(
                (s := _unwrap(side)) is not None and s.type == 'identifier'
                and node_text(s, source) in pointers
                for side in (operands.children[0], operands.children[2])):
            continue
        # Against a constant change, a constant lower bound settles it:
        # `if (len > 2) len -= 2` is safe, and no amount of sink analysis
        # makes it otherwise.
        delta = _constant_operand(operands if op == compound
                                  else operands.children[2], source)
        if delta is not None and check == 'narrow-sub':
            floor_ = _constant_lower_bound(var, body, source, line)
            if floor_ is not None and floor_ >= delta:
                continue
        # A for-update is bounded by its own condition, or the loop never ends.
        # (Compare ids: the bindings hand back a fresh Node per lookup.)
        parent = n.parent
        if parent is not None and parent.type == 'for_statement':
            upd = parent.child_by_field_name('update')
            if upd is not None and upd.id == n.id:
                continue

        # The result has to go somewhere that matters.  A sink earlier in the
        # same loop still consumes the accumulated value on the next trip —
        # `pnntace = nacl_base + nsize` sits one line above the `nsize +=` it
        # is fed by.
        loop = _enclosing_loop(n, body)
        lo = _line(loop) if loop is not None else line
        hi = loop.end_point[0] + 1 if loop is not None else None

        def _visible(l, since):
            return l >= since or (hi is not None and lo <= l <= hi)

        reached = [(var, r, l) for l, r in sinks.get(var, [])
                   if _visible(l, line)]
        for downstream, hop in flow.get(var, ()):
            if not _visible(hop, line):
                continue
            reached += [(downstream, r, l) for l, r in sinks.get(downstream, [])
                        if _visible(l, hop)]
        if not reached:
            continue
        # The variable's own use beats a use one hop downstream: same wrap,
        # more concrete story.
        sink = min(reached,
                   key=lambda r: (r[0] != var, _SINK_RANK.index(r[1]), r[2]))

        rhs_ids = _identifiers(operands, source) - {var}
        hits.setdefault(var, []).append({
            'line': line,
            'bits': bits,
            'sink': sink,
            'guarded': (_relational_guard(var, rhs_ids, body, source, line)
                        or _bounded_after(var, body, source, line, sink[2])),
            'in_loop': loop is not None,
            'external': _externally_sourced(operands),
            'chain': _walks_a_record_chain(operands, source,
                                           cursors.get(var, ())),
            'accumulates': op == compound or var in _identifiers(operands,
                                                                 source),
        })

    # One accumulator is one bug however many statements feed it; emitting a
    # finding per statement buried the two real DACL cases under seven copies.
    for var, sites in hits.items():
        first = sites[0]
        bits = first['bits']
        via, role, sink_line = min(
            (s['sink'] for s in sites),
            key=lambda r: (r[0] != var, _SINK_RANK.index(r[1]), r[2]))
        guarded = all(s['guarded'] for s in sites)
        in_loop = any(s['in_loop'] for s in sites)
        external = any(s['external'] for s in sites)
        chain = all(s['chain'] for s in sites)
        accumulates = any(s['accumulates'] for s in sites)

        if chain:
            what = (f"{bits}-bit {var!r} walks a chain of length-prefixed "
                    f"records, stepping by each record's own length field; "
                    f"the sum is bounded by the container's size, so whether "
                    f"it can run long depends on who validated the chain")
        elif check == 'narrow-add' and not accumulates:
            what = (f"unsigned {bits}-bit {var!r} is computed as a sum in one "
                    f"expression, so it truncates rather than accumulates; it "
                    f"is wrong only if that single sum can exceed 2^{bits}")
        elif check == 'narrow-sub':
            what = (f"unsigned {bits}-bit {var!r} is decremented without "
                    f"establishing that it is large enough; on wrap it becomes "
                    f"nearly 2^{bits}")
        else:
            what = (f"unsigned {bits}-bit {var!r} accumulates"
                    f"{' inside a loop' if in_loop else ''} with no bound on "
                    f"the total; the sum wraps silently at 2^{bits}")

        through = '' if via == var else f" (via {via!r})"
        more = ('' if len(sites) == 1 else
                f"; {len(sites) - 1} further such statement"
                f"{'' if len(sites) == 2 else 's'} at "
                + ', '.join(str(s['line']) for s in sites[1:]))
        # A sum can only wrap if something unbounded feeds it.  Addition off
        # locals the function itself computed, outside any loop, is the SMB1
        # request-header idiom (`offset = param_offset + params`) — fourteen
        # copies of it in cifssmb.c, none reachable.  A one-expression sum is
        # a narrowing computation, which is Cat H's question, not this one:
        # `log2_bits = sb->s_blocksize_bits + 3` was most of what a whole-fs/
        # run turned up.  Subtraction is exempt from both — one underflowing
        # decrement is enough, whatever fed it and however it is written.
        if role not in _MEMORY_SINKS or chain:
            severity = 'low'
        elif check == 'narrow-add' and not (accumulates
                                            and (in_loop or external)):
            severity = 'low'
        else:
            severity = 'medium' if guarded else 'high'

        findings.append(_finding(
            check, severity, fn, path, source, first['line'],
            f"{what}, and the result reaches "
            f"{'an' if role[0] in 'aeiou' else 'a'} {role} at line {sink_line}"
            f"{through}{more}",
            var=var, bits=bits, sink_role=role, sink_line=sink_line,
            sink_var=via, in_loop=in_loop, possibly_guarded=guarded,
            external_addend=external, record_chain=chain,
            accumulates=accumulates,
            sites=[s['line'] for s in sites],
        ))
    return findings


def check_narrow_sub(fn, body, source, path, max_bits=16):
    return _narrow_arith(fn, body, source, path, 'narrow-sub',
                         {'compound': '-=', 'binary': '-'}, max_bits)


def check_narrow_add(fn, body, source, path, max_bits=16):
    return _narrow_arith(fn, body, source, path, 'narrow-add',
                         {'compound': '+=', 'binary': '+'}, max_bits)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def scan_file(path, checks=CHECKS, max_bits=16):
    tree, source = parse_file(path)
    findings = []
    for fninfo in find_functions(tree, source):
        name, body = fninfo['name'], fninfo['body']
        if 'ptr-advance' in checks:
            findings += check_ptr_advance(name, body, source, path)
        if 'scan-loop' in checks:
            findings += check_scan_loop(name, body, source, path)
        if 'narrow-sub' in checks:
            findings += check_narrow_sub(name, body, source, path, max_bits)
        if 'narrow-add' in checks:
            findings += check_narrow_add(name, body, source, path, max_bits)
    findings.sort(key=lambda f: (f['line'], f['check']))
    return findings


def scan_paths(paths, checks=CHECKS, max_bits=16):
    findings = []
    for path in paths:
        try:
            findings += scan_file(path, checks, max_bits)
        except (OSError, UnicodeDecodeError) as e:
            print(f"warning: {path}: {e}")
    return findings
