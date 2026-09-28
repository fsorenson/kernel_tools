"""
Intra-procedural taint scanner for kernel C code.

Tracks server-supplied values from their origin (calls to endian-conversion
and unaligned-read functions) through assignments and expressions to dangerous
sinks (memcpy, kmalloc, array indexing, etc.) without an intervening bounds check.

Categories detected:
  A — tainted value → pointer arithmetic → used as ptr argument to memory op
  B — tainted value → size argument to memory op or allocator
  C — tainted value → array subscript
  F — tainted value → loop iteration count
  H — tainted wide value stored in a narrower integer type (silent truncation)

Each finding includes the taint source location, the sink location, and a
"possibly_guarded" flag indicating whether a conditional on the tainted variable
appears between the source and sink (line-number heuristic; the LLM stage
reasons about it more carefully).  When a conditional is present but does not
answer the question the sink asks, "guard_kind" says which way it falls short —
see _find_guards_between.
"""

from collections import namedtuple

from kernel_analysis.parsers.c_parser import (
    _walk, node_text, get_source_line,
    find_calls_to, extract_local_array_decls, find_alloc_vars,
    ALLOC_FUNCS, TYPE_NODES,
)


# ---------------------------------------------------------------------------
# Taint sources: functions that return server/network-supplied values
# ---------------------------------------------------------------------------

TAINT_SOURCES = frozenset({
    # Unaligned LE reads (most common in SMB/CIFS)
    'get_unaligned_le16', 'get_unaligned_le32', 'get_unaligned_le64',
    'get_unaligned_le8',
    # Unaligned BE reads (NFS, others)
    'get_unaligned_be16', 'get_unaligned_be32', 'get_unaligned_be64',
    'get_unaligned_be8',
    # Endian conversion from __le/__be struct fields
    'le16_to_cpu', 'le32_to_cpu', 'le64_to_cpu',
    'be16_to_cpu', 'be32_to_cpu', 'be64_to_cpu',
    # In-place endian store/load helpers that return the value
    'le16_to_cpus', 'le32_to_cpus', 'le64_to_cpus',
    # ntohs / ntohl (network byte order, used in some subsystems)
    'ntohs', 'ntohl', 'ntohe',
})

# Maps each taint source to its natural return-value bit width.
# Used by Category H to detect when a wide server-supplied value is stored
# in a narrower integer type (silent truncation).
TAINT_SOURCE_WIDTHS = {
    'get_unaligned_le8':  8,  'get_unaligned_be8':  8,
    'get_unaligned_le16': 16, 'get_unaligned_be16': 16,
    'get_unaligned_le32': 32, 'get_unaligned_be32': 32,
    'get_unaligned_le64': 64, 'get_unaligned_be64': 64,
    'le16_to_cpu': 16, 'be16_to_cpu': 16, 'le16_to_cpus': 16,
    'le32_to_cpu': 32, 'be32_to_cpu': 32, 'le32_to_cpus': 32,
    'le64_to_cpu': 64, 'be64_to_cpu': 64, 'le64_to_cpus': 64,
    'ntohs': 16, 'ntohl': 32, 'ntohe': 32,
}

# ---------------------------------------------------------------------------
# Dangerous sinks: functions where a tainted argument is a bug
# ---------------------------------------------------------------------------

# Maps function name → argument role classification:
#   'size_args'   — argument indices that are sizes/lengths (Category B)
#   'ptr_args'    — argument indices that are destination/source pointers
#                   where a tainted value used in pointer arithmetic lands (Category A)
#   'alloc'       — True if this is an allocator (size_args is the allocation size)
#
# Argument indices are 0-based.

DANGEROUS_SINKS = {
    # Memory operations
    'memcpy':            {'size_args': [2], 'ptr_args': [0, 1]},
    'memmove':           {'size_args': [2], 'ptr_args': [0, 1]},
    'memset':            {'size_args': [2], 'ptr_args': [0]},
    'memcmp':            {'size_args': [2], 'ptr_args': [0, 1]},
    # String operations
    'strncpy':           {'size_args': [2], 'ptr_args': [0]},
    'strlcpy':           {'size_args': [2], 'ptr_args': [0]},
    'strlcat':           {'size_args': [2], 'ptr_args': [0]},
    'strncmp':           {'size_args': [2]},
    'strncat':           {'size_args': [2], 'ptr_args': [0]},
    'snprintf':          {'size_args': [1], 'ptr_args': [0]},
    'scnprintf':         {'size_args': [1], 'ptr_args': [0]},
    # User-space copy
    'copy_to_user':      {'size_args': [2], 'ptr_args': [1]},
    'copy_from_user':    {'size_args': [2], 'ptr_args': [0]},
    '__copy_to_user':    {'size_args': [2], 'ptr_args': [1]},
    '__copy_from_user':  {'size_args': [2], 'ptr_args': [0]},
    'put_user':          {'size_args': []},   # single value — flag if ptr is tainted
    # Allocation — size argument
    'kmalloc':           {'size_args': [0], 'alloc': True},
    'kzalloc':           {'size_args': [0], 'alloc': True},
    'kvmalloc':          {'size_args': [0], 'alloc': True},
    'kvzalloc':          {'size_args': [0], 'alloc': True},
    'vmalloc':           {'size_args': [0], 'alloc': True},
    'vzalloc':           {'size_args': [0], 'alloc': True},
    '__kmalloc':         {'size_args': [0], 'alloc': True},
    'kmalloc_node':      {'size_args': [0], 'alloc': True},
    'kzalloc_node':      {'size_args': [0], 'alloc': True},
    'krealloc':          {'size_args': [1], 'alloc': True},
    'devm_kmalloc':      {'size_args': [1], 'alloc': True},
    'devm_kzalloc':      {'size_args': [1], 'alloc': True},
    # Two-argument allocators (count × element size): both args are relevant
    'kcalloc':           {'size_args': [0, 1], 'alloc': True, 'is_counted': True},
    'kmalloc_array':     {'size_args': [0, 1], 'alloc': True, 'is_counted': True},
    'devm_kcalloc':      {'size_args': [1, 2], 'alloc': True, 'is_counted': True},
}

# For Category C: these operators produce a subscript expression
_SUBSCRIPT_NODE = 'subscript_expression'

# ---------------------------------------------------------------------------
# Category H: type-width narrowing tables
# ---------------------------------------------------------------------------

# Maps C integer type names → bit width.  Only covers types that actually
# appear in kernel protocol parsing code; excludes pointer types.
_TYPE_WIDTHS = {
    # Kernel u/s typedefs
    'u8': 8,  '__u8': 8,  's8': 8,  '__s8': 8,
    'u16': 16, '__u16': 16, 's16': 16, '__s16': 16,
    'u32': 32, '__u32': 32, 's32': 32, '__s32': 32,
    'u64': 64, '__u64': 64, 's64': 64, '__s64': 64,
    # Endian-annotated types (same underlying width)
    '__le16': 16, '__be16': 16,
    '__le32': 32, '__be32': 32,
    '__le64': 64, '__be64': 64,
    # POSIX fixed-width
    'uint8_t': 8,  'int8_t': 8,
    'uint16_t': 16, 'int16_t': 16,
    'uint32_t': 32, 'int32_t': 32,
    'uint64_t': 64, 'int64_t': 64,
    # C primitives (kernel assumes LP64)
    'char': 8,  'unsigned char': 8,
    'short': 16, 'unsigned short': 16,
    'int': 32,  'unsigned int': 32, 'unsigned': 32,
    'long': 64, 'unsigned long': 64,
}


def _get_type_width(type_text):
    """Return bit width of a C integer type string, or None if unknown/pointer."""
    return _TYPE_WIDTHS.get(type_text.strip())


def _build_local_widths(fn_body, source):
    """
    Return {var_name: bit_width} for integer variables declared in fn_body.
    Skips pointer declarators; only covers scalar integer locals.

    Variables declared multiple times with conflicting widths (e.g. same name
    in if/else branches with different types) are excluded — we can't safely
    determine the intended width without scope tracking.
    """
    widths = {}
    conflicts = set()
    for n in _walk(fn_body):
        if n.type != 'declaration':
            continue
        type_node = n.child_by_field_name('type')
        if type_node is None:
            continue
        width = _get_type_width(node_text(type_node, source))
        if width is None:
            continue
        for child in n.children:
            if child.type == 'init_declarator':
                decl = child.children[0] if child.children else None
                if decl and decl.type == 'identifier':
                    name = node_text(decl, source)
                    if name in widths and widths[name] != width:
                        conflicts.add(name)
                    elif name not in conflicts:
                        widths[name] = width
            elif child.type == 'identifier':
                name = node_text(child, source)
                if name in widths and widths[name] != width:
                    conflicts.add(name)
                elif name not in conflicts:
                    widths[name] = width
            # pointer_declarator → skip (not an integer scalar)
    for name in conflicts:
        widths.pop(name, None)
    return widths


# Overflow-safe size helpers: if any of these wrap the size argument (or an
# operand within it), the arithmetic is already overflow-checked — don't flag.
_SAFE_SIZE_HELPERS = frozenset({
    'array_size',           # array_size(n, size) → SIZE_MAX on overflow
    'array3_size',          # array3_size(a, b, c)
    'size_mul',             # 5.8+: size_mul(a, b)
    'size_add',             # 5.8+: size_add(a, b)
    'struct_size',          # struct_size(p, member, n) for trailing-array allocs
    'check_mul_overflow',   # explicit check; caller handles the error path
    'check_add_overflow',
    'saturate_add',
})

# ---------------------------------------------------------------------------
# Category D: unterminated string (strlen / strlcpy on server-supplied buffer)
# ---------------------------------------------------------------------------
#
# Maps function name → index of the argument that must be null-terminated.
# These functions assume null termination without enforcing a length bound on
# the source buffer.  strlcpy is included because it limits the *destination*
# copy length but still internally calls strlen on the source.
_STRING_UNSAFE_SINKS = {
    'strlen':  0,
    'strlcpy': 1,   # strlcpy(dst, src, n)   — still strlen's src
    'strcat':  1,   # strcat(dst, src)
    'strdup':  0,
    'kstrdup': 0,
}

# Calls that establish a safe bounded-length search — constitute a guard for Cat D.
_STRING_SAFE_CALLS = frozenset({'strnlen', 'memchr', 'memchr_inv'})


# ---------------------------------------------------------------------------
# Expression taint analysis helpers
# ---------------------------------------------------------------------------

def _node_has_taint_source_call(node, source):
    """Return the first TAINT_SOURCES function name found in node, or None."""
    for n in _walk(node):
        if n.type != 'call_expression':
            continue
        fn_id = next((c for c in n.children if c.type == 'identifier'), None)
        if fn_id:
            name = node_text(fn_id, source)
            if name in TAINT_SOURCES:
                return name
    return None


def _node_references_tainted_var(node, source, tainted):
    """Return first tainted variable name found in node's identifiers, or None."""
    for n in _walk(node):
        if n.type == 'identifier':
            name = node_text(n, source)
            if name in tainted:
                return name
    return None


def _rhs_has_additive_arith(rhs_node):
    """
    Return True if rhs_node contains additive arithmetic (+ or - as a binary
    operator).  Uses the AST to avoid false positives from '->' member access,
    '--' decrement, unary '-', and similar constructs that contain the '-'
    character but are not pointer arithmetic.
    """
    for n in _walk(rhs_node):
        if n.type == 'binary_expression':
            if any(c.type in ('+', '-') for c in n.children):
                return True
    return False


# Compound assignment operators.  `acc op= rhs` is `acc = acc op rhs`, so the
# LHS keeps any taint it already carried and additionally picks up the RHS's —
# a merge, not a replace.  Size accumulation in kernel protocol parsers is
# written this way almost exclusively.
_COMPOUND_ASSIGN_OPS = frozenset({
    '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=',
})


def _merged_kind(lhs_var, prev, assign_op, var_widths):
    """
    Classify the LHS of a compound assignment as 'value' or 'pointer'.

    Unlike the plain-'=' case there is no RHS shape to read the answer off:
    `p += n` and `acc += n` are the same expression.  Membership in var_widths
    is authoritative (it is built from scalar integer declarations and skips
    pointer declarators); failing that, an existing classification wins, and
    only `+=`/`-=` on an otherwise-unknown name is guessed as pointer walking.
    """
    if lhs_var in var_widths:
        return 'value'
    if prev:
        return prev['kind']
    return 'pointer' if assign_op in ('+=', '-=') else 'value'


def _extract_lhs_var(assign_node, source):
    """
    Extract the variable name from the left-hand side of an assignment or
    init_declarator.  Returns None for complex LHS patterns (struct member, etc.).
    """
    # assignment_expression: [lhs, op, rhs]
    if assign_node.type == 'assignment_expression':
        lhs = assign_node.children[0]
        if lhs.type == 'identifier':
            return node_text(lhs, source)
        # Ignore struct member assignments — we don't track field-level taint
        return None
    # init_declarator: [declarator, '=', initializer]
    if assign_node.type == 'init_declarator':
        decl = assign_node.children[0]
        if decl.type == 'identifier':
            return node_text(decl, source)
        # pointer_declarator: *var = ...
        if decl.type == 'pointer_declarator':
            ident = next((c for c in decl.children if c.type == 'identifier'), None)
            if ident:
                return node_text(ident, source)
    return None


def _arg_nodes(call_node):
    """Return the non-punctuation argument nodes for a call_expression."""
    arg_list = next(
        (c for c in call_node.children if c.type == 'argument_list'), None
    )
    if not arg_list:
        return []
    return [c for c in arg_list.children if c.type not in ('(', ')', ',')]


def _find_overflow_in_size_arg(arg_node, source, tainted):
    """
    Detect integer overflow risk in a size/length argument.

    Checks whether the argument is a top-level binary * or + expression
    where at least one operand carries taint — without a safe overflow
    wrapper (_SAFE_SIZE_HELPERS) guarding the expression.

    Only examines the outermost binary expression (unwrapping one layer of
    parens/casts) to avoid multiple findings for chains like a * b * c.

    Returns a list with at most one dict:
        {'op', 'lhs_text', 'rhs_text', 'taint_source', 'tainted_var',
         'taint_line', 'taint_kind'}
    or [] if no overflow risk is found.
    """
    def _is_safe_call(node):
        if node.type != 'call_expression':
            return False
        fn_id = next((c for c in node.children if c.type == 'identifier'), None)
        return fn_id is not None and node_text(fn_id, source) in _SAFE_SIZE_HELPERS

    # If the whole arg is a safe helper, bail immediately.
    if _is_safe_call(arg_node):
        return []

    # Unwrap one layer of parentheses or cast to find the binary expression.
    target = arg_node
    if arg_node.type in ('parenthesized_expression', 'cast_expression'):
        for child in arg_node.children:
            if child.type == 'binary_expression':
                target = child
                break

    if target.type != 'binary_expression':
        return []

    op_types = {c.type for c in target.children}
    if '*' not in op_types and '+' not in op_types:
        return []
    op = '*' if '*' in op_types else '+'

    lhs = target.children[0]
    rhs = target.children[-1]

    # If either operand is itself a safe helper, the expression is protected.
    if _is_safe_call(lhs) or _is_safe_call(rhs):
        return []

    # Find taint in either operand.
    taint_src = tainted_var = taint_line_v = None
    taint_kind = 'value'
    for side in (lhs, rhs):
        src = _node_has_taint_source_call(side, source)
        if src:
            taint_src, tainted_var = src, node_text(side, source)[:60]
            taint_line_v = target.start_point[0] + 1
            break
        ref = _node_references_tainted_var(side, source, tainted)
        if ref:
            taint_src = tainted[ref]['source_fn']
            tainted_var = ref
            taint_line_v = tainted[ref]['line']
            taint_kind = tainted[ref]['kind']
            break

    if not taint_src:
        return []

    return [{
        'op':          op,
        'lhs_text':    node_text(lhs, source)[:60],
        'rhs_text':    node_text(rhs, source)[:60],
        'taint_source': taint_src,
        'tainted_var': tainted_var,
        'taint_line':  taint_line_v,
        'taint_kind':  taint_kind,
    }]


def _collect_tainted_args(args, source, tainted, call_line):
    """
    Return {arg_idx: taint_info} for arguments that carry taint.
    taint_info: {'var', 'source_fn', 'line', 'kind'}
    """
    result = {}
    for i, arg in enumerate(args):
        src = _node_has_taint_source_call(arg, source)
        if src:
            result[i] = {
                'var': node_text(arg, source)[:60],
                'source_fn': src,
                'line': call_line,
                'kind': 'value',
            }
        else:
            ref = _node_references_tainted_var(arg, source, tainted)
            if ref:
                info = tainted[ref]
                result[i] = {
                    'var': ref,
                    'source_fn': info['source_fn'],
                    'line': info['line'],
                    'kind': info['kind'],
                }
    return result


# ---------------------------------------------------------------------------
# Guard / check detection
# ---------------------------------------------------------------------------

_GUARD_CMP_OPS   = frozenset({'<', '<=', '>', '>=', '==', '!='})
_GUARD_TERM_STMTS = frozenset({
    'return_statement', 'goto_statement', 'break_statement', 'continue_statement',
})
_GUARD_TERM_CALLS = frozenset({
    'BUG', 'BUG_ON', 'BUG_ON_NULL', 'panic',
    'WARN', 'WARN_ON', 'WARN_ON_ONCE',
})

# Which end of the variable's range a comparison pins, when the variable is the
# left operand and the condition is true.  `i > 7` true means i is large, so it
# is a floor; the early-exit form `if (i > 7) return;` inverts it to a ceiling.
_BOUND_FOR_LEFT = {'<': 'upper', '<=': 'upper', '>': 'lower', '>=': 'lower'}
_FLIP = {'upper': 'lower', 'lower': 'upper'}

_ARITH_OPS = frozenset({'+', '-', '*', '<<'})

_SIGNED_TYPES = frozenset({
    's8', '__s8', 's16', '__s16', 's32', '__s32', 's64', '__s64',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'short', 'short int', 'int', 'long', 'long int', 'long long',
    'signed', 'signed char', 'signed short', 'signed int', 'signed long',
    'ssize_t', 'ptrdiff_t', 'loff_t',
})

_UNSIGNED_TYPES = frozenset({
    'u8', '__u8', 'u16', '__u16', 'u32', '__u32', 'u64', '__u64',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'unsigned', 'unsigned char', 'unsigned short', 'unsigned int',
    'unsigned long', 'unsigned long long', 'size_t',
    '__le16', '__le32', '__le64', '__be16', '__be32', '__be64',
})

# Helpers whose return value cannot be negative.  A signed local fed only by
# these needs no floor, however it was declared — `int len = strnlen(p, n);`
# is the dominant shape, and without this every `if (len >= n) return;` in the
# tree reports upper-bound-only-signed.  strscpy() and friends are absent on
# purpose: they return -E2BIG.
_NONNEG_CALLS = frozenset({
    'strlen', 'strnlen', 'ARRAY_SIZE', 'strcspn', 'strspn',
})

# found=False carries a kind explaining *why* the guard that is present does not
# count, which is more actionable than the bare "unguarded" it replaces.
Guard = namedtuple('Guard', 'found kind')

_NO_GUARD = Guard(False, '')
_GUARDED  = Guard(True, 'bounded')


def _build_local_signed(fn_body, source):
    """
    Integer locals declared with a signed type.  Capping such a variable from
    above leaves the negative half open, and a subscript or length that consumes
    it converts to size_t.

    Bare `char` is left out: its signedness is arch-dependent (signed on x86,
    unsigned on arm64), so neither answer is right tree-wide.  Names declared
    twice with conflicting signedness are dropped, as in `_build_local_widths`.
    """
    seen = {}
    for n in _walk(fn_body):
        if n.type != 'declaration':
            continue
        type_node = n.child_by_field_name('type')
        if type_node is None:
            continue
        is_signed = node_text(type_node, source).strip() in _SIGNED_TYPES
        for child in n.children:
            decl = child.children[0] if (child.type == 'init_declarator'
                                         and child.children) else child
            if decl is None or decl.type != 'identifier':
                continue
            seen.setdefault(node_text(decl, source), set()).add(is_signed)
    widths = _build_local_widths(fn_body, source)
    unsigned = _build_local_unsigned(fn_body, source)
    return {name for name, vals in seen.items()
            if vals == {True}
            and not _only_nonneg_sources(fn_body, name, source,
                                         widths.get(name), unsigned)}


def _build_local_unsigned(fn_body, source):
    """{name: bit width} for integer locals declared with an unsigned type."""
    out, conflict = {}, set()
    for n in _walk(fn_body):
        if n.type != 'declaration':
            continue
        type_node = n.child_by_field_name('type')
        if type_node is None:
            continue
        t = node_text(type_node, source).strip()
        if t not in _UNSIGNED_TYPES:
            continue
        w = _get_type_width(t)
        if w is None:
            continue
        for child in n.children:
            decl = child.children[0] if (child.type == 'init_declarator'
                                         and child.children) else child
            if decl is None or decl.type != 'identifier':
                continue
            nm = node_text(decl, source)
            if out.get(nm, w) != w:
                conflict.add(nm)
            out[nm] = w
    for nm in conflict:
        out.pop(nm, None)
    return out


def _max_bits(node, source, unsigned, budget):
    """
    Upper bound on how many bits the expression's value can occupy, or None
    when nothing local settles it.  Only the shapes that actually produce
    provably non-negative values in parsers are modelled — a 16-bit field
    widened into an int, a mask, a right shift of an unsigned.
    """
    if node is None:
        return None
    t = node.type
    if t == 'parenthesized_expression':
        inner = [c for c in node.children if c.is_named]
        return _max_bits(inner[0], source, unsigned, budget) if inner else None
    if t == 'sizeof_expression':
        return 16
    if t == 'number_literal':
        try:
            return int(node_text(node, source).rstrip('uUlL'), 0).bit_length()
        except ValueError:
            return None
    if t == 'identifier':
        return unsigned.get(node_text(node, source))
    if t == 'cast_expression':
        ct = node.child_by_field_name('type')
        cw = _get_type_width(node_text(ct, source)) if ct is not None else None
        if ct is not None and node_text(ct, source).strip() in _UNSIGNED_TYPES:
            return cw
        return None
    if t == 'call_expression':
        fname = node_text(node.child_by_field_name('function'), source)
        if fname in _NONNEG_CALLS:
            return budget           # accepted by fiat, as before
        return TAINT_SOURCE_WIDTHS.get(fname)
    if t == 'binary_expression' and len(node.children) >= 3:
        op = node_text(node.children[1], source)
        lhs = _max_bits(node.children[0], source, unsigned, budget)
        rhs = _max_bits(node.children[2], source, unsigned, budget)
        if op == '&':
            vals = [v for v in (lhs, rhs) if v is not None]
            return min(vals) if vals else None
        if op == '>>':
            try:
                shift = int(node_text(node.children[2], source).rstrip('uUlL'), 0)
            except ValueError:
                return None
            return max(0, lhs - shift) if lhs is not None else None
        if op in ('|', '^'):
            return max(lhs, rhs) if (lhs is not None and rhs is not None) else None
    return None


def _only_nonneg_sources(fn_body, name, source, width=None, unsigned=None):
    """
    True if every value `name` takes in this body provably clears the sign bit.
    A compound assignment or a ++/-- disqualifies it: `len -= hdr` reopens the
    negative half regardless of where len started.

    With the declared width known, an expression qualifies when its range fits
    in width-1 bits, which is what makes `int pin = le16_to_cpu(...)` and
    `int length = type_len >> 8` (u32) safe.  Just under half of this rule's
    tree-wide hits were one of those two.  Without a width only the
    _NONNEG_CALLS/sizeof forms qualify.
    """
    budget = None if width is None else width - 1
    unsigned = unsigned or {}
    found_one = False
    for n in _walk(fn_body):
        if n.type == 'update_expression':
            if _names_in(n, source) == {name}:
                return False
            continue
        if n.type == 'init_declarator':
            decl, rhs = n.child_by_field_name('declarator'), n.child_by_field_name('value')
        elif n.type == 'assignment_expression':
            decl, rhs = n.child_by_field_name('left'), n.child_by_field_name('right')
            if node_text(n.children[1], source) != '=':
                if decl is not None and node_text(decl, source) == name:
                    return False
                continue
        else:
            continue
        if decl is None or rhs is None or node_text(decl, source) != name:
            continue
        if budget is None:
            if not (rhs.type == 'sizeof_expression'
                    or (rhs.type == 'call_expression'
                        and node_text(rhs.child_by_field_name('function'), source)
                            in _NONNEG_CALLS)):
                return False
        else:
            bits = _max_bits(rhs, source, unsigned, budget)
            if bits is None or bits > budget:
                return False
        found_one = True
    return found_one


def _names_in(node, source):
    return {node_text(n, source) for n in _walk(node) if n.type == 'identifier'}


def _walk_operand(node):
    """
    _walk without descending into call arguments.  A variable handed to a
    function is not what the enclosing comparison compares: `memcmp(a, p, n)
    == 0` tests memcmp's result, so crediting it as a bounds check on `p` is
    what `if (memcmp(ea_name, temp_ptr, name_len) == 0)` did in CIFSSMBQAllEAs.
    Conditions wrapped in `unlikely()`/`WARN_ON()` are unaffected — the
    comparison is found by the caller's full walk, and only its operands come
    through here.
    """
    yield node
    for child in node.children:
        if child.type == 'argument_list':
            continue
        yield from _walk_operand(child)


def _names_in_operand(node, source):
    return {node_text(n, source)
            for n in _walk_operand(node) if n.type == 'identifier'}


def _names_compared(node, source):
    """
    The names an operand actually constrains.  A variable reached only as the
    base of a field access is not one: `if (rsp->ByteCount < 8)` bounds the
    field, not the pointer a sink then offsets from — `ldm_frag_add()` gates
    `memcpy(f->data + VBLK_SIZE_HEAD + rec * size, ...)` on `rec >= f->num`,
    which says nothing about `f`.  Kept separate from _names_in_operand so
    _in_arithmetic still sees `f->data + n` as an adjustment of `f`.
    """
    out = set()
    for n in _walk_operand(node):
        if n.type != 'identifier':
            continue
        p = n.parent
        if p is not None and p.type == 'field_expression':
            base = p.child_by_field_name('argument')
            if base is not None and base.id == n.id:
                continue
        out.add(node_text(n, source))
    return out


def _in_arithmetic(node, var_names, source):
    """True if any of var_names appears inside an additive/scaling expression."""
    if node is None:
        return False
    for n in _walk(node):
        if (n.type == 'binary_expression' and len(n.children) >= 3
                and n.children[1].type in _ARITH_OPS
                and (_names_in_operand(n, source) & var_names)):
            return True
    return False


def _has_unsigned_cast(node, source):
    for n in _walk(node):
        if n.type != 'cast_expression':
            continue
        t = n.child_by_field_name('type')
        if t is not None and node_text(t, source).strip() in _UNSIGNED_TYPES:
            return True
    return False


def _comparisons_on(cond, var_names, source):
    """
    Every relational comparison in `cond` that mentions one of var_names, as
    (op, var_is_left_operand, var_appears_in_arithmetic, cast_to_unsigned).
    """
    out = []
    for n in _walk(cond):
        if n.type != 'binary_expression' or len(n.children) < 3:
            continue
        op = n.children[1].type
        if op not in _GUARD_CMP_OPS:
            continue
        left, right = n.children[0], n.children[2]
        on_left = bool(_names_compared(left, source) & var_names)
        if not on_left and not (_names_compared(right, source) & var_names):
            continue
        side = left if on_left else right
        out.append((op, on_left,
                    _in_arithmetic(side, var_names, source),
                    _has_unsigned_cast(n, source)))
    return out


def _label_lines(fn_body, source):
    lines = {}
    for n in _walk(fn_body):
        if n.type == 'labeled_statement':
            lab = n.child_by_field_name('label')
            if lab is not None:
                lines.setdefault(node_text(lab, source), n.start_point[0] + 1)
    return lines


def _has_terminal(subtree, source, label_lines=None, line_hi=None):
    """
    Whether the branch leaves before reaching the use at line_hi.

    `goto` only qualifies if its label sits past the use.  cifs error handling
    is built on `goto out`, and the label is almost always below, but the
    backward-jump and fall-through-to-the-sink forms otherwise read as clean
    exits.  An unresolvable label is credited, keeping a parse gap from turning
    into a wave of findings.
    """
    for n in _walk(subtree):
        if n.type == 'goto_statement':
            if label_lines is None or line_hi is None:
                return True
            lab = n.child_by_field_name('label')
            target = label_lines.get(node_text(lab, source)) if lab is not None else None
            if target is None or target > line_hi:
                return True
            continue
        if n.type in _GUARD_TERM_STMTS:
            return True
        if n.type == 'call_expression':
            fn_id = next((c for c in n.children if c.type == 'identifier'), None)
            if fn_id and node_text(fn_id, source) in _GUARD_TERM_CALLS:
                return True
    return False


def _find_guards_between(fn_body, var_names, line_lo, line_hi, source,
                         signed_vars=frozenset(), sink_expr=None):
    """
    Whether a bounds check on any of var_names between line_lo and line_hi
    actually covers the use at line_hi.

    A candidate guard is an `if` in range whose condition relationally compares
    one of var_names, and which gates the use — either the branch exits
    (return/goto/break/continue/BUG/panic), or line_hi falls inside it.  Bare
    zero-tests do not qualify.

    Two ways a candidate can be present and still not answer the question:

    `covers-base-not-offset` — the sink applies arithmetic to the variable and
    no guard does.  `if (off > total) return;` followed by `data[off + 1]` is
    off by exactly the adjustment the guard never saw.

    `upper-bound-only-signed` — the variable is declared signed and every guard
    pins only its ceiling.  `if (i > 7) return;` then `table[i]` admits every
    negative value, which the subscript converts to size_t.  An unsigned
    variable needs no floor, so this applies to `signed_vars` alone; a cast to
    an unsigned type inside the comparison supplies both ends at once, which is
    the `(unsigned)i >= n` idiom.  `_build_local_signed` also withholds locals
    that only ever hold a non-negative call result, which is where nearly all of
    this rule's noise came from.

    Direction is read off the *falling-through* path, so early-exit conditions
    are inverted before classification: `if (i < 0) return;` establishes a
    floor, while `if (i < n) { use }` establishes a ceiling.
    """
    if not var_names:
        return _NO_GUARD

    adjusted = _in_arithmetic(sink_expr, var_names, source)
    bounds = set()
    found_any = False
    guard_saw_adjustment = False
    labels = None          # built on first candidate; most calls never need it

    for node in _walk(fn_body):
        if node.type != 'if_statement':
            continue
        stmt_line = node.start_point[0] + 1
        if stmt_line <= line_lo or stmt_line >= line_hi:
            continue

        cond = node.child_by_field_name('condition')
        if cond is None:
            continue
        cmps = _comparisons_on(cond, var_names, source)
        if not cmps:
            continue

        consequence = node.child_by_field_name('consequence')
        alternative = node.child_by_field_name('alternative')

        if labels is None:
            labels = _label_lines(fn_body, source)
        early = ((consequence is not None
                  and _has_terminal(consequence, source, labels, line_hi))
                 or (alternative is not None
                     and _has_terminal(alternative, source, labels, line_hi)))
        encloses = any(b is not None
                       and b.start_point[0] + 1 <= line_hi <= b.end_point[0] + 1
                       for b in (consequence, alternative))
        if not (early or encloses):
            continue

        found_any = True
        for op, on_left, in_arith, unsigned_cast in cmps:
            if in_arith:
                guard_saw_adjustment = True
            if unsigned_cast:
                bounds |= {'upper', 'lower'}
                continue
            if op in ('==', '!='):
                # `if (i == K) { use }` and `if (i != K) return;` both leave one
                # value; the other pairings leave the range open.
                if (op == '==') != early:
                    bounds |= {'upper', 'lower'}
                continue
            direction = _BOUND_FOR_LEFT[op]
            if not on_left:
                direction = _FLIP[direction]
            bounds.add(_FLIP[direction] if early else direction)

    if not found_any:
        return _NO_GUARD
    if adjusted and not guard_saw_adjustment:
        return Guard(False, 'covers-base-not-offset')
    if bounds == {'upper'} and (var_names & signed_vars):
        return Guard(False, 'upper-bound-only-signed')
    return _GUARDED


def _find_string_guard(fn_body, var_name, line_lo, line_hi, source):
    """
    Return True if a safe bounded-length call (strnlen, memchr, memchr_inv)
    on var_name appears between line_lo and line_hi.

    These are the only constructs that establish a null-termination guarantee
    without unbounded scanning; a strnlen() result stored and compared is
    sufficient even if not paired with a return.
    """
    for node in _walk(fn_body):
        if node.type != 'call_expression':
            continue
        call_line = node.start_point[0] + 1
        if call_line <= line_lo or call_line >= line_hi:
            continue
        fn_id = next((c for c in node.children if c.type == 'identifier'), None)
        if fn_id is None or node_text(fn_id, source) not in _STRING_SAFE_CALLS:
            continue
        args = _arg_nodes(node)
        if not args:
            continue
        # var_name must appear in the first argument (possibly through a cast)
        for n in _walk(args[0]):
            if n.type == 'identifier' and node_text(n, source) == var_name:
                return True
    return False


# ---------------------------------------------------------------------------
# Core taint walk (shared by intra and cross-function modes)
# ---------------------------------------------------------------------------

def _scan_body(fn_name, fn_body, source, filepath, initial_taint=None):
    """
    Core taint walk for one function body.

    initial_taint: optional {var_name: {'source_fn', 'line', 'kind'}} to pre-seed
        the taint state.  Used by cross-function Phase 1 (parameter simulation):
        treat a specific parameter as if it were tainted on entry.

    Returns:
        findings  — list of finding dicts (same schema as scan_function)
        call_events — list of {callee, line, call_snippet, tainted_args}
            for every call_expression that received at least one tainted argument.
            Used by cross-function Phase 2 to identify dangerous call sites.
    """
    tainted = dict(initial_taint) if initial_taint else {}
    findings = []
    call_events = []

    # Pre-build integer width map for Cat H narrowing detection.
    var_widths = _build_local_widths(fn_body, source)
    signed_vars = _build_local_signed(fn_body, source)

    for node in _walk(fn_body):

        # ── Category H: type-width narrowing in declarations ──
        # Handled here (on declaration, not init_declarator) so we have the
        # declared type of the LHS without needing a parent-node lookup.
        if node.type == 'declaration':
            type_node = node.child_by_field_name('type')
            if type_node is None:
                continue
            dest_type = node_text(type_node, source)
            dest_width = _get_type_width(dest_type)
            if dest_width is None:
                continue
            for child in node.children:
                if child.type != 'init_declarator' or len(child.children) < 3:
                    continue
                decl_node = child.children[0]
                if decl_node.type != 'identifier':
                    continue   # pointer declarator — skip
                dest_var = node_text(decl_node, source)
                rhs = child.children[2]
                line = child.start_point[0] + 1

                src_fn_h = _node_has_taint_source_call(rhs, source)
                src_width_h = TAINT_SOURCE_WIDTHS.get(src_fn_h) if src_fn_h else None
                ref_h = None
                if src_fn_h is None:
                    ref_h = _node_references_tainted_var(rhs, source, tainted)
                    if ref_h:
                        src_fn_h = tainted[ref_h]['source_fn']
                        src_width_h = tainted[ref_h].get('width')

                if src_fn_h and src_width_h and src_width_h > dest_width:
                    guard_vars = {ref_h} if ref_h else set()
                    taint_ln = tainted[ref_h]['line'] if ref_h else line
                    guarded_h = _find_guards_between(
                        fn_body, guard_vars, taint_ln, line, source,
                        signed_vars,
                    ) if guard_vars and taint_ln < line else _NO_GUARD
                    snippet = get_source_line(source, line)
                    findings.append({
                        'function':        fn_name,
                        'file':            str(filepath),
                        'category':        'H',
                        'severity':        'medium',
                        'taint_source_fn': src_fn_h,
                        'tainted_var':     dest_var,
                        'taint_line':      line,
                        'taint_snippet':   snippet,
                        'sink_fn':         'narrowing_assignment',
                        'sink_line':       line,
                        'sink_snippet':    snippet,
                        'sink_arg_index':  0,
                        'sink_arg_role':   'narrowed_value',
                        'src_width':       src_width_h,
                        'dest_width':      dest_width,
                        'dest_type':       dest_type,
                        'possibly_guarded': guarded_h.found,
                        'guard_kind':       guarded_h.kind,
                        'reason': (
                            f"{src_width_h}-bit value from {src_fn_h}() silently "
                            f"truncated to {dest_width}-bit {dest_type} in {dest_var!r}; "
                            f"a later bounds check on {dest_var!r} may pass even when "
                            f"the original value would not"
                        ),
                    })
            continue   # skip the rest of the loop body for declaration nodes

        # ── Taint source: direct assignment or init with taint source in RHS ──
        if node.type in ('assignment_expression', 'init_declarator'):
            children = node.children
            if len(children) < 3:
                continue
            assign_op = children[1].type
            is_merge = assign_op in _COMPOUND_ASSIGN_OPS
            if assign_op != '=' and not is_merge:
                continue
            rhs = children[2]
            lhs_var = _extract_lhs_var(node, source)
            if lhs_var is None:
                continue

            prev = tainted.get(lhs_var) if is_merge else None

            src_fn = _node_has_taint_source_call(rhs, source)
            if src_fn:
                width = TAINT_SOURCE_WIDTHS.get(src_fn)
                if is_merge:
                    kind = _merged_kind(lhs_var, prev, assign_op, var_widths)
                    # The accumulator's own type bounds the value, not the
                    # source's; otherwise Cat H fires on every u16 += u32 read.
                    width = var_widths.get(lhs_var, width)
                else:
                    kind = 'pointer' if _rhs_has_additive_arith(rhs) else 'value'
                tainted[lhs_var] = {
                    # An already-tainted accumulator keeps its first contact
                    # with server data as the reported origin.
                    'source_fn': prev['source_fn'] if prev else src_fn,
                    'line': prev['line'] if prev else node.start_point[0] + 1,
                    'kind': kind,
                    'width': width,
                }
                # Cat H: assignment_expression narrowing (not init_declarator —
                # that case is handled in the declaration branch above).  A
                # compound assignment is an accumulation, not a truncating
                # store; its overflow belongs to the integer-wrap check, and
                # treating it as Cat H fires on every `u16 acc += le32_to_cpu()`.
                if (node.type == 'assignment_expression' and not is_merge
                        and lhs_var in var_widths):
                    dest_width_h = var_widths[lhs_var]
                    src_width_h = TAINT_SOURCE_WIDTHS.get(src_fn)
                    if src_width_h and src_width_h > dest_width_h:
                        line_h = node.start_point[0] + 1
                        snippet_h = get_source_line(source, line_h)
                        findings.append({
                            'function':        fn_name,
                            'file':            str(filepath),
                            'category':        'H',
                            'severity':        'medium',
                            'taint_source_fn': src_fn,
                            'tainted_var':     lhs_var,
                            'taint_line':      line_h,
                            'taint_snippet':   snippet_h,
                            'sink_fn':         'narrowing_assignment',
                            'sink_line':       line_h,
                            'sink_snippet':    snippet_h,
                            'sink_arg_index':  0,
                            'sink_arg_role':   'narrowed_value',
                            'src_width':       src_width_h,
                            'dest_width':      dest_width_h,
                            'dest_type':       f'u{dest_width_h}',
                            'possibly_guarded': False,
                            'reason': (
                                f"{src_width_h}-bit value from {src_fn}() silently "
                                f"truncated to {dest_width_h}-bit {lhs_var!r}; "
                                f"a later bounds check on {lhs_var!r} may pass even "
                                f"when the original value would not"
                            ),
                        })
                continue

            ref = _node_references_tainted_var(rhs, source, tainted)
            if ref:
                ref_kind = tainted[ref]['kind']
                width = tainted[ref].get('width')   # propagate source width
                if is_merge:
                    kind = _merged_kind(lhs_var, prev, assign_op, var_widths)
                    width = var_widths.get(lhs_var, width)
                else:
                    kind = 'pointer' if (
                        _rhs_has_additive_arith(rhs) or ref_kind == 'pointer'
                    ) else 'value'
                origin = prev or tainted[ref]
                tainted[lhs_var] = {
                    'source_fn': origin['source_fn'],
                    'line': origin['line'],   # keep the original source line
                    'kind': kind,
                    'width': width,
                }
                # Cat H: narrowing via tainted variable (assignment_expression only;
                # see the note above for why compound assignments are excluded)
                if (node.type == 'assignment_expression' and not is_merge
                        and lhs_var in var_widths):
                    dest_width_h = var_widths[lhs_var]
                    src_width_h = tainted[ref].get('width')
                    if src_width_h and src_width_h > dest_width_h:
                        line_h = node.start_point[0] + 1
                        src_fn_h = tainted[ref]['source_fn']
                        snippet_h = get_source_line(source, line_h)
                        taint_ln_h = tainted[ref]['line']
                        guarded_h = _find_guards_between(
                            fn_body, {ref}, taint_ln_h, line_h, source,
                            signed_vars,
                        ) if taint_ln_h < line_h else _NO_GUARD
                        findings.append({
                            'function':        fn_name,
                            'file':            str(filepath),
                            'category':        'H',
                            'severity':        'medium',
                            'taint_source_fn': src_fn_h,
                            'tainted_var':     lhs_var,
                            'taint_line':      line_h,
                            'taint_snippet':   snippet_h,
                            'sink_fn':         'narrowing_assignment',
                            'sink_line':       line_h,
                            'sink_snippet':    snippet_h,
                            'sink_arg_index':  0,
                            'sink_arg_role':   'narrowed_value',
                            'src_width':       src_width_h,
                            'dest_width':      dest_width_h,
                            'dest_type':       f'u{dest_width_h}',
                            'possibly_guarded': guarded_h.found,
                            'guard_kind':       guarded_h.kind,
                            'reason': (
                                f"{src_width_h}-bit value (via {ref!r}, from "
                                f"{src_fn_h}()) silently truncated to "
                                f"{dest_width_h}-bit {lhs_var!r}; a later bounds "
                                f"check on {lhs_var!r} may pass even when the "
                                f"original value would not"
                            ),
                        })

        # ── Sink / call site ──
        elif node.type == 'call_expression':
            fn_id = next((c for c in node.children if c.type == 'identifier'), None)
            if not fn_id:
                continue
            callee = node_text(fn_id, source)
            args = _arg_nodes(node)
            call_line = node.start_point[0] + 1

            # Emit call event for any call with tainted arguments; used by
            # cross-function Phase 2 to match against param_sink_map.
            t_args = _collect_tainted_args(args, source, tainted, call_line)
            if t_args:
                call_events.append({
                    'callee': callee,
                    'line': call_line,
                    'call_snippet': get_source_line(source, call_line),
                    'tainted_args': t_args,
                })

            # ── Category D: strlen / strlcpy on server-supplied buffer ──
            #
            # Must run BEFORE the `if not sink_info` guard so functions that
            # are not in DANGEROUS_SINKS (strlen, strcat, strdup, kstrdup) are
            # still checked.  strlcpy IS in DANGEROUS_SINKS (size arg), but
            # we additionally flag its source arg here.
            d_arg_idx = _STRING_UNSAFE_SINKS.get(callee)
            if d_arg_idx is not None and d_arg_idx < len(args):
                d_arg = args[d_arg_idx]
                d_ref = _node_references_tainted_var(d_arg, source, tainted)
                if d_ref and tainted[d_ref]['kind'] == 'pointer':
                    d_info = tainted[d_ref]
                    d_taint_line = d_info['line']
                    if d_taint_line < call_line:
                        d_guarded = _find_string_guard(
                            fn_body, d_ref, d_taint_line, call_line, source,
                        )
                        findings.append({
                            'function':        fn_name,
                            'file':            str(filepath),
                            'category':        'D',
                            'severity':        'high',
                            'taint_source_fn': d_info['source_fn'],
                            'tainted_var':     d_ref,
                            'taint_line':      d_taint_line,
                            'taint_snippet':   get_source_line(source, d_taint_line),
                            'sink_fn':         callee,
                            'sink_line':       call_line,
                            'sink_snippet':    get_source_line(source, call_line),
                            'sink_arg_index':  d_arg_idx,
                            'sink_arg_role':   'string_arg',
                            'possibly_guarded': d_guarded,
                            'reason': (
                                f"pointer {d_ref!r} derived from "
                                f"{d_info['source_fn']}() offset arithmetic "
                                f"passed to {callee}() (arg {d_arg_idx}) without "
                                f"a prior strnlen() or memchr() to verify null "
                                f"termination within packet bounds"
                            ),
                        })

            sink_info = DANGEROUS_SINKS.get(callee)
            if not sink_info:
                continue

            sink_fn = callee
            sink_line = call_line
            sink_snippet = get_source_line(source, sink_line)

            # Check size arguments (Category B)
            for idx in sink_info.get('size_args', []):
                if idx >= len(args):
                    continue
                arg = args[idx]
                role = ('count' if sink_info.get('is_counted') and
                        idx == sink_info['size_args'][0] else 'size')

                src_fn = _node_has_taint_source_call(arg, source)
                tainted_var = None
                taint_line = sink_line

                if src_fn:
                    tainted_var = node_text(arg, source)[:40]
                    taint_line = sink_line
                else:
                    ref = _node_references_tainted_var(arg, source, tainted)
                    if ref:
                        src_fn = tainted[ref]['source_fn']
                        tainted_var = ref
                        taint_line = tainted[ref]['line']

                if src_fn:
                    guarded = _find_guards_between(
                        fn_body, {tainted_var} if tainted_var else set(),
                        taint_line, sink_line, source,
                        signed_vars, sink_expr=arg,
                    )
                    findings.append({
                        'function': fn_name,
                        'file': str(filepath),
                        'category': 'B',
                        'severity': 'high',
                        'taint_source_fn': src_fn,
                        'tainted_var': tainted_var or '(inline)',
                        'taint_line': taint_line,
                        'taint_snippet': get_source_line(source, taint_line),
                        'sink_fn': sink_fn,
                        'sink_line': sink_line,
                        'sink_snippet': sink_snippet,
                        'sink_arg_index': idx,
                        'sink_arg_role': role,
                        'possibly_guarded': guarded.found,
                        'guard_kind':       guarded.kind,
                        'reason': (
                            f"server-supplied value from {src_fn}() used as {role} "
                            f"argument {idx} to {sink_fn}() without bounds check"
                        ),
                    })

            # Integer overflow check: tainted value in multiplicative/additive
            # size expression (e.g., kmalloc(count * sizeof(foo))).
            # Emits a separate 'size_mul_overflow' finding; the dedup pass at
            # the end of _scan_body suppresses the redundant plain Cat B for
            # the same (sink_fn, sink_line, arg_idx).
            for idx in sink_info.get('size_args', []):
                if idx >= len(args):
                    continue
                for hit in _find_overflow_in_size_arg(args[idx], source, tainted):
                    # No sink_expr: the arithmetic here is the finding, so
                    # covers-base-not-offset would fire on every one and say
                    # nothing the overflow flag does not already say.
                    guarded = _find_guards_between(
                        fn_body, {hit['tainted_var']},
                        hit['taint_line'], sink_line, source,
                        signed_vars,
                    )
                    op_word = 'multiplication' if hit['op'] == '*' else 'addition'
                    findings.append({
                        'function':        fn_name,
                        'file':            str(filepath),
                        'category':        'B',
                        'severity':        'high',
                        'overflow':        True,
                        'overflow_op':     hit['op'],
                        'overflow_lhs':    hit['lhs_text'],
                        'overflow_rhs':    hit['rhs_text'],
                        'taint_source_fn': hit['taint_source'],
                        'tainted_var':     hit['tainted_var'],
                        'taint_line':      hit['taint_line'],
                        'taint_snippet':   get_source_line(source, hit['taint_line']),
                        'sink_fn':         sink_fn,
                        'sink_line':       sink_line,
                        'sink_snippet':    sink_snippet,
                        'sink_arg_index':  idx,
                        'sink_arg_role':   'size_mul_overflow',
                        'possibly_guarded': guarded.found,
                        'guard_kind':       guarded.kind,
                        'reason': (
                            f"integer overflow risk: {hit['lhs_text']} {hit['op']} "
                            f"{hit['rhs_text']} passed as size to {sink_fn}(); "
                            f"tainted {hit['tainted_var']} (from {hit['taint_source']}()) "
                            f"could cause {op_word} to wrap, producing an undersized "
                            f"allocation — use kmalloc_array() or check_mul_overflow()"
                        ),
                    })

            # Check pointer arguments (Category A)
            for idx in sink_info.get('ptr_args', []):
                if idx >= len(args):
                    continue
                arg = args[idx]
                ref = _node_references_tainted_var(arg, source, tainted)
                if not ref:
                    continue
                info = tainted[ref]
                if info['kind'] != 'pointer':
                    continue  # Only flag pointer-tainted values as ptr args
                taint_line = info['line']
                guarded = _find_guards_between(
                    fn_body, {ref}, taint_line, sink_line, source,
                    signed_vars, sink_expr=arg,
                )
                findings.append({
                    'function': fn_name,
                    'file': str(filepath),
                    'category': 'A',
                    'severity': 'high',
                    'taint_source_fn': info['source_fn'],
                    'tainted_var': ref,
                    'taint_line': taint_line,
                    'taint_snippet': get_source_line(source, taint_line),
                    'sink_fn': sink_fn,
                    'sink_line': sink_line,
                    'sink_snippet': sink_snippet,
                    'sink_arg_index': idx,
                    'sink_arg_role': 'pointer',
                    'possibly_guarded': guarded.found,
                    'guard_kind':       guarded.kind,
                    'reason': (
                        f"pointer derived from server-supplied {info['source_fn']}() "
                        f"used as pointer argument {idx} to {sink_fn}() "
                        f"without bounds check"
                    ),
                })

        # ── Category F: loop with server-supplied iteration bound ──
        elif node.type in ('for_statement', 'while_statement', 'do_statement'):
            cond = node.child_by_field_name('condition')
            if cond is None:
                continue

            loop_line = node.start_point[0] + 1
            src_fn = ref = None
            taint_line = loop_line

            # Walk condition for a relational comparison (< <= > >=) that
            # involves a tainted variable.  Equality checks (== !=) are state
            # tests, not iteration bounds — skip them.
            for n in _walk(cond):
                if n.type != 'binary_expression':
                    continue
                if not any(c.type in ('<', '<=', '>', '>=') for c in n.children):
                    continue
                ref = _node_references_tainted_var(n, source, tainted)
                if ref:
                    src_fn = tainted[ref]['source_fn']
                    taint_line = tainted[ref]['line']
                    break
                src_fn = _node_has_taint_source_call(n, source)
                if src_fn:
                    break

            if src_fn is None:
                continue

            tainted_var_name = ref or '(inline)'
            loop_type = {
                'for_statement':   'for_loop',
                'while_statement': 'while_loop',
                'do_statement':    'do_loop',
            }[node.type]

            sink_line = loop_line
            sink_snippet = get_source_line(source, sink_line)
            guarded = _find_guards_between(
                fn_body, {ref} if ref else set(),
                taint_line, sink_line, source,
                signed_vars, sink_expr=node.child_by_field_name('condition'),
            )
            findings.append({
                'function':        fn_name,
                'file':            str(filepath),
                'category':        'F',
                'severity':        'medium',
                'taint_source_fn': src_fn,
                'tainted_var':     tainted_var_name,
                'taint_line':      taint_line,
                'taint_snippet':   get_source_line(source, taint_line),
                'sink_fn':         loop_type,
                'sink_line':       sink_line,
                'sink_snippet':    sink_snippet,
                'sink_arg_index':  0,
                'sink_arg_role':   'loop_bound',
                'possibly_guarded': guarded.found,
                'guard_kind':       guarded.kind,
                'reason': (
                    f"server-supplied value {tainted_var_name!r} "
                    f"(from {src_fn}()) controls loop iteration count "
                    f"without validation against buffer size"
                ),
            })

        # ── Category E: dereference of pointer derived from server offset ──
        #
        # Pattern: offset = le32_to_cpu(hdr->Off); ptr = base + offset; ptr->field
        # The ptr variable is tracked as kind='pointer'.  Accessing struct fields
        # through it without first verifying offset + sizeof(*ptr) <= pkt_end is
        # an OOB read.
        #
        # Only flags named pointer variables (kind='pointer' in tainted), not
        # inline cast expressions — those are a known gap for a future follow-up.
        elif node.type == 'field_expression':
            if not any(c.type == '->' for c in node.children):
                continue   # .field on a value type — safe

            arg = node.child_by_field_name('argument')
            if arg is None:
                continue

            ref = _node_references_tainted_var(arg, source, tainted)
            if not ref or tainted[ref]['kind'] != 'pointer':
                continue

            info = tainted[ref]
            taint_line = info['line']
            sink_line = node.start_point[0] + 1
            if taint_line >= sink_line:
                continue

            fld_node = node.child_by_field_name('field')
            field_name = node_text(fld_node, source) if fld_node else '?'
            sink_snippet = get_source_line(source, sink_line)
            guarded = _find_guards_between(
                fn_body, {ref}, taint_line, sink_line, source,
                signed_vars, sink_expr=arg,
            )
            findings.append({
                'function':        fn_name,
                'file':            str(filepath),
                'category':        'E',
                'severity':        'high',
                'taint_source_fn': info['source_fn'],
                'tainted_var':     ref,
                'taint_line':      taint_line,
                'taint_snippet':   get_source_line(source, taint_line),
                'sink_fn':         'ptr_deref',
                'sink_line':       sink_line,
                'sink_snippet':    sink_snippet,
                'sink_arg_index':  0,
                'sink_arg_role':   'tainted_ptr_deref',
                'field_name':      field_name,
                'possibly_guarded': guarded.found,
                'guard_kind':       guarded.kind,
                'reason': (
                    f"pointer {ref!r} derived from {info['source_fn']}() offset "
                    f"arithmetic used without verifying offset + sizeof(*{ref}) "
                    f"<= packet_end; {ref}->{field_name} may read beyond packet bounds"
                ),
            })

        # ── Category C: array subscript with tainted index ──
        elif node.type == _SUBSCRIPT_NODE:
            # subscript_expression: [array, '[', index, ']']
            idx_node = next(
                (c for c in node.children if c.type not in ('[', ']') and
                 c != node.children[0]),
                None,
            )
            if idx_node is None:
                continue

            src_fn = _node_has_taint_source_call(idx_node, source)
            ref = None
            taint_line = node.start_point[0] + 1

            if src_fn:
                pass  # direct taint source inline in subscript
            else:
                ref = _node_references_tainted_var(idx_node, source, tainted)
                if ref:
                    src_fn = tainted[ref]['source_fn']
                    taint_line = tainted[ref]['line']

            if not src_fn:
                continue

            sink_line = node.start_point[0] + 1
            sink_snippet = get_source_line(source, sink_line)
            guarded = _find_guards_between(
                fn_body, {ref} if ref else set(),
                taint_line, sink_line, source,
                signed_vars, sink_expr=idx_node,
            )
            findings.append({
                'function': fn_name,
                'file': str(filepath),
                'category': 'C',
                'severity': 'high',
                'taint_source_fn': src_fn,
                'tainted_var': ref or node_text(idx_node, source)[:40],
                'taint_line': taint_line,
                'taint_snippet': get_source_line(source, taint_line),
                'sink_fn': '[]',
                'sink_line': sink_line,
                'sink_snippet': sink_snippet,
                'sink_arg_index': 0,
                'sink_arg_role': 'subscript',
                'possibly_guarded': guarded.found,
                'guard_kind':       guarded.kind,
                'reason': (
                    f"server-supplied value from {src_fn}() used as array subscript "
                    f"without bounds check"
                ),
            })

    # Deduplicate and resolve conflicts between overflow and plain Cat B.
    # When an overflow finding and a plain Cat B cover the same
    # (function, sink_fn, sink_line, arg_idx), suppress the plain Cat B —
    # the overflow finding is more specific and has the right fix suggestion.
    overflow_locs = {
        (f['function'], f['sink_fn'], f['sink_line'], f['sink_arg_index'])
        for f in findings if f.get('overflow')
    }

    seen = set()
    unique = []
    for f in findings:
        loc = (f['function'], f['sink_fn'], f['sink_line'], f['sink_arg_index'])
        if (f['category'] == 'B' and not f.get('overflow') and
                f['sink_arg_role'] in ('size', 'count') and loc in overflow_locs):
            continue   # superseded by the more specific overflow finding
        key = (f['category'], f.get('sink_arg_role', ''), f['tainted_var'],
               f['sink_fn'], f['sink_line'])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique, call_events


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_function(fn_name, fn_def_node, fn_body, source, filepath):
    """
    Scan one function body for taint flows from TAINT_SOURCES to DANGEROUS_SINKS.

    Returns a list of finding dicts, one per (taint_source, sink) pair:
      {
        'function':        str,
        'file':            str,
        'category':        'A'|'B'|'C',
        'severity':        'high'|'medium',
        'taint_source_fn': str,      # e.g. 'get_unaligned_le16'
        'tainted_var':     str,      # variable name that carries the taint
        'taint_line':      int,
        'taint_snippet':   str,
        'sink_fn':         str,      # e.g. 'memcpy'
        'sink_line':       int,
        'sink_snippet':    str,
        'sink_arg_index':  int,      # which argument is tainted
        'sink_arg_role':   str,      # 'size', 'pointer', 'subscript', 'count'
        'possibly_guarded': bool,
        'guard_kind':      str,      # '' | 'bounded' | 'covers-base-not-offset'
                                     #    | 'upper-bound-only-signed'
        'reason':          str,
      }
    """
    findings, _ = _scan_body(fn_name, fn_body, source, filepath)
    return findings


def scan_files(source_paths, verbose=False):
    """
    Scan a list of source files and return all taint findings.

    Returns list of finding dicts (see scan_function for schema).
    """
    from kernel_analysis.parsers.c_parser import parse_file, find_functions

    all_findings = []
    for path in source_paths:
        try:
            tree, source = parse_file(path)
        except Exception as e:
            if verbose:
                print(f"  [skip {path}: {e}]")
            continue
        for fn in find_functions(tree, source):
            findings, _ = _scan_body(
                fn['name'], fn['body'], source, path
            )
            all_findings.extend(findings)

    return all_findings


# ---------------------------------------------------------------------------
# Categories G1 / G2: user-copy correctness
# ---------------------------------------------------------------------------

# Functions whose return value must be checked (returns bytes NOT copied; 0 = success).
_COPY_USER_FNS = frozenset({
    'copy_from_user', 'copy_to_user',
    '__copy_from_user', '__copy_to_user',
    'get_user', 'put_user',
    '__get_user', '__put_user',
    'clear_user',
})

# Explicit size-argument index for the copy functions that take one.
# get_user / put_user copy a single typed value — no explicit size arg.
_COPY_USER_SIZE_ARG = {
    'copy_from_user':   2,
    'copy_to_user':     2,
    '__copy_from_user': 2,
    '__copy_to_user':   2,
    'clear_user':       1,
}


def _g_get_callee(call_node, source):
    fn_child = call_node.child_by_field_name('function')
    if fn_child is None:
        return ''
    if fn_child.type == 'identifier':
        return node_text(fn_child, source)
    for n in _walk(fn_child):
        if n.type == 'identifier':
            return node_text(n, source)
    return ''


def _g1_retval_checked(fn_body, var_name, after_line, source):
    """
    Return True if var_name appears in a conditional check or return_statement
    anywhere in fn_body after after_line.  Heuristic: presence of the variable
    in any condition context is treated as a check.
    """
    _COND_TYPES = frozenset({
        'if_statement', 'while_statement', 'do_statement',
        'for_statement', 'conditional_expression',
    })
    for node in _walk(fn_body):
        if node.start_point[0] + 1 <= after_line:
            continue
        if node.type in _COND_TYPES:
            cond = node.child_by_field_name('condition')
            if cond:
                for n in _walk(cond):
                    if n.type == 'identifier' and node_text(n, source) == var_name:
                        return True
        elif node.type == 'return_statement':
            for n in _walk(node):
                if n.type == 'identifier' and node_text(n, source) == var_name:
                    return True
    return False


def _g2_size_identifiers(arg_node, source):
    """
    Return the set of variable-name identifiers in a size argument expression,
    skipping identifiers inside sizeof() subexpressions (type/field names) and
    numeric/character/string literals.  An empty set means the size is a
    compile-time constant and needs no runtime validation.
    """
    names = set()
    stack = [arg_node]
    while stack:
        n = stack.pop()
        if n.type == 'sizeof_expression':
            continue   # don't descend — contents are type names, not variables
        if n.type in ('number_literal', 'char_literal', 'string_literal'):
            continue
        if n.type == 'identifier':
            names.add(node_text(n, source))
        else:
            stack.extend(n.children)
    return names


def _scan_fn_copy_user(fn_body, fn_name, source, filepath, cats):
    """
    Scan one function for Category G1 (retval unchecked) and/or G2
    (unvalidated size argument).  cats is the active category set.
    """
    do_g1 = 'G1' in cats
    do_g2 = 'G2' in cats
    findings = []

    for node in _walk(fn_body):
        if node.type != 'call_expression':
            continue
        callee = _g_get_callee(node, source)
        if callee not in _COPY_USER_FNS:
            continue

        call_line    = node.start_point[0] + 1
        call_snippet = get_source_line(source, call_line)
        args         = _arg_nodes(node)
        parent       = node.parent
        if parent is None:
            continue

        # ── G1: return value not checked ─────────────────────────────────────
        if do_g1:
            g1_role = None
            g1_var  = ''

            if parent.type == 'expression_statement':
                # copy_from_user(...);  — return value discarded entirely
                g1_role = 'retval_discarded'

            elif parent.type == 'assignment_expression':
                # rc = copy_from_user(...);  — assigned in a statement
                gp = parent.parent
                if gp and gp.type == 'expression_statement':
                    lhs = parent.child_by_field_name('left')
                    if lhs is not None:
                        g1_var = node_text(lhs, source)
                        if not _g1_retval_checked(fn_body, g1_var, call_line, source):
                            g1_role = 'retval_unchecked'

            elif parent.type == 'init_declarator':
                # int rc = copy_from_user(...);
                decl = parent.child_by_field_name('declarator')
                if decl is not None:
                    while decl.type == 'pointer_declarator':
                        decl = decl.child_by_field_name('declarator') or decl
                        break
                    g1_var = node_text(decl, source)
                    if not _g1_retval_checked(fn_body, g1_var, call_line, source):
                        g1_role = 'retval_unchecked'
            # else: call is used directly in a condition or return → checked

            if g1_role == 'retval_discarded':
                findings.append({
                    'function':        fn_name,
                    'file':            str(filepath),
                    'category':        'G1',
                    'severity':        'medium',
                    'taint_source_fn': callee,
                    'tainted_var':     '',
                    'taint_line':      call_line,
                    'taint_snippet':   call_snippet,
                    'sink_fn':         callee,
                    'sink_line':       call_line,
                    'sink_snippet':    call_snippet,
                    'sink_arg_index':  -1,
                    'sink_arg_role':   'retval_discarded',
                    'possibly_guarded': False,
                    'propagation':     'intra',
                    'reason': (
                        f"{callee}() return value discarded — partial copy silently "
                        f"treated as success (returns bytes NOT copied; non-zero = fault)"
                    ),
                })

            elif g1_role == 'retval_unchecked':
                findings.append({
                    'function':        fn_name,
                    'file':            str(filepath),
                    'category':        'G1',
                    'severity':        'medium',
                    'taint_source_fn': callee,
                    'tainted_var':     g1_var,
                    'taint_line':      call_line,
                    'taint_snippet':   call_snippet,
                    'sink_fn':         callee,
                    'sink_line':       call_line,
                    'sink_snippet':    call_snippet,
                    'sink_arg_index':  -1,
                    'sink_arg_role':   'retval_unchecked',
                    'possibly_guarded': False,
                    'propagation':     'intra',
                    'reason': (
                        f"{g1_var} = {callee}() return value assigned but never "
                        f"checked against zero — partial copy silently treated as success"
                    ),
                })

        # ── G2: size argument not validated before use ────────────────────────
        if do_g2:
            size_idx = _COPY_USER_SIZE_ARG.get(callee)
            if size_idx is not None and size_idx < len(args):
                size_arg  = args[size_idx]
                size_vars = _g2_size_identifiers(size_arg, source)
                if size_vars:
                    fn_start = fn_body.start_point[0] + 1
                    guarded  = _find_guards_between(
                        fn_body, size_vars, fn_start - 1, call_line, source,
                        _build_local_signed(fn_body, source), sink_expr=size_arg,
                    )
                    if not guarded.found:
                        size_text = node_text(size_arg, source)
                        findings.append({
                            'function':        fn_name,
                            'file':            str(filepath),
                            'category':        'G2',
                            'severity':        'medium',
                            'taint_source_fn': callee,
                            'tainted_var':     size_text,
                            'taint_line':      call_line,
                            'taint_snippet':   call_snippet,
                            'sink_fn':         callee,
                            'sink_line':       call_line,
                            'sink_snippet':    call_snippet,
                            'sink_arg_index':  size_idx,
                            'sink_arg_role':   'unvalidated_size',
                            'possibly_guarded': False,
                            'propagation':     'intra',
                            'reason': (
                                f"size argument {size_text!r} to {callee}() not "
                                f"validated against buffer capacity before use"
                            ),
                        })

    return findings


def scan_copy_user_files(source_paths, cats, verbose=False):
    """
    Scan source files for Categories G1 (retval unchecked) and/or G2
    (unvalidated size argument).  cats: iterable containing 'G1' and/or 'G2'.
    Returns list of finding dicts in the same schema as scan_files().
    """
    from kernel_analysis.parsers.c_parser import parse_file, find_functions

    cats = set(cats)
    all_findings = []
    for path in source_paths:
        try:
            tree, source = parse_file(path)
        except Exception as e:
            if verbose:
                print(f"  [skip {path}: {e}]")
            continue
        for fn in find_functions(tree, source):
            all_findings.extend(
                _scan_fn_copy_user(fn['body'], fn['name'], source, path, cats)
            )
    return all_findings
