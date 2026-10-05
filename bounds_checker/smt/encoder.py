"""
C expression AST → Z3 bitvector term.

Values are carried as (term, width, signed) so that the usual arithmetic
conversions can be applied at each operator rather than guessed once.  An
expression the encoder does not model yields a fresh unconstrained constant of
the best-known width, which keeps the UNSAT direction sound.
"""

import z3

from kernel_analysis.parsers.c_parser import _walk, node_text


# Reads of server/user data.  The encoder knows only their width: the value
# itself is whatever the far side chose to send.
_LE_READS = {
    'le16_to_cpu': 16, 'le32_to_cpu': 32, 'le64_to_cpu': 64,
    'be16_to_cpu': 16, 'be32_to_cpu': 32, 'be64_to_cpu': 64,
    'get_unaligned_le16': 16, 'get_unaligned_le32': 32,
    'get_unaligned_le64': 64,
    'get_unaligned_be16': 16, 'get_unaligned_be32': 32,
    'get_unaligned_be64': 64,
    'cpu_to_le16': 16, 'cpu_to_le32': 32, 'cpu_to_le64': 64,
}

# Wrappers whose value is their first argument.  WARN_ON() and friends yield
# !!cond rather than cond, which differs only where the result is used
# arithmetically; in a condition, which is everywhere these appear, it does
# not.  Missing these leaves `if (WARN_ON_ONCE(i >= size || i < 0)) return;`
# contributing nothing to the path condition.
_TRANSPARENT = frozenset({
    'likely', 'unlikely', 'likely_notrace', 'unlikely_notrace',
    '__builtin_expect', 'WARN_ON', 'WARN_ON_ONCE', 'WARN_ONCE',
    'BUG_ON', 'READ_ONCE', 'WRITE_ONCE', 'ACCESS_ONCE',
})

# Returns that cannot be negative, matching _NONNEG_CALLS in the taint scanner.
_NONNEG_CALLS = frozenset({'strlen', 'strnlen', 'ARRAY_SIZE', 'strcspn', 'strspn'})

_SIGNED_TYPE_NAMES = frozenset({
    's8', '__s8', 's16', '__s16', 's32', '__s32', 's64', '__s64',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'short', 'short int', 'int', 'long', 'long int', 'long long',
    'signed', 'signed char', 'signed short', 'signed int', 'signed long',
    'ssize_t', 'ptrdiff_t', 'loff_t', 'char',
})

_TYPE_WIDTHS = {
    'u8': 8, '__u8': 8, 's8': 8, '__s8': 8, 'char': 8,
    'unsigned char': 8, 'signed char': 8, 'bool': 8, '_Bool': 8,
    'u16': 16, '__u16': 16, 's16': 16, '__s16': 16,
    '__le16': 16, '__be16': 16, 'short': 16, 'unsigned short': 16,
    'u32': 32, '__u32': 32, 's32': 32, '__s32': 32,
    '__le32': 32, '__be32': 32, 'int': 32, 'unsigned int': 32,
    'unsigned': 32, 'signed': 32, 'signed int': 32,
    'u64': 64, '__u64': 64, 's64': 64, '__s64': 64,
    '__le64': 64, '__be64': 64, 'long': 64, 'unsigned long': 64,
    'long long': 64, 'unsigned long long': 64,
    'size_t': 64, 'ssize_t': 64, 'loff_t': 64, 'ptrdiff_t': 64,
    'uint8_t': 8, 'int8_t': 8, 'uint16_t': 16, 'int16_t': 16,
    'uint32_t': 32, 'int32_t': 32, 'uint64_t': 64, 'int64_t': 64,
}

# A sizeof the encoder cannot evaluate is still a positive, modest constant.
# Leaving it fully free would make every product look like it can wrap.  The
# ceiling matches the 16-bit budget _max_bits() already assumes for sizeof.
_SIZEOF_MAX = 0xFFFF

INT_BITS = 32           # the rank everything narrower promotes to
PTR_BITS = 64

# Limit macros with the same value on every target.  Without these a guard
# like `if (len > U8_MAX)` constrains len against a free variable and so
# constrains nothing.  Anything architecture- or config-dependent is left out
# deliberately: a wrong constant is worse than an unknown one, because it
# reaches the UNSAT direction.
_LIMIT_CONSTS = {
    'U8_MAX': (0xff, 8, False), 'U16_MAX': (0xffff, 16, False),
    'U32_MAX': (0xffffffff, 32, False),
    'U64_MAX': (0xffffffffffffffff, 64, False),
    'S8_MAX': (0x7f, 8, True), 'S16_MAX': (0x7fff, 16, True),
    'S32_MAX': (0x7fffffff, 32, True),
    'S64_MAX': (0x7fffffffffffffff, 64, True),
    'S8_MIN': (-0x80, 8, True), 'S16_MIN': (-0x8000, 16, True),
    'S32_MIN': (-0x80000000, 32, True),
    'S64_MIN': (-0x8000000000000000, 64, True),
    'INT_MAX': (0x7fffffff, 32, True), 'INT_MIN': (-0x80000000, 32, True),
    'UINT_MAX': (0xffffffff, 32, False),
    'SHRT_MAX': (0x7fff, 32, True), 'SHRT_MIN': (-0x8000, 32, True),
    'USHRT_MAX': (0xffff, 32, True),
    'UCHAR_MAX': (0xff, 32, True), 'SCHAR_MAX': (0x7f, 32, True),
    'LONG_MAX': (0x7fffffffffffffff, 64, True),
    'LONG_MIN': (-0x8000000000000000, 64, True),
    'ULONG_MAX': (0xffffffffffffffff, 64, False),
    'LLONG_MAX': (0x7fffffffffffffff, 64, True),
    'LLONG_MIN': (-0x8000000000000000, 64, True),
    'ULLONG_MAX': (0xffffffffffffffff, 64, False),
    'SIZE_MAX': (0xffffffffffffffff, 64, False),
    'SSIZE_MAX': (0x7fffffffffffffff, 64, True),
    'CHAR_BIT': (8, 32, True), 'BITS_PER_BYTE': (8, 32, True),
    'BITS_PER_LONG': (64, 32, True), 'BITS_PER_LONG_LONG': (64, 32, True),
}


class Value:
    __slots__ = ('bv', 'width', 'signed', 'guessed')

    def __init__(self, bv, width, signed, guessed=False):
        self.bv, self.width, self.signed = bv, width, signed
        # The width and signedness are a fallback rather than the source's.
        # The value itself is no less known for it, so the UNSAT direction
        # still holds; only reasoning *about* the type — does this fit, can
        # this be negative — has nothing under it.
        self.guessed = guessed


def _const(name, width):
    return z3.BitVec(name, width)


def _resize(val, width, signed_src=None):
    """Widen with the source's signedness, or truncate, as C conversion does."""
    sign = val.signed if signed_src is None else signed_src
    if val.width == width:
        return val.bv
    if val.width < width:
        return (z3.SignExt if sign else z3.ZeroExt)(width - val.width, val.bv)
    return z3.Extract(width - 1, 0, val.bv)


def promote(val):
    """Integer promotion: everything of lesser rank than int becomes int."""
    if val.width >= INT_BITS:
        return val
    return Value(_resize(val, INT_BITS), INT_BITS, True, val.guessed)


def usual_conversions(a, b):
    """
    C's usual arithmetic conversions, after promotion.

    Equal width with one operand unsigned yields unsigned, which is the rule
    that turns `i < len` into an unsigned compare when len is size_t and makes
    a negative i pass.
    """
    a, b = promote(a), promote(b)
    width = max(a.width, b.width)
    if a.width == b.width:
        signed = a.signed and b.signed
    else:
        wider = a if a.width > b.width else b
        signed = wider.signed
    guessed = a.guessed or b.guessed
    return (Value(_resize(a, width), width, signed, guessed),
            Value(_resize(b, width), width, signed, guessed),
            width, signed)


class Encoder:
    """
    Translates expressions within one function body.

    `env` maps a variable name to its current Value (SSA: rebound on each
    assignment the path takes).  `decl` maps a name to its (width, signed)
    from the declaration, used when a variable is read before the encoder has
    bound it — a parameter, or a write it chose not to model.
    """

    def __init__(self, source, decl_types=None):
        self.source = source
        self.decl = decl_types or {}
        self.env = {}
        self.facts = []          # constraints on fresh constants (sizeof > 0, …)
        # Constants standing for C the encoder failed to model, as opposed to
        # values that are genuinely unknown (a parameter, a wire read).  A
        # counterexample that needs one of these to take an absurd value is
        # not a witness, it is the gap in the model talking.
        self.opaque = set()
        # Names whose value the walk could not follow — written inside a loop,
        # or live across a label a goto can reach.  A later read is a fresh
        # constant like any other, but it stands for the gap rather than for
        # something genuinely unknown.
        self.lost = set()
        self._n = 0

    # -- fresh unconstrained values ---------------------------------------

    def fresh(self, hint, width, signed=False, opaque=False, guessed=None):
        self._n += 1
        name = f'{hint}!{self._n}'
        if opaque:
            self.opaque.add(name)
        return Value(_const(name, width), width, signed,
                     opaque if guessed is None else guessed)

    def declared(self, name):
        return self.decl.get(name, (INT_BITS, True))

    def read_var(self, name):
        if name in self.env:
            return self.env[name]
        undeclared = name not in self.decl
        lit = _LIMIT_CONSTS.get(name) if undeclared else None
        if lit is not None:
            v, width, signed = lit
            val = Value(z3.BitVecVal(v, width), width, signed)
        else:
            width, signed = self.declared(name)
            # An all-caps undeclared name is a macro or an enumerator, so the
            # constant stands for something fixed the encoder could not expand
            # rather than for a value the path leaves open.
            val = self.fresh(name, width, signed,
                             opaque=(name in self.lost
                                     or (undeclared and name.isupper())),
                             guessed=undeclared)
        self.env[name] = val
        return val

    def bind(self, name, val):
        width, signed = self.declared(name)
        # The assignment converts to the destination's type, so a known
        # declaration grounds the result however the right side was reached.
        self.env[name] = Value(_resize(val, width), width, signed,
                               name not in self.decl)
        return self.env[name]

    # -- expressions -------------------------------------------------------

    def encode(self, node):
        """Always returns a Value; unmodelled shapes become fresh constants."""
        if node is None:
            return self.fresh('unknown', INT_BITS, True, opaque=True)
        return getattr(self, f'_e_{node.type}', self._e_default)(node)

    def _e_default(self, node):
        return self.fresh('opaque', INT_BITS, True, opaque=True)

    def _text(self, node):
        return node_text(node, self.source)

    def _e_parenthesized_expression(self, node):
        inner = [c for c in node.children if c.is_named]
        return self.encode(inner[0]) if inner else self._e_default(node)

    def _e_comma_expression(self, node):
        return self.encode(node.child_by_field_name('right'))

    def _e_number_literal(self, node):
        text = self._text(node).strip()
        core = text.rstrip('uUlL')
        suffix = text[len(core):].lower()
        try:
            v = int(core, 0)
        except ValueError:
            return self.fresh('lit', INT_BITS, True, opaque=True)
        signed = 'u' not in suffix
        if 'l' in suffix:
            width = 64
        elif not signed:
            width = INT_BITS if v < (1 << 32) else 64
        else:
            width = INT_BITS if -(1 << 31) <= v < (1 << 31) else 64
        return Value(z3.BitVecVal(v, width), width, signed)

    def _e_char_literal(self, node):
        return Value(z3.BitVecVal(0, INT_BITS), INT_BITS, True)

    def _e_identifier(self, node):
        return self.read_var(self._text(node))

    def _e_sizeof_expression(self, node):
        val = self.fresh('sizeof', PTR_BITS, False, opaque=True)
        self.facts.append(z3.And(z3.UGE(val.bv, 1),
                                 z3.ULE(val.bv, _SIZEOF_MAX)))
        return val

    def _e_cast_expression(self, node):
        type_node = node.child_by_field_name('type')
        inner = self.encode(node.child_by_field_name('value'))
        if type_node is None:
            return inner
        text = self._text(type_node).strip()
        if '*' in text:
            return Value(_resize(inner, PTR_BITS), PTR_BITS, False)
        width = _TYPE_WIDTHS.get(text)
        if width is None:
            return inner
        return Value(_resize(inner, width), width,
                     text in _SIGNED_TYPE_NAMES)   # the cast states the type

    def _e_unary_expression(self, node):
        op = self._op_text(node)
        val = promote(self.encode(node.child_by_field_name('argument')))
        if op == '-':
            return Value(-val.bv, val.width, val.signed, val.guessed)
        if op == '~':
            return Value(~val.bv, val.width, val.signed, val.guessed)
        if op == '!':
            return Value(z3.If(val.bv == 0,
                               z3.BitVecVal(1, INT_BITS),
                               z3.BitVecVal(0, INT_BITS)), INT_BITS, True)
        if op == '+':
            return val
        return self.fresh('unary', INT_BITS, True, opaque=True)

    def _op_text(self, node):
        for c in node.children:
            if not c.is_named:
                return self._text(c)
        return ''

    def _e_binary_expression(self, node):
        op = self._op_text(node)
        lhs = self.encode(node.child_by_field_name('left'))
        rhs = self.encode(node.child_by_field_name('right'))

        if op in ('&&', '||'):
            lb, rb = self.as_bool(lhs), self.as_bool(rhs)
            comb = z3.And(lb, rb) if op == '&&' else z3.Or(lb, rb)
            return Value(z3.If(comb, z3.BitVecVal(1, INT_BITS),
                               z3.BitVecVal(0, INT_BITS)), INT_BITS, True)

        if op in ('<<', '>>'):
            # Shifts do not undergo the usual conversions: the left operand is
            # promoted on its own and the result keeps its type.
            l = promote(lhs)
            r = Value(_resize(promote(rhs), l.width), l.width, l.signed)
            if op == '<<':
                return Value(l.bv << r.bv, l.width, l.signed, l.guessed)
            shifted = (l.bv >> r.bv) if l.signed else z3.LShR(l.bv, r.bv)
            return Value(shifted, l.width, l.signed, l.guessed)

        l, r, width, signed = usual_conversions(lhs, rhs)

        if op in ('<', '<=', '>', '>=', '==', '!='):
            return Value(z3.If(self.compare(op, l, r, signed),
                               z3.BitVecVal(1, INT_BITS),
                               z3.BitVecVal(0, INT_BITS)), INT_BITS, True)

        if op == '+':
            return Value(l.bv + r.bv, width, signed, l.guessed)
        if op == '-':
            return Value(l.bv - r.bv, width, signed, l.guessed)
        if op == '*':
            return Value(l.bv * r.bv, width, signed, l.guessed)
        if op == '/':
            q = (l.bv / r.bv) if signed else z3.UDiv(l.bv, r.bv)
            return Value(z3.If(r.bv == 0, l.bv, q), width, signed, l.guessed)
        if op == '%':
            m = z3.SRem(l.bv, r.bv) if signed else z3.URem(l.bv, r.bv)
            return Value(z3.If(r.bv == 0, l.bv, m), width, signed, l.guessed)
        if op == '&':
            return Value(l.bv & r.bv, width, signed, l.guessed)
        if op == '|':
            return Value(l.bv | r.bv, width, signed, l.guessed)
        if op == '^':
            return Value(l.bv ^ r.bv, width, signed, l.guessed)
        return self.fresh('binop', width, signed, opaque=True)

    @staticmethod
    def compare(op, l, r, signed):
        if op == '==':
            return l.bv == r.bv
        if op == '!=':
            return l.bv != r.bv
        if signed:
            return {'<': l.bv < r.bv, '<=': l.bv <= r.bv,
                    '>': l.bv > r.bv, '>=': l.bv >= r.bv}[op]
        return {'<': z3.ULT(l.bv, r.bv), '<=': z3.ULE(l.bv, r.bv),
                '>': z3.UGT(l.bv, r.bv), '>=': z3.UGE(l.bv, r.bv)}[op]

    def _e_conditional_expression(self, node):
        cond = self.as_bool(self.encode(node.child_by_field_name('condition')))
        a = self.encode(node.child_by_field_name('consequence'))
        b = self.encode(node.child_by_field_name('alternative'))
        a, b, width, signed = usual_conversions(a, b)
        return Value(z3.If(cond, a.bv, b.bv), width, signed, a.guessed)

    def _e_call_expression(self, node):
        fn = next((c for c in node.children if c.type == 'identifier'), None)
        name = self._text(fn) if fn is not None else ''
        if name in _TRANSPARENT:
            args = node.child_by_field_name('arguments')
            inner = [c for c in args.children if c.is_named] if args else []
            if inner:
                return self.encode(inner[0])
        if name in _LE_READS:
            # The defining unknown: width is fixed by the accessor, value is
            # entirely the far side's choice.
            return self.fresh(f'{name}_val', _LE_READS[name], False)
        val = self.fresh(f'{name or "call"}_ret', INT_BITS, True, opaque=True)
        if name in _NONNEG_CALLS:
            self.facts.append(val.bv >= 0)
        return val

    def _e_field_expression(self, node):
        return self.fresh('field', INT_BITS, False, opaque=True)

    def _e_subscript_expression(self, node):
        return self.fresh('elem', INT_BITS, False, opaque=True)

    def _e_pointer_expression(self, node):
        return self.fresh('deref', PTR_BITS, False, opaque=True)

    def _e_assignment_expression(self, node):
        return self.encode(node.child_by_field_name('right'))

    def _e_update_expression(self, node):
        return self.encode(node.child_by_field_name('argument'))

    # -- predicates --------------------------------------------------------

    def as_bool(self, val):
        return val.bv != 0

    def cond(self, node):
        """A condition expression as a Z3 Bool."""
        return self.as_bool(self.encode(node))


def build_decl_types(fn_body, source):
    """
    {name: (width, signed)} for locals and parameters with a known integer
    type.  A name declared twice with different widths is dropped — guessing
    either way would silently change what a comparison means.
    """
    out, conflict = {}, set()

    def record(name, text):
        text = text.strip()
        width = _TYPE_WIDTHS.get(text)
        if width is None:
            return
        entry = (width, text in _SIGNED_TYPE_NAMES)
        if out.get(name, entry) != entry:
            conflict.add(name)
        out[name] = entry

    for n in _walk(fn_body):
        if n.type not in ('declaration', 'parameter_declaration'):
            continue
        type_node = n.child_by_field_name('type')
        if type_node is None:
            continue
        text = node_text(type_node, source)
        for child in n.children:
            decl = (child.children[0]
                    if child.type == 'init_declarator' and child.children
                    else child)
            if decl is not None and decl.type == 'identifier':
                record(node_text(decl, source), text)

    for name in conflict:
        out.pop(name, None)
    return out
