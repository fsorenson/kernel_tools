"""
Struct field types, read from the struct definitions themselves.

Knowing that `rsp->StructureSize` is a `__le16` is the difference between a
term the solver can reason about and an unconstrained 32-bit blank.  Nothing
about any particular struct is recorded here: the index is built by parsing
the definitions the translation unit can reach through its #includes, so a
field that gains a bit, changes width, or moves to another header changes
what the checker concludes without anything here being touched.

The endianness annotation is worth as much as the width.  A `__le32` field is
on-the-wire or on-disk data by declaration, which is the same provenance
`le32_to_cpu()` carries and the reason a value is worth tracking at all.
"""

import functools
import os
import re

from kernel_analysis.parsers.c_parser import (
    TYPE_NODES, node_text, parse_file, _walk,
)

_INCLUDE = re.compile(rb'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"\n]+)[>"]', re.M)

# How far to follow #include.  Definitions sit one or two hops out —
# fs/smb/client/smb2misc.c reaches struct smb2_lease_break via smb2pdu.h —
# and each further hop multiplies the parse cost for a long tail of
# definitions nothing in the file references.
_DEPTH = 2

_NOISE_WORDS = frozenset({
    'const', 'volatile', 'static', 'extern', 'register', 'restrict',
    'struct', 'union', 'enum', '__packed', '__aligned', '_Atomic',
})

# What a field access yields.  Only a scalar is the value of its declared
# type: `char *name` and `u8 buf[64]` both read as addresses.
SCALAR, POINTER, ARRAY = '', 'ptr', 'array'


def base_type(type_text):
    """'const unsigned int' → 'unsigned int', for the width tables."""
    return ' '.join(w for w in type_text.replace('*', ' ').split()
                    if w not in _NOISE_WORDS)


def type_key(type_text):
    """The name a type looks up under: 'const struct foo *' → 'foo'."""
    words = base_type(type_text).split()
    return words[-1] if words else None


# ---------------------------------------------------------------------------
# Reading definitions out of one file
# ---------------------------------------------------------------------------

def _declarator(node, source):
    """(name, kind) for a field declarator, following it down to the name."""
    kind = SCALAR
    while True:
        if node.type == 'pointer_declarator':
            kind = POINTER
        elif node.type == 'array_declarator' and kind != POINTER:
            kind = ARRAY
        inner = node.child_by_field_name('declarator')
        if inner is None:
            break
        node = inner
    if node.type in ('field_identifier', 'identifier'):
        return node_text(node, source), kind
    return None, kind


def _field_map(body, source):
    out = {}
    for decl in body.children:
        if decl.type != 'field_declaration':
            continue
        type_text = ' '.join(node_text(c, source) for c in decl.children
                             if c.type in TYPE_NODES)
        if not type_text:
            continue
        bits = None
        for child in decl.children:
            if child.type != 'bitfield_clause':
                continue
            lit = next((c for c in child.children
                        if c.type == 'number_literal'), None)
            if lit is not None:
                try:
                    bits = int(node_text(lit, source))
                except ValueError:
                    pass
        for child in decl.children:
            if child.type == 'field_identifier':
                out.setdefault(node_text(child, source),
                               (type_text, bits, SCALAR))
            elif child.type in ('pointer_declarator', 'array_declarator'):
                name, kind = _declarator(child, source)
                if name:
                    out.setdefault(name, (type_text, bits, kind))
    return out


@functools.lru_cache(maxsize=4096)
def _types_in(path):
    """
    {type name: {field: (type string, bitfield width, kind)}} from one file.

    Tagged definitions are taken from anywhere in the tree rather than from
    file scope: a header keeps its whole contents inside the include guard,
    which is a preprocessor node, so nothing in one is at file scope at all.
    A tag the file defines two ways — the #ifdef pair a stub header uses —
    maps to None, which is how a conflict travels out to field_types().
    """
    try:
        tree, source = parse_file(path)
    except Exception:
        return {}

    out = {}

    def record(name, body):
        decls = _field_map(body, source)
        if out.setdefault(name, decls) != decls:
            out[name] = None

    for node in _walk(tree.root_node):
        if node.type in ('struct_specifier', 'union_specifier'):
            name = next((c for c in node.children
                         if c.type == 'type_identifier'), None)
            body = next((c for c in node.children
                         if c.type == 'field_declaration_list'), None)
            if name is not None and body is not None:
                record(node_text(name, source), body)
        elif node.type == 'type_definition':
            spec = next((c for c in node.children
                         if c.type in ('struct_specifier', 'union_specifier')),
                        None)
            if spec is None:
                continue
            body = next((c for c in spec.children
                         if c.type == 'field_declaration_list'), None)
            if body is None:
                continue
            alias = next((node_text(c, source) for c in reversed(node.children)
                          if c.type == 'type_identifier'), None)
            if alias:
                record(alias, body)
    return out


# ---------------------------------------------------------------------------
# Reaching the definitions a file can see
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def _tree_root(path):
    """The kernel tree a file belongs to, for resolving <linux/...>."""
    d = os.path.dirname(os.path.abspath(path))
    while d != os.path.dirname(d):
        if os.path.isdir(os.path.join(d, 'include', 'linux')):
            return d
        d = os.path.dirname(d)
    return None


@functools.lru_cache(maxsize=None)
def _includes(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return ()
    return tuple((m.group(1) == b'"', m.group(2).decode('utf8', 'replace'))
                 for m in _INCLUDE.finditer(data))


def _resolve(name, quoted, origin, root):
    cands = [os.path.join(os.path.dirname(origin), name)] if quoted else []
    if root:
        cands.append(os.path.join(root, 'include', name))
        cands.append(os.path.join(root, 'include', 'uapi', name))
    for c in cands:
        if os.path.isfile(c):
            return os.path.realpath(c)
    return None


@functools.lru_cache(maxsize=16)
def field_types(c_path):
    """
    Every field declaration a file can see, keyed by type name then field.

    Headers are shared heavily between translation units, so what costs is
    parsing a given header, and that happens once however many files reach it.

    A tag two reachable headers define differently is dropped rather than
    decided by parse order: `struct node` is not a unique name in this tree,
    and the wrong field widths reach the UNSAT direction.
    """
    root = _tree_root(c_path)
    out = {}
    start = os.path.realpath(c_path)
    seen = {start}
    frontier = [start]

    for _ in range(_DEPTH + 1):
        nxt = []
        for path in frontier:
            for name, decls in _types_in(path).items():
                if out.setdefault(name, decls) != decls:
                    out[name] = None
            for quoted, inc in _includes(path):
                target = _resolve(inc, quoted, path, root)
                if target is not None and target not in seen:
                    seen.add(target)
                    nxt.append(target)
        frontier = nxt
    return {k: v for k, v in out.items() if v}


def var_types(fn_node, fn_body, source):
    """
    {variable: type name} for parameters and locals.

    Pointer-ness is dropped: `struct foo *p` and `struct foo p` resolve a
    field through `foo` either way, and which operator was written to reach
    it does not change what the field is.
    """
    out = {}

    def record(type_text, declarator):
        key = type_key(type_text)
        if not key:
            return
        # Down the declarator chain rather than into the subtree: the name is
        # what `*p = get_foo(x)` declares, not what it calls.
        node = declarator
        while True:
            inner = node.child_by_field_name('declarator')
            if inner is None:
                break
            node = inner
        if node.type in ('identifier', 'field_identifier'):
            out.setdefault(node_text(node, source), key)

    def scan(node, decl_kinds):
        type_text = ' '.join(node_text(c, source)
                             for c in node.children if c.type in TYPE_NODES)
        if not type_text:
            return
        for child in node.children:
            if child.type in decl_kinds:
                record(type_text, child)

    params = next((c for c in _walk(fn_node)
                   if c.type == 'parameter_list'), None)
    if params is not None:
        for param in params.children:
            if param.type == 'parameter_declaration':
                scan(param, ('pointer_declarator', 'identifier',
                             'array_declarator'))

    for node in _walk(fn_body):
        if node.type == 'declaration':
            scan(node, ('init_declarator', 'pointer_declarator', 'identifier',
                        'array_declarator'))
    return out
