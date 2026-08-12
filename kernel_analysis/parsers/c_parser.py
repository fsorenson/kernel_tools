"""
Generic tree-sitter C parser utilities for kernel source analysis.

Provides parsing primitives shared across analysis tools (race checker,
bounds checker, etc.).  Contains no tool-specific logic — only AST
traversal, type extraction, field/function scanning, and access
classification.

Node type reference (tree-sitter-c 0.24, tree-sitter 0.26):
  field_declaration_list children:
    field_declaration   — a struct field
    comment             — /* */ or // comment (sibling, not child of field_declaration)
    preproc_def         — #define inside struct
    preproc_if/ifdef    — conditional compilation blocks

  field_declaration children:
    type node           — type_identifier | primitive_type | sized_type_specifier |
                          struct_specifier | enum_specifier | union_specifier
    field_identifier    — direct name (simple fields, bitfields)
    pointer_declarator  — *name  (contains field_identifier)
    array_declarator    — name[N] (contains field_identifier)
    function_declarator — (*fn)() (contains field_identifier)
    bitfield_clause     — :N  (width in number_literal child)
"""

import re
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_c

C_LANGUAGE = Language(tree_sitter_c.language())
_parser = Parser(C_LANGUAGE)

# Node types that represent a C type specifier
TYPE_NODES = frozenset({
    'type_identifier', 'primitive_type', 'sized_type_specifier',
    'struct_specifier', 'union_specifier', 'enum_specifier',
    'type_qualifier', 'storage_class_specifier',
})

# Node types that contain the field name
DECLARATOR_NODES = frozenset({
    'field_identifier', 'pointer_declarator', 'array_declarator',
    'function_declarator', 'parenthesized_declarator',
})

# Storage unit sizes (in bits) for C types that commonly appear in bitfields.
_TYPE_BITS = {
    'bool': 8, '_Bool': 8,
    'char': 8, 'unsigned char': 8, 'signed char': 8,
    '__u8': 8, '__s8': 8, 'u8': 8, 's8': 8,
    'short': 16, 'unsigned short': 16,
    '__u16': 16, '__s16': 16, 'u16': 16, 's16': 16,
    'int': 32, 'unsigned int': 32, 'unsigned': 32,
    '__u32': 32, '__s32': 32, 'u32': 32, 's32': 32,
    'long': 64, 'unsigned long': 64,
    'long long': 64, 'unsigned long long': 64,
    '__u64': 64, '__s64': 64, 'u64': 64, 's64': 64,
}

# typedef attribute keywords that are not the typedef alias name
_TYPEDEF_ATTR_KEYWORDS = frozenset({
    '__packed', '__aligned', '__attribute__', '__nocast', '__bitwise', '__force',
})

# Parent node types that imply a write access to a field expression
_WRITE_PARENT_TYPES = frozenset({'update_expression', 'compound_assignment_expression'})


# ---------------------------------------------------------------------------
# Core parsing helpers
# ---------------------------------------------------------------------------

def parse_file(path):
    """Return (tree, source_bytes) for a C source file."""
    with open(path, 'rb') as f:
        source = f.read()
    return _parser.parse(source), source


def node_text(node, source):
    return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')


def strip_comment_delimiters(text):
    text = text.strip()
    if text.startswith('/*') and text.endswith('*/'):
        text = text[2:-2].strip()
    elif text.startswith('//'):
        text = text[2:].strip()
    text = ' '.join(text.split())
    return text


def get_source_line(source, line_no):
    """Return the text of 1-indexed line_no from source bytes."""
    lines = source.split(b'\n')
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].decode('utf-8', errors='replace').strip()
    return ''


def _walk(node):
    """Depth-first walk of all nodes in a tree."""
    yield node
    for child in node.children:
        yield from _walk(child)


# ---------------------------------------------------------------------------
# Type utilities
# ---------------------------------------------------------------------------

def _type_bits(type_str):
    """Return the storage-unit size in bits for a bitfield's declared type."""
    if not type_str:
        return 32
    norm = ' '.join(type_str.lower().split())
    for q in ('const ', 'volatile ', 'static ', 'signed '):
        norm = norm.replace(q, '')
    return _TYPE_BITS.get(norm.strip(), 32)


def _base_struct_name(type_text):
    """
    Return the bare struct name from a C type string, or None if not a struct.
    'struct cifsFileInfo' → 'cifsFileInfo'
    'struct rw_semaphore *' → 'rw_semaphore'
    'int' → None
    """
    words = type_text.split()
    try:
        idx = words.index('struct')
        if idx + 1 < len(words):
            return words[idx + 1].rstrip('*')
    except ValueError:
        pass
    return None


# ---------------------------------------------------------------------------
# AST helper functions
# ---------------------------------------------------------------------------

def _find_field_identifier(node, source):
    """Recursively find the innermost field_identifier in a declarator subtree."""
    if node.type == 'field_identifier':
        return node_text(node, source)
    for child in node.children:
        result = _find_field_identifier(child, source)
        if result:
            return result
    return None


def _find_identifier(node, source):
    """Recursively find the first identifier in a declarator subtree."""
    if node.type == 'identifier':
        return node_text(node, source)
    for child in node.children:
        result = _find_identifier(child, source)
        if result:
            return result
    return None


def _find_param_list(node):
    """Recursively find the parameter_list node in a function_definition."""
    if node.type == 'parameter_list':
        return node
    for child in node.children:
        found = _find_param_list(child)
        if found:
            return found
    return None


def _fn_name_from_def(fn_def_node, source):
    """Extract function name from a function_definition node."""
    def _search(node):
        if node.type == 'function_declarator':
            for child in node.children:
                if child.type == 'identifier':
                    return node_text(child, source)
                if child.type in ('pointer_declarator', 'parenthesized_declarator'):
                    result = _search(child)
                    if result:
                        return result
        elif node.type in ('pointer_declarator', 'parenthesized_declarator'):
            for child in node.children:
                result = _search(child)
                if result:
                    return result
        return None

    for child in fn_def_node.children:
        if child.type in ('function_declarator', 'pointer_declarator'):
            result = _search(child)
            if result:
                return result
    return None


# ---------------------------------------------------------------------------
# Field declaration extraction
# ---------------------------------------------------------------------------

def _extract_field_decl_info(decl_node, source):
    """
    Extract (type_str, field_name, bit_width) from a field_declaration node.
    bit_width is an int for bitfields, None otherwise.
    Returns (None, None, None) if extraction fails.
    """
    type_parts = []
    field_name = None
    bit_width = None

    for child in decl_node.children:
        if child.type in TYPE_NODES:
            type_parts.append(node_text(child, source).strip())
        elif child.type == 'field_identifier':
            field_name = node_text(child, source)
        elif child.type in DECLARATOR_NODES - {'field_identifier'}:
            field_name = _find_field_identifier(child, source)
        elif child.type == 'bitfield_clause':
            for bfc in child.children:
                if bfc.type == 'number_literal':
                    try:
                        bit_width = int(node_text(bfc, source))
                    except ValueError:
                        pass

    return ' '.join(type_parts) or None, field_name, bit_width


# ---------------------------------------------------------------------------
# Type definition collection (typedef + named struct/union)
# ---------------------------------------------------------------------------

def find_struct_definition(tree, struct_name, source):
    """
    Find the struct_specifier node for a full struct definition (not forward decl).
    Returns the node, or None.
    """
    for node in _walk(tree.root_node):
        if node.type != 'struct_specifier':
            continue
        has_name = False
        has_body = False
        for child in node.children:
            if child.type == 'type_identifier' and node_text(child, source) == struct_name:
                has_name = True
            if child.type == 'field_declaration_list':
                has_body = True
        if has_name and has_body:
            return node
    return None


def collect_type_definitions(tree, source):
    """
    Collect struct/union type definitions from a parsed file.

    Returns {type_name: [(field_name, type_str, bit_width), ...]} covering:
    - typedef struct { ... } TypeName;
    - typedef struct { ... } __packed TypeName;   (__packed → ERROR node in tree-sitter)
    - typedef struct TagName { ... } TypeName;
    - struct TagName { ... };                      (named struct at file scope)
    - union TagName { ... };                       (named union at file scope)
    """
    types = {}

    def _extract_field_list(fdl_node):
        result = []
        for child in fdl_node.children:
            if child.type != 'field_declaration':
                continue
            type_str, field_name, bit_width = _extract_field_decl_info(child, source)
            if field_name:
                result.append((field_name, type_str or '', bit_width))
        return result

    # Pass 1: typedef'd structs/unions.
    for node in _walk(tree.root_node):
        if node.type != 'type_definition':
            continue
        fdl_node = None
        for child in node.children:
            if child.type in ('struct_specifier', 'union_specifier'):
                fdl_node = next(
                    (c for c in child.children if c.type == 'field_declaration_list'),
                    None,
                )
                if fdl_node:
                    break
        if not fdl_node:
            continue

        # Alias name: last non-attribute type_identifier child, or identifier inside
        # an ERROR node (tree-sitter puts __packed-qualified names there).
        name = None
        for tid in reversed([c for c in node.children if c.type == 'type_identifier']):
            txt = node_text(tid, source)
            if txt not in _TYPEDEF_ATTR_KEYWORDS:
                name = txt
                break
        if name is None:
            for err in (c for c in node.children if c.type == 'ERROR'):
                ident = next((c for c in err.children if c.type == 'identifier'), None)
                if ident:
                    name = node_text(ident, source)
                    break
        if name:
            types[name] = _extract_field_list(fdl_node)

    # Pass 2: named (tagged) structs/unions defined at file scope without typedef.
    for node in tree.root_node.children:
        specs = []
        if node.type in ('struct_specifier', 'union_specifier'):
            specs.append(node)
        elif node.type == 'declaration':
            specs.extend(
                c for c in node.children
                if c.type in ('struct_specifier', 'union_specifier')
            )
        for spec in specs:
            type_id = next(
                (c for c in spec.children if c.type == 'type_identifier'), None
            )
            fdl_node = next(
                (c for c in spec.children if c.type == 'field_declaration_list'), None
            )
            if type_id and fdl_node:
                name = node_text(type_id, source)
                if name not in types:
                    types[name] = _extract_field_list(fdl_node)

    return types


def collect_type_definitions_from_paths(paths):
    """
    Collect and merge type definitions from multiple source files.
    Returns {type_name: [(field_name, type_str, bit_width), ...]} merged across
    all files.  First definition encountered wins; parse errors are silently skipped.
    """
    merged = {}
    for path in paths:
        try:
            tree, source = parse_file(path)
        except Exception:
            continue
        for name, fields in collect_type_definitions(tree, source).items():
            if name not in merged:
                merged[name] = fields
    return merged


# ---------------------------------------------------------------------------
# Function discovery and variable type mapping
# ---------------------------------------------------------------------------

def find_functions(tree, source):
    """
    Find all top-level function definitions.
    Returns list of {name, node, body, start_line, end_line}.
    """
    results = []
    for node in tree.root_node.children:
        if node.type != 'function_definition':
            continue
        body = next((c for c in node.children if c.type == 'compound_statement'), None)
        if not body:
            continue
        name = _fn_name_from_def(node, source)
        results.append({
            'name': name or '<unknown>',
            'node': node,
            'body': body,
            'start_line': node.start_point[0] + 1,
            'end_line': node.end_point[0] + 1,
        })
    return results


def build_var_type_map(fn_def_node, fn_body_node, source):
    """
    Build a variable-name → struct-type-name map for a function.

    Covers function parameters and local declarations of the form
    `struct X *var` or `struct X var`.  Variables whose type cannot be
    statically determined (casts, typedefs, complex initialisers) are
    simply absent from the map.
    """
    type_map = {}

    def _add_decl(type_text, decl_node):
        struct_name = _base_struct_name(type_text)
        if not struct_name:
            return
        name = _find_identifier(decl_node, source)
        if name:
            type_map[name] = struct_name

    # Function parameters
    param_list = _find_param_list(fn_def_node)
    if param_list:
        for param in param_list.children:
            if param.type != 'parameter_declaration':
                continue
            type_text = ' '.join(
                node_text(c, source)
                for c in param.children if c.type in TYPE_NODES
            )
            for child in param.children:
                if child.type in ('pointer_declarator', 'identifier', 'array_declarator'):
                    _add_decl(type_text, child)

    # Local variable declarations
    for node in _walk(fn_body_node):
        if node.type != 'declaration':
            continue
        type_text = ' '.join(
            node_text(c, source)
            for c in node.children if c.type in TYPE_NODES
        )
        for child in node.children:
            if child.type in ('init_declarator', 'pointer_declarator',
                              'identifier', 'array_declarator'):
                _add_decl(type_text, child)

    return type_map


# ---------------------------------------------------------------------------
# Access classification
# ---------------------------------------------------------------------------

def get_access_type(field_expr_node):
    """
    Classify a field_expression access as 'read', 'write', or 'address_of'.
    """
    parent = field_expr_node.parent
    if not parent:
        return 'read'
    if parent.type in _WRITE_PARENT_TYPES:
        return 'write'
    if parent.type == 'assignment_expression':
        lhs = next((c for c in parent.children if c.type not in ('=',)), None)
        return 'write' if lhs == field_expr_node else 'read'
    if parent.type == 'pointer_expression':
        return 'address_of'
    return 'read'


def find_field_accesses(body_node, target_field_names, source):
    """
    Recursively find all field_expression nodes in body_node where the
    field name is in target_field_names.

    Returns list of {field, obj, line, access_type, snippet}.
    """
    accesses = []
    for node in _walk(body_node):
        if node.type != 'field_expression':
            continue
        fid = next((c for c in node.children if c.type == 'field_identifier'), None)
        if not fid:
            continue
        field_name = node_text(fid, source)
        if field_name not in target_field_names:
            continue
        obj = next(
            (c for c in node.children if c.type not in ('field_identifier', '->', '.')),
            None,
        )
        obj_text = node_text(obj, source) if obj else ''
        line = node.start_point[0] + 1
        accesses.append({
            'field': field_name,
            'obj': obj_text,
            'line': line,
            'access_type': get_access_type(node),
            'snippet': get_source_line(source, line),
        })
    return accesses


# ---------------------------------------------------------------------------
# Generic call finder
# ---------------------------------------------------------------------------

def find_calls_to(node, source, func_names):
    """
    Find all calls to any function in func_names within node.

    Yields (call_node, func_name, args, line) where:
      call_node — the call_expression node
      func_name — the called function name (str)
      args      — list of argument nodes (excluding punctuation)
      line      — 1-based source line number
    """
    func_names = frozenset(func_names)
    for n in _walk(node):
        if n.type != 'call_expression':
            continue
        fn_id = next((c for c in n.children if c.type == 'identifier'), None)
        if not fn_id:
            continue
        name = node_text(fn_id, source)
        if name not in func_names:
            continue
        arg_list = next((c for c in n.children if c.type == 'argument_list'), None)
        args = (
            [c for c in arg_list.children if c.type not in ('(', ')', ',')]
            if arg_list else []
        )
        yield n, name, args, n.start_point[0] + 1


# ---------------------------------------------------------------------------
# Local array declaration extractor
# ---------------------------------------------------------------------------

def _find_array_declarators(node, source, type_str, line, out):
    """
    Recursively find array_declarator nodes within a declaration subtree and
    populate out with {var_name: {type, size_expr, size, line}} entries.
    """
    if node.type == 'array_declarator':
        name = None
        size_expr = None
        for child in node.children:
            t = child.type
            if t in ('[', ']'):
                continue
            if t == 'identifier':
                name = node_text(child, source)
            elif t in ('pointer_declarator', 'parenthesized_declarator',
                       'init_declarator'):
                inner = _find_identifier(child, source)
                if inner:
                    name = inner
            else:
                # Everything else is the size expression
                size_expr = node_text(child, source).strip()
        if name:
            size = None
            if size_expr:
                try:
                    size = int(size_expr, 0)
                except (ValueError, TypeError):
                    pass
            out[name] = {
                'type': type_str,
                'size_expr': size_expr or '',
                'size': size,   # int if a numeric literal, None if symbolic (e.g. MAX_BUF)
                'line': line,
            }
    else:
        for child in node.children:
            _find_array_declarators(child, source, type_str, line, out)


def extract_local_array_decls(fn_body_node, source):
    """
    Find local fixed-size array declarations in a function body.

    Returns {var_name: {'type': str, 'size_expr': str, 'size': int|None, 'line': int}}.
    Covers: char buf[256], int arr[MAX], char buf[CONST] = {...}, etc.
    'size' is an int when the size is a numeric literal, None for symbolic constants.
    """
    decls = {}
    for node in _walk(fn_body_node):
        if node.type != 'declaration':
            continue
        type_parts = [node_text(c, source) for c in node.children if c.type in TYPE_NODES]
        type_str = ' '.join(type_parts)
        line = node.start_point[0] + 1
        for child in node.children:
            _find_array_declarators(child, source, type_str, line, decls)
    return decls


# ---------------------------------------------------------------------------
# Allocation tracking
# ---------------------------------------------------------------------------

ALLOC_FUNCS = frozenset({
    # Core slab/page allocators
    'kmalloc', 'kzalloc', 'kcalloc', 'kmalloc_node', 'kzalloc_node',
    'kmalloc_array', 'kmalloc_array_node', 'kmalloc_large',
    'kzalloc_obj', 'kzalloc_objs',
    '__kmalloc', '__kmalloc_node',
    # vmalloc family
    'vmalloc', 'vzalloc', 'vmalloc_node', 'vmalloc_32',
    # kvmalloc (kmalloc with vmalloc fallback)
    'kvmalloc', 'kvzalloc', 'kvmalloc_node', 'kvmalloc_array',
    # Slab cache
    'kmem_cache_alloc', 'kmem_cache_zalloc',
    'kmem_cache_alloc_node', 'kmem_cache_alloc_lru',
    # Device-managed
    'devm_kmalloc', 'devm_kzalloc', 'devm_kcalloc',
    # Page allocators
    'alloc_pages', 'alloc_pages_node', 'get_zeroed_page',
    # Percpu
    'alloc_percpu', 'alloc_percpu_gfp',
})


def _is_alloc_call(node, source):
    """Return True if node is a call to a known allocation function, including through casts."""
    if node.type == 'call_expression':
        fn_id = next((c for c in node.children if c.type == 'identifier'), None)
        return fn_id is not None and node_text(fn_id, source) in ALLOC_FUNCS
    if node.type == 'cast_expression':
        inner = next((c for c in node.children if c.type == 'call_expression'), None)
        return inner is not None and _is_alloc_call(inner, source)
    return False


def _var_name_from_declarator(node, source):
    """Recursively find the first identifier in a variable declarator subtree."""
    if node.type == 'identifier':
        return node_text(node, source)
    for child in node.children:
        result = _var_name_from_declarator(child, source)
        if result:
            return result
    return None


def find_alloc_vars(fn_body, source):
    """
    Find variables in fn_body that are assigned from kernel allocation functions.

    Handles:
      var = alloc_func(...)                  assignment_expression
      var = (type *)alloc_func(...)          assignment through cast
      struct X *var = alloc_func(...)        init_declarator in declaration

    Returns a set of variable name strings representing freshly-allocated objects
    that have not yet been published.
    """
    alloc_vars = set()

    for node in _walk(fn_body):
        if node.type == 'assignment_expression':
            children = node.children
            if len(children) == 3 and children[1].type == '=':
                lhs, _, rhs = children
                if lhs.type == 'identifier' and _is_alloc_call(rhs, source):
                    alloc_vars.add(node_text(lhs, source))

        elif node.type == 'init_declarator':
            children = node.children
            if len(children) == 3 and children[1].type == '=':
                decl, _, rhs = children
                if _is_alloc_call(rhs, source):
                    var_name = _var_name_from_declarator(decl, source)
                    if var_name:
                        alloc_vars.add(var_name)

    return alloc_vars
