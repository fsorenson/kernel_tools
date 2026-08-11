"""
Tree-sitter based C parser utilities for kernel struct/field/lock extraction.

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
    bitfield_clause     — :N  (width extracted for bitfield race detection)
    ;
"""

import re
from collections import defaultdict
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_c

C_LANGUAGE = Language(tree_sitter_c.language())
_parser = Parser(C_LANGUAGE)

# Lock types embedded in structs
LOCK_TYPES = frozenset({
    'spinlock_t', 'raw_spinlock_t',
    'mutex', 'ww_mutex',
    'rwlock_t', 'rw_semaphore', 'rwsem_t',
    'seqlock_t', 'seqcount_t', 'seqcount_spinlock_t',
    'percpu_rwsem', 'srcu_struct',
    'local_lock_t',
})

# Atomic/refcount types
ATOMIC_TYPES = frozenset({
    'atomic_t', 'atomic64_t', 'atomic_long_t',
    'refcount_t', 'kref',
    'local_t', 'local64_t',
})

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

_PROTECTION_RE = re.compile(r'protected\s+by\s+(\w+)', re.IGNORECASE)
_BEGIN_RE = re.compile(r'begin.*?protected\s+by\s+(\w+)', re.IGNORECASE)
_END_RE = re.compile(r'end.*?protected', re.IGNORECASE)

# Reverse-direction lock annotations: the lock comment names what it guards.
# "protect(s) the fields above" → lock covers all non-lock fields above it.
# "protect(s) <word>" → lock covers the named field.
_LOCK_PROTECTS_ABOVE_RE = re.compile(
    r'\bprotects?\s+(?:the\s+)?(?:all\s+)?fields?\s+above\b', re.IGNORECASE
)
_LOCK_PROTECTS_NAMED_RE = re.compile(r'\bprotects?\s+(\w+)', re.IGNORECASE)
_NON_FIELD_WORDS = frozenset({
    'the', 'a', 'an', 'all', 'fields', 'field', 'above', 'below',
    'this', 'its', 'for', 'of', 'on', 'in', 'or', 'and',
})

# "protect the fields above" scans backwards and stops at a complex embedded
# struct.  These common kernel link/anchor structs are simple and safe to
# cross; everything else (embedded objects with their own locking) terminates
# the scan.
_SIMPLE_EMBEDDED_STRUCTS = frozenset({
    'list_head', 'hlist_head', 'hlist_node',
    'hlist_bl_head', 'hlist_bl_node',
    'rb_node', 'rb_root', 'rb_root_cached',
    'llist_head', 'llist_node',
    'callback_head',
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


def _type_bits(type_str):
    """Return the storage-unit size in bits for a bitfield's declared type."""
    if not type_str:
        return 32
    norm = ' '.join(type_str.lower().split())
    for q in ('const ', 'volatile ', 'static ', 'signed '):
        norm = norm.replace(q, '')
    return _TYPE_BITS.get(norm.strip(), 32)


def _group_inner_bitfields(inner_fields):
    """
    Group (field_name, type_str, bit_width) tuples into co-located bitfield units.
    Only groups with >=2 members are returned; each group is a list of those tuples.
    """
    groups = []
    current = []
    bf_cap = 0
    bf_used = 0

    for field_name, type_str, bit_width in inner_fields:
        if bit_width is not None and bit_width > 0:
            cap = _type_bits(type_str)
            if bf_cap == 0 or cap != bf_cap or bf_used + bit_width > bf_cap:
                if len(current) >= 2:
                    groups.append(current)
                current = [(field_name, type_str, bit_width)]
                bf_cap = cap
                bf_used = bit_width
            else:
                current.append((field_name, type_str, bit_width))
                bf_used += bit_width
        else:
            if len(current) >= 2:
                groups.append(current)
            current = []
            bf_cap = 0
            bf_used = 0

    if len(current) >= 2:
        groups.append(current)
    return groups


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
    # Normalize internal whitespace (multi-line comments become one line)
    text = ' '.join(text.split())
    return text


def _find_field_identifier(node, source):
    """Recursively find the innermost field_identifier in a declarator subtree."""
    if node.type == 'field_identifier':
        return node_text(node, source)
    for child in node.children:
        result = _find_field_identifier(child, source)
        if result:
            return result
    return None


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


def _parse_protection(comment_text):
    """Extract lock name from 'protected by <lock>' in a comment string."""
    m = _PROTECTION_RE.search(comment_text)
    return m.group(1) if m else None


def classify_field(field_name, type_str, comment):
    """
    Return a dict of classification flags for a struct field.
    Flags: is_lock, is_atomic, is_refcount, is_state
    """
    if not type_str:
        return {}

    # Extract the base type (last token, strip pointer '*')
    base_type = type_str.split()[-1].rstrip('*').strip()
    name_lower = (field_name or '').lower()
    comment_lower = (comment or '').lower()

    if base_type in LOCK_TYPES:
        return {'is_lock': True}

    if base_type in ATOMIC_TYPES:
        flags = {'is_atomic': True}
        if any(k in name_lower for k in ('count', 'ref', 'users', 'usage')):
            flags['is_refcount'] = True
        return flags

    result = {}

    # State fields: enum types, bool, fields named *flags/*status/*state/*mode
    if 'enum' in type_str:
        result['is_state'] = True
    elif base_type == 'bool' or 'bool' in type_str.split():
        result['is_state'] = True
    elif any(k in name_lower for k in ('flag', 'status', 'state', 'mode', 'phase')):
        result['is_state'] = True

    # Refcount fields: plain int/long named *count/*ref/*users, or comment says so
    if any(k in name_lower for k in ('count', 'ref', 'users', 'usage')):
        result['is_refcount'] = True
    if 'reference counter' in comment_lower or 'refcount' in comment_lower:
        result['is_refcount'] = True

    return result


def find_struct_definition(tree, struct_name, source):
    """
    Find the struct_specifier node for a full struct definition (not forward decl).
    Returns the node, or None.
    """
    # A full definition has a field_declaration_list (body); forward decls don't.
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


def _walk(node):
    """Depth-first walk of all nodes in a tree."""
    yield node
    for child in node.children:
        yield from _walk(child)


_TYPEDEF_ATTR_KEYWORDS = frozenset({
    '__packed', '__aligned', '__attribute__', '__nocast', '__bitwise', '__force',
})


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


def extract_struct_info(header_path, struct_name):
    """
    Parse header_path and return a structured dict describing struct_name:
      {
        struct_name, file, line,
        fields: [{name, type, line, comment, protection, is_lock?, is_atomic?,
                  is_refcount?, is_state?, bitfield_unit?, bit_width?}],
        locks: [field names that are lock types],
        protected_regions: [{lock, fields: [names]}],
        suspicious_fields: [{name, reason}] — unprotected state/refcount fields,
                            plus bitfields co-located in a storage unit with
                            different (or absent) lock protection,
        bitfield_groups: [{fields: [names], protections: [str]}] — groups of
                          consecutive bitfields sharing one storage word,
                          only those with mixed/absent lock protection,
      }
    Returns None if the struct is not found.
    """
    tree, source = parse_file(header_path)
    struct_node = find_struct_definition(tree, struct_name, source)
    if not struct_node:
        return None

    body_node = next(
        (c for c in struct_node.children if c.type == 'field_declaration_list'),
        None
    )
    if not body_node:
        return None

    fields, protected_regions = _extract_fields_and_regions(body_node, source)

    # Build field_name → lock map from explicit regions
    field_to_lock = {}
    for region in protected_regions:
        for fname in region['fields']:
            field_to_lock[fname] = region['lock']

    # Finalize fields: resolve protection, add to lock map if commented
    for f in fields:
        if f['name'] in field_to_lock:
            f['protection'] = field_to_lock[f['name']]
        elif f.get('_comment_protection'):
            f['protection'] = f['_comment_protection']
            field_to_lock[f['name']] = f['protection']
        f.pop('_comment_protection', None)

    # Apply reverse-direction lock hints: lock comment names what it guards.
    for i, f in enumerate(fields):
        if not f.get('is_lock'):
            continue
        lock_name = f['name']

        if f.get('_lock_protects_above'):
            # Walk backwards; stop at another embedded lock or a complex
            # embedded struct (which manages its own locking).
            for prev in reversed(fields[:i]):
                if prev.get('is_lock'):
                    break
                type_str = prev.get('type') or ''
                if 'struct ' in type_str or 'union ' in type_str:
                    base = type_str.split()[-1].rstrip('*')
                    if base not in _SIMPLE_EMBEDDED_STRUCTS:
                        break  # complex embedded object — don't claim it
                if not prev.get('protection'):
                    prev['protection'] = lock_name
                    field_to_lock[prev['name']] = lock_name

        for target_name in f.get('_lock_protects_named', []):
            for other in fields:
                if other['name'] == target_name and not other.get('protection'):
                    other['protection'] = lock_name
                    field_to_lock[target_name] = lock_name
                    break

        f.pop('_lock_protects_above', None)
        f.pop('_lock_protects_named', None)

    # Identify suspicious fields: state or non-atomic refcount with no stated protection
    locks = [f['name'] for f in fields if f.get('is_lock')]
    suspicious = []
    for f in fields:
        if f.get('is_lock') or f.get('is_atomic'):
            continue
        if f.get('protection'):
            continue
        if f.get('is_refcount'):
            suspicious.append({
                'name': f['name'],
                'reason': 'non-atomic refcount with no stated protection',
            })
        elif f.get('is_state'):
            suspicious.append({
                'name': f['name'],
                'reason': 'state/flag field with no stated protection',
            })

    # Bitfield co-location analysis: consecutive bitfields packed into the same
    # storage word race on concurrent writes even when each field is individually
    # "protected" — the compiler emits RMW on the whole word.
    bf_units = defaultdict(list)
    for f in fields:
        uid = f.get('bitfield_unit')
        if uid is not None:
            bf_units[uid].append(f)

    bitfield_groups = []
    existing_suspicious = {s['name'] for s in suspicious}
    for uid, group in sorted(bf_units.items()):
        if len(group) < 2:
            continue
        protections = {f.get('protection') for f in group}
        # All fields share one lock → no co-location race
        if len(protections) == 1 and None not in protections:
            continue
        names = [f['name'] for f in group]
        locks_in_group = sorted({p for p in protections if p})
        if len(locks_in_group) > 1:
            reason_suffix = f'under different locks ({", ".join(locks_in_group)})'
        elif locks_in_group:
            reason_suffix = 'not all fields have stated lock protection'
        else:
            reason_suffix = 'no stated lock protection on any field'
        for f in group:
            if f.get('is_lock') or f.get('is_atomic'):
                continue
            if f['name'] in existing_suspicious:
                continue
            others = ', '.join(n for n in names if n != f['name'])
            suspicious.append({
                'name': f['name'],
                'reason': (
                    f"bitfield shares storage unit with {others}; "
                    f"concurrent RMW writes race on the storage word ({reason_suffix})"
                ),
            })
            existing_suspicious.add(f['name'])
        bitfield_groups.append({
            'fields': names,
            'protections': [str(p) for p in sorted(protections, key=str)],
        })

    # Recursive type expansion: non-bitfield fields whose type is a struct/union
    # defined in this same file and contains its own co-located bitfields.
    type_defs = collect_type_definitions(tree, source)
    for f in fields:
        if f.get('bitfield_unit') is not None:
            continue
        type_str = f.get('type', '')
        inner_name = None
        if type_str in type_defs:
            inner_name = type_str
        else:
            for kw in ('struct ', 'union '):
                idx = type_str.find(kw)
                if idx != -1:
                    parts = type_str[idx + len(kw):].split()
                    if parts:
                        candidate = parts[0].rstrip('*')
                        if candidate in type_defs:
                            inner_name = candidate
                            break
        if inner_name is None:
            continue

        inner_groups = _group_inner_bitfields(type_defs[inner_name])
        if not inner_groups:
            continue

        outer_prot = f.get('protection')
        for grp in inner_groups:
            inner_names = [fn for fn, _, _ in grp]
            dot_names = [f"{f['name']}.{fn}" for fn in inner_names]
            if f['name'] not in existing_suspicious:
                suspicious.append({
                    'name': f['name'],
                    'reason': (
                        f"embedded type '{inner_name}' contains co-located bitfields "
                        f"({', '.join(inner_names)}); concurrent writes to different "
                        f"subfields race on the storage word"
                    ),
                })
                existing_suspicious.add(f['name'])
            bitfield_groups.append({
                'fields': dot_names,
                'protections': [outer_prot or 'none'],
                'embedded_in': f['name'],
                'inner_type': inner_name,
            })

    return {
        'struct_name': struct_name,
        'file': str(header_path),
        'line': struct_node.start_point[0] + 1,
        'fields': fields,
        'locks': locks,
        'protected_regions': protected_regions,
        'suspicious_fields': suspicious,
        'bitfield_groups': bitfield_groups,
    }


_PREPROC_COND_TYPES = frozenset({
    'preproc_ifdef', 'preproc_ifndef', 'preproc_if',
    'preproc_else', 'preproc_elif',
})


def _extract_fields_and_regions(body_node, source):
    """
    Walk a field_declaration_list, extracting fields and tracking protected regions.
    Recurses into #ifdef/#ifndef/#if/#else/#elif blocks so that config-gated
    fields are not silently dropped.  Both branches of a conditional are
    processed (conservative: treats all branches as potentially active).
    Returns (fields_list, regions_list).
    """
    fields = []
    protected_regions = []
    current_lock = None
    current_region_fields = []
    last_field = None  # most recently seen field_declaration node

    # Bitfield storage-unit tracking: consecutive bitfields of the same storage
    # unit size share a unit_id.  A non-bitfield or a type change resets tracking.
    bf_unit_id = 0
    bf_unit_cap = 0   # bits capacity of current unit (0 = not in a bitfield run)
    bf_unit_used = 0  # bits consumed so far in current unit

    def _process(children):
        nonlocal current_lock, current_region_fields, last_field
        nonlocal bf_unit_id, bf_unit_cap, bf_unit_used

        for i, child in enumerate(children):
            if child.type == 'field_declaration':
                type_str, name, bit_width = _extract_field_decl_info(child, source)
                if not name:
                    last_field = child
                    continue

                # Check the very next sibling for a same-line comment
                inline_comment = None
                if i + 1 < len(children):
                    nxt = children[i + 1]
                    if nxt.type == 'comment' and nxt.start_point[0] == child.start_point[0]:
                        inline_comment = strip_comment_delimiters(node_text(nxt, source))

                classification = classify_field(name, type_str, inline_comment)
                field_info = {
                    'name': name,
                    'type': type_str or '',
                    'line': child.start_point[0] + 1,
                    'comment': inline_comment,
                    'protection': None,
                    '_comment_protection': _parse_protection(inline_comment) if inline_comment else None,
                    **classification,
                }

                # Track bitfield storage units for co-location race detection.
                if bit_width is not None and bit_width > 0:
                    cap = _type_bits(type_str)
                    if bf_unit_cap == 0 or cap != bf_unit_cap or bf_unit_used + bit_width > bf_unit_cap:
                        bf_unit_id += 1
                        bf_unit_cap = cap
                        bf_unit_used = bit_width
                    else:
                        bf_unit_used += bit_width
                    field_info['bitfield_unit'] = bf_unit_id
                    field_info['bit_width'] = bit_width
                else:
                    # Non-bitfield (or zero-width pad) resets unit tracking.
                    bf_unit_cap = 0
                    bf_unit_used = 0

                # Reverse-direction: lock comment names what it guards
                if classification.get('is_lock') and inline_comment:
                    if _LOCK_PROTECTS_ABOVE_RE.search(inline_comment):
                        field_info['_lock_protects_above'] = True
                    else:
                        named = [
                            m.group(1) for m in _LOCK_PROTECTS_NAMED_RE.finditer(inline_comment)
                            if m.group(1).lower() not in _NON_FIELD_WORDS
                        ]
                        if named:
                            field_info['_lock_protects_named'] = named

                fields.append(field_info)

                if current_lock and not classification.get('is_lock'):
                    current_region_fields.append(name)

                last_field = child

            elif child.type == 'comment':
                comment_text = strip_comment_delimiters(node_text(child, source))

                # Inline comment for the previous field — already captured above
                if last_field and child.start_point[0] == last_field.start_point[0]:
                    continue

                # Protected region begin marker
                m = _BEGIN_RE.search(comment_text)
                if m:
                    if current_lock and current_region_fields:
                        protected_regions.append({
                            'lock': current_lock,
                            'fields': list(current_region_fields),
                        })
                    current_lock = m.group(1)
                    current_region_fields = []
                    continue

                # Protected region end marker
                if current_lock and _END_RE.search(comment_text):
                    if current_region_fields:
                        protected_regions.append({
                            'lock': current_lock,
                            'fields': list(current_region_fields),
                        })
                    current_lock = None
                    current_region_fields = []

            elif child.type in _PREPROC_COND_TYPES:
                # Recurse into both branches; all are treated as potentially active.
                _process(list(child.children))

            # preproc_def, array/pointer declarators, '{', '}', etc. — skip

    _process(list(body_node.children))

    # Close any unclosed region
    if current_lock and current_region_fields:
        protected_regions.append({'lock': current_lock, 'fields': list(current_region_fields)})

    return fields, protected_regions


# ---------------------------------------------------------------------------
# Stage 2: lock-usage scanner primitives
# ---------------------------------------------------------------------------

LOCK_FUNCS = frozenset({
    # spinlock
    'spin_lock', 'spin_lock_bh', 'spin_lock_irq', 'spin_lock_irqsave',
    'spin_trylock', 'spin_trylock_bh', 'spin_trylock_irq',
    'raw_spin_lock', 'raw_spin_lock_bh', 'raw_spin_lock_irq', 'raw_spin_lock_irqsave',
    'raw_spin_trylock', 'raw_spin_trylock_irq',
    # mutex
    'mutex_lock', 'mutex_lock_interruptible', 'mutex_lock_killable',
    'mutex_lock_nested', 'mutex_lock_io', 'mutex_trylock',
    # rwlock
    'read_lock', 'read_lock_bh', 'read_lock_irq', 'read_lock_irqsave',
    'write_lock', 'write_lock_bh', 'write_lock_irq', 'write_lock_irqsave',
    # rw_semaphore
    'down_read', 'down_read_interruptible', 'down_read_trylock',
    'down_write', 'down_write_killable', 'down_write_trylock',
    # seqlock
    'write_seqlock', 'write_seqlock_irq', 'write_seqlock_irqsave',
})

UNLOCK_FUNCS = frozenset({
    # spinlock
    'spin_unlock', 'spin_unlock_bh', 'spin_unlock_irq', 'spin_unlock_irqrestore',
    'raw_spin_unlock', 'raw_spin_unlock_bh', 'raw_spin_unlock_irq', 'raw_spin_unlock_irqrestore',
    # mutex
    'mutex_unlock',
    # rwlock
    'read_unlock', 'read_unlock_bh', 'read_unlock_irq', 'read_unlock_irqrestore',
    'write_unlock', 'write_unlock_bh', 'write_unlock_irq', 'write_unlock_irqrestore',
    # rw_semaphore
    'up_read', 'up_write',
    # seqlock
    'write_sequnlock', 'write_sequnlock_irq', 'write_sequnlock_irqrestore',
})

# access_type classification based on parent node type
_WRITE_PARENT_TYPES = frozenset({'update_expression', 'compound_assignment_expression'})


def get_access_type(field_expr_node):
    """
    Classify a field_expression access as 'read', 'write', or 'address_of'.
    Uses the parent node and position within it.
    """
    parent = field_expr_node.parent
    if not parent:
        return 'read'
    if parent.type in _WRITE_PARENT_TYPES:
        return 'write'
    if parent.type == 'assignment_expression':
        # Write only if we are the left-hand operand (first non-trivial child)
        lhs = next((c for c in parent.children if c.type not in ('=',)), None)
        return 'write' if lhs == field_expr_node else 'read'
    if parent.type == 'pointer_expression':
        # &ses->field — address-of; could be passed to a function (read or write)
        return 'address_of'
    return 'read'


def get_source_line(source, line_no):
    """Return the text of 1-indexed line_no from source bytes."""
    lines = source.split(b'\n')
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].decode('utf-8', errors='replace').strip()
    return ''


def _fn_name_from_def(fn_def_node, source):
    """Extract function name from a function_definition node."""
    def _search(node):
        if node.type == 'function_declarator':
            # The declarator child (before the parameter list) contains the name
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


def _extract_lock_field_from_arg(node, source, lock_field_names):
    """
    Extract the lock field name from a lock/unlock call's first argument.
    Handles: &ses->lock_field, ses->lock_field, &lock_var (global).
    Returns the field name if it's one of lock_field_names, else None.
    """
    # &X pattern (pointer_expression)
    if node.type == 'pointer_expression':
        for child in node.children:
            if child.type != '&':
                return _extract_lock_field_from_arg(child, source, lock_field_names)
    # ses->lock_field (field_expression)
    if node.type == 'field_expression':
        fid = next((c for c in node.children if c.type == 'field_identifier'), None)
        if fid:
            name = node_text(fid, source)
            return name if name in lock_field_names else None
    # Plain identifier (global lock variable) — only match if in our lock_field_names
    if node.type == 'identifier':
        name = node_text(node, source)
        return name if name in lock_field_names else None
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


def build_var_type_map(fn_def_node, fn_body_node, source):
    """
    Build a variable-name → struct-type-name map for a function.

    Covers function parameters and local declarations of the form
    `struct X *var` or `struct X var`.  Variables whose type cannot be
    statically determined (casts, typedefs, complex initialisers) are
    simply absent from the map, so callers must treat absence as
    "unknown / keep the access".
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
                if child.type in ('pointer_declarator', 'identifier',
                                  'array_declarator'):
                    _add_decl(type_text, child)

    # Local variable declarations (compound_statement descendants)
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


def _extract_param_lock_names(fn_def_node, source):
    """
    Return the set of parameter names that are pointers to LOCK_TYPES.
    E.g., `void foo(struct rw_semaphore *sem, int x)` → {'sem'}.
    """
    lock_params = set()

    param_list = _find_param_list(fn_def_node)
    if not param_list:
        return lock_params

    for param in param_list.children:
        if param.type != 'parameter_declaration':
            continue
        type_text = ''
        param_name = None
        has_pointer = False
        for child in param.children:
            if child.type in TYPE_NODES:
                type_text += ' ' + node_text(child, source)
            elif child.type == 'pointer_declarator':
                has_pointer = True
                param_name = _find_identifier(child, source)
        if not has_pointer or not param_name:
            continue
        base_type = type_text.strip().split()[-1].rstrip('*')
        if base_type in LOCK_TYPES:
            lock_params.add(param_name)

    return lock_params


def _call_first_arg_in(call_node, source, names):
    """
    Return True if the first argument of a call_expression is an identifier
    (or &identifier) whose name is in `names`.
    """
    args = next((c for c in call_node.children if c.type == 'argument_list'), None)
    if not args:
        return False
    first = next((c for c in args.children if c.type not in ('(', ')', ',')), None)
    if not first:
        return False
    if first.type == 'identifier':
        return node_text(first, source) in names
    # &param (unusual for pointer args, but handle it)
    if first.type == 'pointer_expression':
        inner = next((c for c in first.children if c.type == 'identifier'), None)
        if inner:
            return node_text(inner, source) in names
    return False


def find_lock_wrappers(source_paths):
    """
    Scan source files for functions that wrap LOCK_FUNCS or UNLOCK_FUNCS.

    A wrapper takes at least one lock-type pointer parameter and calls a
    known LOCK_FUNC (or UNLOCK_FUNC) with that parameter as the first
    argument.  Two passes handle wrappers-of-wrappers.

    Returns (acquire_wrappers: set[str], release_wrappers: set[str]).
    """
    acquire = set()
    release = set()

    for _pass in range(2):
        effective_lock = LOCK_FUNCS | acquire
        effective_unlock = UNLOCK_FUNCS | release

        for path in source_paths:
            try:
                tree, source = parse_file(path)
            except Exception:
                continue
            for fn in find_functions(tree, source):
                name = fn['name']
                if name in acquire or name in release:
                    continue
                lock_params = _extract_param_lock_names(fn['node'], source)
                if not lock_params:
                    continue
                for node in _walk(fn['body']):
                    if node.type != 'call_expression':
                        continue
                    fn_id = next(
                        (c for c in node.children if c.type == 'identifier'), None
                    )
                    if not fn_id:
                        continue
                    called = node_text(fn_id, source)
                    if called not in effective_lock and called not in effective_unlock:
                        continue
                    if not _call_first_arg_in(node, source, lock_params):
                        continue
                    if called in effective_lock:
                        acquire.add(name)
                    else:
                        release.add(name)
                    break  # one qualifying call is enough to classify

    return acquire, release


def find_ops_registrations(source_paths, target_func_names):
    """
    Scan struct initializer lists for function-pointer assignments of the form
    `.field_name = target_function`.

    Returns {func_name: [(file_path, field_name), ...]} covering every ops
    struct (smb_version_operations, etc.) that registers one of the target
    functions.
    """
    from collections import defaultdict as _dd
    registrations = _dd(list)
    for path in source_paths:
        try:
            tree, source = parse_file(path)
        except Exception:
            continue
        for node in _walk(tree.root_node):
            if node.type != 'initializer_pair':
                continue
            field_name = None
            func_name = None
            for child in node.children:
                if child.type == 'field_designator':
                    fid = next(
                        (c for c in child.children if c.type == 'field_identifier'),
                        None,
                    )
                    if fid:
                        field_name = node_text(fid, source)
                elif child.type == 'identifier':
                    func_name = node_text(child, source)
            if field_name and func_name and func_name in target_func_names:
                registrations[func_name].append((str(path), field_name))
    return dict(registrations)


def find_indirect_call_sites(source_paths, field_names,
                              extra_lock_funcs=None, extra_unlock_funcs=None):
    """
    Find indirect call sites of the form ``expr->field_name(...)`` where
    ``field_name`` is in the given set.  Used to resolve function-pointer
    dispatch (e.g. ``server->ops->set_fid()``) back to callers.

    Lock state is tracked using *raw argument text* as the key (not struct
    field names) because the callers are in different translation units and
    may hold locks on unrelated structs.  The raw text (e.g.
    ``&cinode->open_file_lock``) gives the LLM enough context to reason.

    Returns {field_name: [{'file', 'caller_fn', 'line', 'locks_held'}, ...]}
    where ``locks_held`` is a sorted list of raw argument strings.
    """
    from collections import defaultdict as _dd
    eff_lock = LOCK_FUNCS | (extra_lock_funcs or set())
    eff_unlock = UNLOCK_FUNCS | (extra_unlock_funcs or set())
    sites = _dd(list)

    for path in source_paths:
        try:
            tree, source = parse_file(path)
        except Exception:
            continue
        for fn in find_functions(tree, source):
            body = fn['body']

            # Track all lock/unlock events by raw first-argument text.
            raw_events = []
            for node in _walk(body):
                if node.type != 'call_expression':
                    continue
                fn_id = next((c for c in node.children if c.type == 'identifier'), None)
                if not fn_id:
                    continue
                callee = node_text(fn_id, source)
                if callee not in eff_lock and callee not in eff_unlock:
                    continue
                args = next((c for c in node.children if c.type == 'argument_list'), None)
                if not args:
                    continue
                first = next(
                    (c for c in args.children if c.type not in ('(', ')', ',')), None
                )
                if not first:
                    continue
                raw_events.append({
                    'kind': 'lock' if callee in eff_lock else 'unlock',
                    'key': node_text(first, source),
                    'line': node.start_point[0] + 1,
                })
            raw_events.sort(key=lambda e: e['line'])

            def _raw_held_at(line):
                held = {}
                for ev in raw_events:
                    if ev['line'] > line:
                        break
                    if ev['kind'] == 'lock':
                        held[ev['key']] = True
                    else:
                        held.pop(ev['key'], None)
                return sorted(held)

            # Find indirect calls: call_expression whose function part is a
            # field_expression ending in one of our target field names.
            for node in _walk(body):
                if node.type != 'call_expression':
                    continue
                fn_part = next(
                    (c for c in node.children if c.type != 'argument_list'), None
                )
                if not fn_part or fn_part.type != 'field_expression':
                    continue
                fid = next(
                    (c for c in fn_part.children if c.type == 'field_identifier'), None
                )
                if not fid:
                    continue
                field_name = node_text(fid, source)
                if field_name not in field_names:
                    continue
                line = node.start_point[0] + 1
                sites[field_name].append({
                    'file': str(path),
                    'caller_fn': fn['name'],
                    'line': line,
                    'locks_held': _raw_held_at(line),
                })
    return dict(sites)


def find_lock_events(body_node, lock_field_names, source,
                     extra_lock_funcs=None, extra_unlock_funcs=None):
    """
    Recursively find all lock/unlock calls within body_node that reference
    one of our lock fields.
    Returns list of {kind: 'lock'|'unlock', lock_name, fn, line}, sorted by line.
    extra_lock_funcs / extra_unlock_funcs extend the built-in sets with
    discovered wrapper functions.
    """
    eff_lock = LOCK_FUNCS | (extra_lock_funcs or set())
    eff_unlock = UNLOCK_FUNCS | (extra_unlock_funcs or set())
    events = []
    for node in _walk(body_node):
        if node.type != 'call_expression':
            continue
        fn_id = next((c for c in node.children if c.type == 'identifier'), None)
        if not fn_id:
            continue
        fn_name = node_text(fn_id, source)
        if fn_name not in eff_lock and fn_name not in eff_unlock:
            continue
        args = next((c for c in node.children if c.type == 'argument_list'), None)
        if not args:
            continue
        first_arg = next((c for c in args.children if c.type not in ('(', ')', ',')), None)
        if not first_arg:
            continue
        lock_name = _extract_lock_field_from_arg(first_arg, source, lock_field_names)
        if lock_name:
            events.append({
                'kind': 'lock' if fn_name in eff_lock else 'unlock',
                'lock_name': lock_name,
                'fn': fn_name,
                'line': node.start_point[0] + 1,
            })
    return sorted(events, key=lambda e: e['line'])


def lock_state_at(events, line):
    """
    Given sorted lock events for a function, return the set of lock names
    held at the given line using a linear (branch-insensitive) scan.
    Events that occur on the same line as the access are counted as prior.
    """
    held = set()
    for ev in events:
        if ev['line'] > line:
            break
        if ev['kind'] == 'lock':
            held.add(ev['lock_name'])
        else:
            held.discard(ev['lock_name'])
    return held


ALLOC_FUNCS = frozenset({
    # Core slab/page allocators
    'kmalloc', 'kzalloc', 'kcalloc', 'kmalloc_node', 'kzalloc_node',
    'kmalloc_array', 'kmalloc_array_node', 'kmalloc_large',
    'kzalloc_obj', 'kzalloc_objs',           # newer typed-alloc wrappers
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

    Handles three patterns:
      var = alloc_func(...)                         assignment_expression
      var = (type *)alloc_func(...)                 assignment through cast
      struct X *var = alloc_func(...)               init_declarator in declaration

    Returns a set of variable name strings.  These variables hold newly-allocated
    objects that have not yet been published, so accessing their fields does not
    require the struct's locks to be held.
    """
    alloc_vars = set()

    for node in _walk(fn_body):
        if node.type == 'assignment_expression':
            # Children: [lhs, '=', rhs]  — simple assignment only, not +=/-= etc.
            children = node.children
            if len(children) == 3 and children[1].type == '=':
                lhs, _, rhs = children
                if lhs.type == 'identifier' and _is_alloc_call(rhs, source):
                    alloc_vars.add(node_text(lhs, source))

        elif node.type == 'init_declarator':
            # Children: [declarator, '=', initializer]
            children = node.children
            if len(children) == 3 and children[1].type == '=':
                decl, _, rhs = children
                if _is_alloc_call(rhs, source):
                    var_name = _var_name_from_declarator(decl, source)
                    if var_name:
                        alloc_vars.add(var_name)

    return alloc_vars


def collect_call_sites(body_node, lock_events, source):
    """
    Find all direct function calls within body_node, annotated with the lock
    state at each call site.  Lock/unlock primitives themselves are excluded.
    Returns list of {'callee', 'line', 'locks_held'}.
    """
    sites = []
    for node in _walk(body_node):
        if node.type != 'call_expression':
            continue
        fn_id = next((c for c in node.children if c.type == 'identifier'), None)
        if not fn_id:
            continue
        callee = node_text(fn_id, source)
        if callee in LOCK_FUNCS or callee in UNLOCK_FUNCS:
            continue
        line = node.start_point[0] + 1
        held = lock_state_at(lock_events, line)
        sites.append({
            'callee': callee,
            'line': line,
            'locks_held': sorted(held),
        })
    return sites


def find_toctou_candidates(body_node, target_field_names, alloc_vars, source):
    """
    Find TOCTOU candidate pairs within a function body.

    A 'check' is any field access inside an if/while/for condition.
    A 'use' is any access to the same field in the corresponding body.
    Pairs where the struct object is a freshly-allocated variable are excluded.

    Returns list of {field, obj, check_line, check_snippet,
                     use_line, use_snippet, use_access_type}.
    Deduplication by (field, check_line, use_line, use_access_type) is applied.
    """
    seen = set()
    candidates = []

    for ctrl in _walk(body_node):
        if ctrl.type not in ('if_statement', 'while_statement', 'for_statement'):
            continue

        cond_node = ctrl.child_by_field_name('condition')
        if cond_node is None:
            continue

        body_n = ctrl.child_by_field_name(
            'consequence' if ctrl.type == 'if_statement' else 'body'
        )
        if body_n is None:
            continue

        cond_accesses = [
            a for a in find_field_accesses(cond_node, target_field_names, source)
            if a['obj'] not in alloc_vars
        ]
        if not cond_accesses:
            continue

        body_accesses = [
            a for a in find_field_accesses(body_n, target_field_names, source)
            if a['obj'] not in alloc_vars
        ]
        if not body_accesses:
            continue

        for check_acc in cond_accesses:
            for use_acc in body_accesses:
                if use_acc['field'] != check_acc['field']:
                    continue
                key = (check_acc['field'], check_acc['line'],
                       use_acc['line'], use_acc['access_type'])
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    'field': check_acc['field'],
                    'obj': check_acc['obj'],
                    'check_line': check_acc['line'],
                    'check_snippet': check_acc['snippet'],
                    'use_line': use_acc['line'],
                    'use_snippet': use_acc['snippet'],
                    'use_access_type': use_acc['access_type'],
                })

    return candidates


def find_field_accesses(body_node, target_field_names, source):
    """
    Recursively find all field_expression nodes in body_node where the
    field name is in target_field_names.

    Matches by field name only (no variable type tracking), so some false
    positives are possible for generic field names.

    Returns list of {field, obj_text, line, access_type, snippet}.
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
        # Object: the expression before -> or .
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
