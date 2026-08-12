"""
Race-finder specific C parser extensions.

Imports and re-exports all generic parsing utilities from
kernel_analysis.parsers.c_parser so that existing stage-file imports
(e.g. `from race_finder.parsers.c_parser import find_functions`) continue
to work without modification.

Adds race-condition analysis on top: lock classification, struct protection
region scanning, bitfield co-location analysis, VFS inode lock wrappers,
async callback registration detection, lock wrapper discovery, lock event
scanning, TOCTOU detection, and call-site annotation.
"""

import re
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Re-export everything from the shared generic layer.
# Stage files import from this module; keeping these names here means
# no stage file needs to change.
# ---------------------------------------------------------------------------
from kernel_analysis.parsers.c_parser import (  # noqa: F401  (re-exported)
    # Tree-sitter setup
    C_LANGUAGE,
    _parser,
    # Node type sets
    TYPE_NODES,
    DECLARATOR_NODES,
    _TYPEDEF_ATTR_KEYWORDS,
    _WRITE_PARENT_TYPES,
    # Type utilities
    _TYPE_BITS,
    _type_bits,
    _base_struct_name,
    # Parsing helpers
    parse_file,
    node_text,
    strip_comment_delimiters,
    get_source_line,
    _walk,
    # AST helpers
    _find_field_identifier,
    _find_identifier,
    _find_param_list,
    _fn_name_from_def,
    _extract_field_decl_info,
    # Type definition collection
    find_struct_definition,
    collect_type_definitions,
    collect_type_definitions_from_paths,
    # Function discovery and variable typing
    find_functions,
    build_var_type_map,
    # Access classification
    get_access_type,
    find_field_accesses,
    # Generic call finder
    find_calls_to,
    # Local array declarations
    extract_local_array_decls,
    _find_array_declarators,
    # Allocation tracking
    ALLOC_FUNCS,
    _is_alloc_call,
    _var_name_from_declarator,
    find_alloc_vars,
)

# ---------------------------------------------------------------------------
# Race-finder: lock and atomic type classification
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Race-finder: struct annotation patterns
# ---------------------------------------------------------------------------

_PROTECTION_RE = re.compile(r'protected\s+by\s+(\w+)', re.IGNORECASE)
_BEGIN_RE = re.compile(r'begin.*?protected\s+by\s+(\w+)', re.IGNORECASE)
_END_RE = re.compile(r'end.*?protected', re.IGNORECASE)

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

# Embedded structs that are simple link/anchor types; safe to scan through
# when propagating "protects the fields above" annotations.
_SIMPLE_EMBEDDED_STRUCTS = frozenset({
    'list_head', 'hlist_head', 'hlist_node',
    'hlist_bl_head', 'hlist_bl_node',
    'rb_node', 'rb_root', 'rb_root_cached',
    'llist_head', 'llist_node',
    'callback_head',
})

_PREPROC_COND_TYPES = frozenset({
    'preproc_ifdef', 'preproc_ifndef', 'preproc_if',
    'preproc_else', 'preproc_elif',
})


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

    if 'enum' in type_str:
        result['is_state'] = True
    elif base_type == 'bool' or 'bool' in type_str.split():
        result['is_state'] = True
    elif any(k in name_lower for k in ('flag', 'status', 'state', 'mode', 'phase')):
        result['is_state'] = True

    if any(k in name_lower for k in ('count', 'ref', 'users', 'usage')):
        result['is_refcount'] = True
    if 'reference counter' in comment_lower or 'refcount' in comment_lower:
        result['is_refcount'] = True

    return result


def _group_inner_bitfields(inner_fields):
    """
    Group (field_name, type_str, bit_width) tuples into co-located bitfield units.
    Only groups with >=2 members are returned.
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


# ---------------------------------------------------------------------------
# Struct field and protection-region extraction
# ---------------------------------------------------------------------------

def _extract_fields_and_regions(body_node, source):
    """
    Walk a field_declaration_list, extracting fields and tracking protected regions.
    Recurses into #ifdef/#ifndef/#if/#else/#elif blocks.
    Returns (fields_list, regions_list).
    """
    fields = []
    protected_regions = []
    current_lock = None
    current_region_fields = []
    last_field = None

    bf_unit_id = 0
    bf_unit_cap = 0
    bf_unit_used = 0

    def _process(children):
        nonlocal current_lock, current_region_fields, last_field
        nonlocal bf_unit_id, bf_unit_cap, bf_unit_used

        for i, child in enumerate(children):
            if child.type == 'field_declaration':
                type_str, name, bit_width = _extract_field_decl_info(child, source)
                if not name:
                    last_field = child
                    continue

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
                    bf_unit_cap = 0
                    bf_unit_used = 0

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

                if last_field and child.start_point[0] == last_field.start_point[0]:
                    continue

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

                if current_lock and _END_RE.search(comment_text):
                    if current_region_fields:
                        protected_regions.append({
                            'lock': current_lock,
                            'fields': list(current_region_fields),
                        })
                    current_lock = None
                    current_region_fields = []

            elif child.type in _PREPROC_COND_TYPES:
                _process(list(child.children))

    _process(list(body_node.children))

    if current_lock and current_region_fields:
        protected_regions.append({'lock': current_lock, 'fields': list(current_region_fields)})

    return fields, protected_regions


def extract_struct_info(header_path, struct_name, extra_type_map=None):
    """
    Parse header_path and return a structured dict describing struct_name:
      {
        struct_name, file, line,
        fields: [{name, type, line, comment, protection, is_lock?, is_atomic?,
                  is_refcount?, is_state?, bitfield_unit?, bit_width?}],
        locks: [field names that are lock types],
        protected_regions: [{lock, fields: [names]}],
        suspicious_fields: [{name, reason}],
        bitfield_groups: [{fields: [names], protections: [str]}],
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

    field_to_lock = {}
    for region in protected_regions:
        for fname in region['fields']:
            field_to_lock[fname] = region['lock']

    for f in fields:
        if f['name'] in field_to_lock:
            f['protection'] = field_to_lock[f['name']]
        elif f.get('_comment_protection'):
            f['protection'] = f['_comment_protection']
            field_to_lock[f['name']] = f['protection']
        f.pop('_comment_protection', None)

    for i, f in enumerate(fields):
        if not f.get('is_lock'):
            continue
        lock_name = f['name']

        if f.get('_lock_protects_above'):
            for prev in reversed(fields[:i]):
                if prev.get('is_lock'):
                    break
                type_str = prev.get('type') or ''
                if 'struct ' in type_str or 'union ' in type_str:
                    base = type_str.split()[-1].rstrip('*')
                    if base not in _SIMPLE_EMBEDDED_STRUCTS:
                        break
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
    # that contains its own co-located bitfields.  Same-file definitions take
    # precedence over cross-file ones supplied via extra_type_map.
    _same_file = collect_type_definitions(tree, source)
    type_defs = {**(extra_type_map or {}), **_same_file}
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


# ---------------------------------------------------------------------------
# VFS inode / address_space lock wrappers (implied lock field by function name)
# ---------------------------------------------------------------------------

_VFS_LOCK_IMPLIED_FIELD = {
    'inode_lock':                'i_rwsem',
    'inode_lock_nested':         'i_rwsem',
    'inode_lock_shared_nested':  'i_rwsem',
    'inode_lock_killable':       'i_rwsem',
    'inode_trylock':             'i_rwsem',
    'lock_two_nondirectories':   'i_rwsem',
    'inode_lock_shared':         'i_rwsem',
    'inode_lock_shared_killable':'i_rwsem',
    'inode_trylock_shared':      'i_rwsem',
    'filemap_invalidate_lock':       'invalidate_lock',
    'filemap_invalidate_lock_two':   'invalidate_lock',
    'filemap_invalidate_lock_shared':     'invalidate_lock',
    'filemap_invalidate_trylock_shared':  'invalidate_lock',
}

_VFS_UNLOCK_IMPLIED_FIELD = {
    'inode_unlock':                 'i_rwsem',
    'inode_unlock_shared':          'i_rwsem',
    'unlock_two_nondirectories':    'i_rwsem',
    'filemap_invalidate_unlock':        'invalidate_lock',
    'filemap_invalidate_unlock_two':    'invalidate_lock',
    'filemap_invalidate_unlock_shared': 'invalidate_lock',
}

LOCK_FUNCS = frozenset({
    'spin_lock', 'spin_lock_bh', 'spin_lock_irq', 'spin_lock_irqsave',
    'spin_trylock', 'spin_trylock_bh', 'spin_trylock_irq',
    'raw_spin_lock', 'raw_spin_lock_bh', 'raw_spin_lock_irq', 'raw_spin_lock_irqsave',
    'raw_spin_trylock', 'raw_spin_trylock_irq',
    'mutex_lock', 'mutex_lock_interruptible', 'mutex_lock_killable',
    'mutex_lock_nested', 'mutex_lock_io', 'mutex_trylock',
    'read_lock', 'read_lock_bh', 'read_lock_irq', 'read_lock_irqsave',
    'write_lock', 'write_lock_bh', 'write_lock_irq', 'write_lock_irqsave',
    'down_read', 'down_read_interruptible', 'down_read_trylock',
    'down_write', 'down_write_killable', 'down_write_trylock',
    'write_seqlock', 'write_seqlock_irq', 'write_seqlock_irqsave',
    *_VFS_LOCK_IMPLIED_FIELD,
})

UNLOCK_FUNCS = frozenset({
    'spin_unlock', 'spin_unlock_bh', 'spin_unlock_irq', 'spin_unlock_irqrestore',
    'raw_spin_unlock', 'raw_spin_unlock_bh', 'raw_spin_unlock_irq', 'raw_spin_unlock_irqrestore',
    'mutex_unlock',
    'read_unlock', 'read_unlock_bh', 'read_unlock_irq', 'read_unlock_irqrestore',
    'write_unlock', 'write_unlock_bh', 'write_unlock_irq', 'write_unlock_irqrestore',
    'up_read', 'up_write',
    'write_sequnlock', 'write_sequnlock_irq', 'write_sequnlock_irqrestore',
    *_VFS_UNLOCK_IMPLIED_FIELD,
})


# ---------------------------------------------------------------------------
# Lock event extraction
# ---------------------------------------------------------------------------

def _extract_lock_field_from_arg(node, source, lock_field_names):
    """
    Extract the lock field name from a lock/unlock call's first argument.
    Handles: &ses->lock_field, ses->lock_field, &lock_var (global).
    Returns the field name if it's one of lock_field_names, else None.
    """
    if node.type == 'pointer_expression':
        for child in node.children:
            if child.type != '&':
                return _extract_lock_field_from_arg(child, source, lock_field_names)
    if node.type == 'field_expression':
        fid = next((c for c in node.children if c.type == 'field_identifier'), None)
        if fid:
            name = node_text(fid, source)
            return name if name in lock_field_names else None
    if node.type == 'identifier':
        name = node_text(node, source)
        return name if name in lock_field_names else None
    return None


def _extract_param_lock_names(fn_def_node, source):
    """Return the set of parameter names that are pointers to LOCK_TYPES."""
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
    if first.type == 'pointer_expression':
        inner = next((c for c in first.children if c.type == 'identifier'), None)
        if inner:
            return node_text(inner, source) in names
    return False


def find_lock_events(body_node, lock_field_names, source,
                     extra_lock_funcs=None, extra_unlock_funcs=None):
    """
    Recursively find all lock/unlock calls within body_node that reference
    one of our lock fields.
    Returns list of {kind: 'lock'|'unlock', lock_name, fn, line}, sorted by line.
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

        # VFS inode / address_space lock wrappers: implied lock field by function name
        if fn_name in _VFS_LOCK_IMPLIED_FIELD or fn_name in _VFS_UNLOCK_IMPLIED_FIELD:
            implied_map = (_VFS_LOCK_IMPLIED_FIELD if fn_name in eff_lock
                           else _VFS_UNLOCK_IMPLIED_FIELD)
            implied = implied_map.get(fn_name)
            if implied and implied in lock_field_names:
                events.append({
                    'kind': 'lock' if fn_name in eff_lock else 'unlock',
                    'lock_name': implied,
                    'fn': fn_name,
                    'line': node.start_point[0] + 1,
                })
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
    Return the set of lock names held at the given line using a linear scan.
    Events on the same line as the access are counted as prior.
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


# ---------------------------------------------------------------------------
# Lock wrapper discovery
# ---------------------------------------------------------------------------

def find_lock_wrappers(source_paths):
    """
    Scan source files for functions that wrap LOCK_FUNCS or UNLOCK_FUNCS.
    Two passes handle wrappers-of-wrappers.
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
                    break

    return acquire, release


# ---------------------------------------------------------------------------
# Async callback registration detection
# ---------------------------------------------------------------------------

_ASYNC_REGISTRATIONS = {
    'INIT_WORK':             ([1], 'workqueue',    'workqueue handler'),
    'INIT_DELAYED_WORK':     ([1], 'workqueue',    'workqueue delayed handler'),
    'INIT_DEFERRABLE_WORK':  ([1], 'workqueue',    'workqueue deferrable handler'),
    'INIT_WORK_ONSTACK':     ([1], 'workqueue',    'workqueue handler (on-stack)'),
    'call_rcu':              ([1], 'rcu_callback', 'RCU callback; cannot sleep or block'),
    'call_rcu_hurry':        ([1], 'rcu_callback', 'RCU callback (hurry variant)'),
    'timer_setup':           ([1], 'timer',        'timer callback; softirq context'),
    'timer_setup_on_stack':  ([1], 'timer',        'timer callback (on-stack); softirq context'),
    'setup_timer':           ([1], 'timer',        'timer callback (legacy); softirq context'),
    'request_irq':           ([1], 'irq_handler',  'hard IRQ handler'),
    'request_threaded_irq':  ([1, 2], 'irq_handler', 'threaded IRQ handler'),
    'devm_request_irq':      ([2], 'irq_handler',  'device-managed IRQ handler'),
    'tasklet_setup':         ([1], 'tasklet',      'tasklet handler; softirq context'),
    'tasklet_init':          ([1], 'tasklet',      'tasklet handler (legacy); softirq context'),
    'kthread_run':           ([0], 'kthread',      'kernel thread'),
    'kthread_create':        ([0], 'kthread',      'kernel thread'),
    'kthread_run_on_cpu':    ([0], 'kthread',      'kernel thread (pinned to CPU)'),
    'kthread_create_on_node':([0], 'kthread',      'kernel thread (NUMA-local)'),
    'netif_napi_add':        ([2], 'napi_poll',    'NAPI poll handler; softirq context'),
    'netif_napi_add_weight': ([2], 'napi_poll',    'NAPI poll handler (weighted)'),
}


def _extract_fn_ptr_name(node, source):
    """
    Extract a plain function-name identifier from a function-pointer argument.
    Handles: bare identifier, cast_expression wrapping an identifier.
    """
    if node.type == 'identifier':
        return node_text(node, source)
    if node.type == 'cast_expression':
        for child in node.children:
            result = _extract_fn_ptr_name(child, source)
            if result:
                return result
    return None


def find_async_registrations(source_paths):
    """
    Scan source files for registrations of functions as async callbacks.
    Returns {func_name: {'async_kind', 'context_note', 'registrations': [...]}}
    """
    result = {}
    for path in source_paths:
        try:
            tree, source = parse_file(path)
        except Exception:
            continue
        for node in _walk(tree.root_node):
            if node.type != 'call_expression':
                continue
            fn_id = next((c for c in node.children if c.type == 'identifier'), None)
            if not fn_id:
                continue
            reg_name = node_text(fn_id, source)
            reg_info = _ASYNC_REGISTRATIONS.get(reg_name)
            if not reg_info:
                continue
            arg_indices, async_kind, context_note = reg_info

            arg_list = next(
                (c for c in node.children if c.type == 'argument_list'), None
            )
            if not arg_list:
                continue
            args = [c for c in arg_list.children if c.type not in ('(', ')', ',')]

            for idx in arg_indices:
                if idx >= len(args):
                    continue
                fn_name = _extract_fn_ptr_name(args[idx], source)
                if not fn_name or fn_name in ('NULL', '0'):
                    continue
                entry = result.setdefault(fn_name, {
                    'async_kind': async_kind,
                    'context_note': context_note,
                    'registrations': [],
                })
                entry['registrations'].append({
                    'file': str(path),
                    'line': node.start_point[0] + 1,
                    'via': reg_name,
                })

    return result


# ---------------------------------------------------------------------------
# Ops struct / indirect call site scanning
# ---------------------------------------------------------------------------

def find_ops_registrations(source_paths, target_func_names):
    """
    Scan struct initializer lists for .field_name = target_function assignments.
    Returns {func_name: [(file_path, field_name), ...]}
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
    field_name is in the given set.
    Returns {field_name: [{'file', 'caller_fn', 'line', 'locks_held'}, ...]}
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


# ---------------------------------------------------------------------------
# Call site collection (with lock state annotation)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# TOCTOU detection
# ---------------------------------------------------------------------------

def find_toctou_candidates(body_node, target_field_names, alloc_vars, source):
    """
    Find TOCTOU candidate pairs within a function body.
    A 'check' is a field access inside an if/while/for condition.
    A 'use' is any access to the same field in the corresponding body.
    Returns list of {field, obj, check_line, check_snippet,
                     use_line, use_snippet, use_access_type}.
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
