"""
The path condition and assignment chain leading to one sink.

A structured walk down to the sink statement, descending only into the arms
the path takes and merging the ones it may or may not take.  Nothing here
searches for paths: the taint walk already chose one, and this reconstructs
the facts that hold along it.

Where the walk cannot model a write it unbinds the variable rather than
guessing, which costs precision but never soundness in the UNSAT direction.
"""

import re
from collections import namedtuple

import z3

from kernel_analysis.parsers.c_parser import _walk, node_text
from bounds_checker.parsers.taint_scanner import _has_terminal, _label_lines
from bounds_checker.smt.encoder import (
    Encoder, Value, build_decl_types, usual_conversions,
)


_COMPOUND = {
    '+=': '+', '-=': '-', '*=': '*', '/=': '/', '%=': '%',
    '&=': '&', '|=': '|', '^=': '^', '<<=': '<<', '>>=': '>>',
}

_LOOPS = frozenset({'for_statement', 'while_statement', 'do_statement'})

_CMP_OPS = frozenset({'<', '<=', '>', '>=', '==', '!='})

# A guard, plus what can be said about its individual clauses.  `definite` is
# the subset of comparisons that hold on their own given which way the branch
# went — a clause under `||` taken true says nothing by itself, while the same
# clause under a negated `||` does.
Guard = namedtuple('Guard', 'node assume_true env definite')


class Path:
    """Encoder state plus the conditions that hold at the sink."""

    def __init__(self, encoder, conditions, guards):
        self.enc = encoder
        self.conditions = conditions    # [z3.BoolRef]
        # [Guard] parallel to conditions.  The env snapshot is what lets a
        # bound be followed to the sink: a guard constrains the term the
        # variable held then, not the name.
        self.guards = guards

    def assumptions(self):
        return list(self.enc.facts) + list(self.conditions)

    def solver(self, timeout_ms=200):
        s = z3.Solver()
        s.set('timeout', timeout_ms)
        for a in self.assumptions():
            s.add(a)
        return s


def _span(node):
    return node.start_point[0] + 1, node.end_point[0] + 1


def _contains(node, line):
    lo, hi = _span(node)
    return lo <= line <= hi


def _assign_op(node, source):
    for c in node.children:
        if not c.is_named:
            t = node_text(c, source)
            if t == '=' or t in _COMPOUND:
                return t
    return '='


def _written(node, source):
    """
    (names, field names) the subtree writes, for the cases the walk will not
    model.  A write through `a->b` is attributed to `b` alone: which object it
    landed on is exactly what the encoder cannot tell, so every cached field of
    that name has to go.
    """
    names, fields = set(), set()

    def note(target):
        if target is None:
            return
        if target.type == 'identifier':
            names.add(node_text(target, source))
        elif target.type == 'field_expression':
            f = target.child_by_field_name('field')
            if f is not None:
                fields.add(node_text(f, source))

    for n in _walk(node):
        if n.type == 'assignment_expression':
            note(n.child_by_field_name('left'))
        elif n.type == 'update_expression':
            note(n.child_by_field_name('argument'))
        elif n.type == 'init_declarator':
            note(n.child_by_field_name('declarator'))
    return names, fields


def _assigned_names(node, source):
    return _written(node, source)[0]


_FIELD_SEP = ('->', '.')


def _depends_on(key, names):
    """Whether a cached field access reads through any of these variables."""
    return bool(names & set(re.findall(r'[A-Za-z_]\w*', key)))


def _last_field(key):
    return key.rsplit('.', 1)[-1].rsplit('->', 1)[-1]


class _Walker:
    def __init__(self, fn_body, source, sink_line, decl_types,
                 fields=None, var_types=None):
        self.fn_body = fn_body
        self.source = source
        self.sink = sink_line
        self.enc = Encoder(source, decl_types, fields, var_types)
        self.conditions = []
        self.guards = []
        self.labels = _label_lines(fn_body, source)

    # -- helpers ----------------------------------------------------------

    def _text(self, node):
        return node_text(node, self.source)

    def _clobber(self, node):
        names, fields = _written(node, self.source)
        for name in names:
            self.enc.env.pop(name, None)
            self.enc.lost.add(name)
        for key in list(self.enc.env):
            if not any(sep in key for sep in _FIELD_SEP):
                continue
            if _depends_on(key, names) or _last_field(key) in fields:
                self.enc.env.pop(key, None)

    def _bind(self, name, value_node, op):
        rhs = self.enc.encode(value_node)
        if op != '=':
            cur = self.enc.read_var(name)
            l, r, width, signed = usual_conversions(cur, rhs)
            build = {
                '+': lambda: l.bv + r.bv, '-': lambda: l.bv - r.bv,
                '*': lambda: l.bv * r.bv, '&': lambda: l.bv & r.bv,
                '|': lambda: l.bv | r.bv, '^': lambda: l.bv ^ r.bv,
                '<<': lambda: l.bv << r.bv,
                '>>': lambda: (l.bv >> r.bv) if signed else z3.LShR(l.bv, r.bv),
            }.get(_COMPOUND[op])
            if build is None:
                self.enc.env.pop(name, None)
                return
            rhs = Value(build(), width, signed)
        self.enc.bind(name, rhs)

    def _polarity(self, if_node):
        """
        Which way the condition went for control to reach the sink, or None
        when the sink is past a join and both arms could have run.
        """
        then = if_node.child_by_field_name('consequence')
        other = if_node.child_by_field_name('alternative')
        if then is not None and _contains(then, self.sink):
            return True
        if other is not None and _contains(other, self.sink):
            return False
        if then is not None and _has_terminal(then, self.source,
                                              self.labels, self.sink):
            return False
        if other is not None and _has_terminal(other, self.source,
                                               self.labels, self.sink):
            return True
        return None

    def _definite(self, node, want, out):
        """Comparisons that individually hold when the branch went `want`."""
        if node is None:
            return
        if node.type == 'parenthesized_expression':
            inner = [c for c in node.children if c.is_named]
            if inner:
                self._definite(inner[0], want, out)
            return
        if node.type == 'unary_expression' and self._text(
                node.children[0] if node.children else node) == '!':
            self._definite(node.child_by_field_name('argument'), not want, out)
            return
        if node.type == 'binary_expression' and len(node.children) >= 3:
            op = node.children[1].type
            if (op == '&&' and want) or (op == '||' and not want):
                self._definite(node.child_by_field_name('left'), want, out)
                self._definite(node.child_by_field_name('right'), want, out)
                return
            if op in _CMP_OPS:
                pred = self.enc.cond(node)
                out.append((node, want, pred if want else z3.Not(pred)))
            return
        if node.type == 'call_expression':
            # likely()/unlikely() and friends wrap the real comparison.
            args = node.child_by_field_name('arguments')
            inner = [c for c in args.children if c.is_named] if args else []
            if len(inner) == 1:
                self._definite(inner[0], want, out)

    def _short_circuit(self, node):
        """
        Conjuncts that must have held for evaluation to reach the sink.

        `len > 0 && !strncmp(a, b, len)` guards the call with the first
        operand, and the branch the whole condition controls has not been
        decided yet when the sink runs.
        """
        for n in _walk(node):
            if n.type != 'binary_expression' or len(n.children) < 3:
                continue
            op = n.children[1].type
            if op not in ('&&', '||'):
                continue
            left = n.child_by_field_name('left')
            right = n.child_by_field_name('right')
            if left is None or right is None:
                continue
            if not _contains(right, self.sink) or _contains(left, self.sink):
                continue
            want = op == '&&'
            pred = self.enc.cond(left)
            self.conditions.append(pred if want else z3.Not(pred))
            definite = []
            self._definite(left, want, definite)
            self.guards.append(
                Guard(left, want, dict(self.enc.env), definite))

    def _loop_floor(self, node):
        """
        `for (i = 0; ...; i++)` only ever moves i up, so whichever iteration
        reaches the sink has i at or above where it started.  Modelling a
        single arbitrary iteration otherwise lets a counter run negative,
        which no amount of guarding inside the body can rule out.
        """
        upd = node.child_by_field_name('update')
        if upd is None or upd.type != 'update_expression':
            return
        if next((self._text(c) for c in upd.children if not c.is_named), '') != '++':
            return
        arg = upd.child_by_field_name('argument')
        if arg is None or arg.type != 'identifier':
            return
        name = self._text(arg)

        init = node.child_by_field_name('initializer')
        start = None
        if init is None:
            return
        if init.type == 'assignment_expression':
            lhs = init.child_by_field_name('left')
            if (lhs is not None and lhs.type == 'identifier'
                    and self._text(lhs) == name):
                start = init.child_by_field_name('right')
        elif init.type == 'declaration':
            for c in init.children:
                if c.type != 'init_declarator':
                    continue
                d = c.child_by_field_name('declarator')
                if (d is not None and d.type == 'identifier'
                        and self._text(d) == name):
                    start = c.child_by_field_name('value')
        if start is None:
            return

        body = node.child_by_field_name('body')
        if body is not None and name in _assigned_names(body, self.source):
            return
        cur, floor, _, signed = usual_conversions(
            self.enc.read_var(name), self.enc.encode(start))
        self.enc.facts.append(self.enc.compare('>=', cur, floor, signed))

    def _merge(self, cond, then_env, else_env):
        """
        phi for a branch the path may have taken either way.

        A variable only one arm writes still needs the other arm's value, so
        the pre-branch binding is the default; one that neither arm resolves
        is dropped.
        """
        names = set(then_env) | set(else_env)
        for name in names:
            a, b = then_env.get(name), else_env.get(name)
            if a is None or b is None:
                self.enc.env.pop(name, None)
                continue
            if a.bv.eq(b.bv):
                self.enc.env[name] = a
                continue
            if name in self.enc.decl:
                width, signed = self.enc.declared(name)
            else:
                # A field access, keyed by its text: both arms wrote the same
                # storage, so the type either of them carries is that storage's.
                width, signed = max(a.width, b.width), a.signed and b.signed
            from bounds_checker.smt.encoder import _resize
            self.enc.env[name] = Value(
                z3.If(cond, _resize(a, width), _resize(b, width)),
                width, signed, a.guessed or b.guessed)

    # -- statement dispatch -----------------------------------------------

    def block(self, node):
        """Walk a statement or block, stopping at the sink. True = reached it."""
        for stmt in (node.children
                     if node.type in ('compound_statement', 'case_statement')
                     else [node]):
            if not stmt.is_named:
                continue
            lo, hi = _span(stmt)
            if lo > self.sink:
                return True
            if lo == self.sink or (lo < self.sink <= hi
                                   and not self._descends(stmt)):
                # Anything this statement writes on the way to the sink is not
                # being tracked, so it stops standing for a known value.
                self._clobber(stmt)
                self._short_circuit(stmt)
                return True
            if self.stmt(stmt):
                return True
        return False

    @staticmethod
    def _descends(stmt):
        # Loops go to stmt() rather than stopping here so that a sink inside
        # one still loses the values the loop body rewrites.
        return (stmt.type in ('if_statement', 'compound_statement',
                              'labeled_statement', 'switch_statement')
                or stmt.type in _LOOPS)

    def stmt(self, node):
        t = node.type

        if t == 'compound_statement':
            return self.block(node)

        if t == 'labeled_statement':
            # A goto can land here from anywhere, so nothing established above
            # is known to hold.
            self.enc.lost.update(self.enc.env)
            self.enc.env.clear()
            inner = [c for c in node.children if c.is_named][-1:]
            return self.block(inner[0]) if inner else False

        if t == 'if_statement':
            return self.if_stmt(node)

        if t in _LOOPS:
            # Nothing the loop writes carries a known value into the iteration
            # that reaches the sink, but within that iteration the controlling
            # test and the guards above the sink hold like any others.
            self._clobber(node)
            if not _contains(node, self.sink):
                return False
            self._loop_floor(node)
            cond = node.child_by_field_name('condition')
            if (t != 'do_statement' and cond is not None
                    and not _contains(cond, self.sink)):
                pred = self.enc.cond(cond)
                self.conditions.append(pred)
                definite = []
                self._definite(cond, True, definite)
                self.guards.append(
                    Guard(cond, True, dict(self.enc.env), definite))
            body = node.child_by_field_name('body')
            return self.block(body) if body is not None else True

        if t == 'switch_statement':
            # Which arm ran is decided by the switch value, but once inside the
            # arm holding the sink the guards before it dominate normally.
            # Other arms, and fallthrough from them, stay unmodelled.
            self._clobber(node)
            body = node.child_by_field_name('body')
            if body is not None:
                for arm in body.children:
                    if arm.type == 'case_statement' and _contains(arm, self.sink):
                        return self.block(arm)
            return _contains(node, self.sink)

        if t == 'declaration':
            for child in node.children:
                if child.type != 'init_declarator':
                    continue
                decl = child.child_by_field_name('declarator')
                value = child.child_by_field_name('value')
                if decl is not None and decl.type == 'identifier' and value is not None:
                    self._bind(self._text(decl), value, '=')
            return False

        if t == 'expression_statement':
            inner = [c for c in node.children if c.is_named]
            if inner and inner[0].type == 'assignment_expression':
                a = inner[0]
                lhs = a.child_by_field_name('left')
                if lhs is not None and lhs.type == 'identifier':
                    self._bind(self._text(lhs),
                               a.child_by_field_name('right'),
                               _assign_op(a, self.source))
                else:
                    self._clobber(a)
            elif inner:
                self._clobber(inner[0])
            return False

        self._clobber(node)
        return False

    def if_stmt(self, node):
        cond_node = node.child_by_field_name('condition')
        then = node.child_by_field_name('consequence')
        other = node.child_by_field_name('alternative')
        if cond_node is None:
            return _contains(node, self.sink)

        if _contains(cond_node, self.sink):
            self._short_circuit(cond_node)
            return True

        pred = self.enc.cond(cond_node)
        want = self._polarity(node)

        if want in (True, False):
            self.conditions.append(pred if want else z3.Not(pred))
            definite = []
            self._definite(cond_node, want, definite)
            self.guards.append(
                Guard(cond_node, want, dict(self.enc.env), definite))
            arm = then if want else other
            return self.block(arm) if arm is not None else False

        # Control rejoins below: take both arms and merge.
        before = dict(self.enc.env)
        if then is not None:
            self.block(then)
        then_env = dict(self.enc.env)

        self.enc.env = dict(before)
        if other is not None:
            self.block(other)
        else_env = dict(self.enc.env)

        self.enc.env = dict(before)
        self._merge(pred, then_env, else_env)
        return False


def build_path(fn_body, source, sink_line, decl_types=None,
               fields=None, var_types=None):
    w = _Walker(fn_body, source, sink_line,
                decl_types or build_decl_types(fn_body, source),
                fields, var_types)
    w.block(fn_body)
    return Path(w.enc, w.conditions, w.guards)
