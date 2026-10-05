"""
SMT refinement for bounds-checker findings.

Stage 1 decides whether a guard is sufficient with hand-written rules over the
AST.  Those rules answer a question that is really about machine arithmetic —
can this value be negative, can this product wrap, does a bound established for
`off` still hold for `off + 1` — so each one is an approximation that either
over- or under-reports.  This package asks the same questions of a solver
instead, over bitvectors with C's widths and conversions, which is the only
model in which wraparound and truncation mean what they mean in the kernel.

Direction matters.  Everything the encoder cannot resolve — a call return, a
global, a struct field — becomes an unconstrained bitvector, so UNSAT is the
only sound verdict: if the safety property holds with those free, it holds for
every value they could take.  SAT is therefore not a bug claim, only a
witness, and `unknown` keeps the finding.  Stage 1.7 suppresses on 'safe' and
hands the witness to Stage 2 otherwise.
"""

from bounds_checker.smt.properties import check_finding, SmtResult

__all__ = ['check_finding', 'SmtResult']
