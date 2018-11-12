import logging
import itertools
import collections
import random

from claripy import frontend_mixins
from claripy import frontends
from claripy import backends
from claripy.ast import bv
import claripy

logger = logging.getLogger(__name__)


def Sha3(x):
    return bv.BV('SHA3', [x], length=256)


class Sha3Mixin(object):
    def __init__(self, *args, **kwargs):
        self.hashes = {} # Mapping hash input to the symbol
        super().__init__(*args, **kwargs)

    def _copy(self, c):
        super()._copy(c)
        c.hashes = self.hashes.copy()

    def _blank_copy(self, c):
        super()._blank_copy(c)
        c.hashes = {}

    def symbolize_hashes(self, ast):
        if not isinstance(ast, claripy.ast.base.Base):
            return [], ast

        # Replace SHA3 with a BVS
        if ast.op == 'SHA3':
            hash_input, = ast.args
            try:
                return [hash_input], self.hashes[hash_input]
            except KeyError:
                hash_symbol = claripy.BVS('SHA3', 256)
                self.hashes[hash_input] = hash_symbol
                return [hash_input], hash_symbol

        # Recursively apply to children
        hash_inputs = []
        args = []
        for child in ast.args:
            hash_input, child = self.symbolize_hashes(child)
            hash_inputs += hash_input
            args.append(child)

        return hash_inputs, ast.swap_args(args)

    def _expand_constraints(self, constraints):
        expanded = []
        for constraint in constraints:
            hash_inputs, constraint = self.symbolize_hashes(constraint)
            expanded.append(constraint)

            if not hash_inputs:
                pass
            elif len(hash_inputs) == 2:
                in1, in2 = hash_inputs
                s1, s2 = self.hashes[in1], self.hashes[in2]
                # The beauty here is that it's recursive, so sha3(sha3(...))
                # will also work.
                expanded += self._expand_constraints(
                    [claripy.If(in1 == in2, s1 == s2, False)])
            elif len(hash_inputs) == 1:
                # TODO: get a concrete input value, and compute its hash...
                in1, = hash_inputs
                expanded.append(self.hashes[in1] == random.randint(0, 2**256 - 1))
            else:
                #expanded.append(False)
                #logging.warning("Only two hashes supported now. Constraint was '%r'" % constraint)
                raise ValueError("Only two hashes supported now. Constraint was '%r'" % constraint)
        return expanded

    def add(self, constraints, **kwargs):
        if isinstance(constraints, claripy.ast.base.Base):
            constraints = [constraints]

        expanded_constraints = self._expand_constraints(constraints)
        return super().add(expanded_constraints, **kwargs)

    def _expand_extra_constraints(self, extra_constraints):
        saved_hashes = self.hashes.copy()
        try:
            expanded_constraints = self._expand_constraints(extra_constraints)
        finally:
            self.hashes = saved_hashes
        return tuple(expanded_constraints)

    def satisfiable(self, extra_constraints=(), **kwargs):
        extra_constraints = self._expand_extra_constraints(extra_constraints)
        return super().satisfiable(extra_constraints=extra_constraints)

    def eval(self, e, n, extra_constraints=(), **kwargs):
        extra_constraints = self._expand_extra_constraints(extra_constraints)
        return super().eval(e, n, extra_constraints=extra_constraints)

    def batch_eval(self, e, n, extra_constraints=(), **kwargs):
        raise NotImplementedError()

    def max(self, e, extra_constraints=(), **kwargs):
        extra_constraints = self._expand_extra_constraints(extra_constraints)
        return super().max(e, extra_constraints=extra_constraints)

    def min(self, e, extra_constraints=(), **kwargs):
        extra_constraints = self._expand_extra_constraints(extra_constraints)
        return super().min(e, extra_constraints=extra_constraints)


"""
    def update_hash_constraints(self):
        for in1, s1 in self.hashes.items():
            if s1 not in self.input_constrained:
                self.input_constrained[s1] = False
                super().add(s1 == 0)
                super().add(s1 != 0)

        def mark_constrained(s):
            if not self.input_constrained[s]:
                self.input_constrained[s] = True
                super().remove(s == 0)
                super().remove(s != 0)

        for (in1, s1), (in2, s2) in itertools.combinations(self.hashes.items(), 2):
            if self.input_constrained[s1] and self.input_constrained[s2]:
                continue
            # Do s1 needs to be equal to s2 ? Then in1 needs to be equal to in2
            if not self.satisfiable(extra_constraints=[s1 != s2]):
                mark_constrained(s1)
                mark_constrained(s2)
                self.add(in1 == in2)
            # Do s1 needs to be != to s2 ? Then in1 needs to be != to in2
            elif not self.satisfiable(extra_constraints=[s1 == s2]):
                mark_constrained(s1)
                mark_constrained(s2)
                self.add(in1 != in2)
"""


class Solver(
    Sha3Mixin,
    frontend_mixins.ConstraintFixerMixin,
    frontend_mixins.ConcreteHandlerMixin,
    frontend_mixins.EagerResolutionMixin,
    frontend_mixins.ConstraintFilterMixin,
    frontend_mixins.ConstraintDeduplicatorMixin,
    frontend_mixins.SimplifySkipperMixin,
    frontend_mixins.SatCacheMixin,
    frontend_mixins.ModelCacheMixin,
    frontend_mixins.ConstraintExpansionMixin,
    frontend_mixins.SimplifyHelperMixin,
    frontends.FullFrontend):

    def __init__(self, backend=backends.z3, **kwargs):
        super().__init__(backend, **kwargs)
