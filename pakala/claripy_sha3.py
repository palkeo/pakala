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

# TODO: we could keep the resulting constraints in cache or something, so it's
# very fast when we don't use the solver with non-empty extra_constraint.


def Sha3(x):
    return bv.BV("SHA3", [x], length=256)


def _symbolize_hashes(ast, hashes):
    if not isinstance(ast, claripy.ast.base.Base):
        return ast

    # Replace SHA3 with a BVS
    if ast.op == "SHA3":
        hash_input, = ast.args
        hash_input = _symbolize_hashes(hash_input, hashes)
        try:
            return hashes[hash_input]
        except KeyError:
            hash_symbol = claripy.BVS("SHA3", 256)
            hashes[hash_input] = hash_symbol
            logger.debug("Registering new hash: %s(%s)", hash_symbol, hash_input)
            return hash_symbol

    # Recursively apply to children
    args = [_symbolize_hashes(child, hashes) for child in ast.args]
    return ast.swap_args(args)


def _no_sha3_symbol(ast):
    if not isinstance(ast, claripy.ast.base.Base):
        return True
    elif isinstance(ast, claripy.ast.base.BV):
        try:
            return not ast.args[0].startswith("SHA3")
        except AttributeError:
            return True
    else:
        return all(_no_sha3_symbol(child) for child in ast.args)


def _no_sha3_symbols(constraints):
    return all(_no_sha3_symbol(ast) for ast in constraints)


class Sha3Mixin(object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hashes = {}  # Mapping hash input to the symbol

    def _copy(self, c):
        super()._copy(c)
        c.hashes = self.hashes.copy()

    def _blank_copy(self, c):
        super()._blank_copy(c)
        c.hashes = {}

    def add(self, constraints, **kwargs):
        if isinstance(constraints, claripy.ast.base.Base):
            constraints = [constraints]
        # TODO: Put the assertion here. Problem is that this is called from
        # inside claripy as well.
        # assert _no_sha3_symbols(constraints)
        constraints = [_symbolize_hashes(c, self.hashes) for c in constraints]
        return super().add(constraints, **kwargs)

    def satisfiable(self, extra_constraints=(), **kwargs):
        # TODO: Put the assertion here. Problem is that this is called from
        # inside claripy as well.
        # assert _no_sha3_symbols(extra_constraints)
        try:
            extra_constraints = self._hash_constraints(
                extra_constraints, hashes=self.hashes.copy()
            )
        except claripy.errors.UnsatError:
            return False
        return super().satisfiable(extra_constraints=extra_constraints)

    def eval(self, e, n, extra_constraints=(), **kwargs):
        assert _no_sha3_symbol(e)
        assert _no_sha3_symbols(extra_constraints)
        hashes = self.hashes.copy()
        e = _symbolize_hashes(e, hashes)
        extra_constraints = self._hash_constraints(extra_constraints, hashes=hashes)
        return super().eval(e, n, extra_constraints=extra_constraints)

    def batch_eval(self, e, n, extra_constraints=(), **kwargs):
        raise NotImplementedError()

    def max(self, e, extra_constraints=(), **kwargs):
        assert _no_sha3_symbol(e)
        assert _no_sha3_symbols(extra_constraints)
        hashes = self.hashes.copy()
        e = _symbolize_hashes(e, hashes)
        extra_constraints = self._hash_constraints(extra_constraints, hashes=hashes)
        return super().max(e, extra_constraints=extra_constraints)

    def min(self, e, extra_constraints=(), **kwargs):
        assert _no_sha3_symbol(e)
        assert _no_sha3_symbols(extra_constraints)
        hashes = self.hashes.copy()
        e = _symbolize_hashes(e, hashes)
        extra_constraints = self._hash_constraints(extra_constraints, hashes=hashes)
        return super().min(e, extra_constraints=extra_constraints)

    def _hash_constraints(self, extra_constraints, hashes, pairs_done=None):
        extra_constraints = [_symbolize_hashes(c, hashes) for c in extra_constraints]

        # Fast-path if no hashes, or if not satisfiable.
        if not hashes or not super().satisfiable(extra_constraints=extra_constraints):
            return tuple(extra_constraints)

        if pairs_done is None:
            pairs_done = set()

        new_extra_constraints = []
        for (in1, s1), (in2, s2) in itertools.combinations(hashes.items(), 2):
            if (s1, s2) in pairs_done:
                continue
            # Do s1 needs to be equal to s2 ? Then in1 needs to be equal to in2
            if not super().satisfiable(
                extra_constraints=extra_constraints + [s1 != s2]
            ):
                new_extra_constraints.append(in1 == in2)
                logger.debug("Added input constraint: %s", in1 == in2)
                pairs_done.add((s1, s2))
                pairs_done.add((s2, s1))
            # Do s1 needs to be != to s2 ? Then in1 needs to be != to in2
            elif not super().satisfiable(
                extra_constraints=extra_constraints + [s1 == s2]
            ):
                new_extra_constraints.append(in1 != in2)
                logger.debug("Added input constraint: %s", in1 != in2)
                pairs_done.add((s1, s2))
                pairs_done.add((s2, s1))

        if new_extra_constraints:
            return self._hash_constraints(
                extra_constraints + new_extra_constraints, hashes, pairs_done
            )

        assert super().satisfiable(extra_constraints=extra_constraints)

        for in1, s1 in hashes.items():
            # Next line can raise UnsatError. Handled in the caller if needed.
            sol1, = super().eval(in1, 1, extra_constraints=extra_constraints)
            extra_constraints.append(in1 == sol1)
            # TODO: use actual hash value! Not this pseudo-hash thing.
            random.seed(sol1)
            extra_constraints.append(s1 == random.randint(0, 2 ** 256 - 1))
            logger.debug("Added concrete constraint: %s", extra_constraints[-1])

        return tuple(extra_constraints)

    def replace(self, r):
        # First replacement: apply r() everywhere.
        self.constraints = [r(i) for i in self.constraints]
        self.hashes = {r(k): r(v) for k, v in self.hashes.items()}
        # Second one: change the hash symbols as well.
        # Also needed in case we re-import constraints before the replacement:
        # the input is different and we don't want the symbols to be the same.
        new_hashes = {k: claripy.BVS("SHA3", 256) for k, v in self.hashes.items()}
        for k in self.hashes:
            r_from, r_to = self.hashes[k], new_hashes[k]
            self.constraints = [i.replace(r_from, r_to) for i in self.constraints]
        self.hashes = new_hashes

        self.downsize()  # Half-assed attempt at clearing caches... TODO improve.

    def combine(self, others):
        combined = super().combine(others)
        combined.hashes.update(self.hashes)

        for other in others:
            for k, v in self.hashes.items():
                # Make sure the symbols are distinct
                assert all(v is not v2 for v2 in other.hashes.values())
                # TODO: Support identical inputs. We just have to make the symbols identical.
                assert all(k is not k2 for k2 in other.hashes.keys())
            combined.hashes.update(other.hashes)

        return combined

    def __repr__(self):
        return "ClaripySha3(constraints=%s, hashes=%s)" % (
            self.constraints,
            self.hashes,
        )

    def as_dict(self):
        return {"constraints": self.constraints, "hashes": self.hashes}


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
    frontends.FullFrontend,
):
    def __init__(self, backend=backends.z3, **kwargs):
        super().__init__(backend, **kwargs)
