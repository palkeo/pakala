import logging
import itertools

from claripy.ast import bv
import claripy
import eth_utils


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


def get_claripy_solver():
    # TODO: What about SolverComposite? Tried, and seems slower.
    return claripy.Solver()


class Solver:
    __slots__ = ["solver", "hashes"]

    def __init__(self, claripy_solver=None, hashes=None):
        self.solver = claripy_solver or get_claripy_solver()
        self.hashes = hashes or {}  # Mapping hash input to the symbol

    def branch(self):
        return Solver(claripy_solver=self.solver.branch(), hashes=self.hashes.copy())

    def add(self, constraints, **kwargs):
        if isinstance(constraints, claripy.ast.base.Base):
            constraints = [constraints]
        assert _no_sha3_symbols(constraints)
        constraints = [_symbolize_hashes(c, self.hashes) for c in constraints]
        return self.solver.add(constraints, **kwargs)

    def satisfiable(self, extra_constraints=(), **kwargs):
        assert _no_sha3_symbols(extra_constraints)
        try:
            extra_constraints = self._hash_constraints(
                extra_constraints, hashes=self.hashes.copy()
            )
        except claripy.errors.UnsatError:
            return False
        return self.solver.satisfiable(extra_constraints=extra_constraints)

    def eval(self, e, n, extra_constraints=(), **kwargs):
        assert _no_sha3_symbol(e)
        assert _no_sha3_symbols(extra_constraints)
        hashes = self.hashes.copy()
        e = _symbolize_hashes(e, hashes)
        extra_constraints = self._hash_constraints(extra_constraints, hashes=hashes)
        return self.solver.eval(e, n, extra_constraints=extra_constraints)

    def batch_eval(self, e, n, extra_constraints=(), **kwargs):
        raise NotImplementedError()

    def max(self, e, extra_constraints=(), **kwargs):
        assert _no_sha3_symbol(e)
        assert _no_sha3_symbols(extra_constraints)
        hashes = self.hashes.copy()
        e = _symbolize_hashes(e, hashes)
        extra_constraints = self._hash_constraints(extra_constraints, hashes=hashes)
        return self.solver.max(e, extra_constraints=extra_constraints)

    def min(self, e, extra_constraints=(), **kwargs):
        assert _no_sha3_symbol(e)
        assert _no_sha3_symbols(extra_constraints)
        hashes = self.hashes.copy()
        e = _symbolize_hashes(e, hashes)
        extra_constraints = self._hash_constraints(extra_constraints, hashes=hashes)
        return self.solver.min(e, extra_constraints=extra_constraints)

    def solution(self, e, v, extra_constraints=(), **kwargs):
        assert _no_sha3_symbol(e)
        assert _no_sha3_symbols(extra_constraints)
        hashes = self.hashes.copy()
        e = _symbolize_hashes(e, hashes)
        extra_constraints = self._hash_constraints(extra_constraints, hashes=hashes)
        return self.solver.solution(e, v, extra_constraints=extra_constraints)

    def _hash_constraints(self, extra_constraints, hashes, pairs_done=None):
        extra_constraints = [_symbolize_hashes(c, hashes) for c in extra_constraints]

        # Fast-path if no hashes, or if not satisfiable.
        if not hashes or not self.solver.satisfiable(
            extra_constraints=extra_constraints
        ):
            return tuple(extra_constraints)

        if pairs_done is None:
            pairs_done = set()

        new_extra_constraints = []
        for (in1, s1), (in2, s2) in itertools.combinations(hashes.items(), 2):
            if (s1, s2) in pairs_done:
                continue
            # Do s1 needs to be equal to s2 ? Then in1 needs to be equal to in2
            if not self.solver.satisfiable(
                extra_constraints=extra_constraints + [s1 != s2]
            ):
                logger.debug("Adding input constraint: %s == %s", in1, in2)
                if in1.size() == in2.size():
                    new_extra_constraints.append(in1 == in2)
                else:
                    new_extra_constraints.append(False)
                pairs_done.add((s1, s2))
                pairs_done.add((s2, s1))
            # Do s1 needs to be != to s2 ? Then in1 needs to be != to in2
            elif not self.solver.satisfiable(
                extra_constraints=extra_constraints + [s1 == s2]
            ):
                logger.debug("Adding input constraint: %s != %s", in1, in2)
                if in1.size() == in2.size():
                    new_extra_constraints.append(in1 != in2)
                pairs_done.add((s1, s2))
                pairs_done.add((s2, s1))

        if new_extra_constraints:
            return self._hash_constraints(
                extra_constraints + new_extra_constraints, hashes, pairs_done
            )

        assert self.solver.satisfiable(extra_constraints=extra_constraints)

        for in1, s1 in hashes.items():
            # Next line can raise UnsatError. Handled in the caller if needed.
            sol1, = self.solver.eval(in1, 1, extra_constraints=extra_constraints)
            extra_constraints.append(in1 == sol1)
            # lstrip() is needed if the length is 0.
            sol1_bytes = (
                eth_utils.conversions.to_bytes(sol1)
                .lstrip(b"\0")
                .rjust(in1.length // 8, b"\0")
            )
            assert len(sol1_bytes) * 8 == in1.length
            extra_constraints.append(s1 == eth_utils.crypto.keccak(sol1_bytes))
            logger.debug("Added concrete constraint: %s", extra_constraints[-1])

        return tuple(extra_constraints)

    def replace(self, r):
        # First replacement: apply r() everywhere.
        new_constraints = [r(i) for i in self.solver.constraints]
        self.hashes = {r(k): r(v) for k, v in self.hashes.items()}
        # Second one: change the hash symbols as well.
        # Also needed in case we re-import constraints before the replacement:
        # the input is different and we don't want the symbols to be the same.
        new_hashes = {k: claripy.BVS("SHA3", 256) for k, v in self.hashes.items()}
        for k in self.hashes:
            r_from, r_to = self.hashes[k], new_hashes[k]
            new_constraints = [i.replace(r_from, r_to) for i in new_constraints]
        self.hashes = new_hashes

        # We need to rebuild the solver because we cannot just modify the constraints.
        self.solver = get_claripy_solver()
        self.solver.add(new_constraints)

    def combine(self, others):
        other_claripy_solvers = [i.solver for i in others]
        combined = Solver(
            claripy_solver=self.solver.combine(other_claripy_solvers),
            hashes=self.hashes,
        )

        for other in others:
            for k, v in self.hashes.items():
                # Make sure the hash symbols are distinct
                assert all(v is not v2 for v2 in other.hashes.values())
                # TODO: If some hash input are equal, we should merge the hash
                # symols here, it would be more efficient.
            combined.hashes.update(other.hashes)

        return combined

    def downsize(self):
        return self.solver.downsize()

    def simplify(self):
        return self.solver.simplify()

    def __repr__(self):
        return "ClaripySha3(constraints=%s, hashes=%s)" % (
            self.solver.constraints,
            self.hashes,
        )

    def as_dict(self):
        return {"constraints": self.solver.constraints, "hashes": self.hashes}

    @property
    def constraints(self):
        return self.solver.constraints
