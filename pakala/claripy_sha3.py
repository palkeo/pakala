import logging
import itertools
import operator

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
        (hash_input,) = ast.args
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


def _this_sha3_symbol(ast, symbol):
    if not isinstance(ast, claripy.ast.base.Base):
        return False
    if ast is symbol:
        return True
    return any(_this_sha3_symbol(child, symbol) for child in ast.args)


def _no_sha3_symbols(constraints):
    return all(_no_sha3_symbol(ast) for ast in constraints)


def _hash_depth(hashes, hash_symbol):
    """Returns how "deep" this hash symbol is, if it's inside another hash."""
    depth = 0
    for in1, s1 in hashes.items():
        if _this_sha3_symbol(in1, hash_symbol):
            assert s1 is not hash_symbol  # A hash cannot contain itself.
            depth = max(depth, 1 + _hash_depth(hashes, s1))
    return depth


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
        logger.debug("Adding constraint: %r", constraints)
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

        constraint_added = False
        for (in1, s1), (in2, s2) in itertools.combinations(hashes.items(), 2):
            if (s1, s2) in pairs_done:
                continue
            # Do s1 needs to be equal to s2 ? Then in1 needs to be equal to in2
            if not self.solver.satisfiable(
                extra_constraints=extra_constraints + [s1 != s2]
            ):
                logger.debug("Adding input constraint: %s == %s", in1, in2)
                if in1.size() == in2.size():
                    extra_constraints.append(in1 == in2)
                else:
                    logger.debug("Size are different!")
                    extra_constraints.append(False)
                pairs_done.add((s1, s2))
                pairs_done.add((s2, s1))
                constraint_added = True
            # Do s1 needs to be != to s2 ? Then in1 needs to be != to in2
            elif not self.solver.satisfiable(
                extra_constraints=extra_constraints + [s1 == s2]
            ):
                logger.debug("Adding input constraint: %s != %s", in1, in2)
                if in1.size() == in2.size():
                    extra_constraints.append(in1 != in2)
                    constraint_added = True
                else:
                    logger.debug("Size are different!")
                pairs_done.add((s1, s2))
                pairs_done.add((s2, s1))

        if constraint_added:
            return self._hash_constraints(extra_constraints, hashes, pairs_done)

        assert self.solver.satisfiable(extra_constraints=extra_constraints)

        # We need to first concretize the hashes that are the "deepest", i.e. that
        # are serving as input for other hashes.
        hash_depth = {symbol: _hash_depth(hashes, symbol) for symbol in hashes.values()}
        for in1, s1 in sorted(
            hashes.items(), key=lambda i: hash_depth[i[1]], reverse=True
        ):
            # Next line can raise UnsatError. Handled in the caller if needed.
            (sol1,) = self.solver.eval(in1, 1, extra_constraints=extra_constraints)
            extra_constraints.append(in1 == sol1)
            # lstrip() is needed if the length is 0.
            sol1_bytes = (
                eth_utils.conversions.to_bytes(sol1)
                .lstrip(b"\0")
                .rjust(in1.length // 8, b"\0")
            )
            assert len(sol1_bytes) * 8 == in1.length
            extra_constraints.append(s1 == eth_utils.crypto.keccak(sol1_bytes))
            logger.debug(
                "Added concrete constraint on hash: %s and on input: %s",
                extra_constraints[-1],
                extra_constraints[-2],
            )

        return tuple(extra_constraints)

    def replace(self, r):
        # First replacement: apply r() everywhere.
        new_constraints = [r(i) for i in self.solver.constraints]
        self.hashes = {r(k): r(v) for k, v in self.hashes.items()}

        # We need to rebuild the solver because we cannot just modify the constraints.
        self.solver = get_claripy_solver()
        self.solver.add(new_constraints)

    def regenerate_hash_symbols(self):
        # We can copy such a solver, and replace symbols in a new environment,
        # and want to combine() it again with the parent solver, or one derived
        # from it. In that case the hashes symbols need to be different! So we
        # can use that function and call replace() on all the symbols to use
        # new hash symbols everywhere.
        new_hashes = {k: claripy.BVS("SHA3", 256) for k, v in self.hashes.items()}

        def r(ast):
            for in_ in self.hashes:
                ast = ast.replace(self.hashes[in_], new_hashes[in_])
            return ast

        return r

    def combine(self, others):
        other_claripy_solvers = [i.solver for i in others]
        combined = Solver(
            claripy_solver=self.solver.combine(other_claripy_solvers),
            hashes=self.hashes,
        )

        for other in others:
            for k, v in self.hashes.items():
                # Make sure the hash symbols are distinct
                if any(v is v2 for v2 in other.hashes.values()):
                    # Call regenerate_hash_symbols() on one of them first?
                    raise ValueError("Cannot combine with equivalent hashes.")

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
