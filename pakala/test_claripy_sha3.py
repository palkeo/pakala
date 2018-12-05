import unittest
import functools

import claripy

from pakala.claripy_sha3 import Sha3
from pakala.utils import get_solver
from pakala import env
from pakala.state import State


class TestSha3Support(unittest.TestCase):
    def test_sha3_equality(self):
        a = claripy.BVV(1, 256)
        b = claripy.BVV(2, 256)
        self.assertEqual(Sha3(a), Sha3(claripy.BVV(1, 256)))
        self.assertNotEqual(Sha3(a), Sha3(b))

    def test_solver_basic(self):
        s = get_solver()
        in1 = claripy.BVS("in1", 256)
        in2 = claripy.BVS("in2", 256)

        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) == Sha3(in2)]))
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) != Sha3(in2)]))
        # These next two always hold anyway.
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) + 1 != Sha3(in2)]))
        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(in1) + 1 == Sha3(in2)]))

        s.add(in1 == in2)
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) == Sha3(in2)]))
        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(in1) != Sha3(in2)]))
        # These next two always hold anyway.
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) + 1 != Sha3(in2)]))
        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(in1) + 1 == Sha3(in2)]))

        s = get_solver()
        s.add(in1 != in2)
        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(in1) == Sha3(in2)]))
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) != Sha3(in2)]))
        # These next two always hold anyway.
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) + 1 != Sha3(in2)]))
        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(in1) + 1 == Sha3(in2)]))

    def test_solver_arithmetics(self):
        s = get_solver()
        in1 = claripy.BVS("in1", 256)
        in2 = claripy.BVS("in2", 256)

        self.assertTrue(
            s.satisfiable(extra_constraints=[Sha3(in1) + 1 == Sha3(in2) + 1])
        )
        self.assertFalse(
            s.satisfiable(extra_constraints=[Sha3(in1) + 1 == Sha3(in2) + 2])
        )
        self.assertFalse(
            s.satisfiable(extra_constraints=[Sha3(in1) + 1 == Sha3(in2) + 2])
        )

        self.assertTrue(
            s.satisfiable(extra_constraints=[Sha3(in1 + 1) == Sha3(in2 + 1)])
        )
        self.assertTrue(
            s.satisfiable(extra_constraints=[Sha3(in1 + 1) == Sha3(in2 - 1)])
        )
        self.assertFalse(
            s.satisfiable(extra_constraints=[Sha3(in1 + 1) + 42 == Sha3(in2 - 1)])
        )

    def test_solver_one_var(self):
        s = get_solver()
        in1 = claripy.BVS("in1", 256)

        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(in1) == 42]))
        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(in1) == 0]))
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) == Sha3(42)]))
        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(in1) == Sha3(0)]))
        self.assertTrue(
            s.satisfiable(extra_constraints=[Sha3(in1 + 1) + 2 == Sha3(0) + 2])
        )

    def test_solver_recursive(self):
        s = get_solver()
        in1 = claripy.BVS("in1", 256)
        in2 = claripy.BVS("in2", 256)

        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(Sha3(in1)) == 0]))
        self.assertFalse(s.satisfiable(extra_constraints=[Sha3(Sha3(in1)) == Sha3(0)]))
        self.assertTrue(
            s.satisfiable(extra_constraints=[Sha3(Sha3(in1)) == Sha3(Sha3(0))])
        )

        s.add(Sha3(in1) == Sha3(in2))
        self.assertTrue(s.satisfiable())

        self.assertTrue(
            s.satisfiable(
                extra_constraints=[Sha3(Sha3(in1) + 1) == Sha3(Sha3(in2) + 1)]
            )
        )

        s.add(Sha3(Sha3(in1) + 1) == Sha3(Sha3(in2) + 1))
        self.assertTrue(s.satisfiable())

        self.assertFalse(
            s.satisfiable(
                extra_constraints=[Sha3(Sha3(in1) + 2) == Sha3(Sha3(in2) + 1)]
            )
        )
        self.assertFalse(
            s.satisfiable(
                extra_constraints=[Sha3(Sha3(in1)) + 1 == Sha3(Sha3(in2) + 1)]
            )
        )

        s.add(Sha3(Sha3(in1)) + 3 == Sha3(Sha3(in2)) + 1)
        self.assertFalse(s.satisfiable())

        s_copy = s.branch()
        self.assertFalse(s.satisfiable())

    def test_solver_copy(self):
        s = get_solver()
        in1 = claripy.BVS("in1", 256)
        s.add(Sha3(in1) == 0)
        self.assertFalse(s.satisfiable())
        s2 = s.branch()
        self.assertFalse(s2.satisfiable())

    def test_env_replace_merge(self):
        old_env = env.Env(b"")
        new_env = old_env.clean_copy()

        old_state = State(old_env)
        old_state.solver.add(Sha3(old_env.caller) == old_env.value)

        self.assertTrue(old_state.solver.satisfiable())
        self.assertFalse(
            old_state.solver.satisfiable(extra_constraints=[old_env.value == 5])
        )

        new_state = old_state.copy()
        new_state.replace(functools.partial(env.replace, old_env, new_env))

        self.assertTrue(new_state.solver.satisfiable())
        self.assertFalse(
            new_state.solver.satisfiable(extra_constraints=[new_env.value == 5])
        )
        self.assertTrue(
            new_state.solver.satisfiable(extra_constraints=[old_env.value == 5])
        )

        new_state.solver.add(old_env.value == new_env.value)
        self.assertTrue(new_state.solver.satisfiable())
        self.assertFalse(
            new_state.solver.satisfiable(extra_constraints=[new_env.value == 5])
        )
        self.assertFalse(
            new_state.solver.satisfiable(extra_constraints=[old_env.value == 5])
        )

        old_state.solver = old_state.solver.combine([new_state.solver])
        self.assertTrue(new_state.solver.satisfiable())
        self.assertEqual(len(old_state.solver.constraints), 3)
        self.assertEqual(len(old_state.solver.hashes), 2)


if __name__ == "__main__":
    unittest.main()
