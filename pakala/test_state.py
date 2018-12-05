import claripy
import unittest
import functools

from pakala.state import State
from pakala import env


class TestState(unittest.TestCase):
    def testHashWorks(self):
        state = State(env.Env(b""))
        state.pc = 5
        state.memory.write(0, 1, claripy.BVV(42, 8))
        state.memory.write(10, 1, claripy.BVV(43, 8))
        state.memory.write(20, 1, claripy.BVV(44, 8))
        state_copy = state.copy()
        self.assertEqual(hash(state), hash(state_copy))

        state.pc = 6
        self.assertNotEqual(hash(state), hash(state_copy))
        state_copy.pc = 6
        self.assertEqual(hash(state), hash(state_copy))

        state.memory.write(10, 1, claripy.BVV(45, 8))
        self.assertNotEqual(hash(state), hash(state_copy))
        state_copy.memory.write(10, 1, claripy.BVV(45, 8))
        self.assertEqual(hash(state), hash(state_copy))

        state.stack_push(state.env.calldata.read(0, 1))
        self.assertNotEqual(hash(state), hash(state_copy))
        state_copy.stack_push(state_copy.env.calldata.read(0, 1))
        self.assertEqual(hash(state), hash(state_copy))

    def testSameHashIfDifferentOrder(self):
        a = State()
        b = State()
        self.assertEqual(hash(a), hash(b))

        e = env.Env("code")

        a.solver.add(e.value == 1)
        a.solver.add(e.block_timestamp == 2)

        # Same thing, different order
        b.solver.add(e.block_timestamp == 2)
        b.solver.add(e.value == 1)

        self.assertEqual(hash(a), hash(b))

    def testReplace(self):
        old_env = env.Env(b"")
        new_env = old_env.clean_copy()
        state = State(new_env)
        state.storage_written[old_env.caller] = old_env.value
        state.replace(functools.partial(env.replace, old_env, state.env))
        self.assertIs(state.storage_written[new_env.caller], new_env.value)
