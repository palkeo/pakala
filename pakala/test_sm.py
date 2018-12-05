import unittest
from unittest import mock
import random
import numbers

import claripy

from pakala.env import Env
from pakala import sm
from pakala import utils


class TestSymbolicMachine(unittest.TestCase):
    """Basic tests for the members of the symbolic machine."""

    def setUp(self):
        code = "6003600302600f56601b60006000a15b6101a560006000a160019003801515600f57600660006000a1"
        code = utils.hex_to_bytes(code)
        env = Env(code)

        self.sm = sm.SymbolicMachine(env)

    def test_add_branch(self):
        state = self.sm.branch_queue[0][1]
        state.pc += 1

        self.sm.add_branch(state)
        self.assertEqual(len(self.sm.branch_queue), 2)

        # Add duplicate branch
        self.sm.add_branch(state)
        self.assertEqual(len(self.sm.branch_queue), 2)
        self.assertEqual(len(self.sm.code_errors), 1)

        # Add unsatisfiable state
        state.solver.add(claripy.BVS("lol", 8) == 5)
        self.sm.add_branch(state)
        self.assertEqual(len(self.sm.branch_queue), 3)
        state.solver.add(claripy.BVV(1, 8) == claripy.BVV(0, 8))
        self.sm.add_branch(state)
        self.assertEqual(len(self.sm.branch_queue), 3)
        self.assertEqual(len(self.sm.code_errors), 2)

    def test_add_for_fuzzing(self):
        state = self.sm.branch_queue[0][1]
        variable = claripy.BVS("test", 8)
        state.solver.add(variable < 50)
        self.sm.add_for_fuzzing(
            state, variable, [min, max, None, None, None, None, 42, 1337]
        )
        self.assertTrue(
            any(s.solver.eval(variable, 2) == (0,) for _, s in self.sm.branch_queue)
        )
        self.assertTrue(
            any(s.solver.eval(variable, 2) == (49,) for _, s in self.sm.branch_queue)
        )
        self.assertTrue(
            any(s.solver.eval(variable, 2) == (42,) for _, s in self.sm.branch_queue)
        )
        self.assertGreater(len(self.sm.branch_queue), 3)

    def test_execute(self):
        self.sm.execute(timeout_sec=10)

    def test_get_coverage(self):
        # Just test that it seems to work
        self.assertEqual(self.sm.get_coverage(), 0)


class TestInstructions(unittest.TestCase):
    def assertBEqual(self, a, b):
        self.assertTrue((a == b).is_true(), msg="%s != %s" % (a, b))

    @mock.patch.object(utils, "disassemble", lambda x: x)
    def run_code(self, code, env={}):
        self.sm = sm.SymbolicMachine(Env(code, **env))
        self.state = self.sm.branch_queue[0][1]
        return self.sm.exec_branch(self.state)

    def assert_stack(self, stack):
        self.assertEqual(len(stack), len(self.state.stack))
        for reference, observed in zip(stack, self.state.stack):
            self.assertBEqual(reference, observed)

    def test_jumpdest(self):
        self.assertTrue(self.run_code(["JUMPDEST"]))

    def test_add(self):
        self.run_code(["PUSH1", 1, "PUSH1", 2, "ADD"])
        self.assert_stack([3])
        self.run_code(["PUSH1", 1, "PUSH1", 2 ** 256 - 1, "ADD"])
        self.assert_stack([0])

    def test_sub(self):
        self.run_code(["PUSH1", 2, "PUSH1", 1, "SUB"])
        self.assert_stack([claripy.BVV(2 ** 256 - 1, 256)])

    def test_mul(self):
        self.run_code(["PUSH1", 2, "PUSH1", 4, "MUL"])
        self.assert_stack([8])

    def test_div(self):
        self.run_code(["PUSH1", 2, "PUSH1", 8, "DIV"])
        self.assert_stack([4])
        self.run_code(["PUSH1", 3, "PUSH1", 8, "DIV"])
        self.assert_stack([2])
        self.run_code(["PUSH1", 10, "PUSH1", 8, "DIV"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 2 ** 256 - 1, "PUSH1", 1, "DIV"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0, "PUSH1", 1, "DIV"])
        self.assert_stack([0])

    def test_sdiv(self):
        self.run_code(["PUSH1", 2 ** 256 - 1, "PUSH1", 1, "SDIV"])
        self.assert_stack([2 ** 256 - 1])
        self.run_code(["PUSH1", 0, "PUSH1", 1, "SMOD"])
        self.assert_stack([0])

    def test_mod(self):
        self.run_code(["PUSH1", 3, "PUSH1", 7, "MOD"])
        self.assert_stack([1])
        self.run_code(["PUSH1", 3, "PUSH1", 2 ** 256 - 1, "MOD"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0, "PUSH1", 1, "MOD"])
        self.assert_stack([0])

    def test_smod(self):
        self.run_code(["PUSH1", 3, "PUSH1", 2 ** 256 - 1, "SMOD"])
        self.assert_stack([2 ** 256 - 1])
        self.run_code(["PUSH1", 3, "PUSH1", 2 ** 256 - 4, "SMOD"])
        self.assert_stack([2 ** 256 - 1])
        self.run_code(["PUSH1", 3, "PUSH1", 4, "SMOD"])
        self.assert_stack([1])
        self.run_code(["PUSH1", 0, "PUSH1", 1, "SMOD"])
        self.assert_stack([0])

    def test_addmod(self):
        self.run_code(["PUSH1", 2, "PUSH1", 1, "PUSH1", 1, "ADDMOD"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 2, "PUSH1", 2, "PUSH1", 1, "ADDMOD"])
        self.assert_stack([1])
        self.run_code(["PUSH1", 2, "PUSH1", 2, "PUSH1", 2, "ADDMOD"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0, "PUSH1", 2, "PUSH1", 1, "ADDMOD"])
        self.assert_stack([0])

    def test_mulmod(self):
        self.run_code(["PUSH1", 2, "PUSH1", 1, "PUSH1", 1, "MULMOD"])
        self.assert_stack([1])
        self.run_code(["PUSH1", 2, "PUSH1", 2, "PUSH1", 1, "MULMOD"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 2, "PUSH1", 2, "PUSH1", 2, "MULMOD"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0, "PUSH1", 1, "PUSH1", 1, "MULMOD"])
        self.assert_stack([0])

    def test_exp(self):
        self.run_code(["PUSH1", 3, "PUSH1", 7, "EXP"])
        self.assert_stack([343])

    def test_signextend(self):
        self.run_code(["PUSH1", 0xFF, "PUSH1", 0x0, "SIGNEXTEND"])
        self.assert_stack([2 ** 256 - 1])
        self.run_code(["PUSH1", 0x3, "PUSH1", 0x0, "SIGNEXTEND"])
        self.assert_stack([3])
        self.run_code(["PUSH1", 0x0, "PUSH1", 0x0, "SIGNEXTEND"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0xFFFE, "PUSH1", 0x1, "SIGNEXTEND"])
        self.assert_stack([2 ** 256 - 2])
        self.run_code(["PUSH1", 0xFFFE, "PUSH1", 0x2, "SIGNEXTEND"])
        self.assert_stack([0xFFFE])

    def test_lt(self):
        self.run_code(["PUSH1", 7, "PUSH1", 6, "LT"])
        self.assert_stack([True])
        self.run_code(["PUSH1", 7, "PUSH1", 7, "LT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", -7, "PUSH1", -6, "LT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", -1, "PUSH1", 1, "LT"])
        self.assert_stack([True])

    def test_gt(self):
        self.run_code(["PUSH1", 7, "PUSH1", 6, "GT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", 7, "PUSH1", 7, "GT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", -7, "PUSH1", -6, "GT"])
        self.assert_stack([True])
        self.run_code(["PUSH1", -1, "PUSH1", 1, "GT"])
        self.assert_stack([False])

    def test_slt(self):
        self.run_code(["PUSH1", 7, "PUSH1", 6, "SLT"])
        self.assert_stack([True])
        self.run_code(["PUSH1", 7, "PUSH1", 7, "SLT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", -7, "PUSH1", -6, "SLT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", -1, "PUSH1", 1, "SLT"])
        self.assert_stack([False])

    def test_sgt(self):
        self.run_code(["PUSH1", 7, "PUSH1", 6, "SGT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", 7, "PUSH1", 7, "SGT"])
        self.assert_stack([False])
        self.run_code(["PUSH1", -7, "PUSH1", -6, "SGT"])
        self.assert_stack([True])
        self.run_code(["PUSH1", -1, "PUSH1", 1, "SGT"])
        self.assert_stack([True])

    def test_eq(self):
        self.run_code(["PUSH1", -1, "PUSH1", 2 ** 256 - 1, "EQ"])
        self.assert_stack([True])
        self.run_code(["PUSH1", -2, "PUSH1", 2 ** 256 - 1, "EQ"])
        self.assert_stack([False])
        self.run_code(
            ["PUSH1", claripy.BoolV(False), "PUSH1", claripy.BoolV(False), "EQ"]
        )
        self.assert_stack([True])
        self.run_code(
            ["PUSH1", claripy.BoolV(True), "PUSH1", claripy.BoolV(False), "EQ"]
        )
        self.assert_stack([False])

    def test_iszero(self):
        self.run_code(["PUSH1", 1, "ISZERO"])
        self.assert_stack([False])
        self.run_code(["PUSH1", 1, "PUSH1", -1, "ADD", "ISZERO"])
        self.assert_stack([True])

    def test_and(self):
        self.run_code(["PUSH1", 3, "PUSH1", 2, "AND"])
        self.assert_stack([2])

    def test_or(self):
        self.run_code(["PUSH1", 3, "PUSH1", 2, "OR"])
        self.assert_stack([3])

    def test_or(self):
        self.run_code(["PUSH1", claripy.BoolV(True), "PUSH1", 2, "OR"])
        self.assert_stack([3])

    def test_xor(self):
        self.run_code(["PUSH1", 3, "PUSH1", 2, "XOR"])
        self.assert_stack([1])

        a = random.randint(0, 2 ** 256 - 1)
        b = random.randint(0, 2 ** 256 - 1)
        self.run_code(["PUSH1", a, "PUSH1", b, "DUP1", "XOR", "XOR"])
        self.assert_stack([a])

    def test_not(self):
        self.run_code(["PUSH1", 0x43, "NOT"])
        self.assert_stack([(2 ** 256 - 1) ^ 0x43])
        self.run_code(["PUSH1", 0, "NOT"])
        self.assert_stack([2 ** 256 - 1])
        self.run_code(["PUSH1", 2 ** 256 - 1, "NOT"])
        self.assert_stack([0])

        a = random.randint(0, 2 ** 256 - 1)
        self.run_code(["PUSH1", a, "NOT", "NOT"])

    def test_byte(self):
        self.run_code(["PUSH1", 0x4243, "PUSH1", 0, "BYTE"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0x4243, "PUSH1", 29, "BYTE"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0x4243, "PUSH1", 30, "BYTE"])
        self.assert_stack([0x42])
        self.run_code(["PUSH1", 0x4243, "PUSH1", 31, "BYTE"])
        self.assert_stack([0x43])
        self.run_code(["PUSH1", 0x4243, "PUSH1", 32, "BYTE"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0x4243, "PUSH1", 50, "BYTE"])
        self.assert_stack([0])
        self.run_code(["PUSH1", 0x414243, "PUSH1", 29, "BYTE"])
        self.assert_stack([0x41])

    def test_pc(self):
        self.run_code(["PUSH1", 1, "PC"])
        self.assert_stack([1, 2])

    def test_gas(self):
        self.run_code(["GAS"])
        self.assert_stack([self.state.env.gas])

    def test_address(self):
        self.run_code(["ADDRESS"])
        self.assert_stack([self.state.env.address])

    def test_balance(self):
        self.run_code(["ADDRESS", "BALANCE"], env={"address": claripy.BVV(789, 256)})
        self.assert_stack([self.state.env.balance])

        with self.assertRaises(ValueError):
            self.run_code(["PUSH1", 1, "BALANCE"])

    def test_origin(self):
        self.run_code(["ORIGIN"])
        self.assert_stack([self.state.env.origin])

    def test_caller(self):
        self.run_code(["CALLER"])
        self.assert_stack([self.state.env.caller])

    def test_callvalue(self):
        self.run_code(["CALLVALUE"])
        self.assert_stack([self.state.env.value])

    def test_blockhash(self):
        self.run_code(["NUMBER", "BLOCKHASH"])
        self.assert_stack([self.state.env.block_hashes[self.state.env.block_number]])

    def test_timestamp(self):
        self.run_code(["TIMESTAMP"])
        self.assert_stack([self.state.env.block_timestamp])

    def test_number(self):
        self.run_code(["NUMBER"])
        self.assert_stack([self.state.env.block_number])

    def test_coinbase(self):
        self.run_code(["COINBASE"])
        self.assert_stack([self.state.env.coinbase])

    def test_difficulty(self):
        self.run_code(["DIFFICULTY"])
        self.assert_stack([self.state.env.difficulty])

    def test_pop(self):
        self.run_code(["PUSH1", 1, "POP"])
        self.assert_stack([])
        with self.assertRaises(utils.CodeError):
            self.run_code(["POP"])

    def test_jump(self):
        r = self.run_code(["PUSH1", 4, "JUMP", "PC", "JUMPDEST"])
        self.assertFalse(r)
        self.assert_stack([])
        self.assertEqual(len(self.sm.branch_queue), 2)
        self.sm.exec_branch(self.sm.branch_queue[1][1])
        self.assert_stack([])

        with self.assertRaises(utils.CodeError):
            self.run_code(["PUSH1", 4, "JUMP", "POP", "PC"])

    def test_jumpi(self):
        r = self.run_code(
            ["PUSH1", 1337, "CALLVALUE", "EQ", "PUSH1", 8, "JUMPI", "PC", "JUMPDEST"]
        )
        self.assertFalse(r)

        def true_state(state):
            self.state = state
            self.sm.exec_branch(self.state)
            try:
                self.assert_stack([7])
                self.assertEqual(self.state.solver.min(self.state.env.value), 0)
            except AssertionError:
                return False
            return True

        def false_state(state):
            self.state = state
            self.sm.exec_branch(self.state)
            try:
                self.assert_stack([])
                self.assertEqual(self.state.solver.min(self.state.env.value), 1337)
            except AssertionError:
                return False
            return True

        # We don't know which state is first (it changes). So we do that
        # to avoid flakiness.
        self.assertTrue(any(true_state(bq[1])) for bq in self.sm.branch_queue)
        self.assertTrue(any(false_state(bq[1])) for bq in self.sm.branch_queue)

        with self.assertRaises(utils.CodeError):
            self.run_code(["PUSH1", 0, "PUSH1", 0, "JUMPI"])

    def test_push(self):
        self.run_code(["PUSH1", 2])
        self.assert_stack([2])
        self.run_code(["PUSH3", 2, 0, 0, "PUSH1", 4])
        self.assert_stack([2, 4])

    def test_dup(self):
        self.run_code(["PUSH1", 1, "PUSH1", 2, "PUSH1", 3, "DUP3"])
        self.assert_stack([1, 2, 3, 1])
        self.run_code(["PUSH1", 1, "PUSH1", 2, "PUSH1", 3, "DUP1"])
        self.assert_stack([1, 2, 3, 3])

    def test_swap(self):
        self.run_code(["PUSH1", 1, "PUSH1", 2, "PUSH1", 3, "SWAP2"])
        self.assert_stack([3, 2, 1])
        self.run_code(["PUSH1", 1, "PUSH1", 2, "PUSH1", 3, "SWAP1"])
        self.assert_stack([1, 3, 2])

    def test_log(self):
        self.run_code(["PUSH1", 0, "PUSH1", 0, "PUSH1", 0, "LOG1"])

    # TODO: test_sha3

    def test_stop(self):
        r = self.run_code(["STOP"])
        self.assertTrue(r)

    def test_return(self):
        r = self.run_code(["RETURN"])
        self.assertTrue(r)

    def test_calldataload(self):
        self.run_code(["PUSH1", 0, "CALLDATALOAD", "PUSH1", 0, "CALLDATALOAD"])
        self.assertTrue(self.state.stack[0] is self.state.stack[1])
        self.run_code(["PUSH1", 0, "CALLDATALOAD", "PUSH1", 32, "CALLDATALOAD"])
        self.assertTrue(self.state.stack[0] is not self.state.stack[1])

    def test_calldatasize(self):
        self.run_code(["CALLDATASIZE", "PUSH1", 4, "CALLDATALOAD"])
        self.assertEqual(self.state.solver.min(self.state.stack[0]), 36)

    def test_calldatacopy(self):
        # size, dstart, mstart
        self.run_code(
            [
                "PUSH1",
                64,
                "PUSH1",
                20,
                "PUSH1",
                10,
                "CALLDATACOPY",
                "PUSH1",
                10,
                "MLOAD",
                "PUSH1",
                42,
                "MLOAD",
            ]
        )
        self.assertEqual(self.state.solver.min(self.state.env.calldata_size), 84)
        self.assert_stack(
            [self.state.env.calldata.read(20, 32), self.state.env.calldata.read(52, 32)]
        )

    def test_codesize(self):
        self.run_code(["PUSH1", 0, "POP", "CODESIZE"])
        self.assert_stack([4])

    def test_extcodesize_self(self):
        self.run_code(["ADDRESS", "EXTCODESIZE"])
        self.assert_stack([2])

    def test_extcodesize_other(self):
        self.run_code(["PUSH1", 42, "EXTCODESIZE"])
        self.assertTrue(len(self.state.stack), 1)
        self.assertTrue(
            self.state.solver.satisfiable(extra_constraints=[self.state.stack[0] == 0])
        )
        self.assertTrue(
            self.state.solver.satisfiable(
                extra_constraints=[self.state.stack[0] == 1337]
            )
        )

    @mock.patch.object(utils, "disassemble")
    def test_codecopy(self, mock_disassemble):
        code = ["CODESIZE", "PUSH1", 0, "DUP1", "CODECOPY", "PUSH1", 0, "MLOAD"]
        mock_disassemble.return_value = code
        self.sm = sm.SymbolicMachine(Env(b"\x60" + bytearray(len(code) - 2) + b"\xa1"))
        self.state = self.sm.branch_queue[0][1]
        self.sm.exec_branch(self.state)
        number = 0x60000000000000A1 << ((32 - len(code)) * 8)
        self.assert_stack([number])

    def test_mload(self):
        self.run_code(["PUSH1", 0, "MLOAD", "PUSH1", 0, "MLOAD"])
        self.assertTrue(self.state.stack[0] is self.state.stack[1])

    def test_mstore(self):
        self.run_code(["PUSH1", 1337, "PUSH1", 1, "MSTORE", "PUSH1", 1, "MLOAD"])
        self.assert_stack([1337])
        self.run_code(["PUSH1", 1337, "PUSH1", 0, "MSTORE", "PUSH1", 0, "MLOAD"])
        self.assert_stack([1337])
        self.run_code(
            [
                "PUSH1",
                0xCAFE,
                "PUSH1",
                64,
                "MSTORE",
                "PUSH1",
                0xDEAD,
                "PUSH1",
                62,
                "MSTORE",
                "PUSH1",
                66,
                "MLOAD",
            ]
        )
        self.assert_stack([0xDEADCAFE0000])

    def test_mstore8(self):
        self.run_code(["PUSH1", 0x1337, "PUSH1", 30, "MSTORE8", "PUSH1", 0, "MLOAD"])
        self.assert_stack([0x3700])

    def test_msize(self):
        self.run_code(["PUSH1", 1, "PUSH1", 0, "MSTORE8", "MSIZE"])
        self.assert_stack([1])
        self.run_code(["PUSH1", 1, "PUSH1", 32, "MSTORE", "MSIZE"])
        self.assert_stack([64])

    def test_sload(self):
        self.run_code(["PUSH1", 0, "SLOAD", "PUSH1", 0, "SLOAD"])
        self.assertTrue(self.state.stack[0] is self.state.stack[1])
        self.run_code(["PUSH1", 0, "SLOAD", "PUSH1", 32, "SLOAD"])
        self.assertTrue(self.state.stack[0] is not self.state.stack[1])

    def test_sstore(self):
        self.run_code(
            [
                "PUSH1",
                1337,
                "PUSH1",
                0,
                "SSTORE",
                "PUSH1",
                0,
                "SLOAD",
                "PUSH1",
                1338,
                "PUSH1",
                0,
                "SSTORE",
                "PUSH1",
                0,
                "SLOAD",
            ]
        )
        self.assert_stack([1337, 1338])
        self.run_code(
            [
                "PUSH1",
                0,
                "SLOAD",
                "PUSH1",
                32,
                "SSTORE",
                "PUSH1",
                32,
                "SLOAD",
                "PUSH1",
                0,
                "SLOAD",
            ]
        )
        self.assertTrue(self.state.stack[0] is self.state.stack[1])

    # TODO: test_call, test_callcode, test_suicide

    def test_invalid_opcode(self):
        with self.assertRaises(utils.CodeError):
            self.run_code(["INVALID 0xfe"])


if __name__ == "__main__":
    unittest.main()
