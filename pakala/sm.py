"""
    pakala: EVM symbolic execution tool and vulnerability scanner.
    Copyright (C) 2018 Korantin Auguste

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import collections
import datetime
import heapq
import logging
import math
import numbers
import time

from ethereum import opcodes
from ethereum import vm
from ethereum import utils as ethutils
import claripy

from pakala import utils
from pakala.state import State
from pakala.claripy_sha3 import Sha3

logger = logging.getLogger(__name__)  # pylint:disable=invalid-name


bvv = utils.bvv  # pylint:disable=invalid-name
BVV_0 = bvv(0)
BVV_1 = bvv(1)

# interesting values aligned to classic parameters.
CALLDATASIZE_FUZZ = [min, max, 4, 32, 36, 64, 68, 100, 132, 164, 196]


def not_bool(variable):
    """Ensure a BV is not a BoolS.
    If it is, it's converted to a BVV: 0 or 1.
    """
    if isinstance(variable, claripy.ast.Bool):
        return claripy.If(variable, BVV_1, BVV_0)
    return variable


def make_consistent(a, b):
    """Ensure a and b are not bool and not bool."""
    if isinstance(a, claripy.ast.Bool) and not isinstance(b, claripy.ast.Bool):
        return not_bool(a), b
    elif isinstance(b, claripy.ast.Bool) and not isinstance(a, claripy.ast.Bool):
        return a, not_bool(b)
    return a, b


class SymbolicMachine:
    """Class to represent a state of a EVM program, and execute it symbolically.
    """

    def __init__(self, env):
        self.code = utils.disassemble(env.code)
        logger.debug("Initializing symbolic machine with source code: %s", self.code)
        # For use by heapq only. Contains couples (score, state).
        self.branch_queue = []
        self.states_seen = set()
        self.coverage = [0] * len(self.code)
        # List of all normal/good terminations of the contract
        self.outcomes = []
        # List of all the place where we didn't know how to continue execution
        self.partial_outcomes = []
        self.fuzz = True
        self.code_errors = collections.Counter()
        self.interpreter_errors = collections.Counter()
        self.add_branch(State(env))

    def add_branch(self, state):
        """Add a state corresponding to a branch to be executed.
        We look at how many times the branch was executed, that's the score.
        We will take the branches with the smallest score first.
        """
        if not state.solver.satisfiable():
            logger.debug("Avoided adding unsatisfiable state.")
            self.code_errors["Avoided adding unsatisfiable state"] += 1
            return

        if hash(state) in self.states_seen:
            logger.debug("Avoided adding visited state.")
            self.code_errors["Avoided adding visited state"] += 1
            return

        # We have to downsize the used solver to free memory in z3, otherwise
        # they will collectively end up eating all the memory.
        state.solver.downsize()
        state.solver.simplify()

        # If it's a unknown code, let's set the score to 0, otherwise use the
        # score from the state.
        new_code = state.pc >= len(self.coverage) or not self.coverage[state.pc]
        if new_code:
            state.score = 0

        # TODO: Run comprehensive tests with that formula instead.
        # state.score = 0 if state.pc >= len(self.coverage) else self.coverage[state.pc]

        logger.debug(
            "Adding branch to %i with score %i " "(visited %i times)",
            state.pc,
            state.score,
            self.coverage[state.pc] if state.pc < len(self.coverage) else 0,
        )

        heapq.heappush(self.branch_queue, (state.score, state))
        self.states_seen.add(hash(state))

    def add_for_fuzzing(self, state, variable, tries):
        """
        Will try to fuzz the variable, setting it to different values.
        The tries parameter must be an array of :
         - min: if you want to add the minimum value possible
         - max: if you want to add the maximum value possible
         - a number: to try that number
         - None: a random number that works, you can repeat it.
        """
        # TODO: If the fuzzer is used, then I will generate tons of branches
        # that are equivalent... There should be a way to deduplicate them,
        # but it's not trivial.

        if not self.fuzz:
            raise utils.InterpreterError(state, "Fuzzer is disabled")

        to_try = set()
        nb_random = 0
        for t in tries:
            if isinstance(t, numbers.Number) and state.solver.solution(variable, t):
                to_try.add(t)
            elif t is min:
                to_try.add(state.solver.min(variable))
            elif t is max:
                to_try.add(state.solver.max(variable))
            elif t is None:
                nb_random += 1
        if nb_random:
            to_try |= set(state.solver.eval(variable, nb_random))

        logger.debug("Fuzzing will try %s in %s.", variable, to_try)
        for value in to_try:
            new_state = state.copy()
            new_state.solver.add(variable == value)
            self.add_branch(new_state)

    def exec_branch(
        self, state
    ):  # pylint: disable=too-many-locals,too-many-return-statements,too-many-branches,too-many-statements
        """Execute forward from a state, queuing new states if needed."""
        logger.debug("Constraints: %s", state.solver.constraints)

        def solution(variable):
            """Returns the solution. There must be one or we fail."""
            solutions = state.solver.eval(variable, 2)
            if len(solutions) > 1:
                raise ValueError(
                    "Ambiguous solution for %s (%s)" % (variable, self.code[state.pc])
                )
            solution = solutions[0]
            return solution if isinstance(solution, numbers.Number) else solution.value

        state.score += 1

        while True:
            if state.pc >= len(self.code):
                return True

            # TODO: Don't log for things like PUSH, POP...
            logger.debug("NEW STEP")
            logger.debug("Memory: %s", state.memory)
            logger.debug("Stack: %s", state.stack)
            logger.debug("PC: %i %s", state.pc, self.code[state.pc])

            op = self.code[state.pc]  # pylint:disable=invalid-name
            self.coverage[state.pc] += 1

            assert all(
                hasattr(i, "symbolic") for i in state.stack
            ), "The stack musty only contains claripy BV's"

            # Trivial operations first

            if isinstance(op, numbers.Number):
                raise utils.CodeError("Trying to execute PUSH data.")
            elif op == "JUMPDEST":
                pass
            elif op == "ADD":
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(s0 + s1)
            elif op == "SUB":
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(s0 - s1)
            elif op == "MUL":
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(s0 * s1)
            elif op == "DIV":
                # We need to use claripy.LShR instead of a division if possible,
                # because the solver is bad dealing with divisions, better
                # with shifts. And we need shifts to handle the solidity ABI
                # for function selection.
                s0, s1 = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=invalid-name
                try:
                    s1 = solution(s1)  # pylint:disable=invalid-name
                except ValueError:
                    state.stack_push(claripy.If(s1 == 0, BVV_0, s0 / s1))
                else:
                    if s1 == 0:
                        state.stack_push(BVV_0)
                    elif s1 == 1:
                        state.stack_push(s0)
                    elif s1 & (s1 - 1) == 0:
                        exp = int(math.log(s1, 2))
                        state.stack_push(s0.LShR(exp))
                    else:
                        state.stack_push(s0 / s1)
            elif op == "SDIV":
                s0, s1 = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=invalid-name
                try:
                    s1 = solution(s1)
                except ValueError:
                    state.stack_push(claripy.If(s1 == 0, BVV_0, s0.SDiv(s1)))
                else:
                    state.stack_push(BVV_0 if s1 == 0 else s0.SDiv(s1))
            elif op == "MOD":
                s0, s1 = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=invalid-name
                try:
                    s1 = solution(s1)
                except ValueError:
                    state.stack_push(claripy.If(s1 == 0, BVV_0, s0 % s1))
                else:
                    state.stack_push(BVV_0 if s1 == 0 else s0 % s1)
            elif op == "SMOD":
                s0, s1 = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=invalid-name
                try:
                    s1 = solution(s1)
                except ValueError:
                    state.stack_push(claripy.If(s1 == 0, BVV_0, s0.SMod(s1)))
                else:
                    state.stack_push(BVV_0 if s1 == 0 else s0.SMod(s1))
            elif op == "ADDMOD":
                s0, s1, s2 = state.stack_pop(), state.stack_pop(), state.stack_pop()
                try:
                    s2 = solution(s2)
                except ValueError:
                    state.stack_push(claripy.If(s2 == 0, BVV_0, (s0 + s1) % s2))
                else:
                    state.stack_push(BVV_0 if s2 == 0 else (s0 + s1) % s2)
            elif op == "MULMOD":
                s0, s1, s2 = state.stack_pop(), state.stack_pop(), state.stack_pop()
                try:
                    s2 = solution(s2)
                except ValueError:
                    state.stack_push(claripy.If(s2 == 0, BVV_0, (s0 * s1) % s2))
                else:
                    state.stack_push(BVV_0 if s2 == 0 else (s0 * s1) % s2)
            elif op == "EXP":
                base, exponent = solution(state.stack_pop()), state.stack_pop()
                if base == 2:
                    state.stack_push(1 << exponent)
                else:
                    exponent = solution(exponent)
                    state.stack_push(claripy.BVV(base ** exponent, 256))
            elif op == "LT":
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.ULT(s0, s1))
            elif op == "GT":
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.UGT(s0, s1))
            elif op == "SLT":
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.SLT(s0, s1))
            elif op == "SGT":
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.SGT(s0, s1))
            elif op == "SIGNEXTEND":
                s0, s1 = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=invalid-name
                # s0 is the number of bits. s1 the number we want to extend.
                s0 = solution(s0)
                if s0 <= 31:
                    sign_bit = 1 << (s0 * 8 + 7)
                    state.stack_push(
                        claripy.If(
                            s1 & sign_bit == 0,
                            s1 & (sign_bit - 1),
                            s1 | ((1 << 256) - sign_bit),
                        )
                    )
                else:
                    state.stack_push(s1)
            elif op == "EQ":
                s0, s1 = state.stack_pop(), state.stack_pop()
                if isinstance(s0, claripy.ast.Bool) and isinstance(
                    s1, claripy.ast.Bool
                ):
                    state.stack_push(s0 == s1)
                else:
                    state.stack_push(not_bool(s0) == not_bool(s1))
            elif op == "ISZERO":
                condition = state.stack_pop()
                if isinstance(condition, claripy.ast.Bool):
                    state.stack_push(claripy.Not(condition))
                else:
                    state.stack_push(condition == BVV_0)
            elif op == "AND":
                s0, s1 = make_consistent(state.stack_pop(), state.stack_pop())
                if isinstance(s0, claripy.ast.Bool) and isinstance(
                    s1, claripy.ast.Bool
                ):
                    state.stack_push(s0 and s1)
                else:
                    state.stack_push(s0 & s1)
            elif op == "OR":
                s0, s1 = make_consistent(state.stack_pop(), state.stack_pop())
                if isinstance(s0, claripy.ast.Bool) and isinstance(
                    s1, claripy.ast.Bool
                ):
                    state.stack_push(s0 or s1)
                else:
                    state.stack_push(s0 | s1)
            elif op == "XOR":
                s0, s1 = make_consistent(state.stack_pop(), state.stack_pop())
                state.stack_push(s0 ^ s1)
            elif op == "NOT":
                state.stack_push(~state.stack_pop())
            elif op == "BYTE":
                s0, s1 = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=invalid-name
                state.stack_push(s1.LShR(claripy.If(s0 > 31, 32, 31 - s0) * 8) & 0xFF)

            elif op == "PC":
                state.stack_push(bvv(state.pc))
            elif op == "GAS":
                state.stack_push(state.env.gas)
            elif op == "ADDRESS":
                state.stack_push(state.env.address)
            elif op == "BALANCE":
                addr = solution(state.stack_pop())
                if addr != solution(state.env.address):
                    raise utils.InterpreterError(
                        state, "Can only query balance of the current contract for now"
                    )
                state.stack_push(state.env.balance)
            elif op == "ORIGIN":
                state.stack_push(state.env.origin)
            elif op == "CALLER":
                state.stack_push(state.env.caller)
            elif op == "CALLVALUE":
                state.stack_push(state.env.value)
            elif op == "BLOCKHASH":
                block_num = state.stack_pop()
                if block_num not in state.env.block_hashes:
                    state.env.block_hashes[block_num] = claripy.BVS(
                        "blockhash[%s]" % block_num, 256
                    )
                state.stack_push(state.env.block_hashes[block_num])
            elif op == "TIMESTAMP":
                state.stack_push(state.env.block_timestamp)
            elif op == "NUMBER":
                state.stack_push(state.env.block_number)
            elif op == "COINBASE":
                state.stack_push(state.env.coinbase)
            elif op == "DIFFICULTY":
                state.stack_push(state.env.difficulty)
            elif op == "POP":
                state.stack_pop()
            elif op == "JUMP":
                addr = solution(state.stack_pop())
                if (
                    addr >= len(self.code)
                    or self.code[addr] != "JUMPDEST"
                    or addr == state.pc
                ):
                    raise utils.CodeError("Invalid jump (%i)" % addr)
                state.pc = addr
                self.add_branch(state)
                return
            elif op == "JUMPI":
                addr, condition = solution(state.stack_pop()), state.stack_pop()
                state_false = state.copy()
                if isinstance(condition, claripy.ast.Bool):
                    state.solver.add(condition)
                    state_false.solver.add(claripy.Not(condition))
                else:
                    state.solver.add(condition != 0)
                    state_false.solver.add(condition == 0)
                state_false.pc += 1
                self.add_branch(state_false)
                state.pc = addr
                if state.pc >= len(self.code) or self.code[state.pc] != "JUMPDEST":
                    raise utils.CodeError("Invalid jump (%i)" % (state.pc - 1))
                self.add_branch(state)
                return
            elif op.startswith("PUSH"):
                pushnum = int(op[4:])
                push_data = self.code[state.pc + 1]
                state.pc += pushnum
                if hasattr(push_data, "symbolic"):  # If it's already a BV
                    state.stack_push(push_data)
                else:
                    state.stack_push(bvv(push_data))
            elif op.startswith("DUP"):
                depth = int(op[3:])
                state.stack_push(state.stack[-depth])
            elif op.startswith("SWAP"):
                depth = int(op[4:])
                temp = state.stack[-depth - 1]
                state.stack[-depth - 1] = state.stack[-1]
                state.stack[-1] = temp
            elif op.startswith("LOG"):
                depth = int(op[3:])
                mstart, msz = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=unused-variable
                topics = [
                    state.stack_pop() for x in range(depth)
                ]  # pylint:disable=unused-variable
            elif op == "SHA3":
                start, length = solution(state.stack_pop()), solution(state.stack_pop())
                memory = state.memory.read(start, length)
                state.stack_push(Sha3(memory))
            elif op == "STOP":
                return True
            elif op == "RETURN":
                return True

            elif op == "CALLDATALOAD":
                indexes = state.stack_pop()
                try:
                    index = solution(indexes)
                except ValueError:  # Multiple solutions, let's fuzz.
                    state.stack_push(indexes)  # restore the stack
                    self.add_for_fuzzing(state, indexes, CALLDATASIZE_FUZZ)
                    return
                state.solver.add(state.env.calldata_size >= index + 32)
                state.stack_push(state.env.calldata.read(index, 32))
            elif op == "CALLDATASIZE":
                state.stack_push(state.env.calldata_size)
            elif op == "CALLDATACOPY":
                old_state = state.copy()
                mstart, dstart, size = (
                    state.stack_pop(),
                    state.stack_pop(),
                    state.stack_pop(),
                )
                mstart, dstart = solution(mstart), solution(dstart)
                try:
                    size = solution(size)
                except ValueError:
                    self.add_for_fuzzing(old_state, size, CALLDATASIZE_FUZZ)
                    return
                state.memory.copy_from(state.env.calldata, mstart, dstart, size)
                state.solver.add(state.env.calldata_size >= dstart + size)
            elif op == "CODESIZE":
                state.stack_push(bvv(len(self.code)))
            elif op == "EXTCODESIZE":
                addr = state.stack_pop()
                if (addr == state.env.address).is_true():
                    state.stack_push(bvv(len(self.code)))
                else:
                    # TODO: Improve that... It's clearly not constraining enough.
                    state.stack_push(claripy.BVS("EXTCODESIZE[%s]" % addr, 256))
            elif op == "CODECOPY":
                mem_start, code_start, size = [
                    solution(state.stack_pop()) for _ in range(3)
                ]
                for i in range(size):
                    if code_start + i < len(state.env.code):
                        state.memory.write(
                            mem_start + i,
                            1,
                            claripy.BVV(state.env.code[code_start + i], 8),
                        )
                    else:
                        state.memory.write(mem_start + i, 1, claripy.BVV(0, 8))

            elif op == "MLOAD":
                index = solution(state.stack_pop())
                state.stack_push(state.memory.read(index, 32))
            elif op == "MSTORE":
                index, value = solution(state.stack_pop()), not_bool(state.stack_pop())
                state.memory.write(index, 32, value)
            elif op == "MSTORE8":
                index, value = solution(state.stack_pop()), not_bool(state.stack_pop())
                state.memory.write(index, 1, value[7:0])
            elif op == "MSIZE":
                state.stack_push(bvv(state.memory.size()))
            elif op == "SLOAD":
                # TODO: This is inaccurate, because the storage can change in a single transaction.
                # See commit d98cab834f8f359f01ef805256d179f5529ebe30.
                key = state.stack_pop()
                if key in state.storage_written:
                    state.stack_push(state.storage_written[key])
                else:
                    if key not in state.storage_read:
                        state.storage_read[key] = claripy.BVS("storage[%s]" % key, 256)
                    state.stack_push(state.storage_read[key])
            elif op == "SSTORE":
                # TODO: This is inaccurate, because the storage can change in a single transaction.
                # See commit d98cab834f8f359f01ef805256d179f5529ebe30.
                key = state.stack_pop()
                value = state.stack_pop()
                state.storage_written[key] = value

            elif op == "CALL":
                state.pc += 1

                # First possibility: the call fails (always possible with a call stack big enough)
                state_fail = state.copy()
                state_fail.stack_push(claripy.BoolV(False))
                self.add_branch(state_fail)

                # Second possibility: success.
                state.calls.append(state.stack[-7:])

                gas, to_, value, meminstart, meminsz, memoutstart, memoutsz = (  # pylint:disable=unused-variable
                    state.stack_pop() for _ in range(7)
                )

                if solution(memoutsz) != 0:
                    raise utils.InterpreterError(state, "CALL seems to return data")
                if solution(meminsz) != 0:
                    raise utils.InterpreterError(state, "CALL seems to take data")

                state.stack_push(claripy.BoolV(True))
                self.add_branch(state)
                return

            elif op == "SUICIDE":
                state.suicide_to = state.stack[-1]
                return True

            elif op == "REVERT":
                return
            elif op.startswith("INVALID "):
                raise utils.CodeError("Invalid opcode at %i: %s" % (state.pc, op))
            else:
                raise utils.InterpreterError(state, "Unknown opcode %s" % op)

            state.pc += 1

    def execute(self, timeout_sec):
        """Run the code, searching for all the interesting outcomes.

        Returns the process time it took to execute."""

        if self.outcomes:
            raise RuntimeError("Already executed.")

        time_start = time.process_time()

        time_last_coverage_increase = time_start
        last_coverage = 0

        while self.branch_queue:

            coverage = sum(bool(c) for c in self.coverage)
            if coverage > last_coverage:
                time_last_coverage_increase = time.process_time()
                logger.log(utils.INFO_INTERACTIVE, "Coverage is now %i.", coverage)
                last_coverage = coverage

            if (
                not timeout_sec
                and time.process_time() - time_last_coverage_increase
                > max(60, time_last_coverage_increase - time_start)
            ) or (timeout_sec and time.process_time() - time_start > timeout_sec):
                logger.debug("Timeout.")
                self.interpreter_errors["execute timeout"] += 1
                break

            score, state = heapq.heappop(self.branch_queue)

            logger.debug("Executing branch at %i with score %i.", state.pc, score)
            try:
                success = self.exec_branch(state)
            except (utils.CodeError, claripy.errors.UnsatError) as error:
                logger.debug("Code error: %s", error)
                self.code_errors[repr(error)] += 1
            except (
                utils.InterpreterError,
                claripy.errors.ClaripyError,
                ValueError,
                ZeroDivisionError,
            ) as error:
                logger.debug("Interpreter error: %s", error)
                self.interpreter_errors[repr(error)] += 1
                if isinstance(error, utils.InterpreterError):
                    self.add_partial_outcome(error.state)
            else:
                if success:
                    self.add_outcome(state)
                logger.debug("Branch done.")

        # In case of timeouts, we still have unfinished branches in the queue!
        # Add them as partial outcomes.
        while self.branch_queue:
            score, state = heapq.heappop(self.branch_queue)
            self.add_partial_outcome(state)

        logger.info(
            "Analysis finished with %i outcomes (%i interesting), " "coverage is %i%%",
            len(self.outcomes),
            sum(int(o.is_interesting()) for o in self.outcomes),
            int(self.get_coverage() * 100),
        )

        if self.code_errors:
            logger.info("Code errors encountered: %s", self.code_errors.most_common())
        if self.interpreter_errors:
            logger.info(
                "Interpreter errors encountered: %s",
                self.interpreter_errors.most_common(),
            )

        logger.debug("List of outcomes:")
        for outcome in self.outcomes:
            logger.debug(outcome)

    def add_outcome(self, state):
        """Add an outcome to the list."""
        logger.debug("Adding outcome: %r", state)
        state.clean()
        self.outcomes.append(state)

    def add_partial_outcome(self, state):
        """Add an outcome to the list of partial outcomes."""
        logger.debug("Adding partial outcome: %r", state)
        state.clean()
        self.partial_outcomes.append(state)

    def get_coverage(self):
        """Return the ratio of instructions that were executed by the total
        number of instructions."""
        total_lines = 0
        covered_lines = 0
        for pc, instruction in enumerate(self.code):  # pylint:disable=invalid-name
            if instruction == "JUMPDEST" or isinstance(instruction, numbers.Number):
                continue
            total_lines += 1
            covered_lines += bool(self.coverage[pc])
        return covered_lines / float(total_lines or 1)
