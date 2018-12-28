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
import heapq
import logging
import math
import numbers
import time

import claripy

from eth.vm import opcode_values

from pakala import utils
from pakala.state import State
from pakala.claripy_sha3 import Sha3

logger = logging.getLogger(__name__)  # pylint:disable=invalid-name


bvv = utils.bvv  # pylint:disable=invalid-name
BVV_0 = bvv(0)
BVV_1 = bvv(1)

# interesting values aligned to classic parameters.
CALLDATASIZE_FUZZ = [4, 32, 36, 64, 68, 100, 132, 164, 196]


def not_bool(variable):
    """Ensure a BV is not a BoolS.
    If it is, it's converted to a BVV: 0 or 1.
    """
    if isinstance(variable, claripy.ast.Bool):
        return claripy.If(variable, BVV_1, BVV_0)
    return variable


def make_consistent(a, b):  # pylint:disable=invalid-name
    """Ensure a and b are not bool and not bool."""
    if isinstance(a, claripy.ast.Bool) and not isinstance(b, claripy.ast.Bool):
        return not_bool(a), b
    if isinstance(b, claripy.ast.Bool) and not isinstance(a, claripy.ast.Bool):
        return a, not_bool(b)
    return a, b


class SymbolicMachine:
    """Class to represent a state of a EVM program, and execute it symbolically.
    """

    def __init__(self, env, fuzz=True):
        self.code = env.code
        logger.debug("Initializing symbolic machine with source code: %s", self.code)
        # For use by heapq only. Contains couples (score, state).
        self.branch_queue = []
        self.states_seen = set()
        self.coverage = [0] * len(self.code)
        # List of all normal/good terminations of the contract
        self.outcomes = []
        # List of all the place where we didn't know how to continue execution
        self.partial_outcomes = []
        self.fuzz = fuzz
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
        for t in tries:  # pylint:disable=invalid-name
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
            new_state.score += 5  # Lower the priority of what we got by fuzzing.
            new_state.solver.add(variable == value)
            self.add_branch(new_state)

    def exec_branch(self, state):  # pylint:disable=invalid-name
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
        self.code.pc = state.pc

        while True:
            if state.pc >= len(self.code):
                return True

            op = self.code.next()
            self.coverage[state.pc] += 1

            logger.debug("NEW STEP")
            logger.debug("Memory: %s", state.memory)
            logger.debug("Stack: %s", state.stack)
            logger.debug("PC: %i, %s", state.pc, op)

            assert self.code.pc == state.pc + 1
            assert isinstance(op, numbers.Number)
            assert all(
                hasattr(i, "symbolic") for i in state.stack
            ), "The stack musty only contains claripy BV's"

            # Trivial operations first
            if not self.code.is_valid_opcode(state.pc):
                raise utils.CodeError("Trying to execute PUSH data")
            elif op == 254:  # INVALID opcode
                raise utils.CodeError("designed INVALID opcode")
            elif op == opcode_values.JUMPDEST:
                pass
            elif op == opcode_values.ADD:
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(s0 + s1)
            elif op == opcode_values.SUB:
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(s0 - s1)
            elif op == opcode_values.MUL:
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(s0 * s1)
            elif op == opcode_values.DIV:
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
            elif op == opcode_values.SDIV:
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
            elif op == opcode_values.MOD:
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
            elif op == opcode_values.SMOD:
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
            elif op == opcode_values.ADDMOD:
                s0, s1, s2 = state.stack_pop(), state.stack_pop(), state.stack_pop()
                try:
                    s2 = solution(s2)
                except ValueError:
                    state.stack_push(claripy.If(s2 == 0, BVV_0, (s0 + s1) % s2))
                else:
                    state.stack_push(BVV_0 if s2 == 0 else (s0 + s1) % s2)
            elif op == opcode_values.MULMOD:
                s0, s1, s2 = state.stack_pop(), state.stack_pop(), state.stack_pop()
                try:
                    s2 = solution(s2)
                except ValueError:
                    state.stack_push(claripy.If(s2 == 0, BVV_0, (s0 * s1) % s2))
                else:
                    state.stack_push(BVV_0 if s2 == 0 else (s0 * s1) % s2)
            elif op == opcode_values.EXP:
                base, exponent = solution(state.stack_pop()), state.stack_pop()
                if base == 2:
                    state.stack_push(1 << exponent)
                else:
                    exponent = solution(exponent)
                    state.stack_push(claripy.BVV(base ** exponent, 256))
            elif op == opcode_values.LT:
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.ULT(s0, s1))
            elif op == opcode_values.GT:
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.UGT(s0, s1))
            elif op == opcode_values.SLT:
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.SLT(s0, s1))
            elif op == opcode_values.SGT:
                s0, s1 = (
                    not_bool(state.stack_pop()),
                    not_bool(state.stack_pop()),
                )  # pylint:disable=invalid-name
                state.stack_push(claripy.SGT(s0, s1))
            elif op == opcode_values.SIGNEXTEND:
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
            elif op == opcode_values.EQ:
                s0, s1 = state.stack_pop(), state.stack_pop()
                if isinstance(s0, claripy.ast.Bool) and isinstance(
                    s1, claripy.ast.Bool
                ):
                    state.stack_push(s0 == s1)
                else:
                    state.stack_push(not_bool(s0) == not_bool(s1))
            elif op == opcode_values.ISZERO:
                condition = state.stack_pop()
                if isinstance(condition, claripy.ast.Bool):
                    state.stack_push(claripy.Not(condition))
                else:
                    state.stack_push(condition == BVV_0)
            elif op == opcode_values.AND:
                s0, s1 = make_consistent(state.stack_pop(), state.stack_pop())
                if isinstance(s0, claripy.ast.Bool) and isinstance(
                    s1, claripy.ast.Bool
                ):
                    state.stack_push(s0 and s1)
                else:
                    state.stack_push(s0 & s1)
            elif op == opcode_values.OR:
                s0, s1 = make_consistent(state.stack_pop(), state.stack_pop())
                if isinstance(s0, claripy.ast.Bool) and isinstance(
                    s1, claripy.ast.Bool
                ):
                    state.stack_push(s0 or s1)
                else:
                    state.stack_push(s0 | s1)
            elif op == opcode_values.XOR:
                s0, s1 = make_consistent(state.stack_pop(), state.stack_pop())
                state.stack_push(s0 ^ s1)
            elif op == opcode_values.NOT:
                state.stack_push(~state.stack_pop())
            elif op == opcode_values.BYTE:
                s0, s1 = (
                    state.stack_pop(),
                    state.stack_pop(),
                )  # pylint:disable=invalid-name
                state.stack_push(s1.LShR(claripy.If(s0 > 31, 32, 31 - s0) * 8) & 0xFF)

            elif op == opcode_values.PC:
                state.stack_push(bvv(state.pc))
            elif op == opcode_values.GAS:
                state.stack_push(state.env.gas)
            elif op == opcode_values.ADDRESS:
                state.stack_push(state.env.address)
            elif op == opcode_values.BALANCE:
                addr = solution(state.stack_pop())
                if addr != solution(state.env.address):
                    raise utils.InterpreterError(
                        state, "Can only query balance of the current contract for now"
                    )
                state.stack_push(state.env.balance)
            elif op == opcode_values.ORIGIN:
                state.stack_push(state.env.origin)
            elif op == opcode_values.CALLER:
                state.stack_push(state.env.caller)
            elif op == opcode_values.CALLVALUE:
                state.stack_push(state.env.value)
            elif op == opcode_values.BLOCKHASH:
                block_num = state.stack_pop()
                if block_num not in state.env.block_hashes:
                    state.env.block_hashes[block_num] = claripy.BVS(
                        "blockhash[%s]" % block_num, 256
                    )
                state.stack_push(state.env.block_hashes[block_num])
            elif op == opcode_values.TIMESTAMP:
                state.stack_push(state.env.block_timestamp)
            elif op == opcode_values.NUMBER:
                state.stack_push(state.env.block_number)
            elif op == opcode_values.COINBASE:
                state.stack_push(state.env.coinbase)
            elif op == opcode_values.DIFFICULTY:
                state.stack_push(state.env.difficulty)
            elif op == opcode_values.POP:
                state.stack_pop()
            elif op == opcode_values.JUMP:
                addr = solution(state.stack_pop())
                if addr >= len(self.code) or self.code[addr] != opcode_values.JUMPDEST:
                    raise utils.CodeError("Invalid jump (%i)" % addr)
                state.pc = addr
                self.add_branch(state)
                return False
            elif op == opcode_values.JUMPI:
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
                if (
                    state.pc >= len(self.code)
                    or self.code[state.pc] != opcode_values.JUMPDEST
                ):
                    raise utils.CodeError("Invalid jump (%i)" % (state.pc - 1))
                self.add_branch(state)
                return False
            elif opcode_values.PUSH1 <= op <= opcode_values.PUSH32:
                pushnum = op - opcode_values.PUSH1 + 1
                raw_value = self.code.read(pushnum)
                state.pc += pushnum
                state.stack_push(bvv(int.from_bytes(raw_value, byteorder="big")))
            elif opcode_values.DUP1 <= op <= opcode_values.DUP16:
                depth = op - opcode_values.DUP1 + 1
                state.stack_push(state.stack[-depth])
            elif opcode_values.SWAP1 <= op <= opcode_values.SWAP16:
                depth = op - opcode_values.SWAP1 + 1
                temp = state.stack[-depth - 1]
                state.stack[-depth - 1] = state.stack[-1]
                state.stack[-1] = temp
            elif opcode_values.LOG0 <= op <= opcode_values.LOG4:
                depth = op - opcode_values.LOG0
                mstart, msz = (state.stack_pop(), state.stack_pop())
                topics = [state.stack_pop() for x in range(depth)]
            elif op == opcode_values.SHA3:
                start, length = solution(state.stack_pop()), solution(state.stack_pop())
                memory = state.memory.read(start, length)
                state.stack_push(Sha3(memory))
            elif op == opcode_values.STOP:
                return True
            elif op == opcode_values.RETURN:
                return True

            elif op == opcode_values.CALLDATALOAD:
                indexes = state.stack_pop()
                try:
                    index = solution(indexes)
                except ValueError:  # Multiple solutions, let's fuzz.
                    state.stack_push(indexes)  # restore the stack
                    self.add_for_fuzzing(state, indexes, CALLDATASIZE_FUZZ)
                    return False
                state.solver.add(state.env.calldata_size >= index + 32)
                state.stack_push(state.env.calldata.read(index, 32))
            elif op == opcode_values.CALLDATASIZE:
                state.stack_push(state.env.calldata_size)
            elif op == opcode_values.CALLDATACOPY:
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
                    return False
                state.memory.copy_from(state.env.calldata, mstart, dstart, size)
                state.solver.add(state.env.calldata_size >= dstart + size)
            elif op == opcode_values.CODESIZE:
                state.stack_push(bvv(len(self.code)))
            elif op == opcode_values.EXTCODESIZE:
                addr = state.stack_pop()
                if (addr == state.env.address).is_true():
                    state.stack_push(bvv(len(self.code)))
                else:
                    # TODO: Improve that... It's clearly not constraining enough.
                    state.stack_push(claripy.BVS("EXTCODESIZE[%s]" % addr, 256))
            elif op == opcode_values.CODECOPY:
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

            elif op == opcode_values.MLOAD:
                index = solution(state.stack_pop())
                state.stack_push(state.memory.read(index, 32))
            elif op == opcode_values.MSTORE:
                index, value = solution(state.stack_pop()), not_bool(state.stack_pop())
                state.memory.write(index, 32, value)
            elif op == opcode_values.MSTORE8:
                index, value = solution(state.stack_pop()), not_bool(state.stack_pop())
                state.memory.write(index, 1, value[7:0])
            elif op == opcode_values.MSIZE:
                state.stack_push(bvv(state.memory.size()))
            elif op == opcode_values.SLOAD:
                # TODO: This is inaccurate, because the storage can change
                # in a single transaction.
                # See commit d98cab834f8f359f01ef805256d179f5529ebe30.
                key = state.stack_pop()
                if key in state.storage_written:
                    state.stack_push(state.storage_written[key])
                else:
                    if key not in state.storage_read:
                        state.storage_read[key] = claripy.BVS("storage[%s]" % key, 256)
                    state.stack_push(state.storage_read[key])
            elif op == opcode_values.SSTORE:
                # TODO: This is inaccurate, because the storage can change
                # in a single transaction.
                # See commit d98cab834f8f359f01ef805256d179f5529ebe30.
                key = state.stack_pop()
                value = state.stack_pop()
                state.storage_written[key] = value

            elif op == opcode_values.CALL:
                state.pc += 1

                # First possibility: the call fails
                # (always possible with a call stack big enough)
                state_fail = state.copy()
                state_fail.stack_push(claripy.BoolV(False))
                self.add_branch(state_fail)

                # Second possibility: success.
                state.calls.append(state.stack[-7:])

                # pylint:disable=unused-variable
                gas, to_, value, meminstart, meminsz, memoutstart, memoutsz = (
                    state.stack_pop() for _ in range(7)
                )

                if solution(memoutsz) != 0:
                    raise utils.InterpreterError(state, "CALL seems to return data")
                if solution(meminsz) != 0:
                    raise utils.InterpreterError(state, "CALL seems to take data")

                state.stack_push(claripy.BoolV(True))
                self.add_branch(state)
                return False

            elif op == opcode_values.SELFDESTRUCT:
                state.selfdestruct_to = state.stack[-1]
                return True

            elif op == opcode_values.REVERT:
                return False
            else:
                raise utils.InterpreterError(state, "Unknown opcode %s" % op)

            state.pc += 1

    def execute(self, timeout_sec):
        """Run the code, searching for all the interesting outcomes.

        Returns the process time it took to execute.
        """

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
            "Analysis finished with %i outcomes (%i interesting, %i unfinished), "
            "coverage is %i%%",
            len(self.outcomes),
            sum(int(o.is_interesting()) for o in self.outcomes),
            len(self.partial_outcomes),
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
            logger.debug(outcome.debug_string())

    def add_outcome(self, state):
        """Add an outcome to the list."""
        state.clean()
        logger.debug("Adding outcome: %s", state.debug_string())
        self.outcomes.append(state)

    def add_partial_outcome(self, state):
        """Add an outcome to the list of partial outcomes."""
        state.clean()
        logger.debug("Adding partial outcome: %s", state.debug_string())
        self.partial_outcomes.append(state)

    def get_coverage(self):
        """Return the ratio of instructions that were executed by the total
        number of instructions."""
        total_lines = 0
        covered_lines = 0
        for pc, instruction in enumerate(self.code):  # pylint:disable=invalid-name
            if pc == len(self.code):
                break
            if instruction == opcode_values.JUMPDEST or not self.code.is_valid_opcode(
                pc
            ):
                continue
            total_lines += 1
            covered_lines += bool(self.coverage[pc])
        return covered_lines / float(total_lines or 1)
