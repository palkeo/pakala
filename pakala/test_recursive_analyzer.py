import claripy
import unittest
import logging
import random
import itertools

from pakala.recursive_analyzer import RecursiveAnalyzer
from pakala.analyzer import FakeStorage
from pakala.env import Env
from pakala.state import State
from pakala import utils
from pakala.claripy_sha3 import Sha3

from web3 import Web3


logging.basicConfig(level=logging.DEBUG)
logging.getLogger("claripy").setLevel(logging.ERROR)


class TestCheckStates(unittest.TestCase):
    """The interesting tests.

    Inventing various classic scenarios and making sure that we find the bug
    if there is one. And that we don't if we are not supposed to find one.
    """

    def setUp(self):
        self.env = Env(b"", caller=utils.DEFAULT_CALLER, address=utils.DEFAULT_ADDRESS)

    def check_states(self, states, mock_storage=None):
        self.analyzer = RecursiveAnalyzer(
            max_wei_to_send=Web3.toWei(10, "ether"),
            min_wei_to_receive=Web3.toWei(1, "milliether"),
        )
        self.analyzer.storage_cache = FakeStorage(mock_storage or {})
        return self.analyzer.check_states(states, timeout=0, max_depth=4)

    def get_call(self, value, to=None):
        if to is None:
            to = self.env.caller
        return [
            utils.bvv(0),
            utils.bvv(0),
            utils.bvv(0),
            utils.bvv(0),
            value,
            to,
            utils.bvv(0),
        ]

    def test_nothing(self):
        self.assertFalse(self.check_states([]))

    def test_simple(self):
        state = State(self.env)
        self.assertFalse(self.check_states([state]))

    def test_suicide_simple(self):
        state = State(self.env)
        state.suicide_to = self.env.caller
        self.assertTrue(self.check_states([state]))

    def test_call_simple(self):
        state = State(self.env)
        state.calls.append(self.get_call(self.env.balance))
        self.assertTrue(self.check_states([state]))

    def test_write_and_suicide(self):
        state = State(self.env)

        state_write = state.copy()
        state_write.storage_written = {utils.bvv(0): self.env.calldata.read(4, 32)}

        state_suicide = state.copy()
        state_suicide.suicide_to = self.env.calldata.read(4, 32)
        storage_0 = claripy.BVS("storage[0]", 256)
        state_suicide.storage_read = {utils.bvv(0): storage_0}
        state_suicide.solver.add(storage_0 == 0xDEADBEEF0101)

        storage = {0: 0xBAD1DEA}
        self.assertTrue(
            self.check_states([state_write, state_suicide], mock_storage=storage)
        )
        self.assertFalse(self.check_states([state_suicide], mock_storage=storage))
        self.assertFalse(self.check_states([state_write]))

    def test_sha3_key(self):
        """Exercise solidity-like mappings, with the key being a sha3."""
        state = State(self.env)

        state_write = state.copy()
        # Arbitrary write input[1], at SHA3(input[0])
        state_write.storage_written = {
            Sha3(self.env.calldata.read(4, 32)): self.env.calldata.read(36, 32)
        }

        # Needs that: storage[SHA3(input[0])] == 43, made possible by the previous call
        state_suicide = state.copy()
        state_suicide.suicide_to = self.env.calldata.read(36, 32)
        storage_input = claripy.BVS("storage[SHA3(input)]", 256)
        state_suicide.storage_read = {
            Sha3(self.env.calldata.read(4, 32)): storage_input
        }
        state_suicide.solver.add(storage_input == 0xDEADBEEF101010)

        storage = {
            55186156870478567193644641351382124067713781048612400765092754877653207859685: 0
        }
        self.assertTrue(
            self.check_states([state_write, state_suicide], mock_storage=storage)
        )
        self.assertFalse(self.check_states([state_suicide], mock_storage=storage))
        self.assertFalse(self.check_states([state_write]))

    def test_sha3_value1(self):
        """Exercise comparison of two SHA3 (as values)."""
        state = State(self.env)

        state_write = state.copy()
        state_write.storage_written = {
            utils.bvv(0): Sha3(self.env.calldata.read(4, 32))
        }

        state_suicide = state.copy()
        state_suicide.suicide_to = self.env.calldata.read(36, 32)
        storage_input = claripy.BVS("storage[0]", 256)
        state_suicide.storage_read = {utils.bvv(0): storage_input}
        state_suicide.solver.add(storage_input == Sha3(self.env.calldata.read(4, 32)))

        storage = {0: 0}
        self.assertTrue(
            self.check_states([state_write, state_suicide], mock_storage=storage)
        )
        self.assertFalse(self.check_states([state_suicide], mock_storage=storage))
        self.assertFalse(self.check_states([state_write], mock_storage=storage))

    def test_sha3_value2(self):
        """Same as above, but we need to pass the computed SHA3."""
        state = State(self.env)

        state_write = state.copy()
        state_write.storage_written = {
            utils.bvv(0): Sha3(self.env.calldata.read(4, 32))
        }

        state_suicide = state.copy()
        state_suicide.suicide_to = self.env.calldata.read(36, 32)
        storage_input = claripy.BVS("storage[0]", 256)
        state_suicide.storage_read = {utils.bvv(0): storage_input}
        state_suicide.solver.add(storage_input == self.env.calldata.read(4, 32))
        state_suicide.solver.add(storage_input != 0)

        storage = {0: 0}
        self.assertTrue(
            self.check_states([state_write, state_suicide], mock_storage=storage)
        )
        self.assertFalse(self.check_states([state_suicide], mock_storage=storage))
        self.assertFalse(self.check_states([state_write], mock_storage=storage))

    def test_write_write_and_suicide(self):
        state = State(self.env)
        # Anybody can set owner
        state_write1 = state.copy()
        state_write1.storage_written = {utils.bvv(0): self.env.calldata.read(4, 32)}

        # Onlyowner: set a magic constant allowing the suicide bug, at an
        # user-controlled storage key.
        state_write2 = state.copy()
        read_0 = claripy.BVS("storage[0]", 256)
        state_write2.storage_read = {utils.bvv(0): read_0}
        state_write2.storage_written = {
            self.env.calldata.read(36, 32): self.env.calldata.read(4, 32)
        }
        state_write2.solver.add(read_0 == self.env.caller)

        # Suicide, when owner and magic constant set
        state_suicide = state.copy()
        read_0 = claripy.BVS("storage[0]", 256)
        read_40 = claripy.BVS("storage[4]", 256)
        state_suicide.storage_read = {utils.bvv(0): read_0, utils.bvv(40): read_40}
        state_suicide.solver.add(self.env.caller == read_0)
        state_suicide.solver.add(read_40 == 1337)
        state_suicide.suicide_to = self.env.caller

        states = [state_write1, state_write2, state_suicide]
        random.shuffle(states)

        storage = {0: 123456789, 40: 387642}
        for s in itertools.combinations(states, 2):
            self.assertFalse(self.check_states(s, mock_storage=storage))
        self.assertTrue(self.check_states(states, mock_storage=storage))

    def test_send_after_write(self):
        state = State(self.env)

        # We send storage[0]
        state_send = state.copy()
        storage_0 = claripy.BVS("storage[0]", 256)
        state_send.storage_read = {utils.bvv(0): storage_0}
        state_send.calls.append(self.get_call(storage_0))

        # storage[0] is 0.5 ETH
        storage = {0: Web3.toWei(0.5, "ether")}
        self.assertTrue(self.check_states([state_send], mock_storage=storage))

        # storage[0] is 0 ETH
        storage = {0: 0}
        self.assertFalse(self.check_states([state_send], mock_storage=storage))

        # storage[0] is still 0 ETH initially, but we have an arbitrary write now
        state_write = state.copy()
        state_write.storage_written = {utils.bvv(0): self.env.calldata.read(4, 32)}
        state_write.solver.add(self.env.calldata.read(0, 4) == 0x1337)
        state_write.solver.add(self.env.calldata.read(4, 32) < Web3.toWei(1, "ether"))

        self.assertFalse(self.check_states([state_write], mock_storage=storage))
        self.assertTrue(
            self.check_states([state_send, state_write], mock_storage=storage)
        )
        self.assertTrue(
            self.check_states([state_write, state_send], mock_storage=storage)
        )

        # ...arbitrary write of 1 wei only, which is too little
        state_write_0 = state_write.copy()
        state_write_0.solver.add(self.env.calldata.read(4, 32) == 1)
        self.assertFalse(
            self.check_states([state_write_0, state_send], mock_storage=storage)
        )

        # ...arbitrary write only if the block timestamp is <10, which is impossible.
        state_write_ts = state_write.copy()
        state_write_ts.solver.add(self.env.block_timestamp < 10)
        self.assertFalse(
            self.check_states([state_write_ts, state_send], mock_storage=storage)
        )

        self.assertFalse(
            self.check_states(
                [state_write_0, state_send, state_write_ts], mock_storage=storage
            )
        )

        # now we put all these state_write* together, so there is a solution.
        self.assertTrue(
            self.check_states(
                [state_write_0, state_send, state_write, state_write_ts],
                mock_storage=storage,
            )
        )
        self.assertTrue(
            self.check_states(
                [state_write_0, state_write, state_write_ts, state_send],
                mock_storage=storage,
            )
        )
