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
from pakala import claripy_sha3

from web3 import Web3

claripy_sha3.sha3_monkeypatch()

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('claripy').setLevel(logging.ERROR)

class TestStateDone(unittest.TestCase):
    """Test that a state already done is not processed again."""
    def setUp(self):
        self.env = Env(b'', caller=utils.DEFAULT_CALLER,
                            address=utils.DEFAULT_ADDRESS)
        self.empty_state = State(self.env)
        self.state = State(self.env)
        self.state.storage_written = {utils.bvv(0): utils.bvv(42)}
        self.analyzer = RecursiveAnalyzer(
            max_wei_to_send=Web3.toWei(10, 'ether'),
            min_wei_to_receive=Web3.toWei(1, 'milliether'))
        self.analyzer.reference_states.append(self.state)

    def test_same(self):
        """We search the same state."""
        self.analyzer._search_path(self.empty_state, [self.state])
        self.assertEqual(len(self.analyzer.path_queue), 1)
        self.analyzer._search_path(self.empty_state.copy(), [self.state])
        self.assertEqual(len(self.analyzer.path_queue), 1)

    def test_successive_applications(self):
        """We apply the same state two times."""
        self.analyzer._search_path(self.empty_state, [self.state])
        self.assertEqual(len(self.analyzer.path_queue), 1)
        composite_state, path = self.analyzer.path_queue.popleft()
        self.analyzer._search_path(composite_state, path)
        self.assertEqual(len(self.analyzer.path_queue), 0)


class TestCheckStates(unittest.TestCase):
    """The interesting tests.

    Inventing various classic scenarios and making sure that we find the bug
    if there is one. And that we don't if we are not supposed to find one.
    """

    def setUp(self):
        self.env = Env(b'', caller=utils.DEFAULT_CALLER,
                            address=utils.DEFAULT_ADDRESS)

    def check_states(self, states, mock_storage=None):
        self.analyzer = RecursiveAnalyzer(
            max_wei_to_send=Web3.toWei(10, 'ether'),
            min_wei_to_receive=Web3.toWei(1, 'milliether'))
        self.analyzer.storage_cache = FakeStorage(mock_storage or {})
        return self.analyzer.check_states(states)

    def get_call(self, value, to=None):
        if to is None:
            to = self.env.caller
        return [utils.bvv(0), utils.bvv(0), utils.bvv(0), utils.bvv(0),
                value, to, utils.bvv(0)]


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
        state_write.storage_written = {utils.bvv(0):
                                       self.env.calldata.read(4, 32)}

        state_suicide = state.copy()
        state_suicide.suicide_to = self.env.calldata.read(4, 32)
        state_suicide.storage_read = {utils.bvv(0):
                                      self.env.calldata.read(4, 32)}
        state_suicide.solver.add(
            self.env.calldata.read(4, 32) == state.env.caller)

        storage = {0: 0xBAD1DEA}
        self.assertTrue(self.check_states([state_write, state_suicide],
                    mock_storage=storage))
        self.assertFalse(self.check_states([state_suicide],
                         mock_storage=storage))
        self.assertFalse(self.check_states([state_write]))

    def test_write_write_and_suicide(self):
        state = State(self.env)
        # Anybody can set owner
        state_write1 = state.copy()
        state_write1.storage_written = {utils.bvv(0):
                                       self.env.calldata.read(4, 32)}

        # Onlyowner: set a magic constant allowing the suicide bug
        state_write2 = state.copy()
        read_0 = claripy.BVS('read_0', 256)
        state_write2.storage_read = {utils.bvv(0): read_0}
        state_write2.storage_written = {self.env.caller.SHA3():
                                        self.env.calldata.read(4, 32)}
        state_write2.solver.add(read_0 == self.env.caller)

        # Suicide, when owner and magic constant set
        state_suicide = state.copy()
        read_0 = claripy.BVS('read_0', 256)
        read_sha_caller = claripy.BVS('read_sha_caller', 256)
        state_suicide.storage_read = {
            utils.bvv(0): read_0,
            self.env.caller.SHA3(): read_sha_caller}
        state_suicide.solver.add(self.env.caller == read_0)
        state_suicide.solver.add(read_sha_caller == 1337)
        state_suicide.suicide_to = self.env.caller

        states = [state_write1, state_write2, state_suicide]
        random.shuffle(states)

        storage = {0: 123456789}
        for s in itertools.combinations(states, 2):
            self.assertFalse(self.check_states(s, mock_storage=storage))
        self.assertTrue(self.check_states(states, mock_storage=storage))

    def test_send_after_write(self):
        state = State(self.env)

        # We send storage[0]
        state_send = state.copy()
        storage_0 = claripy.BVS('storage[0]', 256)
        state_send.storage_read = {utils.bvv(0): storage_0}
        state_send.calls.append(self.get_call(storage_0))

        # storage[0] is 0.5 ETH
        storage = {0: Web3.toWei(0.5, 'ether')}
        self.assertTrue(self.check_states([state_send], mock_storage=storage))

        # storage[0] is 0 ETH
        storage = {0: 0}
        self.assertFalse(self.check_states([state_send], mock_storage=storage))

        # storage[0] is still 0 ETH initially, but we have an arbitrary write now
        state_write = state.copy()
        state_write.storage_written = {utils.bvv(0):
                                       self.env.calldata.read(4, 32)}
        state_write.solver.add(self.env.calldata.read(0, 4) == 0x1337)
        state_write.solver.add(
                self.env.calldata.read(4, 32) < Web3.toWei(1, 'ether'))

        self.assertFalse(self.check_states([state_write],
                                           mock_storage=storage))
        self.assertTrue(self.check_states([state_send, state_write],
                                          mock_storage=storage))
        self.assertTrue(self.check_states([state_write, state_send],
                                          mock_storage=storage))

        # ...arbitrary write of 1 wei only, which is too little
        state_write_0 = state_write.copy()
        state_write_0.solver.add(self.env.calldata.read(4, 32) == 1)
        self.assertFalse(self.check_states([state_write_0, state_send],
                                           mock_storage=storage))

        # ...arbitrary write only if the block timestamp is <10, which is impossible.
        state_write_ts = state_write.copy()
        state_write_ts.solver.add(self.env.block_timestamp < 10)
        self.assertFalse(self.check_states([state_write_ts, state_send],
                                           mock_storage=storage))

        self.assertFalse(self.check_states(
            [state_write_0, state_send, state_write_ts],
            mock_storage=storage))

        # now we put all these state_write* together, so there is a solution.
        self.assertTrue(self.check_states(
            [state_write_0, state_send, state_write, state_write_ts],
            mock_storage=storage))
        self.assertTrue(self.check_states(
            [state_write_0, state_write, state_write_ts, state_send],
            mock_storage=storage))
