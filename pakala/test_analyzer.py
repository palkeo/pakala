import claripy
import unittest
from unittest.mock import patch
import logging

from pakala.analyzer import Analyzer
from pakala.env import Env
from pakala.state import State
from pakala import utils

from web3 import Web3

logging.basicConfig(level=logging.DEBUG)


class TestCheckState(unittest.TestCase):
    def setUp(self):
        self.env = Env(b"", caller=utils.DEFAULT_CALLER, address=utils.DEFAULT_ADDRESS)

        self.state = State(self.env)
        self.analyzer = Analyzer(
            address=self.env.address,
            caller=self.env.caller,
            max_wei_to_send=Web3.toWei(10, "ether"),
            min_wei_to_receive=Web3.toWei(1, "milliether"),
        )

    def check_state(self, state):
        return self.analyzer.check_state(state)

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
        self.assertFalse(self.check_state(self.state))

    def test_selfdestruct(self):
        self.state.selfdestruct_to = self.env.caller
        self.assertTrue(self.check_state(self.state))

    def test_send_back(self):
        self.state.calls.append(self.get_call(self.env.value))
        self.assertFalse(self.check_state(self.state))

    def test_send_back_more(self):
        self.state.calls.append(self.get_call(self.env.value + Web3.toWei(1, "ether")))
        self.assertTrue(self.check_state(self.state))

    def test_send_back_if_impossible_block(self):
        self.state.calls.append(
            self.get_call(
                claripy.If(
                    self.env.block_number > 100000000000,
                    self.env.value + Web3.toWei(1, "ether"),
                    0,
                )
            )
        )
        self.assertFalse(self.check_state(self.state))

    def test_send_back_if_possible_block(self):
        self.state.calls.append(
            self.get_call(
                claripy.If(
                    self.env.block_number < 100000000000,
                    self.env.value + Web3.toWei(1, "ether"),
                    0,
                )
            )
        )
        self.assertTrue(self.check_state(self.state))

    def test_send_back_nothing(self):
        self.state.calls.append(self.get_call(utils.bvv(0)))
        self.assertFalse(self.check_state(self.state))

    def test_send_back_twice(self):
        self.state.calls.append(self.get_call(self.env.value))
        self.state.calls.append(self.get_call(self.env.value / 10))
        self.assertTrue(self.check_state(self.state))

    def test_send_back_fixed_amount(self):
        self.state.calls.append(self.get_call(Web3.toWei(1, "ether")))
        self.assertTrue(self.check_state(self.state))

    def test_send_back_to_someone_else(self):
        self.state.calls.append(
            self.get_call(Web3.toWei(1, "ether"), to=self.env.caller + 1)
        )
        self.assertFalse(self.check_state(self.state))

    def test_send_all(self):
        self.state.calls.append(self.get_call(self.env.balance))
        self.assertTrue(self.check_state(self.state))

    def test_send_back_calldata(self):
        self.state.calls.append(self.get_call(self.env.calldata.read(0, 32)))
        self.state.solver.add(claripy.UGT(self.env.calldata.read(0, 32), 0))
        self.assertTrue(self.check_state(self.state))

    def test_send_back_negative_signed(self):
        self.state.calls.append(self.get_call(self.env.calldata.read(0, 32)))
        self.state.solver.add(claripy.SLT(self.env.calldata.read(0, 32), 0))
        self.assertFalse(self.check_state(self.state))

    def test_send_back_negative_unsigned(self):
        self.state.calls.append(self.get_call(self.env.calldata.read(0, 32)))
        self.state.solver.add(claripy.ULT(self.env.calldata.read(0, 32), 0))
        self.assertFalse(self.check_state(self.state))


    # TODO: Fix it!
    @unittest.skip(
        "Known issue: we are sending back env.balance, "
        "that doesn't contain env.value, and it should!"
    )
    def test_send_all_and_selfdestruct(self):
        self.state.calls.append(self.get_call(self.env.balance, to=self.env.caller + 1))
        self.state.selfdestruct_to = self.env.caller
        self.assertFalse(self.check_state(self.state))

    def test_read_concrete(self):
        self.analyzer.actual_storage = {0: 0xBAD1DEA}

        self.state.storage_read[utils.bvv(0)] = claripy.BVS("storage[0]", 256)
        self.state.selfdestruct_to = self.state.storage_read[utils.bvv(0)]
        self.assertFalse(self.check_state(self.state))

        self.state.calls.append(
            self.get_call(
                Web3.toWei(1, "ether") * self.state.storage_read[utils.bvv(0)]
            )
        )
        self.assertTrue(self.check_state(self.state))

    def test_non_exhaustive_storage(self):
        self.analyzer.actual_storage = {1: 0xBAD1DEA}
        self.analyzer.actual_storage_exhaustive = False

        self.state.storage_read[utils.bvv(0)] = claripy.BVS("storage[0]", 256)
        self.state.selfdestruct_to = self.state.storage_read[utils.bvv(0)]

        # Suicide to storage[0] that contains our address (state.env.caller)
        with patch.object(self.analyzer, "_read_storage_key") as mock_read_storage_key:
            mock_read_storage_key.return_value = utils.bvv_to_number(
                self.state.env.caller
            )
            self.assertTrue(self.check_state(self.state))
            mock_read_storage_key.assert_called_with(0)

    def test_non_exhaustive_storage2(self):
        """Same as the previous test, but we suicide to 0 so it doesn't work."""
        self.analyzer.actual_storage = {1: 0xBAD1DEA}
        self.analyzer.actual_storage_exhaustive = False

        self.state.storage_read[utils.bvv(0)] = claripy.BVS("storage[0]", 256)
        self.state.selfdestruct_to = self.state.storage_read[utils.bvv(0)]

        # Same as above, but we suicide to 0 instead of caller.
        with patch.object(self.analyzer, "_read_storage_key") as mock_read_storage_key:
            mock_read_storage_key.return_value = 0
            self.assertFalse(self.check_state(self.state))
            mock_read_storage_key.assert_called_with(0)

    def test_exhaustive_storage(self):
        self.analyzer.actual_storage = {1: 0xBAD1DEA}
        self.analyzer.actual_storage_exhaustive = True

        self.state.storage_read[utils.bvv(0)] = claripy.BVS("storage[0]", 256)
        self.state.selfdestruct_to = self.state.storage_read[utils.bvv(0)]

        # Same as above, but we suicide to 0 instead of caller.
        with patch.object(self.analyzer, "_read_storage_key") as mock_read_storage_key:
            self.assertFalse(self.check_state(self.state))
            mock_read_storage_key.assert_not_called()
