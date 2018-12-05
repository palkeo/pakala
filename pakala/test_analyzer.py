import claripy
import unittest
import logging

from pakala.analyzer import Analyzer, FakeStorage
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

    def test_suicide(self):
        self.state.suicide_to = self.env.caller
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

    # TODO: Fix it!
    @unittest.skip(
        "Known issue: we are sending back env.balance, that doesn't contain env.value, and it should!"
    )
    def test_send_all_and_suicide(self):
        self.state.calls.append(self.get_call(self.env.balance, to=self.env.caller + 1))
        self.state.suicide_to = self.env.caller
        self.assertFalse(self.check_state(self.state))

    def test_read_concrete(self):
        self.analyzer.storage_cache = FakeStorage({0: 0xBAD1DEA})

        self.state.storage_read[utils.bvv(0)] = claripy.BVS("storage[0]", 256)
        self.state.suicide_to = self.state.storage_read[utils.bvv(0)]
        self.assertFalse(self.check_state(self.state))

        self.state.calls.append(
            self.get_call(
                Web3.toWei(1, "ether") * self.state.storage_read[utils.bvv(0)]
            )
        )
        self.assertTrue(self.check_state(self.state))

    def test_fakestorage_raises(self):
        """If the code accesses a FakeStorage key that we didn't specify,
           it should crash (only meant for testing)."""
        self.analyzer.storage_cache = FakeStorage({42: 0xBAD1DEA})
        self.state.storage_read[utils.bvv(0)] = claripy.BVS("storage[0]", 256)
        with self.assertRaises(KeyError):
            self.check_state(self.state)
