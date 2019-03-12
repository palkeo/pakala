import logging
import numbers

import claripy

from pakala import utils

from web3 import Web3


# We can load up to this many keys from the contract storage. More than that
# and we won't load them all, and read them lazily instead (which is less precise).
MAX_STORAGE_KEYS = 32

# When we cannot list the keys, we can always try these ones:
STORAGE_KEYS_WHEN_CANNOT_LIST = list(range(10))


logger = logging.getLogger(__name__)


class BaseAnalyzer(object):
    """Base class for an Analyzer.

    Child classes need to define `caller` and `address`.
    """

    def __init__(self, max_wei_to_send, min_wei_to_receive, block="latest"):
        self.web3 = Web3()
        self.web3.eth.defaultBlock = block
        self.max_wei_to_send = max_wei_to_send
        self.min_wei_to_receive = min_wei_to_receive

        self.actual_storage = None

        # Whether or not actual_storage is guaranteed to contain all the storage,
        # or just a subset of it. Will be False for contracts with a lot of keys
        # so that we cannot load them all.
        # For testing we can replace actual_storage with a dict so it's never
        # actually filled. In that case we can assume it's exhaustive.
        self.actual_storage_exhaustive = True

    @property
    def hex_addr(self):
        return self.web3.toChecksumAddress(
            utils.number_to_address(utils.bvv_to_number(self.address))
        )

    def _read_storage_key(self, key):
        return self.web3.toInt(self.web3.eth.getStorageAt(self.hex_addr, key))

    def _fill_actual_storage(self):
        try:
            storage_keys = [
                self.web3.toInt(hexstr=k)
                for k in self.web3.parity.listStorageKeys(
                    self.hex_addr, MAX_STORAGE_KEYS, None, self.web3.eth.defaultBlock
                )
            ]
        except Exception as e:
            # If we cannot list storage keys, let's read the beginning of the
            # space, and below we will mark that it's not exhaustive anyway.
            logger.warning(
                "Cannot list storage keys (%s). We will loose a bit of accuracy. "
                "Try to use a node that supports the parity_listStorageKeys RPC. ",
                e.__class__.__name__,
            )
            storage_keys = STORAGE_KEYS_WHEN_CANNOT_LIST
            self.actual_storage_exhaustive = False
        else:
            assert len(storage_keys) <= MAX_STORAGE_KEYS
            self.actual_storage_exhaustive = len(storage_keys) < MAX_STORAGE_KEYS

        self.actual_storage = {k: self._read_storage_key(k) for k in storage_keys}

        logger.info(
            "Loaded %i storage slots from the contract (%s). %i non-zero.",
            len(storage_keys),
            "exhaustive" if self.actual_storage_exhaustive else "non-exhaustive",
            sum(1 for v in self.actual_storage.values() if v != 0),
        )
        logger.debug("actual_storage: %r", self.actual_storage)

    def _read_storage(self, state, key):
        logger.debug("Reading storage %r" % key)

        if self.actual_storage is None:
            self._fill_actual_storage()

        # If our storage is not exhaustive, let's try to concretize the key and read the
        # corresponding storage directly.
        if not self.actual_storage_exhaustive:
            try:
                concrete_keys = state.solver.eval(key, 2)
            except claripy.errors.UnsatError as e:
                # We will lose accuracy, and assume that our actual_storage is exhaustive...
                logger.debug(
                    "Encountered an exception when resolving key %r: %r", key, e
                )
            else:
                for concrete_key in concrete_keys:
                    if concrete_key not in self.actual_storage:
                        self.actual_storage[concrete_key] = self._read_storage_key(
                            concrete_key
                        )
                if len(concrete_keys) == 1:
                    return self.actual_storage[concrete_keys[0]]
                else:
                    # We will lose accuracy, and assume that our actual_storage is exhaustive...
                    logger.debug(
                        "Non-exhaustive storage and multiple values possible for key %r",
                        key,
                    )

        symbolic_storage = utils.bvv(0)  # When uninitialized: 0
        for k, v in self.actual_storage.items():
            if v != 0:
                symbolic_storage = claripy.If(key == k, v, symbolic_storage)

        return symbolic_storage

    def check_state(self, state, path=None):
        """Check a reachable state for bugs"""
        logger.debug("Check state: %s", state)
        logger.debug("Constraints: %s", state.solver.constraints)

        solver = state.solver.branch()

        if path is None:
            path = [state]
            # Static read were we never wrote, but we know the key is not symbolic.
            # So we go and fetch it.
            for key, value in state.storage_read.items():
                constraint = state.storage_read[key] == self._read_storage(state, key)
                solver.add(constraint)
                logger.debug("Add storage constraint: %s", constraint)

        for s in path:
            solver.add(list(s.env.extra_constraints()))
            solver.add([
                s.env.caller == utils.DEFAULT_CALLER,
                s.env.origin == utils.DEFAULT_CALLER,
            ])

        # Calls
        total_sent = sum(s.env.value for s in path)
        sent_constraints = [s.env.value < self.max_wei_to_send for s in path]

        total_received_by_me = utils.bvv(0)
        total_received = utils.bvv(0)

        for call in state.calls:
            # TODO: Improve delegatecall support! And make it clearer it's
            # delegatecall, not just based on the length.
            assert 6 <= len(call) <= 7
            value, to, gas = call[-3:]  # pylint: disable=unused-variable,invalid-name

            delegatecall = len(call) == 6

            if delegatecall:
                if solver.satisfiable(extra_constraints=[to[159:0] == self.caller[159:0]]):
                    logger.info("Found delegatecall bug.")
                    return True
            else:
                total_received_by_me += claripy.If(to[159:0] == self.caller[159:0], value, utils.bvv(0))
                total_received += value
                solver.add(value <= total_sent + path[0].env.balance)

        final_balance = (
            path[0].env.balance
            + total_sent
            - total_received
        )

        # Suicide
        if state.selfdestruct_to is not None:
            constraints = [
                final_balance >= self.min_wei_to_receive,
                state.selfdestruct_to[159:0] == self.caller[159:0],
            ]
            logger.debug("Check for selfdestruct bug with constraints %s", constraints)
            if solver.satisfiable(extra_constraints=constraints):
                logger.info("Found selfdestruct bug. Model: %s",
                            solver.get_model())
                return True

        if total_received_by_me is utils.bvv(0):
            return False

        logger.debug("Found calls back to caller: %s", total_received_by_me)

        solver.add(sent_constraints)
        solver.add([
                claripy.SGE(final_balance, 0),
                total_received_by_me > total_sent,  # I get more than what I sent?
                total_received_by_me > self.min_wei_to_receive,
        ])

        if solver.satisfiable():
            logger.info("Found call bug. Model: %s", solver.get_model())
            return True

        return False


class Analyzer(BaseAnalyzer):
    """Simple Analyzer class, where caller and address are given explicitly."""

    def __init__(self, address, caller, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.caller = caller
        self.address = address
