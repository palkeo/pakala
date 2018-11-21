import collections
import logging
import functools
import datetime
import time
import itertools

import claripy

from pakala import analyzer
from pakala import env
from pakala import utils
from pakala.state import State

logger = logging.getLogger(__name__)


def is_function(state, function):
    return state.solver.satisfiable([
        state.env.calldata.read(0, 4) == function])


class RecursiveAnalyzer(analyzer.BaseAnalyzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Each element in the queue is a couple:
        # 0) State, a state made of the successive applications of all the state
        #    of the path, except the last one.
        # 1) list, path of states we applied.
        self.path_queue = collections.deque()

        # The dict in the queue before
        self.state_done = set()

        self.reference_states = []

    @property
    def address(self):
        return self.reference_states[0].env.address

    @property
    def caller(self):
        return self.reference_states[0].env.caller

    def _search_path(self, composite_state, path):
        logger.debug("Search path: %s", path)
        logger.debug("Composite state: %s", composite_state)

        # If we already encountered the same composite state with some other
        # path...
        if hash(composite_state) in self.state_done:
            return
        self.state_done.add(hash(composite_state))

        logger.debug("Check for bugs in composite state...")
        if self.check_state(composite_state, path=path):
            return path

        # If we kill the contract, we can't make any more call!
        if path[-1].suicide_to is not None:
            return

        # We have to downsize the used solver to free memory in z3, otherwise
        # they will collectively end up eating all the memory.
        composite_state.solver.downsize()

        for reference_state in self.reference_states:
            self.path_queue.append(
                (composite_state.copy(), path + [reference_state]))

    def _append_state(self, composite_state, state):
        logger.debug("_append_state: appending state %s to composite state %s",
                     state, composite_state)
        assert composite_state.suicide_to is None

        composite_state.solver = composite_state.solver.combine([state.solver])
        composite_state.storage_read.update(state.storage_read)

        if not composite_state.solver.satisfiable():
            return []
        assert state.solver.satisfiable()

        for call in state.calls:
            composite_state.calls.append(call)

        if state.suicide_to is not None:
            composite_state.suicide_to = state.suicide_to

        # Resolve read/write

        def apply_read(r_key, r_val, composite_state):
            """Apply a read operation with (key, value) to the state."""
            composite_states_next = []

            # Here we consider the cases where it's possible to read something
            # we previously wrote to.
            not_overwritten_c = []
            for w_key, w_val in composite_state.storage_written.items():
                read_written = [r_key == w_key, r_val == w_val]

                if composite_state.solver.satisfiable(extra_constraints=read_written):
                    not_overwritten_c.append(r_key != w_key)
                    cs = composite_state.copy()
                    cs.solver.add(read_written)
                    composite_states_next.append(cs)
                    logger.debug("Found key read %s, corresponding to key written %s", r_key, w_key)

            # Is it not something we previously wrote to?
            for c in not_overwritten_c:
                composite_state.solver.add(c)
            composite_state.solver.add(
                state.storage_read[r_key] == self._read_storage(state, r_key))
            if composite_state.solver.satisfiable():
                composite_states_next.append(composite_state)

            return composite_states_next

        composite_states = [composite_state]
        for r_key, r_val in state.storage_read.items():
            composite_states = list(itertools.chain.from_iterable(
                apply_read(r_key, r_val, composite_state)
                for composite_state in composite_states))

        for composite_state in composite_states:
            for key, val in state.storage_written.items():
                composite_state.storage_written[key] = val

        logger.debug("_append_state: found states: %s", composite_states)

        return composite_states

    def check_states(self, states, timeout, max_depth):
        states = [state for state in states if state.is_interesting()]
        if not states:
            return

        # Each state must have its own independent environment
        assert not self.reference_states
        assert all(i.env is states[0].env for i in states)
        for state in states:
            old_env = state.env
            new_env = old_env.clean_copy()
            state = state.copy()
            state.env = new_env
            state.replace(functools.partial(env.replace, old_env, new_env))
            self.reference_states.append(state)

        # Add them to the paths to explore
        for state in self.reference_states:
            assert state.solver.satisfiable()
            self.path_queue.append(
                (State(self.reference_states[0].env), [state]))

        # Recursive exploration
        last_path_len = 1
        time_start = time.process_time()
        while self.path_queue:
            initial_composite_state, path = self.path_queue.popleft()

            if len(path) > last_path_len:
                logger.log(utils.INFO_INTERACTIVE,
                           "Now scanning paths of length %i.", len(path))
                last_path_len = len(path)
            if len(path) > max_depth:
                logger.debug("Over the max allowed depth, stopping.")
                return

            new_composite_states = self._append_state(
                    initial_composite_state, path[-1])

            for composite_state in new_composite_states:
                if self._search_path(composite_state, path) is not None:
                    return composite_state, path

            if timeout and time.process_time() - time_start > timeout:
                logger.debug("Timeout at depth %i, stopping.", len(path))
                return
