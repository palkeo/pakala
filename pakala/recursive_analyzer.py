import collections
import logging
import functools
import datetime
import time

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
        logger.debug("Old composite state: %s", composite_state)
        composite_state = self._append_state(composite_state, path[-1])
        logger.debug("After appending last state, new composite state: %s", composite_state)

        # If we already encountered the same composite state with some other
        # path...
        if hash(composite_state) in self.state_done:
            return
        self.state_done.add(hash(composite_state))

        logger.debug("Satisfiability check...")
        if not composite_state.solver.satisfiable():
            return

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
        assert composite_state.suicide_to is None

        for key, val in state.storage_read.items():
            if any((key == k).is_true() for k in composite_state.storage_written.keys()):
                # What we read was written
                composite_state.solver.add(
                    composite_state.storage_written[key] == state.storage_read[key])
            elif any((key == k).is_true() for k in composite_state.storage_read.keys()):
                # If what we read is already read by the composite state
                # TODO: is that needed?
                composite_state.solver.add(
                    composite_state.storage_read[key] == state.storage_read[key])
            else:
                # We read something else
                composite_state.storage_read[key] = val
                composite_state.solver.add(
                    state.storage_read[key] == self._read_storage(state, key))

        for key, val in state.storage_written.items():
            composite_state.storage_written[key] = val

        for call in state.calls:
            composite_state.calls.append(call)

        for constraint in state.solver.constraints:
            composite_state.solver.add(constraint)

        if state.suicide_to is not None:
            composite_state.suicide_to = state.suicide_to

        return composite_state

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
            self.path_queue.append(
                (State(self.reference_states[0].env), [state]))

        # Recursive exploration
        time_start = time.process_time()
        while self.path_queue:
            composite_state, path = self.path_queue.popleft()
            #try:
            if self._search_path(composite_state, path) is not None:
                return composite_state, path
            # TODO: Maybe get rid of that? If we are out of memory is it worth
            # trying, really?
            # TODO: Claripy is raising normal z3 errors...
            #except claripy.errors.ClaripyError as error:
            #except Exception as error:
            #    logger.warning("Claripy error in search_path: %s", error)

            if timeout and time.process_time() - time_start > timeout:
                logger.debug("Timeout at depth %i, stopping.", len(path))
                return
            if len(path) > max_depth:
                logger.debug("Over the max allowed depth, stopping.")
                return
