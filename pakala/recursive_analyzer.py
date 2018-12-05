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
import logging
import functools
import datetime
import time
import itertools
import pprint

import claripy

from pakala import analyzer
from pakala import env
from pakala import utils
from pakala.state import State

logger = logging.getLogger(__name__)


DEBUG_MARK_PATH = []


def is_function(state, function):
    return state.solver.satisfiable([state.env.calldata.read(0, 4) == function])


def with_new_env(state):
    assert state.solver.satisfiable()
    old_env = state.env
    new_env = old_env.clean_copy()
    state = state.copy()
    state.env = new_env
    state.replace(functools.partial(env.replace, old_env, new_env))

    for read_k, read_v in state.storage_read.items():
        new_v = claripy.BVS("storage[%s]" % read_k, 256)
        state.replace(lambda ast: ast.replace(read_v, new_v))

    assert state.solver.satisfiable()
    return state


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
        return self.reference_states[0][0].env.address

    @property
    def caller(self):
        return self.reference_states[0][0].env.caller

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

        # For each reference state, find the right one (with an unused env)
        # and add it to the queue.
        for reference_states in self.reference_states:
            for reference_state in reference_states:
                if all(s is not reference_state for s in path):
                    self.path_queue.append(
                        (composite_state.copy(), path + [reference_state])
                    )
                    break

    def _append_state(self, composite_state, state):
        # May fail because pprint compare claripy symbols. So only if needed.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "_append_state: appending state %s\nto composite state %s",
                pprint.pformat(state.as_dict()),
                pprint.pformat(composite_state.as_dict()),
            )

        assert composite_state.suicide_to is None

        composite_state.solver = composite_state.solver.combine([state.solver])

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
                not_overwritten_c.append(r_key != w_key)

                if composite_state.solver.satisfiable(extra_constraints=read_written):
                    cs = composite_state.copy()
                    cs.solver.add(read_written)
                    composite_states_next.append(cs)
                    logger.debug(
                        "Found key read %s, corresponding to key written %s",
                        r_key,
                        w_key,
                    )

            # Is it not something we previously wrote to?
            composite_state.solver.add(not_overwritten_c)
            composite_state.solver.add(
                state.storage_read[r_key] == self._read_storage(state, r_key)
            )
            if composite_state.solver.satisfiable():
                composite_states_next.append(composite_state)

            return composite_states_next

        composite_states = [composite_state]
        for r_key, r_val in state.storage_read.items():
            composite_states = list(
                itertools.chain.from_iterable(
                    apply_read(r_key, r_val, composite_state)
                    for composite_state in composite_states
                )
            )

        for composite_state in composite_states:
            # Delete any storage_written at the same key in the composite
            # state.
            for c_key in list(composite_state.storage_written.keys()):
                for key in state.storage_written.keys():
                    if not composite_state.solver.satisfiable(
                        extra_constraints=[key != c_key]
                    ):
                        del composite_state.storage_written[c_key]
                        break

            for key, val in state.storage_written.items():
                composite_state.storage_written[key] = val

        # May fail because pprint compare claripy symbols. So only if needed.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "_append_state: found states: %s",
                pprint.pformat(
                    [composite_state.as_dict() for composite_state in composite_states]
                ),
            )

        return composite_states

    def check_states(self, states, timeout, max_depth):
        states = [state for state in states if state.is_interesting()]
        if not states:
            return

        # Each state must have its own independent environment
        assert not self.reference_states

        # For each state, a list of equivalent state, but each in a different
        # env so that they can be stacked together.
        self.reference_states = []
        for state in states:
            self.reference_states.append(
                [with_new_env(state) for _ in range(max_depth)]
            )
            # Add it to the paths to explore
            self.path_queue.append((State(), [self.reference_states[-1][0]]))

        # Recursive exploration
        last_path_len = 1
        time_start = time.process_time()
        while self.path_queue:
            initial_composite_state, path = self.path_queue.popleft()

            if len(path) > last_path_len:
                logger.log(
                    utils.INFO_INTERACTIVE,
                    "Now scanning paths of length %i.",
                    len(path),
                )
                last_path_len = len(path)
            if len(path) > max_depth:
                logger.debug("Over the max allowed depth, stopping.")
                return

            if DEBUG_MARK_PATH and all(
                is_function(s, f) for s, f in zip(path, DEBUG_MARK_PATH)
            ):
                logger.warning("DEBUG_MARK_PATH len %i", len(path))
                logger.warning("path: %s", path)
                breakpoint()

            new_composite_states = self._append_state(initial_composite_state, path[-1])

            for composite_state in new_composite_states:
                if self._search_path(composite_state, path) is not None:
                    return composite_state, path

            if timeout and time.process_time() - time_start > timeout:
                logger.debug("Timeout at depth %i, stopping.", len(path))
                return
