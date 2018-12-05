import claripy
import logging

from pakala import memory
from pakala import utils

logger = logging.getLogger(__name__)


class State(object):
    """Represents a state during the execution of a contract.
    It also contains the interactions with the world.
    """

    def __init__(self, env=None):
        self.env = env
        self.pc = 0  # pylint:disable=invalid-name
        self.stack = []

        # TODO: explain
        self.score = 0

        self.memory = memory.Memory()

        # That's an override to the storage in the blockchain.
        # It's the storage that has been written at the end of the execution of
        # the contract.
        self.storage_written = {}

        # Storage read while executing the contract.
        self.storage_read = {}

        self.calls = []
        self.suicide_to = None

        self.solver = utils.get_solver()

    def __repr__(self):
        return (
            "State(suicide_to=%s, calls=%s, storage_written=%s, "
            "storage_read=%s, env=%s, solver=%s)"
        ) % (
            self.suicide_to,
            self.calls,
            self.storage_written,
            self.storage_read,
            self.env,
            self.solver,
        )

    def as_dict(self):
        return {
            "suicide_to": self.suicide_to,
            "calls": self.calls,
            "storage_written": self.storage_written,
            "storage_read": self.storage_read,
            "env": None if self.env is None else self.env.as_dict(),
            "solver": self.solver.as_dict(),
        }

    def clean(self):
        """Clean the state, when it won't be executed anymore and we are only
        interested by the calls, suicides..."""
        self.stack = []
        self.memory = memory.Memory()
        self.solver.downsize()

    def replace(self, r):
        """Call r() repeatedly, with every single AST that's present in the
        state:
            - in storage, read and written
            - calls
            - in suicide data
            - in solver constraints
        r() can replace symbols in the AST by other symbols. Generally, r() is
        derived from Env.replace(), to substitute an environment with another.
        """
        logger.debug("State.replace %s", r)
        self.storage_written = {r(k): r(v) for k, v in self.storage_written.items()}
        self.storage_read = {r(k): r(v) for k, v in self.storage_read.items()}
        self.calls = [[r(i) for i in call] for call in self.calls]
        self.suicide_to = None if self.suicide_to is None else r(self.suicide_to)

        # TODO: Do something cleaner! This work only with our custom solver mixin.
        self.solver.replace(r)
        # constraints = [r(i) for i in self.solver.constraints]
        # self.solver = utils.get_solver()
        # for c in constraints:
        #    self.solver.add(c)

    def __hash__(self):
        l = [hash(self.env), hash(self.pc), hash(self.memory), hash(self.suicide_to)]
        for i in self.stack:
            l.append(hash(i))
        for call in self.calls:
            for arg in call:
                l.append(hash(arg))
        # The following is because the ordering shouldn't matter:
        x = 0
        for k, v in self.storage_written.items():
            x ^= hash((k, v))
        l.append(x)
        for k, v in self.storage_read.items():
            x ^= hash((k, v))
        l.append(x)
        for constraint in self.solver.constraints:
            x ^= hash(constraint)
        l.append(x)
        return hash(tuple(l))

    def stack_push(self, x):
        if len(self.stack) >= 1024:
            raise utils.CodeError("Stack overflow")
        self.stack.append(x)

    def stack_pop(self):
        if not self.stack:
            raise utils.CodeError("Stack underflow")
        return self.stack.pop()

    def is_interesting(self):
        return bool(self.storage_written or self.calls or self.suicide_to is not None)

    def copy(self):
        """Make a shallow copy of the current environment. Needs to be fast."""
        new_state = State(self.env)
        new_state.pc = self.pc
        new_state.stack = self.stack[:]
        new_state.memory = self.memory.copy()
        new_state.storage_written = self.storage_written.copy()
        new_state.storage_read = self.storage_read.copy()
        new_state.solver = self.solver.branch()
        new_state.calls = self.calls[:]
        new_state.suicide_to = self.suicide_to
        new_state.score = self.score
        return new_state

    # TODO(palkeo): Get rid of that. Needed because of heapq in sm.py...
    def __eq__(self, other):
        return 1

    def __ne__(self, other):
        return 0

    __lt__ = __ne__
    __gt__ = __ne__
    __ge__ = __eq__
    __le__ = __eq__
