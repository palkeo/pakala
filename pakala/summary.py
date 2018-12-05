"""Experimental module to print basic information about a contract.

For now it gives a list of its methods (and try to resolve the name from their
signatures), and interesting properties inferred on them (onlyOwner? can we send
money to that method?...).
"""

import collections
import json
import lzma

from pakala import sm


# TODO: Don't hardcode it...
SIGNATURE_FILE = "../signatures.json.xz"


class HumanSummarizer:
    def __init__(self, symbolic_machine):
        self.signatures = json.load(lzma.open(SIGNATURE_FILE))
        self.signatures["0x00000000"] = "fallback"
        for magic, signature in self.signatures.items():
            assert isinstance(signature, str)
            assert isinstance(magic, str)
            assert magic.startswith("0x"), magic
            assert len(magic) == 10, magic
            assert int(magic, 16) is not None  # Should not raise any exception

        self.sm = symbolic_machine

    def states_by_method(self):
        states = self.sm.outcomes + self.sm.partial_outcomes
        m = collections.defaultdict(list)
        for state in states:
            signature = 0
            solutions = state.solver.eval(state.env.calldata.read(0, 4), 2)
            assert solutions, "All states should be reachable"
            if len(solutions) == 1:
                signature = solutions[0]
            # If there are multiple solutions, signature stays null, which will be
            # the default method.
            m["{0:#010x}".format(signature)].append(state)
        return m

    def print_methods(self):
        for method, states in sorted(self.states_by_method().items()):
            signature = self.signatures.get(method, "")

            flags = set()
            all_not_payable = True
            all_only_payable = True
            for state in states:
                if state.calls:
                    flags.add("call")
                if state.suicide_to:
                    flags.add("suicide")

                for s in self.sm.partial_outcomes:
                    if state is s:
                        flags.add("errored")

                for s in self.sm.outcomes:
                    if state is s and state.is_interesting():
                        flags.add("interesting")

                if state.solver.satisfiable(extra_constraints=[state.env.value > 0]):
                    all_not_payable = False
                if state.solver.satisfiable(extra_constraints=[state.env.value == 0]):
                    all_only_payable = False

                # TODO: actually read the storage...
                read_constraints = [v == 1 for v in state.storage_read.values()]
                try:
                    callers = state.solver.eval(
                        state.env.caller[159:0], 2, extra_constraints=read_constraints
                    )
                    if len(callers) == 1:
                        flags.add("onlyOwner")
                except Exception:
                    pass

                state.solver.downsize()

            if all_not_payable:
                flags.add("notPayable")
            if all_only_payable:
                flags.add("onlyPayable")

            print("%s %s %s" % (method, signature.ljust(40), " ".join(sorted(flags))))
