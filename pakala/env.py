import pprint
import time

import claripy
from eth.vm import code_stream
from web3 import Web3

from pakala import memory


ENV_VARS = (
    ("caller", None, None),
    ("origin", None, None),
    ("value", None, Web3.toWei(10 ** 6, "ether")),
    ("address", None, None),
    ("balance", None, Web3.toWei(10 ** 9, "ether")),
    ("gas", None, None),
    ("block_timestamp", int(time.time()), int(time.time() + 86400 * 365)),
    ("block_number", 6000000, 10 ** 9),
    ("calldata_size", None, 2 ** 20),
    ("coinbase", None, None),
    ("difficulty", None, None),
    ("chainid", None, None),
)


class Env(object):
    def __init__(self, code, **kwargs):
        if isinstance(code, code_stream.CodeStream):
            self.code = code
        else:
            self.code = code_stream.CodeStream(code)

        self.calldata = memory.CalldataMemory()
        self.block_hashes = {}

        for name, _, _ in ENV_VARS:
            default = claripy.BVS(name, 256)
            setattr(self, name, kwargs.get(name, default))

    def __repr__(self):
        return "Env(balance=%s, caller=%s, value=%s)" % (
            self.balance,
            self.caller,
            self.value,
        )

    def as_dict(self):
        return {"balance": self.balance, "caller": self.caller, "value": self.value}

    def clean_copy(self):
        """Create a new env, which is a copy of the current one but with
        new symbolic variables (with the same name)"""
        new_env = Env(self.code)

        for name, _, _ in ENV_VARS:
            value = getattr(self, name)
            if value.symbolic:
                setattr(new_env, name, claripy.BVS(name, 256))
            else:
                setattr(new_env, name, value)

        new_env.calldata = self.calldata.copy()
        for addr, value in self.calldata._mem.items():
            new_env.calldata._mem[addr] = claripy.BVS(
                "calldata[%i]" % addr, value.size()
            )

        # Block hashes are always the same (but the current number can change)
        new_env.block_hashes = self.block_hashes.copy()
        return new_env

    def extra_constraints(self):
        for name, min_, max_ in ENV_VARS:
            if min_ is not None:
                yield getattr(self, name) >= min_
            if max_ is not None:
                yield getattr(self, name) <= max_

    def solution_string(self, solver):
        calldata_size = max(solver.min(self.calldata_size), self.calldata.size())
        solution = {
            "data": "{0:0{1}x}".format(
                solver.min(self.calldata.read(0, calldata_size)), calldata_size * 2
            ),
            "value": solver.min(self.value),
            "caller": "{0:#042x}".format(solver.eval(self.caller, 1)[0]),
        }
        return pprint.pformat(solution, width=90)


def replace(old_env, new_env, var):
    """Replace all the references of old_env to references to new_env, in the
    claripy AST var."""
    for name, _, _ in ENV_VARS:
        var = var.replace(getattr(old_env, name), getattr(new_env, name))

    for addr in old_env.calldata._mem.keys():
        var = var.replace(old_env.calldata._mem[addr], new_env.calldata._mem[addr])

    return var
