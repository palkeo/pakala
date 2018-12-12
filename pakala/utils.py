import numbers
import logging

import claripy

from pakala import claripy_sha3

# Custom logging levels:
INFO_INTERACTIVE = 19
logging.addLevelName(INFO_INTERACTIVE, "INFO_INTERACTIVE")

ADDR_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

DEFAULT_ADDRESS = claripy.BVV(0xCAFEBABEFFFFFFFFFFFFFFFFFFFFFF7CFF7247C9, 256)
DEFAULT_CALLER = claripy.BVV(0xCAFEBABEFFFFFFFFF0202FFFFFFFFF7CFF7247C9, 256)


class CodeError(Exception):
    pass


class InterpreterError(Exception):
    def __init__(self, state, message):
        self.state = state
        super().__init__(message)


def bvv(v):
    return claripy.BVV(v, 256)


def get_solver():
    return claripy_sha3.Solver()


def bvv_to_number(bvv):
    if bvv.symbolic:
        raise ValueError("Passed a BVS in bvv_to_number")
    assert isinstance(bvv.args[0], numbers.Number)
    return bvv.args[0]


def number_to_address(number):
    return "{:#042x}".format(number)
