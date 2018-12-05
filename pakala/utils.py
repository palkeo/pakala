import re
import numbers
import logging

import claripy

# This is toxic material, as it can mess up with the logging configuration with
# its "slogging" module.
from ethereum import opcodes
from ethereum import utils
from ethereum import vm

logging._loggerClass = logging.Logger  # Counter-hack to fix the logging monkey-patch.

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


def int_to_bytes(v, size):
    b = b""
    while v:
        b = bytearray((v % 256,)) + b
        v = v // 256
    if len(b) < size:
        b = bytearray(size - len(b)) + b
    assert len(b) == size
    return b


def bvv_to_number(bvv):
    if bvv.symbolic:
        raise ValueError("Passed a BVS in bvv_to_number")
    assert isinstance(bvv.args[0], numbers.Number)
    return bvv.args[0]


def disassemble(ocode):
    assert isinstance(ocode, bytes)
    o, pushcache = vm.preprocess_code(ocode)
    code = []
    push_data = 0
    i = 0
    while i < len(ocode):
        try:
            # opcodes[] is like ['opcode', nb_input, nb_output, gas, opcode, param]
            instr = opcodes.opcodes[utils.safe_ord(ocode[i])][0]
        except KeyError:
            instr = "INVALID 0x%x" % utils.safe_ord(ocode[i])
        if instr.startswith("PUSH"):
            code.append(instr)
            code.append(pushcache[i])
            for x in range(int(instr[4:]) - 1):
                code.append(0)
            i += int(instr[4:])
        else:
            code.append(instr)
        i += 1
    # cde is like ['opcode', 'opcode', 'push', 87, 'opcode', ...]
    return code


def hex_to_bytes(code):
    code = code.strip()
    if not re.match("^(0x)?[0-9a-zA-Z]*$", code):
        raise ValueError("Invalid code.")
    if code.startswith("0x"):
        code = code[2:]
    groups = [code[n : n + 2] for n in range(0, len(code), 2)]
    # The bytes(bytearray()) is for python2-compatibility.
    return bytes(bytearray(int(i, 16) for i in groups if len(i) == 2))


def number_to_address(number):
    return "{:#042x}".format(number)
