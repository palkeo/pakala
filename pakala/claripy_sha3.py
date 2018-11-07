"""
Monkeypatch claripy and add support for SHA1

The idea is to be able to compare claripy ASTs containing SHA1, which is good
enough for storage.
If we try to test for satisfiability or anything on these ASTs, it will crash.

/!\ This is an experimental module, and it's particularly ugly.
    But it works, more or less.
"""

import random
import numbers

import ethereum.utils

import pakala.utils

from claripy.ast import bv
import claripy


"""
def concrete_sha3(value):
    if isinstance(value, claripy.bv.BVV):
        value = value.value
    else:
        value = value.as_long()
    #assert isinstance(value, numbers.Number), "%s %s" % (value, type(value))
    return utils.sha3(value)
"""


def sha3_monkeypatch():
    bv.BV.SHA3 = lambda x: bv.BV('SHA3', [x], length=256)

    # Previous tries, for reference:

    #bv.BV.SHA3 = bv.operations.op('SHA3', (bv.BV,), bv.BV, calc_length=bv.operations.basic_length_calc)

    #claripy.bv.BVV.SHA3 = lambda self: BVV(ethereum.utils.big_endian_to_int(ethereum.utils.sha3(pakala.utils.int_to_bytes(self.value))), 256)

    #claripy.backends.z3._op_raw['SHA3'] = lambda i: claripy.backends.z3.BVV(claripy.BVV(hash(i), 256))
    #claripy.backends.concrete._op_raw['SHA3'] = concrete_sha3
