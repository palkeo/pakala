import claripy
import unittest
import logging

from pakala.memory import Memory, CalldataMemory
from pakala import utils

logging.basicConfig(level=logging.DEBUG)


class TestMemory(unittest.TestCase):
    def setUp(self):
        self.mem = Memory()

    def assertBEqual(self, a, b):
        self.assertTrue((a == b).is_true(), msg="%s != %s" % (a, b))

    def assertBNotEqual(self, a, b):
        self.assertTrue((a == b).is_false(), msg="%s == %s" % (a, b))

    def test_read_default(self):
        self.assertBEqual(self.mem.read(1, 1), 0)

    def overwrite(self, a, b):
        self.mem.write(a[0], a[1], claripy.BVV(0x42, a[1] * 8))
        self.assertBEqual(self.mem.read(a[0], a[1]), 0x42)
        self.mem.write(b[0], b[1], claripy.BVV(0x01020304, b[1] * 8))
        self.assertBEqual(self.mem.read(b[0], b[1]), 0x01020304)
        self.assertBNotEqual(self.mem.read(a[0], a[1]), 0x42)

    def test_overwrite_same(self):
        self.overwrite((0, 4), (0, 4))

    def test_overwrite_simple(self):
        self.overwrite((1, 1), (0, 4))

    def test_overwrite_left(self):
        self.overwrite((0, 1), (0, 4))

    def test_overwrite_right(self):
        self.overwrite((3, 1), (0, 4))

    def test_partial_overwrite_left(self):
        self.mem.write(0, 4, claripy.BVV(0x50515253, 32))
        self.mem.write(2, 4, claripy.BVV(0x60616263, 32))
        self.assertBEqual(self.mem.read(0, 2), 0x5051)
        self.assertBEqual(self.mem.read(2, 4), 0x60616263)
        self.assertBEqual(self.mem.read(0, 6), 0x505160616263)
        self.assertBEqual(self.mem.read(1, 1), 0x51)
        self.assertBEqual(self.mem.read(5, 1), 0x63)

    def test_partial_overwrite_right(self):
        self.mem.write(2, 4, claripy.BVV(0x60616263, 32))
        self.mem.write(0, 4, claripy.BVV(0x50515253, 32))
        self.assertBEqual(self.mem.read(0, 2), 0x5051)
        self.assertBEqual(self.mem.read(2, 4), 0x52536263)
        self.assertBEqual(self.mem.read(0, 6), 0x505152536263)
        self.assertBEqual(self.mem.read(1, 1), 0x51)
        self.assertBEqual(self.mem.read(5, 1), 0x63)

    def test_overwrite_inside(self):
        self.mem.write(10, 6, claripy.BVV(0x112233445566, 8 * 6))
        self.mem.write(12, 2, claripy.BVV(0x3040, 16))
        self.assertBEqual(self.mem.read(10, 6), 0x112230405566)

    def test_successive_left(self):
        self.mem.write(0, 4, claripy.BVV(0x01020304, 32))
        self.mem.write(4, 4, claripy.BVV(0x05060708, 32))
        self.assertBEqual(self.mem.read(0, 8), 0x0102030405060708)

    def test_successive_right(self):
        self.mem.write(4, 4, claripy.BVV(0x05060708, 32))
        self.mem.write(0, 4, claripy.BVV(0x01020304, 32))
        self.assertBEqual(self.mem.read(0, 8), 0x0102030405060708)

    def test_successive(self):
        self.mem.write(0, 4, claripy.BVV(0x11223344, 32))
        self.mem.write(6, 4, claripy.BVV(0x55667788, 32))
        self.assertBEqual(self.mem.read(0, 11), 0x1122334400005566778800)

    def test_read(self):
        self.mem.write(10, 4, claripy.BVV(0xAABBCCDD, 32))
        self.assertBEqual(self.mem.read(8, 4), 0x0000AABB)
        self.assertBEqual(self.mem.read(12, 4), 0xCCDD0000)
        self.assertBEqual(self.mem.read(11, 2), 0xBBCC)
        self.assertBEqual(self.mem.read(9, 1), 0)
        self.assertBEqual(self.mem.read(14, 1), 0)

        with self.assertRaises(utils.CodeError):
            self.mem.read(0, 0)
        with self.assertRaises(utils.CodeError):
            self.mem.read(999999999999, 32)

    def test_size(self):
        self.assertEqual(self.mem.size(), 0)
        self.mem.write(10, 4, claripy.BVV(42, 4 * 8))
        self.assertEqual(self.mem.size(), 14)

    def test_copy(self):
        self.mem.write(1, 1, claripy.BVV(42, 8))
        new_mem = self.mem.copy()
        new_mem.write(1, 1, claripy.BVV(43, 8))
        self.assertBEqual(self.mem.read(1, 1), 42)
        self.assertBEqual(new_mem.read(1, 1), 43)

    def test_hash(self):
        self.mem.write(0, 1, claripy.BVV(42, 8))
        self.mem.write(10, 1, claripy.BVV(43, 8))
        mem_copy = self.mem.copy()
        self.assertEqual(hash(self.mem), hash(mem_copy))

        self.mem.write(5, 1, claripy.BVV(44, 8))
        self.assertNotEqual(hash(self.mem), hash(mem_copy))
        mem_copy.write(5, 1, claripy.BVV(44, 8))
        self.assertEqual(hash(self.mem), hash(mem_copy))

        self.mem.write(0, 10, claripy.BVV(46, 80))
        self.assertNotEqual(hash(self.mem), hash(mem_copy))
        mem_copy.write(0, 10, claripy.BVV(46, 80))
        self.assertEqual(hash(self.mem), hash(mem_copy))

    def test_copy_from(self):
        calldata = CalldataMemory()
        calldata.read(28, 4)
        calldata_24 = calldata.read(24, 4)

        # self.mem[10 to 20] contains calldata[20 to 30]
        self.mem.copy_from(calldata, 10, 20, 10)

        self.assertIs(self.mem.read(14, 4), calldata_24)
        mem_10 = self.mem.read(10, 4)
        self.assertIs(calldata.read(20, 4), mem_10)

        self.assertBEqual(self.mem.read(18, 2), calldata.read(28, 2))

        # Test writing
        self.mem.write(14, 4, claripy.BVV(0x40414243, 32))
        self.assertBEqual(self.mem.read(14, 4), 0x40414243)
        self.assertBEqual(self.mem.read(18, 2), calldata.read(28, 2))


class TestCalldataMemory(unittest.TestCase):
    def setUp(self):
        self.mem = CalldataMemory()

    def test_readonly(self):
        with self.assertRaises(AssertionError):
            self.mem.write(0, 1, None)
        with self.assertRaises(AssertionError):
            self.mem.copy_from(0, 1, None)

    def test_read_default(self):
        r = self.mem.read(0, 1)
        self.assertTrue(r.symbolic)
