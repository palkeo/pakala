import unittest

import claripy

from pakala.claripy_sha3 import Sha3
from pakala.utils import get_solver


class TestSha3Support(unittest.TestCase):
    def test_sha3_support(self):
        a = claripy.BVV(0, 256)
        Sha3(a)

    def test_sha3_equality(self):
        a = claripy.BVV(1, 256)
        b = claripy.BVV(2, 256)
        self.assertEqual(Sha3(a), Sha3(claripy.BVV(1, 256)))
        self.assertNotEqual(Sha3(a), Sha3(b))

    def test_sha3_solver(self):
        s = get_solver()

        s1 = claripy.BVS('s1', 256)
        s2 = claripy.BVS('s2', 256)

        self.assertTrue(s.satisfiable(extra_constraints=[Sha3(s1) == Sha3(s2)]))

        s.add(Sha3(s1) == Sha3(s2))
        self.assertTrue(s.satisfiable())

        self.assertTrue(s.satisfiable(
            extra_constraints=[Sha3(Sha3(s1) + 1) == Sha3(Sha3(s2) + 1)]))

        s.add(Sha3(Sha3(s1) + 1) == Sha3(Sha3(s2) + 1))
        self.assertTrue(s.satisfiable())

        self.assertFalse(s.satisfiable(
            extra_constraints=[Sha3(Sha3(s1) + 2) == Sha3(Sha3(s2) + 1)]))
        self.assertFalse(s.satisfiable(
            extra_constraints=[Sha3(Sha3(s1)) + 1 == Sha3(Sha3(s2) + 1)]))

        s.add(Sha3(Sha3(s1)) + 3 == Sha3(Sha3(s2)) + 1)
        self.assertFalse(s.satisfiable())


if __name__ == '__main__':
    unittest.main()
