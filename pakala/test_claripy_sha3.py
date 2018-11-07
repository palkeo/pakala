import unittest

import claripy

from pakala import claripy_sha3
claripy_sha3.sha3_monkeypatch()

class TestSha3Support(unittest.TestCase):
    def test_sha3_support(self):
        a = claripy.BVV(0, 256)
        a.SHA3()

    def test_sha3_equality(self):
        a = claripy.BVV(1, 256)
        b = claripy.BVV(2, 256)
        self.assertEqual(a.SHA3(), claripy.BVV(1, 256))
        self.assertNotEqual(a.SHA3(), b.SHA3())

    # TODO: Make it work nicely...
    def todo(self):
        s = claripy.Solver()

        e = s.eval(a.SHA3(), 2)
        self.assertEqual(len(e), 1)
        f = s.eval(a.SHA3(), 2)
        self.assertEqual(len(f), 1)
        self.assertNotEqual(e, f)


if __name__ == '__main__':
    unittest.main()
