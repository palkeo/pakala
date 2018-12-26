import unittest
import claripy

from pakala import env


class TestEnv(unittest.TestCase):
    def testReplace(self):
        a = env.Env(b"")
        calldata_a = a.calldata.read(0, 32)
        b = a.clean_copy()
        self.assertIs(env.replace(a, b, a.value), b.value)
        self.assertIs(env.replace(a, b, calldata_a), b.calldata.read(0, 32))

    def testReplace2(self):
        a = env.Env(b"")
        sa = a.value + a.caller + a.origin

        b = a.clean_copy()
        sb = b.value + b.caller + b.origin

        self.assertIsNot(sa, sb)
        self.assertIs(env.replace(a, b, sa), sb)
