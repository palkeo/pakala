import claripy
import unittest

from pakala import env


class TestEnv(unittest.TestCase):
    def testReplace(self):
        a = env.Env(b"")
        calldata_a = a.calldata.read(0, 32)
        b = a.clean_copy()
        self.assertIs(env.replace(a, b, a.value), b.value)
        self.assertIs(env.replace(a, b, calldata_a), b.calldata.read(0, 32))
