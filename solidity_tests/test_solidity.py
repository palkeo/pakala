import unittest
import glob
import os
import logging
import json
import subprocess
import codecs
import collections
import shutil
import sys

from web3 import Web3

from pakala import utils
from pakala import sm
from pakala import env
from pakala import recursive_analyzer
from pakala import analyzer

logger = logging.getLogger(__name__)

MAX_TO_SEND = Web3.toWei(1000, 'ether')
MIN_TO_RECEIVE = Web3.toWei(1, 'wei')
EXEC_TIMEOUT = 1*60
ANALYSIS_TIMEOUT = 30*60
MAX_TRANSACTION_DEPTH = 4
ADDRESS = '0xDEADBEEF00000000000000000000000000000000'
BALANCE = Web3.toWei(1, 'ether')


class SolidityTest(unittest.TestCase):
    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def shortDescription(self):
        return os.path.basename(self.filename)

    @unittest.skipIf(shutil.which("solc") is None, "solc compiler not installed.")
    def runTest(self):
        logger.info("Compiling contract %s" % self.filename)
        p = subprocess.run(
            ["solc", "--optimize", "--combined-json=bin-runtime", self.filename],
            capture_output=True, text=True)
        self.assertEqual(p.returncode, 0,
                         "solc compilation failed:\n%s" % p.stderr)

        output = json.loads(p.stdout)

        assert "contracts" in output
        identifier, properties = list(output['contracts'].items())[0]
        bin_runtime = properties['bin-runtime']

        bin_runtime = codecs.decode(bin_runtime, 'hex')
        logger.info("Compiled. Symbolic execution.")

        e = env.Env(bin_runtime,
                    address=utils.bvv(int(ADDRESS, 16)),
                    caller=utils.DEFAULT_CALLER,
                    origin=utils.DEFAULT_CALLER,
                    balance=utils.bvv(BALANCE))
        s = sm.SymbolicMachine(e)
        s.execute(timeout_sec=EXEC_TIMEOUT)

        self.assertTrue(s.outcomes)

        ra = recursive_analyzer.RecursiveAnalyzer(
                max_wei_to_send=MAX_TO_SEND,
                min_wei_to_receive=MIN_TO_RECEIVE,
                block='invalid')

        # Never contact the blockchain, instead all the storage are 0
        ra.storage_cache = analyzer.EmptyStorage()

        bug = ra.check_states(
                s.outcomes,
                timeout=ANALYSIS_TIMEOUT,
                max_depth=MAX_TRANSACTION_DEPTH)

        self.assertTrue(bug, self.filename)


def load_tests(loader, tests, pattern):
    files = glob.glob(os.path.join(os.path.dirname(__file__), "*.sol"))
    return unittest.TestSuite(map(SolidityTest, files))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('claripy').setLevel(logging.INFO)
    if len(sys.argv) == 1:
        unittest.main()
    else:
        files = sys.argv[1:]
        for filename in files:
            SolidityTest(filename).runTest()
