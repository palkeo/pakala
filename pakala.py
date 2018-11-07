import argparse
import codecs
import datetime
import logging
import sys
import time
import re

from pakala import sm
from pakala import recursive_analyzer
from pakala import analyzer
from pakala import env
from pakala import utils
from pakala import summary

from web3.auto import w3
from web3 import Web3


def ethWeiAmount(arg):
    m = re.match(r'^([0-9.]+) ?(\w+)$', arg)
    if m is None:
        raise argparse.ArgumentError(
            "The argument must be in the form '1 ether' for example.")
    return Web3.toWei(float(m.group(1)), m.group(2))


parser = argparse.ArgumentParser(
    description="Find exploitable Ethereum smart contracts.")
parser.add_argument("contract_addr", help="Address of the contract to analyze.")

timeouts = parser.add_argument_group("limits")
timeouts.add_argument(
        "--exec-timeout",
        help="Timeout in seconds for the symbolic execution stage.\nUse 0 for a system that will stop when the last coverage increase was too long ago.",
        type=int, default=0, metavar='SECONDS')
timeouts.add_argument(
        "--analysis-timeout",
        help="Timeout in seconds for the analysis stage (that will stack the executions and find bugs).\nUse 0 to disable timeout and use only depth limit.",
        type=int, default=0, metavar='SECONDS')


options = parser.add_argument_group('options')
options.add_argument('-v', type=int, default=1, help='log level (0-3)', metavar='LOG_LEVEL')
options.add_argument(
        "--max-outcomes-depth",
        help="Maximum number of outcomes that can be fused together during the analysis step.",
        type=int, default=5)
options.add_argument(
        '-b', '--force-balance',
        type=ethWeiAmount,
        help="Don't use the current contract balance, instead force it to a value.", metavar="BALANCE")
options.add_argument(
        '-B', '--block',
        default='latest',
        help="Use the code/balance/storage at that block instead of latest.")
options.add_argument(
        '-m', '--min-to-receive',
        type=ethWeiAmount,
        default="1 milliether",
        help="Minimum amount to receive from the contract to consider it a bug.",
        metavar="BALANCE")
options.add_argument(
        '-M', '--max-to-send',
        type=ethWeiAmount,
        default="10 ether",
        help="Maximum amount allowed to send to the contract (even if we would receive more).",
        metavar="BALANCE")
options.add_argument(
        '-s', '--summarize', action='store_true',
        help='enable summarizer (EXPERIMENTAL)')

args = parser.parse_args()

if not args.contract_addr:
    parser.print_help()
    sys.exit()

logging.basicConfig(level=[logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG][args.v])

if args.contract_addr == '-':
    # Let's read the runtime bytecode from stdin
    code = sys.stdin.read().strip('\n')
    if not code.isalnum():
        print("Runtime bytecode read from stdin needs to be hexadecimal.")
        sys.exit()
    code = codecs.decode(code, 'hex')
    # Dummy address, dummy balance
    args.contract_addr = '0xDEADBEEF00000000000000000000000000000000'
    if not args.force_balance:
        args.force_balance = Web3.toWei(1, 'ether')
else:
    code = w3.eth.getCode(args.contract_addr, block_identifier=args.block)

balance = (args.force_balance
           or w3.eth.getBalance(args.contract_addr, block_identifier=args.block))

print("Analyzing contract %s with balance %f ether."
      % (args.contract_addr, Web3.fromWei(balance, 'ether')))

if balance < args.min_to_receive:
    print("Balance is smaller than --min-wei-to-receive: "
          "the analyzer will never find anything.")
    sys.exit()

if args.summarize:
    logging.info("Summarizer enabled, we won't constrain the caller/origin "
                 "so more of the contract can get explored. "
                 "It may be slower.")
    e = env.Env(code,
                address=utils.bvv(int(args.contract_addr, 16)),
                balance=utils.bvv(balance))
else:
    e = env.Env(code,
                address=utils.bvv(int(args.contract_addr, 16)),
                caller=utils.DEFAULT_CALLER,
                origin=utils.DEFAULT_CALLER,
                balance=utils.bvv(balance))

print("Starting symbolic execution step...")

s = sm.SymbolicMachine(e)
s.execute(timeout_sec=args.exec_timeout)

print("Symbolic execution phase finished with coverage %i%%."
      % int(s.get_coverage() * 100))
print("Outcomes: %i interesting. %i total and %i partial outcomes."
      % (sum(int(o.is_interesting()) for o in s.outcomes),
         len(s.outcomes),
         len(s.partial_outcomes)))


if args.summarize:
    print()
    print("Methods from the summarizer:")
    summary.HumanSummarizer(s).print_methods()

print()
print("Starting analysis step...")

ra = recursive_analyzer.RecursiveAnalyzer(
        max_wei_to_send=args.max_to_send,
        min_wei_to_receive=args.min_to_receive,
        block=args.block)
bug = ra.check_states(
        s.outcomes,
        timeout=args.analysis_timeout,
        max_depth=args.max_outcomes_depth)

if bug:
    print("=================== Bug found! ===================")
    print('Composite state: %s' % bug[0])
    print()
    print('Path: %s' % bug[1])
    print("=================== Bug found! ===================")
else:
    print("Nothing to report.")
