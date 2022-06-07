"""
    pakala: EVM symbolic execution tool and vulnerability scanner.
    Copyright (C) 2018 Korantin Auguste

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import argparse
import codecs
import logging
import sys
import re

from pakala import sm
from pakala import recursive_analyzer
from pakala import env
from pakala import utils
from pakala import summary

from web3.auto import w3
from web3 import Web3
import web3
import coloredlogs


def err_exit(message):
    print(message, file=sys.stderr)
    exit(-1)


def ethWeiAmount(arg):
    m = re.match(r"^([0-9.]+) ?(\w+)$", arg)
    if m is None:
        raise argparse.ArgumentError(
            "The argument must be in the form '1 ether' for example."
        )
    return Web3.toWei(float(m.group(1)), m.group(2))


def addressOrStdin(s):
    if s == "-":
        return s
    if not re.match(r"^0x([0-9a-fA-F]){40}$", s):
        raise argparse.ArgumentError("Invalid address.")
    return Web3.toChecksumAddress(s)


parser = argparse.ArgumentParser(
    description="Find exploitable Ethereum smart contracts."
)

parser.add_argument(
    "contract_addr",
    type=addressOrStdin,
    help="Address of the contract to analyze. "
    "Use '-' for reading runtime bytecode from stdin instead.",
)
parser.add_argument(
    "-v",
    default=str(utils.INFO_INTERACTIVE),
    help="log level (INFO, DEBUG...)",
    metavar="LOG_LEVEL",
)
parser.add_argument(
    "-s", "--summarize", action="store_true", help="enable summarizer (EXPERIMENTAL)"
)

limits = parser.add_argument_group("time/depth limits")
limits.add_argument(
    "--exec-timeout",
    help=(
        "Timeout in seconds for the symbolic execution stage. Use 0 for a "
        "system that will stop when the last coverage increase was too long ago."
    ),
    type=int,
    default=0,
    metavar="SECONDS",
)
limits.add_argument(
    "--analysis-timeout",
    help=(
        "Timeout in seconds for the analysis stage (that will stack the executions "
        "and find bugs). Use 0 to disable timeout and use only depth limit."
    ),
    type=int,
    default=0,
    metavar="SECONDS",
)
limits.add_argument(
    "--max-transaction-depth",
    help=(
        "Maximum number of outcomes that can be fused "
        "together during the analysis step."
    ),
    type=int,
    default=4,
)


environment = parser.add_argument_group("environment")
environment.add_argument(
    "-b",
    "--force-balance",
    type=ethWeiAmount,
    help="Don't use the current contract balance, instead force it to a value.",
    metavar="BALANCE",
)
environment.add_argument(
    "-B",
    "--block",
    default="latest",
    type=lambda block_number: hex(int(block_number))
    if block_number.isnumeric()
    else block_number,
    help="Use the code/balance/storage at that block instead of latest.",
)

symbolic = parser.add_argument_group("symbolic execution tweaks")
symbolic.add_argument(
    "-z",
    "--disable-fuzzing",
    action="store_true",
    help="Disable forced concretization of symbols where we need a concrete value.",
)

analyzer = parser.add_argument_group("analyzer tweaks")
analyzer.add_argument(
    "-m",
    "--min-to-receive",
    type=ethWeiAmount,
    default="1 milliether",
    help="Minimum amount to receive from the contract to consider it a bug.",
    metavar="BALANCE",
)
analyzer.add_argument(
    "-M",
    "--max-to-send",
    type=ethWeiAmount,
    default="10 ether",
    help=(
        "Maximum amount allowed to send to the contract "
        "(even if we would receive more)."
    ),
    metavar="BALANCE",
)


def main():
    args = parser.parse_args()

    if args.v.isnumeric():
        coloredlogs.install(level=int(args.v))
    elif hasattr(logging, args.v.upper()):
        coloredlogs.install(level=getattr(logging, args.v.upper()))
    else:
        err_exit("Logging should be DEBUG/INFO/WARNING/ERROR.")

    try:
        logging.debug("Node working. Block %i ", w3.eth.blockNumber)
    except web3.exceptions.CannotHandleRequest:
        err_exit(
            "Seems like Web3.py can't auto-connect to your Ethereum node.\n"
            "Please have a local node running or set the environment variable WEB3_PROVIDER_URI to the URL of your node."
        )

    if args.contract_addr == "-":
        # Let's read the runtime bytecode from stdin
        code = sys.stdin.read().strip("\n")
        if not code.isalnum():
            err_exit("Runtime bytecode read from stdin needs to be hexadecimal.")
        code = codecs.decode(code, "hex")
        # Dummy address, dummy balance
        args.contract_addr = "0xDEADBEEF00000000000000000000000000000000"
        if not args.force_balance:
            args.force_balance = Web3.toWei(1.337, "ether")
    else:
        addr = Web3.toChecksumAddress(args.contract_addr)
        code = w3.eth.getCode(addr, block_identifier=args.block)


    balance = args.force_balance or w3.eth.getBalance(
           addr, block_identifier=args.block

    )

    print(
        "Analyzing contract at %s with balance %f ether."
            % (addr, Web3.fromWei(balance, "ether"))
    )

    if balance < args.min_to_receive:
        err_exit(
            "Balance is smaller than --min-to-receive: "
            "the analyzer will never find anything."
        )

    if args.summarize:
        logging.info(
            "Summarizer enabled, we won't constrain the caller/origin "
            "so more of the contract can get explored. "
            "It may be slower."
        )
        e = env.Env(
            code,
            address=utils.bvv(int(addr, 16)),
            balance=utils.bvv(balance),
        )
    else:
        e = env.Env(
            code,
            address=utils.bvv(int(addr, 16)),
            caller=utils.DEFAULT_CALLER,
            origin=utils.DEFAULT_CALLER,
            balance=utils.bvv(balance),
        )

    print("Starting symbolic execution step...")

    s = sm.SymbolicMachine(e, fuzz=not args.disable_fuzzing)
    s.execute(timeout_sec=args.exec_timeout)

    print(
        "Symbolic execution finished with coverage %i%%." % int(s.get_coverage() * 100)
    )
    print(
        "Outcomes: %i interesting. %i total and %i unfinished paths."
        % (
            sum(int(o.is_interesting()) for o in s.outcomes),
            len(s.outcomes),
            len(s.partial_outcomes),
        )
    )

    if args.summarize:
        print()
        print("Methods from the summarizer:")
        summary.HumanSummarizer(s).print_methods()

    print()
    print("Starting analysis step...")

    ra = recursive_analyzer.RecursiveAnalyzer(
        max_wei_to_send=args.max_to_send,
        min_wei_to_receive=args.min_to_receive,
        block=args.block,
    )
    bug = ra.check_states(
        s.outcomes, timeout=args.analysis_timeout, max_depth=args.max_transaction_depth
    )

    if bug:
        solver = bug[2]
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            print("Composite state:")
            print(bug[0].debug_string())
            print()
            print()
        print("Path:")
        for i, state in enumerate(bug[1]):
            print()
            print("Transaction %i, symbolic state:" % (i + 1))
            print(state.debug_string())
            print()
            print("Transaction %i, example solution:" % (i + 1))
            print(state.env.solution_string(solver))
            print()
        print()
        print("======> Bug found! Need %i transactions. <======" % len(bug[1]))
    else:
        print("Nothing to report.")


if __name__ == "__main__":
    main()
