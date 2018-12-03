Pakala
======

[![PyPI](https://badge.fury.io/py/pakala.svg)](https://pypi.python.org/pypi/pakala)
[![Build States](https://circleci.com/gh/palkeo/pakala.svg?style=svg)](https://circleci.com/gh/palkeo/pakala)

"ilo Pakala li pakala e mani sona"

* Pakala is a tool to search for exploitable bugs in Ethereum smart contracts.
* Pakala is a symbolic execution engine for the Ethereum Virtual Machine.

The intended public for the tool are security researchers interested by Ethereum / the EVM.

Installation
------------

```
pip3 install pakala
```

It works only with python 3.

Usage
-----

Let's look at this contract: https://etherscan.io/address/0x612f1bdbe93523b7f5036efa87493b76341726e3

The constructor doesn't have the same name as the contract: anybody can call HT() and become owner,
then call withdraw.

Example use on that contract:

```
./pakala.py 0x612f1BDbe93523b7f5036EfA87493B76341726E3 --force-balance="1 ether"
```

The contract balance being 0, we won't be able to have it send us some ethers. So
we say the balance is 1 ETH instead, so it has some money to send us.

The tool with tell you a bug was found, and dump you a path of "states" (each state
being a transaction, with the associated constraints you need to respect).
Advice: look at the calldata[0] to see the function signature for each transaction.

See ``./pakala.py help`` for more complete usage information.

How does it works? What does it do?
-----------------------------------

See the [introductory article](https://www.palkeo.com/projets/ethereum/pakala.html) for more information.
