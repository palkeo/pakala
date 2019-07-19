Pakala
======

[![PyPI](https://badge.fury.io/py/pakala.svg)](https://pypi.python.org/pypi/pakala)
[![Build States](https://circleci.com/gh/palkeo/pakala.svg?style=svg)](https://circleci.com/gh/palkeo/pakala)

<img align="right" src="https://www.palkeo.com/en/_images/pakala-mani-sona.svg.png">

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

Let's look at [0xeBE6c7a839A660a0F04BdF6816e2eA182F5d542C](http://eveem.com/code/0xeBE6c7a839A660a0F04BdF6816e2eA182F5d542C):
it has a ``transfer(address _to, uint256 _value)`` function. It is supposedly protected by a ``require(call.value - _value) >= 0``
but that condition always holds because we are substracting two unsigned integers, so the result is also an unsigned integer.

Let's scan it:

```
pakala 0xeBE6c7a839A660a0F04BdF6816e2eA182F5d542C --force-balance="1 ether"
```

The contract balance being 0, we won't be able to have it send us some ethers.
So we override the balance to be 1 ETH: then it has some "virtual" money to send us.

The tool with tell you a bug was found, and dump you a path of "states". Each
state corresponds to a transaction, with constraints that needs to be respected
for that code path to be taken, storage that has been read/written...

Advice: look at ``calldata[0]`` in the constraints to see the function signature for each transaction.

See ``pakala help`` for more complete usage information.

How does it works? What does it do?
-----------------------------------

See the [introductory article](https://www.palkeo.com/projets/ethereum/pakala.html) for more information and a demo.

In a nutshell:

* It's very good at finding simple bugs in simple contracts.
* The false-positive rate is very low. If it flags your contract it's likely people can drain it.
* It can exploit non-trivial bugs requiring to overwrite some storage keys with others (array size underflow...), has a good
  modeling of cryptographic hashes, and support chaining multiple transactions.

However, It only implements an "interesting" subset of the EVM. It doesn't handle:

* gas,
* precompiles,
* or a contract interacting with other contracts (DELEGATECALL, STATICCALL...).

This means that CALL support is limited to sending ethers. Other tools like Manticore can do that much better.

