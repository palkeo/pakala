Pakala
======

"ilo Pakala li pakala e mani sona"

* Pakala is a tool to search for exploitable bugs in Ethereum smart contracts.
* Pakala is a symbolic execution engine for the Ethereum Virtual Machine.

The intended public for the tool are security researchers interested by Ethereum / the EVM.

Usage
-----

Example use on a contract, where at that block you could steal money from:

```
./pakala.py 0xF55A32f0107523c14027C4a1e6177cD7291395A0 --block 5790628 --exec-timeout 600
```

See ``./pakala.py`` help for more complete usage information.

Installation
------------

```
pip install pakala
```

It works only with python 3.

What does it do?
----------------

Right now, there are only two built-in analyses:

 * call ``suicide()`` to an user-controlled address.
 * ``send()`` more ethers than the attacker sent.

It basically looks for ways to get money out of the contract, into an address the
attacker control. That's the most obvious kind of vulnerability that people would
seek to exploit.

How does it work
----------------

This tool operates at the level of EVM bytecode, and aims at being
agnostic to higher-level languages.

The false positive rate should be very low. From experience, the kind of false
positives it will find are for contracts that can be emptied but only after a
certain time without any other address interacting
(which is not guaranteed to happen in real life...)

It uses Z3, but through claripy, which is an abstraction layer that expose a nice
interface, and does caching and black magic.

For simplicity, there is no CFG analysis or anything. It just execute the code symbolically, in order.

It also does a bit of "fuzzing", to unblock itself in certain situations when
pure symbols would not work. That means it tries various concrete values.

It is made of two independent layers:

The first one is very similar to "Dr. Y analyzer" (by Yoichi Hirai). It
executes a contract and tries to find a list of "outcomes".
An outcome is a valid execution of the contract that led to a state change
(storage written, or money sent), associated to the precondition that needs
to be satisfied for this specific execution to trigger.

The second layer is able to tell whether an outcome is doing something bad,
corresponding to a vulnerability.
It can also stack multiple outcomes on top of each other, to simulate a sequence
of multiple calls to the contract. That means it's able to detect vulnerabilities
that need more than one transaction (typically, changing the owner, then
calling an "ownerOnly" function).

This approach allow it to only execute the contract once, and then focus on stacking
the outcomes, which is pretty efficient. However, that means there is no support for
calling external contracts. It will never be able to find reentrancy bugs either.

You can use it as a reverse engineering tool: by simply listing the outcomes it
is possible to get a good understanding of what the contract is doing.

Difference with Mythril
-----------------------

Compared to Mythril, that's also a symbolic execution tool developed in Python: Mythril
recursively calls other contracts and does everything in one step.

Because Pakala has these two independent steps it doesn't support calling
other contracts, but this has the upside of being able to build a list of
valid executions that the second step can stack. That's much faster if you
want to go deeper in the number of transactions.

It also give better support for simple contracts that read and write storage,
and where you need to chain multiple transactions.

We have a solidity test suite with various simple contracts that are vulnerable (``solidity_tests/``):

* Pakala found bugs in: 12/12 (``python -m unittest discover solidity_tests/``)
* Mythril found bugs in: 6/12 (``ulimit -Sv 5000000; for i in solidity_tests/*.sol; do echo $i && ../mythril/myth -mether_thief,suicide -x $i -t4 --execution-timeout 600; done``)

Obviously it's biased towards what Pakala supports, as we don't include contracts calling other contracts, for example.

We test things like being able to write to an arbitrary storage location and overriding another
variable, needing multiple transactions, mapping from address to variables, integer overflows...

