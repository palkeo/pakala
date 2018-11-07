Pakala
======

"ilo Pakala li pakala e mani sona"

* Pakala is a tool to search for exploitable bugs in Ethereum smart contracts.
* Pakala is a symbolic execution engine for the Ethereum Virtual Machine.

What does it do?
----------------

Right now, there are only two built-in analyses:

 * call ``suicide()`` to an user-controlled address.
 * ``send()`` more ethers than the attacker sent.

It basically looks for ways to get money out of the contract, into an address the
attacker control. That's the most obvious kind of vulnerability that people would
seek to exploit.

Differences from other tools
----------------------------

This tool operates at the level of EVM bytecode, and aims at being
agnostic to higher-level languages.

It is made for searching exploitable bugs, or vulnerabilities. It won't warn
about potential problems, only exploitable bugs.

The false positive rate should be very low. From experience, the kind of false
positives it will find are for contracts that can be emptied but only after a
certain time without any other address interacting
(which is not guaranteed to happen in real life...)

It uses Z3, but through claripy, which is an abstraction layer that expose a nice
interface, and does caching and black magic.

For simplicity, there is no CFG analysis or anything. It just execute the code symbolically, in order.

It also does a bit of "fuzzing", to unblock itself in certain situations when
pure symbols would not work. That means it tries various concrete values.

It aims at being simple, clean, and have a good test coverage.

How does it work
----------------

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
