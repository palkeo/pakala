import logging

import claripy

from pakala import utils

logger = logging.getLogger(__name__)

# Maximum size the memory is allowed to have.
MEMORY_SIZE = 4096


def _slice(v, start, end):
    start = v.size() - start * 8 - 1
    end = 0 if end is None else (v.size() - end * 8)
    assert end >= 0 and start >= 0 and end <= start
    return v[start:end]


class Memory(object):
    """Base class for memory. Uninitialized memory is zero initially."""

    def __init__(self):
        self._mem = {}

    def __str__(self):
        return str(self._mem)

    def __hash__(self):
        return hash(tuple(hash(k) ^ hash(v) for k, v in self._mem.items()))

    def _default(self, addr, size):
        return claripy.BVV(0, size * 8)

    def read(self, addr, size):
        if size < 1:
            raise utils.CodeError("size < 1 in Memory.read")
        if addr + size >= MEMORY_SIZE:
            raise utils.CodeError("overflow in Memory.read")
        logger.debug("%s.read(%i, %i)" % (self.__class__.__name__, addr, size))

        for iaddr, ivalue in self._mem.items():
            isize = ivalue.size() // 8
            raddr = iaddr - addr
            rend = iaddr + isize - addr
            # completely overlaps (or equals)
            if raddr <= 0 and rend >= size:
                return _slice(ivalue, -raddr, -raddr + size)
            # completely inside (strictly)
            elif raddr > 0 and rend < size:
                return self.read(addr, raddr).concat(
                    self.read(addr + raddr, size - raddr)
                )
            # end inside
            elif 0 < rend < size:
                return _slice(ivalue, isize - rend, None).concat(
                    self.read(addr + rend, size - rend)
                )
            # start inside
            elif 0 < raddr < size:
                return self.read(addr, raddr).concat(_slice(ivalue, 0, size - raddr))

        assert addr not in self._mem
        self._mem[addr] = self._default(addr, size)
        return self._mem[addr]

    def write(self, addr, size, value):
        if size < 1:
            raise utils.CodeError("size < 1 in Memory.write")
        if addr + size >= MEMORY_SIZE:
            raise utils.CodeError("overflow in Memory.write")
        if value.size() // 8 != size:
            raise utils.InterpreterError("BVV size doesn't match size in Memory.write")

        logger.debug(
            "%s.write(%i, %i, %r)" % (self.__class__.__name__, addr, size, value)
        )

        for iaddr, ivalue in list(self._mem.items()):
            isize = ivalue.size() // 8
            raddr = iaddr - addr
            rend = iaddr + isize - addr
            # equal
            if raddr == 0 and rend == size:
                break
            # completely overlaps
            elif raddr <= 0 and rend >= size:
                if raddr < 0:
                    self._mem[iaddr] = _slice(ivalue, 0, -raddr)
                self._mem[addr + size] = _slice(ivalue, -raddr + size, None)
            # completely inside (not strictly)
            elif raddr >= 0 and rend <= size:
                del self._mem[iaddr]
            # end inside
            elif 0 < rend < size:
                self._mem[iaddr] = _slice(ivalue, 0, -raddr)
            # start inside
            elif 0 < raddr < size:
                del self._mem[iaddr]
                self._mem[addr + size] = _slice(ivalue, size - raddr, None)

        self._mem[addr] = value

    def copy_from(self, other, start_self, start_other, size):
        if size < 1:
            raise utils.CodeError("size < 1 in Memory.copy_from")
        if start_self + size >= MEMORY_SIZE or start_other + size >= MEMORY_SIZE:
            raise utils.CodeError("overflow in Memory.copy_from")
        self.write(start_self, size, CalldataMemoryView(other, start_other, size))

    def size(self):
        if not self._mem:
            return 0
        max_addr = max(self._mem.keys())
        return max_addr + self._mem[max_addr].size() // 8

    def copy(self):
        """Not to be confused with copy_from. This is to copy the object, not
        do any memory operation.
        """
        new_memory = self.__class__()
        new_memory._mem = self._mem.copy()
        return new_memory


class CalldataMemory(Memory):
    """Same as Memory, except that uninitialized memory is set to a BVS."""

    def _default(self, addr, size):
        return claripy.BVS("calldata[%i]" % addr, size * 8)

    def write(self, *args, **kwargs):
        assert False, "CalldataMemory is read-only."

    def copy_from(self, *args, **kwargs):
        assert False, "CalldataMemory is read-only."


class CalldataMemoryView(object):
    """Element to be put in memory like a Claripy BV, but is a view to a part
    of another memory."""

    def __init__(self, mem, addr, size):
        self._mem = mem
        self._addr = addr
        self._size = size

    def __hash__(self):
        # TODO: The hash may change even if the part in the view don't...
        return hash(self._mem)

    def size(self):
        return self._size * 8

    def __getitem__(self, item):
        # If I read the whole view, the thing will crash.
        assert isinstance(item, slice)
        assert (item.start + 1) % 8 == 0 and item.stop % 8 == 0 and not item.step
        start = self._size - (item.start + 1) // 8
        stop = self._size - item.stop // 8
        size = stop - start
        assert size <= self._size and start >= 0
        return self._mem.read(self._addr + start, size)
