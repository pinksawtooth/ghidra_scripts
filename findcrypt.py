# Search crypto constants in algorithm.
# @author er28-0652
# @category Search
# @keybinding 
# @menupath 
# @toolbar 
#
# PyGhidra compatible version

import struct

try:
    from jpype import JArray, JByte
except ImportError:
    raise RuntimeError("findcrypt.py needs PyGhidra (CPython 3); it does not run under Jython")

import consts
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import AddressOutOfBoundsException, AddressSet
from ghidra.program.model.data import ArrayDataType, ByteDataType, DWordDataType, QWordDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException
from ghidra.util.task import TaskMonitor

# PyGhidra runs the script with a dict subclass as its globals. A name that is not in it, a
# builtin included, is first looked up on the Java script object, which adds up in a hot loop.
# So bind the builtins the loops use, and what the script needs from GhidraScript, once.
all, enumerate, int, len, max, min, range, sorted, zip = all, enumerate, int, len, max, min, range, sorted, zip
program = currentProgram
flatapi = FlatProgramAPI(program)
try:
    g_monitor = monitor
except NameError:
    g_monitor = TaskMonitor.DUMMY

g_fc_prefix_cmt = 'FC: '
g_fc_prefix_var = 'FC_'

# Memory is pulled out of Ghidra in pieces of this size and searched with bytes.find().
CHUNK_SIZE = 1 << 25
# Sparse matches: the next immediate has to start within this many bytes after the previous one.
SPARSE_GAP = 9
# For x86, only decode instructions whose bytes contain one of the immediates (see scan_operand_x86).
USE_X86_BYTE_PREFILTER = True

ELEMENT_TYPES = {
    "B": (ByteDataType.dataType, 1),
    "L": (DWordDataType.dataType, 4),
    "Q": (QWordDataType.dataType, 8),
}


def build_patterns():
    """Return (const, bytes) for every constant array, little endian first, then big endian
    for the multi-byte element sizes."""
    patterns = []
    for const in consts.constant_arrays:
        size = const["size"]
        array = const["array"]
        if size == "B":
            patterns.append((const, bytes(b & 0xFF for b in array)))
        elif size in ("L", "Q"):
            fmt = "%d%s" % (len(array), size)
            patterns.append((const, struct.pack("<" + fmt, *array)))
            patterns.append((const, struct.pack(">" + fmt, *array)))
    return patterns


def read_memory(memory, addr, length):
    """Read up to length bytes at addr. Returns fewer bytes if readable memory ends first, none if it cannot be read."""
    buf = JArray(JByte)(length)
    try:
        count = memory.getBytes(addr, buf)
    except MemoryAccessException:
        return b""
    data = bytes(buf)
    return data if count == length else data[:count]


def read_tail(memory, addr, length):
    """Read up to `length` bytes of what follows a range, as a window that runs off the end of the range sees them.

    Returns (data, hard). Memory.getBytes() returns a short count when readable memory ends, but throws when
    it reaches a byte mapped block whose source cannot be read; hard says it was the latter."""
    for n in range(length, 0, -1):
        buf = JArray(JByte)(n)
        try:
            count = memory.getBytes(addr, buf)
        except MemoryAccessException:
            continue
        return bytes(buf)[:count], n < length
    block = memory.getBlock(addr)
    return b"", block is not None and block.isMapped()


def iter_chunks(memory, start, length, lookahead, tail=0):
    """Yield (offset, data, owned, hard) covering [start, start+length) in CHUNK_SIZE pieces.

    data holds `owned` bytes followed by the next `lookahead` bytes of the range, so a match that starts in
    the owned part and is at most lookahead + 1 bytes long lies completely inside data. A piece that reaches
    the end of the range also gets up to `tail` bytes of what follows it (see read_tail for `hard`)."""
    offset = 0
    while offset < length:
        g_monitor.checkCancelled()
        owned = min(CHUNK_SIZE, length - offset)
        if length - offset - owned == 1:
            owned += 1  # never leave a single byte for the last piece
        end = min(offset + owned + lookahead, length)
        data = read_memory(memory, start.add(offset), end - offset)
        hard = False
        if tail and end == length and len(data) == end - offset:
            try:
                extra, hard = read_tail(memory, start.add(length), tail)
                data += extra
            except AddressOutOfBoundsException:
                pass  # the range ends at the last address of its space
        yield offset, data, owned, hard
        offset += owned


def address_at(start, offset):
    """start + offset, written the way Ghidra's own address iterators write it (it shows for segmented x86).
    Address.getOffset() is a signed long, so it is negative above 2**63 in a 64 bit space."""
    flat = (start.getOffset() + offset + (1 << 63)) % (1 << 64) - (1 << 63)
    return start.getAddressSpace().getAddress(flat)


def readable_parts(memory, block):
    """(offset, length) of the parts of `block` whose bytes can be read. A byte mapped block may only be
    readable in places, where its source is initialized."""
    if not block.isMapped():
        return [(0, int(block.getSize()))] if block.isInitialized() else []
    start = block.getStart()
    readable = memory.getAllInitializedAddressSet().intersect(AddressSet(start, block.getEnd()))
    return [(int(r.getMinAddress().subtract(start)), int(r.getLength())) for r in readable.getAddressRanges()]


def make_data(addr, const_size, length):
    # const_size: "B", "L", "Q"; length: number of elements
    data_type, element_size = ELEMENT_TYPES[const_size]
    flatapi.clearListing(addr, addr.add(length * element_size - 1))
    program.getListing().createData(addr, ArrayDataType(data_type, length, element_size))


def add_comment(code_unit, comment_type, text, separator):
    current = code_unit.getComment(comment_type) or ""
    if not current:
        code_unit.setComment(comment_type, text)
    elif text not in current:
        code_unit.setComment(comment_type, current + separator + text)


def find_exact(memory, patterns):
    """Map each distinct byte string of `patterns` to the addresses at which it occurs in the
    loaded and initialized memory, in ascending order (overlapping occurrences included)."""
    hits = {}
    for _, data in patterns:
        hits[data] = []
    longest = max((len(data) for data in hits), default=1)

    for rng in memory.getLoadedAndInitializedAddressSet().getAddressRanges():
        g_monitor.checkCancelled()
        start = rng.getMinAddress()
        for offset, data, owned, _ in iter_chunks(memory, start, int(rng.getLength()), longest - 1):
            for needle, found in hits.items():
                limit = min(len(data), owned - 1 + len(needle))
                pos = data.find(needle, 0, limit)
                while pos != -1:
                    found.append(address_at(start, offset + pos))
                    pos = data.find(needle, pos + 1, limit)
    return hits


def scan_exact_matches(patterns):
    print("[*] Searching for crypto constants (Exact Matches)")
    g_monitor.setMessage("findcrypt: exact matches")

    # Several constants can share the same bytes; each distinct byte string is searched once.
    hits = find_exact(program.getMemory(), patterns)

    for const, data in patterns:
        for ea in hits[data]:
            print("[*] {} - Found const array {}.{}".format(ea, const["algorithm"], const["name"]))

            flatapi.createLabel(ea, g_fc_prefix_var + const["name"], True)
            try:
                make_data(ea, const["size"], len(const["array"]))
            except Exception as e:
                print("[!] {} - Could not define {} as an array: {}".format(ea, const["name"], e))


class SparsePattern:
    """One constant split into pointer-sized chunks, as an immediate-heavy code sequence would hold it."""

    def __init__(self, const, data, value_len):
        self.const = const
        self.first = data[:value_len]
        self.rest = [data[k:k + value_len] for k in range(value_len, len(data) // value_len * value_len, value_len)]
        # Every later chunk has to turn up somewhere; checking a few of them first rules out
        # almost every constant without walking its candidates.
        probes = [self.rest[i] for i in sorted({0, len(self.rest) // 2, len(self.rest) - 1})] if self.rest else []
        self.probes = probes


def chunk_present(cache, data, chunk):
    found = cache.get(chunk)
    if found is None:
        found = cache[chunk] = data.find(chunk) != -1
    return found


def sparse_block_hits_legacy(memory, block, sparse, value_len):
    """The original search, which asks Ghidra about every single candidate. It is slow, but it follows
    Ghidra's own rules for a byte mapped block that is readable only in places."""
    start, end = block.getStart(), block.getEnd()
    hits = [[] for _ in sparse]
    for index, pattern in enumerate(sparse):
        g_monitor.checkCancelled()
        cur = start
        while cur.compareTo(end) < 0:
            found = memory.findBytes(cur, end, pattern.first, None, True, g_monitor)
            if found is None:
                break
            try:
                tmp = found.add(value_len)
            except AddressOutOfBoundsException:
                tmp = None  # the end of the address space: nothing can follow
            matched = True
            for chunk in pattern.rest:
                matched = False
                if tmp is None:
                    break
                for i in range(1, SPARSE_GAP + 1):
                    try:
                        check = tmp.add(i)
                    except AddressOutOfBoundsException:
                        break
                    if check.compareTo(end) > 0:
                        break
                    buf = JArray(JByte)(value_len)
                    try:
                        memory.getBytes(check, buf)
                    except MemoryAccessException:
                        break
                    if bytes(buf) == chunk:
                        try:
                            tmp = check.add(value_len)
                        except AddressOutOfBoundsException:
                            tmp = None
                        matched = True
                        break
                if not matched:
                    break
            if matched:
                hits[index].append(int(found.subtract(start)))
            try:
                cur = found.add(1)
            except AddressOutOfBoundsException:
                break
    return hits


def sparse_block_hits(memory, block, sparse, value_len, lookahead):
    """Offsets (from the block start) at which each SparsePattern matches inside one block."""
    size = int(block.getSize())
    hits = [[] for _ in sparse]
    if size < 2:
        return hits
    parts = readable_parts(memory, block)
    if block.isMapped() and parts != [(0, size)]:
        return sparse_block_hits_legacy(memory, block, sparse, value_len)
    start = block.getStart()
    for part_offset, part_length in parts:
        for offset, data, owned, hard in iter_chunks(memory, start.add(part_offset), part_length, lookahead,
                                                     value_len - 1):
            if not data:
                continue
            base = part_offset + offset  # offset of data[0] within the block
            avail = len(data)
            # A read that runs off readable memory comes back zero filled, unless Ghidra throws instead.
            padded = data if hard else data + bytes(value_len)
            last = size - 1 - base  # index of the block's last byte within data
            present = {}
            starts = {}
            for index, pattern in enumerate(sparse):
                g_monitor.checkCancelled()
                if not all(chunk_present(present, padded, c) for c in pattern.probes):
                    continue
                first = pattern.first
                candidates = starts.get(first)
                if candidates is None:
                    candidates = starts[first] = []
                    stop = min(avail, owned - 1 + len(first), last + len(first))
                    pos = data.find(first, 0, stop)
                    while pos != -1:
                        candidates.append(pos)
                        if pos >= last - 1:
                            break
                        pos = data.find(first, pos + 1, stop)
                for pos in candidates:
                    tmp = pos + value_len
                    for chunk in pattern.rest:
                        hi = min(tmp + SPARSE_GAP, last, avail - 1)
                        nxt = padded.find(chunk, tmp + 1, hi + value_len) if hi > tmp else -1
                        if nxt < 0:
                            break
                        tmp = nxt + value_len
                    else:
                        hits[index].append(base + pos)
    return hits


def scan_sparse_matches(patterns, value_len):
    print("[*] Searching for crypto constants (Sparse Matches)")
    g_monitor.setMessage("findcrypt: sparse matches")
    memory = program.getMemory()

    sparse = [SparsePattern(const, data, value_len) for const, data in patterns]
    chain = max((len(p.rest) + 1 for p in sparse), default=1) * (value_len + SPARSE_GAP)
    lookahead = chain + value_len

    # We only look in Execute blocks (CODE)
    for block in memory.getBlocks():
        if not block.isExecute():
            continue

        print("[*] Scanning block: {}".format(block.getName()))
        g_monitor.checkCancelled()

        hits = sparse_block_hits(memory, block, sparse, value_len, lookahead)

        start = block.getStart()
        for pattern, offsets in zip(sparse, hits):
            for offset in offsets:
                found = address_at(start, offset)
                const = pattern.const
                print("[*] {} - Found sparse constant {}.{}".format(found, const["algorithm"], const["name"]))

                inst = flatapi.getInstructionContaining(found)
                if inst:
                    add_comment(inst, CodeUnit.PRE_COMMENT, g_fc_prefix_cmt + const["name"], "\n")
                else:
                    flatapi.setEOLComment(found, g_fc_prefix_cmt + const["name"])


def report_operand_constant(inst, const):
    print("[*] {} - Found immediate operand constant {}.{}".format(inst.getAddress(), const["algorithm"], const["name"]))
    add_comment(inst, CodeUnit.EOL_COMMENT, g_fc_prefix_cmt + const["name"], " ")


def x86_immediate_patterns(values):
    """Byte strings such that every x86 instruction with an immediate operand equal to one of
    `values` contains at least one of them.

    An x86 immediate is a little endian field of the instruction, which the SLEIGH spec zero or
    sign extends to the operand size. So the value is stored either with its minimal little
    endian encoding, or, if it reads as a negative number of a wider operand, as the narrower
    field that sign extends to it."""
    found = set()
    for value in values:
        found.add(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little"))
        for bits in (16, 32, 64):
            for field in (8, 16, 32):
                if field < bits and (1 << bits) - (1 << (field - 1)) <= value < (1 << bits):
                    found.add((value & ((1 << field) - 1)).to_bytes(field // 8, "little"))
    # an occurrence of a longer pattern is also an occurrence of its prefix
    return [p for p in found if not any(q != p and p.startswith(q) for q in found)]


def scan_operand_x86(by_value):
    """Decode only the instructions that contain the bytes of one of the immediates.

    This reports the same operands as decoding every instruction of every function, except that
    SLEIGH also exposes the target address of a RIP-relative operand as a scalar. Those addresses
    are not instruction bytes and are skipped here; set USE_X86_BYTE_PREFILTER to False to see
    them as well."""
    memory = program.getMemory()
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    needles = x86_immediate_patterns(by_value)
    lookahead = max(len(n) for n in needles) - 1

    found = []  # (instruction, matching constants)
    decoded = set()
    for block in memory.getBlocks():
        g_monitor.checkCancelled()
        start = block.getStart()
        # An instruction can start in the block before this one and run into it.
        if not (listing.getInstructions(AddressSet(start, block.getEnd()), True).hasNext()
                or listing.getInstructionContaining(start) is not None):
            continue

        for part_offset, part_length in readable_parts(memory, block):
            part = start.add(part_offset)
            last_end = -1  # end of the previously decoded instruction, as an offset from the start of the part
            for offset, data, owned, _ in iter_chunks(memory, part, part_length, lookahead, lookahead):
                positions = set()
                for needle in needles:
                    limit = min(len(data), owned - 1 + len(needle))
                    pos = data.find(needle, 0, limit)
                    while pos != -1:
                        positions.add(pos)
                        pos = data.find(needle, pos + 1, limit)
                for n, pos in enumerate(sorted(positions)):
                    if not n & 0xFFF:
                        g_monitor.checkCancelled()
                    if offset + pos <= last_end:
                        continue
                    inst = listing.getInstructionContaining(part.add(offset + pos))
                    if inst is None:
                        continue
                    last_end = int(inst.getMaxAddress().subtract(part))
                    if inst.getAddress() in decoded:
                        continue
                    decoded.add(inst.getAddress())
                    consts = []
                    for i in range(inst.getNumOperands()):
                        scalar = inst.getScalar(i)
                        if scalar is not None:
                            consts.extend(by_value.get(scalar.getUnsignedValue(), ()))
                    if consts:
                        found.append((inst, consts))

    # Only instructions inside a function count, reported function by function.
    ordered = []
    for inst, consts in found:
        func = function_manager.getFunctionContaining(inst.getAddress())
        if func is not None and not func.isThunk():
            ordered.append((func.getEntryPoint(), inst.getAddress(), inst, consts))
    ordered.sort(key=lambda t: (t[0], t[1]))
    for _, _, inst, consts in ordered:
        for const in consts:
            report_operand_constant(inst, const)


def scan_operand_generic(by_value):
    listing = program.getListing()
    for func in program.getFunctionManager().getFunctions(True):
        g_monitor.checkCancelled()
        if not func.isThunk():
            for inst in listing.getInstructions(func.getBody(), True):
                for i in range(inst.getNumOperands()):
                    scalar = inst.getScalar(i)
                    if scalar is not None:
                        for const in by_value.get(scalar.getUnsignedValue(), ()):
                            report_operand_constant(inst, const)


def scan_operand_matches(constant_values):
    print("[*] Searching for crypto constants in immediate operand")
    g_monitor.setMessage("findcrypt: immediate operands")

    by_value = {}
    for const in constant_values:
        by_value.setdefault(const["value"], []).append(const)
    if not by_value:
        return

    # x86 also has scalars that are not instruction bytes, such as the 1 of a shift by one.
    if (USE_X86_BYTE_PREFILTER and min(by_value) >= 0x100
            and str(program.getLanguage().getProcessor()) == "x86"):
        scan_operand_x86(by_value)
    else:
        scan_operand_generic(by_value)


def main():
    print("[*] Loading crypto constants")

    # Determine pointer size (value_len)
    ptr_size = int(program.getDefaultPointerSize())

    patterns = build_patterns()

    try:
        # Scan Exact
        scan_exact_matches(patterns)

        # Scan Sparse
        scan_sparse_matches(patterns, ptr_size)

        # Scan Operands
        scan_operand_matches(consts.constant_values)
    except CancelledException:
        print("[*] Cancelled")
        return

    print("[*] Finished")


if __name__ == '__main__':
    main()
