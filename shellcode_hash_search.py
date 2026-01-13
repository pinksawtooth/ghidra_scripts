# Search for known shellcode hash values and annotate matches.
# @author Codex
# @category Search
# @menupath Tools.Search.Shellcode Hash Search
#
# PyGhidra compatible version.

import ctypes
import logging
import os
import re
import sqlite3
import struct

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (
    DataTypeConflictHandler,
    DWordDataType,
    QWordDataType,
    StructureDataType,
)
from ghidra.program.model.lang import OperandType
from ghidra.program.flatapi import FlatProgramAPI

flatapi = FlatProgramAPI(currentProgram)


logger = logging.getLogger("shellcode_hash")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


SQL_LOOKUP_HASH_VALUE = """
select
    h.hash_val,
    h.symbol_name,
    l.lib_name,
    t.hash_name,
    t.hash_size
from
    symbol_hashes h,
    source_libs l,
    hash_types t
where
    h.hash_val=? and
    h.lib_key=l.lib_key and
    h.hash_type=t.hash_type;
"""

SQL_LOOKUP_HASH_TYPE_VALUE = """
select
    h.hash_val,
    h.symbol_name,
    l.lib_name,
    t.hash_name,
    t.hash_size
from
    symbol_hashes h,
    source_libs l,
    hash_types t
where
    h.hash_val=? and
    h.lib_key=l.lib_key and
    h.hash_type=t.hash_type and
    h.hash_type=?;
"""

SQL_GET_ALL_HASH_TYPES = """
select
    hash_type,
    hash_size,
    hash_name,
    hash_code
from hash_types;
"""

SQL_ADJUST_CACHE_SIZE = "PRAGMA cache_size=200000;"


class SymbolHash(object):
    def __init__(self, hash_val, symbol_name, lib_name, hash_name, hash_size):
        self.hash_val = hash_val
        self.symbol_name = symbol_name
        self.lib_name = lib_name
        self.hash_name = hash_name
        self.hash_size = hash_size

    def __str__(self):
        return "%s:0x%08x %s!%s" % (
            self.hash_name,
            self.hash_val & 0xFFFFFFFF,
            self.lib_name,
            self.symbol_name,
        )


class HashType(object):
    def __init__(self, hash_type, hash_size, hash_name, hash_code):
        self.hash_type = hash_type
        self.hash_size = hash_size
        self.hash_name = hash_name
        self.hash_code = hash_code


class HashHit(object):
    def __init__(self, addr_offset, sym_hash):
        self.addr_offset = addr_offset
        self.sym_hash = sym_hash


class DbStore(object):
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(SQL_ADJUST_CACHE_SIZE)
        self._cache = {}
        self._cache_limit = 8192

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _cache_get(self, key):
        return self._cache.get(key)

    def _cache_set(self, key, value):
        if len(self._cache) >= self._cache_limit:
            self._cache.clear()
        self._cache[key] = value

    def get_symbol_by_hash(self, hash_val):
        ret_list = []
        cur = self.conn.execute(
            SQL_LOOKUP_HASH_VALUE, (ctypes.c_int64(hash_val).value,)
        )
        for row in cur:
            ret_list.append(SymbolHash(*row))
        return ret_list

    def get_all_hash_types(self):
        ret_arr = []
        cur = self.conn.execute(SQL_GET_ALL_HASH_TYPES)
        for row in cur:
            ret_arr.append(HashType(*row))
        return ret_arr

    def get_symbol_by_type_hash(self, hash_type, hash_val):
        key = (hash_type, hash_val)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        ret_list = []
        cur = self.conn.execute(
            SQL_LOOKUP_HASH_TYPE_VALUE,
            (ctypes.c_int64(hash_val).value, hash_type),
        )
        for row in cur:
            ret_list.append(SymbolHash(*row))
        self._cache_set(key, ret_list)
        return ret_list


class SearchParams(object):
    def __init__(self):
        self.search_dword_array = False
        self.search_push_args = False
        self.create_struct = False
        self.use_xor_seed = False
        self.xor_seed = 0
        self.hash_types = []
        self.address_set = None





def append_eol_comment(addr, comment):
    listing = currentProgram.getListing()
    cu = listing.getCodeUnitAt(addr)
    if cu is None:
        return
    existing = cu.getComment(CodeUnit.EOL_COMMENT)
    if existing:
        if comment in existing:
            return
        new_comment = existing + "\n" + comment
    else:
        new_comment = comment
    cu.setComment(CodeUnit.EOL_COMMENT, new_comment)


def get_script_dir():
    try:
        return sourceFile.getParent().getFile(False).getPath()
    except Exception:
        # Fallback for non-standard execution
        return os.getcwd()


def get_default_db_path():
    return os.path.join(get_script_dir(), "sc_hashes.db")





def get_address_set():
    if currentSelection is not None and not currentSelection.isEmpty():
        return currentSelection
    if currentAddress is not None:
        block = currentProgram.getMemory().getBlock(currentAddress)
        if block is not None:
            return AddressSet(block.getStart(), block.getEnd())
    return currentProgram.getMemory().getAllInitializedAddressSet()


def parse_script_args(params):
    args = []
    try:
        args = getScriptArgs()
    except Exception:
        return False
    if not args:
        return False

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--push":
            params.search_push_args = True
        elif arg == "--no-push":
            params.search_push_args = False
        elif arg == "--dword":
            params.search_dword_array = True
        elif arg == "--no-dword":
            params.search_dword_array = False
        elif arg == "--struct":
            params.create_struct = True
        elif arg == "--no-struct":
            params.create_struct = False
        elif arg.startswith("--xor="):
            params.use_xor_seed = True
            params.xor_seed = int(arg.split("=", 1)[1], 0)
        elif arg == "--xor" and idx + 1 < len(args):
            params.use_xor_seed = True
            params.xor_seed = int(args[idx + 1], 0)
            idx += 1
        idx += 1
    return True


class ShellcodeHashSearcher(object):
    def __init__(self, dbstore, params):
        self.dbstore = dbstore
        self.params = params
        self.hits = []
        self.hit_set = set()
        self.ptr_size = currentProgram.getDefaultPointerSize() or 4

    def add_hit(self, addr, sym):
        offset = int(addr.getOffset())
        if offset in self.hit_set:
            return
        self.hits.append(HashHit(offset, sym))
        self.hit_set.add(offset)

    def markup_line(self, addr, sym):
        comment = "%s!%s" % (sym.lib_name, sym.symbol_name)
        append_eol_comment(addr, comment)

    def look_for_op_args(self, address_set):
        listing = currentProgram.getListing()
        for inst in listing.getInstructions(address_set, True):
            if monitor is not None:
                monitor.checkCanceled()
            for i in range(inst.getNumOperands()):
                op_type = inst.getOperandType(i)
                if not OperandType.isScalar(op_type):
                    continue
                scalar = inst.getScalar(i)
                if scalar is None:
                    continue
                opval = scalar.getUnsignedValue()
                bit_len = self.get_scalar_bit_length(scalar)
                if bit_len and bit_len < 64:
                    opval &= (1 << bit_len) - 1
                if self.params.use_xor_seed:
                    opval ^= self.params.xor_seed
                for h in self.params.hash_types:
                    # TODO: optimize this loop, redundant if many types
                    # Ideally we used the pre-fetched type to filter but current DB layout differs.
                    # This logic matches original but is slightly inefficient.
                    hits = self.dbstore.get_symbol_by_type_hash(h.hash_type, opval)
                    for sym in hits:
                        addr = inst.getAddress()
                        logger.info("0x%08x - %s", int(addr.getOffset()), str(sym))
                        self.add_hit(addr, sym)
                        self.markup_line(addr, sym)

    def look_for_dword_array(self, address_set):
        memory = currentProgram.getMemory()
        hash_types_32 = [h for h in self.params.hash_types if h.hash_size == 32]
        if not hash_types_32:
            logger.info("No 32-bit hash types available for dword search.")
            return
        chunk_size = 1024 * 1024
        for addr_range in address_set.getAddressRanges():
            if monitor is not None:
                monitor.checkCanceled()
            start = addr_range.getMinAddress()
            end = addr_range.getMaxAddress()
            length = int(end.subtract(start)) + 1
            offset = 0
            tail = b""
            while offset < length:
                if monitor is not None:
                    monitor.checkCanceled()
                read_len = min(chunk_size, length - offset)
                buf = bytearray(read_len)
                try:
                    memory.getBytes(start.add(offset), buf)
                except Exception:
                    break
                data = tail + bytes(buf)
                base_offset = offset - len(tail)
                for i in range(0, len(data) - 3):
                    val = struct.unpack_from("<I", data, i)[0]
                    if self.params.use_xor_seed:
                        val ^= self.params.xor_seed
                    for h in hash_types_32:
                        hits = self.dbstore.get_symbol_by_type_hash(h.hash_type, val)
                        for sym in hits:
                            addr = start.add(base_offset + i)
                            logger.info(
                                "0x%08x - %s", int(addr.getOffset()), str(sym)
                            )
                            self.add_hit(addr, sym)
                            self.markup_line(addr, sym)
                tail = data[-3:] if len(data) >= 3 else data
                offset += read_len

    def run(self):
        address_set = self.params.address_set
        if self.params.search_push_args:
            logger.info("Searching for immediate hash operands...")
            self.look_for_op_args(address_set)
        if self.params.search_dword_array:
            logger.info("Searching for dword hash arrays...")
            self.look_for_dword_array(address_set)
        if self.params.create_struct:
            self.post_process_hits()
        self.dbstore.close()
        logger.info("Done.")

    def get_scalar_bit_length(self, scalar):
        try:
            return scalar.getBitLength()
        except Exception:
            pass
        attr = getattr(scalar, "bitLength", None)
        if attr is None:
            return None
        try:
            return attr() if callable(attr) else attr
        except Exception:
            return None

    def post_process_hits(self):
        if not self.hits:
            return
        hits_sorted = sorted(self.hits, key=lambda h: h.addr_offset)
        count = 0
        start = 0
        while start < (len(hits_sorted) - 1):
            prev = start
            curr = start + 1
            while (
                curr < len(hits_sorted)
                and hits_sorted[curr].addr_offset
                == hits_sorted[prev].addr_offset + self.ptr_size
            ):
                curr, prev = (curr + 1, curr)
            if start != prev:
                self.make_struct_from_hits(count, hits_sorted[start:curr])
                count += 1
            start = curr

    def make_struct_from_hits(self, count, hit_range):
        struct_name = "sc%d" % count
        field_dt = DWordDataType.dataType
        if self.ptr_size == 8:
            field_dt = QWordDataType.dataType
        struct = StructureDataType(struct_name, 0)
        used_names = set()
        for idx, hit in enumerate(hit_range):
            base_name = hit.sym_hash.symbol_name
            field_name = self.sanitize_field_name(base_name, idx, used_names)
            struct.add(field_dt, self.ptr_size, field_name, None)
            used_names.add(field_name)

        dtm = currentProgram.getDataTypeManager()
        struct = dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)
        start_addr = flatapi.toAddr(hit_range[0].addr_offset)
        length = struct.getLength()
        if length <= 0:
            logger.warning("Struct %s has zero length; skipping", struct_name)
            return
        end_addr = start_addr.add(length - 1)
        listing = currentProgram.getListing()
        try:
            listing.clearCodeUnits(start_addr, end_addr, False)
        except Exception as err:
            logger.debug(
                "Failed to clear code units for %s at 0x%08x - %s",
                struct_name,
                int(start_addr.getOffset()),
                err,
            )
        try:
            listing.createData(start_addr, struct)
        except Exception as err:
            logger.warning(
                "Failed to apply struct %s at 0x%08x - %s",
                struct_name,
                int(start_addr.getOffset()),
                err,
            )

    def sanitize_field_name(self, name, idx, used_names):
        clean = re.sub(r"[^0-9A-Za-z_]", "_", name)
        if not clean or clean[0].isdigit():
            clean = "field_%d" % idx
        candidate = clean
        suffix = 1
        while candidate in used_names:
            candidate = "%s_%d" % (clean, suffix)
            suffix += 1
        return candidate


def main():
    if currentProgram is None:
        raise RuntimeError("No active program found.")

    params = SearchParams()
    parsed = parse_script_args(params)
    if not parsed:
        params.search_push_args = askYesNo(
            "Shellcode Hash Search",
            "Search for immediate hash operands?"
        )
        params.search_dword_array = askYesNo(
            "Shellcode Hash Search",
            "Search for dword arrays of hashes?"
        )
        params.create_struct = askYesNo(
            "Shellcode Hash Search",
            "Create struct for consecutive hash hits?"
        )
        if not params.search_push_args and not params.search_dword_array:
            raise RuntimeError("No search types selected.")
        use_xor = askYesNo(
            "Shellcode Hash Search",
            "XOR seed hash values before lookup?"
        )
        if use_xor:
            params.use_xor_seed = True
            seed_text = askString(
                "Shellcode Hash Search",
                "XOR seed (e.g. 0x1234)",
                "0x0",
            )
            params.xor_seed = int(seed_text, 0)

    params.address_set = get_address_set()
    db_path = get_default_db_path()
    if not os.path.isfile(db_path):
        db_file = askFile("Select shellcode hash database", "Open")
        if db_file is None:
            logger.info("No database selected.")
            return
        db_path = db_file.getAbsolutePath()

    dbstore = DbStore(db_path)
    params.hash_types = dbstore.get_all_hash_types()
    logger.info("Loaded %d hash types.", len(params.hash_types))

    searcher = ShellcodeHashSearcher(dbstore, params)
    searcher.run()


if __name__ == "__main__":
    main()
