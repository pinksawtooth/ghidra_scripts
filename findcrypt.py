# Search crypto constants in algorithm.
# @author er28-0652
# @category Search
# @keybinding 
# @menupath 
# @toolbar 
#
# PyGhidra compatible version

import struct
import struct
import copy
from java.lang.reflect import Array
from java.lang import Byte
import consts
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit, Data
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor
from ghidra.program.model.mem import MemoryAccessException
from ghidra.app.util import XReferenceUtil

flatapi = FlatProgramAPI(currentProgram)
monitor = globals().get("monitor") or TaskMonitor.DUMMY

g_fc_prefix_cmt = 'FC: '
g_fc_prefix_var = 'FC_'

def convert_to_byte_array(const, big_endian=False):
    byte_array = []
    if const["size"] == "B":
        byte_array = const["array"]
    elif const["size"] == "L":
        for val in const["array"]:
            if big_endian:
                byte_array += list(bytearray(struct.pack(">L", val)))
            else:
                byte_array += list(bytearray(struct.pack("<L", val)))
    elif const["size"] == "Q":
        for val in const["array"]:
            if big_endian:
                byte_array += list(bytearray(struct.pack(">Q", val)))
            else:
                byte_array += list(bytearray(struct.pack("<Q", val)))
    
    # Ensure all elements are integers (byte values)
    return [x if isinstance(x, int) else ord(x) for x in byte_array]

def get_byte_array_as_bytes(byte_array):
    # Convert list of ints to python bytes object for Ghidra findBytes
    # Handle potential negative values if any (though consts should be unsigned bytes)
    return bytes(bytearray(b & 0xFF for b in byte_array))

def make_data(addr, const_size, length):
    # const_size: "B", "L", "Q"
    # length: number of elements
    program = currentProgram
    listing = program.getListing()
    if const_size == "B":
        # Create array of bytes
        # In Ghidra, createByte() creates a single byte. createData(addr, ByteDataType)
        from ghidra.program.model.data import ByteDataType, ArrayDataType
        dt = ByteDataType.dataType
        # To make an array, we need ArrayDataType
        # But findcrypt_ida just does repeated create_byte or make_array
        # We will try to clean existing data first
         # clear code/data
        flatapi.clearListing(addr, addr.add(length))
        flatapi.createByte(addr)
        # Create array
        listing.createData(addr, ArrayDataType(dt, length, 1))

    elif const_size == "L":
        from ghidra.program.model.data import DWordDataType, ArrayDataType
        dt = DWordDataType.dataType
        flatapi.clearListing(addr, addr.add(length * 4))
        flatapi.createDWord(addr)
        listing.createData(addr, ArrayDataType(dt, length, 4))

    elif const_size == "Q":
        from ghidra.program.model.data import QWordDataType, ArrayDataType
        dt = QWordDataType.dataType
        flatapi.clearListing(addr, addr.add(length * 8))
        flatapi.createQWord(addr)
        listing.createData(addr, ArrayDataType(dt, length, 8))

def scan_exact_matches(constant_arrays2):
    print("[*] Searching for crypto constants (Exact Matches)")
    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()
    
    # Pre-convert byte arrays to python bytes for finding
    # Tuple: (bytes_obj, const_dict)
    search_list = []
    for const in constant_arrays2:
        b_obj = get_byte_array_as_bytes(const["byte_array"])
        search_list.append((b_obj, const))

    # Iterate matching findcrypt_ida logic: filtering by segments is implicit in findBytes?
    # findBytes searches entire memory.
    # findcrypt_ida iterates segments. 
    # Use global findBytes for efficiency.
    
    for b_obj, const in search_list:
        if monitor.isCancelled(): break
        
        # Searching...
        # print("Searching " + const["name"])
        
        addrs = []
        cur_addr = memory.getMinAddress()
        while True:
            found = memory.findBytes(cur_addr, b_obj, None, True, monitor)
            if found is None:
                break
            addrs.append(found)
            cur_addr = found.add(1)
        
        for ea in addrs:
            print("[*] {} - Found const array {}.{}".format(ea, const["algorithm"], const["name"]))
            
            # Rename
            name = g_fc_prefix_var + const["name"]
            # symbol creation
            flatapi.createLabel(ea, name, True)
            
            # Create Data
            make_data(ea, const["size"], len(const["array"]))

def scan_sparse_matches(constant_arrays2, value_len):
    print("[*] Searching for crypto constants (Sparse Matches)")
    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()
    
    # We only look in Execute blocks (CODE)
    
    for block in blocks:
        if not block.isExecute():
            continue
            
        print("[*] Scanning block: {}".format(block.getName()))
        
        start_addr = block.getStart()
        end_addr = block.getEnd()
        
        # We need to read memory. Using getBytes/getInt/getLong
        
        for const in constant_arrays2:
            if monitor.isCancelled(): break
            
            # Optimization: Use findBytes for the FIRST chunk to locate candidates
            first_chunk = const["byte_array"][:value_len]
            first_chunk_bytes = get_byte_array_as_bytes(first_chunk)
            
            cur_addr = start_addr
            while cur_addr < end_addr:
                found = memory.findBytes(cur_addr, end_addr, first_chunk_bytes, None, True, monitor)
                if found is None:
                    break
                
                # Candidate found at 'found'. Check subsequent chunks.
                # Logic:
                # tmp = ea + value_len
                # for j in range(1, len // value_len):
                #   val = ...
                #   for i in range(1, 10):
                #     if get_val(tmp + i) == val:
                #        tmp = tmp + i + value_len (Wait, IDA logic verification needed)
                #        break
                #   else: break (match failed)
                # else: match found
                
                match = True
                tmp_addr = found.add(value_len)
                
                num_chunks = len(const["byte_array"]) // value_len
                
                for j in range(1, num_chunks):
                    # target value bytes
                    chunk_start = j * value_len
                    chunk_end = chunk_start + value_len
                    target_bytes_list = const["byte_array"][chunk_start:chunk_end]
                    target_bytes = get_byte_array_as_bytes(target_bytes_list)
                    
                    found_next = False
                    for i in range(1, 10): # search window
                        # We check bytes at tmp_addr + i (NOTE: IDA logic was tmp + i)
                        # Is it byte offset or unit offset? 
                        # IDA: ida_bytes.get_dword(tmp + i). 
                        # get_dword takes byte address. So existing logic checks byte offsets 1..9.
                        # BUT wait, instructions are usually aligned?
                        # Using byte offsets 1..9 checks for unaligned immediates too.
                        
                        try:
                            # Read value_len bytes at tmp_addr + i
                            check_addr = tmp_addr.add(i)
                            if check_addr > end_addr: break
                            
                            buffer = Array.newInstance(Byte.TYPE, value_len)
                            memory.getBytes(check_addr, buffer)
                            # Convert signed java bytes to python unsigned bytes checks
                            mem_bytes_unsigned = bytes(bytearray(b & 0xFF for b in buffer))
                            
                            if mem_bytes_unsigned == target_bytes:
                                tmp_addr = check_addr.add(value_len) # Advance base
                                found_next = True
                                break
                        except MemoryAccessException:
                            break
                            
                    if not found_next:
                        match = False
                        break
                
                if match:
                    print("[*] {} - Found sparse constant {}.{}".format(found, const["algorithm"], const["name"]))
                    
                    # Add comment
                    # idc.get_cmt(idc.prev_head(ea), 0)
                    # Ghidra: get instruction before? or just at 'found'?
                    # IDA prev_head implies the instruction containing this data or previous instruction?
                    # If found points to an immediate inside an instruction, prev_head(found) is that instruction start.
                    # Ghidra: getInstructionContaining(found)
                    
                    inst = flatapi.getInstructionContaining(found)
                    if inst:
                        cmt_addr = inst.getAddress()
                        current_cmt = inst.getComment(CodeUnit.PRE_COMMENT) or ""
                        new_cmt = g_fc_prefix_cmt + const["name"]
                        if current_cmt:
                            if new_cmt not in current_cmt:
                                inst.setComment(CodeUnit.PRE_COMMENT, current_cmt + "\n" + new_cmt)
                        else:
                            inst.setComment(CodeUnit.PRE_COMMENT, new_cmt)
                    else:
                        # Fallback: EOL comment at address
                        flatapi.setEOLComment(found, g_fc_prefix_cmt + const["name"])
                        
                # Advance search
                cur_addr = found.add(1)


def scan_operand_matches(constant_values):
    print("[*] Searching for crypto constants in immediate operand")
    
    # Iterate functions
    func_iter = flatapi.getFirstFunction()
    while func_iter:
        if monitor.isCancelled(): break
        
        # Check flags (Lib/Thunk)
        # Ghidra doesn't have exact FUNC_LIB flags on function usually, unless analyzed from library.
        # We can check isThunk.
        if not func_iter.isThunk():
            # Iterate instructions
            insts = currentProgram.getListing().getInstructions(func_iter.getBody(), True)
            for inst in insts:
                num_ops = inst.getNumOperands()
                for i in range(num_ops):
                    # Check for scalar (Immediate)
                    # getScalar(i) returns Scalar object if operand is scalar
                    scalar = inst.getScalar(i)
                    if scalar:
                        val = scalar.getUnsignedValue()
                        
                        # Check against constants
                        for const in constant_values:
                            if val == const["value"]:
                                ea = inst.getAddress()
                                print("[*] {} - Found immediate operand constant {}.{}".format(ea, const["algorithm"], const["name"]))
                                
                                current_cmt = inst.getComment(CodeUnit.EOL_COMMENT) or ""
                                new_cmt = g_fc_prefix_cmt + const["name"]
                                
                                if current_cmt:
                                     if new_cmt not in current_cmt:
                                         inst.setComment(CodeUnit.EOL_COMMENT, current_cmt + " " + new_cmt)
                                else:
                                    inst.setComment(CodeUnit.EOL_COMMENT, new_cmt)
        
        func_iter = flatapi.getFunctionAfter(func_iter)

def main():
    print("[*] Loading crypto constants")
    
    # Determine pointer size (value_len)
    ptr_size = currentProgram.getDefaultPointerSize()
    
    constant_arrays2 = []
    for const in consts.constant_arrays:
        # Create standard (little endian usually or logical byte array)
        c_copy = copy.copy(const)
        c_copy["byte_array"] = convert_to_byte_array(c_copy)
        constant_arrays2.append(c_copy)
        
        if const["size"] != "B":
            # Create big endian version
            c_be = copy.copy(const)
            c_be["byte_array"] = convert_to_byte_array(c_be, big_endian=True)
            constant_arrays2.append(c_be)
            
    # Scan Exact
    scan_exact_matches(constant_arrays2)
    
    # Scan Sparse
    scan_sparse_matches(constant_arrays2, ptr_size)
    
    # Scan Operands
    scan_operand_matches(consts.constant_values)
    
    print("[*] Finished")

if __name__ == '__main__':
    main()
