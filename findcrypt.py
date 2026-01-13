# Search crypto constants in algorithm.
# @author er28-0652
# @category Search
# @keybinding 
# @menupath 
# @toolbar 
#
# PyGhidra compatible version

import functools
import struct

import const
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor

flatapi = FlatProgramAPI(currentProgram)
monitor = globals().get("monitor") or TaskMonitor.DUMMY


# ghidra api
def find(find_bytes, min_addr=None):
    program = currentProgram
    min_addr = min_addr or program.getMinAddress()
    return program.getMemory().findBytes(min_addr, find_bytes, None, True, monitor)


def create_label(addr, label_name, source=SourceType.USER_DEFINED):
    program = currentProgram
    sym_table = program.getSymbolTable()
    sym_table.createLabel(addr, label_name, source)


def get_instructions_from(addr=None):
    program = currentProgram
    return program.getListing().getInstructions(addr, True)


def get_all_instructions():
    program = currentProgram
    return program.getListing().getInstructions(True)


def get_instruction_at(addr):
    return flatapi.getInstructionAt(addr)


def get_memory_address_ranges():
    program = currentProgram
    return program.getMemory().getAddressRanges()


def has_scalar_operand(inst, idx=1):
    return inst.getScalar(idx) is not None


def set_eol_comment(addr, text):
    program = currentProgram
    code_unit = program.getListing().getCodeUnitAt(addr)
    code_unit.setComment(CodeUnit.EOL_COMMENT, text)


def get_function_containing(addr):
    return flatapi.getFunctionContaining(addr)


def get_instructions_in_func(func):
    if func is None:
        return
    inst = get_instruction_at(func.getEntryPoint())
    while inst and get_function_containing(inst.getAddress()) == func:
        yield inst
        inst = inst.getNext()


# partial funcs
pack_longlong = functools.partial(struct.pack, '<Q')
pack_long = functools.partial(struct.pack, '<L')


class NonSparseConst:
    BYTE = 'B'
    LONG = 'L'
    LONGLONG = 'Q'

    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.size = const['size']
        self.array = const['array']
        self._byte_array = None

    def handle_byte(self):
        return self.array

    def handle_long(self):
        return b''.join(map(pack_long, self.array))

    def handle_longlong(self):
        return b''.join(map(pack_longlong, self.array))

    def to_bytes(self):
        handler = {
            self.BYTE: self.handle_byte,
            self.LONG: self.handle_long,
            self.LONGLONG: self.handle_longlong
            # if there'll be another types, add handler here
        }.get(self.size)

        if handler is None:
            raise ValueError('{} is not supported'.format(self.size))
        
        result = handler()
        if isinstance(result, bytes):
            return result
        return bytes(bytearray(result))

    @property
    def byte_array(self):
        if self._byte_array is None:
            self._byte_array = self.to_bytes()
        return self._byte_array


class SparseConst:
    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.array = const['array']


class OperandConst:
    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.value = const['value']


def build_scalar_addr_pairs():
    """Build a dictionary of scalar values to their instruction addresses."""
    pairs = {}
    for inst in filter(has_scalar_operand, get_all_instructions()):
        scalar = inst.getScalar(1)
        if scalar is not None:
            pairs[scalar.getValue()] = inst.getAddress()
    return pairs


def find_crypt_non_sparse_consts():
    print('[*] processing non-sparse consts')
    for nsc in map(NonSparseConst, const.non_sparse_consts):
        found = find(nsc.byte_array)
        if found:
            print(' [+] found {name} for {alg} at {addr}'.format(name=nsc.name, alg=nsc.algorithm, addr=found))
            create_label(found, nsc.name)


def find_crypt_sparse_consts(scalar_addr_pairs):
    print('[*] processing sparse consts')

    for sc in map(SparseConst, const.sparse_consts):
        # get address of first const matched one in operands 
        found_addr = scalar_addr_pairs.get(sc.array[0])
        if found_addr:
            # check the rest of consts, maybe it should be in the same function
            # it is noted that it will be failed if the constants are not used in function (like shellcode).
            maybe_crypto_func = get_function_containing(found_addr)
            if maybe_crypto_func is None:
                continue
            insts = get_instructions_in_func(maybe_crypto_func)

            # get all scalars in same function
            insts_with_scalars = filter(has_scalar_operand, insts)
            scalars = [inst.getScalar(1).getValue() for inst in insts_with_scalars]

            # check all values in consts array are contained in scalars in same function 
            if all([c in scalars for c in sc.array]):
                # if all consts are contained
                # add comment at the first found const's address
                print(' [+] found {name} for {alg} at {addr}'.format(name=sc.name, alg=sc.algorithm, addr=found_addr))
                create_label(found_addr, sc.name)


def find_crypt_operand_consts(scalar_addr_pairs):
    print('[*] processing operand consts')
    for oc in map(OperandConst, const.operand_consts):
        found_addr = scalar_addr_pairs.get(oc.value)
        if found_addr:
            print(' [+] found {name} for {alg} at {addr}'.format(name=oc.name, alg=oc.algorithm, addr=found_addr))
            set_eol_comment(found_addr, oc.name)


def main():
    # Build scalar address pairs dictionary at runtime
    print('[*] Building scalar address pairs...')
    scalar_addr_pairs = build_scalar_addr_pairs()
    print('[*] Found {} scalar operands'.format(len(scalar_addr_pairs)))
    
    find_crypt_non_sparse_consts()
    find_crypt_sparse_consts(scalar_addr_pairs)
    find_crypt_operand_consts(scalar_addr_pairs)


if __name__ == '__main__':
    main()
