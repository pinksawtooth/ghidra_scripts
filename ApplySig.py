#Apply IDA FLIRT signatures for Ghidra
# original code from
#    https://github.com/thebabush/nampa/blob/b04a506ea83e6ac48c1e13288ce155d97d42922d/nampa/flirt.py
#    https://github.com/radare/radare2/blob/0948f9536b20be553bfbdbf1fc877b80fad3efa0/libr/anal/flirt.c
# @author NWMonster
# @category FunctionID
# @menupath Tools.Function ID.ApplySig
#
# PyGhidra compatible version

from ghidra.framework.model import DomainFile
from ghidra.program.model.symbol import SourceType
from ghidra.util import Msg

from java.lang import IllegalArgumentException
try:
    from typing import List
except ImportError:
    pass

from itertools import islice
from io import StringIO, BytesIO

import zlib
import struct

# PyGhidra compatibility: Import Ghidra APIs
from ghidra.program.flatapi import FlatProgramAPI

flatapi = FlatProgramAPI(currentProgram)





#############  binrw lib

def read_x(fmt, f, l):
    return struct.unpack(fmt, f.read(l))[0]


def read_u8(f):
    return read_x('B', f, 1)


def read_u16be(f):
    return read_x('>H', f, 2)


def read_u24be(f):
    return read_u8(f) << 16 | read_u16be(f)


def read_u32be(f):
    return read_x('>L', f, 4)


def read_u16le(f):
    return read_x('<H', f, 2)


def read_u32le(f):
    return read_x('<L', f, 4)


############# crc lib

POLY = 0x1021
_crc_table = []


def _rev8(n):
    return int('{:08b}'.format(n)[::-1], 2)


def _rev16(n):
    return int('{:016b}'.format(n)[::-1], 2)

_poly_rev = _rev16(POLY)


def _init_table():
    for i in range(256):
        i = _rev8(i)

        crc = 0
        c = (i << 8) & 0xFFFF

        for j in range(8):
            if (crc ^ c) & 0x8000:
                crc = (crc << 1) ^ POLY
            else:
                crc = (crc << 1)

            crc &= 0xFFFF
            c = (c << 1) & 0xFFFF

        crc = _rev16(crc)
        _crc_table.append(crc)
_init_table()


def crc16(data, start_value=0xFFFF):
    out = start_value
    for b in data:
        if isinstance(b, int):
            tmp = (out ^ b) & 0xFF
        else:
            tmp = (out ^ ord(b)) & 0xFF
        out = (out >> 8) ^ _crc_table[tmp]
    out ^= 0xFFFF
    out = ((out & 0xFF) << 8) | ((out >> 8) & 0xff)
    return out


def crc16slow(data, start_value=0xFFFF):
    out = start_value
    for b in data:
        if not isinstance(b, int):
            b = ord(b)
        for i in range(8):
            if (out ^ b) & 1 == 1:
                out = (out >> 1) ^ _poly_rev
            else:
                out >>= 1
            b >>= 1
    out = (~out) & 0xFFFF
    out = ((out & 0xFF) << 8) | ((out >> 8) & 0xff)
    return out

############# flirt parser

FLIRT_NAME_MAX = 1024

def list2hexstring(ll):
    return ''.join(['{:02X}'.format(l) for l in ll])


def pattern2string(pp, mask_array):
    if pp is None:
        return ''
    return ''.join(['{:02X}'.format(p) if not m else '..' for p, m in zip(pp, mask_array)])


def read_max_2_bytes(f):
    b = read_u8(f)
    if b & 0x80 == 0x80:
        return ((b & 0x7F) << 8) | read_u8(f)
    else:
        return b


def read_multiple_bytes(f):
    b = read_u8(f)
    if b & 0x80 != 0x80:
        return b
    elif b & 0xC0 != 0xC0:
        return ((b & 0x7F) << 8) | read_u8(f)
    elif b & 0xE0 != 0xE0:
        return ((b & 0x3F) << 24) | read_u24be(f)
    else:
        return read_u32be(f)


def read_node_variant_mask(f, length):
    if length < 0x10:
        return read_max_2_bytes(f)
    elif length <= 0x20:
        return read_multiple_bytes(f)
    elif length <= 0x40:
        return (read_multiple_bytes(f) << 32) | read_multiple_bytes(f)
    else:
        raise FlirtException('Wrong node variant mask length: {}'.format(length))


def read_node_bytes(f, length, variant_mask):
    mask_bit = 1 << length - 1
    variant_bools = list()
    pattern = list()
    for i in range(length):
        curr_mask_bool = variant_mask & mask_bit != 0
        if curr_mask_bool:
            pattern.append(0)
        else:
            pattern.append(read_u8(f))
        variant_bools.append(curr_mask_bool)
        mask_bit >>= 1
    return variant_bools, pattern


class FlirtArch(object):
    ARCH_386 = 0
    ARCH_Z80 = 1
    ARCH_I860 = 2
    ARCH_8051 = 3
    ARCH_TMS = 4
    ARCH_6502 = 5
    ARCH_PDP = 6
    ARCH_68K = 7
    ARCH_JAVA = 8
    ARCH_6800 = 9
    ARCH_ST7 = 10
    ARCH_MC6812 = 11
    ARCH_MIPS = 12
    ARCH_ARM = 13
    ARCH_TMSC6 = 14
    ARCH_PPC = 15
    ARCH_80196 = 16
    ARCH_Z8 = 17
    ARCH_SH = 18
    ARCH_NET = 19
    ARCH_AVR = 20
    ARCH_H8 = 21
    ARCH_PIC = 22
    ARCH_SPARC = 23
    ARCH_ALPHA = 24
    ARCH_HPPA = 25
    ARCH_H8500 = 26
    ARCH_TRICORE = 27
    ARCH_DSP56K = 28
    ARCH_C166 = 29
    ARCH_ST20 = 30
    ARCH_IA64 = 31
    ARCH_I960 = 32
    ARCH_F2MC = 33
    ARCH_TMS320C54 = 34
    ARCH_TMS320C55 = 35
    ARCH_TRIMEDIA = 36
    ARCH_M32R = 37
    ARCH_NEC_78K0 = 38
    ARCH_NEC_78K0S = 39
    ARCH_M740 = 40
    ARCH_M7700 = 41
    ARCH_ST9 = 42
    ARCH_FR = 43
    ARCH_MC6816 = 44
    ARCH_M7900 = 45
    ARCH_TMS320C3 = 46
    ARCH_KR1878 = 47
    ARCH_AD218X = 48
    ARCH_OAKDSP = 49
    ARCH_TLCS900 = 50
    ARCH_C39 = 51
    ARCH_CR16 = 52
    ARCH_MN102L00 = 53
    ARCH_TMS320C1X = 54
    ARCH_NEC_V850X = 55
    ARCH_SCR_ADPT = 56
    ARCH_EBC = 57
    ARCH_MSP430 = 58
    ARCH_SPU = 59
    ARCH_DALVIK = 60


class FlirtFileType(object):
    FILE_DOS_EXE_OLD = 0x00000001
    FILE_DOS_COM_OLD = 0x00000002
    FILE_BIN         = 0x00000004
    FILE_DOSDRV      = 0x00000008
    FILE_NE          = 0x00000010
    FILE_INTELHEX    = 0x00000020
    FILE_MOSHEX      = 0x00000040
    FILE_LX          = 0x00000080
    FILE_LE          = 0x00000100
    FILE_NLM         = 0x00000200
    FILE_COFF        = 0x00000400
    FILE_PE          = 0x00000800
    FILE_OMF         = 0x00001000
    FILE_SREC        = 0x00002000
    FILE_ZIP         = 0x00004000
    FILE_OMFLIB      = 0x00008000
    FILE_AR          = 0x00010000
    FILE_LOADER      = 0x00020000
    FILE_ELF         = 0x00040000
    FILE_W32RUN      = 0x00080000
    FILE_AOUT        = 0x00100000
    FILE_PILOT       = 0x00200000
    FILE_DOS_EXE     = 0x00400000
    FILE_DOS_COM     = 0x00800000
    FILE_AIXAR       = 0x01000000


class FlirtOsType(object):
    OS_MSDOS   = 0x01
    OS_WIN     = 0x02
    OS_OS2     = 0x04
    OS_NETWARE = 0x08
    OS_UNIX    = 0x10
    OS_OTHER   = 0x20


class FlirtAppType(object):
    APP_CONSOLE         = 0x0001
    APP_GRAPHICS        = 0x0002
    APP_EXE             = 0x0004
    APP_DLL             = 0x0008
    APP_DRV             = 0x0010
    APP_SINGLE_THREADED = 0x0020
    APP_MULTI_THREADED  = 0x0040
    APP_16_BIT          = 0x0080
    APP_32_BIT          = 0x0100
    APP_64_BIT          = 0x0200


class FlirtFeatureFlag(object):
    FEATURE_STARTUP       = 0x01
    FEATURE_CTYPE_CRC     = 0x02
    FEATURE_2BYTE_CTYPE   = 0x04
    FEATURE_ALT_CTYPE_CRC = 0x08
    FEATURE_COMPRESSED    = 0x10


class FlirtParseFlag(object):
    PARSE_MORE_PUBLIC_NAMES          = 0x01
    PARSE_READ_TAIL_BYTES            = 0x02
    PARSE_READ_REFERENCED_FUNCTIONS  = 0x04
    PARSE_MORE_MODULES_WITH_SAME_CRC = 0x08
    PARSE_MORE_MODULES               = 0x10


class FlirtFunctionFlag(object):
    FUNCTION_LOCAL = 0x02
    FUNCTION_UNRESOLVED_COLLISION = 0x08


class FlirtException(Exception):
    pass


class FlirtFunction(object):
    def __init__(self, name, offset, negative_offset, is_local, is_collision):
        self.name = name
        self.offset = offset
        self.negative_offset = negative_offset
        self.is_local = is_local
        self.is_collision = is_collision

    def __str__(self):
        return '<{}: name={}, offset=0x{:04X}, negative_offset={}, is_local={}, is_collision={}>'.format(
            self.__class__.__name__, self.name, self.offset, self.negative_offset, self.is_local, self.is_collision
        )


class FlirtTailByte(object):
    def __init__(self, offset, value):
        self.offset = offset
        self.value = value


class FlirtModule(object):
    def __init__(self, crc_length, crc16, length, public_functions, tail_bytes, referenced_functions):
        self.crc_length = crc_length
        self.crc16 = crc16
        self.length = length
        self.public_functions = public_functions
        self.tail_bytes = tail_bytes
        self.referenced_functions = referenced_functions


class FlirtNode(object):
    def __init__(self, children, modules, length, variant_mask, pattern):
        self.children = children
        self.modules = modules
        self.length = length
        self.variant_mask = variant_mask
        self.pattern = pattern

    @property
    def is_leaf(self):
        return len(self.children) == 0

    def __str__(self):
        return '<{}: children={}, modules={}, length={}, variant={}, pattern="{}">'.format(
            self.__class__.__name__, len(self.children), len(self.modules), self.length, self.variant_mask
            , pattern2string(self.pattern, self.variant_mask)
        )


class FlirtHeader(object):
    def __init__(self, version, arch, file_types, os_types, app_types, features, old_n_functions, crc16, ctype
                 , ctypes_crc16, n_functions, pattern_size, library_name):
        self.version = version
        self.arch = arch
        self.file_types = file_types
        self.os_types = os_types
        self.app_types = app_types
        self.features = features
        self.old_n_functions = old_n_functions
        self.crc16 = crc16
        self.ctype = ctype
        self.ctypes_crc16 = ctypes_crc16
        self.n_functions = n_functions
        self.pattern_size = pattern_size
        self.library_name = library_name


class FlirtFile(object):
    def __init__(self, header, root):
        self.header = header
        self.root = root


def parse_header(f):
    magic = f.read(6)
    if magic != b'IDASGN':
        raise FlirtException('Wrong file type')

    version = read_u8(f)
    if version < 5 or version > 10:
        raise FlirtException('Unknown version: {}'.format(version))

    arch = read_u8(f)
    file_types = read_u32le(f)
    os_types = read_u16le(f)
    app_types = read_u16le(f)
    features = read_u16le(f)
    old_n_functions = read_u16le(f)
    crc16 = read_u16le(f)
    ctype = f.read(12)
    library_name_len = read_u8(f)
    ctypes_crc16 = read_u16le(f)

    n_functions = None
    pattern_size = None
    if version >= 6:
        n_functions = read_u32le(f)
        if version >= 8:
            pattern_size = read_u16le(f)
            if version > 9:
                read_u16le(f)

    library_name = f.read(library_name_len)
    return FlirtHeader(version, arch, file_types, os_types, app_types, features, old_n_functions, crc16, ctype
                       , ctypes_crc16, n_functions, pattern_size, library_name)


def parse_tail_byte(f, version):
    if version >= 9:
        offset = read_multiple_bytes(f)
    else:
        offset = read_max_2_bytes(f)
    value = read_u8(f)
    return FlirtTailByte(offset, value)


def parse_tail_bytes(f, version):
    if version >= 8:
        length = read_u8(f)
    else:
        length = 1
    tail_bytes = []
    for i in range(length):
        tail_bytes.append(parse_tail_byte(f, version))
    return tail_bytes


def parse_referenced_function(f, version):
    if version >= 9:
        offset = read_multiple_bytes(f)
    else:
        offset = read_max_2_bytes(f)

    name_length = read_u8(f)
    if name_length == 0:
        name_length = read_multiple_bytes(f)

    if name_length & 0x80000000 != 0:
        raise FlirtException('Negative name length')

    name = list()
    for i in range(name_length):
        name.append(read_u8(f))

    negative_offset = False
    if name[-1] == 0:
        name = name[:-1]
        negative_offset = True

    name = bytearray(name).decode('ascii')
    return FlirtFunction(name, offset, negative_offset, False, False)


def parse_referenced_functions(f, version):
    if version >= 8:
        length = read_u8(f)
    else:
        length = 1

    referenced_functions = []
    for i in range(length):
        referenced_functions.append(parse_referenced_function(f, version))
    return referenced_functions


def parse_public_function(f, version, offset):
    is_local = False
    is_collision = False

    if version >= 9:
        offset += read_multiple_bytes(f)
    else:
        offset += read_max_2_bytes(f)

    b = read_u8(f)
    if b < 0x20:
        if b & FlirtFunctionFlag.FUNCTION_LOCAL:
            is_local = True
        if b & FlirtFunctionFlag.FUNCTION_UNRESOLVED_COLLISION:
            is_collision = True
        if b & 0x01 or b & 0x04:
            print('Investigate public name flag: 0x{:02X} @ 0x{:04X}'.format(b, offset))
        b = read_u8(f)

    name = list()
    name_finished = False
    for i in range(FLIRT_NAME_MAX):
        if b < 0x20:
            name_finished = True
            break
        name.append(b)
        b = read_u8(f)
    flags = b

    name = bytearray(name).decode('ascii')
    if not name_finished:
        print('Function name too long: {}'.format(name))

    return FlirtFunction(name, offset, False, is_local, is_collision), offset, flags


def parse_module(f, version, crc_length, crc16):
    if version >= 9:
        length = read_multiple_bytes(f)
    else:
        length = read_max_2_bytes(f)

    public_functions = []
    offset = 0
    while True:
        func, offset, flags = parse_public_function(f, version, offset)
        public_functions.append(func)
        if flags & FlirtParseFlag.PARSE_MORE_PUBLIC_NAMES == 0:
            break

    tail_bytes = []
    if flags & FlirtParseFlag.PARSE_READ_TAIL_BYTES != 0:
        tail_bytes = parse_tail_bytes(f, version)

    referenced_functions = []
    if flags & FlirtParseFlag.PARSE_READ_REFERENCED_FUNCTIONS != 0:
        referenced_functions = parse_referenced_functions(f, version)

    return FlirtModule(crc_length, crc16, length, public_functions, tail_bytes, referenced_functions), flags


def parse_modules(f, version):
    modules = list()
    while True:
        crc_length = read_u8(f)
        crc16 = read_u16be(f)
        while True:
            module, flags = parse_module(f, version, crc_length, crc16)
            modules.append(module)
            if flags & FlirtParseFlag.PARSE_MORE_MODULES_WITH_SAME_CRC == 0:
                break
        if flags & FlirtParseFlag.PARSE_MORE_MODULES == 0:
            break
    return modules


def parse_tree(f, version, is_root):
    if is_root:
        length = 0
        variant_mask = None
        pattern = None
    else:
        length = read_u8(f)
        variant_mask = read_node_variant_mask(f, length)
        variant_mask, pattern = read_node_bytes(f, length, variant_mask)

    nodes = read_multiple_bytes(f)
    if nodes == 0:
        modules = parse_modules(f, version)
        return FlirtNode([], modules, length, variant_mask, pattern)

    children = list()
    for i in range(nodes):
        children.append(parse_tree(f, version, False))

    return FlirtNode(children, [], length, variant_mask, pattern)


def parse_flirt_file(f):
    header = parse_header(f)
    if header.features & FlirtFeatureFlag.FEATURE_COMPRESSED:
        if header.version == 5:
            raise FlirtException('Compression in unsupported on flirt v5')
        f = BytesIO(zlib.decompress(f.read()))

    tree = parse_tree(f, header.version, is_root=True)
    assert len(f.read(1)) == 0
    return FlirtFile(header, tree)


def match_node_pattern(node, buff, offset):
    assert len(buff) - offset >= 0
    if len(buff) < offset + len(node.pattern):
        return False
    for i, (b, p, v) in enumerate(zip(islice(buff, offset, len(buff)), node.pattern, node.variant_mask)):
        if isinstance(b, int):
            if b < 0:
                b = b + 256
        else:
            b = ord(b)
            if b < 0:
                b = b + 256
        if v:
            continue
        elif b != p:
            return False
    return True


def match_module(module, buff, addr, offset, callback):
    buff_size = len(buff) - offset
    if module.crc_length < buff_size and module.crc16 != crc16(buff[offset:offset+module.crc_length]):
        return False

    for tb in module.tail_bytes:
        tb_val = buff[offset+module.crc_length+tb.offset]
        if not isinstance(tb_val, int):
            tb_val = ord(tb_val)
        if module.crc_length + tb.offset < buff_size and tb_val != tb.value:
            return False

    for func in module.public_functions:
        callback(addr, func)
    return True


def match_node(node, buff, addr, offset, callback):
    if match_node_pattern(node, buff, offset):
        for child in node.children:
            if match_node(child, buff, addr, offset + node.length, callback):
                return True
        for module in node.modules:
            if match_module(module, buff, addr, offset + node.length, callback):
                return True
    return False


def match_function(sig, buff, addr, callback):
    if type(buff) is str:
        buff = bytes(buff.encode('latin-1'))
    for child in sig.root.children:
        if match_node(child, buff, addr, 0, callback):
            return True
    return False


def ask_sig():
    try:
        f = askFile("Choose Sig file:", "ApplySig")
        print('Load File: {}'.format(f))
        return open(f.toString(), 'rb')
    except Exception as e:
        Msg.showError(None, None, "Error", "Failed to open file: {}".format(e))
        return None


def get_function_end(func):
    blocks = func.getBody().toList()
    max_addr = 0
    for block in blocks:
        block_max = int(block.getMaxAddress().toString(), 16)
        if block_max > max_addr:
            max_addr = block_max
    return max_addr


def rename_function(addr, func):
    global rename_cnt
    name = func.name
    if name != '?':
        ghidra_func = flatapi.getFunctionAt(flatapi.toAddr(hex(addr)))
        if ghidra_func and "FUN_" in ghidra_func.getName():
            print("{} @ {}".format(hex(addr), name))
            ghidra_func.setName(name, SourceType.USER_DEFINED)
            rename_cnt += 1


def apply_sig(flirt):
    func = flatapi.getFirstFunction()
    while func is not None:
        func_start = int(func.entryPoint.toString(), 16)
        func_end = get_function_end(func)
        func_buf = flatapi.getBytes(flatapi.toAddr(hex(func_start)), func_end - func_start + 0x100)
        match_function(flirt, func_buf, func_start, rename_function)
        func = flatapi.getFunctionAfter(func)


rename_cnt = 0

def main():
    global rename_cnt
    f = ask_sig()
    if f is None:
        return
    print('Parse Flirt File.....')
    try:
        flirt = parse_flirt_file(f)
    except Exception as e:
        print('Parsing Failed! {}'.format(e))
        return
    print('Name: ', flirt.header.library_name)
    print('Count:', flirt.header.n_functions)
    print('Apply Signatures.....')
    apply_sig(flirt)
    print('[ %d / %d ]' % (rename_cnt, flirt.header.n_functions))
    print('Done!')


if __name__ == '__main__':
    main()
