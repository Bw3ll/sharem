from ctypes import c_byte, c_char, c_double, c_float, c_int, c_int32, c_int64, c_longlong, c_short, c_uint, c_uint32, c_uint64, c_ulonglong, c_ushort, c_wchar
from struct import unpack
from ..helper.emuHelpers import Uc

# Window C Type Mappings
# Inspired by WinTypes from cTypes
# https://github.com/python/cpython/blob/main/Lib/ctypes/wintypes.py

MAX_PATH = 260

# General Types
BYTE = c_byte
WORD = c_ushort
DWORD = c_uint32

CHAR = c_char
WCHAR = c_wchar

BOOLEAN = BYTE
BOOL = c_uint32

USHORT = c_ushort
SHORT = c_short

UINT = c_uint
INT = c_int

ULONG = c_uint32 # Windows LONG is 4 bytes
LONG = c_int32 # Unix LONG is 8 bytes

ULONGLONG = c_ulonglong
LONGLONG = c_longlong

DOUBLE = c_double
FLOAT = c_float

# 32 Bit Pointers / Const Pointers
LPCWSTR_32BIT = LPWSTR_32BIT = PWSTR_32BIT = c_uint32
LPCSTR_32BIT = LPSTR_32BIT = PSTR_32BIT = c_uint32
LPCVOID_32BIT = LPVOID_32BIT = PVOID_32BIT = c_uint32

# 64 Bit Pointers / Const Pointers
LPCWSTR_64BIT = LPWSTR_64BIT = PWSTR_64BIT = c_uint64
LPCSTR_64BIT = LPSTR_64BIT = PSTR_64BIT = c_uint64
LPCVOID_64BIT = LPVOID_64BIT = PVOID_64BIT = c_uint64

# Params 32 Bit 
WPARAM_32BIT = c_uint32
LPARAM_32BIT = c_int32

# Params 64 Bit
WPARAM_64BIT = c_uint64
LPARAM_64BIT = c_int64

ATOM = WORD
LANGID = WORD

COLORREF = DWORD
LGRPID = DWORD
LCTYPE = DWORD
LCID = DWORD

DWORD_PTR = c_uint32

# Handles 32 Bit
HANDLE_32BIT = c_uint32 # Base Handle

HACCEL_32BIT = HBITMAP_32BIT = HBRUSH_32BIT = HCOLORSPACE_32BIT = HDC_32BIT = HDESK_32BIT = HDWP_32BIT = HENHMETAFILE_32BIT = HFONT_32BIT = HGDIOBJ_32BIT = HGLOBAL_32BIT = HHOOK_32BIT = HICON_32BIT = HINSTANCE_32BIT = HKEY_32BIT = HKL_32BIT = HLOCAL_32BIT = HMENU_32BIT = HMETAFILE_32BIT = HMODULE_32BIT = HMONITOR_32BIT = HPALETTE_32BIT = HPEN_32BIT = HRGN_32BIT = HRSRC_32BIT = HSTR_32BIT = HTASK_32BIT = HWINSTA_32BIT = HWND_32BIT = SC_HANDLE_32BIT = SERVICE_STATUS_HANDLE_32BIT = HANDLE_32BIT

# Handles 64 Bit
HANDLE_64BIT = c_uint64 # Base Handle

HACCEL_64BIT = HBITMAP_64BIT = HBRUSH_64BIT = HCOLORSPACE_64BIT = HDC_64BIT = HDESK_64BIT = HDWP_64BIT = HENHMETAFILE_64BIT = HFONT_64BIT = HGDIOBJ_64BIT = HGLOBAL_64BIT = HHOOK_64BIT = HICON_64BIT = HINSTANCE_64BIT = HKEY_64BIT = HKL_64BIT = HLOCAL_64BIT = HMENU_64BIT = HMETAFILE_64BIT = HMODULE_64BIT = HMONITOR_64BIT = HPALETTE_64BIT = HPEN_64BIT = HRGN_64BIT = HRSRC_64BIT = HSTR_64BIT = HTASK_64BIT = HWINSTA_64BIT = HWND_64BIT = SC_HANDLE_64BIT = SERVICE_STATUS_HANDLE_64BIT = HANDLE_64BIT

# Pointer to Types / Handles 32 Bit
LPBOOL_32BIT = PBOOL_32BIT = PBOOLEAN_32BIT = LPBYTE_32BIT = PBYTE_32BIT = PCHAR_32BIT = LPCOLORREF_32BIT = LPDWORD_32BIT = PDWORD_32BIT = LPFILETIME_32BIT = PFILETIME_32BIT = PFLOAT_32BIT = LPHANDLE_32BIT = PHANDLE_32BIT = PHKEY_32BIT = LPHKL_32BIT = LPINT_32BIT = PINT_32BIT = PLCID_32BIT = LPLONG_32BIT = PLONG_32BIT = LPSC_HANDLE_32BIT = PSHORT_32BIT = LPUINT_32BIT = PUINT_32BIT = PULONG_32BIT = PUSHORT_32BIT = PWCHAR_32BIT = LPWORD_32BIT = PWORD_32BIT = c_uint32

# Pointer to Types / Handles 64 Bit
LPBOOL_64BIT = PBOOL_64BIT = PBOOLEAN_64BIT = LPBYTE_64BIT = PBYTE_64BIT = PCHAR_64BIT = LPCOLORREF_64BIT = LPDWORD_64BIT = PDWORD_64BIT = LPFILETIME_64BIT = PFILETIME_64BIT = PFLOAT_64BIT = LPHANDLE_64BIT = PHANDLE_64BIT = PHKEY_64BIT = LPHKL_64BIT = LPINT_64BIT = PINT_64BIT = PLCID_64BIT = LPLONG_64BIT = PLONG_64BIT = LPSC_HANDLE_64BIT = PSHORT_64BIT = LPUINT_64BIT = PUINT_64BIT = PULONG_64BIT = PUSHORT_64BIT = PWCHAR_64BIT = LPWORD_64BIT = PWORD_64BIT = c_uint64

# Pointers to Structures 32 Bit
POINTER_32BIT = c_uint32 # Base Pointer

# Pointers to Structures 64 Bit
POINTER_64BIT = c_uint64 # Base Pointer

# Helpers
def read_string(uc: Uc, address: int):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    if c == 0x0: ret = "[NULL]"  # Option for NULL String

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret

def read_unicode(uc: Uc, address: int):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 0

    if c == 0x0: ret = "[NULL]"  # Option for NULL String

    while c != 0x0:
        c = uc.mem_read(address + read_bytes, 1)[0]
        ret += chr(c)
        read_bytes += 2

    ret = ret.rstrip('\x00')
    return ret

def buildPtrString(pointer, val):
    return hex(pointer) + " -> " + hex(val)

def getPointerVal(uc: Uc, pointer: int):
    val = uc.mem_read(pointer, 4)
    return unpack('<I', val)[0]

def makeStructVals(uc: Uc, struct, address: int,unicode: bool = False):
    pTypes = struct.types
    pNames = struct.names
    pVals = []
    for name in pNames:
        try:
            value = getattr(struct, name)
        except:
            # Some Struct Implementations are both Unicode and Ascii 
            # So some attributes have A or W Suffix.
            if not unicode: 
                name = name + 'A'
                value = getattr(struct, name) 
            else:
                name = name + 'W'
                value = getattr(struct, name)
        if "<sharem." in str(value): 
            # Need to Figure out what to Do for Nested Structures 
            # that are not pointers. Temp Solution
            tempTypes, tempNames, tempVals = makeSubStructVals(uc,value)
            value = '{'
            for t, n, v in zip(tempTypes, tempNames, tempVals):
                value += f'{t} {n}: {v}, '
            if value[-2:] == ', ':
                value = value[:-2]
            value += '}'
        pVals.append(value)

    for i in range(len(pTypes)):
        if "STR" in pTypes[i]:  # finding ones with string
            try:
                if "WSTR" in pTypes[i]:
                    pVals[i] = read_unicode(uc, pVals[i])
                else:
                    pVals[i] = read_string(uc, pVals[i])
            except:
                pass
        elif pTypes[i][0] == 'P': # Pointer Builder
            try:
                pointerVal = getPointerVal(uc, pVals[i])
                pVals[i] = buildPtrString(pVals[i], pointerVal)
            except:
                pass
        elif pTypes[i] == 'BOOLEAN' or pTypes[i] == 'BOOL':
            if pVals[i] == 0x1:
                pVals[i] = 'TRUE'
            elif pVals[i] == 0x0:
                pVals[i] = 'FALSE'
            else:
                pVals[i] = hex(pVals[i])
        else:
            try:
                pVals[i] = hex(pVals[i])
            except:
                pVals[i] = str(pVals[i])
                # If fail then Param is Probably String and Just Display value

    # zipped = tuple(zip(pTypes, pNames, pVals))
    
    return (pTypes, pNames, pVals, hex(address))

def makeSubStructVals(uc: Uc, struct):
    pTypes = struct.types
    pNames = struct.names
    pVals = []
    for name in pNames:
        try:
            value = getattr(struct, name)
        except:
            # Some Struct Implementations are both Unicode and Ascii 
            # So some attributes have A or W Suffix.
            pass
        pVals.append(value)

    for i in range(len(pTypes)):
        if "STR" in pTypes[i]:  # finding ones with string
            try:
                if "WSTR" in pTypes[i]:
                    pVals[i] = read_unicode(uc, pVals[i])
                else:
                    pVals[i] = read_string(uc, pVals[i])
            except:
                pass
        elif pTypes[i][0] == 'P': # Pointer Builder
            try:
                pointerVal = getPointerVal(uc, pVals[i])
                pVals[i] = buildPtrString(pVals[i], pointerVal)
            except:
                pass
        elif pTypes[i] == 'BOOLEAN' or pTypes[i] == 'BOOL':
            if pVals[i] == 0x1:
                pVals[i] = 'TRUE'
            elif pVals[i] == 0x0:
                pVals[i] = 'FALSE'
            else:
                pVals[i] = hex(pVals[i])
        else:
            try:
                pVals[i] = hex(pVals[i])
            except:
                pVals[i] = str(pVals[i])
                # If fail then Param is Probably String and Just Display value

    # zipped = tuple(zip(pTypes, pNames, pVals))
    
    return (pTypes, pNames, pVals)
