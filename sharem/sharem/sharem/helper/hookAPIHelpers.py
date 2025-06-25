import functools
from .emu import EMU
from .emuHelpers import Uc
from struct import pack, unpack
from unicorn.x86_const import *
from sharem.sharem.DLLs.emu_helpers.handles import Handle, HandleType, HandlesDict
#from ..DLLs.hookAPIs import makeArgVals, findStringsParms, stackCleanup

def HookAPI(func, include_eip=False):
    # Author: William Lochte
    """
    Decorator method that simplifies the hook APIs and reduces redundancy.

    Method should declare API variables as function parameters.\n
    Use annotations to display the argument type.\n
    Set the return annotation of the method to the API return type.\n

    The method shoud return the following values in order:\n
    retString -- string representation of the return value\n
    parameterValues -- list containing all of the API parameters\n
    skipStringParams -- list of indexes or parameter names to skip during findStringsParms
    """
    @staticmethod
    @functools.wraps(func)
    def wrapper(uc: Uc, eip: int, esp: int, export_dict: dict, callAddr: int, em: EMU):
        returnType = ""
        methodArgs = {}
        for key, value in func.__annotations__.items():
            if isinstance(value, type) and value.__name__ in ["Uc", "EMU"]:
                continue
            elif key == "return":
                returnType = value # TODO: HANDLE NON-STRING RETURN TYPES
            else:
                methodArgs[key] = value

        pTypes = list(methodArgs.values())
        pNames = list(methodArgs.keys())
        pVals  = makeArgVals(uc, em, esp, len(pTypes))

        passedArgs = dict(zip(pNames, pVals))
        passedArgs["em"] = em
        passedArgs["uc"] = uc

        if (include_eip):
            passedArgs["eip"] = eip

        # Execute the function now
        retValStr, pVals, skip = func(**passedArgs)

        # convert variable names to indexes
        skip = list(map(lambda val: pNames.index(val) if isinstance(val, str) else val, skip))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=skip)

        logged_calls = (func.__name__, hex(callAddr), (retValStr), returnType, pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    return wrapper

def getStackVal(uc: Uc, em: EMU, esp: int, loc: int):
    # x64 Windows parameter order: rcx, rdx, r8, r9, stack
    if loc == 1 and em.arch == 64:
        arg = uc.reg_read(UC_X86_REG_RCX)
    elif loc == 2 and em.arch == 64:
        arg = uc.reg_read(UC_X86_REG_RDX)
    elif loc == 3 and em.arch == 64:
        arg = uc.reg_read(UC_X86_REG_R8)
    elif loc == 4 and em.arch == 64:
        arg = uc.reg_read(UC_X86_REG_R9)
    else:
        if em.arch == 64:
            arg = uc.mem_read(esp + (8 * (loc-4)), 8)
            arg = unpack('<Q', arg)[0]
        else:
            arg = uc.mem_read(esp + (4 * loc), 4)
            arg = unpack('<I', arg)[0]

    return arg


def makeArgVals(uc: Uc, em: EMU, esp: int, numParams: int):
    # print ("numParams", numParams)
    args = [0] * numParams
    for i in range(len(args)):
        args[i] = getStackVal(uc, em, esp, i + 1)
    return args

def stackCleanup(uc: Uc, em: EMU, esp: int, numParams: int):
    if em.arch == 32:
        bytes = numParams * 4
    else:
        bytes = numParams * 8
        bytes -= 32
        if bytes < 0:
            bytes = 0
    return bytes
    # uc.reg_write(UC_X86_REG_ESP, esp + bytes)

def findStringsParms(uc: Uc, pTypes: 'list[str]', pVals: 'list', skip: 'list[int]'):
    i = 0
    for each in pTypes:
        if i not in skip:
            if "STR" in pTypes[i]:  # finding ones with string
                try:
                    # print ("looking", i, pTypes[i], pVals[i])
                    if "WSTR" in pTypes[i]:
                        pVals[i] = read_unicode(uc, pVals[i])
                    else:
                        pVals[i] = read_string(uc, pVals[i])
                    # print (pVals[i],"*")
                except:
                    # print ("pass", i)
                    pass
            elif "PCHAR" in pTypes[i]:
                pVals[i] = read_string(uc, pVals[i])
            elif "PWCHAR" in pTypes[i]:
                pVals[i] = read_unicode(uc, pVals[i])
            elif "char *" in pTypes[i]:
                try:
                    # print ("looking", i, pTypes[i], pVals[i])
                    if "wchar" in pTypes[i]:
                        pVals[i] = read_unicode(uc, pVals[i])
                    else:
                        pVals[i] = read_string(uc, pVals[i])
                    # print (pVals[i],"*")
                except:
                    # print ("pass", i)
                    pass
            elif pTypes[i][0] == 'H': # Handle Builder
                handleKey = getLookUpVal(pVals[i],HandlesDict)
                if isinstance(handleKey, Handle):
                    if handleKey.name != '':
                        pVals[i] = f'{handleKey.name}'
                    else:
                        pVals[i] = hex(pVals[i])
                else:
                    pVals[i] = hex(pVals[i])
            elif pTypes[i][0:2] == 'PH': # Pointer Handle Builder
                pointerVal = getPointerVal(uc, pVals[i])
                handleKey = getLookUpVal(pointerVal,HandlesDict)
                if isinstance(handleKey, Handle):
                    if handleKey.name != '':
                        pVals[i] = f'{hex(pVals[i])} -> {handleKey.name}'
                    else:
                        pVals[i] = buildPtrString(pVals[i],pointerVal)
                else:
                    pVals[i] = buildPtrString(pVals[i],pointerVal)
            elif pTypes[i][0] == 'P': # Pointer Builder
                try:
                    pointerVal = getPointerVal(uc,pVals[i])
                    pVals[i] = buildPtrString(pVals[i], pointerVal)
                except:
                    pass
            elif pTypes[i] == 'LPDWORD': # LPDWORD Builder
                try:
                    pointerVal = getPointerVal(uc,pVals[i])
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
                pVals[i] = hex(pVals[i])

        i += 1
    return pTypes, pVals

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

def read_unicode_extended(uc: Uc, address: int): # Able to read more utf-16 chars
    ret = ""
    mem = uc.mem_read(address, 2)[::-1]
    read_bytes = 2

    unicodeString = str(hex(mem[0])) + str(hex(mem[1])[2::])
    unicodeInt = int(unicodeString, 0)

    if unicodeInt == 0x0000: ret="[NULL]" # Option for NULL String

    while unicodeInt != 0x0000:
        ret += chr(unicodeInt)
        mem = uc.mem_read(address + read_bytes, 2)[::-1]
        unicodeString = str(hex(mem[0])) + str(hex(mem[1])[2::])
        unicodeInt = int(unicodeString, 0)
        read_bytes += 2

    return ret

def buildPtrString(pointer: int, val: int):
    return hex(pointer) + " -> " + hex(val)

def getPointerVal(uc: Uc, pointer):
    val = uc.mem_read(pointer, 4)
    return unpack('<I', val)[0]

def getLookUpVal(search: int, dictionary: 'dict[int,str]'):
    if search in dictionary:
        return dictionary[search]
    else:
        return hex(search)

def bin_to_ipv4(ip):
    return "%d.%d.%d.%d" % (
        (ip & 0xff000000) >> 24,
        (ip & 0xff0000) >> 16,
        (ip & 0xff00) >> 8,
        (ip & 0xff))

def writeAsciiStrToMemory(uc: Uc, address: int, string: str):
    uc.mem_write(address, pack(f"<{len(string.encode('ascii'))+2}s",string.encode('ascii')))

def writeUnicodeStrToMemory(uc: Uc, address: int, string: str):
    uc.mem_write(address, pack(f"<{len(string.encode('utf-16')[2:])+2}s",string.encode('utf-16')[2:]))
