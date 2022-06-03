import json

from unicorn.x86_const import *
from unicorn.x86_const import *
from struct import pack, unpack
from unicorn import *
from ..DLLs.dict4_ALL import *
from ..DLLs.dict_signatures import *
from ..DLLs.dict2_signatures import *
from ..DLLs.dict3_w32 import *
from ..DLLs.dict4_ALL import *
from ..DLLs.hookAPIs import *
from ..DLLs.syscall_signatures import *
import re
import binascii
from pathlib import Path
import sys

def read_unicode(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 0

    if c == 0x0: ret = "[NULL]" # Option for NULL String

    while c != 0x0:
        c = uc.mem_read(address + read_bytes, 1)[0]
        ret += chr(c)
        read_bytes += 2

    ret = ret.rstrip('\x00')
    return ret

def giveRegs(uc, arch):
    instructLine = "\n\t>>> "
    if arch == 32:
        regs32 = {"EAX": UC_X86_REG_EAX, "EBX": UC_X86_REG_EBX, "ECX": UC_X86_REG_ECX, "EDX": UC_X86_REG_EDX, "ESI": UC_X86_REG_ESI, "EDI": UC_X86_REG_EDI, "EBP": UC_X86_REG_EBP, "ESP": UC_X86_REG_ESP}
        for regName, regConst in regs32.items():
            regVal = uc.reg_read(regConst)
            instructLine += f"{regName}: {hex(regVal)} "
        instructLine += "\n"
        return instructLine
    elif arch == 64:
        regs64 = {"RAX": UC_X86_REG_RAX, "RBX": UC_X86_REG_RBX, "RCX": UC_X86_REG_RCX, "RDX": UC_X86_REG_RDX, "RSI": UC_X86_REG_RSI, "RDI": UC_X86_REG_RDI, "R8": UC_X86_REG_R8, "R9": UC_X86_REG_R9, "R10": UC_X86_REG_R10, "R11": UC_X86_REG_R11, "R12": UC_X86_REG_R12, "R13": UC_X86_REG_R13, "R14": UC_X86_REG_R14, "R15": UC_X86_REG_R15, "RBP": UC_X86_REG_RBP, "RSP": UC_X86_REG_RSP}
        for regName, regConst in regs64.items():
            regVal = uc.reg_read(regConst)
            instructLine += f"{regName}: {hex(regVal)} "
        instructLine += "\n"
        return instructLine

def ord2(x):
    return x

def show1(int):
        show = "{0:02x}".format(int) #
        return show

def binaryToStr(binary):
    # OP_SPECIAL = b"\x8d\x4c\xff\xe2\x01\xd8\x81\xc6\x34\x12\x00\x00"
    newop=""
    # newAscii=""
    try:
        j = 1
        for v in binary:
            i = ord2(v)
            newop += show1(i)
            if j % 4 == 0:
                newop += " "
            j += 1
        return newop
    except Exception as e:
        print ("*Not valid format")
        print(e)

def binaryToStr2(binary):
    # OP_SPECIAL = b"\x8d\x4c\xff\xe2\x01\xd8\x81\xc6\x34\x12\x00\x00"
    newop=""
    # newAscii=""
    try:
        j = 3
        addr = 0x45b5c290
        a = 0
        while j < len(binary):
            if a % 24 == 0 or a == 0:
                newop += '\n' + hex(addr + a) + ' '
            i = ord2(binary[j])
            newop += show1(i)
            if j % 4 == 0:
                newop += " "
                j += 8
            j -= 1
            a += 1

        newop = newop.replace('0x', '')
        return newop
    except Exception as e:
        print ("*Not valid format")
        print(e)

def setBit (val, pos, newBit):
    if newBit == 0:
        val &= ~(1 << pos)
    else:
        val |= 1 << pos
    return val

def getBit (value, pos):
    return ((value >> pos & 1) != 0)

def flipBit(val, pos):
    return val ^ (1 << pos)

def signedNegHexTo(signedVal):
    strSigned=str(signedVal)
    ba = binascii.a2b_hex(strSigned[2:])
    new = (int.from_bytes(ba, byteorder='big', signed=True))
    return new

def push(uc, arch, val):
    if arch == 64:
        # read and subtract 8 from esp
        esp = uc.reg_read(UC_X86_REG_RSP) - 8
        uc.reg_write(UC_X86_REG_ESP, esp)

        # insert new value onto the stack
        uc.mem_write(esp, pack("<Q", val))
    else:
        # read and subtract 4 from esp
        esp = uc.reg_read(UC_X86_REG_ESP) - 4
        uc.reg_write(UC_X86_REG_ESP, esp)

        # insert new value onto the stack
        uc.mem_write(esp, pack("<I", val))

def set_register(uc, reg, val):
    if reg == 'rax':
        uc.reg_write(UC_X86_REG_RAX, val)
    elif reg == 'rbx':
        uc.reg_write(UC_X86_REG_RBX, val)
    elif reg == 'rcx':
        uc.reg_write(UC_X86_REG_RCX, val)
    elif reg == 'rdx':
        uc.reg_write(UC_X86_REG_RDX, val)
    elif reg == 'rdi':
        uc.reg_write(UC_X86_REG_RDI, val)
    elif reg == 'rsi':
        uc.reg_write(UC_X86_REG_RSI, val)
    elif reg == 'r8':
        uc.reg_write(UC_X86_REG_R8, val)
    elif reg == 'r9':
        uc.reg_write(UC_X86_REG_R9, val)
    elif reg == 'r10':
        uc.reg_write(UC_X86_REG_R10, val)
    elif reg == 'r11':
        uc.reg_write(UC_X86_REG_R11, val)
    elif reg == 'r12':
        uc.reg_write(UC_X86_REG_R12, val)
    elif reg == 'r13':
        uc.reg_write(UC_X86_REG_R13, val)
    elif reg == 'r14':
        uc.reg_write(UC_X86_REG_R14, val)
    elif reg == 'r15':
        uc.reg_write(UC_X86_REG_R15, val)
    elif reg == 'rbp':
        uc.reg_write(UC_X86_REG_RBP, val)
    elif reg == 'rsp':
        uc.reg_write(UC_X86_REG_RSP, val)
    elif reg == 'eax':
        uc.reg_write(UC_X86_REG_EAX, val)
    elif reg == 'ebx':
        uc.reg_write(UC_X86_REG_EBX, val)
    elif reg == 'ecx':
        uc.reg_write(UC_X86_REG_ECX, val)
    elif reg == 'edx':
        uc.reg_write(UC_X86_REG_EDX, val)
    elif reg == 'edi':
        uc.reg_write(UC_X86_REG_EDI, val)
    elif reg == 'esi':
        uc.reg_write(UC_X86_REG_ESI, val)
    elif reg == 'ebp':
        uc.reg_write(UC_X86_REG_EBP, val)
    elif reg == 'esp':
        uc.reg_write(UC_X86_REG_ESP, val)

def constConvert(uc, string):
    if (string == 'rax'):
        return str(uc.reg_read(UC_X86_REG_RAX))
    elif (string == 'rbx'):
        return str(uc.reg_read(UC_X86_REG_RBX))
    elif (string == 'rcx'):
        return str(uc.reg_read(UC_X86_REG_RCX))
    elif (string == 'rdx'):
        return str(uc.reg_read(UC_X86_REG_RDX))
    elif (string == 'rsi'):
        return str(uc.reg_read(UC_X86_REG_RSI))
    elif (string == 'rdi'):
        return str(uc.reg_read(UC_X86_REG_RDI))
    elif (string == 'rsp'):
        return str(uc.reg_read(UC_X86_REG_RSP))
    elif (string == 'rbp'):
        return str(uc.reg_read(UC_X86_REG_RBP))
    elif (string == 'r8'):
        return str(uc.reg_read(UC_X86_REG_R8))
    elif (string == 'r9'):
        return str(uc.reg_read(UC_X86_REG_R9))
    elif (string == 'r10'):
        return str(uc.reg_read(UC_X86_REG_R10))
    elif (string == 'r11'):
        return str(uc.reg_read(UC_X86_REG_R11))
    elif (string == 'r12'):
        return str(uc.reg_read(UC_X86_REG_R12))
    elif (string == 'r13'):
        return str(uc.reg_read(UC_X86_REG_R13))
    elif (string == 'r14'):
        return str(uc.reg_read(UC_X86_REG_R14))
    elif (string == 'r15'):
        return str(uc.reg_read(UC_X86_REG_R15))

    elif (string == 'eax'):
        return str(uc.reg_read(UC_X86_REG_EAX))
    elif (string == 'ebx'):
        return str(uc.reg_read(UC_X86_REG_EBX))
    elif (string == 'ecx'):
        return str(uc.reg_read(UC_X86_REG_ECX))
    elif (string == 'edx'):
        return str(uc.reg_read(UC_X86_REG_EDX))
    elif (string == 'esi'):
        return str(uc.reg_read(UC_X86_REG_ESI))
    elif (string == 'edi'):
        return str(uc.reg_read(UC_X86_REG_EDI))
    elif (string == 'esp'):
        return str(uc.reg_read(UC_X86_REG_ESP))
    elif (string == 'ebp'):
        return str(uc.reg_read(UC_X86_REG_EBP))
    elif (string == 'r8d'):
        return str(uc.reg_read(UC_X86_REG_R8D))
    elif (string == 'r9d'):
        return str(uc.reg_read(UC_X86_REG_R9D))
    elif (string == 'r10d'):
        return str(uc.reg_read(UC_X86_REG_R10D))
    elif (string == 'r11d'):
        return str(uc.reg_read(UC_X86_REG_R11D))
    elif (string == 'r12d'):
        return str(uc.reg_read(UC_X86_REG_R12D))
    elif (string == 'r13d'):
        return str(uc.reg_read(UC_X86_REG_R13D))
    elif (string == 'r14d'):
        return str(uc.reg_read(UC_X86_REG_R14D))
    elif (string == 'r15d'):
        return str(uc.reg_read(UC_X86_REG_R15D))

    # Support smaller ebp and esp registers
    elif (string == 'ax'):
        return str(uc.reg_read(UC_X86_REG_AX))
    elif (string == 'bx'):
        return str(uc.reg_read(UC_X86_REG_BX))
    elif (string == 'cx'):
        return str(uc.reg_read(UC_X86_REG_CX))
    elif (string == 'dx'):
        return str(uc.reg_read(UC_X86_REG_DX))
    elif (string == 'si'):
        return str(uc.reg_read(UC_X86_REG_SI))
    elif (string == 'di'):
        return str(uc.reg_read(UC_X86_REG_DI))
    elif (string == 'al'):
        return str(uc.reg_read(UC_X86_REG_AL))
    elif (string == 'bl'):
        return str(uc.reg_read(UC_X86_REG_BL))
    elif (string == 'cl'):
        return str(uc.reg_read(UC_X86_REG_CL))
    elif (string == 'dl'):
        return str(uc.reg_read(UC_X86_REG_DL))
    elif (string == 'sil'):
        return str(uc.reg_read(UC_X86_REG_SIL))
    elif (string == 'dil'):
        return str(uc.reg_read(UC_X86_REG_DIL))

    # Supprt
    elif (string == 'ah'):
        return str(uc.reg_read(UC_X86_REG_AL))
    elif (string == 'bl'):
        return str(uc.reg_read(UC_X86_REG_BL))
    elif (string == 'cl'):
        return str(uc.reg_read(UC_X86_REG_CL))
    elif (string == 'dl'):
        return str(uc.reg_read(UC_X86_REG_DL))
    elif (string == 'sil'):
        return str(uc.reg_read(UC_X86_REG_SIL))
    elif (string == 'dil'):
        return str(uc.reg_read(UC_X86_REG_DIL))

def callback(match):
    return next(callback.v)

def getJmpFlag(mnemonic):
    if re.match("^(je)|(jz)|(jne)|(jnz)", mnemonic, re.M|re.I):
        return "zf"
    elif re.match("^(jg)|(jnle)|(jle)|(jng)", mnemonic, re.M|re.I):
        return "osz"
    elif re.match("^(jge)|(jnl)|(jl)|(jnge)", mnemonic, re.M|re.I):
        return "os"
    elif re.match("^(jae)|(jnb)|(jb)|(jnae)|(jc)|(jnc)", mnemonic, re.M|re.I):
        return "cf"
    elif re.match("^(jo)|(jno)", mnemonic, re.M|re.I):
        return "of"
    elif re.match("^(jp)|(jpe)|(jnp)|(jpo)", mnemonic, re.M|re.I):
        return "pf"
    elif re.match("^(js)|(jns)", mnemonic, re.M|re.I):
        return "sf"
    elif re.match("^(ja)|(jnbe)", mnemonic, re.M|re.I):
        return "cz"
    else:
        return ""


def controlFlow(uc, mnemonic, op_str):
    # print ("cf", mnemonic, op_str)
    controlFlow = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(jns)|(call)|(syscall))", mnemonic, re.M|re.I)

    which=0
    address = -1
    if controlFlow:
        ptr = re.match("d*word ptr \\[.*\\]", op_str)
        if ptr:
            expr = op_str.replace('dword ptr [', '')
            expr = expr.replace(']', '')

            # Support for 64 bit as well.
            # Come up with some more test cases to make sure this works
            regs = re.findall('([er][abcdsipx]+|r[8910234]+)', expr)
            for i in range(0, len(regs)):
                regs[i] = constConvert(uc, regs[i])

            callback.v=iter(regs)
            expr = re.sub('([er][abcdsipx]+|r[8910234]+)', callback, expr)

            address = eval(expr)
            # print ("address", hex(address))
            address = unpack("<I", uc.mem_read(address, 4))[0]
            which=1
        elif re.match('syscall', mnemonic): # 64bit Windows Syscall
            address = 0x5000
        elif re.match('dword ptr fs:\[0xc0]', op_str): # 32bit Windows Syscall
            address = 0x5000
        elif re.match('([er][abcdsipx]+|r[8910234]+)', op_str):
            regs = re.findall('([er][abcdsipx]+|r[8910234]+)', op_str)

            for i in range(0, len(regs)):
                regs[i] = constConvert(uc, regs[i])

            callback.v=iter(regs)
            address = int(re.sub('([er][abcdsipx]+|r[8910234]+)', callback, op_str))
            which=2
        elif re.match('0x[(0-9)|(a-f)]+', op_str):
            address = int(op_str, 16)
            which=3

    return address

def exitAPI(funcName):
    if funcName == "ExitProcess" or funcName == "TerminateProcess":
        return True
    else:
        return False

def retEnding(uc, mnemonic):
    esp = uc.reg_read(UC_X86_REG_ESP)
    retLoc = uc.mem_read(esp, 4)
    retLoc = unpack('<I', retLoc)[0]
    if mnemonic == 'ret' and retLoc == 0x1000:
        return True
    else:
        return False

def boolFollowJump(jmpFlag, jmpType, eflags):
    # ZF Flag
    if jmpFlag == "zf":
        zf = getBit(eflags, 6)
        if zf == 0:
            if jmpType == 'jne' or jmpType == 'jnz':
                return False
            else:
                return True
        else:
            if jmpType == 'jne' or jmpType == 'jnz':
                return True
            else:
                return False

    # OF, SF, and ZF Flags
    elif jmpFlag == "osz":
        zf = getBit(eflags, 6)
        sf = getBit(eflags, 7)
        of = getBit(eflags, 11)

        if zf == 0 and sf == of:
            if jmpType == 'jg' or jmpType == 'jnle':
                return False
            else:
                return True
        else:
            if jmpType == 'jg' or jmpType == 'jnle':
                return True
            else:
                return False

    # OF and SF Flags
    elif jmpFlag == "os":
        sf = getBit(eflags, 7)
        of = getBit(eflags, 11)

        if sf == of:
            if jmpType == 'jge' or jmpType == 'jnl':
                return False
            else:
                return True
        else:
            if jmpType == 'jge' or jmpType == 'jnl':
                return True
            else:
                return False

    # CF Flag
    elif jmpFlag == "cf":
        cf = getBit(eflags, 0)

        if cf == 0:
            if jmpType == 'jnb' or jmpType == 'jae' or jmpType == 'jnc':
                return False
            else:
                return True

        else:
            if jmpType == 'jb' or jmpType == 'jnae' or jmpType == 'jc':
                return True
            else:
                return False

    elif jmpFlag == "of":
        of = getBit(eflags, 11)

        if of == 0:
            if jmpType == 'jno':
                return False
            else:
                return True
        else:
            if jmpType == 'jno':
                return True
            else:
                return False

    elif jmpFlag == "pf":
        of = getBit(eflags, 2)

        if of == 0:
            if jmpType == 'jnp' or jmpType == 'jpo':
                return False
            else:
                return True
        else:
            if jmpType == 'jnp' or jmpType == 'jpo':
                return True
            else:
                return False

    elif jmpFlag == "sf":
        sf = getBit(eflags, 7)

        if sf == 0:
            if jmpType == 'jns':
                return False
            else:
                return True
        else:
            if jmpType == 'jns':
                return True
            else:
                return False

    elif jmpFlag == "cz":
        cf = getBit(eflags, 0)
        zf = getBit(eflags, 6)

        if cf == 0 and zf == 0:
            if jmpType == 'ja' and jmpType == 'jnbe':
                return False
            else:
                return True
        else:
            if jmpType == 'ja' and jmpType == 'jnbe':
                return True
            else:
                return False

def bprint(*args):
    brDebugging2=False
    if brDebugging2:
        try:
            if  (len(args) == 1):
                if(type(args[0]) == list):
                    print(args[0])
                    return

            if  (len(args) > 1):
                strList = ""
                for each in args:
                    try:
                        strList += each + " "
                    except:
                        strList += str(each) + " "
                print(strList)

            else:
                for each in args:
                    try:
                        print (str(each) + " ")
                    except:
                        print ("dprint error: 1")
                        print (each + " ")
        except Exception as e:
            print ("dprint error: 3")
            print (e)
            print (args)

def findRetVal(funcName, rs_dict):
    rsLookUp = {'S_OK': 0x00000000, 'STATUS_SUCCESS': 0x00000000, 'E_ABORT': 0x80004004, 'E_ACCESSDENIED': 0x80070005, 'E_FAIL': 0x80004005,
                'E_HANDLE': 0x80070006, 'E_INVALIDARG': 0x80070057, 'E_NOINTERFACE': 0x80004002,
                'E_NOTIMPL': 0x80004001, 'E_OUTOFMEMORY': 0x8007000E, 'E_POINTER': 0x80004003,
                'E_UNEXPECTED': 0x8000FFFF}
    retValStr=""

    if funcName in rs_dict:
        retValStr= rs_dict[funcName]
        if retValStr in rsLookUp:
            retVal=rsLookUp[retValStr]
            # print (retValStr)
            return retVal, retValStr
        else:
            test=isinstance(retValStr,int)
            if test:
                return retValStr, hex(retValStr)
            else:
                return 32, hex(32)
    else:
        return 32, hex(32)

def getRetVal(retVal, retType=""):
    rsReverseLookUp = {0x00000000: 'S_OK', 0x80004001: 'E_NOTIMPL', 0x80004002: 'E_NOINTERFACE',
                       0x80004003: 'E_POINTER', 0x80004004: 'E_ABORT', 0x80004005: 'E_FAIL', 0x8000FFFF: 'E_UNEXPECTED',
                       0x80070005: 'E_ACCESSDENIED', 0x80070006: 'E_HANDLE', 0x8007000E: 'E_OUTOFMEMORY',
                       0x80070057: 'E_INVALIDARG'}
    retBundle=""
    if retVal != "None":
        rIndex=retVal
        if rIndex in rsReverseLookUp:
            retBundle=rsReverseLookUp[rIndex]
        else:
            retBundle =  retVal
    else:
            retBundle =  retVal
    if retBundle=="None None":
        retBundle="None"
    return retBundle

def buildPtrString (pointer, val):
    return hex(pointer) + " -> " + hex(val)

def getPointerVal(uc, pointer):
    val = uc.mem_read(pointer, 4)
    return unpack('<I', val)[0]

def tryDictLocate(dictName, dll):
    dictName += '_'
    try:
        return globals()[dictName + dll]
    except:
        return {}