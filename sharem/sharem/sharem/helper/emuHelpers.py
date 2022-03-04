from unicorn.x86_const import *
from struct import pack, unpack
from unicorn import *
from ..DLLs.dict4_ALL import *
import re
import binascii
import pefile
import os
import sys

PEB_ADDR = 0x11017000

def read_unicode(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 0

    while c != 0x0:
        c = uc.mem_read(address + read_bytes, 1)[0]
        ret += chr(c)
        read_bytes += 2

    ret = ret.rstrip('\x00')
    return ret

def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret

def giveRegs(uc):
    EAX = uc.reg_read(UC_X86_REG_EAX)   # do not delete!
    EBX = uc.reg_read(UC_X86_REG_EBX)
    ECX = uc.reg_read(UC_X86_REG_ECX)
    EDX = uc.reg_read(UC_X86_REG_EDX)
    ESI = uc.reg_read(UC_X86_REG_ESI)
    EDI = uc.reg_read(UC_X86_REG_EDI)
    ESP = uc.reg_read(UC_X86_REG_ESP)
    EBP = uc.reg_read(UC_X86_REG_EBP)
    instructLine=("\n\t>>> EAX: 0x%x\tEBX: 0x%x\tECX: 0x%x\tEDX: 0x%x\tEDI: 0x%x\tESI: 0x%x\tEBP: 0x%x\tESP: 0x%x\n" %(EAX, EBX, ECX, EDX, EDI,ESI, EBP, ESP))
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

def readRaw(appName):
    f = open(appName, "rb")
    myBinary = f.read()
    f.close()
    return myBinary

def insertIntoBytes(binaryBlob, start, size, value):
    lBinary = list(binaryBlob)
    for x in range (size):
        lBinary.insert(start, value)
    final=bytes(lBinary)
    return final

def padDLL(dllPath, dllName, expandedDLLsPath):
    pe = pefile.PE(dllPath)

    virtualAddress = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
    i = 0
    padding = 0
    while True:
        try:
            section = pe.sections[i]

            pointerToRaw = section.PointerToRawData
            sectionVA = section.VirtualAddress
            sizeOfRawData = section.SizeOfRawData

            if (virtualAddress >= sectionVA and virtualAddress < (sectionVA + sizeOfRawData)):
                padding = virtualAddress - (virtualAddress - sectionVA + pointerToRaw)
                break
        except:
            break

        i += 1


    # Replace e_lfanew value
    elfanew = pe.DOS_HEADER.e_lfanew
    pe.DOS_HEADER.e_lfanew = elfanew + padding

    tmpPath = expandedDLLsPath + dllName
    # print("-->", os.getcwd())
    pe.write(tmpPath)

    # Add padding to dll, then save it.
    out = readRaw(tmpPath)
    final = insertIntoBytes(out, 0x40, padding, 0x00)
    newBin = open(tmpPath, "wb")
    newBin.write(final)
    newBin.close()

    rawDll = readRaw(tmpPath)

    return rawDll

def saveDLLsToFile(export_dict, foundDLLAddresses):       # help function called by loadDLLs
    output=""
    for address in export_dict:
        apiName=export_dict[address][0]
        dllName=export_dict[address][1]

        output+=str(hex(address)) +", " + apiName+ ", "  + dllName + "\n"

    with open(foundDLLAddresses, 'a') as out:
        out.write(output)
        out.close()

def push(uc, val):
    # read and subtract 4 from esp
    esp = uc.reg_read(UC_X86_REG_ESP) - 4
    uc.reg_write(UC_X86_REG_ESP, esp)

    # insert new value onto the stack
    uc.mem_write(esp, pack("<i", val))

def constConvert(uc, string):
    if (string == 'eax'):
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
    controlFlow = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(jns)|(call))", mnemonic, re.M|re.I)


    which=0
    address = -1
    if controlFlow:
        ptr = re.match("d*word ptr \\[.*\\]", op_str)
        if ptr:
            expr = op_str.replace('dword ptr [', '')
            expr = expr.replace(']', '')

            # Support for 64 bit as well.
            # Come up with some more test cases to make sure this works
            regs = re.findall('e[abcdsipx]+', expr)
            for i in range(0, len(regs)):
                regs[i] = constConvert(uc, regs[i])

            callback.v=iter(regs)
            expr = re.sub('e[abcdsipx]+', callback, expr)

            address = eval(expr)
            # print ("address", hex(address))
            address = unpack("<I", uc.mem_read(address, 4))[0]
            which=1
        elif re.match('e[abcdsipx]+', op_str):
            regs = re.findall('e[abcdsipx]+', op_str)
            for i in range(0, len(regs)):
                regs[i] = constConvert(uc, regs[i])

            callback.v=iter(regs)
            address = int(re.sub('e[abcdsipx]+', callback, op_str))
            which=2
        elif re.match('0x[(0-9)|(a-f)]+', op_str):
            address = int(op_str, 16)
            which=3

    if str(hex(address))=="0x44370b7b":
        print (mnemonic, op_str, which)

    return address



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
            print(traceback.format_exc())
            print (args)

def findRetVal(funcName, dll):
    bprint ("findRetVal - funcName", dll)
    rsLookUp = {'S_OK': 0x00000000, 'E_ABORT': 0x80004004, 'E_ACCESSDENIED': 0x80070005, 'E_FAIL': 0x80004005,
                'E_HANDLE': 0x80070006, 'E_INVALIDARG': 0x80070057, 'E_NOINTERFACE': 0x80004002,
                'E_NOTIMPL': 0x80004001, 'E_OUTOFMEMORY': 0x8007000E, 'E_POINTER': 0x80004003,
                'E_UNEXPECTED': 0x8000FFFF}
    retValStr=""
    dictR1 = globals()['dictRS_'+dll]
    if funcName in dictR1:
        retValStr= dictR1[funcName]
        if retValStr in rsLookUp:
            retVal=rsLookUp[retValStr]
            return retVal
        else:
            test=isinstance(retValStr,int)
            if test:
                return retValStr
            else:
                return 32
    else:
        return 32

def getRetVal2(retVal, retType=""):
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