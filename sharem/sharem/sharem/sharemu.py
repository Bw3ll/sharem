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
from .helper.emuHelpers import *
import sys
import json
import pefile
import re
import os
import argparse
import colorama
import binascii
import traceback
# artifacts2= [] 
# net_artifacts = []
# file_artifacts = []
# exec_artifacts = []

class EMU():
    def __init__(self):
        self.maxCounter=500000
        self.maxLoop = 500000
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
MAX_LOOP = 5000000


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
    if funcName == 'ExitProcess':
        stopProcess = True
    if 'LoadLibrary' in funcName and uc.reg_read(UC_X86_REG_EAX) == 0:
        print("\t[*] LoadLibrary failed. Emulation ceasing.")
        stopProcess = True

    uc.reg_write(UC_X86_REG_EIP, EXTRA_ADDR)

    return ret

def hook_code(uc, address, size, user_data):
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
    if stopProcess == True:
        uc.emu_stop()

    # Make sure current address is in proper range
    # if address < 0x12000000 or address > 0x18000000:
    #     uc.emu_stop()

    programCounter += 1
    if programCounter > em.maxCounter:
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
    for i in cs.disasm(shells, base):
        val = i.mnemonic + " " + i.op_str # + " " + shells.hex()
        if t==0:
            mnemonic=i.mnemonic
            op_str=i.op_str

        if verbose:
            shells = uc.mem_read(base, size)
            instructLine += val + '\n'
            print(instructLine)
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

    if address == 0:
        hook_sysCall(uc, address)

    if address == 0x1000:
        stopProcess = True

    if cleanStackFlag == True:
        cleanStack(uc, cleanBytes)
        cleanStackFlag = False

    # If parameters were used in the function, we need to clean the stack
    if ret == EXTRA_ADDR:
        cleanStackFlag = True

def hook_syscallDefault(uc, eip, esp, funcAddress, funcName, callLoc):
    try:
        apiDict = dict_kernel32[funcName]

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

def hook_sysCall(uc, address):
    global logged_dlls
    global stopProcess

    syscallID = uc.reg_read(UC_X86_REG_EAX)
    sysCallName = syscall_dict[em.winVersion][em.winSP][str(syscallID)]
    exportAddress = 0
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)

    try:
        funcInfo, cleanBytes = globals()['hook_' + sysCallName](uc, eip, esp, address)
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
        dict4 = globals()['dict4_' + dll]
        dict2 = globals()['dict2_' + dll]
        dict1 = globals()['dict_' + dll]

        bprint ("dll", dll)
        # Log usage of DLL
        if dll not in logged_dlls:
            logged_dlls.append(dll)

        # Use dict three if we find a record for it
        if funcName in dict3_w32:
            # print ("1")
            return dict3_w32[funcName], 'dict3', dll

        # Use dict2 if we can't find the API in dict1
        elif funcName in dict2:
            # print ("2")  
            # print (dict2[funcName])
            return dict2[funcName], 'dict2', dll

        # Use dict four (WINE) if we find a record for it
        elif funcName in dict4:
            # print ("3")

            return dict4[funcName], 'dict4', dll

        # If all else fails, use dict 1
        elif funcName in dict1:
            # print ("4")

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

            # Check if the type is a string
            if "STR" in apiDict[1][i]:
                try:
                    paramVals[i] = read_string(uc, paramVals[i])
                except:
                    pass
            else:
                paramVals[i] = hex(paramVals[i])

        # Go through all parameters, and see if they can be interpreted as a string
        for i in range (0, len(paramVals)):
            if "STR" not in apiDict[1][i]:
                p = int(paramVals[i], 16)
                if (0x40000000 < p and p < 0x50010000):
                    string = read_string(uc, p)
                    if len(string) < 30:
                        paramVals[i] = string

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

        retVal=findRetVal(funcName, dll)
        bprint ("returnVal", funcName, retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        retValStr=getRetVal2(retVal)
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

    code = b"\x6A\x00\x6A\xFF\xB8\x29\x00\x00\x00\x31\xC9\x8D\x14\x24\x64\xFF\x15\xC0\x00\x00\x00"

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
        mu.emu_start(CODE_ADDR + em.entryOffset, CODE_ADDR + len(code))
    except Exception as e:
        print("\t",e)

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

    if arch == 32:
        test_i386(UC_MODE_32, data)

em=EMU()