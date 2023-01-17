#!/usr/bin/env python

from __future__ import print_function
from sharem.sharem.helper.variable import Variables
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from struct import pack, unpack
from collections import defaultdict
from .modules import *
from .DLLs.dict_signatures import *
from .DLLs.dict2_signatures import *
from .DLLs.dict3_w32 import *
from .DLLs.dict4_ALL import *
from .DLLs.hookAPIs import *
from .DLLs.syscall_signatures import *
from .helper.emuHelpers import *
from .helper.sharemuDeob import *
from .sharem_debugger import *
from .DLLs.emu_helpers.sharem_artifacts import Artifacts_regex
#from .sharem_artifacts import *

import json
import re
import os
import colorama
import traceback

finalAddress=0
# from sharemuDeob import *

# class EMU():
#     def __init__(self):
#         self.maxCounter = 500000
#         self.arch = 32
#         self.debug = False
#         self.breakOutOfLoops = True
#         self.maxLoop = 50000  # to break out of loops
#         self.entryOffset = 0
#         self.codeCoverage = True
#         self.beginCoverage = False
#         self.timelessDebugging = False  # todo: bramwell
#         # self.winVersion = "Windows 7" # "Windows 10" ## Should make these value config.
#         # self.winSP = "SP1" # "2004"
#         self.winVersion = "Windows 10"
#         self.winSP = "2004"

class EMU():        #### see EMU note below  
    def __init__(self):
        self.maxCounter = 500000
        self.arch = 32
        self.debug = False
        self.breakOutOfLoops = True
        self.maxLoop = 50000  # to break out of loops
        self.entryOffset = 0
        self.codeCoverage = True
        self.beginCoverage = False
        self.timelessDebugging = False  # todo: bramwell
        self.timeless_debugging_stack = False
        self.winVersion = "Windows 10"
        self.winSP = "2004"
        ############### NOTE: This is not the class any more - the actual EMU class is now in helper/emu.py - this is left here as a placeholder for anyone that needs to add or modify this and is confused.




class Coverage():
    def __init__(self, uc, address):
        # print (cya+"creating Coverage object - coverage number " + res2, coverage_num)
        self.address = address
        if em.arch == 32:
            self.regs = {'eax': 0x0, 'ebx': 0x0, 'ecx': 0x0, 'edx': 0x0, 'edi': 0x0, 'esi': 0x0, 'esp': 0x0, 'ebp': 0x0, 'eflags': 0x0}
        else:
            self.regs = {'rax': 0x0, 'rbx': 0x0, 'rcx': 0x0, 'rdx': 0x0, 'rdi': 0x0, 'rsi': 0x0, 'r8': 0x0, 'r9': 0x0, 'r10': 0x0, 'r11': 0x0, 'r12': 0x0, 'r13': 0x0, 'r14': 0x0, 'r15': 0x0, 'rsp': 0x0, 'rbp': 0x0, 'eflags': 0x0}
        self.stack = b''
        self.ebpStack=b''
        self.inProgress = False
        self.coverage_num=coverage_num

        # Save registers into dict
        for reg, val in self.regs.items():
            self.regs[reg] = int(constConvert(uc, reg))
        
        # Save memory
        # self.mem_file = 'coverage_mem_tmp' + str(coverage_num) + '.bin' # Old Jacob way - no longer needed - we use one memory now
        # with open (self.mem_file, 'wb') as f:
        #     f.write(uc.mem_read(0x10000000, 0x10050000))

        # Save memory
        if em.writeToTempFile:
            print ("writeToTempFile 1")
            with open ('coverage_mem_tmp.bin', 'wb') as f:
                f.write(uc.mem_read(0x10000000, 0x10050000))

        # Save stack bytes
        esp = uc.reg_read(UC_X86_REG_ESP)
        ebp = uc.reg_read(UC_X86_REG_EBP)
        amt=em.codeCoverageStackAmt
        if em.arch == 32:
            esp = self.regs['esp']
            ebp = self.regs['ebp']
            stack_bytes_len = ebp - esp
            if stack_bytes_len < 0:
                stack_bytes_len = STACK_ADDR - esp
            # print ("stack_bytes_len", stack_bytes_len, "esp", hex(esp), "ebp", hex(ebp))

            
            try:
                # print ("new_stack", hex(esp -amt), hex(esp+amt*2), "ebp", hex(esp -amt), hex(esp+amt*2))
                self.stack = bytes(uc.mem_read(esp-amt, amt*2))
                # print (binaryToStr(self.stack))
            except:
                if em.showCCDebugInfo:
                    print (red+"\t[*] "+whi+ "Code coverage: Could not capture memory pointed to by esp - memory not valid: "+res2, hex(esp))
            try:
                # print ("new_stack_ebp", hex(esp -amt), hex(esp+amt*2), "ebp", hex(esp -amt), hex(esp+amt*2))
                self.ebpStack = bytes(uc.mem_read(ebp-amt, amt*2))
                # print ("stack size", len(self.ebpStack))
            except:
                if em.showCCDebugInfo:
                    print (red+"\t[*] "+whi+ "Code coverage: Could not capture memory pointed to by ebp - memory not valid: "+res2, hex(ebp))
        if em.arch == 64:
            rsp = self.regs['rsp']
            rbp = self.regs['rbp']
            try:
                self.stack = bytes(uc.mem_read(rsp-amt, amt*2))
                # print (binaryToStr(self.stack))
            except:
                if em.showCCDebugInfo:
                    print (red+"\t[*] "+whi+ "Code coverage: Could not capture memory pointed to by rsp - memory not valid: "+res2, hex(rsp))
            try:
                self.ebpStack = bytes(uc.mem_read(rbp-amt, amt*2))
                # print ("stack size", len(self.ebpStack))
            except:
                if em.showCCDebugInfo:
                    print (red+"\t[*] "+whi+ "Code coverage: Could not capture memory pointed to by rbp - memory not valid: "+res2, hex(rbp))

        # else:
        #     rsp = self.regs['rsp']
        #     rbp = self.regs['rbp']
        #     stack_bytes_len = rbp - rsp
        #     if stack_bytes_len < 0:
        #         stack_bytes_len = STACK_ADDR - rsp
        #     self.stack = bytes(uc.mem_read(rsp, stack_bytes_len))
        coverageAdds.add(address)

    def dump_saved_info(self, uc):
        # Dump registers
        for reg, val in self.regs.items():
            set_register(uc, reg, val)

        # Restore the memory
        # with open(self.mem_file, 'rb') as f:  ## old Jacob way of doing it
        if em.writeToTempFile:
            print ("writeToTempFile 2")
            with open("coverage_mem_tmp.bin", 'rb') as f:
                uc.mem_write(0x10000000, f.read())

        # self.print_saved_info()

        # Restore the stack
        amt =  em.codeCoverageStackAmt
        if em.arch == 32:
            stackStart=self.regs['esp']-amt
            stackStartEBP=self.regs['ebp']-amt
            try:
                uc.mem_write(stackStart, self.stack)
            except:
                 print ("\tComplete code coverage: restoring memory pointed to by esp,", hex(self.regs['esp']), ", failed for coverage object", self.coverage_num, ".")
            try:
                uc.mem_write(stackStartEBP, self.ebpStack)
            except:
                 print ("\tComplete code coverage: restoring memory pointed to by ebp,", hex(self.regs['ebp']), ", failed for coverage object", self.coverage_num, ". This may be correct behavior.")
        else:
            stackStart=self.regs['rsp']-amt
            stackStartEBP=self.regs['rbp']-amt
            try:
                uc.mem_write(stackStart, self.stack)
            except:
                 print ("\tComplete code coverage: restoring memory pointed to by rsp,", hex(self.regs['rsp']), ", failed for coverage object", self.coverage_num, ".")
            try:
                uc.mem_write(stackStartEBP, self.ebpStack)
            except:
                 print ("\tComplete code coverage: restoring memory pointed to by rbp,", hex(self.regs['rbp']), ", failed for coverage object", self.coverage_num, ". This may be correct behavior.")

    def print_saved_info(self):
        print(f"Address: {hex(self.address)}")
        for reg, val in self.regs.items():
            print(f"{reg}: {hex(val)}")
        print(f"Stack = {binaryToStr(self.stack)}")

    def delete(self, index):
        if em.showCCDebugInfo:
            print (yel+"\t[*] Deleting code coverage object:" + res2, coverage_objects[index].coverage_num, gre+ "   Address:", whi+hex(coverage_objects[index].address))
        # os.remove(self.mem_file) # old Jacob way - not needed any longer - we use one memory file now
        if verbose:
                # outFile.write("\nDeleting code coverage object - index value: "  +str(coverage_objects[index].coverage_num) + "   Address:" +hex(coverage_objects[index].address) +"\n")
                pass

        del coverage_objects[index]
    def giveAddress(self,address):
        print (cya+"Coverage - adding address", hex(address), "num"+res2, self.coverage_num)
        self.address=address
        coverageAdds.add(address)
        

# artifacts = []
# net_artifacts = []
# file_artifacts = []
# exec_artifacts = []
coverage_objects = []
covObjs =  {}
programCounter = 0
verbose = True
WinAPI = CustomWinAPIs()
WinSysCall = CustomWinSysCalls()

CODE_ADDR = 0x12000000
ENTRY_ADDR = 0x1000
STACK_ADDR = 0x17000000
EXTRA_ADDR = 0x18000000
MOD_LOW = 0x14100000
MOD_HIGH = 0x14100000
codeLen = 0
with open(os.path.join(os.path.dirname(__file__), 'WinSysCalls.json'), 'r') as syscall_file:
    syscall_dict = json.load(syscall_file)

with open(os.path.join(os.path.dirname(__file__), 'skipAddressesCCC.json'), 'r') as jsonCCC:
    skipJmpCCC = json.load(jsonCCC)

export_dict = {}
loggedList = []
logged_syscalls = []
logged_dlls = []
paramValues = []
network_activity = {}
jmpInstructs = {}
address_range = []

traversedAdds = set()
coverageAdds = set()
skipForCoverage=set()
coverage_num = 1
loadModsFromFile = True
foundDLLAddresses32 = os.path.join(os.path.dirname(__file__), "foundDLLAddresses32.json")
foundDLLAddresses64 = os.path.join(os.path.dirname(__file__), "foundDLLAddresses64.json")
outFile = open(os.path.join(os.path.dirname(__file__), 'emulationLog.txt'), 'w')
stackFile = open(os.path.join(os.path.dirname(__file__), 'stackLog.txt'), 'w')
cleanStackFlag = False
stopProcess = False
stopProcessCC = False
cleanBytes = 0
bad_instruct_count = 0

if platformType == "Windows":
    expandedDLLsPath32 = os.path.join(os.path.dirname(__file__), "DLLs\\x86\\")
    expandedDLLsPath64 = os.path.join(os.path.dirname(__file__), "DLLs\\x64\\")
else:
    expandedDLLsPath32 = os.path.join(os.path.dirname(__file__), "DLLs/x86/")
    expandedDLLsPath64 = os.path.join(os.path.dirname(__file__), "DLLs/x64/")

bVerbose = True

colorama.init()

red = '\u001b[31;1m'
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
    global MOD_HIGH

    # Set 32 bit variables
    if em.arch == 32:
        foundDLLAddrs = foundDLLAddresses32
        source_path = 'C:\\Windows\\SysWOW64\\'
        save_path = expandedDLLsPath32

    # Set 64 bit variables
    else:
        print ("set 64 bit variables")
        foundDLLAddrs = foundDLLAddresses64
        source_path = 'C:\\Windows\\System32\\'
        save_path = expandedDLLsPath64

    mods, export_dict, MOD_HIGH = initMods(mu, em, export_dict, source_path, save_path)

    if len(export_dict) > 0:
        saveDLLAddsToFile(foundDLLAddrs, export_dict)

    export_dict = readDLLsAddsFromFile(foundDLLAddrs, export_dict)

    return mods


def coverage_branch(uc):
    # this function is deprecated per Jacob
    global coverage_objects

    if len(coverage_objects) > 0:
        uc.reg_write(UC_X86_REG_EIP, coverage_objects[0].address)
        coverage_objects[0].delete(0)
    else:
        uc.emu_stop()

def calculateAddressesSkipCCC():
    if em.excludeJmpCallCoverage:
        for address in skipJmpCCC:
            lim=skipJmpCCC[address]
            address = int(address,16)
            for x in range(lim):
                skipForCoverage.add(address)
                address=address+1

def breakLoop(uc, jmpFlag, jmpType, op_str, addr, size):
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    # print ("eflags", eflags)
    jmpLoc=0
    # print ("breakLoop", hex(addr), op_str)
    if boolFollowJump(jmpFlag, jmpType, eflags):
        if "0x12" in op_str:
            try:
                jmpLoc=int(op_str,16)
            except:
                jmpLoc=int(op_str)

        else:
            if "0x" in op_str:
                jmpLoc = addr + signedNegHexTo(op_str)
                print ("jmpLoc", hex(jmpLoc))
            else:
                try:
                    jmpLoc = addr + int(op_str)
                except:
                    jmpLoc = addr + int(op_str,16)

        uc.reg_write(UC_X86_REG_EIP, jmpLoc)
        # print (yel+"writes1"+res2 + " to "  + gre + hex(jmpLoc) + res2)
    else:
        uc.reg_write(UC_X86_REG_EIP, addr + size)
        jmpLoc= addr + size
        # print (red+"writes2"+res2 + " to "  + gre + hex(jmpLoc) + res2)
        

    print (cya+"\t[*] " + res2 +  "Breaking out of a loop at " + gre +  hex(addr) + res2 + " - going to " + red + hex(jmpLoc) + res2 +  ".")
    if verbose:
        outFile.write("***** Breaking out of a loop at " + hex(addr) + " - going to " + hex(jmpLoc) + ".\n")

def catch_windows_api(uc, addr, ret, size, funcAddress):
    global stopProcess
    global cleanBytes

    # print ("catch_windows_api funcAddress", funcAddress, "Ret", hex(ret), "size", size)

    ret += size
    push(uc, em.arch, ret)
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)

    try:
        funcName = export_dict[funcAddress][0]
        dll = export_dict[funcAddress][1]
        dll = dll[0:-4]

        # Log usage of DLL
        dllL=dll.lower()
        foundAlready=False
        for each in logged_dlls:
            if dll == each or dllL == each.lower():
                foundAlready=True
        if not foundAlready:
            logged_dlls.append(dll)


    except Exception as e:
        funcName = "funcname: DID NOT FIND address - " + funcAddress
        print ("finding funcname")
        print(traceback.format_exc())

    try:
        funcInfo, cleanBytes = getattr(WinAPI, funcName)(uc, eip, esp, export_dict, addr, em)
        logCall(funcName, funcInfo)
        # print ("funcName", funcName)
    except:
        try:
            bprint("hook_default", funcAddress)
            hook_default(uc, eip, esp, funcAddress, export_dict[funcAddress][0], addr)
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            print("\n\tHook failed at " + str(funcAddress) + ".")

    fRaw.add(int(funcAddress, 16), funcName)
    if exitAPI(funcName):
        stopProcess = True
        # print ("Stop: exitAPI, catch_windows_api")

    uc.reg_write(UC_X86_REG_EIP, EXTRA_ADDR)

    return ret


bAddRead=set()
bAddReadTwice=set()
bAddReadTwiceTuple=set()
bAddReadThrice=set()
bAddReadThriceTuple=set()

bAddWrite=set()

bAddReadTuple=set()
bAddWriteTuple=set()
bAddWriteTwiceTuple=set()
bAddWriteTwice=set()
bAddWriteThriceTuple=set()
bAddWriteThrice=set()

bReadListTuple=[]
bWriteListTuple=[]



def hook_mem_access2(uc, address, size, user_data):
    global stackFile
    stackFile.write( "[ mem_access2: bad " + hex(address) +"] ")
    # print( "[ mem_access2: bad " + hex(address) +"] ")


def hook_mem_access3(uc, access, address, size, value=0, user_data=None):
    # print ("access", access, "address", hex(address), "size", size)

    global stackFile
    stackFile.write( "[ mem_access2: bad " + hex(address) +"] ")


def hook_mem_access(uc, access, address, size, value, user_data):
    # print ("hook mem access!!!!!!!!!!!!!")
    if access == UC_MEM_WRITE:
        # print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
        #         %(address, size, value))
        if address > 0x12000000 and address <0x12990070:

            if address in bAddWrite:
                bAddWriteTwice.add(address)
                bAddWriteTwiceTuple.add((address, size))
            elif address in bAddWriteTwice:
                # print (red+"doing thrice1!!!!!"+res)
                bAddWriteThriceTuple.add(address)
                bAddWriteThrice.address((address, size))
            else:
                bAddWriteTuple.add((address, size))
                bAddWrite.add(address)


# CODE_ADDR = 0x12000000
# ENTRY_ADDR = 0x1000
# STACK_ADDR = 0x17000000
# EXTRA_ADDR = 0x18000000
# MOD_LOW = 0x14100000
# MOD_HIGH = 0x14100000

        if address < MOD_LOW or address > MOD_HIGH  and (address < STACK_ADDR-0x5000  or address > STACK_ADDR +0x5000 ) and address != ENTRY_ADDR and address != EXTRA_ADDR:
            bWriteListTuple.append((hex(address),size))

        
    else:   # READ
        # print(">>> Memory is being READ at 0x%x, data size = %u" \
                # %(address, size))
        if address > 0x12000000 and address <0x12990070:

            if address in bAddRead:
                bAddReadTwice.add(address)
                bAddReadTwiceTuple.add((address, size))
            elif address in bAddReadTwice:
                # print (red+"doing thrice!!!!!"+res)
                bAddReadThriceTuple.add(address)
                bAddReadThrice.address((address, size))
            else:
                bAddRead.add(address)
                bAddReadTuple.add((address, size))
        if address < MOD_LOW or address > MOD_HIGH  and (address < STACK_ADDR-0x5000  or address > STACK_ADDR +0x5000 ) and address != ENTRY_ADDR and address != EXTRA_ADDR:
            bReadListTuple.append((hex(address),size))

def hook_code(uc, address, size, user_data):
    global cleanBytes, verbose
    global outFile
    global stackFile
    global programCounter
    global cleanStackFlag
    global stopProcess
    global stopProcessCC
    global traversedAdds
    global coverage_objects
    global em
    global bad_instruct_count
    global coverage_num
    global finalAddress

    finalAddress=address

    funcName = ""

    if cleanStackFlag == True:
        cleanStack(uc, cleanBytes)
        cleanStackFlag = False

    addressF = address
    if stopProcess == True or stopProcessCC == True:
        uc.emu_stop()
        if em.showCCDebugInfo:
            print (red+"\t[!] Forced stop"+res)

    programCounter += 1
    if programCounter > em.maxCounter and em.maxCounter > 0:
        print(red + "\t[*] " +res2+" Exiting emulation because max counter of "  +gre +  str(em.maxCounter) + res2 + " reached.\n")
        uc.emu_stop()

    instructLine = ""
    timelessStack= ""
    if verbose:
        instructLine += giveRegs(uc, em.arch)
        instructLine += str(programCounter) + ": 0x%x" % address + "\t"
        # timelessStack+=giveStackClass(uc, em.arch,programCounter)
    if em.timeless_debugging_stack:
        timelessStack+=giveStack(uc, em.arch)
        timelessStack += str(programCounter) + ": 0x%x" % address + "\t"
        stackFile.write(timelessStack )

    shells = b''
    try:
        shells = uc.mem_read(address, size)
    except Exception as e:
        # print ("Error: ", e)
        # print(traceback.format_exc())
        instructLine += " size: 0x%x" % size + '\t'  # size is overflow - why so big?
        outFile.write("abrupt end:  " + instructLine)
        print("abrupt end: error reading line of shellcode")
        stopProcess = True
        # return # terminate func early   --don't comment - we want to see the earlyrror
        
    ret = address
    base = 0
    # Print out the instruction
    mnemonic = ""
    op_str = ""
    t = 0
    bad_instruct = False

    fRaw.addBytes(shells, addressF - CODE_ADDR, size)
    finalOut = uc.mem_read(CODE_ADDR + em.entryOffset, codeLen)
    fRaw.giveEnd(finalOut)

    if shells == b'\x00\x00':
        bad_instruct_count += 1
        if bad_instruct_count > 5:
            bad_instruct = True

    valInstruction=""
    for i in cs.disasm(shells, address):
        valInstruction = i.mnemonic + " " + i.op_str  # + " " + shells.hex()
        instructLine += valInstruction + '\n'
        # shells = uc.mem_read(base, size)
        # Debugger Test
        if em.debug:
            em = debugger(uc, em)
        if verbose:
            outFile.write(instructLine)
        if em.timeless_debugging_stack:
            stackFile.write("  "+valInstruction)
            # giveStackClass(uc, em.arch,programCounter,val)
        if t == 0:
            mnemonic = i.mnemonic
            op_str = i.op_str
            # print ("mnemonic op_str", mnemonic, op_str)
            break
        t += 1

    # Jump to code coverage branch if shellcode is already done
    # if em.beginCoverage == True and em.codeCoverage == True:
    #     coverage_branch(uc, address, mnemonic, bad_instruct)

    jumpAddr = controlFlow(uc, mnemonic, op_str)

    if (jumpAddr < CODE_ADDR or jumpAddr > MOD_HIGH) and jumpAddr != -1:
        for add in address_range:
            rangeLow = add[0]
            rangeHigh = add[1]
            if jumpAddr < rangeLow or jumpAddr > rangeHigh:
                # print("************************** WE DIPPING EARLY *****************************")
                uc.emu_stop()

    # If jmp instruction, increment jmp counter to track for infinite loop and track in code coverage
    jmpFlag = getJmpFlag(mnemonic)
    if jmpFlag != "":
        if address not in jmpInstructs:
            jmpInstructs[address] = 1
        else:
            jmpInstructs[address] += 1

        if jmpInstructs[address] >= em.maxLoop and em.breakOutOfLoops:
            breakLoop(uc, jmpFlag, mnemonic, op_str, address, len(shells))
            jmpInstructs[address] = 0

        # track for code coverage
        if address not in traversedAdds and em.codeCoverage == True:
            # cvg = Coverage(uc, address)
            # coverage_num += 1
            # coverage_objects.append(cvg)
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            # cvg.giveAddress(jumpAddr)
            # cvg.giveAddress(address + size)

            # if boolFollowJump(jmpFlag, mnemonic, eflags):
            #     print ("boolFollowJump true - adding:", hex(jumpAddr))
            #     cvg.giveAddress(jumpAddr)
            # else:
            #     cvg.giveAddress(address + size)
            #     print ("boolFollowJump false - adding:", hex(address + size))

            if jumpAddr not in coverageAdds:
                cvg1 = Coverage(uc, jumpAddr)
                coverage_num += 1
                coverage_objects.append(cvg1)
                if em.showCCDebugInfo:
                    print (cya+"\t[*] "+cya+ "Creating code coverage object:" +res2, cvg1.coverage_num, gre+"   Address:"+res2, hex(jumpAddr))
            if address + size not in coverageAdds:
                cvg2 = Coverage(uc, address + size)
                coverage_num += 1
                coverage_objects.append(cvg2)
                if em.showCCDebugInfo:
                    print (cya+"\t[*] "+cya+ "Creating code coverage object:" +res2, cvg2.coverage_num, gre+"   Address:"+res2, hex(address + size), )
    elif "call" in mnemonic and em.includeCallInCC and em.codeCoverage:    # we are adding CALL as well.
        if address + size not in coverageAdds and address + size not in skipForCoverage:
            cvg2 = Coverage(uc, address + size)
            coverage_num += 1
            coverage_objects.append(cvg2)
            if em.showCCDebugInfo:
                print (yel+"\t[*] "+cya+ "Code Coverage CALL - adding address"+res2, hex(address + size), cya+"- coverage object:"+res2, cvg2.coverage_num)
    elif "jmp" in mnemonic and em.codeCoverage and em.includeJmpInCC:    # we are adding CALL as well.
        if address + size not in coverageAdds and address + size not in skipForCoverage:
            if address + size == 0x12000005:
                print ("12..5")
            cvg2 = Coverage(uc, address + size)
            coverage_num += 1
            coverage_objects.append(cvg2)
            if em.showCCDebugInfo:
                print (yel+"\t[*] "+cya+ "Code Coverage JMP - adding address"+res2, hex(address + size), cya+"- coverage object:"+res2, cvg2.coverage_num)

    # Track addresses we've already visited
    if em.codeCoverage:
        if em.restartCCInProgress:
            if address in traversedAdds and address != EXTRA_ADDR:
                # print ("\tInstruction already traversed:", valInstruction)
                if em.showCCDebugInfo:
                    if stopProcessCC:
                        print(red+"\t[*]"+res+" Complete code coverage: already traversed " + hex(address) + red+ " -  stopping."+res2)
                    elif em.StopExecutingAfterTraversed:
                        print(red+"\t[*]"+res+" Complete code coverage: already traversed " + hex(address) + red+ " -  stopping after next instruction."+res2)

                if verbose:
                    if stopProcessCC:
                        outFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " -  stopping.\n")
                    elif em.StopExecutingAfterTraversed:
                        outFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " -  stopping after next instruction.\n")

                if em.timeless_debugging_stack:
                    if stopProcessCC:
                        stackFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " - stopping.\n")
                    elif em.StopExecutingAfterTraversed:
                        stackFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " - stopping after next instruction.\n")
                if em.StopExecutingAfterTraversed:
                    stopProcessCC = True
        traversedAdds.add(address)
        if address in coverageAdds:
            for i, obj in enumerate(coverage_objects):
                if obj.address == address:
                    coverage_objects[i].delete(i)

    # Hook usage of Windows API function
    if jumpAddr > MOD_LOW and jumpAddr < MOD_HIGH:
        funcAddress = hex(jumpAddr)
        ret = catch_windows_api(uc, address, ret, size, funcAddress)

    # Hook usage of Windows Syscall
    if jumpAddr == 0x5000:
        hook_sysCall(uc, address, size)

    if retEnding(uc, mnemonic) or bad_instruct:
        stopProcess = True
        # print ("Stop: retEnding")

    # Begin code coverage if the shellcode is finished, and the option is enabled
    # if stopProcess and em.codeCoverage and not em.beginCoverage:
    #     stopProcess = False
    #     em.beginCoverage = True
    #     coverage_branch(uc, address, mnemonic, bad_instruct)

    # Prevent the emulation from stopping if code coverage still has objects left
    # if len(coverage_objects) > 0 and em.beginCoverage:
    #     stopProcess = False

    # If parameters were used in the function, we need to clean the stack
    if address == EXTRA_ADDR:
        cleanStackFlag = True


def hook_syscallBackup(uc, eip, esp, funcAddress, funcName, callLoc, syscallID):
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

        retVal, retValStr = findRetVal(funcName, syscallRS)

        uc.reg_write(UC_X86_REG_EAX, retVal)

        funcInfo = (funcName, hex(callLoc),retValStr, 'INT', paramVals, paramTypes, paramNames, False, syscallID)
        logSysCall(funcName, funcInfo)
    except Exception as e:
        print("Error!", e)
        print(traceback.format_exc())


def hook_syscallDefault(uc, eip, esp, funcAddress, funcName, sysCallID, callLoc):
    returnType, paramVals, paramTypes, paramNames, nt_tuple = '', '', '', '', ()
    dll = 'ntdll'

    try:
        # print (1, funcName)

        nt_tuple = syscall_signature[funcName]
        paramVals = getParams(uc, esp, nt_tuple, 'ntdict')
        paramTypes = nt_tuple[1]

        paramNames = nt_tuple[2]
        returnType = nt_tuple[3]

        retVal, retValStr = findRetVal(funcName, syscallRS)


        funcInfo = (funcName, hex(callLoc), retValStr, returnType, paramVals, paramTypes, paramNames, False, sysCallID)
        logSysCall(funcName, funcInfo)
    except:
        hook_syscallBackup(uc, eip, esp, funcAddress, funcName, callLoc, sysCallID)


def hook_sysCall(uc, address, size):
    # print ("hook_sysCall")
    global logged_dlls
    global stopProcess

    ret = address + size
    push(uc, em.arch, ret)

    syscallID = uc.reg_read(UC_X86_REG_EAX)
    sysCallName = syscall_dict[em.winVersion][em.winSP][str(syscallID)]
    exportAddress = 0
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)

    try:
        funcInfo = getattr(WinSysCall, sysCallName)(uc, eip, esp, address, em)
        funcInfo.append(syscallID)
        logSysCall(sysCallName, funcInfo)
    except:
        try:
            hook_syscallDefault(uc, eip, esp, exportAddress, sysCallName, syscallID, address)
        except Exception as e:
            print("\n\tHook failed at " + str(hex(exportAddress)) + ".")
    if sysCallName == 'NtTerminateProcess':
        stopProcess = True
        # print ("Stop: NtTerminateProcess syscall")
    if 'LoadLibrary' in sysCallName and uc.reg_read(UC_X86_REG_EAX) == 0:
        print("\t[*] LoadLibrary failed. Emulation ceasing.")
        stopProcess = True
        # print ("Stop: LoadLibraryFailed")

    uc.reg_write(UC_X86_REG_EIP, EXTRA_ADDR)


# Most Windows APIs use stdcall, so we need to clean the stack.
def cleanStack(uc, numBytes):
    if numBytes > 0:
        esp = uc.reg_read(UC_X86_REG_ESP)
        uc.reg_write(UC_X86_REG_ESP, esp + numBytes)

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

        # dll=dll.lower()
        dict4 = tryDictLocate('dict4', dll)
        dict2 = tryDictLocate('dict2', dll)
        dict1 = tryDictLocate('dict', dll)

        if (len(dict4)==0) and (len(dict2)==0) and (len(dict1)==0):
            dll=dll.lower()
            dict4 = tryDictLocate('dict4', dll)
            dict2 = tryDictLocate('dict2', dll)
            dict1 = tryDictLocate('dict', dll)
        bprint("dll", dll)
        # Log usage of DLL
        dllL=dll.lower()
        foundAlready=False

        for each in logged_dlls:
            if dll == each or dllL == each.lower():
                foundAlready=True
        if not foundAlready:
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
            print(funcName + " from "  + dll + " was not found in dictionaries.")
            return "none", "none", dll
    except Exception as e:
        bprint("Oh no!!!", e)
        bprint(traceback.format_exc())


def getParams(uc, esp, apiDict, dictName):
    global cleanBytes

    paramVals = []
    if dictName == 'dict1':
        numParams = apiDict[0]
        paramVals = makeArgVals(uc, em, esp, numParams)
        cleanBytes = apiDict[1]
    else:
        # print ("dictName", dictName)
        numParams = apiDict[0]
        paramVals = makeArgVals(uc, em, esp, numParams)
        for i in range(numParams):
            # Check if parameter is pointer, then convert
            if apiDict[1][i][0] == 'P':
                try:
                    pointer = paramVals[i]
                    pointerVal = getPointerVal(uc, pointer)
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
        for i in range(0, len(paramVals)):
            if "STR" not in apiDict[1][i]:
                try:
                    p = int(paramVals[i], 16)
                    if (0x40000000 < p and p < 0x50010000):
                        string = read_string(uc, p)
                        if len(string) < 30:
                            paramVals[i] = string
                except:
                    pass

    cleanBytes = stackCleanup(uc, em, esp, numParams)

    return paramVals


# If we haven't manually implemented the function, we send it to this function
# This function will simply find parameters, then log the call in our dictionary
def hook_default(uc, eip, esp, funcAddress, funcName, callLoc):
    try:
        dictName = apiDict = ""
        bprint(funcAddress, funcName)

        apiDict, dictName, dll = findDict(funcAddress, funcName)
        # bprint ("", apiDict, dictName, dll, funcName)
        if apiDict == "none" and dll == "wsock32":
            apiDict, dictName, dll = findDict(funcAddress, funcName, "ws2_32")
            bprint("", apiDict, dictName, dll)

        # print ("funcName, dll")
        paramVals = getParams(uc, esp, apiDict, dictName)

        if dictName != 'dict1':
            paramTypes = apiDict[1]
            paramNames = apiDict[2]
        else:
            paramTypes = ['DWORD'] * len(paramVals)
            paramNames = ['arg'] * len(paramVals)

        dictR1 = globals()['dictRS_' + dll]
        retVal, retValStr = findRetVal(funcName, dictR1)
        bprint("returnVal", funcName, retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        # retValStr = getRetVal(retVal)
        if retValStr == 32:
            funcInfo = (funcName, hex(callLoc), hex(retValStr), 'INT', paramVals, paramTypes, paramNames, False)
        else:
            funcInfo = (funcName, hex(callLoc), (retValStr), '', paramVals, paramTypes, paramNames, False)

        logCall(funcName, funcInfo)
    except Exception as e:
        print("Error!", e)
        print(traceback.format_exc())


def logCall(funcName, funcInfo):
    global paramValues
    loggedList.append(funcInfo)
    paramValues += funcInfo[4]


def logSysCall(syscallName, syscallInfo):
    global paramValues
    var = Variables()
    var.logged_syscalls.append(syscallInfo)
    logged_syscalls.append(syscallInfo)
    paramValues += syscallInfo[4]


def findArtifacts():
    Regex = Artifacts_regex()
    Regex.initializeRegex()

    for p in paramValues:
        # -------------------------------------------
        #       Finding Paths
        # -------------------------------------------
        # art.path_artifacts += re.findall(find_environment,str(p))
        # art.path_artifacts += re.findall(find_letterDrives,str(p))
        # art.path_artifacts += re.findall(find_relativePaths,str(p))
        # art.path_artifacts += re.findall(find_networkShares,str(p))

        art.path_artifacts += re.findall(Regex.total_findPaths,str(p),re.IGNORECASE)

        # -------------------------------------------
        #       Finding Files
        # -------------------------------------------
        # art.file_artifacts += re.findall(find_files,str(p))
        # art.file_artifacts += re.findall(find_genericFiles,str(p))
        # art.file_artifacts += re.findall(find_zip,str(p))
        # art.file_artifacts += re.findall(find_images,str(p))
        # art.file_artifacts += re.findall(find_programming,str(p))
        # art.file_artifacts += re.findall(find_workRelated,str(p))
        # art.file_artifacts += re.findall(find_videoAudio,str(p))

        art.file_artifacts += re.findall(Regex.find_totalFiles,str(p))
        art.file_artifacts += re.findall(Regex.find_totalFilesBeginning,str(p),re.IGNORECASE)
        #-------------------------------------------
        #       Finding Command line
        # -------------------------------------------
        # art.commandLine_artifacts += re.findall(cmdline_args,str(p))
        # art.commandLine_artifacts += re.findall(powershell_args,str(p))
        # art.commandLine_artifacts += re.findall(reg_args,str(p))
        # art.commandLine_artifacts += re.findall(net_args,str(p))
        # art.commandLine_artifacts += re.findall(netsh_args,str(p))
        # art.commandLine_artifacts += re.findall(schtask_args,str(p),re.IGNORECASE)
        # art.commandLine_artifacts += re.findall(sc_args,str(p))
        art.commandLine_artifacts += re.findall(Regex.total_commandLineArguments, str(p), re.IGNORECASE)
        # -------------------------------------------
        #       Finding WEB
        # -------------------------------------------
        # art.web_artifacts += re.findall(find_website,str(p))
        # art.web_artifacts += re.findall(find_ftp,str(p))
        art.web_artifacts += re.findall(Regex.total_webTraffic, str(p), re.IGNORECASE)
        # -------------------------------------------
        #       Finding Registry
        # -------------------------------------------
        # art.registry_artifacts += re.findall(find_HKEY,str(p))
        # art.registry_artifacts += re.findall(find_CurrentUser,str(p))
        # art.registry_artifacts += re.findall(find_LocalMachine,str(p))
        # art.registry_artifacts += re.findall(find_Users,str(p))
        # art.registry_artifacts += re.findall(find_CurrentConfig,str(p))
        art.registry_artifacts += re.findall(Regex.total_Registry, str(p), re.IGNORECASE)
        # -------------------------------------------
        #       Finding Exe / DLL
        # -------------------------------------------
        art.exe_dll_artifacts += re.findall(Regex.find_exe_dll, str(p), re.IGNORECASE)




    art.combineRegexEmuCMDline()
    art.exePathToCategory()
    art.regexIntoMisc()
    art.regTechniquesFind()
    art.hierarchyFind()

    art.removeDuplicates()
    art.removeStructures(Regex)



"""
def findArtifactsOLD():
    artifacts = []
    net_artifacts = []
    file_artifacts = []
    exec_artifacts = []

    for p in paramValues:
        artifacts += re.findall(r"[a-zA-Z0-9_.-]+\.\S+", str(p))
        net_artifacts += re.findall(r"http|ftp|https:\/\/?|www\.?[a-zA-Z]+\.com|eg|net|org", str(p))
        net_artifacts += re.findall(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", str(p))
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

    return list(dict.fromkeys(artifacts)), list(dict.fromkeys(net_artifacts)), list(
        dict.fromkeys(file_artifacts)), list(dict.fromkeys(exec_artifacts))


    return list(dict.fromkeys(artifacts)), list(dict.fromkeys(net_artifacts)), list(dict.fromkeys(file_artifacts)), list(dict.fromkeys(exec_artifacts))
"""


def getArtifacts():
    artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()

def test_i386(mode, code):
    global artifacts2
    global outFile
    global stackFile
    global cs
    global codeLen
    global address_range
    global finalAddress
    arch=0
    mu = Uc(UC_ARCH_X86, mode)

    startLoc=CODE_ADDR + em.entryOffset
    try:
        codeLen = len(code)

        # Initialize emulator
        try:
            mu.mem_map(0x00000000, 0x20050000)
        except:
            print ("memory loading erorr")
        mods = loadDlls(mu)

        # write machine code to be emulated to memory
        mu.mem_write(CODE_ADDR, code)
        address_range.append([CODE_ADDR, len(code)])

        mu.mem_write(EXTRA_ADDR, b'\xC3')

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, STACK_ADDR-600)
        mu.reg_write(UC_X86_REG_EBP, STACK_ADDR)

        # Push entry point addr to top of stack. Represents calling of entry point.
        push(mu, em.arch, ENTRY_ADDR)
        mu.mem_write(ENTRY_ADDR, b'\x90\x90\x90\x90')

        if mode == UC_MODE_32:
            print(cya + "\n\t[*]" + res2 + " Emulating x86 shellcode")
            cs = Cs(CS_ARCH_X86, CS_MODE_32)
            allocateWinStructs32(mu, mods)
        elif mode == UC_MODE_64:
            print(cya + "\n\t[*]" + res2 + " Emulating x86_64 shellcode")
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            allocateWinStructs64(mu, mods)

        # tracing all instructions with customized callback

        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # mu.hook_add(UC_ERR_FETCH_UNMAPPED, hook_mem_access2)

        if len(coverage_objects) > 0:
            startLoc = coverage_objects[0].address
            coverage_objects[0].dump_saved_info(mu)
            coverage_objects[0].inProgress = True
        else:
            startLoc = CODE_ADDR + em.entryOffset

    except Exception as e:
        print(e)
        print(traceback.format_exc())

    try:
        # Start the emulation
        mu.emu_start(startLoc, (CODE_ADDR + em.entryOffset) + len(code))
        # mu.release_handle(True)

    except Exception as e:
        print("Emulation error: ", e)
        print ("Last address:", hex(finalAddress))
        print(traceback.format_exc())
        # createStackOutput(arch)




    # createStackOutput(arch)
    findArtifacts()

    return mu


# def startEmu(arch, data, vb):
#     # print ("startEmu arch", arch)
#     global verbose
#     verbose = vb
#
#     fRaw.giveSize(data)
#
#     if arch == 32:
#         em.arch=32
#     elif arch == 64:
#         em.arch=64
#
#     while True:
#         if em.arch == 32:
#             test_i386(UC_MODE_32, data)
#         elif em.arch == 64:
#             test_i386(UC_MODE_64, data)
#
#         if len(coverage_objects) <= 0 or em.codeCoverage == False:
#             break
#
#     print(cya + "\t[*]" + res2 + " CPU counter: " + str(programCounter))
#     print(cya + "\t[*]" + res2 + " Emulation complete")
#
#     fRaw.merge2()
#     fRaw.completed()
#     fRaw.findAPIs()
# #
#     outFile.close()
#     stackFile.close()

def showTravAdds():
    print ("TraversedAdds at restart:")
    myOut=""
    for each in traversedAdds:
        myOut+=hex(each) + gre+", "+whi
    print (myOut)

def restartEmu(mu, mode, code):
    global cs
    global codeLen
    global stopProcessCC
    global stopProcess

    stopProcessCC=False
    stopProcess=False
    codeLen = len(code)
    em.restartCCInProgress = True

    # showTravAdds()
    try:
        startLoc = coverage_objects[0].address
        coverage_objects[0].dump_saved_info(mu)
        old_num= coverage_objects[0].coverage_num
        coverage_objects[0].delete(0)

    except Exception as e:
        print(e)
        print(traceback.format_exc())

    try:
        if mode == UC_MODE_32:
            print(gre + "\t[!]"+res2+" Complete code coverage: "+gre+"restarting emulation"+res2+" of x86 shellcode at " + gre + hex(startLoc) + res2 + ".")
            if verbose:
                outFile.write("***** Complete code coverage: restarting emulation of x86 shellcode at " + hex(startLoc) + ".\n")
            if em.timeless_debugging_stack:
                stackFile.write("\n***** Complete code coverage: restarting emulation of x86 shellcode at " + hex(startLoc) + ". " + str(old_num)+ "\n")
            # cs = Cs(CS_ARCH_X86, CS_MODE_32)

        elif mode == UC_MODE_64:
            print(gre + "\t[!]"+res2+" Complete code coverage: "+gre+"restarting emulation"+res2+" of x86_64 shellcode at " + gre + hex(startLoc) + res2 + ".")
            if verbose:
                outFile.write("\n***** Complete code coverage: restarting emulation of x86_64 shellcode at " + hex(startLoc) + ".\n")
            if em.timeless_debugging_stack:
                stackFile.write("\n***** Complete code coverage: restarting emulation of x86_64 shellcode at " + hex(startLoc) + ".\n")

            cs = Cs(CS_ARCH_X86, CS_MODE_64)
        # Start the emulation
        mu.emu_start(startLoc, (CODE_ADDR + em.entryOffset) + len(code))
        print("\n")
    except Exception as e:
        print(e)
        print(traceback.format_exc())

def startEmu(data, vb):
    global verbose
    global programCounter
    programCounter=0
    verbose = vb
    calculateAddressesSkipCCC()


    if em.arch == 32:
        em.arch=32
        mu = test_i386(UC_MODE_32, data)
    elif em.arch == 64:
        em.arch=64
        mu2 = test_i386(UC_MODE_64, data)

    lel = 0
    while len(coverage_objects) > 0 and em.codeCoverage == True:
        if em.arch == 32:
            restartEmu(mu, UC_MODE_32, data)
        elif em.arch == 64:
            restartEmu(mu2,UC_MODE_64, data)

        if lel > 2:
            print ("breaking, lel")
            break
        lel += 1

    print(cya + "\t[*]" + res2 + " CPU counter: " + str(programCounter))
    print(cya + "\t[*]" + res2 + " Emulation complete")

    fRaw.merge2()
    fRaw.completed()
    fRaw.findAPIs()

    outFile.close()

    stackFile.close()


def emuInit():
    pass

def haha():
    fRaw.show()
fRaw=sharDeobf()
vars = Variables()
em = vars.emu
