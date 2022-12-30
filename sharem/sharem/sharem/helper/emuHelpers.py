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


class timelessD:
    def __init__(self, pc):
        # self.esp=0
        # self.esp_4=0
        # self.esp_8=0
        # self.esp_c=0
        # self.esp_0x10=0
        # self.esp_0x14=0
        # self.esp_0x18=0
        # self.esp_0x1c=0
        # self.esp_0x20=0
        # self.esp_0x24=0
        # self.esp_0x28=0
        # self.esp_0x2c=0
        # self.esp_0x30=0
        # self.esp_0x34=0
        # self.esp_0x38=0
        # self.esp_0x3c=0
        # self.esp_0x40=0
        # self.esp_0x44=0
        # self.esp_0x48=0
        # self.esp_0x4c=0
        # self.esp_0x50=0
        # self.esp_0x54=0
        # self.esp_0x58=0
        # self.esp_0x5c=0
        # self.esp_0x60=0
        # self.esp_0x64=0
        # self.esp_0x68=0
        # self.esp_0x6c=0
        # self.esp_0x70=0
        # self.esp_0x74=0
        # self.esp_0x78=0
        # self.esp_0x7c=0
        # self.esp_0x80=0
        # self.esp_0x84=0
        # self.esp_0x88=0
        # self.esp_0x8c=0
        # self.esp_0x90=0
        # self.esp_0x94=0
        # self.esp_0x98=0
        # self.esp_0x9c=0
        # self.esp_0xa0=0
        # self.esp_neg_4=0
        # self.esp_neg_8=0
        # self.esp_neg_c=0
        # self.esp_neg_0x10=0
        # self.esp_neg_0x14=0
        # self.esp_neg_0x18=0
        # self.esp_neg_0x1c=0
        # self.esp_neg_0x20=0
        # self.esp_neg_0x24=0
        # self.esp_neg_0x28=0
        # self.esp_neg_0x2c=0
        # self.esp_neg_0x30=0
        # self.esp_neg_0x34=0
        # self.esp_neg_0x38=0
        # self.esp_neg_0x3c=0
        # self.esp_neg_0x40=0
        # self.esp_neg_0x44=0
        # self.esp_neg_0x48=0
        # self.esp_neg_0x4c=0
        # self.esp_neg_0x50=0
        # self.esp_neg_0x54=0
        # self.esp_neg_0x58=0
        # self.esp_neg_0x5c=0
        # self.esp_neg_0x60=0
        # self.esp_neg_0x64=0
        # self.esp_neg_0x68=0
        # self.esp_neg_0x6c=0
        # self.esp_neg_0x70=0
        # self.esp_neg_0x74=0
        # self.esp_neg_0x78=0
        # self.esp_neg_0x7c=0
        # self.esp_neg_0x80=0
        # self.esp_neg_0x84=0
        # self.esp_neg_0x88=0
        # self.esp_neg_0x8c=0
        # self.esp_neg_0x90=0
        # self.esp_neg_0x94=0
        # self.esp_neg_0x98=0
        # self.esp_neg_0x9c=0
        # self.esp_neg_0xa0=0
        # self.rsp=0
        # self.rsp_8=0
        # self.rsp_0x10=0
        # self.rsp_0x18=0
        # self.rsp_0x20=0
        # self.rsp_0x28=0
        # self.rsp_0x30=0
        # self.rsp_0x38=0
        # self.rsp_0x40=0
        # self.rsp_0x48=0
        # self.rsp_0x50=0
        # self.rsp_0x58=0
        # self.rsp_0x60=0
        # self.rsp_0x68=0
        # self.rsp_0x70=0
        # self.rsp_0x78=0
        # self.rsp_0x80=0
        # self.rsp_0x88=0
        # self.rsp_0x90=0
        # self.rsp_0x98=0
        # self.rsp_0xa0=0
        # self.rsp_neg_8=0
        # self.rsp_neg_0x10=0
        # self.rsp_neg_0x18=0
        # self.rsp_neg_0x20=0
        # self.rsp_neg_0x28=0
        # self.rsp_neg_0x30=0
        # self.rsp_neg_0x38=0
        # self.rsp_neg_0x40=0
        # self.rsp_neg_0x48=0
        # self.rsp_neg_0x50=0
        # self.rsp_neg_0x58=0
        # self.rsp_neg_0x60=0
        # self.rsp_neg_0x68=0
        # self.rsp_neg_0x70=0
        # self.rsp_neg_0x78=0
        # self.rsp_neg_0x80=0
        # self.rsp_neg_0x88=0
        # self.rsp_neg_0x90=0
        # self.rsp_neg_0x98=0
        # self.rsp_neg_0xa0=0
        self.id=pc
        self.arch=32
        self.stackDict={}
        self.start =0
        self.asssemblyInst=""

    def giveVal3(self,uc, esp,memReadVal, stack,start, asssemblyInst):
        self.stackDict=stack
        self.start=start
        self.asssemblyInst = asssemblyInst
        # print (self.stackDict)

    def giveVal2(self,uc, esp,memReadVal):
        self.esp_neg_0xa0 =  int.from_bytes(uc.mem_read(esp-0xa0,memReadVal), "little")
        self.esp_neg_0x9c =  int.from_bytes(uc.mem_read(esp-0x9c,memReadVal), "little")
        self.esp_neg_0x98 =  int.from_bytes(uc.mem_read(esp-0x98,memReadVal), "little")
        self.esp_neg_0x94 =  int.from_bytes(uc.mem_read(esp-0x94,memReadVal), "little")
        self.esp_neg_0x90 =  int.from_bytes(uc.mem_read(esp-0x90,memReadVal), "little")
        self.esp_neg_0x8c =  int.from_bytes(uc.mem_read(esp-0x8c,memReadVal), "little")
        self.esp_neg_0x88 =  int.from_bytes(uc.mem_read(esp-0x88,memReadVal), "little")
        self.esp_neg_0x84 =  int.from_bytes(uc.mem_read(esp-0x84,memReadVal), "little")
        self.esp_neg_0x80 =  int.from_bytes(uc.mem_read(esp-0x80,memReadVal), "little")
        self.esp_neg_0x7c =  int.from_bytes(uc.mem_read(esp-0x7c,memReadVal), "little")
        self.esp_neg_0x78 =  int.from_bytes(uc.mem_read(esp-0x78,memReadVal), "little")
        self.esp_neg_0x74 =  int.from_bytes(uc.mem_read(esp-0x74,memReadVal), "little")
        self.esp_neg_0x70 =  int.from_bytes(uc.mem_read(esp-0x70,memReadVal), "little")
        self.esp_neg_0x6c =  int.from_bytes(uc.mem_read(esp-0x6c,memReadVal), "little")
        self.esp_neg_0x68 =  int.from_bytes(uc.mem_read(esp-0x68,memReadVal), "little")
        self.esp_neg_0x64 =  int.from_bytes(uc.mem_read(esp-0x64,memReadVal), "little")
        self.esp_neg_0x60 =  int.from_bytes(uc.mem_read(esp-0x60,memReadVal), "little")
        self.esp_neg_0x5c =  int.from_bytes(uc.mem_read(esp-0x5c,memReadVal), "little")
        self.esp_neg_0x58 =  int.from_bytes(uc.mem_read(esp-0x58,memReadVal), "little")
        self.esp_neg_0x54 =  int.from_bytes(uc.mem_read(esp-0x54,memReadVal), "little")
        self.esp_neg_0x50 =  int.from_bytes(uc.mem_read(esp-0x50,memReadVal), "little")
        self.esp_neg_0x4c =  int.from_bytes(uc.mem_read(esp-0x4c,memReadVal), "little")
        self.esp_neg_0x48 =  int.from_bytes(uc.mem_read(esp-0x48,memReadVal), "little")
        self.esp_neg_0x44 =  int.from_bytes(uc.mem_read(esp-0x44,memReadVal), "little")
        self.esp_neg_0x40 =  int.from_bytes(uc.mem_read(esp-0x40,memReadVal), "little")
        self.esp_neg_0x3c =  int.from_bytes(uc.mem_read(esp-0x3c,memReadVal), "little")
        self.esp_neg_0x38 =  int.from_bytes(uc.mem_read(esp-0x38,memReadVal), "little")
        self.esp_neg_0x34 =  int.from_bytes(uc.mem_read(esp-0x34,memReadVal), "little")
        self.esp_neg_0x30 =  int.from_bytes(uc.mem_read(esp-0x30,memReadVal), "little")
        self.esp_neg_0x2c =  int.from_bytes(uc.mem_read(esp-0x2c,memReadVal), "little")
        self.esp_neg_0x28 =  int.from_bytes(uc.mem_read(esp-0x28,memReadVal), "little")
        self.esp_neg_0x24 =  int.from_bytes(uc.mem_read(esp-0x24,memReadVal), "little")
        self.esp_neg_0x20 =  int.from_bytes(uc.mem_read(esp-0x20,memReadVal), "little")
        self.esp_neg_0x1c =  int.from_bytes(uc.mem_read(esp-0x1c,memReadVal), "little")
        self.esp_neg_0x18 =  int.from_bytes(uc.mem_read(esp-0x18,memReadVal), "little")
        self.esp_neg_0x14 =  int.from_bytes(uc.mem_read(esp-0x14,memReadVal), "little")
        self.esp_neg_0x10 =  int.from_bytes(uc.mem_read(esp-0x10,memReadVal), "little")
        self.esp_neg_0xc =  int.from_bytes(uc.mem_read(esp-0xc,memReadVal), "little")
        self.esp_neg_8 =  int.from_bytes(uc.mem_read(esp-8,memReadVal), "little")
        self.esp_neg_4 =  int.from_bytes(uc.mem_read(esp-4,memReadVal), "little")
        self.esp = int.from_bytes(uc.mem_read(esp,memReadVal), "little")
        self.esp_4 =  int.from_bytes(uc.mem_read(esp+4,memReadVal), "little")
        self.esp_8 =  int.from_bytes(uc.mem_read(esp+8,memReadVal), "little")
        self.esp_c =  int.from_bytes(uc.mem_read(esp+0xc,memReadVal), "little")
        self.esp_0x10 =   int.from_bytes(uc.mem_read(esp+0x10,memReadVal), "little")
        self.esp_0x14 =   int.from_bytes(uc.mem_read(esp+0x14,memReadVal), "little")
        self.esp_0x18 =   int.from_bytes(uc.mem_read(esp+0x18,memReadVal), "little")
        self.esp_0x1c =   int.from_bytes(uc.mem_read(esp+0x1c,memReadVal), "little")
        self.esp_0x20 =   int.from_bytes(uc.mem_read(esp+0x20,memReadVal), "little")
        self.esp_0x24 =   int.from_bytes(uc.mem_read(esp+0x24,memReadVal), "little")
        self.esp_0x28 =   int.from_bytes(uc.mem_read(esp+0x28,memReadVal), "little")
        self.esp_0x2c =   int.from_bytes(uc.mem_read(esp+0x2c,memReadVal), "little")
        self.esp_0x30 =   int.from_bytes(uc.mem_read(esp+0x30,memReadVal), "little")
        self.esp_0x34 =   int.from_bytes(uc.mem_read(esp+0x34,memReadVal), "little")
        self.esp_0x38 =   int.from_bytes(uc.mem_read(esp+0x38,memReadVal), "little")
        self.esp_0x3c =   int.from_bytes(uc.mem_read(esp+0x3c,memReadVal), "little")
        self.esp_0x40 =   int.from_bytes(uc.mem_read(esp+0x40,memReadVal), "little")
        self.esp_0x44 =   int.from_bytes(uc.mem_read(esp+0x44,memReadVal), "little")
        self.esp_0x48 =   int.from_bytes(uc.mem_read(esp+0x48,memReadVal), "little")
        self.esp_0x4c =   int.from_bytes(uc.mem_read(esp+0x4c,memReadVal), "little")
        self.esp_0x50 =   int.from_bytes(uc.mem_read(esp+0x50,memReadVal), "little")
        self.esp_0x54 =   int.from_bytes(uc.mem_read(esp+0x54,memReadVal), "little")
        self.esp_0x58 =   int.from_bytes(uc.mem_read(esp+0x58,memReadVal), "little")
        self.esp_0x5c =   int.from_bytes(uc.mem_read(esp+0x5c,memReadVal), "little")
        self.esp_0x60 =   int.from_bytes(uc.mem_read(esp+0x60,memReadVal), "little")
        self.esp_0x64 =   int.from_bytes(uc.mem_read(esp+0x64,memReadVal), "little")
        self.esp_0x68 =   int.from_bytes(uc.mem_read(esp+0x68,memReadVal), "little")
        self.esp_0x6c =   int.from_bytes(uc.mem_read(esp+0x6c,memReadVal), "little")
        self.esp_0x70 =   int.from_bytes(uc.mem_read(esp+0x70,memReadVal), "little")
        self.esp_0x74 =   int.from_bytes(uc.mem_read(esp+0x74,memReadVal), "little")
        self.esp_0x78 =   int.from_bytes(uc.mem_read(esp+0x78,memReadVal), "little")
        self.esp_0x7c =   int.from_bytes(uc.mem_read(esp+0x7c,memReadVal), "little")
        self.esp_0x80 =   int.from_bytes(uc.mem_read(esp+0x80,memReadVal), "little")
        self.esp_0x84 =   int.from_bytes(uc.mem_read(esp+0x84,memReadVal), "little")
        self.esp_0x88 =   int.from_bytes(uc.mem_read(esp+0x88,memReadVal), "little")
        self.esp_0x8c =   int.from_bytes(uc.mem_read(esp+0x8c,memReadVal), "little")
        self.esp_0x90 =   int.from_bytes(uc.mem_read(esp+0x90,memReadVal), "little")
        self.esp_0x94 =   int.from_bytes(uc.mem_read(esp+0x94,memReadVal), "little")
        self.esp_0x98 =   int.from_bytes(uc.mem_read(esp+0x98,memReadVal), "little")
        self.esp_0x9c = int.from_bytes(uc.mem_read(esp+0x9c,memReadVal), "little")
        self.esp_0xa0 =  int.from_bytes(uc.mem_read(esp+0xa0,memReadVal), "little")

    def giveVal2_64(self,uc, rsp,memReadVal):
        self.rsp_neg_0xa0 =  int.from_bytes(uc.mem_read(rsp-0xa0,memReadVal), "little")
        self.rsp_neg_0x98 =  int.from_bytes(uc.mem_read(rsp-0x98,memReadVal), "little")
        self.rsp_neg_0x90 =  int.from_bytes(uc.mem_read(rsp-0x90,memReadVal), "little")
        self.rsp_neg_0x88 =  int.from_bytes(uc.mem_read(rsp-0x88,memReadVal), "little")
        self.rsp_neg_0x80 =  int.from_bytes(uc.mem_read(rsp-0x80,memReadVal), "little")
        self.rsp_neg_0x78 =  int.from_bytes(uc.mem_read(rsp-0x78,memReadVal), "little")
        self.rsp_neg_0x70 =  int.from_bytes(uc.mem_read(rsp-0x70,memReadVal), "little")
        self.rsp_neg_0x68 =  int.from_bytes(uc.mem_read(rsp-0x68,memReadVal), "little")
        self.rsp_neg_0x60 =  int.from_bytes(uc.mem_read(rsp-0x60,memReadVal), "little")
        self.rsp_neg_0x58 =  int.from_bytes(uc.mem_read(rsp-0x58,memReadVal), "little")
        self.rsp_neg_0x50 =  int.from_bytes(uc.mem_read(rsp-0x50,memReadVal), "little")
        self.rsp_neg_0x48 =  int.from_bytes(uc.mem_read(rsp-0x48,memReadVal), "little")
        self.rsp_neg_0x40 =  int.from_bytes(uc.mem_read(rsp-0x40,memReadVal), "little")
        self.rsp_neg_0x38 =  int.from_bytes(uc.mem_read(rsp-0x38,memReadVal), "little")
        self.rsp_neg_0x30 =  int.from_bytes(uc.mem_read(rsp-0x30,memReadVal), "little")
        self.rsp_neg_0x28 =  int.from_bytes(uc.mem_read(rsp-0x28,memReadVal), "little")
        self.rsp_neg_0x20 =  int.from_bytes(uc.mem_read(rsp-0x20,memReadVal), "little")
        self.rsp_neg_0x18 =  int.from_bytes(uc.mem_read(rsp-0x18,memReadVal), "little")
        self.rsp_neg_0x10 =  int.from_bytes(uc.mem_read(rsp-0x10,memReadVal), "little")
        self.rsp_neg_8 =  int.from_bytes(uc.mem_read(rsp-8,memReadVal), "little")
        self.rsp = int.from_bytes(uc.mem_read(rsp,memReadVal), "little")
        self.rsp_8 =  int.from_bytes(uc.mem_read(rsp+8,memReadVal), "little")
        self.rsp_0x10 =   int.from_bytes(uc.mem_read(rsp+0x10,memReadVal), "little")
        self.rsp_0x18 =   int.from_bytes(uc.mem_read(rsp+0x18,memReadVal), "little")
        self.rsp_0x20 =   int.from_bytes(uc.mem_read(rsp+0x20,memReadVal), "little")
        self.rsp_0x28 =   int.from_bytes(uc.mem_read(rsp+0x28,memReadVal), "little")
        self.rsp_0x30 =   int.from_bytes(uc.mem_read(rsp+0x30,memReadVal), "little")
        self.rsp_0x38 =   int.from_bytes(uc.mem_read(rsp+0x38,memReadVal), "little")
        self.rsp_0x40 =   int.from_bytes(uc.mem_read(rsp+0x40,memReadVal), "little")
        self.rsp_0x48 =   int.from_bytes(uc.mem_read(rsp+0x48,memReadVal), "little")
        self.rsp_0x50 =   int.from_bytes(uc.mem_read(rsp+0x50,memReadVal), "little")
        self.rsp_0x58 =   int.from_bytes(uc.mem_read(rsp+0x58,memReadVal), "little")
        self.rsp_0x60 =   int.from_bytes(uc.mem_read(rsp+0x60,memReadVal), "little")
        self.rsp_0x68 =   int.from_bytes(uc.mem_read(rsp+0x68,memReadVal), "little")
        self.rsp_0x70 =   int.from_bytes(uc.mem_read(rsp+0x70,memReadVal), "little")
        self.rsp_0x78 =   int.from_bytes(uc.mem_read(rsp+0x78,memReadVal), "little")
        self.rsp_0x80 =   int.from_bytes(uc.mem_read(rsp+0x80,memReadVal), "little")
        self.rsp_0x88 =   int.from_bytes(uc.mem_read(rsp+0x88,memReadVal), "little")
        self.rsp_0x90 =   int.from_bytes(uc.mem_read(rsp+0x90,memReadVal), "little")
        self.rsp_0x98 =   int.from_bytes(uc.mem_read(rsp+0x98,memReadVal), "little")
        self.rsp_0xa0 =  int.from_bytes(uc.mem_read(rsp+0xa0,memReadVal), "little")

tdsList=[]

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

def giveStackClass(uc, arch, pc, asssemblyInst):
    global tdsList
    tDeb = timelessD(pc)
    tdsList.append(tDeb)
    stackVals={}
    if arch == 32:
        esp_4=UC_X86_REG_ESP-4
        start=  uc.reg_read(UC_X86_REG_ESP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        memReadVal=4
        ESPs = {"esp-0xa0":  int.from_bytes(uc.mem_read(esp-0xa0,4), "little"), "esp-0x9c":  int.from_bytes(uc.mem_read(esp-0x9c,4), "little"), "esp-0x98":  int.from_bytes(uc.mem_read(esp-0x98,4), "little"), "esp-0x94":  int.from_bytes(uc.mem_read(esp-0x94,4), "little"), "esp-0x90":  int.from_bytes(uc.mem_read(esp-0x90,4), "little"), "esp-0x8c":  int.from_bytes(uc.mem_read(esp-0x8c,4), "little"), "esp-0x88":  int.from_bytes(uc.mem_read(esp-0x88,4), "little"), "esp-0x84":  int.from_bytes(uc.mem_read(esp-0x84,4), "little"), "esp-0x80":  int.from_bytes(uc.mem_read(esp-0x80,4), "little"), "esp-0x7c":  int.from_bytes(uc.mem_read(esp-0x7c,4), "little"), "esp-0x78":  int.from_bytes(uc.mem_read(esp-0x78,4), "little"), "esp-0x74":  int.from_bytes(uc.mem_read(esp-0x74,4), "little"), "esp-0x70":  int.from_bytes(uc.mem_read(esp-0x70,4), "little"), "esp-0x6c":  int.from_bytes(uc.mem_read(esp-0x6c,4), "little"), "esp-0x68":  int.from_bytes(uc.mem_read(esp-0x68,4), "little"), "esp-0x64":  int.from_bytes(uc.mem_read(esp-0x64,4), "little"), "esp-0x60":  int.from_bytes(uc.mem_read(esp-0x60,4), "little"), "esp-0x5c":  int.from_bytes(uc.mem_read(esp-0x5c,4), "little"), "esp-0x58":  int.from_bytes(uc.mem_read(esp-0x58,4), "little"), "esp-0x54":  int.from_bytes(uc.mem_read(esp-0x54,4), "little"), "esp-0x50":  int.from_bytes(uc.mem_read(esp-0x50,4), "little"), "esp-0x4c":  int.from_bytes(uc.mem_read(esp-0x4c,4), "little"), "esp-0x48":  int.from_bytes(uc.mem_read(esp-0x48,4), "little"), "esp-0x44":  int.from_bytes(uc.mem_read(esp-0x44,4), "little"), "esp-0x40":  int.from_bytes(uc.mem_read(esp-0x40,4), "little"), "esp-0x3c":  int.from_bytes(uc.mem_read(esp-0x3c,4), "little"), "esp-0x38":  int.from_bytes(uc.mem_read(esp-0x38,4), "little"), "esp-0x34":  int.from_bytes(uc.mem_read(esp-0x34,4), "little"), "esp-0x30":  int.from_bytes(uc.mem_read(esp-0x30,4), "little"), "esp-0x2c":  int.from_bytes(uc.mem_read(esp-0x2c,4), "little"), "esp-0x28":  int.from_bytes(uc.mem_read(esp-0x28,4), "little"), "esp-0x24":  int.from_bytes(uc.mem_read(esp-0x24,4), "little"), "esp-0x20":  int.from_bytes(uc.mem_read(esp-0x20,4), "little"), "esp-0x1c":  int.from_bytes(uc.mem_read(esp-0x1c,4), "little"), "esp-0x18":  int.from_bytes(uc.mem_read(esp-0x18,4), "little"), "esp-0x14":  int.from_bytes(uc.mem_read(esp-0x14,4), "little"), "esp-0x10":  int.from_bytes(uc.mem_read(esp-0x10,4), "little"), "esp-0xc":   int.from_bytes(uc.mem_read(esp-0xc,4), "little"), "esp-0x8":   int.from_bytes(uc.mem_read(esp-8,4), "little"), "esp-0x4":   int.from_bytes(uc.mem_read(esp-4,4), "little"), "esp     ": int.from_bytes(uc.mem_read(esp,4), "little"), "esp+0x4":   int.from_bytes(uc.mem_read(esp+4,4), "little"), "esp+0x8":   int.from_bytes(uc.mem_read(esp+8,4), "little"), "esp+0xc":   int.from_bytes(uc.mem_read(esp+0xc,4), "little"), "esp+0x10": int.from_bytes(uc.mem_read(esp+0x10,4), "little"), "esp+0x14": int.from_bytes(uc.mem_read(esp+0x14,4), "little"), "esp+0x18": int.from_bytes(uc.mem_read(esp+0x18,4), "little"), "esp+0x1c": int.from_bytes(uc.mem_read(esp+0x1c,4), "little"), "esp+0x20": int.from_bytes(uc.mem_read(esp+0x20,4), "little"), "esp+0x24": int.from_bytes(uc.mem_read(esp+0x24,4), "little"), "esp+0x28": int.from_bytes(uc.mem_read(esp+0x28,4), "little"), "esp+0x2c": int.from_bytes(uc.mem_read(esp+0x2c,4), "little"), "esp+0x30": int.from_bytes(uc.mem_read(esp+0x30,4), "little"), "esp+0x34": int.from_bytes(uc.mem_read(esp+0x34,4), "little"), "esp+0x38": int.from_bytes(uc.mem_read(esp+0x38,4), "little"), "esp+0x3c": int.from_bytes(uc.mem_read(esp+0x3c,4), "little"), "esp+0x40": int.from_bytes(uc.mem_read(esp+0x40,4), "little"), "esp+0x44": int.from_bytes(uc.mem_read(esp+0x44,4), "little"), "esp+0x48": int.from_bytes(uc.mem_read(esp+0x48,4), "little"), "esp+0x4c": int.from_bytes(uc.mem_read(esp+0x4c,4), "little"), "esp+0x50": int.from_bytes(uc.mem_read(esp+0x50,4), "little"), "esp+0x54": int.from_bytes(uc.mem_read(esp+0x54,4), "little"), "esp+0x58": int.from_bytes(uc.mem_read(esp+0x58,4), "little"), "esp+0x5c": int.from_bytes(uc.mem_read(esp+0x5c,4), "little"), "esp+0x60": int.from_bytes(uc.mem_read(esp+0x60,4), "little"), "esp+0x64": int.from_bytes(uc.mem_read(esp+0x64,4), "little"), "esp+0x68": int.from_bytes(uc.mem_read(esp+0x68,4), "little"), "esp+0x6c": int.from_bytes(uc.mem_read(esp+0x6c,4), "little"), "esp+0x70": int.from_bytes(uc.mem_read(esp+0x70,4), "little"), "esp+0x74": int.from_bytes(uc.mem_read(esp+0x74,4), "little"), "esp+0x78": int.from_bytes(uc.mem_read(esp+0x78,4), "little"), "esp+0x7c": int.from_bytes(uc.mem_read(esp+0x7c,4), "little"), "esp+0x80": int.from_bytes(uc.mem_read(esp+0x80,4), "little"), "esp+0x84": int.from_bytes(uc.mem_read(esp+0x84,4), "little"), "esp+0x88": int.from_bytes(uc.mem_read(esp+0x88,4), "little"), "esp+0x8c": int.from_bytes(uc.mem_read(esp+0x8c,4), "little"), "esp+0x90": int.from_bytes(uc.mem_read(esp+0x90,4), "little"), "esp+0x94": int.from_bytes(uc.mem_read(esp+0x94,4), "little"), "esp+0x98": int.from_bytes(uc.mem_read(esp+0x98,4), "little"), "esp+0x9c": int.from_bytes(uc.mem_read(esp+0x9c,4), "little")}
        stackVals=ESPs.items()
        stackP=esp
    elif arch == 64:
        start=  uc.reg_read(UC_X86_REG_RSP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        memReadVal=8
        RSPs = {"rsp-0xa0":  int.from_bytes(uc.mem_read(rsp-0xa0,8), "little"),"rsp-0x98":  int.from_bytes(uc.mem_read(rsp-0x98,8), "little"),"rsp-0x90":  int.from_bytes(uc.mem_read(rsp-0x90,8), "little"),"rsp-0x88":  int.from_bytes(uc.mem_read(rsp-0x88,8), "little"),"rsp-0x80":  int.from_bytes(uc.mem_read(rsp-0x80,8), "little"),"rsp-0x78":  int.from_bytes(uc.mem_read(rsp-0x78,8), "little"),"rsp-0x70":  int.from_bytes(uc.mem_read(rsp-0x70,8), "little"),"rsp-0x68":  int.from_bytes(uc.mem_read(rsp-0x68,8), "little"),"rsp-0x60":  int.from_bytes(uc.mem_read(rsp-0x60,8), "little"),"rsp-0x58":  int.from_bytes(uc.mem_read(rsp-0x58,8), "little"),"rsp-0x50":  int.from_bytes(uc.mem_read(rsp-0x50,8), "little"),"rsp-0x48":  int.from_bytes(uc.mem_read(rsp-0x48,8), "little"),"rsp-0x40":  int.from_bytes(uc.mem_read(rsp-0x40,8), "little"),"rsp-0x38":  int.from_bytes(uc.mem_read(rsp-0x38,8), "little"),"rsp-0x30":  int.from_bytes(uc.mem_read(rsp-0x30,8), "little"),"rsp-0x28":  int.from_bytes(uc.mem_read(rsp-0x28,8), "little"),"rsp-0x20":  int.from_bytes(uc.mem_read(rsp-0x20,8), "little"),"rsp-0x18":  int.from_bytes(uc.mem_read(rsp-0x18,8), "little"),"rsp-0x10":  int.from_bytes(uc.mem_read(rsp-0x10,8), "little"),"rsp-0x8":   int.from_bytes(uc.mem_read(rsp-8,8), "little"),"rsp     ": int.from_bytes(uc.mem_read(rsp,8), "little"),"rsp+0x8":   int.from_bytes(uc.mem_read(rsp+8,8), "little"),"rsp+0x10": int.from_bytes(uc.mem_read(rsp+0x10,8), "little"),"rsp+0x18": int.from_bytes(uc.mem_read(rsp+0x18,8), "little"),"rsp+0x20": int.from_bytes(uc.mem_read(rsp+0x20,8), "little"),"rsp+0x28": int.from_bytes(uc.mem_read(rsp+0x28,8), "little"),"rsp+0x30": int.from_bytes(uc.mem_read(rsp+0x30,8), "little"),"rsp+0x38": int.from_bytes(uc.mem_read(rsp+0x38,8), "little"),"rsp+0x40": int.from_bytes(uc.mem_read(rsp+0x40,8), "little"),"rsp+0x48": int.from_bytes(uc.mem_read(rsp+0x48,8), "little"),"rsp+0x50": int.from_bytes(uc.mem_read(rsp+0x50,8), "little"),"rsp+0x58": int.from_bytes(uc.mem_read(rsp+0x58,8), "little"),"rsp+0x60": int.from_bytes(uc.mem_read(rsp+0x60,8), "little"),"rsp+0x68": int.from_bytes(uc.mem_read(rsp+0x68,8), "little"),"rsp+0x70": int.from_bytes(uc.mem_read(rsp+0x70,8), "little"),"rsp+0x78": int.from_bytes(uc.mem_read(rsp+0x78,8), "little"),"rsp+0x80": int.from_bytes(uc.mem_read(rsp+0x80,8), "little"),"rsp+0x88": int.from_bytes(uc.mem_read(rsp+0x88,8), "little"),"rsp+0x90": int.from_bytes(uc.mem_read(rsp+0x90,8), "little"),"rsp+0x98": int.from_bytes(uc.mem_read(rsp+0x98,8), "little")}
        stackVals=RSPs.items()
        stackP=rsp
    # tDeb.giveVal2_64(uc,stackP, memReadVal)
    tDeb.giveVal3(uc,stackP, memReadVal, stackVals,start, asssemblyInst)
    return

def createStackOutput(arch):
    print ("createStackOutput")
    global tdsList
    instructLine =""
    stackFile2 = open(os.path.join(os.path.dirname(__file__), '../stackLog.txt'), 'w')
    if arch == 64:
        numGroupings=4
        formatVal="{:016x} "
    elif arch == 32:
        numGroupings=8
        formatVal="{:08x} "
    w=0
    for tds in tdsList:

        t=0
        if w % 500 == 0:
            print (w)
        w=w+1
        start=tds.start
        for stack in tds.stackDict:
            stackName=stack[0] 
            stackVal=stack[1]
            if t % numGroupings==0: 
                instructLine += f"\t{stackName} > " + "{0:x}: ".format(start+t)
            instructLine +=formatVal.format(stackVal)
            t=t+1
            if t % numGroupings==0: 
                instructLine+="\n"
        instructLine+="\n"+str(tds.id) + ":  " + tds.asssemblyInst + "\n"
    # print (instructLine)
    stackFile2.write(instructLine)
    stackFile2.close()

def giveStack(uc, arch):
    instructLine = "\n "
    if arch == 32:
        esp_4=UC_X86_REG_ESP-4
        start=  uc.reg_read(UC_X86_REG_ESP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        ESPs = {"esp-0xa0": esp-0xa0, "esp-0x9c": esp-0x9c, "esp-0x98": esp-0x98, "esp-0x94": esp-0x94, "esp-0x90": esp-0x90, "esp-0x8c": esp-0x8c, "esp-0x88": esp-0x88, "esp-0x84": esp-0x84, "esp-0x80": esp-0x80, "esp-0x7c": esp-0x7c, "esp-0x78": esp-0x78, "esp-0x74": esp-0x74, "esp-0x70": esp-0x70, "esp-0x6c": esp-0x6c, "esp-0x68": esp-0x68, "esp-0x64": esp-0x64, "esp-0x60": esp-0x60, "esp-0x5c": esp-0x5c, "esp-0x58": esp-0x58, "esp-0x54": esp-0x54, "esp-0x50": esp-0x50, "esp-0x4c": esp-0x4c, "esp-0x48": esp-0x48, "esp-0x44": esp-0x44, "esp-0x40": esp-0x40, "esp-0x3c": esp-0x3c, "esp-0x38": esp-0x38, "esp-0x34": esp-0x34, "esp-0x30": esp-0x30, "esp-0x2c": esp-0x2c, "esp-0x28": esp-0x28, "esp-0x24": esp-0x24, "esp-0x20": esp-0x20, "esp-0x1c": esp-0x1c, "esp-0x18": esp-0x18, "esp-0x14": esp-0x14, "esp-0x10": esp-0x10, "esp-0xc": esp-0xc, "esp-0x8": esp-8, "esp-0x4": esp-4,"esp     ": esp, "esp+0x4": esp+4,"esp+0x8": esp+8, "esp+0xc": esp+0xc,"esp+0x10": esp+0x10,"esp+0x14": esp+0x14,"esp+0x18": esp+0x18,"esp+0x1c": esp+0x1c,"esp+0x20": esp+0x20,"esp+0x24": esp+0x24,"esp+0x28": esp+0x28,"esp+0x2c": esp+0x2c,"esp+0x30": esp+0x30,"esp+0x34": esp+0x34,"esp+0x38": esp+0x38,"esp+0x3c": esp+0x3c,"esp+0x40": esp+0x40,"esp+0x44": esp+0x44,"esp+0x48": esp+0x48,"esp+0x4c": esp+0x4c,"esp+0x50": esp+0x50,"esp+0x54": esp+0x54,"esp+0x58": esp+0x58,"esp+0x5c": esp+0x5c,"esp+0x60": esp+0x60,"esp+0x64": esp+0x64,"esp+0x68": esp+0x68,"esp+0x6c": esp+0x6c,"esp+0x70": esp+0x70,"esp+0x74": esp+0x74,"esp+0x78": esp+0x78,"esp+0x7c": esp+0x7c,"esp+0x80": esp+0x80,"esp+0x84": esp+0x84,"esp+0x88": esp+0x88,"esp+0x8c": esp+0x8c,"esp+0x90": esp+0x90,"esp+0x94": esp+0x94,"esp+0x98": esp+0x98,"esp+0x9c": esp+0x9c}
    elif arch == 64:
        start=  uc.reg_read(UC_X86_REG_RSP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        RSPs={"rsp-0xa0": rsp-0xa0,  "rsp-0x98": rsp-0x98,  "rsp-0x90": rsp-0x90,  "rsp-0x88": rsp-0x88,  "rsp-0x80": rsp-0x80,  "rsp-0x78": rsp-0x78, "rsp-0x70": rsp-0x70,  "rsp-0x68": rsp-0x68,  "rsp-0x60": rsp-0x60,  "rsp-0x58": rsp-0x58,  "rsp-0x50": rsp-0x50,  "rsp-0x48": rsp-0x48,  "rsp-0x40": rsp-0x40, "rsp-0x38": rsp-0x38, "rsp-0x30": rsp-0x30, "rsp-0x28": rsp-0x28,  "rsp-0x20": rsp-0x20, "rsp-0x18": rsp-0x18,  "rsp-0x10": rsp-0x10,  "rsp-0x8": rsp-8, "rsp     ": rsp,"rsp+0x8": rsp+8,"rsp+0x10": rsp+0x10,"rsp+0x18": rsp+0x18,"rsp+0x20": rsp+0x20,"rsp+0x28": rsp+0x28,"rsp+0x30": rsp+0x30,"rsp+0x38": rsp+0x38,"rsp+0x40": rsp+0x40,"rsp+0x48": rsp+0x48,"rsp+0x50": rsp+0x50,"rsp+0x58": rsp+0x58,"rsp+0x60": rsp+0x60,"rsp+0x68": rsp+0x68,"rsp+0x70": rsp+0x70,"rsp+0x78": rsp+0x78,"rsp+0x80": rsp+0x80,"rsp+0x88": rsp+0x88,"rsp+0x90": rsp+0x90,"rsp+0x98": rsp+0x98}
    if arch == 64:
        stackVals=RSPs.items()
        numGroupings=4
        memReadVal=8
        formatVal="{:016x} "
        memSize=16
    elif arch == 32:
        stackVals=ESPs.items()
        numGroupings=8
        memReadVal=4
        formatVal="{:08x} "
        memSize=8
    t=0

    for regName, regConst in stackVals:
        # regVal = uc.reg_read(regConst)
        regVal = uc.mem_read(regConst,memReadVal)
        regVal= int.from_bytes(regVal, "little")
        # regval=hex(regVal)

        # print (regName, type(regVal),regVal)
        try:
            if t % numGroupings==0 or t == 0: 
                instructLine += f"\t{regName} > " + "{0:x}: ".format(start+(t*memSize))
            # print ("regVal", regVal, type(regVal))
            instructLine +=formatVal.format(regVal)
            t=t+1
            # print ("end", instructLine)
        except Exception as e:
            print ("Error: ", e)
            print(traceback.format_exc())
            if type(regVal) == tuple:
                instructLine += f"{regName}: ???????? " 
                instructLine += str(regVal)

                t=t+1
            else:
                instructLine += f"{regName}: ?! "
                t=t+1
        if t % numGroupings==0: 
            # print ("yes")
            instructLine+="\n"
    instructLine += "\n\n"
    # regVal = uc.mem_read(0x16fffff0,400)
    # print (regVal)
    # print (instructLine)
    # print ("eip", hex(eip), "rsp", hex(rsp), "\n\n")
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
    # ans= ((value >> pos & 1) != 0)
    # print ("\tgetBit", ans, "value", value, "pos", pos)
    # return ans
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
    # print ("boolFollowJump jmpFlag", jmpFlag, "jmpType", jmpType, "zf", getBit(eflags, 6) )
    
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
                'E_UNEXPECTED': 0x8000FFFF, 'TRUE': 0x00000001}
    retValStr=""

    if funcName in rs_dict:
        
        retValStr= rs_dict[funcName]
        if type(retValStr)==int:
            return retValStr, hex(retValStr)
        elif retValStr in rsLookUp:
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