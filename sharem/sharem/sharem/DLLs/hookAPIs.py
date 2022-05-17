from enum import Enum, auto
from random import choice, randint
from unicorn.x86_const import *
from struct import pack, unpack
from ..modules import ADVAPI32_BASE, ADVAPI32_TOP, ADVPACK_BASE, ADVPACK_TOP, BCRYPT_BASE, BCRYPT_TOP, COMCTL32_BASE, COMCTL32_TOP, COMDLG32_BASE, COMDLG32_TOP, CRYPT32_BASE, CRYPT32_TOP, DNSAPI_BASE, DNSAPI_TOP, GDI32_BASE, GDI32_TOP, GDIPLUS_BASE, GDIPLUS_TOP, IMM32_BASE, IMM32_TOP, KERNEL32_BASE, KERNEL32_TOP, KERNELBASE_BASE, KERNELBASE_TOP, MPR_BASE, MPR_TOP, MSCOREE_BASE, MSCOREE_TOP, MSVCRT_BASE, MSVCRT_TOP, NCRYPT_BASE, NCRYPT_TOP, NETAPI32_BASE, NETAPI32_TOP, NETUTILS_BASE, NETUTILS_TOP, NTDLL_BASE, NTDLL_TOP, OLE32_BASE, OLE32_TOP, OLEAUT32_BASE, OLEAUT32_TOP, SAMCLI_BASE, SAMCLI_TOP, SECUR32_BASE, SECUR32_TOP, SHELL32_BASE, SHELL32_TOP, SHLWAPI_BASE, SHLWAPI_TOP, URLMON_BASE, URLMON_TOP, USER32_BASE, USER32_TOP, WININET_BASE, WININET_TOP, WINMM_BASE, WINMM_TOP, WKSCLI_BASE, WKSCLI_TOP, WS2_32_BASE, WS2_32_TOP, WSOCK32_BASE, WSOCK32_TOP, WTSAPI32_BASE, WTSAPI32_TOP, allDllsDict
from ..helper.emuHelpers import Uc
from .structures import struct_PROCESSENTRY32, struct_MODULEENTRY32, struct_THREADENTRY32
import traceback

FakeProcess=0xbadd0000
ProcessCreationReverseLookUp = {16777216: 'CREATE_BREAKAWAY_FROM_JOB', 67108864: 'CREATE_DEFAULT_ERROR_MODE', 16: 'CREATE_NEW_CONSOLE', 512: 'CREATE_NEW_PROCESS_GROUP', 134217728: 'CREATE_NO_WINDOW', 262144: 'CREATE_PROTECTED_PROCESS', 33554432: 'CREATE_PRESERVE_CODE_AUTHZ_LEVEL', 4194304: 'CREATE_SECURE_PROCESS', 2048: 'CREATE_SEPARATE_WOW_VDM', 4096: 'CREATE_SHARED_WOW_VDM', 4: 'CREATE_SUSPENDED', 1024: 'CREATE_UNICODE_ENVIRONMENT', 2: 'DEBUG_ONLY_THIS_PROCESS', 1: 'DEBUG_PROCESS', 8: 'DETACHED_PROCESS', 524288: 'EXTENDED_STARTUPINFO_PRESENT', 65536: 'INHERIT_PARENT_AFFINITY'}
MemLookUp = {'MEM_COMMIT | MEM_RESERVE':'0x3000', 'MEM_COMMIT': '0x1000', 'MEM_FREE': '0x10000', 'MEM_RESERVE': '0x2000', 'MEM_IMAGE': '0x1000000', 'MEM_MAPPED': '0x40000', 'MEM_PRIVATE': '0x20000', 'PAGE_EXECUTE': '0x10', 'PAGE_EXECUTE_READ': '0x20', 'PAGE_EXECUTE_READWRITE': '0x40', 'PAGE_EXECUTE_WRITECOPY': '0x80', 'PAGE_NOACCESS': '0x01', 'PAGE_READONLY': '0x02', 'PAGE_READWRITE': '0x04', 'PAGE_TARGETS_INVALID': '0x40000000', 'PAGE_TARGETS_NO_UPDATE': '0x40000000'}
MemReverseLookUp = {0x3000:'MEM_COMMIT | MEM_RESERVE', 4096: 'MEM_COMMIT', 65536: 'MEM_FREE', 8192: 'MEM_RESERVE', 16777216: 'MEM_IMAGE', 262144: 'MEM_MAPPED', 131072: 'MEM_PRIVATE', 16: 'PAGE_EXECUTE', 32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 1: 'PAGE_NOACCESS', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 1073741824: 'PAGE_TARGETS_NO_UPDATE'}
availMem = 0x25000000
HeapsDict = {} # Dictionary of All Heaps
HandlesDict = {} # Dictionary of All Handles

# Helper Functions
def makeArgVals(uc, eip, esp, export_dict, callAddr, cnt):
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    arg2 = unpack('<I', arg2)[0]
    arg3 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    arg3 = unpack('<I', arg3)[0]
    arg4 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    arg4 = unpack('<I', arg4)[0]
    arg5 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+20, 4)
    arg5 = unpack('<I', arg5)[0]
    arg6 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+24, 4)
    arg6 = unpack('<I', arg6)[0]
    arg7 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+28, 4)
    arg7 = unpack('<I', arg7)[0]
    arg8 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+32, 4)
    arg8 = unpack('<I', arg8)[0]
    arg9 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+36, 4)
    arg9 = unpack('<I', arg9)[0]
    arg10 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+40, 4)
    arg10 = unpack('<I', arg10)[0]
    arg11 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+44, 4)
    arg11 = unpack('<I', arg11)[0]
    arg12 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+48, 4)
    arg12 = unpack('<I', arg12)[0]
    arg13 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+52, 4)
    arg13 = unpack('<I', arg13)[0]
    arg14 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+56, 4)
    arg14 = unpack('<I', arg14)[0]
    arg15 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+60, 4)
    arg15 = unpack('<I', arg15)[0]
    arg16 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+64, 4)
    arg16 = unpack('<I', arg16)[0]

    if cnt==1:
        return [arg1]
    elif cnt==2:
        return [arg1, arg2]
    elif cnt==3:
        return [arg1, arg2, arg3]
    elif cnt==4:
        return [arg1, arg2, arg3, arg4]
    elif cnt==5:
        return [arg1, arg2, arg3, arg4, arg5]
    elif cnt==6:
        return [arg1, arg2, arg3, arg4, arg5, arg6]
    elif cnt==7:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7]
    elif cnt==8:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7,arg8]
    elif cnt==9:
        return [arg1, arg2, arg3, arg4, arg5, arg6,arg7, arg8, arg9]
    elif cnt==10:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10]
    elif cnt==11:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11]
    elif cnt==12:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12]
    elif cnt==13:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13]
    elif cnt==14:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14]
    elif cnt==15:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15]
    elif cnt==16:
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16]

def findStringsParms(uc, pTypes,pVals, skip):
    i=0
    for each in pTypes:
        if i not in skip:
            if "STR" in pTypes[i]: #finding ones with string
                try:
                    # print ("looking", i, pTypes[i], pVals[i])
                    if "WSTR" in pTypes[i]:
                        pVals[i] = read_unicode2(uc, pVals[i])
                    else:
                        pVals[i] = read_string(uc, pVals[i])
                    # print (pVals[i],"*")
                except:
                    # print ("pass", i)
                    pass
            # elif pTypes[i][0] == 'P': # Pointer Builder
            #     try:
            #         pointerVal = getPointerVal(uc,pVals[i])
            #         pVals[i] = buildPtrString(pVals[i], pointerVal)
            #     except:
            #         pass
            else:
                pVals[i] = hex(pVals[i])

        i+=1
    return pTypes, pVals

def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    if c == 0x0: ret = "[NULL]" # Option for NULL String

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret

# New Version Works for More Unicode Chars
# def read_unicode_extended(uc, address):
#     ret = ""
#     mem = uc.mem_read(address, 2)[::-1]
#     read_bytes = 2

#     unicodeString = str(hex(mem[0])) + str(hex(mem[1])[2::])
#     unicodeInt = int(unicodeString, 0)

#     if unicodeInt == 0x0000: ret="NULL" # Option for NULL String

#     while unicodeInt != 0x0000:
#         ret += chr(unicodeInt)
#         mem = uc.mem_read(address + read_bytes, 2)[::-1]
#         unicodeString = str(hex(mem[0])) + str(hex(mem[1])[2::])
#         unicodeInt = int(unicodeString, 0)
#         read_bytes += 2

#     return ret

# Old Version Only Works for First 256/Ascii
def read_unicode2(uc, address):
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

def buildPtrString (pointer, val):
    return hex(pointer) + " -> " + hex(val)

def getPointerVal(uc, pointer):
    val = uc.mem_read(pointer, 4)
    return unpack('<I', val)[0]

def getLookUpVal(search, dictionary: dict):
    if search in dictionary:
        return dictionary[search]
    else:
        return hex(search)

class HandleType(Enum):
    CreateThread = auto()
    CreateRemoteThread = auto()
    SetWindowsHookExA = auto()
    SetWindowsHookExW = auto()
    CreateToolhelp32Snapshot = auto()
    # Internet Handles
    InternetOpenA = auto()
    InternetOpenW = auto()
    InternetConnectA = auto()
    InternetConnectW = auto()
    InternetOpenUrlA = auto()
    InternetOpenUrlW = auto()
    HttpOpenRequestA = auto()
    HttpOpenRequestW = auto()
    FtpOpenFileA = auto()
    FtpOpenFileW = auto()
    # File Handles
    CreateFileA = auto()
    CreateFileW = auto()
    CreateFileMappingA = auto()
    CreateFileMappingW = auto()
    CreateFileMappingNumaA = auto()
    CreateFileMappingNumaW = auto()
    CreateMutexA = auto()
    CreateMutexW = auto()
    CreateMutexExA = auto()
    CreateMutexExW = auto()
    # Service Handles
    OpenSCManagerA = auto()
    OpenSCManagerW = auto()
    CreateServiceA = auto()
    CreateServiceW = auto()

class Handle:
    usedHandles = set()
    def __init__(self, type: HandleType, data = None, handleValue = 0):
        if handleValue == 0:
            # Generate Handle Value
            handleValue = randint(0x10000000,0x1fffffff)
            while handleValue in self.usedHandles:
                handleValue = randint(0x10000000,0x1fffffff)
        self.usedHandles.add(handleValue)
        self.value = handleValue
        self.type = type
        self.data = data
        HandlesDict.update({self.value: self})

class System_SnapShot:
    def __init__(self, fakeThreads: bool, fakeModules: bool):
        self.processOffset = 0
        self.threadOffset = 0
        self.moduleOffset = 0
        self.baseThreadID = 1000
        self.processDict = {4: struct_PROCESSENTRY32(0,10,0,0,'System'), 2688: struct_PROCESSENTRY32(2688,16,0,4,'explorer.exe'), 9172: struct_PROCESSENTRY32(9172,10,2688,10,'calc.exe'), 8280: struct_PROCESSENTRY32(8280,50,2688,16,'chrome.exe'), 11676: struct_PROCESSENTRY32(11676,78,2688,15,'notepad.exe'), 8768: struct_PROCESSENTRY32(8768,20,2688,4,'firefox.exe')}
        self.threadDict: dict[int,struct_THREADENTRY32] = {}
        self.moduleList: list[struct_MODULEENTRY32] = []
        if fakeThreads:
            self.fakeThreads()
        if fakeModules:
            self.fakeModules()
        self.resetOffsets()
    
    def fakeThreads(self):
        for k, v in self.processDict.items(): # Create Fake Threads
            for i in range(v.cntThreads):
                self.threadDict.update({self.baseThreadID: struct_THREADENTRY32(self.baseThreadID,v.th32ProcessID,v.pcPriClassBase)})
                self.baseThreadID += 1

    def fakeModules(self):
        allDllsSizeDict = {'ntdll.dll': NTDLL_TOP-NTDLL_BASE, 'kernel32.dll': KERNEL32_TOP-KERNEL32_BASE, 'KernelBase.dll': KERNELBASE_TOP-KERNELBASE_BASE, 'advapi32.dll': ADVAPI32_TOP-ADVAPI32_BASE, 'comctl32.dll': COMCTL32_TOP-COMCTL32_BASE, 'comdlg32.dll':COMDLG32_TOP-COMDLG32_BASE, 'gdi32.dll': GDI32_TOP-GDI32_BASE, 'gdiplus.dll': GDIPLUS_TOP-GDIPLUS_BASE, 'imm32.dll': IMM32_TOP-IMM32_BASE, 'mscoree.dll': MSCOREE_TOP-MSCOREE_BASE, 'msvcrt.dll': MSVCRT_TOP-MSVCRT_BASE, 'netapi32.dll': NETAPI32_TOP-NETAPI32_BASE, 'ole32.dll': OLE32_TOP-OLE32_BASE, 'oleaut32.dll': OLEAUT32_TOP-OLEAUT32_BASE, 'shell32.dll': SHELL32_TOP-SHELL32_BASE, 'shlwapi.dll': SHLWAPI_TOP-SHLWAPI_BASE, 'urlmon.dll': URLMON_TOP-URLMON_BASE, 'user32.dll': USER32_TOP-USER32_BASE, 'wininet.dll': WININET_TOP-WININET_BASE, 'winmm.dll': WINMM_TOP-WINMM_BASE, 'ws2_32.dll': WS2_32_TOP-WS2_32_BASE, 'wsock32.dll': WSOCK32_TOP-WSOCK32_BASE, 'advpack.dll': ADVPACK_TOP-ADVPACK_BASE, 'bcrypt.dll': BCRYPT_TOP-BCRYPT_BASE, 'crypt32.dll': CRYPT32_TOP-CRYPT32_BASE, 'dnsapi.dll': DNSAPI_TOP-DNSAPI_BASE, 'mpr.dll': MPR_TOP-MPR_BASE, 'ncrypt.dll':NCRYPT_TOP-NCRYPT_BASE, 'netutils.dll': NETUTILS_TOP-NETUTILS_BASE, 'samcli.dll': SAMCLI_TOP-SAMCLI_BASE, 'secur32.dll': SECUR32_TOP-SECUR32_BASE, 'wkscli.dll': WKSCLI_TOP-WKSCLI_BASE, 'wtsapi32.dll': WTSAPI32_TOP-WTSAPI32_BASE}
        for k, v in self.processDict.items():
            moduleCount = randint(2,16) # Add Random Number of Modules
            modules = set()
            for i in range(moduleCount):
                selectedDLL = choice(list(allDllsDict))
                if selectedDLL not in modules:
                    modules.add(selectedDLL)
                    path = "C:\Windows\SysWOW64\\" + selectedDLL
                    self.moduleList.append(struct_MODULEENTRY32(v.th32ProcessID,allDllsDict[selectedDLL],allDllsSizeDict[selectedDLL],allDllsDict[selectedDLL],selectedDLL,path))

    def resetOffsets(self):
        try:
            self.processOffset = list(self.processDict.keys())[0]
            self.threadOffset = list(self.threadDict.keys())[0]
            self.moduleOffset = 0
        except:
            pass


# Custom APIs

# Custom hook for GetProcAddress. Loops through the export dictionary we created, 
# # then returns the address of the indicated function into eax
def hook_GetProcAddress(uc, eip, esp, export_dict, callAddr):
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    arg2 = unpack('<I', arg2)[0]
    arg2 = read_string(uc, arg2)

    retVal = 0

    for api in export_dict:
        if export_dict[api][0] == arg2:
            retVal = api

    # print("Using custom API function...")

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("GetProcAddress", hex(callAddr), hex(retVal), 'FARPROC', [hex(arg1), arg2], ['HMODULE', 'LPCSTR'], ['hModule', 'lpProcName'], False)

    cleanBytes = 8

    return logged_calls, cleanBytes

def hook_GetProcedureAddress(uc, eip, esp, export_dict, callAddr):
    arg1 = uc.mem_read(esp+4, 4)
    arg2 = uc.mem_read(esp+8, 4)
    arg2 = unpack('<I', arg2)[0]
    arg2 = read_string(uc, arg2)
    arg3 = uc.mem_read(esp+12, 4)
    arg4 = uc.mem_read(esp+16, 4)

    retVal = 0

    for api in export_dict:
        if export_dict[api][0] == arg2:
            retVal = api

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("LdrGetProcedureAddress", hex(callAddr), hex(retVal), 'FARPROC', [hex(arg1), arg2], ['HMODULE', 'LPCSTR'], ['hModule', 'lpProcName'], False)

    cleanBytes = 8

    return logged_calls, cleanBytes


def hook_LoadLibraryA(uc, eip, esp, export_dict, callAddr):
    arg1 = uc.mem_read(esp+4, 4)
    arg1 = unpack('<I', arg1)[0]

    # Read arg1 as string. Need to go back and figure out why it won't let
    # us call read_string from emuHelpers in this function only
    try:
        ret = ""
        c = uc.mem_read(arg1, 1)[0]
        read_bytes = 1

        while c != 0x0:
            ret += chr(c)
            c = uc.mem_read(arg1 + read_bytes, 1)[0]
            read_bytes += 1
        arg1 = ret
    except Exception as e:
        print(e)

    # Return base address of passed library
    try:
        retVal = allDllsDict[arg1]
    except:
        try:
            arg1L=arg1.lower()
            retVal=allDllsDict[arg1L]
        except:
            print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", arg1)
            print (hex(eip), (len(arg1)))
            retVal = 0

    uc.reg_write(UC_X86_REG_EAX, retVal)


    logged_calls = ("LoadLibraryA", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1], ['LPCTSTR'], ['lpLibFileName'], False)

    cleanBytes = 4
    return logged_calls, cleanBytes

def hook_LoadLibraryW(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)

    # Return base address of passed library
    try:
        retVal = allDllsDict[arg1]
    except:
        print("Error: The shellcode tried to load a DLL that isn't handled by this tool: ", arg1)
        retVal = 0

    uc.reg_write(UC_X86_REG_EAX, retVal)
    # ("FuncName", hex(callAddr), hex(retVal), 'returnType', [paramValues], [paramTypes], [paramNames], False)
    logged_calls = ("LoadLibraryW", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1], ['LPCTSTR'], ['lpLibFileName'], False)

    cleanBytes = 4
    return logged_calls, cleanBytes

def hook_LoadLibraryExA(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)
    arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    arg2 = unpack('<I', arg2)[0]
    arg3 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    arg3 = unpack('<I', arg3)[0] # Need to add dwFlags when converting to makeArgs

    # Return base address of passed library
    try:
        retVal = allDllsDict[arg1]
    except:
        print("Error: The shellcode tried to load a DLL that isn't handled by this tool: ", arg1)
        retVal = 0

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("LoadLibraryExA", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1, arg2, arg3], ['LPCTSTR', 'HANDLE', 'DWORD'], ['lpLibFileName', 'hFile', 'dwFlags'], False)

    cleanBytes = 12
    return logged_calls, cleanBytes

def hook_LoadLibraryExW(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_unicode2(uc, arg1)
    arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    arg2 = unpack('<I', arg2)[0]
    arg3 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    arg3 = unpack('<I', arg3)[0] # Need to add dwFlags when converting to makeArgs

    # Return base address of passed library
    try:
        retVal = allDllsDict[arg1]
    except:
        print("Error: The shellcode tried to load a DLL that isn't handled by this tool: ", arg1)
        retVal = 0

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("LoadLibraryExW", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1, arg2, arg3], ['LPCTSTR', 'HANDLE', 'DWORD'], ['lpLibFileName', 'hFile', 'dwFlags'], False)

    cleanBytes = 12
    return logged_calls, cleanBytes


def hook_LdrLoadDll(uc, eip, esp, export_dict, callAddr):
    # print("Doing manual function")
    arg1 = uc.mem_read(esp+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)

    arg2 = uc.mem_read(esp+8, 4)
    arg2 = hex(unpack('<I', arg2)[0])

    arg3 = uc.mem_read(esp+12, 4)
    arg3 = unpack('<I', arg3)[0]
    arg3 = uc.mem_read(arg3+4, 4)
    arg3 = unpack('<I', arg3)[0]
    arg3 = read_unicode2(uc, arg3)

    arg4 = uc.mem_read(esp+16, 4)
    arg4 = unpack('<I', arg4)[0]

    # Return base address of passed library
    try:
        retVal = allDllsDict[arg1]
    except:
        try:
            arg3=arg3.lower()
            retVal=allDllsDict[arg3]
        except:
            print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", arg1)
            print(hex(eip), (len(arg1)))
            retVal = 0

    # uc.reg_write(UC_X86_REG_EAX, retVal)
    uc.mem_write(arg4, pack("<Q", retVal))

    check = uc.mem_read(arg4, 4)
    check = unpack('<I', arg4)[0]
    # print("Check: ", check)

    logged_calls = ("LdrLoadDll", hex(callAddr), hex(retVal), 'ModuleHandle', [arg1, arg2, arg3, arg4], ['PWCHAR', 'ULONG', 'PUNICODE_STRING', 'PHANDLE'], ['PathToFile', 'Flags', 'ModuleFileName', 'ModuleHandle'], False)

    cleanBytes = 16
    return logged_calls, cleanBytes

# Heap Functions
class Heap:
    realSize = 4096
    def __init__(self, uc: Uc, handle: int, size: int):
        global availMem
        try:
            self.baseAddress = availMem
            uc.mem_map(self.baseAddress, self.realSize)
            availMem += self.realSize
        except:
            print('Heap Create Failed')
            pass
        self.availableSize = size
        if handle == 0:
            self.handle = self.baseAddress
        else:
            self.handle = handle
        self.allocations: HeapAllocation = {}
        self.usedSize = 0
        HeapsDict.update({self.handle: self})

    def createAllocation(self, uc: Uc, size: int):
        # Check avaible Memory Increase if Necessary
        while (self.usedSize + size) > self.availableSize:
            self.increaseSize()

        newAllocation = HeapAllocation(uc, size)
        self.usedSize = self.usedSize + size
        self.allocations.update({newAllocation.address: newAllocation})
        return newAllocation

    def reAlloc(self, uc: Uc, addr: int, size: int):
        # Check avaible Memory Increase if Necessary
        while (self.usedSize + size) > self.availableSize:
            self.increaseSize()

        newAllo = HeapAllocation(uc, size)
        oldAllo = self.allocations[addr]

        try:
            memory = uc.mem_read(oldAllo.address, oldAllo.size)
            fmt = '<'+ str(oldAllo.size) + 's' 
            uc.mem_write(newAllo.address, pack(fmt, memory))
        except:
            return oldAllo
        
        self.usedSize = self.usedSize - oldAllo.size + size
        self.free(uc, oldAllo.address)
        self.allocations.update({newAllo.address: newAllo})
        return newAllo

    def increaseSize(self):
        # Double or increase By 1/2 or Just Make Enough Room for new Allocation
        # print('Heap Size Increased')
        self.availableSize = self.availableSize * 2

    def free(self, uc: Uc, addr: int):
        if addr in self.allocations:
            uc.mem_unmap(self.allocations[addr].address, self.allocations[addr].size)
            self.usedSize -= self.allocations[addr].size
            self.allocations.pop(addr)

    def destroy(self, uc: Uc):
        for i in self.allocations:
            self.usedSize -= self.allocations[i].size
            uc.mem_unmap(self.allocations[i].address, self.allocations[i].size)
        self.allocations = {}
        uc.mem_unmap(self.baseAddress, self.realSize)
        HeapsDict.pop(self.baseAddress)

    def printInfo(self):
        print('Heap Info')
        print('Handle: ', hex(self.handle))
        print('BaseAddress: ', hex(self.baseAddress))
        print('Used Size: ', self.usedSize)
        print('Total Size: ', self.availableSize)
        print('Allocations: ', len(self.allocations))
        for i in self.allocations:
            print(' Address:', hex(self.allocations[i].address), 'Size:', self.allocations[i].size)

class HeapAllocation:
    def __init__(self, uc: Uc, size: int):
        global availMem
        try:
            self.address = availMem
            self.size = size
            uc.mem_map(self.address, self.size)
            availMem += size
        except:
            print('Heap Allocation Failed')
            pass

def hook_HeapCreate(uc, eip, esp, export_dict, callAddr):
    # HANDLE HeapCreate([in] DWORD  flOptions,[in] SIZE_T dwInitialSize,[in] SIZE_T dwMaximumSize);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['DWORD', 'SIZE_T', 'SIZE_T']
    pNames=['flOptions', 'dwInitialSize', 'dwMaximumSize']
    flOptionsReverseLookUp={0x00040000: 'HEAP_CREATE_ENABLE_EXECUTE', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS', 0x00000001: 'HEAP_NO_SERIALIZE'}

    # Round up to next page (4096)
    pVals[1] = ((pVals[1]//4096)+1) * 4096
    pVals[2] = ((pVals[2]//4096)+1) * 4096

    heap = Heap(uc, 0, pVals[2])

    pVals[0] = getLookUpVal(pVals[0],flOptionsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=heap.handle
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HeapCreate", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HeapAlloc(uc, eip, esp, export_dict, callAddr):
    # DECLSPEC_ALLOCATOR LPVOID HeapAlloc([in] HANDLE hHeap, [in] DWORD  dwFlags, [in] SIZE_T dwBytes)
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['HANDLE', 'DWORD', 'SIZE_T']
    pNames=['hHeap', 'dwFlags', 'dwBytes']
    dwFlagsReverseLookUp={0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS', 0x00000001: 'HEAP_NO_SERIALIZE'}
    
    # Round up to next page (4096)
    pVals[2] = ((pVals[2]//4096)+1) * 4096

    try:
        heap = HeapsDict[pVals[0]]
    except:
        heap = Heap(uc, pVals[0], pVals[2])

    allocation = heap.createAllocation(uc, pVals[2])

    pVals[1] = getLookUpVal(pVals[1],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=allocation.address
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HeapAlloc", hex(callAddr), (retValStr), 'LPVOID', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HeapDestroy(uc, eip, esp, export_dict, callAddr):
    # BOOL HeapDestroy([in] HANDLE hHeap);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 1)
    pTypes=['HANDLE']
    pNames=['hHeap']
    
    try:
        heap = HeapsDict[pVals[0]]
        heap.destroy(uc)
    except:
        pass

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HeapDestroy", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HeapFree(uc, eip, esp, export_dict, callAddr):
    # BOOL HeapFree([in] HANDLE hHeap,[in] DWORD dwFlags,[in] _Frees_ptr_opt_ LPVOID lpMem);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['HANDLE', 'DWORD', '_Frees_ptr_opt_ LPVOID']
    pNames=['hHeap', 'dwFlags', 'lpMem']
    dwFlagsReverseLookUp={0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS', 0x00000001: 'HEAP_NO_SERIALIZE'}

    try:
        heap = HeapsDict[pVals[0]]
        heap.free(uc, pVals[2])
    except:
        pass

    pVals[1] = getLookUpVal(pVals[1],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HeapFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes


def hook_HeapSize(uc, eip, esp, export_dict, callAddr):
    # SIZE_T HeapSize([in] HANDLE  hHeap,[in] DWORD   dwFlags,[in] LPCVOID lpMem);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['HANDLE', 'DWORD', 'LPCVOID']
    pNames=['hHeap', 'dwFlags', 'lpMem']
    dwFlagsReverseLookUp={0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS', 0x00000001: 'HEAP_NO_SERIALIZE'}

    try:
        heap = HeapsDict[pVals[0]]
        if pVals[2] in heap.allocations:
            retVal = heap.allocations[pVals[2]].size
    except:
        retVal = 0x0
        pass

    pVals[1] = getLookUpVal(pVals[1],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HeapSize", hex(callAddr), (retValStr), 'SIZE_T', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HeapReAlloc(uc, eip, esp, export_dict, callAddr):
    # DECLSPEC_ALLOCATOR LPVOID HeapReAlloc([in] HANDLE hHeap,[in] DWORD dwFlags,[in] _Frees_ptr_opt_ LPVOID lpMem,[in] SIZE_T dwBytes);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HANDLE', 'DWORD', '_Frees_ptr_opt_ LPVOID', 'SIZE_T']
    pNames=['hHeap', 'dwFlags', 'lpMem', 'dwBytes']
    dwFlagsReverseLookUp={0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS', 0x00000001: 'HEAP_NO_SERIALIZE', 0x00000010: 'HEAP_REALLOC_IN_PLACE_ONLY'}
    
    # Round up to next page (4096)
    pVals[3] = ((pVals[3]//4096)+1) * 4096

    if pVals[0] in HeapsDict:
        heap = HeapsDict[pVals[0]]
        allocation = heap.reAlloc(uc, pVals[2], pVals[3])
    else:
        heap = Heap(uc, pVals[0], pVals[2])
        allocation = heap.createAllocation(uc, pVals[3])

    pVals[1] = getLookUpVal(pVals[1],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=allocation.address
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HeapReAlloc", hex(callAddr), (retValStr), 'LPVOID', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateToolhelp32Snapshot(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['DWORD', 'DWORD']
    pNames= ['dwFlags', 'th32ProcessID']
    dwFlagsReverseLookUp = {2147483648: 'TH32CS_INHERIT', 15: 'TH32CS_SNAPALL', 1: 'TH32CS_SNAPHEAPLIST', 8: 'TH32CS_SNAPMODULE', 16: 'TH32CS_SNAPMODULE32', 2: 'TH32CS_SNAPPROCESS', 4: 'TH32CS_SNAPTHREAD', 15: 'TH32CS_SNAPALL'}

    SnapShot = System_SnapShot(True, True)
    handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot)

    pVals[0] = getLookUpVal(pVals[0],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateToolhelp32Snapshot", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Process32First(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Process32First([in] HANDLE hSnapshot,[in, out] LPPROCESSENTRY32 lppe);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPPROCESSENTRY32']
    pNames= ['hSnapshot', 'lppe']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get First Process
    if handle.data.processOffset in handle.data.processDict:
        process = handle.data.processDict[handle.data.processOffset]
        process.writeToMemoryA(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE' 

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Process32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Process32Next(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Process32Next([in]  HANDLE hSnapshot,[out] LPPROCESSENTRY32 lppe);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPPROCESSENTRY32']
    pNames= ['hSnapshot', 'lppe']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get Next Process
    try:
        processList = list(handle.data.processDict)
        handle.data.processOffset = processList[processList.index(handle.data.processOffset)+1]
    except:
        handle.data.processOffset = None
        pass

    if handle.data.processOffset in handle.data.processDict:
        process = handle.data.processDict[handle.data.processOffset]
        process.writeToMemoryA(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Process32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes    

def hook_Process32FirstW(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Process32FirstW([in] HANDLE hSnapshot,[in, out] LPPROCESSENTRY32W lppe);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPPROCESSENTRY32W']
    pNames= ['hSnapshot', 'lppe']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get First Process
    if handle.data.processOffset in handle.data.processDict:
        process = handle.data.processDict[handle.data.processOffset]
        process.writeToMemoryW(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'  

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Process32FirstW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Process32NextW(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Process32NextW([in]  HANDLE hSnapshot,[out] LPPROCESSENTRY32W lppe);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPPROCESSENTRY32W']
    pNames= ['hSnapshot', 'lppe']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get Next Process
    try:
        processList = list(handle.data.processDict)
        handle.data.processOffset = processList[processList.index(handle.data.processOffset)+1]
    except:
        handle.data.processOffset = None
        pass

    if handle.data.processOffset in handle.data.processDict:
        process = handle.data.processDict[handle.data.processOffset]
        process.writeToMemoryW(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'  

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Process32NextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Thread32First(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Thread32First([in] HANDLE hSnapshot,[in, out] LPTHREADENTRY32 lpte);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPTHREADENTRY32']
    pNames= ['hSnapshot', 'lpte']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get First Thread
    if handle.data.threadOffset in handle.data.threadDict:
        thread = handle.data.threadDict[handle.data.threadOffset]
        thread.writeToMemory(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'  

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Thread32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Thread32Next(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Thread32Next([in] HANDLE hSnapshot,[out] LPTHREADENTRY32 lpte);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPTHREADENTRY32']
    pNames= ['hSnapshot', 'lpte']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get Next Thread
    try:
        threadList = list(handle.data.threadDict)
        handle.data.threadOffset = threadList[threadList.index(handle.data.threadOffset)+1]
    except:
        handle.data.threadOffset = None
        pass

    if handle.data.threadOffset in handle.data.threadDict:
        thread = handle.data.threadDict[handle.data.threadOffset]
        thread.writeToMemory(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Thread32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Module32First(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Module32First([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32 lpme);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPMODULEENTRY32']
    pNames= ['hSnapshot', 'lpme']
    
    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get First Module
    if handle.data.moduleOffset < len(handle.data.moduleList):
        module = handle.data.moduleList[handle.data.moduleOffset]
        module.writeToMemoryA(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'  

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Module32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Module32Next(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Module32Next([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32 lpme);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPMODULEENTRY32']
    pNames= ['hSnapshot', 'lpme']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get Next Module
    try:
        handle.data.moduleOffset += 1
    except:
        handle.data.moduleOffset = None
        pass

    if handle.data.moduleOffset < len(handle.data.moduleList):
        module = handle.data.moduleList[handle.data.moduleOffset]
        module.writeToMemoryA(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'  

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Module32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Module32FirstW(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Module32FirstW([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32W lpme);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPMODULEENTRY32']
    pNames= ['hSnapshot', 'lpme']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get First Module
    if handle.data.moduleOffset < len(handle.data.moduleList):
        module = handle.data.moduleList[handle.data.moduleOffset]
        module.writeToMemoryW(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'  

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Module32FirstW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Module32NextW(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL Module32NextW([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32W lpme);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['HANDLE', 'LPMODULEENTRY32W']
    pNames= ['hSnapshot', 'lpme']

    # Get Handle
    if pVals[0] in HandlesDict:
        handle = HandlesDict[pVals[0]]
        if handle.type != HandleType.CreateToolhelp32Snapshot:
            handle.data = System_SnapShot(True, True)
            handle.type = HandleType.CreateToolhelp32Snapshot
    else:
        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot, handleValue=pVals[0])

    # Get Next Module
    try:
        handle.data.moduleOffset += 1
    except:
        handle.data.moduleOffset = None
        pass

    if handle.data.moduleOffset < len(handle.data.moduleList):
        module = handle.data.moduleList[handle.data.moduleOffset]
        module.writeToMemoryW(uc, pVals[1])
        retVal=0x1
        retValStr='TRUE'
    else:
        retVal=0x0
        retValStr='FALSE'  

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Module32NextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes


def hook_Toolhelp32ReadProcessMemory2(uc: Uc, eip, esp, export_dict, callAddr):
    # Needs to be Redone
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['DWORD', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T']
    pNames=['th32ProcessID', 'lpBaseAddress', 'lpBuffer', 'cbRead', 'lpNumberOfBytesRead']

    th32ProcessID = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    th32ProcessID = unpack('<I', th32ProcessID)[0]
    lpBaseAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    lpBaseAddress = unpack('<I', lpBaseAddress)[0]
    lpBuffer = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    lpBuffer = unpack('<I', lpBuffer)[0]
    cbRead = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    cbRead = unpack('<I', cbRead)[0]
    lpNumberOfBytesRead = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+20, 4)
    lpNumberOfBytesRead = unpack('<I', lpNumberOfBytesRead)[0]
    global availMem
    # Round up to next page (4096)
    cbRead = ((cbRead//4096)+1) * 4096
    retAddr = 0
    try:
        uc.mem_map(lpBuffer, cbRead)
        retAddr = lpBuffer
    except:
        try:
            allocLoc = availMem
            uc.mem_map(allocLoc, cbRead)
            availMem += cbRead
            lpBuffer = allocLoc
        except:
            success = False
            retAddr = 0xbadd0000

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr ='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("Toolhelp32ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_VirtualAlloc(uc, eip, esp, export_dict, callAddr):
    global availMem

    lpAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    lpAddress = unpack('<I', lpAddress)[0]
    dwSize = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    dwSize = unpack('<I', dwSize)[0]
    flAllocationType = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    flAllocationType = unpack('<I', flAllocationType)[0]
    flProtect = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    flProtect = unpack('<I', flProtect)[0]


    # Round up to next page (4096)
    dwSize = ((dwSize//4096)+1) * 4096

    retVal = 0
    try:
        uc.mem_map(lpAddress, dwSize)
        retVal = lpAddress
        uc.reg_write(UC_X86_REG_EAX, retVal)
    except:
        try:
            allocLoc = availMem
            uc.mem_map(allocLoc, dwSize)
            availMem += dwSize
            uc.reg_write(UC_X86_REG_EAX, allocLoc)
            retVal = allocLoc
        except Exception as e:
            success = False
            retVal = 0xbadd0000
            uc.reg_write(UC_X86_REG_EAX, retVal)

    if flAllocationType in MemReverseLookUp:
        flAllocationType=MemReverseLookUp[flAllocationType]
    else:
        flAllocationType = hex(flAllocationType)

    if flProtect in MemReverseLookUp:
        flProtect=MemReverseLookUp[flProtect]
    else:
        flProtect = hex(flProtect)

    logged_calls = ("VirtualAlloc", hex(callAddr), hex(retVal), 'INT', [hex(lpAddress), hex(dwSize), (flAllocationType), (flProtect)], ['LPVOID', 'SIZE_T', 'DWORD', 'DWORD'], ['lpAddress', 'dwSize', 'flAllocationType', 'flProtect'], False)
    cleanBytes = 16

    return logged_calls, cleanBytes

# Memory Functions
def hook_WriteProcessMemory(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL WriteProcessMemory([in]  HANDLE  hProcess,[in]  LPVOID  lpBaseAddress,[in]  LPCVOID lpBuffer,[in]  SIZE_T  nSize,[out] SIZE_T  *lpNumberOfBytesWritten);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HANDLE', 'LPVOID', 'LPCVOID', 'SIZE_T', 'SIZE_T']
    pNames=['hProcess', 'lpBaseAddress', 'lpBuffer', 'nSize', '*lpNumberOfBytesWritten']
    
    try:
        buffer = uc.mem_read(pVals[2], pVals[3])
        fmt = '<'+ str(pVals[3]) + 's' 
        uc.mem_write(pVals[1], pack(fmt, buffer))
    except:
        pass

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("WriteProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_memcpy(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['void', 'const void', 'size_t']
    pNames=['*dest', '*src', 'count']

    try:
        buffer = uc.mem_read(pVals[1], pVals[2])
        fmt = '<'+ str(pVals[2]) + 's' 
        uc.mem_write(pVals[0], pack(fmt, buffer))
    except:
        pass

    retVal = pVals[0]

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("memcpy", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_memcpy_s(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['void', 'size_t', 'const void', 'size_t']
    pNames=['*dest', 'destSize', '*src', 'count']

    try:
        buffer = uc.mem_read(pVals[2], pVals[3])
        fmt = '<'+ str(pVals[1]) + 's' 
        uc.mem_write(pVals[0], pack(fmt, buffer))
    except:
        pass

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("memcpy_s", hex(callAddr), (retValStr), 'errno_t', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_memmove(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['void', 'const void', 'size_t']
    pNames=['*dest', '*src', 'count']

    try:
        buffer = uc.mem_read(pVals[1], pVals[2])
        fmt = '<'+ str(pVals[2]) + 's' 
        uc.mem_write(pVals[0], pack(fmt, buffer))
    except:
        pass

    retVal = pVals[0]

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("memmove", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_memmove_s(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['void', 'size_t', 'const void', 'size_t']
    pNames=['*dest', 'numberOfElements', '*src', 'count']

    try:
        buffer = uc.mem_read(pVals[2], pVals[3])
        fmt = '<'+ str(pVals[1]) + 's' 
        uc.mem_write(pVals[0], pack(fmt, buffer))
    except:
        pass

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("memcpy_s", hex(callAddr), (retValStr), 'errno_t', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_memset(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['void', 'int', 'size_t']
    pNames=['*dest', 'c', 'count']

    try:
        buffer = uc.mem_read(pVals[0], pVals[2])
        for i in range(pVals[2]):
            buffer[i] = pVals[1]
        fmt = '<'+ str(pVals[2]) + 's'
        uc.mem_write(pVals[0], pack(fmt, buffer))
    except:
        pass

    retVal = pVals[0]

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("memset", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_memcmp(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['const void', 'const void', 'size_t']
    pNames=['*buffer1', '*buffer2', 'count']

    try:
        buffer1 = uc.mem_read(pVals[0], pVals[2])
        buffer2 = uc.mem_read(pVals[1], pVals[2])
        if buffer1[:pVals[2]] == buffer2[:pVals[2]]: # Check if Same
            retVal = 0
        else:
            for i in range(pVals[2]): # Check Byte by Byte
                # print('Index:', i, 'B1:', buffer1[i], 'B2:', buffer2[i])
                if buffer1[i] < buffer2[i]:
                    retVal = -1
                    break
                elif buffer1[i] > buffer2[i]:
                    retVal = 1
                    break 
    except:
        pass

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("memcmp", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_memchr(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['const void', 'int', 'size_t']
    pNames=['*buffer', 'c', 'count']

    try:
        buffer = uc.mem_read(pVals[0], pVals[2])
        if pVals[1] in buffer:
            offset = 0
            for i in buffer:
                if i == pVals[1]:
                    retVal = pVals[0] + offset
                    break
                offset += 1
        else:
            retVal=0
    except:
        pass

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    if retVal == 0:
        retValStr='NULL'
    else:
        retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("memchr", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_RtlMoveMemory(uc: Uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['VOID UNALIGNED', 'VOID UNALIGNED', 'SIZE_T']
    pNames=['*Destination', '*Source', 'Length']

    try:
        buffer = uc.mem_read(pVals[1], pVals[2])
        fmt = '<'+ str(pVals[2]) + 's' 
        uc.mem_write(pVals[0], pack(fmt, buffer))
    except:
        pass


    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=''

    logged_calls= ("RtlMoveMemory", hex(callAddr), (retValStr), 'VOID', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ReadProcessMemory(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL ReadProcessMemory([in]  HANDLE  hProcess,[in]  LPCVOID lpBaseAddress,[out] LPVOID  lpBuffer,[in]  SIZE_T  nSize,[out] SIZE_T  *lpNumberOfBytesRead);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HANDLE', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T']
    pNames=['hProcess', 'lpBaseAddress', 'lpBuffer', 'nSize', '*lpNumberOfBytesRead']

    try:
        buffer = uc.mem_read(pVals[1], pVals[3])
        fmt = '<'+ str(pVals[3]) + 's' 
        uc.mem_write(pVals[2], pack(fmt, buffer))
        if pVals[4] != 0x0:
            uc.mem_write(pVals[4], pack('<i', pVals[4]))
    except:
        pass

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)


    logged_calls= ("ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ExitProcess(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    uExitCode = uc.mem_read(esp+4, 4)
    uExitCode = unpack('<I', uExitCode)[0]

    cleanBytes = 4
    logged_calls = ("ExitProcess", hex(callAddr), 'None', '', [uExitCode], ['UINT'],  ['uExitCode'], False)
    return logged_calls, cleanBytes

def hook_CreateFileA(uc, eip, esp, export_dict, callAddr):
    """  HANDLE CreateFile(
      LPCTSTR lpFileName, // pointer to name of the file
      DWORD dwDesiredAccess,      // access (read-write) mode
      DWORD dwShareMode,      // share mode
      LPSECURITY_ATTRIBUTES lpSecurityAttributes,      // pointer to security attributes
      DWORD dwCreationDistribution,      // how to create
      DWORD dwFlagsAndAttributes,      // file attributes
      HANDLE hTemplateFile      // handle to file with attributes to copy
      );
'CreateFile': (2, ['LPCTSTR', 'DWORD'], ['lpFileName', 'dwDesiredAccess'], 'HANDLE'),
      """
    lpFileName = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    lpFileName = unpack('<I', lpFileName)[0]
    lpFileName = read_string(uc, lpFileName)

    dwDesiredAccess = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    dwDesiredAccess = unpack('<I', dwDesiredAccess)[0]
    dwShareMode = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    dwShareMode = unpack('<I', dwShareMode)[0]
    lpSecurityAttributes = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    lpSecurityAttributes = unpack('<I', lpSecurityAttributes)[0]
    dwCreationDistribution = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+20, 4)
    dwCreationDistribution = unpack('<I', dwCreationDistribution)[0]
    dwFlagsAndAttributes = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+24, 4)
    dwFlagsAndAttributes = unpack('<I', dwFlagsAndAttributes)[0]
    hTemplateFile = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+28, 4)
    hTemplateFile = unpack('<I', hTemplateFile)[0]

    retVal=FakeProcess
    uc.reg_write(UC_X86_REG_EAX, retVal)

    createDispoReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING', 3: 'OPEN_EXISTING'}
    dwShareReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE'}
    dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
    if dwCreationDistribution in createDispoReverseLookUp:
        dwCreationDistribution= createDispoReverseLookUp[dwCreationDistribution]
    else:
        dwCreationDistribution=hex(dwCreationDistribution)
    if dwShareMode in dwShareReverseLookUp:
        dwShareMode=dwShareReverseLookUp[dwShareMode]
    else:
        dwShareMode=hex(dwShareMode)
    if dwDesiredAccess in dwAccessReverseLookUp:
        dwDesiredAccess =dwAccessReverseLookUp[dwDesiredAccess]
    else:
        dwDesiredAccess=hex(dwDesiredAccess)
    cleanBytes = 28
    logged_calls = ("CreateFileA", hex(callAddr), hex(retVal), 'HANDLE', [hex(lpFileName), dwDesiredAccess, dwShareMode,hex(lpSecurityAttributes), dwCreationDistribution,hex(dwFlagsAndAttributes), hex(hTemplateFile)], ["LPCSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD", "HANDLE"], ["lpFileName", "dwDesiredAccess", "dwShareMode","lpSecurityAttributes", "dwCreationDistribution","dwFlagsAndAttributes", "hTemplateFile"],False)

    return logged_calls, cleanBytes

def hook_CreateFileW(uc, eip, esp, export_dict, callAddr):
    # HANDLE CreateFileW([in] LPCWSTR lpFileName,[in] DWORD dwDesiredAccess,[in] DWORD dwShareMode,[in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,[in] DWORD dwCreationDisposition,[in] DWORD dwFlagsAndAttributes,[in, optional] HANDLE hTemplateFile);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 8)
    pTypes=['LPCWSTR', 'lpFileName', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'HANDLE']
    pNames= ["lpFileName", "dwDesiredAccess", "dwShareMode","lpSecurityAttributes", "dwCreationDistribution","dwFlagsAndAttributes", "hTemplateFile"]
    dwDesiredAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
    dwShareModeReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE', 4: 'FILE_SHARE_DELETE'}
    dwCreationDistributionReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING', 3: 'OPEN_EXISTING', 5: 'TRUNCATE_EXISTING'}
    dwFlagsAndAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 16384: 'FILE_ATTRIBUTE_ENCRYPTED', 2: 'FILE_ATTRIBUTE_HIDDEN', 128: 'FILE_ATTRIBUTE_NORMAL', 4096: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY', 4: 'FILE_ATTRIBUTE_SYSTEM', 256: 'FILE_ATTRIBUTE_TEMPORARY', 33554432: 'FILE_FLAG_BACKUP_SEMANTICS', 67108864: 'FILE_FLAG_DELETE_ON_CLOSE', 536870912: 'FILE_FLAG_NO_BUFFERING', 1048576: 'FILE_FLAG_OPEN_NO_RECALL', 2097152: 'FILE_FLAG_OPEN_REPARSE_POINT', 1073741824: 'FILE_FLAG_OVERLAPPED', 16777216: 'FILE_FLAG_POSIX_SEMANTICS', 268435456: 'FILE_FLAG_RANDOM_ACCESS', 8388608: 'FILE_FLAG_SESSION_AWARE', 134217728: 'FILE_FLAG_SEQUENTIAL_SCAN', 2147483648: 'FILE_FLAG_WRITE_THROUGH'}
    
    handle = Handle(HandleType.CreateFileW)

    pVals[1] = getLookUpVal(pVals[1],dwDesiredAccessReverseLookUp)
    pVals[2] = getLookUpVal(pVals[2],dwShareModeReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4],dwCreationDistributionReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwFlagsAndAttributesReverseLookUp)

    # create strings for everything except ones in our skip
    skip=[1,2,4,5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateFileW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateProcessA(uc, eip, esp, export_dict, callAddr):
    # print ("hook_CreateProcessA2")
    """'CreateProcess': (10, ['LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION'], ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation'], 'BOOL'),"""

    # function to get values for parameters - count as specified at the end - returned as a list
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 10)
    pTypes=['LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
    pNames=['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']

    pVals[5] = getLookUpVal(pVals[5],ProcessCreationReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateProcessA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateProcessW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 10)
    pTypes=['LPCWSTR', 'LPWSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCWSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
    pNames=['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']

    pVals[5] = getLookUpVal(pVals[5],ProcessCreationReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateProcessW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_URLDownloadToFileA(uc, eip, esp, export_dict, callAddr):
    # function to get values for parameters - count as specified at the end - returned as a list
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['LPUNKNOWN', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
    pNames=['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='S_OK'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("URLDownloadToFileA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_URLDownloadToFileW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['LPUNKNOWN', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
    pNames=['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='S_OK'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("URLDownloadToFileW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_WinExec(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPCSTR', 'UINT']
    pNames=['lpCmdLine', 'uCmdShow']
    cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE', 4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE', 8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

    pVals[1] = getLookUpVal(pVals[1],cmdShowReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("WinExec", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ShellExecuteA(uc, eip, esp, export_dict, callAddr):
    # HINSTANCE ShellExecuteA([in, optional] HWND   hwnd, [in, optional] LPCSTR lpOperation,[in] LPCSTR lpFile,
    # [in, optional] LPCSTR lpParameters, [in, optional] LPCSTR lpDirectory, [in] INT    nShowCmd);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'INT']
    pNames=['hwnd', 'lpOperation', 'lpFile', 'lpParameters', 'lpDirectory', 'nShowCmd']
    cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE', 4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE', 8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}
    
    pVals[5] = getLookUpVal(pVals[5],cmdShowReverseLookUp)

    # create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ShellExecuteA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ShellExecuteW(uc, eip, esp, export_dict, callAddr):
    # HINSTANCE ShellExecuteW([in, optional] HWND   hwnd, [in, optional] LPCSTR lpOperation,[in] LPCSTR lpFile,
    # [in, optional] LPCSTR lpParameters, [in, optional] LPCSTR lpDirectory, [in] INT    nShowCmd);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['HWND', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'INT']
    pNames=['hwnd', 'lpOperation', 'lpFile', 'lpParameters', 'lpDirectory', 'nShowCmd']
    cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE', 4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE', 8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}
    
    pVals[5] = getLookUpVal(pVals[5],cmdShowReverseLookUp)

    # create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ShellExecuteW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_VirtualProtect(uc, eip, esp, export_dict, callAddr):
    # BOOL VirtualProtect([in]  LPVOID lpAddress,[in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect)
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
    pNames= ['lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']

    pVals[2] = getLookUpVal(pVals[2],MemReverseLookUp)

    # create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("VirtualProtect", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_VirtualProtectEx(uc, eip, esp, export_dict, callAddr):
    # BOOL VirtualProtectEx([in]  HANDLE hProcess, [in]  LPVOID lpAddress, [in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
    pNames= ['hProcess', 'lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']

    pVals[3] = getLookUpVal(pVals[3],MemReverseLookUp)

    # create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("VirtualProtectEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_VirtualFree(uc, eip, esp, export_dict, callAddr):
    # 'VirtualFree': (3, ['LPVOID', 'SIZE_T', 'DWORD'], ['lpAddress', 'dwSize', 'dwFreeType'], 'BOOL'), 
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPVOID', 'SIZE_T', 'DWORD']
    pNames=['lpAddress', 'dwSize', 'dwFreeType']
    memReleaseReverseLookUp = {16384: 'MEM_DECOMMIT', 32768: 'MEM_RELEASE', 1: 'MEM_COALESCE_PLACEHOLDERS', 2: 'MEM_PRESERVE_PLACEHOLDER', 0x00004001: 'MEM_DECOMMIT | MEM_COALESCE_PLACEHOLDERS', 0x00004002: 'MEM_DECOMMIT | MEM_PRESERVE_PLACEHOLDER', 0x00008001: 'MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS', 0x00008002: 'MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER'}
    
    pVals[2] = getLookUpVal(pVals[2],memReleaseReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("VirtualFree", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_WSASocketA(uc, eip, esp, export_dict, callAddr):
    # 'WSASocketA': (6, ['INT', 'INT', 'INT', 'LPWSAPROTOCOL_INFOA', 'GROUP', 'DWORD'], ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags'], 'SOCKET'),
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['int', 'int', 'int', 'LPWSAPROTOCOL_INFOA', 'GROUP', 'DWORD']
    pNames= ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags']
    aFReverseLookUp = {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 22: 'AF_APPLETALK', 23: 'AF_NETBIOS', 35: 'AF_INET6', 38: 'AF_IRDA', 50: 'AF_BTH'}
    sockTypeReverseLookUp = {1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 4: 'SOCK_RDM', 5: 'SOCK_SEQPACKET'}
    sockProtocolReverseLookUp = {1: 'IPPROTO_ICMP', 2: 'IPPROTO_IGMP', 3: 'BTHPROTO_RFCOMM', 6: 'IPPROTO_TCP', 23: 'IPPROTO_UDP', 88: 'IPPROTO_ICMPV6', 275: 'IPPROTO_RM'}
    dwFlagsReverseLookUp = {1: 'WSA_FLAG_OVERLAPPED', 2: 'WSA_FLAG_MULTIPOINT_C_ROOT', 4: 'WSA_FLAG_MULTIPOINT_C_LEAF', 8: 'WSA_FLAG_MULTIPOINT_D_ROOT', 16: 'WSA_FLAG_MULTIPOINT_D_LEAF', 64: 'WSA_FLAG_ACCESS_SYSTEM_SECURITY', 128: 'WSA_FLAG_NO_HANDLE_INHERIT'}
    groupReverseLookUp = {1: 'SG_UNCONSTRAINED_GROUP', 2: 'SG_CONSTRAINED_GROUP'}

    pVals[0] = getLookUpVal(pVals[0],aFReverseLookUp)
    pVals[1] = getLookUpVal(pVals[1],sockTypeReverseLookUp)
    pVals[2] = getLookUpVal(pVals[2],sockProtocolReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4],groupReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[0,1,2,4,5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("WSASocketA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_WSASocketW(uc, eip, esp, export_dict, callAddr):
    # 'WSASocketW': (6, ['INT', 'INT', 'INT', 'LPWSAPROTOCOL_INFOW', 'GROUP', 'DWORD'], ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags'], 'SOCKET'),
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['int', 'int', 'int', 'LPWSAPROTOCOL_INFOW', 'GROUP', 'DWORD']
    pNames= ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags']
    aFReverseLookUp = {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 16: 'AF_APPLETALK', 17: 'AF_NETBIOS', 23: 'AF_INET6', 26: 'AF_IRDA', 32: 'AF_BTH'}
    sockTypeReverseLookUp = {1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 4: 'SOCK_RDM', 5: 'SOCK_SEQPACKET'}
    sockProtocolReverseLookUp = {1: 'IPPROTO_ICMP', 2: 'IPPROTO_IGMP', 3: 'BTHPROTO_RFCOMM', 6: 'IPPROTO_TCP', 17: 'IPPROTO_UDP', 58: 'IPPROTO_ICMPV6', 113: 'IPPROTO_RM'}
    groupReverseLookUp = {1: 'SG_UNCONSTRAINED_GROUP', 2: 'SG_CONSTRAINED_GROUP'}
    dwFlagsReverseLookUp = {1: 'WSA_FLAG_OVERLAPPED', 2: 'WSA_FLAG_MULTIPOINT_C_ROOT', 4: 'WSA_FLAG_MULTIPOINT_C_LEAF', 8: 'WSA_FLAG_MULTIPOINT_D_ROOT', 16: 'WSA_FLAG_MULTIPOINT_D_LEAF', 64: 'WSA_FLAG_ACCESS_SYSTEM_SECURITY', 128: 'WSA_FLAG_NO_HANDLE_INHERIT'}
    
    pVals[0] = getLookUpVal(pVals[0],aFReverseLookUp)
    pVals[1] = getLookUpVal(pVals[1],sockTypeReverseLookUp)
    pVals[2] = getLookUpVal(pVals[2],sockProtocolReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4],groupReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[0,1,2,4,5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("WSASocketW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_socket(uc, eip, esp, export_dict, callAddr):
    # SOCKET WSAAPI socket([in] int af, [in] int type, [in] int protocol)
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['int', 'int', 'int']
    pNames= ['af', 'type', 'protocol']
    aFReverseLookUp = {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 16: 'AF_APPLETALK', 17: 'AF_NETBIOS', 23: 'AF_INET6', 26: 'AF_IRDA', 32: 'AF_BTH'}
    sockTypeReverseLookUp = {1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 4: 'SOCK_RDM', 5: 'SOCK_SEQPACKET'}
    sockProtocolReverseLookUp = {1: 'IPPROTO_ICMP', 2: 'IPPROTO_IGMP', 3: 'BTHPROTO_RFCOMM', 6: 'IPPROTO_TCP', 17: 'IPPROTO_UDP', 58: 'IPPROTO_ICMPV6', 113: 'IPPROTO_RM'}

    pVals[0] = getLookUpVal(pVals[0],aFReverseLookUp)
    pVals[1] = getLookUpVal(pVals[1],sockTypeReverseLookUp)
    pVals[2] = getLookUpVal(pVals[2],sockProtocolReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[0,1,2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("socket", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_BroadcastSystemMessageA(uc, eip, esp, export_dict, callAddr):
    # long BroadcastSystemMessage([in] DWORD   flags, [in, out, optional] LPDWORD lpInfo, 
    # [in] UINT Msg, [in]  WPARAM  wParam, [in]  LPARAM  lParam );
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['DWORD', 'LPDWORD', 'UINT', 'WPARAM', 'LPARAM']
    pNames= ['flags', 'lpInfo', 'Msg', 'wParam', 'lParam']
    flagsReverseLookUp = {0x00000080: 'BSF_ALLOWSFW', 0x00000004: 'BSF_FLUSHDISK', 0x00000020: 'BSF_FORCEIFHUNG', 0x00000002: 'BSF_IGNORECURRENTTASK', 0x00000008: 'BSF_NOHANG', 0x00000040: 'BSF_NOTIMEOUTIFNOTHUNG', 0x00000010: 'BSF_POSTMESSAGE', 0x00000001: 'BSF_QUERY', 0x00000100: 'BSF_SENDNOTIFYMESSAGE'}
    lpInfoReverseLookUp = {0x00000000: 'BSM_ALLCOMPONENTS', 0x00000010: 'BSM_ALLDESKTOPS', 0x00000008: 'BSM_APPLICATIONS'}

    pVals[0] = getLookUpVal(pVals[0],flagsReverseLookUp)
    pVals[1] = getLookUpVal(pVals[1],lpInfoReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[0,1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("BroadcastSystemMessageA", hex(callAddr), (retValStr), 'long', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_BroadcastSystemMessageW(uc, eip, esp, export_dict, callAddr):
    # long BroadcastSystemMessage([in] DWORD   flags, [in, out, optional] LPDWORD lpInfo, 
    # [in] UINT Msg, [in]  WPARAM  wParam, [in]  LPARAM  lParam );
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['DWORD', 'LPDWORD', 'UINT', 'WPARAM', 'LPARAM']
    pNames= ['flags', 'lpInfo', 'Msg', 'wParam', 'lParam']
    flagsReverseLookUp = {0x00000080: 'BSF_ALLOWSFW', 0x00000004: 'BSF_FLUSHDISK', 0x00000020: 'BSF_FORCEIFHUNG', 0x00000002: 'BSF_IGNORECURRENTTASK', 0x00000008: 'BSF_NOHANG', 0x00000040: 'BSF_NOTIMEOUTIFNOTHUNG', 0x00000010: 'BSF_POSTMESSAGE', 0x00000001: 'BSF_QUERY', 0x00000100: 'BSF_SENDNOTIFYMESSAGE'}
    lpInfoReverseLookUp = {0x00000000: 'BSM_ALLCOMPONENTS', 0x00000010: 'BSM_ALLDESKTOPS', 0x00000008: 'BSM_APPLICATIONS'}

    pVals[0] = getLookUpVal(pVals[0],flagsReverseLookUp)
    pVals[1] = getLookUpVal(pVals[1],lpInfoReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[0,1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("BroadcastSystemMessageW", hex(callAddr), (retValStr), 'long', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

# SysCalls
def hook_NtTerminateProcess(uc, eip, esp, callAddr):
    handle = uc.mem_read(esp+4, 4)
    handle = unpack('<I', handle)[0]
    ntstatus = uc.mem_read(esp+8, 4)
    ntstatus = unpack('<I', ntstatus)[0]

    retVal = 1

    logged_calls = ("NtTerminateProcess", hex(callAddr), hex(retVal), 'INT', [hex(handle), hex(ntstatus)], ['HANDLE', 'NTSTATUS'], ['ProcessHandle', 'ExitStatus'], False)
    return logged_calls

def hook_NtAllocateVirtualMemory(uc, eip, esp, callAddr):
    global availMem
    global address_range

    processHandle = uc.mem_read(esp+4, 4)
    processHandle = unpack('<I', processHandle)[0]
    baseAddress = uc.mem_read(esp+8, 4)
    baseAddress = unpack('<I', baseAddress)[0]
    zeroBits = uc.mem_read(esp+12, 4)
    zeroBits = unpack('<I', zeroBits)[0]
    regionSize = uc.mem_read(esp+16, 4)
    regionSize = unpack('<I', regionSize)[0]
    allocationType = uc.mem_read(esp + 20, 4)
    allocationType = unpack('<I', allocationType)[0]
    protect = uc.mem_read(esp + 24, 4)
    protect = unpack('<I', protect)[0]

    # Get pointer values
    allocLoc = getPointerVal(uc, baseAddress)
    size = getPointerVal(uc, regionSize)

    size = ((size//4096)+1) * 4096

    retVal = 0
    try:
        uc.mem_map(allocLoc, size)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        address_range.append([allocLoc, size])

        tmp = uc.mem_read(baseAddress, 4)
        tmp = unpack('<I', tmp)[0]
    except Exception as e:
        print("Error: ", e)
        print(traceback.format_exc())
        try:
            allocLoc = availMem
            uc.mem_map(allocLoc, size)
            address_range.append([allocLoc, size])

            availMem += regionSize
            uc.reg_write(UC_X86_REG_EAX, retVal)
            uc.mem_write(baseAddress, pack("<Q", allocLoc))

            tmp = uc.mem_read(baseAddress, 4)
            tmp = unpack('<I', tmp)[0]
        except Exception as e:
            print("Error: ", e)
            print(traceback.format_exc())
            print ("VirtualAlloc Function Failed")
            success = False
            retVal = 0xbadd0000
            uc.reg_write(UC_X86_REG_EAX, retVal)

    if allocationType in MemReverseLookUp:
        flAllocationType=MemReverseLookUp[allocationType]
    else:
        flAllocationType = hex(allocationType)

    if protect in MemReverseLookUp:
        flProtect=MemReverseLookUp[protect]
    else:
        flProtect = hex(protect)

    baseAddress = buildPtrString(baseAddress, allocLoc)
    regionSize = buildPtrString(regionSize, size)

    logged_calls = ("NtAllocateVirtualMemory", hex(callAddr), hex(retVal), 'INT', [hex(processHandle), baseAddress, hex(zeroBits), regionSize, hex(allocationType), hex(protect)], ['HANDLE', 'PVOID', 'ULONG_PTR', 'PSIZE_T', 'ULONG', 'ULONG'], ['ProcessHandle', '*BaseAddress', 'ZeroBits', '*RegionSize', 'AllocationType', 'Protect'], False)

    return logged_calls

def hook_CreateThread(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
    pNames= ['lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpThreadId']
    dwCreateFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

    pVals[4] = getLookUpVal(pVals[4],dwCreateFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00616161 # Implement handle later
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateServiceA(uc, eip, esp, export_dict, callAddr):
    # SC_HANDLE CreateServiceA([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 13)
    pTypes=['SC_HANDLE', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'LPCSTR', 'LPDWORD', 'LPCSTR', 'LPCSTR', 'LPCSTR']
    pNames=['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType', 'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies', 'lpServiceStartName', 'lpPassword']
    dwDesiredAccessReverseLookUp={0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
    dwServiceTypeReverseLookUp={0x00000004: 'SERVICE_ADAPTER', 0x00000002: 'SERVICE_FILE_SYSTEM_DRIVER', 0x00000001: 'SERVICE_KERNEL_DRIVER', 0x00000008: 'SERVICE_RECOGNIZER_DRIVER', 0x00000010: 'SERVICE_WIN32_OWN_PROCESS', 0x00000020: 'SERVICE_WIN32_SHARE_PROCESS', 0x00000100: 'SERVICE_INTERACTIVE_PROCESS'}
    dwStartTypeReverseLookUp={0x00000002: 'SERVICE_AUTO_START', 0x00000000: 'SERVICE_BOOT_START', 0x00000003: 'SERVICE_DEMAND_START', 0x00000004: 'SERVICE_DISABLED', 0x00000001: 'SERVICE_SYSTEM_START'}
    dwErrorControlReverseLookUp={0x00000003: 'SERVICE_ERROR_CRITICAL', 0x00000000: 'SERVICE_ERROR_IGNORE', 0x00000001: 'SERVICE_ERROR_NORMAL', 0x00000002: 'SERVICE_ERROR_SEVERE'}

    handle = Handle(HandleType.CreateServiceA)

    pVals[3] = getLookUpVal(pVals[3],dwDesiredAccessReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4],dwServiceTypeReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwStartTypeReverseLookUp)
    pVals[6] = getLookUpVal(pVals[6],dwErrorControlReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3,4,5,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateServiceA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateServiceW(uc, eip, esp, export_dict, callAddr):
    # SC_HANDLE CreateServiceW([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 13)
    pTypes=['SC_HANDLE', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR', 'LPCWSTR', 'LPDWORD', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR']
    pNames=['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType', 'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies', 'lpServiceStartName', 'lpPassword']
    dwDesiredAccessReverseLookUp={0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
    dwServiceTypeReverseLookUp={0x00000004: 'SERVICE_ADAPTER', 0x00000002: 'SERVICE_FILE_SYSTEM_DRIVER', 0x00000001: 'SERVICE_KERNEL_DRIVER', 0x00000008: 'SERVICE_RECOGNIZER_DRIVER', 0x00000010: 'SERVICE_WIN32_OWN_PROCESS', 0x00000020: 'SERVICE_WIN32_SHARE_PROCESS', 0x00000100: 'SERVICE_INTERACTIVE_PROCESS'}
    dwStartTypeReverseLookUp={0x00000002: 'SERVICE_AUTO_START', 0x00000000: 'SERVICE_BOOT_START', 0x00000003: 'SERVICE_DEMAND_START', 0x00000004: 'SERVICE_DISABLED', 0x00000001: 'SERVICE_SYSTEM_START'}
    dwErrorControlReverseLookUp={0x00000003: 'SERVICE_ERROR_CRITICAL', 0x00000000: 'SERVICE_ERROR_IGNORE', 0x00000001: 'SERVICE_ERROR_NORMAL', 0x00000002: 'SERVICE_ERROR_SEVERE'}

    handle = Handle(HandleType.CreateServiceW)

    pVals[3] = getLookUpVal(pVals[3],dwDesiredAccessReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4],dwServiceTypeReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwStartTypeReverseLookUp)
    pVals[6] = getLookUpVal(pVals[6],dwErrorControlReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3,4,5,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateServiceW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetOpenA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['LPCSTR', 'DWORD', 'LPCSTR', 'LPCSTR', 'DWORD']
    pNames= ['lpszAgent', 'dwAccessType', 'lpszProxy', 'lpszProxyBypass', 'dwFlags']

    dwAccessTypeReverseLookUp = {0: 'INTERNET_OPEN_TYPE_PRECONFIG', 1: 'INTERNET_OPEN_TYPE_DIRECT', 3: 'INTERNET_OPEN_TYPE_PROXY', 4: 'INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY'}
    dwFlagsReverseLookUp = {268435456: 'INTERNET_FLAG_ASYNC', 16777216: 'INTERNET_FLAG_FROM_CACHE'}

    pVals[1] = getLookUpVal(pVals[4],dwAccessTypeReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4],dwFlagsReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1,4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00626262
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetOpenA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetOpenW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['LPCWSTR', 'DWORD', 'LPCWSTR', 'LPCWSTR', 'DWORD']
    pNames= ['lpszAgent', 'dwAccessType', 'lpszProxy', 'lpszProxyBypass', 'dwFlags']

    dwAccessTypeReverseLookUp = {0: 'INTERNET_OPEN_TYPE_PRECONFIG', 1: 'INTERNET_OPEN_TYPE_DIRECT', 3: 'INTERNET_OPEN_TYPE_PROXY', 4: 'INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY'}
    dwFlagsReverseLookUp = {268435456: 'INTERNET_FLAG_ASYNC', 16777216: 'INTERNET_FLAG_FROM_CACHE'}

    pVals[1] = getLookUpVal(pVals[4],dwAccessTypeReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4],dwFlagsReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1,4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00737373
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetOpenW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes


def hook_InternetConnectA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 8)
    pTypes=['HINTERNET', 'LPCSTR', 'INTERNET_PORT', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hInternet', 'lpszServerName', 'nServerPort', 'lpszUserName', 'lpszPassword', 'dwService', 'dwFlags', 'dwContext']

    nServerPortReverseLookUp = {0: 'INTERNET_INVALID_PORT_NUMBER', 33: 'INTERNET_DEFAULT_FTP_PORT', 112: 'INTERNET_DEFAULT_GOPHER_PORT', 128: 'INTERNET_DEFAULT_HTTP_PORT', 1091: 'INTERNET_DEFAULT_HTTPS_PORT', 4224: 'INTERNET_DEFAULT_SOCKS_PORT'}
    dwServiceReverseLookUp = {1: 'INTERNET_SERVICE_FTP', 2: 'INTERNET_SERVICE_GOPHER', 3: 'INTERNET_SERVICE_HTTP'}
    dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 134217728: 'INTERNET_FLAG_PASSIVE', 1: 'WININET_API_FLAG_ASYNC', 4: 'WININET_API_FLAG_SYNC'}
    
    pVals[2] = getLookUpVal(pVals[2],nServerPortReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwServiceReverseLookUp)
    pVals[6] = getLookUpVal(pVals[6],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,5,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00636363
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetConnectA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetConnectW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 8)
    pTypes=['HINTERNET', 'LPCWSTR', 'INTERNET_PORT', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hInternet', 'lpszServerName', 'nServerPort', 'lpszUserName', 'lpszPassword', 'dwService', 'dwFlags', 'dwContext']

    nServerPortReverseLookUp = {0: 'INTERNET_INVALID_PORT_NUMBER', 33: 'INTERNET_DEFAULT_FTP_PORT', 112: 'INTERNET_DEFAULT_GOPHER_PORT', 128: 'INTERNET_DEFAULT_HTTP_PORT', 1091: 'INTERNET_DEFAULT_HTTPS_PORT', 4224: 'INTERNET_DEFAULT_SOCKS_PORT'}
    dwServiceReverseLookUp = {1: 'INTERNET_SERVICE_FTP', 2: 'INTERNET_SERVICE_GOPHER', 3: 'INTERNET_SERVICE_HTTP'}
    dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 134217728: 'INTERNET_FLAG_PASSIVE', 1: 'WININET_API_FLAG_ASYNC', 4: 'WININET_API_FLAG_SYNC'}

    pVals[2] = getLookUpVal(pVals[2],nServerPortReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwServiceReverseLookUp)
    pVals[6] = getLookUpVal(pVals[6],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,5,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00727272
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetConnectW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateRemoteThread(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HANDLE', 'LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
    pNames= ['hProcess', 'lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpThreadId']

    dwCreationFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

    pVals[5] = getLookUpVal(pVals[5],dwCreationFlagsReverseLookUp)
        
    #create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00646464
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateRemoteThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_VirtualAllocEx(uc, eip, esp, export_dict, callAddr):
    global availMem

    hProcess = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    hProcess = unpack('<I', hProcess)[0]
    lpAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    lpAddress = unpack('<I', lpAddress)[0]
    dwSize = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    dwSize = unpack('<I', dwSize)[0]
    flAllocationType = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    flAllocationType = unpack('<I', flAllocationType)[0]
    flProtect = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+20, 4)
    flProtect = unpack('<I', flProtect)[0]

    # Round up to next page (4096)
    dwSize = ((dwSize//4096)+1) * 4096

    retVal = 0
    try:
        uc.mem_map(lpAddress, dwSize)
        retVal = lpAddress
        uc.reg_write(UC_X86_REG_EAX, retVal)
    except:
        try:
            allocLoc = availMem
            uc.mem_map(allocLoc, dwSize)
            availMem += dwSize
            uc.reg_write(UC_X86_REG_EAX, allocLoc)
            retVal = allocLoc
        except:
            success = False
            retVal = 0xbaddd000
            uc.reg_write(UC_X86_REG_EAX, retVal)

    if flAllocationType in MemReverseLookUp:
        flAllocationType=MemReverseLookUp[flAllocationType]
    else:
        flAllocationType = hex(flAllocationType)

    if flProtect in MemReverseLookUp:
        flProtect=MemReverseLookUp[flProtect]
    else:
        flProtect = hex(flProtect)

    logged_calls = ("VirtualAllocEx", hex(callAddr), hex(retVal), 'INT', [hex(hProcess), hex(lpAddress), hex(dwSize), (flAllocationType), (flProtect)], ['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'DWORD'], ['hProcess', 'lpAddress', 'dwSize', 'flAllocationType', 'flProtect'], False)
    cleanBytes = 20

    return logged_calls, cleanBytes

def hook_RegCreateKeyExA(uc, eip, esp, export_dict, callAddr):
    # LSTATUS RegCreateKeyExA([in] HKEY hKey,[in] LPCSTR lpSubKey,DWORD Reserved,[in, optional]  LPSTR lpClass,[in] DWORD dwOptions,[in] REGSAM samDesired,[in, optional] const LPSECURITY_ATTRIBUTES lpSecurityAttributes,[out] PHKEY phkResult,[out, optional] LPDWORD lpdwDisposition);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 9)
    pTypes=['HKEY', 'LPCSTR', 'DWORD', 'LPSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD']
    pNames= ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes', 'phkResult', 'lpdwDisposition']
    dwOptionsReverseLookUp={4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK', 0: 'REG_OPTION_NON_VOLATILE', 1: 'REG_OPTION_VOLATILE'}
    samDesiredReverseLookUp = {983103: 'KEY_ALL_ACCESS', 32:'KEY_CREATE_LINK', 4: 'KEY_CREATE_SUB_KEY', 8: 'KEY_ENUMERATE_SUB_KEYS', 131097: 'KEY_READ', 16: 'KEY_NOTIFY', 1: 'KEY_QUERY_VALUE', 2: 'KEY_SET_VALUE',512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY', 131078: 'KEY_WRITE'}
    lpdwDispostitionReverseLookUp={1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}

    pVals[4] = getLookUpVal(pVals[4],dwOptionsReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],samDesiredReverseLookUp)
    pVals[8] = getLookUpVal(pVals[8],lpdwDispostitionReverseLookUp)

    # create strings for everything except ones in our skip
    skip=[4,5,8]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='ERROR_SUCCESS'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("RegCreateKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_RegCreateKeyExW(uc, eip, esp, export_dict, callAddr):
    # LSTATUS RegCreateKeyExA([in] HKEY hKey,[in] LPCSTR lpSubKey,DWORD Reserved,[in, optional]  LPSTR lpClass,[in] DWORD dwOptions,[in] REGSAM samDesired,[in, optional] const LPSECURITY_ATTRIBUTES lpSecurityAttributes,[out] PHKEY phkResult,[out, optional] LPDWORD lpdwDisposition);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 9)
    pTypes=['HKEY', 'LPCWSTR', 'DWORD', 'LPWSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD']
    pNames= ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes', 'phkResult', 'lpdwDisposition']
    dwOptionsReverseLookUp={4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK', 0: 'REG_OPTION_NON_VOLATILE', 1: 'REG_OPTION_VOLATILE'}
    samDesiredReverseLookUp = {983103: 'KEY_ALL_ACCESS', 32:'KEY_CREATE_LINK', 4: 'KEY_CREATE_SUB_KEY', 8: 'KEY_ENUMERATE_SUB_KEYS', 131097: 'KEY_READ', 16: 'KEY_NOTIFY', 1: 'KEY_QUERY_VALUE', 2: 'KEY_SET_VALUE',512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY', 131078: 'KEY_WRITE'}
    lpdwDispostitionReverseLookUp={1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}

    pVals[4] = getLookUpVal(pVals[4],dwOptionsReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],samDesiredReverseLookUp)
    pVals[8] = getLookUpVal(pVals[8],lpdwDispostitionReverseLookUp)

    # create strings for everything except ones in our skip
    skip=[4,5,8]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='ERROR_SUCCESS'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("RegCreateKeyExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_RegDeleteKeyExA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HKEY', 'LPCSTR', 'REGSAM', 'DWORD']
    pNames= ['hKey', 'lpSubKey', 'samDesired', 'Reserved']

    samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

    pVals[2] = getLookUpVal(pVals[2],samDesiredReverseLookUp)
        
    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='ERROR_SUCCESS'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("RegDeleteKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_RegDeleteKeyExW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HKEY', 'LPCWSTR', 'REGSAM', 'DWORD']
    pNames= ['hKey', 'lpSubKey', 'samDesired', 'Reserved']

    samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

    pVals[2] = getLookUpVal(pVals[2],samDesiredReverseLookUp)
        
    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='ERROR_SUCCESS'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("RegDeleteKeyExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_RegGetValueA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HKEY', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPDWORD', 'PVOID', 'LPDWORD']
    pNames= ['hKey', 'lpSubKey', 'lpValue', 'dwFlags', 'pdwType', 'pvData', 'pcbData']

    dwFlagsReverseLookUp = {65535: 'RRF_RT_ANY', 24: 'RRF_RT_DWORD', 72: 'RRF_RT_QWORD', 8: 'RRF_RT_REG_BINARY', 16: 'RRF_RT_REG_DWORD', 4: 'RRF_RT_REG_EXPAND_SZ', 32: 'RRF_RT_REG_MULTI_SZ', 1: 'RRF_RT_REG_NONE', 64: 'RRF_RT_REG_QWORD', 2: 'RRF_RT_REG_SZ', 268435456: 'RRF_NOEXPAND', 536870912: 'RRF_ZEROONFAILURE', 65536: 'RRF_SUBKEY_WOW6464KEY', 131072: 'RRF_SUBKEY_WOW6432KEY'}

    pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)
        
    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='ERROR_SUCCESS'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("RegGetValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_RegGetValueW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HKEY', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPDWORD', 'PVOID', 'LPDWORD']
    pNames= ['hKey', 'lpSubKey', 'lpValue', 'dwFlags', 'pdwType', 'pvData', 'pcbData']

    dwFlagsReverseLookUp = {65535: 'RRF_RT_ANY', 24: 'RRF_RT_DWORD', 72: 'RRF_RT_QWORD', 8: 'RRF_RT_REG_BINARY', 16: 'RRF_RT_REG_DWORD', 4: 'RRF_RT_REG_EXPAND_SZ', 32: 'RRF_RT_REG_MULTI_SZ', 1: 'RRF_RT_REG_NONE', 64: 'RRF_RT_REG_QWORD', 2: 'RRF_RT_REG_SZ', 268435456: 'RRF_NOEXPAND', 536870912: 'RRF_ZEROONFAILURE', 65536: 'RRF_SUBKEY_WOW6464KEY', 131072: 'RRF_SUBKEY_WOW6432KEY'}

    pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr='ERROR_SUCCESS'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("RegGetValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CryptDecrypt(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['HCRYPTKEY', 'HCRYPTHASH', 'BOOL', 'DWORD', 'BYTE', 'DWORD']
    pNames= ['hKey', 'hHash', 'Final', 'dwFlags', 'pbData', 'pdwDataLen']

    dwFlagsReverseLookUp = {64: 'CRYPT_OAEP', 32: 'CRYPT_DECRYPT_RSA_NO_PADDING_CHECK'}

    pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CryptDecrypt", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_SetWindowsHookExA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['int', 'HOOKPROC', 'HINSTANCE', 'DWORD']
    pNames= ['idHook', 'lpfn', 'hmod', 'dwThreadId']

    idHookReverseLookUp = {4: 'WH_CALLWNDPROC', 18: 'WH_CALLWNDPROCRET', 5: 'WH_CBT', 9: 'WH_DEBUG', 17: 'WH_FOREGROUNDIDLE', 3: 'WH_GETMESSAGE', 1: 'WH_JOURNALPLAYBACK', 0: 'WH_JOURNALRECORD', 2: 'WH_KEYBOARD', 19: 'WH_KEYBOARD_LL', 7: 'WH_MOUSE', 20: 'WH_MOUSE_LL', -1: 'WH_MSGFILTER', 16: 'WH_SHELL', 6: 'WH_SYSMSGFILTER'}

    pVals[0] = getLookUpVal(pVals[0],idHookReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00656565
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("SetWindowsHookExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_SetWindowsHookExW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['int', 'HOOKPROC', 'HINSTANCE', 'DWORD']
    pNames= ['idHook', 'lpfn', 'hmod', 'dwThreadId']

    idHookReverseLookUp = {4: 'WH_CALLWNDPROC', 18: 'WH_CALLWNDPROCRET', 5: 'WH_CBT', 9: 'WH_DEBUG', 17: 'WH_FOREGROUNDIDLE', 3: 'WH_GETMESSAGE', 1: 'WH_JOURNALPLAYBACK', 0: 'WH_JOURNALRECORD', 2: 'WH_KEYBOARD', 19: 'WH_KEYBOARD_LL', 7: 'WH_MOUSE', 20: 'WH_MOUSE_LL', -1: 'WH_MSGFILTER', 16: 'WH_SHELL', 6: 'WH_SYSMSGFILTER'}

    pVals[0] = getLookUpVal(pVals[0],idHookReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00717171
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("SetWindowsHookExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_shutdown(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['SOCKET', 'int']
    pNames= ['s', 'how']

    howReverseLookUp = {0: 'SD_RECEIVE', 1: 'SD_SEND', 2: 'SD_BOTH'}

    pVals[1] = getLookUpVal(pVals[1],howReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x0
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("shutdown", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ReplaceFileA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['LPCSTR', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPVOID', 'LPVOID']
    pNames= ['lpReplacedFileName', 'lpReplacementFileName', 'lpBackupFileName', 'dwReplaceFlags', 'lpExclude', 'lpReserved']

    dwReplaceFlagsReverseLookUp = {1: 'REPLACEFILE_WRITE_THROUGH', 2: 'REPLACEFILE_IGNORE_MERGE_ERRORS', 4: 'REPLACEFILE_IGNORE_ACL_ERRORS'}

    pVals[3] = getLookUpVal(pVals[3],dwReplaceFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ReplaceFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ReplaceFileW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPVOID', 'LPVOID']
    pNames= ['lpReplacedFileName', 'lpReplacementFileName', 'lpBackupFileName', 'dwReplaceFlags', 'lpExclude', 'lpReserved']

    dwReplaceFlagsReverseLookUp = {1: 'REPLACEFILE_WRITE_THROUGH', 2: 'REPLACEFILE_IGNORE_MERGE_ERRORS', 4: 'REPLACEFILE_IGNORE_ACL_ERRORS'}

    pVals[3] = getLookUpVal(pVals[3],dwReplaceFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ReplaceFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ReadDirectoryChangesW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 8)
    pTypes=['HANDLE', 'LPVOID', 'DWORD', 'BOOL', 'DWORD', 'LPDWORD', 'LPOVERLAPPED', 'LPOVERLAPPED_COMPLETION_ROUTINE']
    pNames= ['hDirectory', 'lpBuffer', 'nBufferLength', 'bWatchSubtree', 'dwNotifyFilter', 'lpBytesReturned', 'lpOverlapped', 'lpCompletionRoutine']

    dwNotifyFilterReverseLookUp = {1: 'FILE_NOTIFY_CHANGE_FILE_NAME', 2: 'FILE_NOTIFY_CHANGE_DIR_NAME', 4: 'FILE_NOTIFY_CHANGE_ATTRIBUTES', 8: 'FILE_NOTIFY_CHANGE_SIZE', 16: 'FILE_NOTIFY_CHANGE_LAST_WRITE', 32: 'FILE_NOTIFY_CHANGE_LAST_ACCESS', 64: 'FILE_NOTIFY_CHANGE_CREATION', 256: 'FILE_NOTIFY_CHANGE_SECURITY'}

    pVals[4] = getLookUpVal(pVals[4],dwNotifyFilterReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ReadDirectoryChangesW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetCombineUrlA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['LPCSTR', 'LPCSTR', 'LPSTR', 'LPDWORD', 'DWORD']
    pNames= ['lpszBaseUrl', 'lpszRelativeUrl', 'lpszBuffer', 'lpdwBufferLength', 'dwFlags']

    dwFlagsReverseLookUp = {536870912: 'ICU_NO_ENCODE', 268435456: 'ICU_DECODE', 134217728: 'ICU_NO_META', 67108864: 'ICU_ENCODE_SPACES_ONLY', 33554432: 'ICU_BROWSER_MODE', 4096: 'ICU_ENCODE_PERCENT'}

    pVals[4] = getLookUpVal(pVals[4],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetCombineUrlA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetCombineUrlW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['LPCWSTR', 'LPCWSTR', 'LPWSTR', 'LPDWORD', 'DWORD']
    pNames= ['lpszBaseUrl', 'lpszRelativeUrl', 'lpszBuffer', 'lpdwBufferLength', 'dwFlags']

    dwFlagsReverseLookUp = {536870912: 'ICU_NO_ENCODE', 268435456: 'ICU_DECODE', 134217728: 'ICU_NO_META', 67108864: 'ICU_ENCODE_SPACES_ONLY', 33554432: 'ICU_BROWSER_MODE', 4096: 'ICU_ENCODE_PERCENT'}

    pVals[4] = getLookUpVal(pVals[4],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetCombineUrlW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ExitWindowsEx(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['UINT', 'DWORD']
    pNames= ['uFlags', 'dwReason']

    uFlagsReverseLookUp = {4194304: 'EWX_HYBRID_SHUTDOWN', 0: 'EWX_LOGOFF', 8: 'EWX_POWEROFF', 2: 'EWX_REBOOT', 64: 'EWX_RESTARTAPPS', 1: 'EWX_SHUTDOWN', 4: 'EWX_FORCE', 16: 'EWX_FORCEIFHUNG'}
    dwReasonReverseLookUp = {262144: 'SHTDN_REASON_MAJOR_APPLICATION', 65536: 'SHTDN_REASON_MAJOR_HARDWARE', 458752: 'SHTDN_REASON_MAJOR_LEGACY_API', 131072: 'SHTDN_REASON_MAJOR_OPERATINGSYSTEM', 0: 'SHTDN_REASON_MINOR_OTHER', 393216: 'SHTDN_REASON_MAJOR_POWER', 196608: 'SHTDN_REASON_MAJOR_SOFTWARE', 327680: 'SHTDN_REASON_MAJOR_SYSTEM', 15: 'SHTDN_REASON_MINOR_BLUESCREEN', 11: 'SHTDN_REASON_MINOR_CORDUNPLUGGED', 7: 'SHTDN_REASON_MINOR_DISK', 12: 'SHTDN_REASON_MINOR_ENVIRONMENT', 13: 'SHTDN_REASON_MINOR_HARDWARE_DRIVER', 17: 'SHTDN_REASON_MINOR_HOTFIX', 23: 'SHTDN_REASON_MINOR_HOTFIX_UNINSTALL', 5: 'SHTDN_REASON_MINOR_HUNG', 2: 'SHTDN_REASON_MINOR_INSTALLATION', 1: 'SHTDN_REASON_MINOR_MAINTENANCE', 25: 'SHTDN_REASON_MINOR_MMC', 20: 'SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY', 9: 'SHTDN_REASON_MINOR_NETWORKCARD', 14: 'SHTDN_REASON_MINOR_OTHERDRIVER', 10: 'SHTDN_REASON_MINOR_POWER_SUPPLY', 8: 'SHTDN_REASON_MINOR_PROCESSOR', 4: 'SHTDN_REASON_MINOR_RECONFIG', 19: 'SHTDN_REASON_MINOR_SECURITY', 18: 'SHTDN_REASON_MINOR_SECURITYFIX', 24: 'SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL', 16: 'SHTDN_REASON_MINOR_SERVICEPACK', 22: 'SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL', 32: 'SHTDN_REASON_MINOR_TERMSRV', 6: 'SHTDN_REASON_MINOR_UNSTABLE', 3: 'SHTDN_REASON_MINOR_UPGRADE', 21: 'SHTDN_REASON_MINOR_WMI', 1073741824: 'SHTDN_REASON_FLAG_USER_DEFINED', 2147483648: 'SHTDN_REASON_FLAG_PLANNED'}

    pVals[0] = getLookUpVal(pVals[0], uFlagsReverseLookUp)
    pVals[1] = getLookUpVal(pVals[1],dwReasonReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[0,1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ExitWindowsEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_SetFileAttributesA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPCSTR', 'DWORD']
    pNames= ['lpFileName', 'dwFileAttributes']

    dwFileAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 2: 'FILE_ATTRIBUTE_HIDDEN', 128: 'FILE_ATTRIBUTE_NORMAL', 8192: 'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED', 4096: 'FILE_ATTRIBUTE_OFFLINE', 4: 'FILE_ATTRIBUTE_SYSTEM', 256: 'FILE_ATTRIBUTE_TEMPORARY'}

    pVals[1] = getLookUpVal(pVals[1], dwFileAttributesReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("SetFileAttributesA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_SetFileAttributesW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPCWSTR', 'DWORD']
    pNames= ['lpFileName', 'dwFileAttributes']

    dwFileAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 2: 'FILE_ATTRIBUTE_HIDDEN', 128: 'FILE_ATTRIBUTE_NORMAL', 8192: 'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED', 4096: 'FILE_ATTRIBUTE_OFFLINE', 4: 'FILE_ATTRIBUTE_SYSTEM', 256: 'FILE_ATTRIBUTE_TEMPORARY'}

    pVals[1] = getLookUpVal(pVals[1], dwFileAttributesReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("SetFileAttributesW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ControlService(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['SC_HANDLE', 'DWORD', 'LPSERVICE_STATUS']
    pNames= ['hService', 'dwControl', 'lpServiceStatus']

    dwControlReverseLookUp = {3: 'SERVICE_CONTROL_CONTINUE', 4: 'SERVICE_CONTROL_INTERROGATE', 7: 'SERVICE_CONTROL_NETBINDADD', 10: 'SERVICE_CONTROL_NETBINDDISABLE', 9: 'SERVICE_CONTROL_NETBINDENABLE', 8: 'SERVICE_CONTROL_NETBINDREMOVE', 6: 'SERVICE_CONTROL_PARAMCHANGE', 2: 'SERVICE_CONTROL_PAUSE', 1: 'SERVICE_CONTROL_STOP'}

    pVals[1] = getLookUpVal(pVals[1],dwControlReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ControlService", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateFileMappingA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR']
    pNames= ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName']

    flProtectReverseLookUp = {2: 'PAGE_READONLY', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT', 16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES', 268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}
    
    pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00676767
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateFileMappingA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateFileMappingW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR']
    pNames= ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName']

    flProtectReverseLookUp = {2: 'PAGE_READONLY', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT', 16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES', 268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}

    pVals[2] = getLookUpVal(pVals[2],flProtectReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00707070
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateFileMappingW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CryptAcquireContextA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HCRYPTPROV', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD']
    pNames= ['phProv', 'szContainer', 'szProvider', 'dwProvType', 'dwFlags']

    dwProvTypeReverseLookUp = {1: 'PROV_RSA_FULL', 2: 'PROV_RSA_SIG', 3: 'PROV_DSS', 4: 'PROV_FORTEZZA', 5: 'PROV_MS_EXCHANGE', 6: 'PROV_SSL', 18: 'PROV_RSA_SCHANNEL', 19: 'PROV_DSS_DH', 24: 'PROV_DH_SCHANNEL', 36: 'PROV_RSA_AES'}
    dwFlagsReverseLookUp = {4026531840: 'CRYPT_VERIFYCONTEXT', 8: 'CRYPT_NEWKEYSET', 16: 'CRYPT_DELETEKEYSET', 32: 'CRYPT_MACHINE_KEYSET', 64: 'CRYPT_SILENT', 128: 'CRYPT_DEFAULT_CONTAINER_OPTIONAL'}

    pVals[3] = getLookUpVal(pVals[3],dwProvTypeReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3,4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CryptAcquireContextA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CryptAcquireContextW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HCRYPTPROV', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD']
    pNames= ['phProv', 'szContainer', 'szProvider', 'dwProvType', 'dwFlags']

    dwProvTypeReverseLookUp = {1: 'PROV_RSA_FULL', 2: 'PROV_RSA_SIG', 3: 'PROV_DSS', 4: 'PROV_FORTEZZA', 5: 'PROV_MS_EXCHANGE', 6: 'PROV_SSL', 18: 'PROV_RSA_SCHANNEL', 19: 'PROV_DSS_DH', 24: 'PROV_DH_SCHANNEL', 36: 'PROV_RSA_AES'}
    dwFlagsReverseLookUp = {4026531840: 'CRYPT_VERIFYCONTEXT', 8: 'CRYPT_NEWKEYSET', 16: 'CRYPT_DELETEKEYSET', 32: 'CRYPT_MACHINE_KEYSET', 64: 'CRYPT_SILENT', 128: 'CRYPT_DEFAULT_CONTAINER_OPTIONAL'}

    pVals[3] = getLookUpVal(pVals[3],dwProvTypeReverseLookUp)
    pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3,4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CryptAcquireContextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_OpenSCManagerA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPCSTR', 'LPCSTR', 'DWORD']
    pNames= ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']

    dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE', 1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE', 8: 'SC_MANAGER_LOCK', 32: 'SC_MANAGER_MODIFY_BOOT_CONFIG', 16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

    pVals[2] = getLookUpVal(pVals[2],dwDesiredAccessReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00686868
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("OpenSCManagerA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_OpenSCManagerW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPCWSTR', 'LPCWSTR', 'DWORD']
    pNames= ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']

    dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE', 1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE', 8: 'SC_MANAGER_LOCK', 32: 'SC_MANAGER_MODIFY_BOOT_CONFIG', 16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

    pVals[2] = getLookUpVal(pVals[2],dwDesiredAccessReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00696969
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("OpenSCManagerW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_FtpPutFileA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HINTERNET', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszLocalFile', 'lpszNewRemoteFile', 'dwFlags', 'dwContext']

    dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII', 2: 'FTP_TRANSFER_TYPE_BINARY', 1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

    pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("FtpPutFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_FtpPutFileW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszLocalFile', 'lpszNewRemoteFile', 'dwFlags', 'dwContext']

    dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII', 2: 'FTP_TRANSFER_TYPE_BINARY', 1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

    pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("FtpPutFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetQueryOptionA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD']
    pNames= ['hInternet', 'dwOption', 'lpBuffer', 'lpdwBufferLength']

    dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC', 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY', 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE', 105: 'INTERNET_OPTION_CACHE_TIMESTAMPS', 1: 'INTERNET_OPTION_CALLBACK', 84: 'INTERNET_OPTION_CALLBACK_FILTER', 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH', 4: 'INTERNET_OPTION_CONNECT_BACKOFF', 3: 'INTERNET_OPTION_CONNECT_RETRIES', 85: 'INTERNET_OPTION_CONNECT_TIME', 2: 'INTERNET_OPTION_CONNECT_TIMEOUT', 80: 'INTERNET_OPTION_CONNECTED_STATE', 69: 'INTERNET_OPTION_CONTEXT_VALUE', 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT', 5: 'INTERNET_OPTION_SEND_TIMEOUT', 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT', 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT', 51: 'INTERNET_OPTION_DATAFILE_NAME', 103: 'INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO', 112: 'INTERNET_OPTION_DISABLE_AUTODIAL', 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT', 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL', 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA', 98: 'INTERNET_OPTION_ERROR_MASK', 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT', 36: 'INTERNET_OPTION_EXTENDED_ERROR', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT', 9: 'INTERNET_OPTION_HANDLE_TYPE', 343: 'INTERNET_OPTION_HSTS', 101: 'INTERNET_OPTION_HTTP_DECODING', 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED', 89: 'INTERNET_OPTION_HTTP_VERSION', 120: 'INTERNET_OPTION_IDENTITY', 81: 'INTERNET_OPTION_IDLE_STATE', 119: 'INTERNET_OPTION_IGNORE_OFFLINE', 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT', 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER', 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER', 38: 'INTERNET_OPTION_OFFLINE_MODE', 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS', 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE', 33: 'INTERNET_OPTION_PARENT_HANDLE', 41: 'INTERNET_OPTION_PASSWORD', 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY', 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD', 67: 'INTERNET_OPTION_PROXY_USERNAME', 18: 'INTERNET_OPTION_READ_BUFFER_SIZE', 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT', 121: 'INTERNET_OPTION_REMOVE_IDENTITY', 35: 'INTERNET_OPTION_REQUEST_FLAGS', 88: 'INTERNET_OPTION_REQUEST_PRIORITY', 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 53: 'INTERNET_OPTION_SECURITY_CERTIFICATE', 50: 'INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT', 49: 'INTERNET_OPTION_SECURITY_FLAGS', 54: 'INTERNET_OPTION_SECURITY_KEY_BITNESS', 86: 'INTERNET_OPTION_SEND_THROUGHPUT', 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT', 129: 'INTERNET_OPTION_SUPPRESS_BEHAVIOR', 52: 'INTERNET_OPTION_URL', 65: 'INTERNET_OPTION_USER_AGENT', 40: 'INTERNET_OPTION_USERNAME', 64: 'INTERNET_OPTION_VERSION', 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

    pVals[1] = getLookUpVal(pVals[1], dwOptionReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetQueryOptionA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetQueryOptionW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD']
    pNames= ['hInternet', 'dwOption', 'lpBuffer', 'lpdwBufferLength']

    dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC', 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY', 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE', 105: 'INTERNET_OPTION_CACHE_TIMESTAMPS', 1: 'INTERNET_OPTION_CALLBACK', 84: 'INTERNET_OPTION_CALLBACK_FILTER', 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH', 4: 'INTERNET_OPTION_CONNECT_BACKOFF', 3: 'INTERNET_OPTION_CONNECT_RETRIES', 85: 'INTERNET_OPTION_CONNECT_TIME', 2: 'INTERNET_OPTION_CONNECT_TIMEOUT', 80: 'INTERNET_OPTION_CONNECTED_STATE', 69: 'INTERNET_OPTION_CONTEXT_VALUE', 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT', 5: 'INTERNET_OPTION_SEND_TIMEOUT', 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT', 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT', 51: 'INTERNET_OPTION_DATAFILE_NAME', 103: 'INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO', 112: 'INTERNET_OPTION_DISABLE_AUTODIAL', 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT', 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL', 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA', 98: 'INTERNET_OPTION_ERROR_MASK', 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT', 36: 'INTERNET_OPTION_EXTENDED_ERROR', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT', 9: 'INTERNET_OPTION_HANDLE_TYPE', 343: 'INTERNET_OPTION_HSTS', 101: 'INTERNET_OPTION_HTTP_DECODING', 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED', 89: 'INTERNET_OPTION_HTTP_VERSION', 120: 'INTERNET_OPTION_IDENTITY', 81: 'INTERNET_OPTION_IDLE_STATE', 119: 'INTERNET_OPTION_IGNORE_OFFLINE', 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT', 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER', 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER', 38: 'INTERNET_OPTION_OFFLINE_MODE', 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS', 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE', 33: 'INTERNET_OPTION_PARENT_HANDLE', 41: 'INTERNET_OPTION_PASSWORD', 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY', 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD', 67: 'INTERNET_OPTION_PROXY_USERNAME', 18: 'INTERNET_OPTION_READ_BUFFER_SIZE', 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT', 121: 'INTERNET_OPTION_REMOVE_IDENTITY', 35: 'INTERNET_OPTION_REQUEST_FLAGS', 88: 'INTERNET_OPTION_REQUEST_PRIORITY', 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 53: 'INTERNET_OPTION_SECURITY_CERTIFICATE', 50: 'INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT', 49: 'INTERNET_OPTION_SECURITY_FLAGS', 54: 'INTERNET_OPTION_SECURITY_KEY_BITNESS', 86: 'INTERNET_OPTION_SEND_THROUGHPUT', 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT', 129: 'INTERNET_OPTION_SUPPRESS_BEHAVIOR', 52: 'INTERNET_OPTION_URL', 65: 'INTERNET_OPTION_USER_AGENT', 40: 'INTERNET_OPTION_USERNAME', 64: 'INTERNET_OPTION_VERSION', 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

    pVals[1] = getLookUpVal(pVals[1],dwOptionReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetQueryOptionW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetSetOptionA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HINTERNET', 'DWORD', 'LPVOID', 'DWORD']
    pNames= ['hInternet', 'dwOption', 'lpBuffer', 'dwBufferLength']

    dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC', 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY', 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE', 1: 'INTERNET_OPTION_CALLBACK', 84: 'INTERNET_OPTION_CALLBACK_FILTER', 132: 'INTERNET_OPTION_CLIENT_CERT_CONTEXT', 104: 'INTERNET_OPTION_CODEPAGE', 256: 'INTERNET_OPTION_CODEPAGE_PATH', 257: 'INTERNET_OPTION_CODEPAGE_EXTRA', 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH', 4: 'INTERNET_OPTION_CONNECT_BACKOFF', 3: 'INTERNET_OPTION_CONNECT_RETRIES', 85: 'INTERNET_OPTION_CONNECT_TIME', 2: 'INTERNET_OPTION_CONNECT_TIMEOUT', 80: 'INTERNET_OPTION_CONNECTED_STATE', 69: 'INTERNET_OPTION_CONTEXT_VALUE', 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT', 5: 'INTERNET_OPTION_SEND_TIMEOUT', 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT', 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT', 150: 'INTERNET_OPTION_DATAFILE_EXT', 118: 'INTERNET_OPTION_DIGEST_AUTH_UNLOAD', 112: 'INTERNET_OPTION_DISABLE_AUTODIAL', 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT', 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL', 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA', 66: 'INTERNET_OPTION_END_BROWSER_SESSION', 98: 'INTERNET_OPTION_ERROR_MASK', 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT', 343: 'INTERNET_OPTION_HSTS', 101: 'INTERNET_OPTION_HTTP_DECODING', 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED', 89: 'INTERNET_OPTION_HTTP_VERSION', 120: 'INTERNET_OPTION_IDENTITY', 81: 'INTERNET_OPTION_IDLE_STATE', 258: 'INTERNET_OPTION_IDN', 119: 'INTERNET_OPTION_IGNORE_OFFLINE', 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT', 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER', 259: 'INTERNET_OPTION_MAX_CONNS_PER_PROXY', 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER', 38: 'INTERNET_OPTION_OFFLINE_MODE', 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS', 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE', 41: 'INTERNET_OPTION_PASSWORD', 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY', 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD', 149: 'INTERNET_OPTION_PROXY_SETTINGS_CHANGED', 67: 'INTERNET_OPTION_PROXY_USERNAME', 18: 'INTERNET_OPTION_READ_BUFFER_SIZE', 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT', 55: 'INTERNET_OPTION_REFRESH', 121: 'INTERNET_OPTION_REMOVE_IDENTITY', 88: 'INTERNET_OPTION_REQUEST_PRIORITY', 96: 'INTERNET_OPTION_RESET_URLCACHE_SESSION', 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 86: 'INTERNET_OPTION_SEND_THROUGHPUT', 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT', 57: 'INTERNET_OPTION_SETTINGS_CHANGED', 260: 'INTERNET_OPTION_SUPPRESS_SERVER_AUTH', 65: 'INTERNET_OPTION_USER_AGENT', 40: 'INTERNET_OPTION_USERNAME', 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

    pVals[1] = getLookUpVal(pVals[1],dwOptionReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetSetOptionA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetSetOptionW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HINTERNET', 'DWORD', 'LPVOID', 'DWORD']
    pNames= ['hInternet', 'dwOption', 'lpBuffer', 'dwBufferLength']

    dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC', 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY', 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE', 1: 'INTERNET_OPTION_CALLBACK', 84: 'INTERNET_OPTION_CALLBACK_FILTER', 132: 'INTERNET_OPTION_CLIENT_CERT_CONTEXT', 104: 'INTERNET_OPTION_CODEPAGE', 256: 'INTERNET_OPTION_CODEPAGE_PATH', 257: 'INTERNET_OPTION_CODEPAGE_EXTRA', 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH', 4: 'INTERNET_OPTION_CONNECT_BACKOFF', 3: 'INTERNET_OPTION_CONNECT_RETRIES', 85: 'INTERNET_OPTION_CONNECT_TIME', 2: 'INTERNET_OPTION_CONNECT_TIMEOUT', 80: 'INTERNET_OPTION_CONNECTED_STATE', 69: 'INTERNET_OPTION_CONTEXT_VALUE', 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT', 5: 'INTERNET_OPTION_SEND_TIMEOUT', 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT', 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT', 150: 'INTERNET_OPTION_DATAFILE_EXT', 118: 'INTERNET_OPTION_DIGEST_AUTH_UNLOAD', 112: 'INTERNET_OPTION_DISABLE_AUTODIAL', 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT', 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL', 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA', 66: 'INTERNET_OPTION_END_BROWSER_SESSION', 98: 'INTERNET_OPTION_ERROR_MASK', 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT', 343: 'INTERNET_OPTION_HSTS', 101: 'INTERNET_OPTION_HTTP_DECODING', 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED', 89: 'INTERNET_OPTION_HTTP_VERSION', 120: 'INTERNET_OPTION_IDENTITY', 81: 'INTERNET_OPTION_IDLE_STATE', 258: 'INTERNET_OPTION_IDN', 119: 'INTERNET_OPTION_IGNORE_OFFLINE', 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT', 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER', 259: 'INTERNET_OPTION_MAX_CONNS_PER_PROXY', 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER', 38: 'INTERNET_OPTION_OFFLINE_MODE', 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS', 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE', 41: 'INTERNET_OPTION_PASSWORD', 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY', 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD', 149: 'INTERNET_OPTION_PROXY_SETTINGS_CHANGED', 67: 'INTERNET_OPTION_PROXY_USERNAME', 18: 'INTERNET_OPTION_READ_BUFFER_SIZE', 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT', 55: 'INTERNET_OPTION_REFRESH', 121: 'INTERNET_OPTION_REMOVE_IDENTITY', 88: 'INTERNET_OPTION_REQUEST_PRIORITY', 96: 'INTERNET_OPTION_RESET_URLCACHE_SESSION', 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 86: 'INTERNET_OPTION_SEND_THROUGHPUT', 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT', 57: 'INTERNET_OPTION_SETTINGS_CHANGED', 260: 'INTERNET_OPTION_SUPPRESS_SERVER_AUTH', 65: 'INTERNET_OPTION_USER_AGENT', 40: 'INTERNET_OPTION_USERNAME', 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

    pVals[1] = getLookUpVal(pVals[1],dwOptionReverseLookUp)
    
    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetSetOptionW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HttpOpenRequestA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 8)
    pTypes=['HINTERNET', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszVerb', 'lpszObjectName', 'lpszVersion', 'lpszReferrer', 'lplpszAcceptTypes', 'dwFlags', 'dwContext']

    dwFlagsReverseLookUp = {65536: 'INTERNET_FLAG_CACHE_IF_NET_FAIL', 1024: 'INTERNET_FLAG_HYPERLINK', 4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID', 8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID', 32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP', 16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS', 4194304: 'INTERNET_FLAG_KEEP_CONNECTION', 16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH', 2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE', 524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI', 256: 'INTERNET_FLAG_PRAGMA_NOCACHE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

    pVals[6] = getLookUpVal(pVals[6],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    if pVals[3] == '[NULL]':
        pVals[3] = 'HTTP/1.1'

    cleanBytes=len(pTypes)*4
    retVal=0x00747474
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HttpOpenRequestA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HttpOpenRequestW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 8)
    pTypes=['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszVerb', 'lpszObjectName', 'lpszVersion', 'lpszReferrer', 'lplpszAcceptTypes', 'dwFlags', 'dwContext']

    dwFlagsReverseLookUp = {65536: 'INTERNET_FLAG_CACHE_IF_NET_FAIL', 1024: 'INTERNET_FLAG_HYPERLINK', 4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID', 8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID', 32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP', 16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS', 4194304: 'INTERNET_FLAG_KEEP_CONNECTION', 16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH', 2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE', 524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI', 256: 'INTERNET_FLAG_PRAGMA_NOCACHE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

    pVals[6] = getLookUpVal(pVals[6],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    if pVals[3] == '[NULL]':
        pVals[3] = 'HTTP/1.1'

    cleanBytes=len(pTypes)*4
    retVal=0x00757575
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HttpOpenRequestW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HttpAddRequestHeadersA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HINTERNET', 'LPCSTR', 'DWORD', 'DWORD']
    pNames= ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'dwModifiers']

    dwModifiersReverseLookUp = {536870912: 'HTTP_ADDREQ_FLAG_ADD', 268435456: 'HTTP_ADDREQ_FLAG_ADD_IF_NEW', 1073741824: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA', 16777216: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON', 2147483648: 'HTTP_ADDREQ_FLAG_REPLACE'}

    pVals[3] = getLookUpVal(pVals[3],dwModifiersReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HttpAddRequestHeadersA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HttpAddRequestHeadersW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['HINTERNET', 'LPCWSTR', 'DWORD', 'DWORD']
    pNames= ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'dwModifiers']

    dwModifiersReverseLookUp = {536870912: 'HTTP_ADDREQ_FLAG_ADD', 268435456: 'HTTP_ADDREQ_FLAG_ADD_IF_NEW', 1073741824: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA', 16777216: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON', 2147483648: 'HTTP_ADDREQ_FLAG_REPLACE'}

    pVals[3] = getLookUpVal(pVals[3],dwModifiersReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HttpAddRequestHeadersW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HttpQueryInfoA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD', 'LPDWORD']
    pNames= ['hRequest', 'dwInfoLevel', 'lpBuffer', 'lpdwBufferLength', 'lpdwIndex']

    dwInfoLevelReverseLookUp = {36: 'HTTP_QUERY_ACCEPT', 37: 'HTTP_QUERY_ACCEPT_CHARSET', 38: 'HTTP_QUERY_ACCEPT_ENCODING', 39: 'HTTP_QUERY_ACCEPT_LANGUAGE', 66: 'HTTP_QUERY_ACCEPT_RANGES', 72: 'HTTP_QUERY_AGE', 7: 'HTTP_QUERY_ALLOW', 40: 'HTTP_QUERY_AUTHORIZATION', 73: 'HTTP_QUERY_CACHE_CONTROL', 35: 'HTTP_QUERY_CONNECTION', 80: 'HTTP_QUERY_CONTENT_BASE', 4: 'HTTP_QUERY_CONTENT_DESCRIPTION', 71: 'HTTP_QUERY_CONTENT_DISPOSITION', 41: 'HTTP_QUERY_CONTENT_ENCODING', 3: 'HTTP_QUERY_CONTENT_ID', 6: 'HTTP_QUERY_CONTENT_LANGUAGE', 5: 'HTTP_QUERY_CONTENT_LENGTH', 81: 'HTTP_QUERY_CONTENT_LOCATION', 82: 'HTTP_QUERY_CONTENT_MD5', 83: 'HTTP_QUERY_CONTENT_RANGE', 2: 'HTTP_QUERY_CONTENT_TRANSFER_ENCODING', 1: 'HTTP_QUERY_CONTENT_TYPE', 68: 'HTTP_QUERY_COOKIE', 21: 'HTTP_QUERY_COST', 415029: 'HTTP_QUERY_CUSTOM', 9: 'HTTP_QUERY_DATE', 20: 'HTTP_QUERY_DERIVED_FROM', 115: 'HTTP_QUERY_ECHO_HEADERS', 116: 'HTTP_QUERY_ECHO_HEADERS_CRLF', 114: 'HTTP_QUERY_ECHO_REPLY', 113: 'HTTP_QUERY_ECHO_REQUEST', 84: 'HTTP_QUERY_ETAG', 104: 'HTTP_QUERY_EXPECT', 16: 'HTTP_QUERY_EXPIRES', 48: 'HTTP_QUERY_FORWARDED', 49: 'HTTP_QUERY_FROM', 85: 'HTTP_QUERY_HOST', 86: 'HTTP_QUERY_IF_MATCH', 50: 'HTTP_QUERY_IF_MODIFIED_SINCE', 87: 'HTTP_QUERY_IF_NONE_MATCH', 88: 'HTTP_QUERY_IF_RANGE', 89: 'HTTP_QUERY_IF_UNMODIFIED_SINCE', 17: 'HTTP_QUERY_LAST_MODIFIED', 22: 'HTTP_QUERY_LINK', 51: 'HTTP_QUERY_LOCATION', 120: 'HTTP_QUERY_MAX', 96: 'HTTP_QUERY_MAX_FORWARDS', 18: 'HTTP_QUERY_MESSAGE_ID', 0: 'HTTP_QUERY_MIME_VERSION', 52: 'HTTP_QUERY_ORIG_URI', 23: 'HTTP_QUERY_PRAGMA', 65: 'HTTP_QUERY_PROXY_AUTHENTICATE', 97: 'HTTP_QUERY_PROXY_AUTHORIZATION', 105: 'HTTP_QUERY_PROXY_CONNECTION', 8: 'HTTP_QUERY_PUBLIC', 98: 'HTTP_QUERY_RANGE', 33: 'HTTP_QUERY_RAW_HEADERS', 34: 'HTTP_QUERY_RAW_HEADERS_CRLF', 53: 'HTTP_QUERY_REFERER', 70: 'HTTP_QUERY_REFRESH', 69: 'HTTP_QUERY_REQUEST_METHOD', 54: 'HTTP_QUERY_RETRY_AFTER', 55: 'HTTP_QUERY_SERVER', 67: 'HTTP_QUERY_SET_COOKIE', 25: 'HTTP_QUERY_STATUS_CODE', 32: 'HTTP_QUERY_STATUS_TEXT', 56: 'HTTP_QUERY_TITLE', 99: 'HTTP_QUERY_TRANSFER_ENCODING', 112: 'HTTP_QUERY_UNLESS_MODIFIED_SINCE', 100: 'HTTP_QUERY_UPGRADE', 19: 'HTTP_QUERY_URI', 57: 'HTTP_QUERY_USER_AGENT', 101: 'HTTP_QUERY_VARY', 24: 'HTTP_QUERY_VERSION', 102: 'HTTP_QUERY_VIA', 103: 'HTTP_QUERY_WARNING', 64: 'HTTP_QUERY_WWW_AUTHENTICATE', 121: 'HTTP_QUERY_X_CONTENT_TYPE_OPTIONS', 128: 'HTTP_QUERY_P3P', 129: 'HTTP_QUERY_X_P2P_PEERDIST', 130: 'HTTP_QUERY_TRANSLATE', 131: 'HTTP_QUERY_X_UA_COMPATIBLE', 132: 'HTTP_QUERY_DEFAULT_STYLE', 133: 'HTTP_QUERY_X_FRAME_OPTIONS', 134: 'HTTP_QUERY_X_XSS_PROTECTION', 268435456: 'HTTP_QUERY_FLAG_COALESCE', 536870912: 'HTTP_QUERY_FLAG_NUMBER', 2147483648: 'HTTP_QUERY_FLAG_REQUEST_HEADERS', 1073741824: 'HTTP_QUERY_FLAG_SYSTEMTIME'}

    pVals[1] = getLookUpVal(pVals[1], dwInfoLevelReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HttpQueryInfoA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_HttpQueryInfoW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD', 'LPDWORD']
    pNames= ['hRequest', 'dwInfoLevel', 'lpBuffer', 'lpdwBufferLength', 'lpdwIndex']

    dwInfoLevelReverseLookUp = {36: 'HTTP_QUERY_ACCEPT', 37: 'HTTP_QUERY_ACCEPT_CHARSET', 38: 'HTTP_QUERY_ACCEPT_ENCODING', 39: 'HTTP_QUERY_ACCEPT_LANGUAGE', 66: 'HTTP_QUERY_ACCEPT_RANGES', 72: 'HTTP_QUERY_AGE', 7: 'HTTP_QUERY_ALLOW', 40: 'HTTP_QUERY_AUTHORIZATION', 73: 'HTTP_QUERY_CACHE_CONTROL', 35: 'HTTP_QUERY_CONNECTION', 80: 'HTTP_QUERY_CONTENT_BASE', 4: 'HTTP_QUERY_CONTENT_DESCRIPTION', 71: 'HTTP_QUERY_CONTENT_DISPOSITION', 41: 'HTTP_QUERY_CONTENT_ENCODING', 3: 'HTTP_QUERY_CONTENT_ID', 6: 'HTTP_QUERY_CONTENT_LANGUAGE', 5: 'HTTP_QUERY_CONTENT_LENGTH', 81: 'HTTP_QUERY_CONTENT_LOCATION', 82: 'HTTP_QUERY_CONTENT_MD5', 83: 'HTTP_QUERY_CONTENT_RANGE', 2: 'HTTP_QUERY_CONTENT_TRANSFER_ENCODING', 1: 'HTTP_QUERY_CONTENT_TYPE', 68: 'HTTP_QUERY_COOKIE', 21: 'HTTP_QUERY_COST', 415029: 'HTTP_QUERY_CUSTOM', 9: 'HTTP_QUERY_DATE', 20: 'HTTP_QUERY_DERIVED_FROM', 115: 'HTTP_QUERY_ECHO_HEADERS', 116: 'HTTP_QUERY_ECHO_HEADERS_CRLF', 114: 'HTTP_QUERY_ECHO_REPLY', 113: 'HTTP_QUERY_ECHO_REQUEST', 84: 'HTTP_QUERY_ETAG', 104: 'HTTP_QUERY_EXPECT', 16: 'HTTP_QUERY_EXPIRES', 48: 'HTTP_QUERY_FORWARDED', 49: 'HTTP_QUERY_FROM', 85: 'HTTP_QUERY_HOST', 86: 'HTTP_QUERY_IF_MATCH', 50: 'HTTP_QUERY_IF_MODIFIED_SINCE', 87: 'HTTP_QUERY_IF_NONE_MATCH', 88: 'HTTP_QUERY_IF_RANGE', 89: 'HTTP_QUERY_IF_UNMODIFIED_SINCE', 17: 'HTTP_QUERY_LAST_MODIFIED', 22: 'HTTP_QUERY_LINK', 51: 'HTTP_QUERY_LOCATION', 120: 'HTTP_QUERY_MAX', 96: 'HTTP_QUERY_MAX_FORWARDS', 18: 'HTTP_QUERY_MESSAGE_ID', 0: 'HTTP_QUERY_MIME_VERSION', 52: 'HTTP_QUERY_ORIG_URI', 23: 'HTTP_QUERY_PRAGMA', 65: 'HTTP_QUERY_PROXY_AUTHENTICATE', 97: 'HTTP_QUERY_PROXY_AUTHORIZATION', 105: 'HTTP_QUERY_PROXY_CONNECTION', 8: 'HTTP_QUERY_PUBLIC', 98: 'HTTP_QUERY_RANGE', 33: 'HTTP_QUERY_RAW_HEADERS', 34: 'HTTP_QUERY_RAW_HEADERS_CRLF', 53: 'HTTP_QUERY_REFERER', 70: 'HTTP_QUERY_REFRESH', 69: 'HTTP_QUERY_REQUEST_METHOD', 54: 'HTTP_QUERY_RETRY_AFTER', 55: 'HTTP_QUERY_SERVER', 67: 'HTTP_QUERY_SET_COOKIE', 25: 'HTTP_QUERY_STATUS_CODE', 32: 'HTTP_QUERY_STATUS_TEXT', 56: 'HTTP_QUERY_TITLE', 99: 'HTTP_QUERY_TRANSFER_ENCODING', 112: 'HTTP_QUERY_UNLESS_MODIFIED_SINCE', 100: 'HTTP_QUERY_UPGRADE', 19: 'HTTP_QUERY_URI', 57: 'HTTP_QUERY_USER_AGENT', 101: 'HTTP_QUERY_VARY', 24: 'HTTP_QUERY_VERSION', 102: 'HTTP_QUERY_VIA', 103: 'HTTP_QUERY_WARNING', 64: 'HTTP_QUERY_WWW_AUTHENTICATE', 121: 'HTTP_QUERY_X_CONTENT_TYPE_OPTIONS', 128: 'HTTP_QUERY_P3P', 129: 'HTTP_QUERY_X_P2P_PEERDIST', 130: 'HTTP_QUERY_TRANSLATE', 131: 'HTTP_QUERY_X_UA_COMPATIBLE', 132: 'HTTP_QUERY_DEFAULT_STYLE', 133: 'HTTP_QUERY_X_FRAME_OPTIONS', 134: 'HTTP_QUERY_X_XSS_PROTECTION', 268435456: 'HTTP_QUERY_FLAG_COALESCE', 536870912: 'HTTP_QUERY_FLAG_NUMBER', 2147483648: 'HTTP_QUERY_FLAG_REQUEST_HEADERS', 1073741824: 'HTTP_QUERY_FLAG_SYSTEMTIME'}

    pVals[1] = getLookUpVal(pVals[1], dwInfoLevelReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HttpQueryInfoW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_FtpGetFileA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HINTERNET', 'LPCSTR', 'LPCSTR', 'BOOL', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszRemoteFile', 'lpszNewFile', 'fFailIfExists', 'dwFlagsAndAttributes', 'dwFlags', 'dwContext']
    
    dwFlagsAndAttributesReverseLookUp = {50: 'FILE_ATTRIBUTE_ARCHIVE', 91012: 'FILE_ATTRIBUTE_ENCRYPTED', 2: 'FILE_ATTRIBUTE_HIDDEN', 296: 'FILE_ATTRIBUTE_NORMAL', 16534: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY', 4: 'FILE_ATTRIBUTE_SYSTEM', 598: 'FILE_ATTRIBUTE_TEMPORARY'}
    dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII', 2: 'FTP_TRANSFER_TYPE_BINARY', 1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

    pVals[4] = getLookUpVal(pVals[4],dwFlagsAndAttributesReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4,5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("FtpGetFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_FtpGetFileW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'BOOL', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszRemoteFile', 'lpszNewFile', 'fFailIfExists', 'dwFlagsAndAttributes', 'dwFlags', 'dwContext']
    
    dwFlagsAndAttributesReverseLookUp = {50: 'FILE_ATTRIBUTE_ARCHIVE', 91012: 'FILE_ATTRIBUTE_ENCRYPTED', 2: 'FILE_ATTRIBUTE_HIDDEN', 296: 'FILE_ATTRIBUTE_NORMAL', 16534: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY', 4: 'FILE_ATTRIBUTE_SYSTEM', 598: 'FILE_ATTRIBUTE_TEMPORARY'}
    dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII', 2: 'FTP_TRANSFER_TYPE_BINARY', 1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

    pVals[4] = getLookUpVal(pVals[4],dwFlagsAndAttributesReverseLookUp)
    pVals[5] = getLookUpVal(pVals[5],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4,5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("FtpGetFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_FtpOpenFileA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HINTERNET', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszFileName', 'dwAccess', 'dwFlags', 'dwContext']

    dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE'}
    dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII', 2: 'FTP_TRANSFER_TYPE_BINARY', 1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

    pVals[2] = getLookUpVal(pVals[2],dwAccessReverseLookUp)
    pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00767676
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("FtpOpenFileA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_FtpOpenFileW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['HINTERNET', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hConnect', 'lpszFileName', 'dwAccess', 'dwFlags', 'dwContext']

    dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE'}
    dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII', 2: 'FTP_TRANSFER_TYPE_BINARY', 1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

    pVals[2] = getLookUpVal(pVals[2],dwAccessReverseLookUp)
    pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00777777
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("FtpOpenFileW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetOpenUrlA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['HINTERNET', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hInternet', 'lpszUrl', 'lpszHeaders', 'dwHeadersLength', 'dwFlags', 'dwContext']

    dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 1024: 'INTERNET_FLAG_HYPERLINK', 4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID', 8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID', 32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP', 16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS', 4194304: 'INTERNET_FLAG_KEEP_CONNECTION', 16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH', 2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE', 524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI', 134217728: 'INTERNET_FLAG_PASSIVE', 256: 'INTERNET_FLAG_PRAGMA_NOCACHE', 1073741824: 'INTERNET_FLAG_RAW_DATA', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

    pVals[4] = getLookUpVal(pVals[4],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00787878
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetOpenUrlA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_InternetOpenUrlW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
    pNames= ['hInternet', 'lpszUrl', 'lpszHeaders', 'dwHeadersLength', 'dwFlags', 'dwContext']

    dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 1024: 'INTERNET_FLAG_HYPERLINK', 4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID', 8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID', 32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP', 16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS', 4194304: 'INTERNET_FLAG_KEEP_CONNECTION', 16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH', 2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE', 524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI', 134217728: 'INTERNET_FLAG_PASSIVE', 256: 'INTERNET_FLAG_PRAGMA_NOCACHE', 1073741824: 'INTERNET_FLAG_RAW_DATA', 2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

    pVals[4] = getLookUpVal(pVals[4],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00797979
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("InternetOpenUrlW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes


def hook_MoveFileExA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPCSTR', 'LPCSTR', 'DWORD']
    pNames= ['lpExistingFileName', 'lpNewFileName', 'dwFlags']

    dwFlagsReverseLookUp = {2: 'MOVEFILE_COPY_ALLOWED', 16: 'MOVEFILE_CREATE_HARDLINK', 4: 'MOVEFILE_DELAY_UNTIL_REBOOT', 32: 'MOVEFILE_FAIL_IF_NOT_TRACKABLE', 1: 'MOVEFILE_REPLACE_EXISTING', 8: 'MOVEFILE_WRITE_THROUGH'}

    pVals[2] = getLookUpVal(pVals[2],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("MoveFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_MoveFileExW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPCWSTR', 'LPCWSTR', 'DWORD']
    pNames= ['lpExistingFileName', 'lpNewFileName', 'dwFlags']

    dwFlagsReverseLookUp = {2: 'MOVEFILE_COPY_ALLOWED', 16: 'MOVEFILE_CREATE_HARDLINK', 4: 'MOVEFILE_DELAY_UNTIL_REBOOT', 32: 'MOVEFILE_FAIL_IF_NOT_TRACKABLE', 1: 'MOVEFILE_REPLACE_EXISTING', 8: 'MOVEFILE_WRITE_THROUGH'}

    pVals[2] = getLookUpVal(pVals[2],dwFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("MoveFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CopyFileExA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['LPCSTR', 'LPCSTR', 'LPPROGRESS_ROUTINE', 'LPVOID', 'LPBOOL', 'DWORD']
    pNames= ['lpExistingFileName', 'lpNewFileName', 'lpProgressRoutine', 'lpData', 'pbCancel', 'dwCopyFlags']

    mdwCopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK', 1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING', 4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE', 268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

    pVals[5] = getLookUpVal(pVals[5],mdwCopyFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CopyFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CopyFileExW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['LPCWSTR', 'LPCWSTR', 'LPPROGRESS_ROUTINE', 'LPVOID', 'LPBOOL', 'DWORD']
    pNames= ['lpExistingFileName', 'lpNewFileName', 'lpProgressRoutine', 'lpData', 'pbCancel', 'dwCopyFlags']

    mdwCopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK', 1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING', 4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE', 268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

    pVals[5] = getLookUpVal(pVals[5],mdwCopyFlagsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CopyFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_DuplicateHandle(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HANDLE', 'HANDLE', 'HANDLE', 'LPHANDLE', 'DWORD', 'BOOL', 'DWORD']
    pNames= ['hSourceProcessHandle', 'hSourceHandle', 'hTargetProcessHandle', 'lpTargetHandle', 'dwDesiredAccess', 'bInheritHandle', 'dwOptions']

    dwDesiredAccessReverseLookUp = {65536: 'DELETE', 131072: 'READ_CONTROL', 262144: 'WRITE_DAC', 524288: 'WRITE_OWNER', 1048576: 'SYNCHRONIZE', 983040: 'STANDARD_RIGHTS_REQUIRED', 2031616: 'STANDARD_RIGHTS_ALL'}
    dwOptionsReverseLookUp = {1: 'DUPLICATE_CLOSE_SOURCE', 2: 'DUPLICATE_SAME_ACCESS'}

    pVals[4] = getLookUpVal(pVals[4],dwDesiredAccessReverseLookUp)
    pVals[6] = getLookUpVal(pVals[6],dwOptionsReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[4,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("DuplicateHandle", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateFileMappingNumaA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'DWORD']
    pNames= ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName', 'nndPreferred']

    flProtectReverseLookUp = {32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT', 16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES', 268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}
    nndPreferredReverseLookUp = {4294967295: 'NUMA_NO_PREFERRED_NODE'}

    pVals[2] = getLookUpVal(pVals[2],flProtectReverseLookUp)
    pVals[6] = getLookUpVal(pVals[6],nndPreferredReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00808080
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateFileMappingNumaA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateFileMappingNumaW(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 7)
    pTypes=['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR', 'DWORD']
    pNames= ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName', 'nndPreferred']

    flProtectReverseLookUp = {32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT', 16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES', 268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}
    nndPreferredReverseLookUp = {4294967295: 'NUMA_NO_PREFERRED_NODE'}

    pVals[2] = getLookUpVal(pVals[2],flProtectReverseLookUp)
    pVals[6] = getLookUpVal(pVals[6],nndPreferredReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00818181
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateFileMappingNumaW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateMutexA(uc, eip, esp, export_dict, callAddr):
    # HANDLE CreateMutexA([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in] BOOL bInitialOwner,[in, optional] LPCSTR lpName)
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPSECURITY_ATTRIBUTES', 'BOOL', 'LPCSTR']
    pNames= ['lpMutexAttributes', 'bInitialOwner', 'lpName']

    handle = Handle(HandleType.CreateMutexA)

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateMutexA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateMutexW(uc, eip, esp, export_dict, callAddr):
    # HANDLE CreateMutexW([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in] BOOL bInitialOwner,[in, optional] LPCWSTR lpName)
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPSECURITY_ATTRIBUTES', 'BOOL', 'LPCWSTR']
    pNames= ['lpMutexAttributes', 'bInitialOwner', 'lpName']

    handle = Handle(HandleType.CreateMutexW)

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateMutexW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateMutexExA(uc, eip, esp, export_dict, callAddr):
    # HANDLE CreateMutexExA([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in, optional] LPCSTR lpName,[in] DWORD dwFlags,[in] DWORD dwDesiredAccess);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['LPSECURITY_ATTRIBUTES', 'LPCSTR', 'DWORD', 'DWORD']
    pNames= ['lpMutexAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
    dwFlagsReverseLookUp={0x00000001: 'CREATE_MUTEX_INITIAL_OWNER'}
    dwDesiredAccessReverseLookUp={0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}

    handle = Handle(HandleType.CreateMutexExA)

    pVals[2] = getLookUpVal(pVals[2],dwFlagsReverseLookUp)
    pVals[3] = getLookUpVal(pVals[3],dwDesiredAccessReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)
    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateMutexExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateMutexExW(uc, eip, esp, export_dict, callAddr):
    # HANDLE CreateMutexExW([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in, optional] LPCWSTR lpName,[in] DWORD dwFlags,[in] DWORD dwDesiredAccess);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['LPSECURITY_ATTRIBUTES', 'LPCWSTR', 'DWORD', 'DWORD']
    pNames= ['lpMutexAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
    dwFlagsReverseLookUp={0x00000001: 'CREATE_MUTEX_INITIAL_OWNER'}
    dwDesiredAccessReverseLookUp={0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}

    handle = Handle(HandleType.CreateMutexExA)

    pVals[2] = getLookUpVal(pVals[2],dwFlagsReverseLookUp)
    pVals[3] = getLookUpVal(pVals[3],dwDesiredAccessReverseLookUp)

    #create strings for everything except ones in our skip
    skip=[2,3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=handle.value
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateMutexExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_ReleaseMutex(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL ReleaseMutex([in] HANDLE hMutex);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 1)
    pTypes=['HANDLE']
    pNames= ['hMutex']

    # Remove Handle from HandlesDict
    if pVals[0] in HandlesDict:
        HandlesDict.pop(pVals[0])

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ReleaseMutex", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetComputerNameA(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL GetComputerNameA([out] LPSTR lpBuffer,[in, out] LPDWORD nSize);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPSTR', 'LPDWORD']
    pNames= ['lpBuffer', 'nSize']

    computerName = 'Desktop-JR4WS'.encode('ascii')
    uc.mem_write(pVals[0], pack('<15s', computerName))
    uc.mem_write(pVals[1], pack('<I',len(computerName)))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetComputerNameA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetComputerNameW(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL GetComputerNameW([out] LPWSTR lpBuffer,[in, out] LPDWORD nSize);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPWSTR', 'LPDWORD']
    pNames= ['lpBuffer', 'nSize']
    
    computerName = 'Desktop-JR4WS'.encode('utf-16')
    uc.mem_write(pVals[0], pack('<30s', computerName[2:]))
    uc.mem_write(pVals[1], pack('<I',len(computerName)))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetComputerNameW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetComputerNameExA(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL GetComputerNameExA([in] COMPUTER_NAME_FORMAT NameType,[out] LPSTR  lpBuffer,[in, out] LPDWORD nSize);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['COMPUTER_NAME_FORMAT', 'LPSTR', 'LPDWORD']
    pNames= ['NameType', 'lpBuffer', 'nSize']
    nameTypeReverseLookup = {  0: 'ComputerNameNetBIOS', 1: 'ComputerNameDnsHostname', 2: 'ComputerNameDnsDomain', 3: 'ComputerNameDnsFullyQualified', 4: 'ComputerNamePhysicalNetBIOS', 5: 'ComputerNamePhysicalDnsHostname', 6: 'ComputerNamePhysicalDnsDomain', 7: 'ComputerNamePhysicalDnsFullyQualified', 8: 'ComputerNameMax'}
    
    pVals[0] = getLookUpVal(pVals[0], nameTypeReverseLookup)
    
    computerName = 'Desktop-JR4WS'.encode('ascii')
    uc.mem_write(pVals[1], pack('<15s', computerName))
    uc.mem_write(pVals[2], pack('<I',len(computerName)))

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetComputerNameExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetComputerNameExW(uc: Uc, eip, esp, export_dict, callAddr):
    # BOOL GetComputerNameExW([in] COMPUTER_NAME_FORMAT NameType,[out] LPWSTR  lpBuffer,[in, out] LPDWORD nSize);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['COMPUTER_NAME_FORMAT', 'LPWSTR', 'LPDWORD']
    pNames= ['NameType', 'lpBuffer', 'nSize']
    nameTypeReverseLookup = {  0: 'ComputerNameNetBIOS', 1: 'ComputerNameDnsHostname', 2: 'ComputerNameDnsDomain', 3: 'ComputerNameDnsFullyQualified', 4: 'ComputerNamePhysicalNetBIOS', 5: 'ComputerNamePhysicalDnsHostname', 6: 'ComputerNamePhysicalDnsDomain', 7: 'ComputerNamePhysicalDnsFullyQualified', 8: 'ComputerNameMax'}
    
    pVals[0] = getLookUpVal(pVals[0], nameTypeReverseLookup)
    
    computerName = 'Desktop-JR4WS'.encode('utf-16')
    uc.mem_write(pVals[1], pack('<30s', computerName[2:]))
    uc.mem_write(pVals[2], pack('<I',len(computerName[2:])))

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetComputerNameExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetWindowsDirectoryA(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetWindowsDirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);    
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPSTR', 'UNINT']
    pNames= ['lpBuffer', 'uSize']

    path = 'C:\Windows'.encode('ascii')
    uc.mem_write(pVals[0], pack('<260s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetWindowsDirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetWindowsDirectoryW(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetWindowsDirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);    
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPWSTR', 'UNINT']
    pNames= ['lpBuffer', 'uSize']

    path = 'C:\Windows'.encode('utf-16')[2:]
    uc.mem_write(pVals[0], pack('<520s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetWindowsDirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetSystemWindowsDirectoryA(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetSystemWindowsDirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);    
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPSTR', 'UNINT']
    pNames= ['lpBuffer', 'uSize']

    path = 'C:\Windows'.encode('ascii')
    uc.mem_write(pVals[0], pack('<260s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetSystemWindowsDirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetSystemWindowsDirectoryW(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetSystemWindowsDirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);    
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPWSTR', 'UNINT']
    pNames= ['lpBuffer', 'uSize']

    path = 'C:\Windows'.encode('utf-16')[2:]
    uc.mem_write(pVals[0], pack('<520s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetSystemWindowsDirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetTempPathA(uc: Uc, eip, esp, export_dict, callAddr):
    # DWORD GetTempPathA([in]  DWORD nBufferLength,[out] LPSTR lpBuffer);  
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['DWORD', 'LPSTR',]
    pNames= ['nBufferLength', 'lpBuffer',]

    path = 'C:\TEMP\\'.encode('ascii')
    uc.mem_write(pVals[1], pack('<260s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetTempPathA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetTempPathW(uc: Uc, eip, esp, export_dict, callAddr):
    # DWORD GetTempPathW([in]  DWORD nBufferLength,[out] LPWSTR lpBuffer);  
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['DWORD', 'LPWSTR',]
    pNames= ['nBufferLength', 'lpBuffer',]

    path = 'C:\TEMP\\'.encode('utf-16')[2:]
    uc.mem_write(pVals[1], pack('<520s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetTempPathW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetTempFileNameA(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetTempFileNameA([in]  LPCSTR lpPathName,[in]  LPCSTR lpPrefixString,[in]  UINT   uUnique,[out] LPSTR  lpTempFileName);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['LPCSTR', 'LPCSTR', 'UINT', 'LPSTR']
    pNames= ['lpPathName', 'lpPrefixString', 'uUnique', 'lpTempFileName']

    tempPath = read_string(uc, pVals[0])
    preFix = read_string(uc, pVals[1])

    if pVals[2] == 0x0:
        retVal = randint(0x0,0xffff)
        value = hex(retVal)[2:]
        while len(value) < 4: # Pad to 4
            value = str(0) + value
        if preFix != '[NULL]':
            path = f'{tempPath}{preFix[:3]}{value}.TMP'
        else:
            path = f'{tempPath}{value}.TMP'
    else:
        retVal = pVals[2]
        value = hex(retVal)[2:]
        while len(value) < 4: # Pad to 4
            value = str(0) + value
        if preFix != '[NULL]':
            path = f'{tempPath}{preFix[:3]}{value}.TMP'
        else:
            path = f'{tempPath}{value}.TMP'

    uc.mem_write(pVals[3], pack('<260s', path.encode('ascii')))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetTempFileNameA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetTempFileNameW(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetTempFileNameW([in]  LPCWSTR lpPathName,[in]  LPCWSTR lpPrefixString,[in]  UINT   uUnique,[out] LPWSTR  lpTempFileName);
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 4)
    pTypes=['LPCWSTR', 'LPCWSTR', 'UINT', 'LPWSTR']
    pNames= ['lpPathName', 'lpPrefixString', 'uUnique', 'lpTempFileName']

    tempPath = read_unicode2(uc, pVals[0])
    preFix = read_unicode2(uc, pVals[1])

    if pVals[2] == 0x0:
        retVal = randint(0x0,0xffff)
        value = hex(retVal)[2:]
        while len(value) < 4: # Pad to 4
            value = str(0) + value
        if preFix != '[NULL]':
            path = f'{tempPath}{preFix[:3]}{value}.TMP'
        else:
            path = f'{tempPath}{value}.TMP'
    else:
        retVal = pVals[2]
        value = hex(retVal)[2:]
        while len(value) < 4: # Pad to 4
            value = str(0) + value
        if preFix != '[NULL]':
            path = f'{tempPath}{preFix[:3]}{value}.TMP'
        else:
            path = f'{tempPath}{value}.TMP'

    uc.mem_write(pVals[3], pack('<520s', path.encode('utf-16')[2:]))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetTempFileNameW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetSystemWow64DirectoryA(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetSystemWow64DirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);    
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPSTR', 'UNINT']
    pNames= ['lpBuffer', 'uSize']

    path = 'C:\Windows\SysWOW64'.encode('ascii')
    uc.mem_write(pVals[0], pack('<260s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetSystemWow64DirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_GetSystemWow64DirectoryW(uc: Uc, eip, esp, export_dict, callAddr):
    # UINT GetSystemWow64DirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);    
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPWSTR', 'UNINT']
    pNames= ['lpBuffer', 'uSize']

    path = 'C:\Windows\SysWOW64'.encode('utf-16')[2:]
    uc.mem_write(pVals[0], pack('<520s', path))

    #create strings for everything except ones in our skip
    skip=[]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=len(path)
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("GetSystemWow64DirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes