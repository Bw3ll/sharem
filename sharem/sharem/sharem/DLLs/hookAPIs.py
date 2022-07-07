from copy import deepcopy
from enum import Enum, auto
from random import choice, randint
from time import perf_counter_ns
from urllib.parse import quote, unquote
from sharem.sharem.DLLs.reverseLookUps import ReverseLookUps
from sharem.sharem.DLLs.structures import *
from sharem.sharem.helper.structHelpers import makeStructVals
from unicorn.x86_const import *
from struct import pack, unpack
from ..helper.emuHelpers import Uc
from ..modules import allDllsDict
import traceback
from ..sharem_artifacts import *
import re

art = Artifacts_emulation()

FakeProcess = 0xbadd0000
availMem = 0x25000000
lastErrorCode = 0x0
HeapsDict = {}  # Dictionary of All Heaps
HandlesDict: 'dict[int,Handle]' = {}  # Dictionary of All Handles
RegistryKeys: 'dict[str,RegKey]' = {} # Dictionary of All Reg Keys

class HandleType(Enum):
    # Threads
    Thread = auto()
    # Process
    Process = auto()
    SetWindowsHookExA = auto()
    SetWindowsHookExW = auto()
    CreateToolhelp32Snapshot = auto()
    # Internet Handles
    HINTERNET = auto()
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
    CreateFile2 = auto()
    CreateFileMappingA = auto()
    CreateFileMappingW = auto()
    CreateFileMappingNumaA = auto()
    CreateFileMappingNumaW = auto()
    SendMessageA = auto()
    # Mutex
    Mutex = auto()
    # Service Handles
    SC_HANDLE = auto()
    # PIPE
    pipeName = auto()
    ReadPipe = auto()
    WritePipe = auto()
    ReadWritePipe = auto()
    # CHAR
    charName = auto()
    # Other
    HGLOBAL = auto()
    DuplicateToken = auto()
    # Module
    HMODULE = auto()
    # Desktop/Window
    HWND = auto()
    ClipBoard = auto()
    # Registry
    HKEY = auto()
    Transaction = auto()
    # Sockets
    Socket = auto()
    # Events
    Event = auto()


class Handle:
    nextValue = 0x88880000  # Start of Handle IDs

    def __init__(self, type: HandleType, data=None, name='', handleValue=0):
        if handleValue == 0:
            # Generate Handle Value
            handleValue = Handle.nextValue
            Handle.nextValue += 8
        self.value = handleValue
        self.type = type
        self.name = name
        self.data = data
        HandlesDict.update({self.value: self})

class EmulationSimulationValues:
    def __init__(self):
        self.user_name = 'administrator'
        self.computer_name = 'Desktop-SHAREM'
        self.temp_file_prefix = 'SHAREM'
        self.default_registry_value = '(SHAREM Default Value)'
        self.computer_ip_address = '192.168.1.111'
        self.timezone = 'UTC'
        self.system_time_since_epoch = 0
        self.system_uptime_minutes = 60
        self.clipboard_data = 'https://sharem.com/login/#'

emuSimVals = EmulationSimulationValues()

class CustomWinAPIs():
    def GetProcAddress(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['HMODULE', 'LPCSTR']
        pNames = ['hModule', 'lpProcName']
        
        name = read_string(uc, pVals[1])

        retVal = 0

        for api in export_dict:
            if export_dict[api][0] == name:
                retVal = int(api, 16)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("GetProcAddress", hex(callAddr), hex(retVal), 'FARPROC', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LdrGetProcedureAddress(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['HMODULE', 'const ANSI_STRING *', 'ULONG', 'PVOID *']
        pNames = ['hModule', 'name', 'ord', 'address']

        pVals[1] = read_string(uc, pVals[1])
                
        for api in export_dict:
            if export_dict[api][0] == pVals[1]:
                address = int(api, 16)

        try:
            uc.mem_write(pVals[3],pack('<I',address))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        retValStr = 'STATUS_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("LdrGetProcedureAddress", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LoadLibraryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['LPCTSTR']
        pNames = ['lpLibFileName']

        name = read_string(uc, pVals[0])

        try:
            foundVal = allDllsDict[name]
            handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
            retVal = handle.value
        except:
            try:
                nameL = name.lower()
                foundVal = allDllsDict[nameL]
                handle = Handle(HandleType.HMODULE,data=name,handleValue=foundVal)
                retVal = handle.value
            except:
                try:
                    nameLdll = nameL + '.dll'
                    foundVal = allDllsDict[nameLdll]
                    handle = Handle(HandleType.HMODULE,data=name,handleValue=foundVal)
                    retVal = handle.value
                except:
                    print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                    retVal = 0

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("LoadLibraryA", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LoadLibraryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['LPCWSTR']
        pNames = ['lpLibFileName']

        name = read_unicode(uc, pVals[0])

        try:
            foundVal = allDllsDict[name]
            handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
            retVal = handle.value
        except:
            try:
                nameL = name.lower()
                foundVal = allDllsDict[nameL]
                handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
                retVal = handle.value
            except:
                try:
                    nameLdll = nameL + '.dll'
                    foundVal = allDllsDict[nameLdll]
                    handle = Handle(HandleType.HMODULE,data=name,handleValue=foundVal)
                    retVal = handle.value
                except:
                    print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                    retVal = 0

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("LoadLibraryW", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LoadLibraryExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['LPCSTR', 'HANDLE', 'DWORD']
        pNames = ['lpLibFileName', 'hFile', 'dwFlags']
        
        name = read_string(uc, pVals[0])

        try:
            foundVal = allDllsDict[name]
            handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
            retVal = handle.value
        except:
            try:
                nameL = name.lower()
                foundVal = allDllsDict[nameL]
                handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
                retVal = handle.value
            except:
                try:
                    nameLdll = nameL + '.dll'
                    foundVal = allDllsDict[nameLdll]
                    handle = Handle(HandleType.HMODULE,data=name,handleValue=foundVal)
                    retVal = handle.value
                except:
                    print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                    retVal = 0

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.LoadLibrary.Flags)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("LoadLibraryExA", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LoadLibraryExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['LPCWSTR', 'HANDLE', 'DWORD']
        pNames = ['lpLibFileName', 'hFile', 'dwFlags']

        name = read_unicode(uc, pVals[0])

        try:
            foundVal = allDllsDict[name]
            handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
            retVal = handle.value
        except:
            try:
                nameL = name.lower()
                foundVal = allDllsDict[nameL]
                handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
                retVal = handle.value
            except:
                try:
                    nameLdll = nameL + '.dll'
                    foundVal = allDllsDict[nameLdll]
                    handle = Handle(HandleType.HMODULE,data=name,handleValue=foundVal)
                    retVal = handle.value
                except:
                    print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                    retVal = 0

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.LoadLibrary.Flags)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("LoadLibraryExW", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LdrLoadDll(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['PWCHAR', 'ULONG', 'PUNICODE_STRING', 'PHANDLE']
        pNames = ['PathToFile', 'Flags', 'ModuleFileName', 'ModuleHandle']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        unicode_string = get_UNICODE_STRING(uc, pVals[2], em)
        name = read_unicode(uc, unicode_string.Buffer)

        try:
            moduleLoc = allDllsDict[name]
        except:
            try:
                nameL = name.lower()
                moduleLoc = allDllsDict[nameL]
            except:
                try:
                    nameLdll = nameL + '.dll'
                    moduleLoc = allDllsDict[nameLdll]
                except:
                    print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                    moduleLoc = 0

        # uc.reg_write(UC_X86_REG_EAX, retVal)
        if moduleLoc != 0:
            handle = Handle(HandleType.HMODULE,name=name,handleValue=moduleLoc)
            uc.mem_write(pVals[3], pack("<I", handle.value))
        retVal = 0

        pVals[0] = read_unicode(uc, pVals[0])
        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.LoadLibrary.Flags)
        pVals[2] = makeStructVals(uc, unicode_string, pVals[2])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0,1,2])

        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("LdrLoadDll", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def VirtualAlloc(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPVOID', 'SIZE_T', 'DWORD', 'DWORD']
        pNames = ['lpAddress', 'dwSize', 'flAllocationType', 'flProtect']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        global availMem

        # Round up to next page (4096)
        pVals[1] = ((pVals[1] // 4096) + 1) * 4096

        try:
            uc.mem_map(pVals[0], pVals[1])
            retVal = pVals[0]
        except:
            try:
                allocLoc = availMem
                uc.mem_map(allocLoc, pVals[1])
                availMem += pVals[1]
                retVal = allocLoc
            except:
                retVal = 0xbadd0000
                pass

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Memmory)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.flProtect)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2,3])

        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualAlloc", hex(callAddr), hex(retVal), 'INT',pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def VirtualAllocEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'DWORD']
        pNames = ['hProcess', 'lpAddress', 'dwSize', 'flAllocationType', 'flProtect']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        global availMem

        # Round up to next page (4096)
        pVals[2] = ((pVals[2] // 4096) + 1) * 4096

        retVal = 0
        try:
            uc.mem_map(pVals[1], pVals[2])
            retVal = pVals[1]
        except:
            try:
                allocLoc = availMem
                uc.mem_map(allocLoc, pVals[2])
                availMem += pVals[2]
                retVal = allocLoc
            except:
                retVal = 0xbaddd000

        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Memmory)
        pVals[4] = getLookUpVal(pVals[4], ReverseLookUps.flProtect)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3,4])

        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("VirtualAllocEx", hex(callAddr), hex(retVal), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ExitProcess(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['UINT']
        pNames = ['uExitCode']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pVals[0] = getLookUpVal(pVals[0],ReverseLookUps.ErrorCodes)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal = 0
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("ExitProcess", hex(callAddr), 'None', 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ExitThread(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['DWORD']
        pNames = ['uExitCode']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pVals[0] = getLookUpVal(pVals[0],ReverseLookUps.ErrorCodes)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal = 0
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("ExitThread", hex(callAddr), 'None', 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ["LPCSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD", "HANDLE"]
        pNames = ["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDistribution", "dwFlagsAndAttributes", "hTemplateFile"]
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        handle = Handle(HandleType.CreateFileA)

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.File.DesiredAccess)
        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.File.ShareMode)
        pVals[4] = getLookUpVal(pVals[4], ReverseLookUps.File.CreationDistribution)
        pVals[5] = getLookUpVal(pVals[5], ReverseLookUps.File.FlagsAndAttribute)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [1, 2, 4, 5])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileA", hex(callAddr), retValStr, 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateFileW([in] LPCWSTR lpFileName,[in] DWORD dwDesiredAccess,[in] DWORD dwShareMode,[in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,[in] DWORD dwCreationDisposition,[in] DWORD dwFlagsAndAttributes,[in, optional] HANDLE hTemplateFile);
        pTypes=['LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'HANDLE']
        pNames= ["lpFileName", "dwDesiredAccess", "dwShareMode","lpSecurityAttributes", "dwCreationDistribution","dwFlagsAndAttributes", "hTemplateFile"]
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        handle = Handle(HandleType.CreateFileW)

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.File.DesiredAccess)
        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.File.ShareMode)
        pVals[4] = getLookUpVal(pVals[4], ReverseLookUps.File.CreationDistribution)
        pVals[5] = getLookUpVal(pVals[5], ReverseLookUps.File.FlagsAndAttribute)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip= [1, 2, 4, 5])

        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def VirtualProtect(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL VirtualProtect([in]  LPVOID lpAddress,[in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect)
        pTypes = ['LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
        pNames = ['lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Memmory)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualProtect", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def VirtualProtectEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL VirtualProtectEx([in]  HANDLE hProcess, [in]  LPVOID lpAddress, [in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect);
        pTypes = ['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
        pNames = ['hProcess', 'lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Memmory)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualProtectEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def VirtualFree(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'VirtualFree': (3, ['LPVOID', 'SIZE_T', 'DWORD'], ['lpAddress', 'dwSize', 'dwFreeType'], 'BOOL'),
        pTypes = ['LPVOID', 'SIZE_T', 'DWORD']
        pNames = ['lpAddress', 'dwSize', 'dwFreeType']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        memReleaseReverseLookUp = {16384: 'MEM_DECOMMIT', 32768: 'MEM_RELEASE', 1: 'MEM_COALESCE_PLACEHOLDERS',
                                   2: 'MEM_PRESERVE_PLACEHOLDER',
                                   0x00004001: 'MEM_DECOMMIT | MEM_COALESCE_PLACEHOLDERS',
                                   0x00004002: 'MEM_DECOMMIT | MEM_PRESERVE_PLACEHOLDER',
                                   0x00008001: 'MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS',
                                   0x00008002: 'MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER'}
        
        pVals[2] = getLookUpVal(pVals[2],memReleaseReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        
        retVal = 0x1
        retValStr = 'FALSE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def WSASocketA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'WSASocketA': (6, ['INT', 'INT', 'INT', 'LPWSAPROTOCOL_INFOA', 'GROUP', 'DWORD'], ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags'], 'SOCKET'),
        pTypes = ['int', 'int', 'int', 'LPWSAPROTOCOL_INFOA', 'GROUP', 'DWORD']
        pNames = ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        aFReverseLookUp = {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 22: 'AF_APPLETALK', 23: 'AF_NETBIOS',
                           35: 'AF_INET6', 38: 'AF_IRDA', 50: 'AF_BTH'}
        sockTypeReverseLookUp = {1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 4: 'SOCK_RDM', 5: 'SOCK_SEQPACKET'}
        sockProtocolReverseLookUp = {1: 'IPPROTO_ICMP', 2: 'IPPROTO_IGMP', 3: 'BTHPROTO_RFCOMM', 6: 'IPPROTO_TCP',
                                     23: 'IPPROTO_UDP', 88: 'IPPROTO_ICMPV6', 275: 'IPPROTO_RM'}
        dwFlagsReverseLookUp = {1: 'WSA_FLAG_OVERLAPPED', 2: 'WSA_FLAG_MULTIPOINT_C_ROOT',
                                4: 'WSA_FLAG_MULTIPOINT_C_LEAF', 8: 'WSA_FLAG_MULTIPOINT_D_ROOT',
                                16: 'WSA_FLAG_MULTIPOINT_D_LEAF', 64: 'WSA_FLAG_ACCESS_SYSTEM_SECURITY',
                                128: 'WSA_FLAG_NO_HANDLE_INHERIT'}
        groupReverseLookUp = {1: 'SG_UNCONSTRAINED_GROUP', 2: 'SG_CONSTRAINED_GROUP'}

        pVals[0] = getLookUpVal(pVals[0],aFReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],sockTypeReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2],sockProtocolReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4],groupReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5],dwFlagsReverseLookUp)
        
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip= [0, 1, 2, 4, 5])

        socket = Handle(HandleType.Socket)
        
        retVal = socket.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WSASocketA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def WSASocketW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'WSASocketW': (6, ['INT', 'INT', 'INT', 'LPWSAPROTOCOL_INFOW', 'GROUP', 'DWORD'], ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags'], 'SOCKET'),
        pTypes = ['int', 'int', 'int', 'LPWSAPROTOCOL_INFOW', 'GROUP', 'DWORD']
        pNames = ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        aFReverseLookUp = {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 16: 'AF_APPLETALK', 17: 'AF_NETBIOS',
                           23: 'AF_INET6', 26: 'AF_IRDA', 32: 'AF_BTH'}
        sockTypeReverseLookUp = {1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 4: 'SOCK_RDM', 5: 'SOCK_SEQPACKET'}
        sockProtocolReverseLookUp = {1: 'IPPROTO_ICMP', 2: 'IPPROTO_IGMP', 3: 'BTHPROTO_RFCOMM', 6: 'IPPROTO_TCP',
                                     17: 'IPPROTO_UDP', 58: 'IPPROTO_ICMPV6', 113: 'IPPROTO_RM'}
        groupReverseLookUp = {1: 'SG_UNCONSTRAINED_GROUP', 2: 'SG_CONSTRAINED_GROUP'}
        dwFlagsReverseLookUp = {1: 'WSA_FLAG_OVERLAPPED', 2: 'WSA_FLAG_MULTIPOINT_C_ROOT',
                                4: 'WSA_FLAG_MULTIPOINT_C_LEAF', 8: 'WSA_FLAG_MULTIPOINT_D_ROOT',
                                16: 'WSA_FLAG_MULTIPOINT_D_LEAF', 64: 'WSA_FLAG_ACCESS_SYSTEM_SECURITY',
                                128: 'WSA_FLAG_NO_HANDLE_INHERIT'}

        pVals[0] = getLookUpVal(pVals[0],aFReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],sockTypeReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2],sockProtocolReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4],groupReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5],dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [0, 1, 2, 4, 5])
        
        socket = Handle(HandleType.Socket)

        retVal = socket.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WSASocketW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def socket(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # SOCKET WSAAPI socket([in] int af, [in] int type, [in] int protocol)
        pTypes = ['int', 'int', 'int']
        pNames = ['af', 'type', 'protocol']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        aFReverseLookUp = {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 16: 'AF_APPLETALK', 17: 'AF_NETBIOS',
                           23: 'AF_INET6', 26: 'AF_IRDA', 32: 'AF_BTH'}
        sockTypeReverseLookUp = {1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 4: 'SOCK_RDM', 5: 'SOCK_SEQPACKET'}
        sockProtocolReverseLookUp = {1: 'IPPROTO_ICMP', 2: 'IPPROTO_IGMP', 3: 'BTHPROTO_RFCOMM', 6: 'IPPROTO_TCP',
                                     17: 'IPPROTO_UDP', 58: 'IPPROTO_ICMPV6', 113: 'IPPROTO_RM'}

        pVals[0] = getLookUpVal(pVals[0],aFReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],sockTypeReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2],sockProtocolReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [0, 1, 2])

        socket = Handle(HandleType.Socket)
        
        retVal = socket.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("socket", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def BroadcastSystemMessageA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # long BroadcastSystemMessage([in] DWORD   flags, [in, out, optional] LPDWORD lpInfo,
        # [in] UINT Msg, [in]  WPARAM  wParam, [in]  LPARAM  lParam );
        pTypes = ['DWORD', 'LPDWORD', 'UINT', 'WPARAM', 'LPARAM']
        pNames = ['flags', 'lpInfo', 'Msg', 'wParam', 'lParam']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        flagsReverseLookUp = {0x00000080: 'BSF_ALLOWSFW', 0x00000004: 'BSF_FLUSHDISK', 0x00000020: 'BSF_FORCEIFHUNG',
                              0x00000002: 'BSF_IGNORECURRENTTASK', 0x00000008: 'BSF_NOHANG',
                              0x00000040: 'BSF_NOTIMEOUTIFNOTHUNG', 0x00000010: 'BSF_POSTMESSAGE',
                              0x00000001: 'BSF_QUERY', 0x00000100: 'BSF_SENDNOTIFYMESSAGE'}
        lpInfoReverseLookUp = {0x00000000: 'BSM_ALLCOMPONENTS', 0x00000010: 'BSM_ALLDESKTOPS',
                               0x00000008: 'BSM_APPLICATIONS'}

        pVals[0] = getLookUpVal(pVals[0],flagsReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],lpInfoReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [0, 1])

        
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("BroadcastSystemMessageA", hex(callAddr), (retValStr), 'long', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def BroadcastSystemMessageW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # long BroadcastSystemMessage([in] DWORD   flags, [in, out, optional] LPDWORD lpInfo,
        # [in] UINT Msg, [in]  WPARAM  wParam, [in]  LPARAM  lParam );
        pTypes = ['DWORD', 'LPDWORD', 'UINT', 'WPARAM', 'LPARAM']
        pNames = ['flags', 'lpInfo', 'Msg', 'wParam', 'lParam']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        flagsReverseLookUp = {0x00000080: 'BSF_ALLOWSFW', 0x00000004: 'BSF_FLUSHDISK', 0x00000020: 'BSF_FORCEIFHUNG',
                              0x00000002: 'BSF_IGNORECURRENTTASK', 0x00000008: 'BSF_NOHANG',
                              0x00000040: 'BSF_NOTIMEOUTIFNOTHUNG', 0x00000010: 'BSF_POSTMESSAGE',
                              0x00000001: 'BSF_QUERY', 0x00000100: 'BSF_SENDNOTIFYMESSAGE'}
        lpInfoReverseLookUp = {0x00000000: 'BSM_ALLCOMPONENTS', 0x00000010: 'BSM_ALLDESKTOPS',
                               0x00000008: 'BSM_APPLICATIONS'}

        pVals[0] = getLookUpVal(pVals[0],flagsReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],lpInfoReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [0, 1])
        
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("BroadcastSystemMessageW", hex(callAddr), (retValStr), 'long', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateThread(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpThreadId']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwCreateFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        handle = Handle(HandleType.Thread)

        # Round up to next page (4096)
        pVals[1] = ((pVals[1] // 4096) + 1) * 4096

        pVals[4] = getLookUpVal(pVals[4],dwCreateFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4])

        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateRemoteThread(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['hProcess', 'lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags',
                  'lpThreadId']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwCreationFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        handle = Handle(HandleType.Thread)

        # Round up to next page (4096)
        pVals[2] = ((pVals[2] // 4096) + 1) * 4096

        pVals[5] = getLookUpVal(pVals[5],dwCreationFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateRemoteThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def CreateRemoteThreadEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPPROC_THREAD_ATTRIBUTE_LIST', 'LPDWORD']
        pNames = ['hProcess', 'lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpAttributeList', 'lpThreadId']
        dwCreationFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.Thread)

        # Round up to next page (4096)
        pVals[2] = ((pVals[2] // 4096) + 1) * 4096

        pVals[5] = getLookUpVal(pVals[5],dwCreationFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateRemoteThreadEx", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateServiceA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # SC_HANDLE CreateServiceA([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
        pTypes=['SC_HANDLE', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'LPCSTR', 'LPDWORD', 'LPCSTR', 'LPCSTR', 'LPCSTR']
        pNames=['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType', 'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies', 'lpServiceStartName', 'lpPassword']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwDesiredAccessReverseLookUp={0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
        dwServiceTypeReverseLookUp={0x00000004: 'SERVICE_ADAPTER', 0x00000002: 'SERVICE_FILE_SYSTEM_DRIVER', 0x00000001: 'SERVICE_KERNEL_DRIVER', 0x00000008: 'SERVICE_RECOGNIZER_DRIVER', 0x00000010: 'SERVICE_WIN32_OWN_PROCESS', 0x00000020: 'SERVICE_WIN32_SHARE_PROCESS', 0x00000100: 'SERVICE_INTERACTIVE_PROCESS'}
        dwStartTypeReverseLookUp={0x00000002: 'SERVICE_AUTO_START', 0x00000000: 'SERVICE_BOOT_START', 0x00000003: 'SERVICE_DEMAND_START', 0x00000004: 'SERVICE_DISABLED', 0x00000001: 'SERVICE_SYSTEM_START'}
        dwErrorControlReverseLookUp={0x00000003: 'SERVICE_ERROR_CRITICAL', 0x00000000: 'SERVICE_ERROR_IGNORE', 0x00000001: 'SERVICE_ERROR_NORMAL', 0x00000002: 'SERVICE_ERROR_SEVERE'}

        serviceName = read_string(uc, pVals[1])

        handle = Handle(HandleType.SC_HANDLE, name=serviceName)

        pVals[3] = getLookUpVal(pVals[3],dwDesiredAccessReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4],dwServiceTypeReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5],dwStartTypeReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6],dwErrorControlReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [3, 4, 5, 6])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateServiceA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateServiceW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # SC_HANDLE CreateServiceW([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
        pTypes=['SC_HANDLE', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR', 'LPCWSTR', 'LPDWORD', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR']
        pNames=['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType', 'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies', 'lpServiceStartName', 'lpPassword']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwDesiredAccessReverseLookUp={0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
        dwServiceTypeReverseLookUp={0x00000004: 'SERVICE_ADAPTER', 0x00000002: 'SERVICE_FILE_SYSTEM_DRIVER', 0x00000001: 'SERVICE_KERNEL_DRIVER', 0x00000008: 'SERVICE_RECOGNIZER_DRIVER', 0x00000010: 'SERVICE_WIN32_OWN_PROCESS', 0x00000020: 'SERVICE_WIN32_SHARE_PROCESS', 0x00000100: 'SERVICE_INTERACTIVE_PROCESS'}
        dwStartTypeReverseLookUp={0x00000002: 'SERVICE_AUTO_START', 0x00000000: 'SERVICE_BOOT_START', 0x00000003: 'SERVICE_DEMAND_START', 0x00000004: 'SERVICE_DISABLED', 0x00000001: 'SERVICE_SYSTEM_START'}
        dwErrorControlReverseLookUp={0x00000003: 'SERVICE_ERROR_CRITICAL', 0x00000000: 'SERVICE_ERROR_IGNORE', 0x00000001: 'SERVICE_ERROR_NORMAL', 0x00000002: 'SERVICE_ERROR_SEVERE'}

        serviceName = read_unicode(uc, pVals[1])

        handle = Handle(HandleType.SC_HANDLE, name=serviceName)

        pVals[3] = getLookUpVal(pVals[3],dwDesiredAccessReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4],dwServiceTypeReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5],dwStartTypeReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6],dwErrorControlReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [3, 4, 5, 6])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateServiceW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenServiceA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE', 'LPCSTR', 'DWORD']
        pNames = ['hSCManager', 'lpServiceName', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}

        serviceName = read_string(uc, pVals[1])

        retVal = 0
        for key, handle in HandlesDict.items():
            if handle.name == serviceName:
                retVal = handle.value
                break

        pVals[2] = getLookUpVal(pVals[2],dwDesiredAccessReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenServiceA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenServiceW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE', 'LPCWSTR', 'DWORD']
        pNames = ['hSCManager', 'lpServiceName', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG', 0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE', 0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG', 0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP', 0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE', 0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}

        serviceName = read_unicode(uc, pVals[1])

        retVal = 0
        for key, handle in HandlesDict.items():
            if handle.name == serviceName:
                retVal = handle.value
                break

        pVals[2] = getLookUpVal(pVals[2],dwDesiredAccessReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenServiceW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def StartServiceA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE', 'DWORD', 'LPCSTR *']
        pNames = ['hService', 'dwNumServiceArgs', 'lpServiceArgVectors']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("StartServiceA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def StartServiceW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE', 'DWORD', 'LPCWSTR *']
        pNames = ['hService', 'dwNumServiceArgs', 'lpServiceArgVectors']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("StartServiceW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ControlService(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE', 'DWORD', 'LPSERVICE_STATUS']
        pNames = ['hService', 'dwControl', 'lpServiceStatus']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwControlReverseLookUp = {3: 'SERVICE_CONTROL_CONTINUE', 4: 'SERVICE_CONTROL_INTERROGATE',
                                  7: 'SERVICE_CONTROL_NETBINDADD', 10: 'SERVICE_CONTROL_NETBINDDISABLE',
                                  9: 'SERVICE_CONTROL_NETBINDENABLE', 8: 'SERVICE_CONTROL_NETBINDREMOVE',
                                  6: 'SERVICE_CONTROL_PARAMCHANGE', 2: 'SERVICE_CONTROL_PAUSE',
                                  1: 'SERVICE_CONTROL_STOP'}

        pVals[1] = getLookUpVal(pVals[1], dwControlReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ControlService", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ControlServiceExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE', 'DWORD', 'DWORD', 'PVOID']
        pNames = ['hService', 'dwControl', 'dwInfoLevel', 'pControlParams']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwControlReverseLookUp = {3: 'SERVICE_CONTROL_CONTINUE', 4: 'SERVICE_CONTROL_INTERROGATE',
                                  7: 'SERVICE_CONTROL_NETBINDADD', 10: 'SERVICE_CONTROL_NETBINDDISABLE',
                                  9: 'SERVICE_CONTROL_NETBINDENABLE', 8: 'SERVICE_CONTROL_NETBINDREMOVE',
                                  6: 'SERVICE_CONTROL_PARAMCHANGE', 2: 'SERVICE_CONTROL_PAUSE',
                                  1: 'SERVICE_CONTROL_STOP'}
        dwInfoLevelReverseLookUp = {1: 'SERVICE_CONTROL_STATUS_REASON_INFO'}

        pVals[1] = getLookUpVal(pVals[1], dwControlReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2], dwInfoLevelReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ControlServiceExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ControlServiceExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE', 'DWORD', 'DWORD', 'PVOID']
        pNames = ['hService', 'dwControl', 'dwInfoLevel', 'pControlParams']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwControlReverseLookUp = {3: 'SERVICE_CONTROL_CONTINUE', 4: 'SERVICE_CONTROL_INTERROGATE',
                                  7: 'SERVICE_CONTROL_NETBINDADD', 10: 'SERVICE_CONTROL_NETBINDDISABLE',
                                  9: 'SERVICE_CONTROL_NETBINDENABLE', 8: 'SERVICE_CONTROL_NETBINDREMOVE',
                                  6: 'SERVICE_CONTROL_PARAMCHANGE', 2: 'SERVICE_CONTROL_PAUSE',
                                  1: 'SERVICE_CONTROL_STOP'}
        dwInfoLevelReverseLookUp = {1: 'SERVICE_CONTROL_STATUS_REASON_INFO'}

        pVals[1] = getLookUpVal(pVals[1], dwControlReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2], dwInfoLevelReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ControlServiceExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def DeleteService(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE']
        pNames = ['hService']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if pVals[0] in HandlesDict:
            HandlesDict.pop(pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("DeleteService", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CloseServiceHandle(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SC_HANDLE']
        pNames = ['hSCObject']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if pVals[0] in HandlesDict:
            HandlesDict.pop(pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CloseServiceHandle", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptDecrypt(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HCRYPTKEY', 'HCRYPTHASH', 'BOOL', 'DWORD', 'BYTE', 'DWORD']
        pNames = ['hKey', 'hHash', 'Final', 'dwFlags', 'pbData', 'pdwDataLen']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {64: 'CRYPT_OAEP', 32: 'CRYPT_DECRYPT_RSA_NO_PADDING_CHECK'}

        pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptDecrypt", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HeapCreate(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HANDLE HeapCreate([in] DWORD  flOptions,[in] SIZE_T dwInitialSize,[in] SIZE_T dwMaximumSize);
        pTypes = ['DWORD', 'SIZE_T', 'SIZE_T']
        pNames = ['flOptions', 'dwInitialSize', 'dwMaximumSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        flOptionsReverseLookUp = {0x00040000: 'HEAP_CREATE_ENABLE_EXECUTE', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                  0x00000001: 'HEAP_NO_SERIALIZE'}

        heap = Heap(uc, 0, pVals[2])

        pVals[0] = getLookUpVal(pVals[0], flOptionsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = heap.handle
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapCreate", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HeapAlloc(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # DECLSPEC_ALLOCATOR LPVOID HeapAlloc([in] HANDLE hHeap, [in] DWORD  dwFlags, [in] SIZE_T dwBytes)
        pTypes = ['HANDLE', 'DWORD', 'SIZE_T']
        pNames = ['hHeap', 'dwFlags', 'dwBytes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReverseLookUp = {0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                0x00000001: 'HEAP_NO_SERIALIZE'}

        # Round up to next page (4096)
        pVals[2] = ((pVals[2] // 4096) + 1) * 4096

        try:
            heap = HeapsDict[pVals[0]]
        except:
            heap = Heap(uc, pVals[0], pVals[2])

        allocation = heap.createAllocation(uc, pVals[2])

        pVals[1] = getLookUpVal(pVals[1], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = allocation.address
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapAlloc", hex(callAddr), (retValStr), 'LPVOID', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HeapDestroy(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL HeapDestroy([in] HANDLE hHeap);
        pTypes = ['HANDLE']
        pNames = ['hHeap']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            heap = HeapsDict[pVals[0]]
            heap.destroy(uc)
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapDestroy", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HeapFree(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL HeapFree([in] HANDLE hHeap,[in] DWORD dwFlags,[in] _Frees_ptr_opt_ LPVOID lpMem);
        pTypes = ['HANDLE', 'DWORD', '_Frees_ptr_opt_ LPVOID']
        pNames = ['hHeap', 'dwFlags', 'lpMem']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReverseLookUp = {0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                0x00000001: 'HEAP_NO_SERIALIZE'}

        try:
            heap = HeapsDict[pVals[0]]
            heap.free(uc, pVals[2])
        except:
            pass

        pVals[1] = getLookUpVal(pVals[1], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HeapSize(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # SIZE_T HeapSize([in] HANDLE  hHeap,[in] DWORD   dwFlags,[in] LPCVOID lpMem);
        pTypes = ['HANDLE', 'DWORD', 'LPCVOID']
        pNames = ['hHeap', 'dwFlags', 'lpMem']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReverseLookUp = {0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                0x00000001: 'HEAP_NO_SERIALIZE'}

        try:
            heap = HeapsDict[pVals[0]]
            if pVals[2] in heap.allocations:
                retVal = heap.allocations[pVals[2]].size
        except:
            retVal = 0x0
            pass

        pVals[1] = getLookUpVal(pVals[1], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapSize", hex(callAddr), (retValStr), 'SIZE_T', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HeapReAlloc(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # DECLSPEC_ALLOCATOR LPVOID HeapReAlloc([in] HANDLE hHeap,[in] DWORD dwFlags,[in] _Frees_ptr_opt_ LPVOID lpMem,[in] SIZE_T dwBytes);
        pTypes = ['HANDLE', 'DWORD', '_Frees_ptr_opt_ LPVOID', 'SIZE_T']
        pNames = ['hHeap', 'dwFlags', 'lpMem', 'dwBytes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReverseLookUp = {0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                0x00000001: 'HEAP_NO_SERIALIZE', 0x00000010: 'HEAP_REALLOC_IN_PLACE_ONLY'}

        # Round up to next page (4096)
        pVals[3] = ((pVals[3] // 4096) + 1) * 4096

        if pVals[0] in HeapsDict:
            heap = HeapsDict[pVals[0]]
            allocation = heap.reAlloc(uc, pVals[2], pVals[3])
        else:
            heap = Heap(uc, pVals[0], pVals[2])
            allocation = heap.createAllocation(uc, pVals[3])

        pVals[1] = getLookUpVal(pVals[1], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = allocation.address
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapReAlloc", hex(callAddr), (retValStr), 'LPVOID', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetProcessHeap(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HANDLE GetProcessHeap()
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Create new Heap
        heap = Heap(uc, 0, 4096)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = heap.handle
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetProcessHeap", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetProcessHeaps(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'GetProcessHeaps': (2, ['DWORD', 'PHANDLE'], ['NumberOfHeaps', 'ProcessHeaps'], 'DWORD'),
        pTypes = ['DWORD', 'PHANDLE']
        pNames = ['NumberOfHeaps', 'ProcessHeaps']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Get Heaps from Heap Dict
        total = 0
        for heap in HeapsDict:
            uc.mem_write(pVals[1] + (total * 4), pack('<I', HeapsDict[heap].handle))
            total += 1
            if total == pVals[0]:  # Write up to NumberOfHeaps to Memory
                break

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = total
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetProcessHeaps", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateToolhelp32Snapshot(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['DWORD', 'DWORD']
        pNames = ['dwFlags', 'th32ProcessID']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReverseLookUp = {2147483648: 'TH32CS_INHERIT', 15: 'TH32CS_SNAPALL', 1: 'TH32CS_SNAPHEAPLIST',
                                8: 'TH32CS_SNAPMODULE', 16: 'TH32CS_SNAPMODULE32', 2: 'TH32CS_SNAPPROCESS',
                                4: 'TH32CS_SNAPTHREAD', 15: 'TH32CS_SNAPALL'}

        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot)

        pVals[0] = getLookUpVal(pVals[0], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateToolhelp32Snapshot", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Process32First(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32First([in] HANDLE hSnapshot,[in, out] LPPROCESSENTRY32 lppe);
        pTypes = ['HANDLE', 'LPPROCESSENTRY32']
        pNames = ['hSnapshot', 'lppe']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'
        
        pVals[1] = makeStructVals(uc, process, pVals[1])
        
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Process32Next(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32Next([in]  HANDLE hSnapshot,[out] LPPROCESSENTRY32 lppe);
        pTypes = ['HANDLE', 'LPPROCESSENTRY32']
        pNames = ['hSnapshot', 'lppe']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            handle.data.processOffset = processList[processList.index(handle.data.processOffset) + 1]
        except:
            handle.data.processOffset = None
            pass

        if handle.data.processOffset in handle.data.processDict:
            process = handle.data.processDict[handle.data.processOffset]
            process.writeToMemoryA(uc, pVals[1])
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Process32FirstW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32FirstW([in] HANDLE hSnapshot,[in, out] LPPROCESSENTRY32W lppe);
        pTypes = ['HANDLE', 'LPPROCESSENTRY32W']
        pNames = ['hSnapshot', 'lppe']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32FirstW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Process32NextW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32NextW([in]  HANDLE hSnapshot,[out] LPPROCESSENTRY32W lppe);
        pTypes = ['HANDLE', 'LPPROCESSENTRY32W']
        pNames = ['hSnapshot', 'lppe']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            handle.data.processOffset = processList[processList.index(handle.data.processOffset) + 1]
        except:
            handle.data.processOffset = None
            pass

        if handle.data.processOffset in handle.data.processDict:
            process = handle.data.processDict[handle.data.processOffset]
            process.writeToMemoryW(uc, pVals[1])
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32NextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Thread32First(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Thread32First([in] HANDLE hSnapshot,[in, out] LPTHREADENTRY32 lpte);
        pTypes = ['HANDLE', 'LPTHREADENTRY32']
        pNames = ['hSnapshot', 'lpte']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Thread32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Thread32Next(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Thread32Next([in] HANDLE hSnapshot,[out] LPTHREADENTRY32 lpte);
        pTypes = ['HANDLE', 'LPTHREADENTRY32']
        pNames = ['hSnapshot', 'lpte']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            handle.data.threadOffset = threadList[threadList.index(handle.data.threadOffset) + 1]
        except:
            handle.data.threadOffset = None
            pass

        if handle.data.threadOffset in handle.data.threadDict:
            thread = handle.data.threadDict[handle.data.threadOffset]
            thread.writeToMemory(uc, pVals[1])
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Thread32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Module32First(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32First([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32 lpme);
        pTypes = ['HANDLE', 'LPMODULEENTRY32']
        pNames = ['hSnapshot', 'lpme']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Module32Next(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32Next([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32 lpme);
        pTypes = ['HANDLE', 'LPMODULEENTRY32']
        pNames = ['hSnapshot', 'lpme']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Module32FirstW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32FirstW([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32W lpme);
        pTypes = ['HANDLE', 'LPMODULEENTRY32']
        pNames = ['hSnapshot', 'lpme']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32FirstW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Module32NextW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32NextW([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32W lpme);
        pTypes = ['HANDLE', 'LPMODULEENTRY32W']
        pNames = ['hSnapshot', 'lpme']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
            retVal = 0x1
            retValStr = 'TRUE'
        else:
            retVal = 0x0
            retValStr = 'FALSE'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32NextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Toolhelp32ReadProcessMemory2(self, uc: Uc, eip, esp, export_dict, callAddr, em): # Needs to be Redone 
        pTypes = ['DWORD', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T']
        pNames = ['th32ProcessID', 'lpBaseAddress', 'lpBuffer', 'cbRead', 'lpNumberOfBytesRead']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        th32ProcessID = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        th32ProcessID = unpack('<I', th32ProcessID)[0]
        lpBaseAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 4)
        lpBaseAddress = unpack('<I', lpBaseAddress)[0]
        lpBuffer = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 12, 4)
        lpBuffer = unpack('<I', lpBuffer)[0]
        cbRead = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 16, 4)
        cbRead = unpack('<I', cbRead)[0]
        lpNumberOfBytesRead = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 20, 4)
        lpNumberOfBytesRead = unpack('<I', lpNumberOfBytesRead)[0]
        global availMem
        # Round up to next page (4096)
        cbRead = ((cbRead // 4096) + 1) * 4096
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

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Toolhelp32ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    # Memory Functions
    def WriteProcessMemory(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL WriteProcessMemory([in]  HANDLE  hProcess,[in]  LPVOID  lpBaseAddress,[in]  LPCVOID lpBuffer,[in]  SIZE_T  nSize,[out] SIZE_T  *lpNumberOfBytesWritten);
        pTypes = ['HANDLE', 'LPVOID', 'LPCVOID', 'SIZE_T', 'SIZE_T']
        pNames = ['hProcess', 'lpBaseAddress', 'lpBuffer', 'nSize', '*lpNumberOfBytesWritten']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[2], pVals[3])
            fmt = '<' + str(pVals[3]) + 's'
            uc.mem_write(pVals[1], pack(fmt, buffer))
            uc.mem_write(pVals[4], pack('<I',pVals[3]))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WriteProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def memcpy(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['void', 'const void', 'size_t']
        pNames = ['*dest', '*src', 'count']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[1], pVals[2])
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        retVal = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memcpy", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def memcpy_s(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['void', 'size_t', 'const void', 'size_t']
        pNames = ['*dest', 'destSize', '*src', 'count']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[2], pVals[3])
            fmt = '<' + str(pVals[1]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memcpy_s", hex(callAddr), (retValStr), 'errno_t', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def memmove(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['void', 'const void', 'size_t']
        pNames = ['*dest', '*src', 'count']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[1], pVals[2])
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        retVal = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memmove", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def memmove_s(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['void', 'size_t', 'const void', 'size_t']
        pNames = ['*dest', 'numberOfElements', '*src', 'count']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[2], pVals[3])
            fmt = '<' + str(pVals[1]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memmove_s", hex(callAddr), (retValStr), 'errno_t', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def memset(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['void', 'int', 'size_t']
        pNames = ['*dest', 'c', 'count']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[0], pVals[2])
            for i in range(pVals[2]):
                buffer[i] = pVals[1]
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        retVal = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memset", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def memcmp(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['const void', 'const void', 'size_t']
        pNames = ['*buffer1', '*buffer2', 'count']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer1 = uc.mem_read(pVals[0], pVals[2])
            buffer2 = uc.mem_read(pVals[1], pVals[2])
            if buffer1[:pVals[2]] == buffer2[:pVals[2]]:  # Check if Same
                retVal = 0
            else:
                for i in range(pVals[2]):  # Check Byte by Byte
                    # print('Index:', i, 'B1:', buffer1[i], 'B2:', buffer2[i])
                    if buffer1[i] < buffer2[i]:
                        retVal = -1
                        break
                    elif buffer1[i] > buffer2[i]:
                        retVal = 1
                        break
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memcmp", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def memchr(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['const void', 'int', 'size_t']
        pNames = ['*buffer', 'c', 'count']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

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
                retVal = 0
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        if retVal == 0:
            retValStr = 'NULL'
        else:
            retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memchr", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RtlMoveMemory(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['VOID UNALIGNED', 'VOID UNALIGNED', 'SIZE_T']
        pNames = ['*Destination', '*Source', 'Length']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[1], pVals[2])
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retValStr = ''

        logged_calls = ("RtlMoveMemory", hex(callAddr), (retValStr), 'VOID', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ReadProcessMemory(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL ReadProcessMemory([in]  HANDLE  hProcess,[in]  LPCVOID lpBaseAddress,[out] LPVOID  lpBuffer,[in]  SIZE_T  nSize,[out] SIZE_T  *lpNumberOfBytesRead);
        pTypes = ['HANDLE', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T']
        pNames = ['hProcess', 'lpBaseAddress', 'lpBuffer', 'nSize', '*lpNumberOfBytesRead']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            buffer = uc.mem_read(pVals[1], pVals[3])
            fmt = '<' + str(pVals[3]) + 's'
            uc.mem_write(pVals[2], pack(fmt, buffer))
            if pVals[4] != 0x0:
                uc.mem_write(pVals[4], pack('<I', len(buffer)))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # print ("CreateProcessA2")
        """'CreateProcess': (10, ['LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION'], ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation'], 'BOOL'),"""

        # function to get values for parameters - count as specified at the end - returned as a list
        pTypes = ['LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID',
                  'LPCSTR',
                  'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
        pNames = ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles',
                  'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[5] = getLookUpVal(pVals[5], ReverseLookUps.ProcessCreation)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = get_PROCESS_INFORMATION(uc, pVals[9], em)
        processInfo.setValues(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[9])

        pVals[9] = makeStructVals(uc, processInfo, pVals[9])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5,9])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPWSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID',
                  'LPCWSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
        pNames = ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles',
                  'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[5] = getLookUpVal(pVals[5], ReverseLookUps.ProcessCreation)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = get_PROCESS_INFORMATION(uc, pVals[9], em)
        processInfo.setValues(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[9])

        pVals[9] = makeStructVals(uc, processInfo, pVals[9])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5,9])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessInternalA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['DWORD', 'LPCTSTR', 'LPTSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID',
                  'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION', 'DWORD']
        pNames = ['unknown1', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation', 'unknown2']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pVals[6] = getLookUpVal(pVals[6], ReverseLookUps.ProcessCreation)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = get_PROCESS_INFORMATION(uc, pVals[10], em)
        processInfo.setValues(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessInternalA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessInternalW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['DWORD', 'LPCTWSTR', 'LPTWSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID', 'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION', 'DWORD']
        pNames = ['unknown1', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation', 'unknown2']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pVals[6] = getLookUpVal(pVals[6], ReverseLookUps.ProcessCreation)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = get_PROCESS_INFORMATION(uc, pVals[10], em)
        processInfo.setValues(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessInternalW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessAsUserA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID',
                  'LPCSTR', 'LPSTARTUPINFOA', 'LPPROCESS_INFORMATION']
        pNames = ['hToken', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pVals[6] = getLookUpVal(pVals[6], ReverseLookUps.ProcessCreation)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = get_PROCESS_INFORMATION(uc, pVals[10], em)
        processInfo.setValues(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessAsUserA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessAsUserW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPCWSTR', 'LPWSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID', 'LPCWSTR', 'LPSTARTUPINFOW', 'LPPROCESS_INFORMATION']
        pNames = ['hToken', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pVals[6] = getLookUpVal(pVals[6], ReverseLookUps.ProcessCreation)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = get_PROCESS_INFORMATION(uc, pVals[10], em)
        processInfo.setValues(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessAsUserW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLDownloadToFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # function to get values for parameters - count as specified at the end - returned as a list
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToFileA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLDownloadToCacheFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'LPTSTR', 'DWORD', 'DWORD', 'IBindStatusCallback']
        pNames = ['lpUnkCaller', 'szURL', 'szFileName', 'cchFileName', 'dwReserved', '*pBSC']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToCacheFileA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLDownloadToCacheFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'IBindStatusCallback']
        pNames = ['lpUnkCaller', 'szURL', 'szFileName', 'cchFileName', 'dwReserved', '*pBSC']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToCacheFileW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLDownloadToFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToFileW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def WinExec(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'UINT']
        pNames = ['lpCmdLine', 'uCmdShow']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

    
        pVals[1] = getLookUpVal(pVals[1], cmdShowReverseLookUp)
    
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        #get the commandline from the arguments
        winexec_args = (pVals[0])
        art.commandLine_HookApis.add(winexec_args)

        
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WinExec", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ShellExecuteA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HINSTANCE ShellExecuteA([in, optional] HWND   hwnd, [in, optional] LPCSTR lpOperation,[in] LPCSTR lpFile,
        # [in, optional] LPCSTR lpParameters, [in, optional] LPCSTR lpDirectory, [in] INT    nShowCmd);
        pTypes = ['HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'INT']
        pNames = ['hwnd', 'lpOperation', 'lpFile', 'lpParameters', 'lpDirectory', 'nShowCmd']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

        pVals[5] = getLookUpVal(pVals[5], cmdShowReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5])
        
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ShellExecuteA", hex(callAddr), (retValStr), 'HINSTANCE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ShellExecuteW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HINSTANCE ShellExecuteW([in, optional] HWND   hwnd, [in, optional] LPCSTR lpOperation,[in] LPCSTR lpFile,
        # [in, optional] LPCSTR lpParameters, [in, optional] LPCSTR lpDirectory, [in] INT    nShowCmd);
        pTypes = ['HWND', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'INT']
        pNames = ['hwnd', 'lpOperation', 'lpFile', 'lpParameters', 'lpDirectory', 'nShowCmd']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

        pVals[5] = getLookUpVal(pVals[5], cmdShowReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5])
        
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ShellExecuteW", hex(callAddr), (retValStr), 'HINSTANCE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def system(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # int system(const char *command);
        pTypes = ['const char']
        pNames = ['*command']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[0] = read_string(uc, pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        system_args = (pVals[0])
        art.commandLine_HookApis.add(system_args)

        
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("system", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def _wsystem(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # int _wsystem(const wchar_t *command);
        pTypes = ['const wchar_t']
        pNames = ['*command']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[0] = read_unicode(uc, pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        wsystem_args = (pVals[0])
        art.commandLine_HookApis.add(wsystem_args)

        
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("_wsystem", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetOpenA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'DWORD', 'LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpszAgent', 'dwAccessType', 'lpszProxy', 'lpszProxyBypass', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwAccessTypeReverseLookUp = {0: 'INTERNET_OPEN_TYPE_PRECONFIG', 1: 'INTERNET_OPEN_TYPE_DIRECT',
                                     3: 'INTERNET_OPEN_TYPE_PROXY', 4: 'INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY'}
        dwFlagsReverseLookUp = {268435456: 'INTERNET_FLAG_ASYNC', 16777216: 'INTERNET_FLAG_FROM_CACHE'}

        pVals[1] = getLookUpVal(pVals[1], dwAccessTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        handle = Handle(HandleType.HINTERNET)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,4])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetOpenW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'DWORD', 'LPCWSTR', 'LPCWSTR', 'DWORD']
        pNames = ['lpszAgent', 'dwAccessType', 'lpszProxy', 'lpszProxyBypass', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwAccessTypeReverseLookUp = {0: 'INTERNET_OPEN_TYPE_PRECONFIG', 1: 'INTERNET_OPEN_TYPE_DIRECT',
                                     3: 'INTERNET_OPEN_TYPE_PROXY', 4: 'INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY'}
        dwFlagsReverseLookUp = {268435456: 'INTERNET_FLAG_ASYNC', 16777216: 'INTERNET_FLAG_FROM_CACHE'}

        pVals[1] = getLookUpVal(pVals[1], dwAccessTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        handle = Handle(HandleType.HINTERNET)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,4])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetConnectA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'INTERNET_PORT', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszServerName', 'nServerPort', 'lpszUserName', 'lpszPassword', 'dwService', 'dwFlags','dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        nServerPortReverseLookUp = {0: 'INTERNET_INVALID_PORT_NUMBER', 33: 'INTERNET_DEFAULT_FTP_PORT',
                                    112: 'INTERNET_DEFAULT_GOPHER_PORT', 128: 'INTERNET_DEFAULT_HTTP_PORT',
                                    1091: 'INTERNET_DEFAULT_HTTPS_PORT', 4224: 'INTERNET_DEFAULT_SOCKS_PORT'}
        dwServiceReverseLookUp = {1: 'INTERNET_SERVICE_FTP', 2: 'INTERNET_SERVICE_GOPHER', 3: 'INTERNET_SERVICE_HTTP'}
        dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 134217728: 'INTERNET_FLAG_PASSIVE',
                                1: 'WININET_API_FLAG_ASYNC', 4: 'WININET_API_FLAG_SYNC'}

        pVals[2] = getLookUpVal(pVals[2], nServerPortReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], dwServiceReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [2, 5, 6])

        handle = Handle(HandleType.HINTERNET,name=pVals[1])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetConnectA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetConnectW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCWSTR', 'INTERNET_PORT', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszServerName', 'nServerPort', 'lpszUserName', 'lpszPassword', 'dwService', 'dwFlags','dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        nServerPortReverseLookUp = {0: 'INTERNET_INVALID_PORT_NUMBER', 33: 'INTERNET_DEFAULT_FTP_PORT',
                                    112: 'INTERNET_DEFAULT_GOPHER_PORT', 128: 'INTERNET_DEFAULT_HTTP_PORT',
                                    1091: 'INTERNET_DEFAULT_HTTPS_PORT', 4224: 'INTERNET_DEFAULT_SOCKS_PORT'}
        dwServiceReverseLookUp = {1: 'INTERNET_SERVICE_FTP', 2: 'INTERNET_SERVICE_GOPHER', 3: 'INTERNET_SERVICE_HTTP'}
        dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 134217728: 'INTERNET_FLAG_PASSIVE',
                                1: 'WININET_API_FLAG_ASYNC', 4: 'WININET_API_FLAG_SYNC'}

        pVals[2] = getLookUpVal(pVals[2], nServerPortReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], dwServiceReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [2, 5, 6])
        
        handle = Handle(HandleType.HINTERNET,name=pVals[1])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetConnectW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCreateKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'LPSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwOptionsReverseLookUp = {4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK',
                                  0: 'REG_OPTION_NON_VOLATILE',
                                  1: 'REG_OPTION_VOLATILE'}
        lpdwDispostitionReverseLookUp = {1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}

        

        keyPath = ''

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[7], pack('<I',hKey))
        except:
            pass
        
        pVals[4] = getLookUpVal(pVals[4], dwOptionsReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], RegKey.securityAccessRights)
        pVals[8] = getLookUpVal(pVals[8], lpdwDispostitionReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1, 4, 5, 8])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegCreateKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCreateKeyExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # LSTATUS RegCreateKeyExW([in] HKEY hKey,[in] LPCSTR lpSubKey,DWORD Reserved,[in, optional]  LPSTR lpClass,[in] DWORD dwOptions,[in] REGSAM samDesired,[in, optional] const LPSECURITY_ATTRIBUTES lpSecurityAttributes,[out] PHKEY phkResult,[out, optional] LPDWORD lpdwDisposition);
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'LPWSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwOptionsReverseLookUp = {4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK',
                                  0: 'REG_OPTION_NON_VOLATILE',
                                  1: 'REG_OPTION_VOLATILE'}
        lpdwDispostitionReverseLookUp = {1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}

        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[7], pack('<I',hKey))
        except:
            pass

        pVals[4] = getLookUpVal(pVals[4], dwOptionsReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], RegKey.securityAccessRights)
        pVals[8] = getLookUpVal(pVals[8], lpdwDispostitionReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1, 4, 5, 8] )

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegCreateKeyExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCreateKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'PHKEY']
        pNames = ['hkey', 'lpSubKey', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[2], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)
           
        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegCreateKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCreateKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'PHKEY']
        pNames = ['hkey', 'lpSubKey', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[2], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)
    
        logged_calls = ("RegCreateKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCreateKeyTransactedA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'LPSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD','HANDLE','PVOID']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition','hTransaction','pExtendedParemeter']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwOptionsReverseLookUp = {4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK',
                                  0: 'REG_OPTION_NON_VOLATILE',
                                  1: 'REG_OPTION_VOLATILE'}
        lpdwDispostitionReverseLookUp = {1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}

        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[7], pack('<I',hKey))
        except:
            pass
        
        pVals[4] = getLookUpVal(pVals[4], dwOptionsReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], RegKey.securityAccessRights)
        pVals[8] = getLookUpVal(pVals[8], lpdwDispostitionReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1, 4, 5, 8])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegCreateKeyTransactedA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCreateKeyTransactedW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'LPWSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD','HANDLE','PVOID']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition','hTransaction','pExtendedParemeter']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwOptionsReverseLookUp = {4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK',
                                  0: 'REG_OPTION_NON_VOLATILE',
                                  1: 'REG_OPTION_VOLATILE'}
        lpdwDispostitionReverseLookUp = {1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[7], pack('<I',hKey))
        except:
            pass
        
        pVals[4] = getLookUpVal(pVals[4], dwOptionsReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], RegKey.securityAccessRights)
        pVals[8] = getLookUpVal(pVals[8], lpdwDispostitionReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1, 4, 5, 8])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegCreateKeyTransactedW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenKeyTransactedA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult','hTransaction','pExtendedParemeter']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        ulOptionReverseLookUp = {0x00000008: 'REG_OPTION_OPEN_LINK'}
        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}
        
        pVals[2] = getLookUpVal(pVals[2], ulOptionReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], samDesiredReverseLookUp)     

        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[4], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegOpenKeyTransactedA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenKeyTransactedW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult','hTransaction','pExtendedParemeter']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        ulOptionReverseLookUp = {0x00000008: 'REG_OPTION_OPEN_LINK'}
        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}
        
        pVals[2] = getLookUpVal(pVals[2], ulOptionReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], samDesiredReverseLookUp)     

        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[4], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegOpenKeyTransactedW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['HKEY', 'LPCSTR', 'PHKEY']
        pNames = ['hkey', 'lpSubKey', 'phkResult']

        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[2], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)
 
        logged_calls = ("RegOpenKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'PHKEY']
        pNames = ['hkey', 'lpSubKey', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[2], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)
        
        logged_calls = ("RegOpenKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        
        

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        foundKey.deleteKey()
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.deleteKey()
                else:
                    keyPath = hKey.name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_delete_keys.add(keyPath)

        logged_calls = ("RegDeleteKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        foundKey.deleteKey()
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.deleteKey()
                else:
                    keyPath = hKey.name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_delete_keys.add(keyPath)

        logged_calls = ("RegDeleteKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'REGSAM', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        foundKey.deleteKey()
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.deleteKey()
                else:
                    keyPath = hKey.name


        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_delete_keys.add(keyPath)

        logged_calls = ("RegDeleteKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteKeyExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'REGSAM', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        


        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        foundKey.deleteKey()
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.deleteKey()
                else:
                    keyPath = hKey.name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_delete_keys.add(keyPath)

        logged_calls = ("RegDeleteKeyExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteKeyTransactedA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'REGSAM', 'DWORD', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved', 'hTransaction', 'pExtendedParameter']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        foundKey.deleteKey()
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.deleteKey()
                else:
                    keyPath = hKey.name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_delete_keys.add(keyPath)

        logged_calls = ("RegDeleteKeyTransactedA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteKeyTransactedW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'REGSAM', 'DWORD', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved', 'hTransaction', 'pExtendedParameter']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        foundKey.deleteKey()
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.deleteKey()
                else:
                    keyPath = hKey.name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_delete_keys.add(keyPath)

        logged_calls = ("RegDeleteKeyTransactedW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteTreeA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        keysToDelete = set()

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys:
                        foundKey = RegistryKeys[keyPath]
                        keysToDelete.add(foundKey)
                        for key, val in RegistryKeys.items():
                            if keyPath in key:
                                keysToDelete.add(val)
                    else: # KeyPath Not Found Check If Part of another Key
                        for key, val in RegistryKeys.items():
                            if keyPath in key:
                                keysToDelete.add(val)
                else:
                    keyPath = hKey.name + lpSubKey
                    for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)
            else:
                keyPath += lpSubKey
                for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)
        else: # [NULL] lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)
                else:
                    keyPath = hKey.name
                    for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)

        
        if len(keysToDelete) > 0:
            art.registry_delete_keys.add(keyPath)
            for rKey in keysToDelete:
                rKey.deleteKey()

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)


        logged_calls = ("RegDeleteTreeA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteTreeW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        keysToDelete = set()

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys:
                        foundKey = RegistryKeys[keyPath]
                        keysToDelete.add(foundKey)
                        for key, val in RegistryKeys.items():
                            if keyPath in key:
                                keysToDelete.add(val)
                    else: # KeyPath Not Found Check If Part of another Key
                        for key, val in RegistryKeys.items():
                            if keyPath in key:
                                keysToDelete.add(val)
                else:
                    keyPath = hKey.name + lpSubKey
                    for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)
            else:
                keyPath += lpSubKey
                for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)
        else: # [NULL] lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)
                else:
                    keyPath = hKey.name
                    for key, val in RegistryKeys.items():
                        if keyPath in key:
                            keysToDelete.add(val)


        if len(keysToDelete) > 0:
            art.registry_delete_keys.add(keyPath)
            for rKey in keysToDelete:
                rKey.deleteKey()

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)


        logged_calls = ("RegDeleteTreeW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def RegGetValueA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPDWORD', 'PVOID', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValue', 'dwFlags', 'pdwType', 'pvData', 'pcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        dwFlagsReverseLookUp = {65535: 'RRF_RT_ANY', 24: 'RRF_RT_DWORD', 72: 'RRF_RT_QWORD', 8: 'RRF_RT_REG_BINARY',
                                16: 'RRF_RT_REG_DWORD', 4: 'RRF_RT_REG_EXPAND_SZ', 32: 'RRF_RT_REG_MULTI_SZ',
                                1: 'RRF_RT_REG_NONE', 64: 'RRF_RT_REG_QWORD', 2: 'RRF_RT_REG_SZ',
                                268435456: 'RRF_NOEXPAND',
                                536870912: 'RRF_ZEROONFAILURE', 65536: 'RRF_SUBKEY_WOW6464KEY',
                                131072: 'RRF_SUBKEY_WOW6432KEY'}

        lpSubKey = read_string(uc, pVals[1])
        lpValue = read_string(uc, pVals[2])

        keyPath = ''
        keyValue = None

        if lpSubKey == '[NULL]':
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        registry_key_address = foundKey
                        if lpValue == '[NULL]':
                            keyValue = foundKey.getValue()
                        else:
                            keyValue = foundKey.getValue(lpValue)
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        registry_key_address = foundKey
                        if lpValue == '[NULL]':
                            keyValue = foundKey.getValue()
                        else:
                            keyValue = foundKey.getValue(lpValue)

        if keyValue is not None:
            # info grab here 
            # print(keyValue.name)
            #registry_values.add(())
            type = keyValue.type
            try:
                uc.mem_write(pVals[4],pack('<I',keyValue.type.value))
                if type == RegValueTypes.REG_BINARY:
                    uc.mem_write(pVals[5],pack(f'<{len(keyValue.data)}s',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',len(keyValue.data)))
                elif type == RegValueTypes.REG_DWORD:
                    uc.mem_write(pVals[5],pack(f'<I',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',4))
                elif type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    uc.mem_write(pVals[5],pack(f'>I',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',4))
                elif type == RegValueTypes.REG_QWORD:
                    uc.mem_write(pVals[5],pack(f'<Q',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',8))
                elif type == RegValueTypes.REG_SZ:
                    uc.mem_write(pVals[5],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[6],pack('<I',len(keyValue.dataAsStr)+1))
                elif type == RegValueTypes.REG_EXPAND_SZ:
                    uc.mem_write(pVals[5],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[6],pack('<I',len(keyValue.dataAsStr)+1))
                elif type == RegValueTypes.REG_MULTI_SZ:
                    uc.mem_write(pVals[5],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[6],pack('<I',len(keyValue.dataAsStr)+1))
                elif type == RegValueTypes.REG_LINK:
                    uc.mem_write(pVals[5],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[6],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_NONE:
                    uc.mem_write(pVals[5],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[6],pack('<I',len(keyValue.dataAsStr)+1))         
            except:
                pass
            retVal = 0x0
            retValStr = 'ERROR_SUCCESS'
        else:
            retVal = 0x2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
             # Another Possible ErrorCode 161: 'ERROR_BAD_PATHNAME'

        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        written_values = registry_key_address.getValue(lpSubKey)
        if(lpSubKey == '[NULL]'):
            art.registry_edit_keys.add((keyPath,'(Default)', written_values.dataAsStr))
        else: 
            art.registry_edit_keys.add((keyPath,written_values.name, written_values.dataAsStr))
        

        logged_calls = ("RegGetValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegGetValueW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPDWORD', 'PVOID', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValue', 'dwFlags', 'pdwType', 'pvData', 'pcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        dwFlagsReverseLookUp = {65535: 'RRF_RT_ANY', 24: 'RRF_RT_DWORD', 72: 'RRF_RT_QWORD', 8: 'RRF_RT_REG_BINARY',16: 'RRF_RT_REG_DWORD', 4: 'RRF_RT_REG_EXPAND_SZ', 32: 'RRF_RT_REG_MULTI_SZ',1: 'RRF_RT_REG_NONE', 64: 'RRF_RT_REG_QWORD', 2: 'RRF_RT_REG_SZ',268435456: 'RRF_NOEXPAND',536870912: 'RRF_ZEROONFAILURE', 65536: 'RRF_SUBKEY_WOW6464KEY',131072: 'RRF_SUBKEY_WOW6432KEY'}

        lpSubKey = read_unicode(uc, pVals[1])
        lpValue = read_unicode(uc, pVals[2])

        keyPath = ''
        keyValue = None

        if lpSubKey == '[NULL]':
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        registry_key_address = foundKey
                        if lpValue == '[NULL]':
                            keyValue = foundKey.getValue()
                        else:
                            keyValue = foundKey.getValue(lpValue)
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        registry_key_address = foundKey
                        if lpValue == '[NULL]':

                            keyValue = foundKey.getValue()
                        else:
                            keyValue = foundKey.getValue(lpValue)

        if keyValue is not None:
            # info grab here 
            # print(keyValue.name)
            type = keyValue.type
            try:
                uc.mem_write(pVals[4],pack('<I',keyValue.type.value))
                if type == RegValueTypes.REG_BINARY:
                    uc.mem_write(pVals[5],pack(f'<{len(keyValue.data)}s',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',len(keyValue.data)))
                elif type == RegValueTypes.REG_DWORD:
                    uc.mem_write(pVals[5],pack(f'<I',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',4))
                elif type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    uc.mem_write(pVals[5],pack(f'>I',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',4))
                elif type == RegValueTypes.REG_QWORD:
                    uc.mem_write(pVals[5],pack(f'<Q',keyValue.data))
                    uc.mem_write(pVals[6],pack('<I',8))
                elif type == RegValueTypes.REG_SZ:
                    uc.mem_write(pVals[5],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[6],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_EXPAND_SZ:
                    uc.mem_write(pVals[5],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[6],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_MULTI_SZ:
                    uc.mem_write(pVals[5],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[6],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_LINK:
                    uc.mem_write(pVals[5],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[6],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_NONE:
                    uc.mem_write(pVals[5],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[6],pack('<I',(len(keyValue.dataAsStr)*2)+2))         
            except:
                pass
            retVal = 0x0
            retValStr = 'ERROR_SUCCESS'
        else:
            retVal = 0x2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
             # Another Possible ErrorCode 161: 'ERROR_BAD_PATHNAME'

        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        written_values = registry_key_address.getValue(lpSubKey)
        art.registry_edit_keys.add((keyPath,written_values.name, written_values.dataAsStr))

        logged_calls = ("RegGetValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))
    
    def RegQueryValueA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'LPSTR', 'PLONG']
        pNames = ['hKey', 'lpSubKey', 'lpData', 'lpcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_string(uc, pVals[1])
        pVals[1] = lpSubKey

        keyPath = ''
        keyValue = None

        if lpSubKey == '[NULL]':
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        keyValue = foundKey.getValue()
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        keyValue = foundKey.getValue()
                    else:
                        rKey = RegKey(keyPath)
                        keyValue = rKey.getValue()

        if keyValue is not None:
            # info grab here 
            # registry_keys.add()
            # print(keyValue.name)
            #registry_values.add(())
            art.registry_edit_keys.add((rKey.path,keyValue.name,keyValue.dataAsStr))
            #art.registry_edit_keys.add((keyPath,keyValue.name,keyValue.dataAsStr))
            try:
                uc.mem_write(pVals[2],pack(f'<{len(keyValue.data)}s',keyValue.dataAsStr.encode('ascii')))
                uc.mem_write(pVals[3],pack('<I',len(keyValue.data)))
            except:
                pass
            retVal = 0x0
            retValStr = 'ERROR_SUCCESS'
        else:
            retVal = 0x2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
             # Another Possible ErrorCode 161: 'ERROR_BAD_PATHNAME'


        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegQueryValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegQueryValueW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPWSTR', 'PLONG']
        pNames = ['hKey', 'lpSubKey', 'lpData', 'lpcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_unicode(uc, pVals[1])
        pVals[1] = lpSubKey

        keyPath = ''
        keyValue = None

        if lpSubKey == '[NULL]':
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        keyValue = foundKey.getValue()
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey = RegistryKeys[keyPath]
                        keyValue = foundKey.getValue()
                    else:
                        rKey = RegKey(keyPath)
                        keyValue = rKey.getValue()

        if keyValue is not None:
            # info grab here 
            # registry_keys.add()
            # print(keyValue.name)
            #registry_values.add(())
            art.registry_edit_keys.add((rKey.path,keyValue.name,keyValue.dataAsStr))
            #art.registry_edit_keys.add((keyPath,keyValue.name,keyValue.dataAsStr))

            try:
                uc.mem_write(pVals[2],pack(f'<{len(keyValue.data)*2}s',keyValue.dataAsStr.encode('utf-16')[2:]))
                uc.mem_write(pVals[3],pack('<I',(len(keyValue.data)*2)))
            except:
                pass
            retVal = 0x0
            retValStr = 'ERROR_SUCCESS'
        else:
            retVal = 0x2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
             # Another Possible ErrorCode 161: 'ERROR_BAD_PATHNAME'


        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegQueryValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegQueryValueExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'LPDWORD', 'LPDWORD', 'LPBYTE', 'LPDWORD']
        pNames = ['hKey', 'lpValueName', 'lpReserved', 'lpType', 'lpData', 'lpcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpValue = read_string(uc, pVals[1])

        keyPath = ''
        keyValue = None
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if lpValue == '[NULL]':
                    keyValue = rKey.getValue()
                else:
                    keyValue = rKey.getValue(lpValue)
            else: # key Not Found
                keyPath = hKey.name
                rKey = RegKey(keyPath)
                if lpValue == '[NULL]':
                    keyValue = rKey.getValue()
                else:
                    keyValue = rKey.getValue(lpValue)
        else: # Handle Not Found
            pass

        if keyValue is not None:
            # info grab here 
            # registry_keys.add()
            # print(keyValue.name)
            #registry_values.add(())
            art.registry_edit_keys.add((rKey.path,keyValue.name,keyValue.dataAsStr))
            type = keyValue.type
            try:
                uc.mem_write(pVals[3],pack('<I',keyValue.type.value))
                if type == RegValueTypes.REG_BINARY:
                    uc.mem_write(pVals[4],pack(f'<{len(keyValue.data)}s',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',len(keyValue.data)))
                elif type == RegValueTypes.REG_DWORD:
                    uc.mem_write(pVals[4],pack(f'<I',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',4))
                elif type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    uc.mem_write(pVals[4],pack(f'>I',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',4))
                elif type == RegValueTypes.REG_QWORD:
                    uc.mem_write(pVals[4],pack(f'<Q',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',8))
                elif type == RegValueTypes.REG_SZ:
                    uc.mem_write(pVals[4],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[5],pack('<I',len(keyValue.dataAsStr)+1))
                elif type == RegValueTypes.REG_EXPAND_SZ:
                    uc.mem_write(pVals[4],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[5],pack('<I',len(keyValue.dataAsStr)+1))
                elif type == RegValueTypes.REG_MULTI_SZ:
                    uc.mem_write(pVals[4],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[5],pack('<I',len(keyValue.dataAsStr)+1))
                elif type == RegValueTypes.REG_LINK:
                    uc.mem_write(pVals[4],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[5],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_NONE:
                    uc.mem_write(pVals[4],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                    uc.mem_write(pVals[5],pack('<I',len(keyValue.dataAsStr)+1))         
            except:
                pass
            retVal = 0x0
            retValStr = 'ERROR_SUCCESS'
        else:
            retVal = 0x2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
             # Another Possible ErrorCode 161: 'ERROR_BAD_PATHNAME'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegQueryValueExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegQueryValueExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPDWORD', 'LPDWORD', 'LPBYTE', 'LPDWORD']
        pNames = ['hKey', 'lpValueName', 'lpReserved', 'lpType', 'lpData', 'lpcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpValue = read_unicode(uc, pVals[1])

        keyPath = ''
        keyValue = None
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if lpValue == '[NULL]':
                    keyValue = rKey.getValue()
                else:
                    keyValue = rKey.getValue(lpValue)
            else: # key Not Found
                keyPath = hKey.name
                rKey = RegKey(keyPath)
                if lpValue == '[NULL]':
                    keyValue = rKey.getValue()
                else:
                    keyValue = rKey.getValue(lpValue)
        else: # Handle Not Found
            print("handle not found")
            pass

        if keyValue is not None:
            # info grab here 
            art.registry_edit_keys.add((rKey.path,keyValue.name,keyValue.dataAsStr))

            type = keyValue.type
            try:
                uc.mem_write(pVals[3],pack('<I',keyValue.type.value))
                if type == RegValueTypes.REG_BINARY:
                    uc.mem_write(pVals[4],pack(f'<{len(keyValue.data)}s',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',len(keyValue.data)))
                elif type == RegValueTypes.REG_DWORD:
                    uc.mem_write(pVals[4],pack(f'<I',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',4))
                elif type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    uc.mem_write(pVals[4],pack(f'>I',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',4))
                elif type == RegValueTypes.REG_QWORD:
                    uc.mem_write(pVals[4],pack(f'<Q',keyValue.data))
                    uc.mem_write(pVals[5],pack('<I',8))
                elif type == RegValueTypes.REG_SZ:
                    uc.mem_write(pVals[4],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[5],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_EXPAND_SZ:
                    uc.mem_write(pVals[4],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[5],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_MULTI_SZ:
                    uc.mem_write(pVals[4],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[5],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_LINK:
                    uc.mem_write(pVals[4],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[5],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                elif type == RegValueTypes.REG_NONE:
                    uc.mem_write(pVals[4],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')))
                    uc.mem_write(pVals[5],pack('<I',(len(keyValue.dataAsStr)*2)+2))         
            except:
                pass
            retVal = 0x0
            retValStr = 'ERROR_SUCCESS'
        else:
            retVal = 0x2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
             # Another Possible ErrorCode 161: 'ERROR_BAD_PATHNAME'
        
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegQueryValueExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSetValueA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'LPCSTR', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'dwType', 'lpData', 'cbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        lpSubKey = read_string(uc, pVals[1])
        lpData = read_string(uc, pVals[3])

        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Set Value
                        foundKey = RegistryKeys[keyPath]
                        foundKey.setValue(RegValueTypes(pVals[2]),lpData)
                        createKey = False
                        registry_key_address = foundKey
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey
            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.setValue(RegValueTypes(pVals[2]),lpData)
                    registry_key_address = rKey
            createKey = False
            
        if createKey: # Create New Key
            newKey = RegKey(keyPath)
            newKey.setValue(RegValueTypes(pVals[2]),lpData)
            registry_key_address = newKey

        pVals[2] = RegValueTypes(pVals[2]).name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        written_values = registry_key_address.getValue()
        art.registry_edit_keys.add((keyPath,written_values.name, written_values.dataAsStr))

        logged_calls = ("RegSetValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSetValueW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'LPCWSTR', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'dwType', 'lpData', 'cbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        


        lpSubKey = read_unicode(uc, pVals[1])
        lpData = read_unicode(uc, pVals[3])
        
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Set Value
                        foundKey = RegistryKeys[keyPath]
                        foundKey.setValue(RegValueTypes(pVals[2]),lpData)
                        createKey = False
                        registry_key_address = foundKey
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey 
            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    rKey.setValue(RegValueTypes(pVals[2]),lpData)
                    registry_key_address = rKey
            createKey = False
            
        if createKey: # Create New Key
            newKey = RegKey(keyPath)
            newKey.setValue(RegValueTypes(pVals[2]),lpData)
            registry_key_address = newKey

        pVals[2] = RegValueTypes(pVals[2]).name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        written_values = registry_key_address.getValue()
        art.registry_edit_keys.add((keyPath,written_values.name, written_values.dataAsStr))

        logged_calls = ("RegSetValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSetValueExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
            #'RegSetValueExA': (6, ['HKEY', 'LPCSTR', 'DWORD', 'DWORD', 'BYTE *', 'DWORD'], ['hKey', 'lpValueName', 'Reserved', 'dwType', 'lpData', 'cbData'], 'LSTATUS')
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'DWORD', 'BYTE *', 'DWORD']
        pNames = ['hKey', 'lpValueName', 'Reserved', 'dwType', 'lpData', 'cbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        valType = RegValueTypes(pVals[3])
        valName = read_string(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        if pVals[0] in HandlesDict: # Handle Not Found
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name] # Key Found
                if valType == RegValueTypes.REG_BINARY:
                    bin = uc.mem_read(pVals[4],pVals[5])
                    rKey.setValue(valType,bin,valName)
                    pVals[4] = bin.hex()
                elif valType == RegValueTypes.REG_DWORD:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('<I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('>I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_QWORD: # Needs to Be Tested with 64bit
                    if em.arch == 32:
                        mem = uc.mem_read(pVals[4],8)
                        val = unpack('<Q',mem)[0]
                    else:
                        val = pVals[4]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_SZ:
                    val = read_string(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_EXPAND_SZ:
                    val = read_string(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_LINK:
                    val = read_unicode(uc,pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_MULTI_SZ:
                    mem = uc.mem_read(pVals[4],pVals[5])
                    hexStrings = mem.hex()
                    string = bytes.fromhex(hexStrings).decode('ascii')
                    multiString = string.split('\x00')[:-1]
                    rKey.setValue(valType,multiString,valName)
                    kVal = rKey.getValue(valName)
                    pVals[4] = kVal.dataAsStr
                elif valType == RegValueTypes.REG_NONE:
                    rKey.setValue(valType,pVals[4],valName)
                registry_key_address = rKey
            else: # Key Not Found
                pass
        else: # Handle Not Found
            pass
        
        # RegKey.printInfoAllKeys()

        pVals[3] = RegValueTypes(pVals[3]).name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,3,4])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        written_values = registry_key_address.getValue(valName)
        art.registry_edit_keys.add((registry_key_address.path,written_values.name,written_values.dataAsStr))

        logged_calls = ("RegSetValueExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSetValueExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
            #'RegSetValueExW': (6, ['HKEY', 'LPCWSTR', 'DWORD', 'DWORD', 'BYTE *', 'DWORD'], ['hKey', 'lpValueName', 'Reserved', 'dwType', 'lpData', 'cbData'], 'LSTATUS'
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'DWORD', 'BYTE *', 'DWORD']
        pNames = ['hKey', 'lpValueName', 'Reserved', 'dwType', 'lpData', 'cbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        valType = RegValueTypes(pVals[3])
        valName = read_unicode(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        if pVals[0] in HandlesDict: # Handle Not Found
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name] # Key Found
                if valType == RegValueTypes.REG_BINARY:
                    bin = uc.mem_read(pVals[4],pVals[5])
                    rKey.setValue(valType,bin,valName)
                    pVals[4] = bin.hex()
                elif valType == RegValueTypes.REG_DWORD:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('<I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('>I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_QWORD: # Needs to Be Tested with 64bit
                    if em.arch == 32:
                        mem = uc.mem_read(pVals[4],8)
                        val = unpack('<Q',mem)[0]
                    else:
                        val = pVals[4]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_SZ:
                    val = read_unicode(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_EXPAND_SZ:
                    val = read_unicode(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_LINK:
                    val = read_unicode(uc,pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_MULTI_SZ:
                    mem = uc.mem_read(pVals[4],pVals[5])
                    hexStrings = mem.hex()
                    string = bytes.fromhex(hexStrings).decode('utf-16')
                    multiString = string.split('\x00')[:-1]
                    rKey.setValue(valType,multiString,valName)
                    kVal = rKey.getValue(valName)
                    pVals[4] = kVal.dataAsStr
                elif valType == RegValueTypes.REG_NONE:
                    rKey.setValue(valType,pVals[4],valName)
                registry_key_address = rKey
            else: # Key Not Found
                pass
        else: # Handle Not Found
            pass


        pVals[3] = RegValueTypes(pVals[3]).name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,3,4])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        written_values = registry_key_address.getValue(valName)
        art.registry_edit_keys.add((registry_key_address.path,written_values.name,written_values.dataAsStr))

        logged_calls = ("RegSetValueExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSetKeyValueA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPCVOID', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValueName', 'dwType', 'lpData', 'cbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        valType = RegValueTypes(pVals[3])
        valName = read_string(uc,pVals[2])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[2] = valName
        lpSubKey = read_string(uc,pVals[1])
    
        if lpSubKey == '[NULL]':
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict: # Handle Not Found
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys: # Key Found
                    rKey = RegistryKeys[hKey.name] 
                else: # Key Not Found Create It
                    rKey = RegKey(hKey.name,hKey.value)
                    
                if valType == RegValueTypes.REG_BINARY:
                    bin = uc.mem_read(pVals[4],pVals[5])
                    rKey.setValue(valType,bin,valName)
                    pVals[4] = bin.hex()
                elif valType == RegValueTypes.REG_DWORD:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('<I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('>I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_QWORD: # Needs to Be Tested with 64bit
                    if em.arch == 32:
                        mem = uc.mem_read(pVals[4],8)
                        val = unpack('<Q',mem)[0]
                    else:
                        val = pVals[4]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_SZ:
                    val = read_string(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_EXPAND_SZ:
                    val = read_string(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_LINK:
                    val = read_unicode(uc,pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_MULTI_SZ:
                    mem = uc.mem_read(pVals[4],pVals[5])
                    hexStrings = mem.hex()
                    string = bytes.fromhex(hexStrings).decode('ascii')
                    multiString = string.split('\x00')[:-1]
                    rKey.setValue(valType,multiString,valName)
                    kVal = rKey.getValue(valName)
                    pVals[4] = kVal.dataAsStr
                elif valType == RegValueTypes.REG_NONE:
                    rKey.setValue(valType,pVals[4],valName)
                else:
                    rKey.setValue(valType,RegValueTypes.REG_NONE,valName)

                registry_key_address = rKey
            else: # Handle Not Found
                pass
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict: # Handle Not Found
                hKey = HandlesDict[pVals[0]]
                keyPath = hKey.name + lpSubKey
                if keyPath in RegistryKeys:
                    rKey = RegistryKeys[hKey.name] # Key Found
                else: # Create Key
                    rKey = RegKey(keyPath)

                if valType == RegValueTypes.REG_BINARY:
                    bin = uc.mem_read(pVals[4],pVals[5])
                    rKey.setValue(valType,bin,valName)
                    pVals[4] = bin.hex()
                elif valType == RegValueTypes.REG_DWORD:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('<I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('>I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_QWORD: # Needs to Be Tested with 64bit
                    if em.arch == 32:
                        mem = uc.mem_read(pVals[4],8)
                        val = unpack('<Q',mem)[0]
                    else:
                        val = pVals[4]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_SZ:
                    val = read_string(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_EXPAND_SZ:
                    val = read_string(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_LINK:
                    val = read_unicode(uc,pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_MULTI_SZ:
                    mem = uc.mem_read(pVals[4],pVals[5])
                    hexStrings = mem.hex()
                    string = bytes.fromhex(hexStrings).decode('ascii')
                    multiString = string.split('\x00')[:-1]
                    rKey.setValue(valType,multiString,valName)
                    kVal = rKey.getValue(valName)
                    pVals[4] = kVal.dataAsStr
                elif valType == RegValueTypes.REG_NONE:
                    rKey.setValue(valType,pVals[4],valName)
                registry_key_address = rKey
            else: # Handle Not Found
                pass
        
        pVals[3] = RegValueTypes(pVals[3]).name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3,4])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        written_values = registry_key_address.getValue()
        art.registry_edit_keys.add((registry_key_address.path,written_values.name,written_values.dataAsStr))

        logged_calls = ("RegSetKeyValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSetKeyValueW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPCVOID', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValueName', 'dwType', 'lpData', 'cbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        valType = RegValueTypes(pVals[3])
        valName = read_unicode(uc,pVals[2])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[2] = valName
        lpSubKey = read_unicode(uc,pVals[1])
    
        if lpSubKey == '[NULL]':
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict: # Handle Not Found
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys: # Key Found
                    rKey = RegistryKeys[hKey.name] 
                else: # Key Not Found Create It
                    rKey = RegKey(hKey.name,hKey.value)

                if valType == RegValueTypes.REG_BINARY:
                    bin = uc.mem_read(pVals[4],pVals[5])
                    rKey.setValue(valType,bin,valName)
                    pVals[4] = bin.hex()
                elif valType == RegValueTypes.REG_DWORD:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('<I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('>I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_QWORD: # Needs to Be Tested with 64bit
                    if em.arch == 32:
                        mem = uc.mem_read(pVals[4],8)
                        val = unpack('<Q',mem)[0]
                    else:
                        val = pVals[4]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_SZ:
                    val = read_unicode(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_EXPAND_SZ:
                    val = read_unicode(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_LINK:
                    val = read_unicode(uc,pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_MULTI_SZ:
                    mem = uc.mem_read(pVals[4],pVals[5])
                    hexStrings = mem.hex()
                    string = bytes.fromhex(hexStrings).decode('utf-16')
                    multiString = string.split('\x00')[:-1]
                    rKey.setValue(valType,multiString,valName)
                    kVal = rKey.getValue(valName)
                    pVals[4] = kVal.dataAsStr
                elif valType == RegValueTypes.REG_NONE:
                    rKey.setValue(valType,pVals[4],valName)
                else:
                    rKey.setValue(RegValueTypes.REG_NONE,pVals[4],valName)
                
                registry_key_address = rKey
            else: # Handle Not Found
                pass
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict: # Handle Not Found
                hKey = HandlesDict[pVals[0]]
                keyPath = hKey.name + lpSubKey
                if keyPath in RegistryKeys:
                    rKey = RegistryKeys[hKey.name] # Key Found
                else: # Create Key
                    rKey = RegKey(keyPath)

                if valType == RegValueTypes.REG_BINARY:
                    bin = uc.mem_read(pVals[4],pVals[5])
                    rKey.setValue(valType,bin,valName)
                    pVals[4] = bin.hex()
                elif valType == RegValueTypes.REG_DWORD:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('<I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                    if em.arch == 64:
                        mem = uc.mem_read(esp+(8*1),4)
                    else:
                        mem = uc.mem_read(esp+(4*5),4)
                    val = unpack('>I',mem)[0]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_QWORD: # Needs to Be Tested with 64bit
                    if em.arch == 32:
                        mem = uc.mem_read(pVals[4],8)
                        val = unpack('<Q',mem)[0]
                    else:
                        val = pVals[4]
                    rKey.setValue(valType,val,valName)
                    pVals[4] = hex(val)
                elif valType == RegValueTypes.REG_SZ:
                    val = read_unicode(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_EXPAND_SZ:
                    val = read_unicode(uc, pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_LINK:
                    val = read_unicode(uc,pVals[4])
                    rKey.setValue(valType,val,valName)
                    pVals[4] = val
                elif valType == RegValueTypes.REG_MULTI_SZ:
                    mem = uc.mem_read(pVals[4],pVals[5])
                    hexStrings = mem.hex()
                    string = bytes.fromhex(hexStrings).decode('utf-16')
                    multiString = string.split('\x00')[:-1]
                    rKey.setValue(valType,multiString,valName)
                    kVal = rKey.getValue(valName)
                    pVals[4] = kVal.dataAsStr
                elif valType == RegValueTypes.REG_NONE:
                    rKey.setValue(valType,pVals[4],valName)
                registry_key_address = rKey
            else: # Handle Not Found
                pass
        
        pVals[3] = RegValueTypes(pVals[3]).name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3,4])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        written_values = registry_key_address.getValue()
        art.registry_edit_keys.add((registry_key_address.path,written_values.name,written_values.dataAsStr))

        logged_calls = ("RegSetKeyValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteValueA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpValueName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        valName = read_string(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        keyPath = ''
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
                deletedValue = rKey.deleteValue(valName)
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            pass
            
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        #print(deletedValue)
        art.registry_delete_keys.add((keyPath,valName))

        logged_calls = ("RegDeleteValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteValueW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpValueName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        valName = read_unicode(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        keyPath = ''
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
                deletedValue = rKey.deleteValue(valName)
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        #print(deletedValue)
        art.registry_delete_keys.add((keyPath,valName))

        logged_calls = ("RegDeleteValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def RegDeleteKeyValueA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey', 'lpValueName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        

        valName = read_string(uc,pVals[2])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[2] = valName
        lpSubKey = read_string(uc, pVals[1])

        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        deletedValue = foundKey.deleteValue(valName)
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    deletedValue = rKey.deleteValue(valName)
                else:
                    keyPath = hKey.name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_delete_keys.add((keyPath,valName))

        logged_calls = ("RegDeleteKeyValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteKeyValueW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey', 'lpValueName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        


        valName = read_unicode(uc,pVals[2])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[2] = valName
        lpSubKey = read_unicode(uc, pVals[1])

        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        deletedValue = foundKey.deleteValue(valName)
                    else: # KeyPath Not Found
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    deletedValue = rKey.deleteValue(valName)
                else:
                    keyPath = hKey.name

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        #print(deletedValue)
        art.registry_delete_keys.add((keyPath,valName))
        

        logged_calls = ("RegDeleteKeyValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def RegOpenCurrentUser(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['REGSAM', 'PHKEY']
        pNames = ['access', 'retkey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[0] = getLookUpVal(pVals[0], RegKey.securityAccessRights)

        try:
            uc.mem_write(pVals[1], pack('<I',0x80000001))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add('HKEY_CURRENT_USER')

        logged_calls = ("RegOpenCurrentUser", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenUserClassesRoot(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'DWORD', 'REGSAM', 'PHKEY']
        pNames = ['hToken', 'dwOptions', 'samDesired', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
       
        pVals[0] = getLookUpVal(pVals[2], RegKey.securityAccessRights)

        try:
            uc.mem_write(pVals[3], pack('<I',0x80000000))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add('HKEY_CLASSES_ROOT')


        logged_calls = ("RegOpenUserClassesRoot", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
            #'RegOpenKeyExA': (5, ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY'], ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult'], 'LSTATUS')
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        ulOptionReverseLookUp = {0x00000008: 'REG_OPTION_OPEN_LINK'}
        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}
        
        pVals[2] = getLookUpVal(pVals[2], ulOptionReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], samDesiredReverseLookUp)     

        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[4], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)
        #written_values = registry_key_address.getValue()
        #registry_values.add((written_values.name,written_values.data))

        logged_calls = ("RegOpenKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenKeyExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
            #RegOpenKeyExW': (5, ['HKEY', 'LPCWSTR', 'DWORD', 'REGSAM', 'PHKEY'], ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult'], 'LSTATUS')
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'REGSAM', 'PHKEY']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        ulOptionReverseLookUp = {0x00000008: 'REG_OPTION_OPEN_LINK'}
        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], ulOptionReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], samDesiredReverseLookUp)

        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                        createKey = False
                    else:
                        createKey = True
                else:
                    createKey = True
                    keyPath = hKey.name + lpSubKey
            else:
                createKey = True
                keyPath += lpSubKey
        else: # [NULL] lpSubKey Return hKey
            pVals[1] = lpSubKey
            createKey = False
            hKey = pVals[0]
            
        if createKey: # Create New
            newKey = RegKey(keyPath)
            hKey = newKey.handle.value

        try:
            uc.mem_write(pVals[4], pack('<I',hKey))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)
        #written_values = registry_key_address.getValue()
        #registry_values.add((written_values.name,written_values.data))

        logged_calls = ("RegOpenKeyExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegFlushKey(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'RegFlushKey': (1, ['HKEY'], ['hKey'], 'LSTATUS')
        pTypes = ['HKEY']
        pNames = ['hKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        keyPath =''
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else: # RegKey Not Found Use handle Name Instead Might Not Be KeyPath
              keyPath = hKey.name 
        else:
            #print("figure out what to do in the case of key not in dict")
            keyPath = 'Error in retreving key'
             

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegFlushKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegLoadKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'RegLoadKeyA': (3, ['HKEY', 'LPCSTR', 'LPCSTR'], ['hKey', 'lpSubKey', 'lpFile'], 'LSTATUS')
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey', 'lpFile']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                    else:
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                else:
                    keyPath = hKey.name
            else:
                keyPath = ''
             

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[2])

        logged_calls = ("RegLoadKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegLoadKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey', 'lpFile']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                    else:
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                else:
                    keyPath = hKey.name
            else:
                keyPath = ''
             

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[2])

        logged_calls = ("RegLoadKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegUnLoadKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                    else:
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey 
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                else:
                    keyPath = hKey.name
            else:
                keyPath = ''
             

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegUnLoadKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegUnLoadKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey = RegistryKeys[keyPath]
                        hKey = foundKey.handle.value
                    else:
                        pass
                else:
                    keyPath = hKey.name + lpSubKey
            else:
                keyPath += lpSubKey
        else: # [NULL] lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                else:
                    keyPath = hKey.name
            else:
                keyPath = ''
             

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegUnLoadKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def RegCloseKey(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'RegCloseKey': (1, ['HKEY'], ['hKey'], 'LSTATUS')
        pTypes = ['HKEY']
        pNames = ['hKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        keyPath =''
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else:
                keyPath = hKey.name
        else:
            #print("figure out what to do in the case of key not in dict")
            keyPath = 'Error in retreving key - closeKey'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegCloseKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegRenameKey(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKeyName', 'lpNewKeyName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        keysToRename = set()
        keyPath = ''

        lpSubKey = read_unicode(uc, pVals[1])
        newKeyName = read_unicode(uc, pVals[2])

        if newKeyName != '[NULL]':
            if '\\' in newKeyName: # Clean new Name
                newKeyName = newKeyName.replace('\\','')

            if lpSubKey != '[NULL]':
                if lpSubKey[0] != '\\':
                    lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

                oldKeyName = lpSubKey.split('\\')[-1] # Get Key Name

                if pVals[0] in HandlesDict:
                    hKey = HandlesDict[pVals[0]]
                    if hKey.name in RegistryKeys:
                        rKey = RegistryKeys[hKey.name]
                        keyPath = rKey.path + lpSubKey
                        if keyPath in RegistryKeys:
                            fKey = RegistryKeys[keyPath]
                            keysToRename.add(fKey)
                            for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToRename.add(val)
                        else:
                            for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToRename.add(val)
                    else: # Key Not Found
                        keyPath = hKey.name + lpSubKey
                        for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToRename.add(val)
                else: # Handle Not Found
                    pass
            else:
                pVals[1] = lpSubKey
                if pVals[0] in HandlesDict:
                    hKey = HandlesDict[pVals[0]]
                    if hKey.name in RegistryKeys:
                        rKey = RegistryKeys[hKey.name]
                        keyPath = rKey.path
                        oldKeyName = rKey.name
                        for key, val in RegistryKeys.items():
                            if keyPath in key:
                                keysToRename.add(val)
                    else: # Key Not Found
                        oldKeyName = hKey.name.split('\\')[-1] # Get Key Name
                        keyPath = hKey.name
                        for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToRename.add(val)
                else: # Handle Not Found
                    pass
        else: # No New Name Given
            pass

        if len(keysToRename) > 0:
            newKeyPath = '\\'.join(keyPath.split('\\')[:-1]) + '\\' + newKeyName
            for key in keysToRename:
                if isinstance(key,RegKey):
                    if key.path == keyPath: # Update Exact Key
                        key.name = newKeyName
                        key.path = key.path.replace(keyPath,newKeyPath)
                        key.handle.name = key.path
                        if isinstance(key.parentKey,RegKey): # Update Parent Key
                            if oldKeyName in key.parentKey.childKeys:
                                key.parentKey.childKeys.pop(oldKeyName)
                                key.parentKey.childKeys.update({key.name: key})
                    else: 
                        key.path = key.path.replace(keyPath,newKeyPath)
                        key.handle.name = key.path
        
        pVals[2] = newKeyName
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegRenameKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCopyTreeA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'HKEY']
        pNames = ['hKeySrc', 'lpSubKey', 'hKeyDest']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        keysToCopy = set()
        keyPath = ''

        lpSubKey = read_string(uc, pVals[1])
        pVals[1] = lpSubKey

        if pVals[2] in HandlesDict:
            hKeyDest = HandlesDict[pVals[2]]
            if hKeyDest.name in RegistryKeys:
                rKeyDest = RegistryKeys[hKeyDest.name]
                newKeyPath = rKeyDest.path
            else:
                newKeyPath = hKeyDest.name

            if lpSubKey != '[NULL]':
                if lpSubKey[0] != '\\':
                    lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

                if pVals[0] in HandlesDict:
                    hKeySrc = HandlesDict[pVals[0]]
                    if hKeySrc.name in RegistryKeys:
                        rKeySrc = RegistryKeys[hKeySrc.name]
                        keyPath = rKeySrc.path + lpSubKey
                        if keyPath in RegistryKeys:
                            fKey = RegistryKeys[keyPath]
                            keysToCopy.add(fKey)
                            for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                        else:
                            for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                    else: # Key Not Found
                        keyPath = hKeySrc.name + lpSubKey
                        for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                else: # Handle Not Found
                    pass
            else:
                pVals[1] = lpSubKey
                if pVals[0] in HandlesDict:
                    hKey = HandlesDict[pVals[0]]
                    if hKey.name in RegistryKeys:
                        rKey = RegistryKeys[hKey.name]
                        keyPath = rKey.path
                        for key, val in RegistryKeys.items():
                            if keyPath in key:
                                keysToCopy.add(val)
                    else: # Key Not Found
                        keyPath = hKey.name
                        for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                else: # Handle Not Found
                    pass
        else: # No Dest Handle Given
            pass

        # Recursive function to update child keys
        def updateChildKeys(key: RegKey, oldPath: str, newPath: str): 
            if len(oldPath) != 0:
                key.path = key.path.replace(oldPath,newPath)
            else:
                key.path = newPath + '\\' + key.path
            art.registry_add_keys.add(key.path)
            key.handle = Handle(HandleType.HKEY,name=key.path, handleValue=RegKey.nextHandleValue)
            RegKey.nextHandleValue += 8
            RegistryKeys.update({key.path: key})
            
            for val in key.childKeys.values():
                val.parentKey = key
                updateChildKeys(val, oldPath, newPath)

        if len(keysToCopy) > 0:
            oldKeyPath = '\\'.join(keyPath.split('\\')[:-1])
            for key in keysToCopy:
                if isinstance(key,RegKey):
                    if key.path == keyPath: # Update Exact Key
                        keyCopy = deepcopy(key)
                        if len(oldKeyPath) != 0:
                            keyCopy.path = keyCopy.path.replace(oldKeyPath,newKeyPath)
                        else:
                            keyCopy.path = newKeyPath + '\\' + keyCopy.path
                        keyCopy.handle = Handle(HandleType.HKEY,name=keyCopy.path, handleValue=RegKey.nextHandleValue)
                        RegKey.nextHandleValue += 8
                        keyCopy.parentKey = rKeyDest
                        rKeyDest.childKeys.update({keyCopy.name: keyCopy})
                        RegistryKeys.update({keyCopy.path: keyCopy})
                        #print(2)
                        #print(keyCopy.path)
                        #print(newKeyPath)
                        for cVal in keyCopy.childKeys.values():
                            cVal.parentKey = keyCopy
                            updateChildKeys(cVal,oldKeyPath,newKeyPath)


        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegCopyTreeA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCopyTreeW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'HKEY']
        pNames = ['hKeySrc', 'lpSubKey', 'hKeyDest']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        keysToCopy = set()
        keyPath = ''

        lpSubKey = read_unicode(uc, pVals[1])
        pVals[1] = lpSubKey

        if pVals[2] in HandlesDict:
            hKeyDest = HandlesDict[pVals[2]]
            if hKeyDest.name in RegistryKeys:
                rKeyDest = RegistryKeys[hKeyDest.name]
                newKeyPath = rKeyDest.path
            else:
                newKeyPath = hKeyDest.name
            
            if lpSubKey != '[NULL]':
                if lpSubKey[0] != '\\':
                    lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

                if pVals[0] in HandlesDict:
                    hKeySrc = HandlesDict[pVals[0]]
                    if hKeySrc.name in RegistryKeys:
                        rKeySrc = RegistryKeys[hKeySrc.name]
                        keyPath = rKeySrc.path + lpSubKey
                        if keyPath in RegistryKeys:
                            fKey = RegistryKeys[keyPath]
                            keysToCopy.add(fKey)
                            for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                        else:
                            for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                    else: # Key Not Found
                        keyPath = hKeySrc.name + lpSubKey
                        for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                else: # Handle Not Found
                    pass
            else:
                pVals[1] = lpSubKey
                if pVals[0] in HandlesDict:
                    hKey = HandlesDict[pVals[0]]
                    if hKey.name in RegistryKeys:
                        rKey = RegistryKeys[hKey.name]
                        keyPath = rKey.path
                        for key, val in RegistryKeys.items():
                            if keyPath in key:
                                keysToCopy.add(val)
                    else: # Key Not Found
                        keyPath = hKey.name
                        for key, val in RegistryKeys.items():
                                if keyPath in key:
                                    keysToCopy.add(val)
                else: # Handle Not Found
                    pass
        else: # No Dest Handle Given
            pass

        # Recursive function to update child keys
        def updateChildKeys(key: RegKey, oldPath: str, newPath: str):
            if len(oldPath) != 0:
                key.path = key.path.replace(oldPath,newPath)
            else:
                key.path = newPath + '\\' + key.path
            art.registry_add_keys.add(key.path)
            key.handle = Handle(HandleType.HKEY,name=key.path, handleValue=RegKey.nextHandleValue)
            RegKey.nextHandleValue += 8
            RegistryKeys.update({key.path: key})
            for val in key.childKeys.values():
                val.parentKey = key
                updateChildKeys(val, oldPath, newPath)

        if len(keysToCopy) > 0:
            oldKeyPath = '\\'.join(keyPath.split('\\')[:-1])
            for key in keysToCopy:
                if isinstance(key,RegKey):
                    if key.path == keyPath: # Update Exact Key
                        keyCopy = deepcopy(key)
                        if len(oldKeyPath) != 0:
                            keyCopy.path = keyCopy.path.replace(oldKeyPath,newKeyPath)
                        else:
                            keyCopy.path = newKeyPath + '\\' + keyCopy.path
                        keyCopy.handle = Handle(HandleType.HKEY,name=keyCopy.path, handleValue=RegKey.nextHandleValue)
                        RegKey.nextHandleValue += 8
                        keyCopy.parentKey = rKeyDest
                        rKeyDest.childKeys.update({keyCopy.name: keyCopy})
                        RegistryKeys.update({keyCopy.path: keyCopy})
                        for cVal in keyCopy.childKeys.values():
                            cVal.parentKey = keyCopy
                            updateChildKeys(cVal,oldKeyPath,newKeyPath)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegCopyTreeW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))



    def RegOverridePredefKey(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'HKEY']
        pNames = ['hKey', 'hNewHKEY']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        handleKey = getLookUpVal(pVals[0],HandlesDict)
        if isinstance(handleKey, Handle):
            p0 = f'{hex(pVals[0])} - {handleKey.name}'
        else:
            p0 = hex(pVals[0])

        handleKey = getLookUpVal(pVals[1],HandlesDict)
        if isinstance(handleKey, Handle):
            p1 = f'{hex(pVals[1])} - {handleKey.name}'
        else:
            p1 = hex(pVals[1])

        keyPath =''
        if pVals[0] in RegKey.PreDefinedKeys:
            preKeyPath = RegKey.PreDefinedKeys[pVals[0]]
            if pVals[1] != 0x0:
                if pVals[1] in HandlesDict:
                    hKey = HandlesDict[pVals[1]]
                    if hKey.name in RegistryKeys:
                        rKey = RegistryKeys[hKey.name]
                        newKeyPath = rKey.path
                        if pVals[0] in HandlesDict:
                            hKey = HandlesDict[pVals[0]]
                            hKey.name = newKeyPath
                    else:
                        newKeyPath = hKey.name
                        if pVals[0] in HandlesDict:
                            hKey = HandlesDict[pVals[0]]
                            hKey.name = newKeyPath
                else:
                    newKeyPath = 'Error in retreving key - OverridePredefKey'
            else: # Swap Back if newKey Null
                if pVals[0] in HandlesDict:
                    hKey = HandlesDict[pVals[0]]
                    hKey.name = preKeyPath
        else: 
            # Predefined Key Not Provided
            preKeyPath = ''
            newKeyPath = ''

        pVals[0] = p0
        pVals[1] = p1

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0,1])

        
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(preKeyPath)


        logged_calls = ("RegOverridePredefKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegEnumKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'RegEnumKeyA': (4, ['HKEY', 'DWORD', 'LPSTR', 'DWORD'], ['hKey', 'dwIndex', 'lpName', 'cchName'], 'LSTATUS')
        pTypes = ['HKEY', 'DWORD', 'LPSTR', 'DWORD']
        pNames = ['hKey', 'dwIndex', 'lpName', 'cchName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            keyPath = hKey.name
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.childKeys):
                    ChildKeysList = list(rKey.childKeys)
                    childKey = rKey.childKeys[ChildKeysList[pVals[1]]]
                    try:
                        uc.mem_write(pVals[2],pack(f'<{len(childKey.name)+1}s',childKey.name.encode('ascii')))
                    except:
                        pass
                    retVal = 0
                    retValStr = 'ERROR_SUCCESS'
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
        else: # Handle Not Found
            retVal = 2 
            retValStr = 'ERROR_FILE_NOT_FOUND'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
    
        uc.reg_write(UC_X86_REG_EAX, retVal)
        art.registry_add_keys.add(keyPath)
        logged_calls = ("RegEnumKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegEnumKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'DWORD', 'LPWSTR', 'DWORD']
        pNames = ['hKey', 'dwIndex', 'lpName', 'cchName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            keyPath = hKey.name
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.childKeys):
                    ChildKeysList = list(rKey.childKeys)
                    childKey = rKey.childKeys[ChildKeysList[pVals[1]]]
                    try:
                        uc.mem_write(pVals[2],pack(f'<{(len(childKey.name)*2)+1}s',childKey.name.encode('utf-16')[2:]))
                    except:
                        pass
                    retVal = 0
                    retValStr = 'ERROR_SUCCESS'
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
        else: # Handle Not Found
            retVal = 2 
            retValStr = 'ERROR_FILE_NOT_FOUND'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        uc.reg_write(UC_X86_REG_EAX, retVal)
        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegEnumKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegEnumKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'DWORD', 'LPSTR', 'LPDWORD', 'LPDWORD', 'LPSTR', 'LPDWORD', 'PFILETIME']
        pNames = ['hKey', 'dwIndex', 'lpName', 'lpcchName', 'lpReserved', 'lpClass', 'lpcchClass', 'lpftLastWriteTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        fileTime = get_FILETIME(uc, pVals[7], em)
        fileTime.genTime()

        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            keyPath = hKey.name
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.childKeys):
                    ChildKeysList = list(rKey.childKeys)
                    childKey = rKey.childKeys[ChildKeysList[pVals[1]]]
                    art.registry_add_keys.add(childKey.path)
                    try:
                        uc.mem_write(pVals[2],pack(f'<{len(childKey.name)+1}s',childKey.name.encode('ascii')))
                        fileTime.writeToMemory(uc, pVals[7])
                    except:
                        pass
                    retVal = 0
                    retValStr = 'ERROR_SUCCESS'
                    pVals[7] = makeStructVals(uc, fileTime, pVals[7])
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
                    pVals[7] = hex(pVals[7])
        else: # Handle Not Found
            retVal = 2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
            pVals[7] = hex(pVals[7])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[7])
    
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegEnumKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegEnumKeyExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'DWORD', 'LPWSTR', 'LPDWORD', 'LPDWORD', 'LPWSTR', 'LPDWORD', 'PFILETIME']
        pNames = ['hKey', 'dwIndex', 'lpName', 'lpcchName', 'lpReserved', 'lpClass', 'lpcchClass', 'lpftLastWriteTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        fileTime = get_FILETIME(uc, pVals[7], em)
        fileTime.genTime()

        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.childKeys):
                    ChildKeysList = list(rKey.childKeys)
                    childKey = rKey.childKeys[ChildKeysList[pVals[1]]]
                    art.registry_add_keys.add(childKey.path)
                    try:
                        uc.mem_write(pVals[2],pack(f'<{(len(childKey.name)*2)+2}s',childKey.name.encode('utf-16')[2:]))
                        fileTime.writeToMemory(uc, pVals[7])
                    except:
                        pass
                    retVal = 0
                    retValStr = 'ERROR_SUCCESS'
                    pVals[7] = makeStructVals(uc, fileTime, pVals[7])
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
                    pVals[7] = hex(pVals[7])
        else: # Handle Not Found
            retVal = 2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
            pVals[7] = hex(pVals[7])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[7])
    
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls = ("RegEnumKeyExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegEnumValueA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'DWORD', 'LPSTR', 'LPDWORD', 'LPDWORD', 'LPDWORD', 'LPBYTE', 'LPDWORD']
        pNames = ['hKey', 'dwIndex', 'lpValueName', 'lpcchValueName', 'lpReserved', 'lpType', 'lpData', 'lpcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.values):
                    valuesList = list(rKey.values)
                    keyValue = rKey.values[valuesList[pVals[1]]]
                    try:
                        uc.mem_write(pVals[2],pack(f'<{len(keyValue.name)+1}s',keyValue.name.encode('ascii')))
                        uc.mem_write(pVals[5],pack('<I',keyValue.type.value))
                        type = keyValue.type
                        if type == RegValueTypes.REG_BINARY:
                            uc.mem_write(pVals[6],pack(f'<{len(keyValue.data)}s',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',len(keyValue.data)))
                        elif type == RegValueTypes.REG_DWORD:
                            uc.mem_write(pVals[6],pack(f'<I',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',4))
                        elif type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                            uc.mem_write(pVals[6],pack(f'>I',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',4))
                        elif type == RegValueTypes.REG_QWORD:
                            uc.mem_write(pVals[6],pack(f'<Q',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',8))
                        elif type == RegValueTypes.REG_SZ:
                            uc.mem_write(pVals[6],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                            uc.mem_write(pVals[7],pack('<I',len(keyValue.dataAsStr)+1))
                        elif type == RegValueTypes.REG_EXPAND_SZ:
                            uc.mem_write(pVals[6],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                            uc.mem_write(pVals[7],pack('<I',len(keyValue.dataAsStr)+1))
                        elif type == RegValueTypes.REG_MULTI_SZ:
                            uc.mem_write(pVals[6],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                            uc.mem_write(pVals[7],pack('<I',len(keyValue.dataAsStr)+1))
                        elif type == RegValueTypes.REG_LINK:
                            uc.mem_write(pVals[6],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')[2:]))
                            uc.mem_write(pVals[7],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                        elif type == RegValueTypes.REG_NONE:
                            uc.mem_write(pVals[6],pack(f'<{len(keyValue.dataAsStr)+1}s',keyValue.dataAsStr.encode('ascii')))
                            uc.mem_write(pVals[7],pack('<I',len(keyValue.dataAsStr)+1))         
                    except:
                        pass
                    retVal = 0
                    retValStr = 'ERROR_SUCCESS'
                    pVals[6] = keyValue.dataAsStr
                    pVals[5] = type.name
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
                    pVals[6] = hex(pVals[6])
                    pVals[5] = hex(pVals[5])
        else: # Handle Not Found
            retVal = 2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
            pVals[6] = hex(pVals[6])
            pVals[5] = hex(pVals[5])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5,6])
    
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegEnumValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegEnumValueW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'DWORD', 'LPWSTR', 'LPDWORD', 'LPDWORD', 'LPDWORD', 'LPBYTE', 'LPDWORD']
        pNames = ['hKey', 'dwIndex', 'lpValueName', 'lpcchValueName', 'lpReserved', 'lpType', 'lpData', 'lpcbData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.values):
                    valuesList = list(rKey.values)
                    keyValue = rKey.values[valuesList[pVals[1]]]
                    try:
                        uc.mem_write(pVals[2],pack(f'<{(len(keyValue.name)*2)+2}s',keyValue.name.encode('utf-16')[2:]))
                        uc.mem_write(pVals[5],pack('<I',keyValue.type.value))
                        type = keyValue.type
                        if type == RegValueTypes.REG_BINARY:
                            uc.mem_write(pVals[6],pack(f'<{len(keyValue.data)}s',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',len(keyValue.data)))
                        elif type == RegValueTypes.REG_DWORD:
                            uc.mem_write(pVals[6],pack(f'<I',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',4))
                        elif type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                            uc.mem_write(pVals[6],pack(f'>I',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',4))
                        elif type == RegValueTypes.REG_QWORD:
                            uc.mem_write(pVals[6],pack(f'<Q',keyValue.data))
                            uc.mem_write(pVals[7],pack('<I',8))
                        elif type == RegValueTypes.REG_SZ:
                            uc.mem_write(pVals[6],pack(f'<{(len(keyValue.name)*2)+2}s',keyValue.dataAsStr.encode('utf-16')[2:]))
                            uc.mem_write(pVals[7],pack('<I',(len(keyValue.name)*2)+2))
                        elif type == RegValueTypes.REG_EXPAND_SZ:
                            uc.mem_write(pVals[6],pack(f'<{(len(keyValue.name)*2)+2}s',keyValue.dataAsStr.encode('utf-16')[2:]))
                            uc.mem_write(pVals[7],pack('<I',(len(keyValue.name)*2)+2))
                        elif type == RegValueTypes.REG_MULTI_SZ:
                            uc.mem_write(pVals[6],pack(f'<{(len(keyValue.name)*2)+2}s',keyValue.dataAsStr.encode('utf-16')[2:]))
                            uc.mem_write(pVals[7],pack('<I',len(keyValue.dataAsStr)+1))
                        elif type == RegValueTypes.REG_LINK:
                            uc.mem_write(pVals[6],pack(f'<{(len(keyValue.dataAsStr)*2)+2}s',keyValue.dataAsStr.encode('utf-16')[2:]))
                            uc.mem_write(pVals[7],pack('<I',(len(keyValue.dataAsStr)*2)+2))
                        elif type == RegValueTypes.REG_NONE:
                            uc.mem_write(pVals[6],pack(f'<{(len(keyValue.name)*2)+2}s',keyValue.dataAsStr.encode('utf-16')[2:]))
                            uc.mem_write(pVals[7],pack('<I',(len(keyValue.name)*2)+2))         
                    except:
                        pass
                    retVal = 0
                    retValStr = 'ERROR_SUCCESS'
                    pVals[6] = keyValue.dataAsStr
                    pVals[5] = type.name
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
                    pVals[6] = hex(pVals[6])
                    pVals[5] = hex(pVals[5])
        else: # Handle Not Found
            retVal = 2 
            retValStr = 'ERROR_FILE_NOT_FOUND'
            pVals[6] = hex(pVals[6])
            pVals[5] = hex(pVals[5])


        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5,6])
    
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegEnumValueW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def RegConnectRegistryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'RegConnectRegistryA': (3, ['LPCSTR', 'HKEY', 'PHKEY'], ['lpMachineName', 'hKey', 'phkResult'], 'LSTATUS')
        pTypes = ['LPCSTR', 'HKEY', 'PHKEY']
        pNames = ['lpMachineName', 'hKey', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        

        #build out
        # it seems to return the result of the hKey but on the other computer.
        #is ther a way to somehow define registry keys if they are being used remotely like this?
        #like how 80000000 is the root for the current computer, can we do something like 90000000 for a remote computer?
        # something to show that the shellcode attempted to connect to a remote registry and do something with it. 

        machineName = read_string(uc, pVals[0])

        phk = 0x0
        keyPath = ''
        if machineName != '[NULL]':
            if machineName[0:2] != '\\\\':
                machineName = '\\\\' + machineName
            pVals[0] = machineName
            preKey = getLookUpVal(pVals[1],RegKey.PreDefinedKeys)
            keyPath = machineName + '\\' + preKey
            key = RegKey(keyPath,remote=True)
            phk = key.handle.value
        else: # Local Computer Name Used
            pVals[0] = machineName
            if pVals[1] in HandlesDict:
                hKey = HandlesDict[pVals[1]]
                keyPath = hKey.name
                if hKey.name in RegistryKeys:
                    key = RegistryKeys[hKey.name]
                    phk = key.handle.value
                else:
                    phk = hKey.value

            #print("figure out what to do in the case of key not in dict")
            # keyPath = 'Error in retreving key - ConnectRegistryA'
        try:
            uc.mem_write(pVals[2],pack('<I',phk))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[0])
        logged_calls = ("RegConnectRegistryA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegConnectRegistryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'HKEY', 'PHKEY']
        pNames = ['lpMachineName', 'hKey', 'phkResult']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        

        #build out
        # it seems to return the result of the hKey but on the other computer.
        #is ther a way to somehow define registry keys if they are being used remotely like this?
        #like how 80000000 is the root for the current computer, can we do something like 90000000 for a remote computer?
        # something to show that the shellcode attempted to connect to a remote registry and do something with it. 

        machineName = read_unicode(uc, pVals[0])

        phk = 0x0
        keyPath = ''
        if machineName != '[NULL]':
            if machineName[0:2] != '\\\\':
                machineName = '\\\\' + machineName
            pVals[0] = machineName
            preKey = getLookUpVal(pVals[1],RegKey.PreDefinedKeys)
            keyPath = machineName + '\\' + preKey
            key = RegKey(keyPath,remote=True)
            phk = key.handle.value
        else: # Local Computer Name Used
            pVals[0] = machineName
            if pVals[1] in HandlesDict:
                hKey = HandlesDict[pVals[1]]
                keyPath = hKey.name
                if hKey.name in RegistryKeys:
                    key = RegistryKeys[hKey.name]
                    phk = key.handle.value
                else:
                    phk = hKey.value

            #print("figure out what to do in the case of key not in dict")
            # keyPath = 'Error in retreving key - ConnectRegistryA'

        try:
            uc.mem_write(pVals[2],pack('<I',phk))
        except:
            pass

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegConnectRegistryW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegRestoreKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'DWORD']
        pNames = ['hKey', 'lpFile', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReverseLookUp = {0x00000008: 'REG_FORCE_RESTORE', 0x00000001: 'REG_WHOLE_HIVE_VOLATILE'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
            else: # Key Not Found
                pass
        else: # Handle Not Found
            pass
          
        pVals[2] = getLookUpVal(pVals[2],dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(hKey.name)
        art.registry_misc.add(pVals[1])

        logged_calls = ("RegRestoreKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegRestoreKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD']
        pNames = ['hKey', 'lpFile', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReverseLookUp = {0x00000008: 'REG_FORCE_RESTORE', 0x00000001: 'REG_WHOLE_HIVE_VOLATILE'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
            else: # Key Not Found
                pass
        else: # Handle Not Found
            pass
          
        pVals[2] = getLookUpVal(pVals[2],dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(hKey.name)
        art.registry_misc.add(pVals[1])

        logged_calls = ("RegRestoreKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def RegSaveKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'const LPSECURITY_ATTRIBUTES']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            keyPath = ''
          
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegSaveKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSaveKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'const LPSECURITY_ATTRIBUTES']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            keyPath = ''

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegSaveKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSaveKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'const LPSECURITY_ATTRIBUTES', 'DWORD']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes', 'Flags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReversLookUp = {1: 'REG_STANDARD_FORMAT', 2: 'REG_LATEST_FORMAT', 4: 'REG_NO_COMPRESSION'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            keyPath = ''

        pVals[3] = getLookUpVal(pVals[3],dwFlagsReversLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegSaveKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSaveKeyExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'const LPSECURITY_ATTRIBUTES', 'DWORD']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes', 'Flags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        dwFlagsReversLookUp = {1: 'REG_STANDARD_FORMAT', 2: 'REG_LATEST_FORMAT', 4: 'REG_NO_COMPRESSION'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            keyPath = ''

        pVals[3] = getLookUpVal(pVals[3],dwFlagsReversLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(pVals[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegSaveKeyExW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegReplaceKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey', 'lpNewFile', 'lpOldFile']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_string(uc,pVals[1])
        newFile = read_string(uc,pVals[2])
        oldFile = read_string(uc,pVals[3])
        pVals[1] = lpSubKey

        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if lpSubKey != '[NULL]':
                    if lpSubKey[0] != '\\':
                        lpSubKey = '\\' + lpSubKey
                    pVals[1] = lpSubKey
                    keyPath = rKey.path + lpSubKey
                else:
                    pVals[1] = lpSubKey
                    keyPath = rKey.path
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            keyPath = ''
          

        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(newFile)
        art.registry_misc.add(oldFile)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegReplaceKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegReplaceKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey', 'lpNewFile', 'lpOldFile']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        lpSubKey = read_unicode(uc,pVals[1])
        newFile = read_string(uc,pVals[2])
        oldFile = read_string(uc,pVals[3])
        pVals[1] = lpSubKey
        
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                if lpSubKey != '[NULL]':
                    if lpSubKey[0] != '\\':
                        lpSubKey = '\\' + lpSubKey
                    pVals[1] = lpSubKey
                    keyPath = rKey.path + lpSubKey
                else:
                    pVals[1] = lpSubKey
                    keyPath = rKey.path
            else: # Key Not Found
                keyPath = hKey.name
        else: # Handle Not Found
            keyPath = ''
          
        art.registry_add_keys.add(keyPath)
        art.registry_misc.add(newFile)
        art.registry_misc.add(oldFile)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegReplaceKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegQueryInfoKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPSTR', 'LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','PFILETIME']
        pNames = ['hKey', 'lpClass', 'lpcchClass', 'lpReserved','lpcSubKeys','lpcbMaxSubKeyLen','lpcbMaxClassLen','lpcValues','lpcbMaxValueNameLen','lpcbMaxValueLen','lpcbSecurityDescriptor','lpftLastWriteTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        fileTime = get_FILETIME(uc, pVals[11], em)
        fileTime.genTime()
        
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                art.registry_add_keys.add(rKey.path)
                try:
                    uc.mem_write(pVals[1],pack('<I',0)) # Class Name Don't Do Reg Classes Currently
                    uc.mem_write(pVals[2],pack('<I',0)) # Class Length
                    uc.mem_write(pVals[4],pack('<I',len(rKey.childKeys))) # SubKey Count
                    maxSubKey = 0
                    for sKey in rKey.childKeys:
                        if len(sKey) > maxSubKey: 
                            maxSubKey = len(sKey)
                    uc.mem_write(pVals[5],pack('<I',maxSubKey)) # Max SubKey Length
                    uc.mem_write(pVals[6],pack('<I',0)) # Max Class Length
                    uc.mem_write(pVals[7],pack('<I',len(rKey.values))) # Value Count
                    maxValName = 0
                    for k, value in rKey.values.items():
                        if len(value.name) > maxValName: 
                            maxValName = len(value.name)
                    uc.mem_write(pVals[8],pack('<I',maxValName)) # Max Value Name Length
                    maxValData = 0
                    for k, value in rKey.values.items():
                        if not isinstance(value.data, int): # Can't Get Length of int
                            if len(value.data) > maxValData:
                                maxValData = len(value.data)
                    uc.mem_write(pVals[9],pack('<I',maxValData)) # Max Value Length
                    uc.mem_write(pVals[10],pack('<I',0)) # Security Descriptor
                    fileTime.writeToMemory(uc,pVals[11]) # LastWriteTime
                except:
                    pass
                retVal = 0
                retValStr = 'ERROR_SUCCESS'
            else: # Key Not Found
                retVal = 2
                retValStr = 'ERROR_FILE_NOT_FOUND'
        else: # Handle Not Found
            retVal = 6
            retValStr = 'ERROR_INVALID_HANDLE'
        
        pVals[11] = makeStructVals(uc, fileTime, pVals[11])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[11])

        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegQueryInfoKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegQueryInfoKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'LPWSTR', 'LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','LPDWORD','PFILETIME']
        pNames = ['hKey', 'lpClass', 'lpcchClass', 'lpReserved','lpcSubKeys','lpcbMaxSubKeyLen','lpcbMaxClassLen','lpcValues','lpcbMaxValueNameLen','lpcbMaxValueLen','lpcbSecurityDescriptor','lpftLastWriteTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        fileTime = get_FILETIME(uc, pVals[11], em)
        fileTime.genTime()
        
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                art.registry_add_keys.add(rKey.path)
                try:
                    uc.mem_write(pVals[1],pack('<I',0)) # Class Name Don't Do Reg Classes Currently
                    uc.mem_write(pVals[2],pack('<I',0)) # Class Length
                    uc.mem_write(pVals[4],pack('<I',len(rKey.childKeys))) # SubKey Count
                    maxSubKey = 0
                    for sKey in rKey.childKeys:
                        if len(sKey) > maxSubKey: 
                            maxSubKey = len(sKey)
                    uc.mem_write(pVals[5],pack('<I',maxSubKey)) # Max SubKey Length
                    uc.mem_write(pVals[6],pack('<I',0)) # Max Class Length
                    uc.mem_write(pVals[7],pack('<I',len(rKey.values))) # Value Count
                    maxValName = 0
                    for k, value in rKey.values.items():
                        if len(value.name) > maxValName: 
                            maxValName = len(value.name)
                    uc.mem_write(pVals[8],pack('<I',maxValName)) # Max Value Name Length
                    maxValData = 0
                    for k, value in rKey.values.items():
                        if not isinstance(value.data, int): # Can't Get Length of int
                            if len(value.data) > maxValData:
                                maxValData = len(value.data)
                    uc.mem_write(pVals[9],pack('<I',maxValData)) # Max Value Length
                    uc.mem_write(pVals[10],pack('<I',0)) # Security Descriptor
                    fileTime.writeToMemory(uc,pVals[11]) # LastWriteTime
                except:
                    pass
                retVal = 0
                retValStr = 'ERROR_SUCCESS'
            else: # Key Not Found
                retVal = 2
                retValStr = 'ERROR_FILE_NOT_FOUND'
        else: # Handle Not Found
            retVal = 6
            retValStr = 'ERROR_INVALID_HANDLE'
        
        pVals[11] = makeStructVals(uc, fileTime, pVals[11])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[11])

        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegQueryInfoKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegSetKeySecurity(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'SECURITY_INFORMATION', 'PSECURITY_DESCRIPTOR']
        pNames = ['hKey', 'SecurityInformation', 'pSecurityDescriptor']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                retVal = 0
                retValStr = 'ERROR_SUCCESS'
            else: # Key Not Found
                retVal = 2
                retValStr = 'ERROR_FILE_NOT_FOUND'
        else: # Handle Not Found
            retVal = 6
            retValStr = 'ERROR_INVALID_HANDLE'
        
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(hKey.name)

        logged_calls = ("RegSetKeySecurity", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegGetKeySecurity(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HKEY', 'SECURITY_INFORMATION', 'PSECURITY_DESCRIPTOR', 'LPDWORD']
        pNames = ['hKey', 'SecurityInformation', 'pSecurityDescriptor','lpcbSecurityDescriptor']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        if pVals[0] in HandlesDict:
            hKey = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey = RegistryKeys[hKey.name]
                retVal = 0
                retValStr = 'ERROR_SUCCESS'
            else: # Key Not Found
                retVal = 2
                retValStr = 'ERROR_FILE_NOT_FOUND'
        else: # Handle Not Found
            retVal = 6
            retValStr = 'ERROR_INVALID_HANDLE'
        
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(hKey.name)

        logged_calls = ("RegGetKeySecurity", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetWindowsHookExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['int', 'HOOKPROC', 'HINSTANCE', 'DWORD']
        pNames = ['idHook', 'lpfn', 'hmod', 'dwThreadId']

        idHookReverseLookUp = {4: 'WH_CALLWNDPROC', 18: 'WH_CALLWNDPROCRET', 5: 'WH_CBT', 9: 'WH_DEBUG',
                               17: 'WH_FOREGROUNDIDLE', 3: 'WH_GETMESSAGE', 1: 'WH_JOURNALPLAYBACK',
                               0: 'WH_JOURNALRECORD',
                               2: 'WH_KEYBOARD', 19: 'WH_KEYBOARD_LL', 7: 'WH_MOUSE', 20: 'WH_MOUSE_LL',
                               -1: 'WH_MSGFILTER',
                               16: 'WH_SHELL', 6: 'WH_SYSMSGFILTER'}

        pVals[0] = getLookUpVal(pVals[0], idHookReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        handle = Handle(HandleType.SetWindowsHookExA)

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetWindowsHookExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetWindowsHookExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['int', 'HOOKPROC', 'HINSTANCE', 'DWORD']
        pNames = ['idHook', 'lpfn', 'hmod', 'dwThreadId']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        idHookReverseLookUp = {4: 'WH_CALLWNDPROC', 18: 'WH_CALLWNDPROCRET', 5: 'WH_CBT', 9: 'WH_DEBUG',
                               17: 'WH_FOREGROUNDIDLE', 3: 'WH_GETMESSAGE', 1: 'WH_JOURNALPLAYBACK',
                               0: 'WH_JOURNALRECORD',
                               2: 'WH_KEYBOARD', 19: 'WH_KEYBOARD_LL', 7: 'WH_MOUSE', 20: 'WH_MOUSE_LL',
                               -1: 'WH_MSGFILTER',
                               16: 'WH_SHELL', 6: 'WH_SYSMSGFILTER'}

        pVals[0] = getLookUpVal(pVals[0], idHookReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        handle = Handle(HandleType.SetWindowsHookExW)

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetWindowsHookExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def shutdown(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['SOCKET', 'int']
        pNames = ['s', 'how']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        howReverseLookUp = {0: 'SD_RECEIVE', 1: 'SD_SEND', 2: 'SD_BOTH'}

        pVals[1] = getLookUpVal(pVals[1], howReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("shutdown", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ReplaceFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPVOID', 'LPVOID']
        pNames = ['lpReplacedFileName', 'lpReplacementFileName', 'lpBackupFileName', 'dwReplaceFlags', 'lpExclude','lpReserved']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwReplaceFlagsReverseLookUp = {1: 'REPLACEFILE_WRITE_THROUGH', 2: 'REPLACEFILE_IGNORE_MERGE_ERRORS',
                                       4: 'REPLACEFILE_IGNORE_ACL_ERRORS'}

        pVals[3] = getLookUpVal(pVals[3], dwReplaceFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReplaceFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ReplaceFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPVOID', 'LPVOID']
        pNames = ['lpReplacedFileName', 'lpReplacementFileName', 'lpBackupFileName', 'dwReplaceFlags', 'lpExclude','lpReserved']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwReplaceFlagsReverseLookUp = {1: 'REPLACEFILE_WRITE_THROUGH', 2: 'REPLACEFILE_IGNORE_MERGE_ERRORS',
                                       4: 'REPLACEFILE_IGNORE_ACL_ERRORS'}

        pVals[3] = getLookUpVal(pVals[3], dwReplaceFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReplaceFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ReadDirectoryChangesW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPVOID', 'DWORD', 'BOOL', 'DWORD', 'LPDWORD', 'LPOVERLAPPED',
                  'LPOVERLAPPED_COMPLETION_ROUTINE']
        pNames = ['hDirectory', 'lpBuffer', 'nBufferLength', 'bWatchSubtree', 'dwNotifyFilter', 'lpBytesReturned',
                  'lpOverlapped', 'lpCompletionRoutine']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwNotifyFilterReverseLookUp = {1: 'FILE_NOTIFY_CHANGE_FILE_NAME', 2: 'FILE_NOTIFY_CHANGE_DIR_NAME',
                                       4: 'FILE_NOTIFY_CHANGE_ATTRIBUTES', 8: 'FILE_NOTIFY_CHANGE_SIZE',
                                       16: 'FILE_NOTIFY_CHANGE_LAST_WRITE', 32: 'FILE_NOTIFY_CHANGE_LAST_ACCESS',
                                       64: 'FILE_NOTIFY_CHANGE_CREATION', 256: 'FILE_NOTIFY_CHANGE_SECURITY'}

        pVals[4] = getLookUpVal(pVals[4], dwNotifyFilterReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReadDirectoryChangesW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetCombineUrlA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'LPCSTR', 'LPSTR', 'LPDWORD', 'DWORD']
        pNames = ['lpszBaseUrl', 'lpszRelativeUrl', 'lpszBuffer', 'lpdwBufferLength', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {536870912: 'ICU_NO_ENCODE', 268435456: 'ICU_DECODE', 134217728: 'ICU_NO_META', 67108864: 'ICU_ENCODE_SPACES_ONLY', 33554432: 'ICU_BROWSER_MODE', 4096: 'ICU_ENCODE_PERCENT'}

        baseUrl = read_string(uc, pVals[0])
        relativeUrl = read_string(uc, pVals[1])
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        if pVals[4] == 'ICU_NO_ENCODE':
            relativeUrl = relativeUrl
        elif pVals[4] == 'ICU_DECODE':
            relativeUrl = unquote(relativeUrl)
        elif pVals[4] == 'ICU_NO_META':
            relativeUrl = quote(relativeUrl, safe='.')
            relativeUrl = relativeUrl.replace('%2F','/') # Put / Back
        elif pVals[4] == 'ICU_ENCODE_SPACES_ONLY':
            relativeUrl = relativeUrl.replace(' ', '%20')
        elif pVals[4] == 'ICU_BROWSER_MODE':
            encodedVal = ''
            found = False
            for char in relativeUrl:
                if not found:
                    if char == '?' or char == '#':
                        found = True
                        encodedVal += char
                    else:
                        encodedVal += quote(char)
                else:
                    if char == ' ':
                        encodedVal += quote(char)
                    else:
                        encodedVal += char
            relativeUrl = encodedVal
        elif pVals[4] == 'ICU_ENCODE_PERCENT':
            relativeUrl = quote(relativeUrl)
        else:
            relativeUrl = quote(relativeUrl)

        combinedUrl =  baseUrl + relativeUrl

        try:
            uc.mem_write(pVals[2], pack(f'<{len(combinedUrl)+1}s', combinedUrl.encode('ascii')))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetCombineUrlA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetCombineUrlW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPCWSTR', 'LPWSTR', 'LPDWORD', 'DWORD']
        pNames = ['lpszBaseUrl', 'lpszRelativeUrl', 'lpszBuffer', 'lpdwBufferLength', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {536870912: 'ICU_NO_ENCODE', 268435456: 'ICU_DECODE', 134217728: 'ICU_NO_META', 67108864: 'ICU_ENCODE_SPACES_ONLY', 33554432: 'ICU_BROWSER_MODE', 4096: 'ICU_ENCODE_PERCENT'}

        baseUrl = read_unicode(uc, pVals[0])
        relativeUrl = read_unicode(uc, pVals[1])
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        if pVals[4] == 'ICU_NO_ENCODE':
            relativeUrl = relativeUrl
        elif pVals[4] == 'ICU_DECODE':
            relativeUrl = unquote(relativeUrl)
        elif pVals[4] == 'ICU_NO_META':
            relativeUrl = quote(relativeUrl, safe='.')
            relativeUrl = relativeUrl.replace('%2F','/') # Put / Back
        elif pVals[4] == 'ICU_ENCODE_SPACES_ONLY':
            relativeUrl = relativeUrl.replace(' ', '%20')
        elif pVals[4] == 'ICU_BROWSER_MODE':
            encodedVal = ''
            found = False
            for char in relativeUrl:
                if not found:
                    if char == '?' or char == '#':
                        found = True
                        encodedVal += char
                    else:
                        encodedVal += quote(char)
                else:
                    if char == ' ':
                        encodedVal += quote(char)
                    else:
                        encodedVal += char
            relativeUrl = encodedVal
        elif pVals[4] == 'ICU_ENCODE_PERCENT':
            relativeUrl = quote(relativeUrl)
        else:
            relativeUrl = quote(relativeUrl)

        combinedUrl =  baseUrl + relativeUrl

        try:
            uc.mem_write(pVals[2], pack(f'<{(len(combinedUrl)*2) + 2}s', combinedUrl.encode('utf-16')[2:]))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetCombineUrlW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ExitWindowsEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['UINT', 'DWORD']
        pNames = ['uFlags', 'dwReason']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        uFlagsReverseLookUp = {4194304: 'EWX_HYBRID_SHUTDOWN', 0: 'EWX_LOGOFF', 8: 'EWX_POWEROFF', 2: 'EWX_REBOOT',
                               64: 'EWX_RESTARTAPPS', 1: 'EWX_SHUTDOWN', 4: 'EWX_FORCE', 16: 'EWX_FORCEIFHUNG'}
        dwReasonReverseLookUp = {262144: 'SHTDN_REASON_MAJOR_APPLICATION', 65536: 'SHTDN_REASON_MAJOR_HARDWARE',
                                 458752: 'SHTDN_REASON_MAJOR_LEGACY_API', 131072: 'SHTDN_REASON_MAJOR_OPERATINGSYSTEM',
                                 0: 'SHTDN_REASON_MINOR_OTHER', 393216: 'SHTDN_REASON_MAJOR_POWER',
                                 196608: 'SHTDN_REASON_MAJOR_SOFTWARE', 327680: 'SHTDN_REASON_MAJOR_SYSTEM',
                                 15: 'SHTDN_REASON_MINOR_BLUESCREEN', 11: 'SHTDN_REASON_MINOR_CORDUNPLUGGED',
                                 7: 'SHTDN_REASON_MINOR_DISK', 12: 'SHTDN_REASON_MINOR_ENVIRONMENT',
                                 13: 'SHTDN_REASON_MINOR_HARDWARE_DRIVER', 17: 'SHTDN_REASON_MINOR_HOTFIX',
                                 23: 'SHTDN_REASON_MINOR_HOTFIX_UNINSTALL', 5: 'SHTDN_REASON_MINOR_HUNG',
                                 2: 'SHTDN_REASON_MINOR_INSTALLATION', 1: 'SHTDN_REASON_MINOR_MAINTENANCE',
                                 25: 'SHTDN_REASON_MINOR_MMC', 20: 'SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY',
                                 9: 'SHTDN_REASON_MINOR_NETWORKCARD', 14: 'SHTDN_REASON_MINOR_OTHERDRIVER',
                                 10: 'SHTDN_REASON_MINOR_POWER_SUPPLY', 8: 'SHTDN_REASON_MINOR_PROCESSOR',
                                 4: 'SHTDN_REASON_MINOR_RECONFIG', 19: 'SHTDN_REASON_MINOR_SECURITY',
                                 18: 'SHTDN_REASON_MINOR_SECURITYFIX', 24: 'SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL',
                                 16: 'SHTDN_REASON_MINOR_SERVICEPACK', 22: 'SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL',
                                 32: 'SHTDN_REASON_MINOR_TERMSRV', 6: 'SHTDN_REASON_MINOR_UNSTABLE',
                                 3: 'SHTDN_REASON_MINOR_UPGRADE', 21: 'SHTDN_REASON_MINOR_WMI',
                                 1073741824: 'SHTDN_REASON_FLAG_USER_DEFINED', 2147483648: 'SHTDN_REASON_FLAG_PLANNED'}

        pVals[0] = getLookUpVal(pVals[0], uFlagsReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1], dwReasonReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0,1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ExitWindowsEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetFileAttributesA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'DWORD']
        pNames = ['lpFileName', 'dwFileAttributes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.File.FlagsAndAttribute)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetFileAttributesA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetFileAttributesW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'DWORD']
        pNames = ['lpFileName', 'dwFileAttributes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.File.FlagsAndAttribute)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetFileAttributesW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateFileMappingA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        flProtectReverseLookUp = {2: 'PAGE_READONLY', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE',
                                  285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        handle = Handle(HandleType.CreateFileMappingA) # Might Add Name

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateFileMappingW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        flProtectReverseLookUp = {2: 'PAGE_READONLY', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE',
                                  285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        handle = Handle(HandleType.CreateFileMappingW) # Might Add Name

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptAcquireContextA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HCRYPTPROV', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD']
        pNames = ['phProv', 'szContainer', 'szProvider', 'dwProvType', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwProvTypeReverseLookUp = {1: 'PROV_RSA_FULL', 2: 'PROV_RSA_SIG', 3: 'PROV_DSS', 4: 'PROV_FORTEZZA',
                                   5: 'PROV_MS_EXCHANGE', 6: 'PROV_SSL', 18: 'PROV_RSA_SCHANNEL', 19: 'PROV_DSS_DH',
                                   24: 'PROV_DH_SCHANNEL', 36: 'PROV_RSA_AES'}
        dwFlagsReverseLookUp = {4026531840: 'CRYPT_VERIFYCONTEXT', 8: 'CRYPT_NEWKEYSET', 16: 'CRYPT_DELETEKEYSET',
                                32: 'CRYPT_MACHINE_KEYSET', 64: 'CRYPT_SILENT', 128: 'CRYPT_DEFAULT_CONTAINER_OPTIONAL'}

        pVals[3] = getLookUpVal(pVals[3], dwProvTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3,4])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptAcquireContextA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptAcquireContextW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HCRYPTPROV', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD']
        pNames = ['phProv', 'szContainer', 'szProvider', 'dwProvType', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwProvTypeReverseLookUp = {1: 'PROV_RSA_FULL', 2: 'PROV_RSA_SIG', 3: 'PROV_DSS', 4: 'PROV_FORTEZZA',
                                   5: 'PROV_MS_EXCHANGE', 6: 'PROV_SSL', 18: 'PROV_RSA_SCHANNEL', 19: 'PROV_DSS_DH',
                                   24: 'PROV_DH_SCHANNEL', 36: 'PROV_RSA_AES'}
        dwFlagsReverseLookUp = {4026531840: 'CRYPT_VERIFYCONTEXT', 8: 'CRYPT_NEWKEYSET', 16: 'CRYPT_DELETEKEYSET',
                                32: 'CRYPT_MACHINE_KEYSET', 64: 'CRYPT_SILENT', 128: 'CRYPT_DEFAULT_CONTAINER_OPTIONAL'}

        pVals[3] = getLookUpVal(pVals[3], dwProvTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3,4])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptAcquireContextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenSCManagerA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE',
                                        1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE',
                                        8: 'SC_MANAGER_LOCK',
                                        32: 'SC_MANAGER_MODIFY_BOOT_CONFIG', 16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

        handle = Handle(HandleType.SC_HANDLE)

        pVals[2] = getLookUpVal(pVals[2], dwDesiredAccessReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenSCManagerA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenSCManagerW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPCWSTR', 'DWORD']
        pNames = ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE',
                                        1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE',
                                        8: 'SC_MANAGER_LOCK',
                                        32: 'SC_MANAGER_MODIFY_BOOT_CONFIG', 16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

        handle = Handle(HandleType.SC_HANDLE)

        pVals[2] = getLookUpVal(pVals[2], dwDesiredAccessReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenSCManagerW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FtpPutFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszLocalFile', 'lpszNewRemoteFile', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpPutFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FtpPutFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszLocalFile', 'lpszNewRemoteFile', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpPutFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetQueryOptionA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'lpdwBufferLength']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC',
                                 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY',
                                 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE',
                                 105: 'INTERNET_OPTION_CACHE_TIMESTAMPS', 1: 'INTERNET_OPTION_CALLBACK',
                                 84: 'INTERNET_OPTION_CALLBACK_FILTER',
                                 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH',
                                 4: 'INTERNET_OPTION_CONNECT_BACKOFF', 3: 'INTERNET_OPTION_CONNECT_RETRIES',
                                 85: 'INTERNET_OPTION_CONNECT_TIME', 2: 'INTERNET_OPTION_CONNECT_TIMEOUT',
                                 80: 'INTERNET_OPTION_CONNECTED_STATE', 69: 'INTERNET_OPTION_CONTEXT_VALUE',
                                 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT', 5: 'INTERNET_OPTION_SEND_TIMEOUT',
                                 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT', 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT',
                                 51: 'INTERNET_OPTION_DATAFILE_NAME', 103: 'INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO',
                                 112: 'INTERNET_OPTION_DISABLE_AUTODIAL', 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT',
                                 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL',
                                 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA',
                                 98: 'INTERNET_OPTION_ERROR_MASK', 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT',
                                 36: 'INTERNET_OPTION_EXTENDED_ERROR', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT',
                                 9: 'INTERNET_OPTION_HANDLE_TYPE', 343: 'INTERNET_OPTION_HSTS',
                                 101: 'INTERNET_OPTION_HTTP_DECODING', 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED',
                                 89: 'INTERNET_OPTION_HTTP_VERSION', 120: 'INTERNET_OPTION_IDENTITY',
                                 81: 'INTERNET_OPTION_IDLE_STATE', 119: 'INTERNET_OPTION_IGNORE_OFFLINE',
                                 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT',
                                 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER',
                                 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER', 38: 'INTERNET_OPTION_OFFLINE_MODE',
                                 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS', 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE',
                                 33: 'INTERNET_OPTION_PARENT_HANDLE', 41: 'INTERNET_OPTION_PASSWORD',
                                 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY',
                                 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD',
                                 67: 'INTERNET_OPTION_PROXY_USERNAME', 18: 'INTERNET_OPTION_READ_BUFFER_SIZE',
                                 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT', 121: 'INTERNET_OPTION_REMOVE_IDENTITY',
                                 35: 'INTERNET_OPTION_REQUEST_FLAGS', 88: 'INTERNET_OPTION_REQUEST_PRIORITY',
                                 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 53: 'INTERNET_OPTION_SECURITY_CERTIFICATE',
                                 50: 'INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT',
                                 49: 'INTERNET_OPTION_SECURITY_FLAGS',
                                 54: 'INTERNET_OPTION_SECURITY_KEY_BITNESS', 86: 'INTERNET_OPTION_SEND_THROUGHPUT',
                                 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT',
                                 129: 'INTERNET_OPTION_SUPPRESS_BEHAVIOR',
                                 52: 'INTERNET_OPTION_URL', 65: 'INTERNET_OPTION_USER_AGENT',
                                 40: 'INTERNET_OPTION_USERNAME', 64: 'INTERNET_OPTION_VERSION',
                                 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

        pVals[1] = getLookUpVal(pVals[1], dwOptionReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetQueryOptionA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetQueryOptionW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'lpdwBufferLength']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC',
                                 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY',
                                 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE',
                                 105: 'INTERNET_OPTION_CACHE_TIMESTAMPS', 1: 'INTERNET_OPTION_CALLBACK',
                                 84: 'INTERNET_OPTION_CALLBACK_FILTER',
                                 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH',
                                 4: 'INTERNET_OPTION_CONNECT_BACKOFF', 3: 'INTERNET_OPTION_CONNECT_RETRIES',
                                 85: 'INTERNET_OPTION_CONNECT_TIME', 2: 'INTERNET_OPTION_CONNECT_TIMEOUT',
                                 80: 'INTERNET_OPTION_CONNECTED_STATE', 69: 'INTERNET_OPTION_CONTEXT_VALUE',
                                 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT', 5: 'INTERNET_OPTION_SEND_TIMEOUT',
                                 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT', 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT',
                                 51: 'INTERNET_OPTION_DATAFILE_NAME', 103: 'INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO',
                                 112: 'INTERNET_OPTION_DISABLE_AUTODIAL', 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT',
                                 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL',
                                 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA',
                                 98: 'INTERNET_OPTION_ERROR_MASK', 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT',
                                 36: 'INTERNET_OPTION_EXTENDED_ERROR', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT',
                                 9: 'INTERNET_OPTION_HANDLE_TYPE', 343: 'INTERNET_OPTION_HSTS',
                                 101: 'INTERNET_OPTION_HTTP_DECODING', 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED',
                                 89: 'INTERNET_OPTION_HTTP_VERSION', 120: 'INTERNET_OPTION_IDENTITY',
                                 81: 'INTERNET_OPTION_IDLE_STATE', 119: 'INTERNET_OPTION_IGNORE_OFFLINE',
                                 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT',
                                 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER',
                                 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER', 38: 'INTERNET_OPTION_OFFLINE_MODE',
                                 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS', 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE',
                                 33: 'INTERNET_OPTION_PARENT_HANDLE', 41: 'INTERNET_OPTION_PASSWORD',
                                 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY',
                                 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD',
                                 67: 'INTERNET_OPTION_PROXY_USERNAME', 18: 'INTERNET_OPTION_READ_BUFFER_SIZE',
                                 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT', 121: 'INTERNET_OPTION_REMOVE_IDENTITY',
                                 35: 'INTERNET_OPTION_REQUEST_FLAGS', 88: 'INTERNET_OPTION_REQUEST_PRIORITY',
                                 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 53: 'INTERNET_OPTION_SECURITY_CERTIFICATE',
                                 50: 'INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT',
                                 49: 'INTERNET_OPTION_SECURITY_FLAGS',
                                 54: 'INTERNET_OPTION_SECURITY_KEY_BITNESS', 86: 'INTERNET_OPTION_SEND_THROUGHPUT',
                                 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT',
                                 129: 'INTERNET_OPTION_SUPPRESS_BEHAVIOR',
                                 52: 'INTERNET_OPTION_URL', 65: 'INTERNET_OPTION_USER_AGENT',
                                 40: 'INTERNET_OPTION_USERNAME', 64: 'INTERNET_OPTION_VERSION',
                                 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

        pVals[1] = getLookUpVal(pVals[1], dwOptionReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetQueryOptionW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetSetOptionA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'DWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'dwBufferLength']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.Internet.SetOption_dwOption)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetSetOptionA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetSetOptionW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'DWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'dwBufferLength']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pVals[1] = getLookUpVal(pVals[1],  ReverseLookUps.Internet.SetOption_dwOption)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetSetOptionW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpOpenRequestA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszVerb', 'lpszObjectName', 'lpszVersion', 'lpszReferrer', 'lplpszAcceptTypes',
                  'dwFlags',
                  'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {65536: 'INTERNET_FLAG_CACHE_IF_NET_FAIL', 1024: 'INTERNET_FLAG_HYPERLINK',
                                4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID',
                                8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID',
                                32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP',
                                16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS',
                                4194304: 'INTERNET_FLAG_KEEP_CONNECTION',
                                16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH',
                                2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE',
                                524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI',
                                256: 'INTERNET_FLAG_PRAGMA_NOCACHE', 2147483648: 'INTERNET_FLAG_RELOAD',
                                2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

        pVals[6] = getLookUpVal(pVals[6], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6])

        if pVals[3] == '[NULL]':
            pVals[3] = 'HTTP/1.1'

        handle = Handle(HandleType.HINTERNET)

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpOpenRequestA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpOpenRequestW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszVerb', 'lpszObjectName', 'lpszVersion', 'lpszReferrer', 'lplpszAcceptTypes',
                  'dwFlags',
                  'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {65536: 'INTERNET_FLAG_CACHE_IF_NET_FAIL', 1024: 'INTERNET_FLAG_HYPERLINK',
                                4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID',
                                8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID',
                                32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP',
                                16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS',
                                4194304: 'INTERNET_FLAG_KEEP_CONNECTION',
                                16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH',
                                2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE',
                                524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI',
                                256: 'INTERNET_FLAG_PRAGMA_NOCACHE', 2147483648: 'INTERNET_FLAG_RELOAD',
                                2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

        pVals[6] = getLookUpVal(pVals[6], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6])

        if pVals[3] == '[NULL]':
            pVals[3] = 'HTTP/1.1'
  
        handle = Handle(HandleType.HINTERNET)

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpOpenRequestW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpAddRequestHeadersA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'DWORD', 'DWORD']
        pNames = ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'dwModifiers']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwModifiersReverseLookUp = {536870912: 'HTTP_ADDREQ_FLAG_ADD', 268435456: 'HTTP_ADDREQ_FLAG_ADD_IF_NEW',
                                    1073741824: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA',
                                    16777216: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON',
                                    2147483648: 'HTTP_ADDREQ_FLAG_REPLACE'}

        pVals[3] = getLookUpVal(pVals[3], dwModifiersReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpAddRequestHeadersA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpSendRequestA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'DWORD', 'LPVOID', 'DWORD']
        pNames = ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'lpOptional', 'dwOptionalLength']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpSendRequestA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpSendRequestExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPINTERNET_BUFFERSA', 'LPINTERNET_BUFFERSA', 'DWORD', 'DWORD_PTR']
        pNames = ['hRequest', 'lpBuffersIn', 'lpBuffersOut', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpSendRequestExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetCloseHandle(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET']
        pNames = ['hInternet']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetCloseHandle", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetReadFile(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['hFile', 'lpBuffer', 'dwNumberOfBytesToRead', 'lpdwNumberOfBytesToRead']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetReadFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetReadFileExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPINTERNET_BUFFERSA', 'DWORD', 'DWORD_PTR']
        pNames = ['hFile', 'lpBuffersOut', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {1: 'IRF_ASYNC', 4: 'IRF_SYNC', 8: 'IRF_USE_CONTEXT', 0: 'IRF_NO_WAIT'}
        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetReadFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetReadFileExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPINTERNET_BUFFERSW', 'DWORD', 'DWORD_PTR']
        pNames = ['hFile', 'lpBuffersOut', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {1: 'IRF_ASYNC', 4: 'IRF_SYNC', 8: 'IRF_USE_CONTEXT', 0: 'IRF_NO_WAIT'}
        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetReadFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetWriteFile(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCVOID', 'DWORD', 'LPDWORD']
        pNames = ['hFile', 'lpBuffer', 'dwNumberOfBytesToWrite', 'lpdwNumberOfBytesWritten']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetWriteFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLOpenBlockingStreamA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'LPSTREAM', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', '*ppStream', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenBlockingStreamA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLOpenBlockingStreamW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'LPSTREAM', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', '*ppStream', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenBlockingStreamW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLOpenStreamA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenStreamA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def URLOpenStreamW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenStreamW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpAddRequestHeadersW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCWSTR', 'DWORD', 'DWORD']
        pNames = ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'dwModifiers']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwModifiersReverseLookUp = {536870912: 'HTTP_ADDREQ_FLAG_ADD', 268435456: 'HTTP_ADDREQ_FLAG_ADD_IF_NEW',
                                    1073741824: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA',
                                    16777216: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON',
                                    2147483648: 'HTTP_ADDREQ_FLAG_REPLACE'}

        pVals[3] = getLookUpVal(pVals[3], dwModifiersReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[3])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpAddRequestHeadersW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpQueryInfoA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD', 'LPDWORD']
        pNames = ['hRequest', 'dwInfoLevel', 'lpBuffer', 'lpdwBufferLength', 'lpdwIndex']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwInfoLevelReverseLookUp = {36: 'HTTP_QUERY_ACCEPT', 37: 'HTTP_QUERY_ACCEPT_CHARSET',
                                    38: 'HTTP_QUERY_ACCEPT_ENCODING', 39: 'HTTP_QUERY_ACCEPT_LANGUAGE',
                                    66: 'HTTP_QUERY_ACCEPT_RANGES', 72: 'HTTP_QUERY_AGE', 7: 'HTTP_QUERY_ALLOW',
                                    40: 'HTTP_QUERY_AUTHORIZATION', 73: 'HTTP_QUERY_CACHE_CONTROL',
                                    35: 'HTTP_QUERY_CONNECTION', 80: 'HTTP_QUERY_CONTENT_BASE',
                                    4: 'HTTP_QUERY_CONTENT_DESCRIPTION', 71: 'HTTP_QUERY_CONTENT_DISPOSITION',
                                    41: 'HTTP_QUERY_CONTENT_ENCODING', 3: 'HTTP_QUERY_CONTENT_ID',
                                    6: 'HTTP_QUERY_CONTENT_LANGUAGE', 5: 'HTTP_QUERY_CONTENT_LENGTH',
                                    81: 'HTTP_QUERY_CONTENT_LOCATION', 82: 'HTTP_QUERY_CONTENT_MD5',
                                    83: 'HTTP_QUERY_CONTENT_RANGE', 2: 'HTTP_QUERY_CONTENT_TRANSFER_ENCODING',
                                    1: 'HTTP_QUERY_CONTENT_TYPE', 68: 'HTTP_QUERY_COOKIE', 21: 'HTTP_QUERY_COST',
                                    415029: 'HTTP_QUERY_CUSTOM', 9: 'HTTP_QUERY_DATE', 20: 'HTTP_QUERY_DERIVED_FROM',
                                    115: 'HTTP_QUERY_ECHO_HEADERS', 116: 'HTTP_QUERY_ECHO_HEADERS_CRLF',
                                    114: 'HTTP_QUERY_ECHO_REPLY', 113: 'HTTP_QUERY_ECHO_REQUEST', 84: 'HTTP_QUERY_ETAG',
                                    104: 'HTTP_QUERY_EXPECT', 16: 'HTTP_QUERY_EXPIRES', 48: 'HTTP_QUERY_FORWARDED',
                                    49: 'HTTP_QUERY_FROM', 85: 'HTTP_QUERY_HOST', 86: 'HTTP_QUERY_IF_MATCH',
                                    50: 'HTTP_QUERY_IF_MODIFIED_SINCE', 87: 'HTTP_QUERY_IF_NONE_MATCH',
                                    88: 'HTTP_QUERY_IF_RANGE', 89: 'HTTP_QUERY_IF_UNMODIFIED_SINCE',
                                    17: 'HTTP_QUERY_LAST_MODIFIED', 22: 'HTTP_QUERY_LINK', 51: 'HTTP_QUERY_LOCATION',
                                    120: 'HTTP_QUERY_MAX', 96: 'HTTP_QUERY_MAX_FORWARDS', 18: 'HTTP_QUERY_MESSAGE_ID',
                                    0: 'HTTP_QUERY_MIME_VERSION', 52: 'HTTP_QUERY_ORIG_URI', 23: 'HTTP_QUERY_PRAGMA',
                                    65: 'HTTP_QUERY_PROXY_AUTHENTICATE', 97: 'HTTP_QUERY_PROXY_AUTHORIZATION',
                                    105: 'HTTP_QUERY_PROXY_CONNECTION', 8: 'HTTP_QUERY_PUBLIC', 98: 'HTTP_QUERY_RANGE',
                                    33: 'HTTP_QUERY_RAW_HEADERS', 34: 'HTTP_QUERY_RAW_HEADERS_CRLF',
                                    53: 'HTTP_QUERY_REFERER', 70: 'HTTP_QUERY_REFRESH', 69: 'HTTP_QUERY_REQUEST_METHOD',
                                    54: 'HTTP_QUERY_RETRY_AFTER', 55: 'HTTP_QUERY_SERVER', 67: 'HTTP_QUERY_SET_COOKIE',
                                    25: 'HTTP_QUERY_STATUS_CODE', 32: 'HTTP_QUERY_STATUS_TEXT', 56: 'HTTP_QUERY_TITLE',
                                    99: 'HTTP_QUERY_TRANSFER_ENCODING', 112: 'HTTP_QUERY_UNLESS_MODIFIED_SINCE',
                                    100: 'HTTP_QUERY_UPGRADE', 19: 'HTTP_QUERY_URI', 57: 'HTTP_QUERY_USER_AGENT',
                                    101: 'HTTP_QUERY_VARY', 24: 'HTTP_QUERY_VERSION', 102: 'HTTP_QUERY_VIA',
                                    103: 'HTTP_QUERY_WARNING', 64: 'HTTP_QUERY_WWW_AUTHENTICATE',
                                    121: 'HTTP_QUERY_X_CONTENT_TYPE_OPTIONS', 128: 'HTTP_QUERY_P3P',
                                    129: 'HTTP_QUERY_X_P2P_PEERDIST', 130: 'HTTP_QUERY_TRANSLATE',
                                    131: 'HTTP_QUERY_X_UA_COMPATIBLE', 132: 'HTTP_QUERY_DEFAULT_STYLE',
                                    133: 'HTTP_QUERY_X_FRAME_OPTIONS', 134: 'HTTP_QUERY_X_XSS_PROTECTION',
                                    268435456: 'HTTP_QUERY_FLAG_COALESCE', 536870912: 'HTTP_QUERY_FLAG_NUMBER',
                                    2147483648: 'HTTP_QUERY_FLAG_REQUEST_HEADERS',
                                    1073741824: 'HTTP_QUERY_FLAG_SYSTEMTIME'}

        pVals[1] = getLookUpVal(pVals[1], dwInfoLevelReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpQueryInfoA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def HttpQueryInfoW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD', 'LPDWORD']
        pNames = ['hRequest', 'dwInfoLevel', 'lpBuffer', 'lpdwBufferLength', 'lpdwIndex']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwInfoLevelReverseLookUp = {36: 'HTTP_QUERY_ACCEPT', 37: 'HTTP_QUERY_ACCEPT_CHARSET',
                                    38: 'HTTP_QUERY_ACCEPT_ENCODING', 39: 'HTTP_QUERY_ACCEPT_LANGUAGE',
                                    66: 'HTTP_QUERY_ACCEPT_RANGES', 72: 'HTTP_QUERY_AGE', 7: 'HTTP_QUERY_ALLOW',
                                    40: 'HTTP_QUERY_AUTHORIZATION', 73: 'HTTP_QUERY_CACHE_CONTROL',
                                    35: 'HTTP_QUERY_CONNECTION', 80: 'HTTP_QUERY_CONTENT_BASE',
                                    4: 'HTTP_QUERY_CONTENT_DESCRIPTION', 71: 'HTTP_QUERY_CONTENT_DISPOSITION',
                                    41: 'HTTP_QUERY_CONTENT_ENCODING', 3: 'HTTP_QUERY_CONTENT_ID',
                                    6: 'HTTP_QUERY_CONTENT_LANGUAGE', 5: 'HTTP_QUERY_CONTENT_LENGTH',
                                    81: 'HTTP_QUERY_CONTENT_LOCATION', 82: 'HTTP_QUERY_CONTENT_MD5',
                                    83: 'HTTP_QUERY_CONTENT_RANGE', 2: 'HTTP_QUERY_CONTENT_TRANSFER_ENCODING',
                                    1: 'HTTP_QUERY_CONTENT_TYPE', 68: 'HTTP_QUERY_COOKIE', 21: 'HTTP_QUERY_COST',
                                    415029: 'HTTP_QUERY_CUSTOM', 9: 'HTTP_QUERY_DATE', 20: 'HTTP_QUERY_DERIVED_FROM',
                                    115: 'HTTP_QUERY_ECHO_HEADERS', 116: 'HTTP_QUERY_ECHO_HEADERS_CRLF',
                                    114: 'HTTP_QUERY_ECHO_REPLY', 113: 'HTTP_QUERY_ECHO_REQUEST', 84: 'HTTP_QUERY_ETAG',
                                    104: 'HTTP_QUERY_EXPECT', 16: 'HTTP_QUERY_EXPIRES', 48: 'HTTP_QUERY_FORWARDED',
                                    49: 'HTTP_QUERY_FROM', 85: 'HTTP_QUERY_HOST', 86: 'HTTP_QUERY_IF_MATCH',
                                    50: 'HTTP_QUERY_IF_MODIFIED_SINCE', 87: 'HTTP_QUERY_IF_NONE_MATCH',
                                    88: 'HTTP_QUERY_IF_RANGE', 89: 'HTTP_QUERY_IF_UNMODIFIED_SINCE',
                                    17: 'HTTP_QUERY_LAST_MODIFIED', 22: 'HTTP_QUERY_LINK', 51: 'HTTP_QUERY_LOCATION',
                                    120: 'HTTP_QUERY_MAX', 96: 'HTTP_QUERY_MAX_FORWARDS', 18: 'HTTP_QUERY_MESSAGE_ID',
                                    0: 'HTTP_QUERY_MIME_VERSION', 52: 'HTTP_QUERY_ORIG_URI', 23: 'HTTP_QUERY_PRAGMA',
                                    65: 'HTTP_QUERY_PROXY_AUTHENTICATE', 97: 'HTTP_QUERY_PROXY_AUTHORIZATION',
                                    105: 'HTTP_QUERY_PROXY_CONNECTION', 8: 'HTTP_QUERY_PUBLIC', 98: 'HTTP_QUERY_RANGE',
                                    33: 'HTTP_QUERY_RAW_HEADERS', 34: 'HTTP_QUERY_RAW_HEADERS_CRLF',
                                    53: 'HTTP_QUERY_REFERER', 70: 'HTTP_QUERY_REFRESH', 69: 'HTTP_QUERY_REQUEST_METHOD',
                                    54: 'HTTP_QUERY_RETRY_AFTER', 55: 'HTTP_QUERY_SERVER', 67: 'HTTP_QUERY_SET_COOKIE',
                                    25: 'HTTP_QUERY_STATUS_CODE', 32: 'HTTP_QUERY_STATUS_TEXT', 56: 'HTTP_QUERY_TITLE',
                                    99: 'HTTP_QUERY_TRANSFER_ENCODING', 112: 'HTTP_QUERY_UNLESS_MODIFIED_SINCE',
                                    100: 'HTTP_QUERY_UPGRADE', 19: 'HTTP_QUERY_URI', 57: 'HTTP_QUERY_USER_AGENT',
                                    101: 'HTTP_QUERY_VARY', 24: 'HTTP_QUERY_VERSION', 102: 'HTTP_QUERY_VIA',
                                    103: 'HTTP_QUERY_WARNING', 64: 'HTTP_QUERY_WWW_AUTHENTICATE',
                                    121: 'HTTP_QUERY_X_CONTENT_TYPE_OPTIONS', 128: 'HTTP_QUERY_P3P',
                                    129: 'HTTP_QUERY_X_P2P_PEERDIST', 130: 'HTTP_QUERY_TRANSLATE',
                                    131: 'HTTP_QUERY_X_UA_COMPATIBLE', 132: 'HTTP_QUERY_DEFAULT_STYLE',
                                    133: 'HTTP_QUERY_X_FRAME_OPTIONS', 134: 'HTTP_QUERY_X_XSS_PROTECTION',
                                    268435456: 'HTTP_QUERY_FLAG_COALESCE', 536870912: 'HTTP_QUERY_FLAG_NUMBER',
                                    2147483648: 'HTTP_QUERY_FLAG_REQUEST_HEADERS',
                                    1073741824: 'HTTP_QUERY_FLAG_SYSTEMTIME'}

        pVals[1] = getLookUpVal(pVals[1], dwInfoLevelReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpQueryInfoW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FtpGetFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'BOOL', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszRemoteFile', 'lpszNewFile', 'fFailIfExists', 'dwFlagsAndAttributes', 'dwFlags',
                  'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[4] = getLookUpVal(pVals[4], ReverseLookUps.File.FlagsAndAttribute)
        pVals[5] = getLookUpVal(pVals[5], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4,5])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpGetFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FtpGetFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'BOOL', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszRemoteFile', 'lpszNewFile', 'fFailIfExists', 'dwFlagsAndAttributes', 'dwFlags',
                  'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[4] = getLookUpVal(pVals[4], ReverseLookUps.File.FlagsAndAttribute)
        pVals[5] = getLookUpVal(pVals[5], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4,5])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpGetFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FtpOpenFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszFileName', 'dwAccess', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE'}
        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[2] = getLookUpVal(pVals[2], dwAccessReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2,3])
        
        handle = Handle(HandleType.HINTERNET, name=pVals[1])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpOpenFileA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FtpOpenFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszFileName', 'dwAccess', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE'}
        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[2] = getLookUpVal(pVals[2], dwAccessReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2,3])
        
        handle = Handle(HandleType.HINTERNET, name=pVals[1])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpOpenFileW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetOpenUrlA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszUrl', 'lpszHeaders', 'dwHeadersLength', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 1024: 'INTERNET_FLAG_HYPERLINK',
                                4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID',
                                8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID',
                                32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP',
                                16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS',
                                4194304: 'INTERNET_FLAG_KEEP_CONNECTION',
                                16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH',
                                2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE',
                                524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI',
                                134217728: 'INTERNET_FLAG_PASSIVE', 256: 'INTERNET_FLAG_PRAGMA_NOCACHE',
                                1073741824: 'INTERNET_FLAG_RAW_DATA', 2147483648: 'INTERNET_FLAG_RELOAD',
                                2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4])
        
        handle = Handle(HandleType.HINTERNET, name=pVals[1])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenUrlA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def InternetOpenUrlW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszUrl', 'lpszHeaders', 'dwHeadersLength', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 1024: 'INTERNET_FLAG_HYPERLINK',
                                4096: 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID',
                                8192: 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID',
                                32768: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP',
                                16384: 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS',
                                4194304: 'INTERNET_FLAG_KEEP_CONNECTION',
                                16: 'INTERNET_FLAG_NEED_FILE', 262144: 'INTERNET_FLAG_NO_AUTH',
                                2097152: 'INTERNET_FLAG_NO_AUTO_REDIRECT', 67108864: 'INTERNET_FLAG_NO_CACHE_WRITE',
                                524288: 'INTERNET_FLAG_NO_COOKIES', 512: 'INTERNET_FLAG_NO_UI',
                                134217728: 'INTERNET_FLAG_PASSIVE', 256: 'INTERNET_FLAG_PRAGMA_NOCACHE',
                                1073741824: 'INTERNET_FLAG_RAW_DATA', 2147483648: 'INTERNET_FLAG_RELOAD',
                                2048: 'INTERNET_FLAG_RESYNCHRONIZE', 8388608: 'INTERNET_FLAG_SECURE'}

        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4])

        handle = Handle(HandleType.HINTERNET, name=pVals[1])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenUrlW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MoveFileExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {2: 'MOVEFILE_COPY_ALLOWED', 16: 'MOVEFILE_CREATE_HARDLINK',
                                4: 'MOVEFILE_DELAY_UNTIL_REBOOT', 32: 'MOVEFILE_FAIL_IF_NOT_TRACKABLE',
                                1: 'MOVEFILE_REPLACE_EXISTING', 8: 'MOVEFILE_WRITE_THROUGH'}

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("MoveFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MoveFileExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPCWSTR', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {2: 'MOVEFILE_COPY_ALLOWED', 16: 'MOVEFILE_CREATE_HARDLINK',
                                4: 'MOVEFILE_DELAY_UNTIL_REBOOT', 32: 'MOVEFILE_FAIL_IF_NOT_TRACKABLE',
                                1: 'MOVEFILE_REPLACE_EXISTING', 8: 'MOVEFILE_WRITE_THROUGH'}

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("MoveFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CopyFileExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'LPCSTR', 'LPPROGRESS_ROUTINE', 'LPVOID', 'LPBOOL', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'lpProgressRoutine', 'lpData', 'pbCancel', 'dwCopyFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        mdwCopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK',
                                     1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING',
                                     4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE',
                                     268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

        pVals[5] = getLookUpVal(pVals[5], mdwCopyFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CopyFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CopyFileExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPCWSTR', 'LPPROGRESS_ROUTINE', 'LPVOID', 'LPBOOL', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'lpProgressRoutine', 'lpData', 'pbCancel', 'dwCopyFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        mdwCopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK',
                                     1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING',
                                     4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE',
                                     268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

        pVals[5] = getLookUpVal(pVals[5], mdwCopyFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CopyFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def DuplicateHandle(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'HANDLE', 'HANDLE', 'LPHANDLE', 'DWORD', 'BOOL', 'DWORD']
        pNames = ['hSourceProcessHandle', 'hSourceHandle', 'hTargetProcessHandle', 'lpTargetHandle', 'dwDesiredAccess',
                  'bInheritHandle', 'dwOptions']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwDesiredAccessReverseLookUp = {65536: 'DELETE', 131072: 'READ_CONTROL', 262144: 'WRITE_DAC',
                                        524288: 'WRITE_OWNER',
                                        1048576: 'SYNCHRONIZE', 983040: 'STANDARD_RIGHTS_REQUIRED',
                                        2031616: 'STANDARD_RIGHTS_ALL'}
        dwOptionsReverseLookUp = {1: 'DUPLICATE_CLOSE_SOURCE', 2: 'DUPLICATE_SAME_ACCESS'}

        pVals[4] = getLookUpVal(pVals[4], dwDesiredAccessReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], dwOptionsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4,6])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("DuplicateHandle", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateFileMappingNumaA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'DWORD']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName',
                  'nndPreferred']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        flProtectReverseLookUp = {32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE',
                                  2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}
        nndPreferredReverseLookUp = {4294967295: 'NUMA_NO_PREFERRED_NODE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], nndPreferredReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2,6])

        handle = Handle(HandleType.CreateFileMappingNumaW) # Might Add Name
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingNumaA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateFileMappingNumaW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR', 'DWORD']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName',
                  'nndPreferred']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        flProtectReverseLookUp = {32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE',
                                  2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}
        nndPreferredReverseLookUp = {4294967295: 'NUMA_NO_PREFERRED_NODE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], nndPreferredReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2,6])
        
        handle = Handle(HandleType.CreateFileMappingNumaW) # Might Add Name

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingNumaW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateMutexA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexA([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in] BOOL bInitialOwner,[in, optional] LPCSTR lpName)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'BOOL', 'LPCSTR']
        pNames = ['lpMutexAttributes', 'bInitialOwner', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        name = read_string(uc, pVals[2])
        handle = Handle(HandleType.Mutex, name = name)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateMutexW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexW([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in] BOOL bInitialOwner,[in, optional] LPCWSTR lpName)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'BOOL', 'LPCWSTR']
        pNames = ['lpMutexAttributes', 'bInitialOwner', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        name = read_unicode(uc, pVals[2])
        handle = Handle(HandleType.Mutex, name = name)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateMutexExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexExA([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in, optional] LPCSTR lpName,[in] DWORD dwFlags,[in] DWORD dwDesiredAccess);
        pTypes = ['LPSECURITY_ATTRIBUTES', 'LPCSTR', 'DWORD', 'DWORD']
        pNames = ['lpMutexAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        name = read_string(uc, pVals[1])
        handle = Handle(HandleType.Mutex, name = name)

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Mutex.dwFlags)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Mutex.dwDesiredAccess)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2,3])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateMutexExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexExW([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in, optional] LPCWSTR lpName,[in] DWORD dwFlags,[in] DWORD dwDesiredAccess);
        pTypes = ['LPSECURITY_ATTRIBUTES', 'LPCWSTR', 'DWORD', 'DWORD']
        pNames = ['lpMutexAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        
        name = read_unicode(uc, pVals[1])
        handle = Handle(HandleType.Mutex, name = name)

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Mutex.dwFlags)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Mutex.dwDesiredAccess)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2,3])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenMutexA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['DWORD', 'BOOL', 'LPCSTR']
        pNames = ['dwDesiredAccess', 'bInheritHandle', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
                
        name = read_string(uc, pVals[2])

        handle = None
        for key, val in HandlesDict.items():
            if val.type == HandleType.Mutex:
                if val.name == name:
                    handle = val
                    break

        if handle is None: # Create New Mutex if Not Found
            handle = Handle(HandleType.Mutex, name = name)

        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.Mutex.dwDesiredAccess)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenMutexA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenMutexW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['DWORD', 'BOOL', 'LPCWSTR']
        pNames = ['dwDesiredAccess', 'bInheritHandle', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        name = read_unicode(uc, pVals[2])

        handle = None
        for key, val in HandlesDict.items():
            if val.type == HandleType.Mutex:
                if val.name == name:
                    handle = val
                    break

        if handle is None: # Create New Mutex if Not Found
            handle = Handle(HandleType.Mutex,data=name)

        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.Mutex.dwDesiredAccess)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenMutexW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ReleaseMutex(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL ReleaseMutex([in] HANDLE hMutex);
        pTypes = ['HANDLE']
        pNames = ['hMutex']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
 
        hMutex = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        # Remove Handle from HandlesDict
        if hMutex in HandlesDict:
            if HandlesDict[hMutex].type == HandleType.Mutex:
                HandlesDict.pop(hMutex)

       
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReleaseMutex", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreatePipe(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['PHANDLE', 'PHANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD']
        pNames = ['hReadPipe', 'hWritePipe', 'lpPipeAttributes', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Create Handles
        readHandle = Handle(HandleType.ReadPipe)
        writeHandle = Handle(HandleType.WritePipe)

        # Write Handles to memory
        try:
            uc.mem_write(pVals[0], pack('<I', readHandle.value))
            uc.mem_write(pVals[1], pack('<I', writeHandle.value))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreatePipe", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateNamedPipeA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES']
        pNames = ['lpName', 'dwOpenMode', 'dwPipeMode', 'nMaxInstances', 'nOutBufferSize', 'nInBufferSize',
                  'nDefaultTimeOut', 'lpSecurityAttributes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        name = read_string(uc, pVals[0])

        if pVals[1] == 1:
            pipeHandle = Handle(HandleType.ReadPipe, data=name)
        elif pVals[1] == 2:
            pipeHandle = Handle(HandleType.WritePipe, data=name)
        else:
            pipeHandle = Handle(HandleType.ReadWritePipe, data=name)

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.Pipe.dwOpenMode)
        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Pipe.dwPipeMode)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Pipe.nMaxInstances)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3])
        
        retVal = pipeHandle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateNamedPipeA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateNamedPipeW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES']
        pNames = ['lpName', 'dwOpenMode', 'dwPipeMode', 'nMaxInstances', 'nOutBufferSize', 'nInBufferSize',
                  'nDefaultTimeOut', 'lpSecurityAttributes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        name = read_unicode(uc, pVals[0])

        if pVals[1] == 1:
            pipeHandle = Handle(HandleType.ReadPipe, data=name)
        elif pVals[1] == 2:
            pipeHandle = Handle(HandleType.WritePipe, data=name)
        else:
            pipeHandle = Handle(HandleType.ReadWritePipe, data=name)

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.Pipe.dwOpenMode)
        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Pipe.dwPipeMode)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Pipe.nMaxInstances)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,2,3])
        
        retVal = pipeHandle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateNamedPipeW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MultiByteToWideChar(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['UINT', 'DWORD', 'LPCSTR', 'int', 'LPWSTR', 'int']
        pNames = ['CodePage', 'dwFlags', 'lpMultiByteStr', 'cbMultiByte', 'lpWideCharStr', 'cchWideChar']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            stringToConvert = read_string(uc, pVals[2])
            unicode = stringToConvert.encode('utf-16')[2:]
            if pVals[5] == 0:
                retVal = len(unicode) + 2
            else:
                uc.mem_write(pVals[4], pack(f'<{len(unicode)}s', unicode))
                retVal = len(unicode)
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("MultiByteToWideChar", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def WideCharToMultiByte(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['UINT', 'DWORD', 'LPCWSTR', 'int', 'LPSTR', 'int', 'LPCSTR', 'LPBOOL']
        pNames = ['CodePage', 'dwFlags', 'lpWideCharStr', 'cchWideChar', 'lpMultiByteStr', 'cbMultiByte',
                  'lpDefaultChar',
                  'lpUsedDefaultChar']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            stringToConvert = read_unicode(uc, pVals[2])
            ascii = stringToConvert.encode('ascii', errors="replace")  # Attempt to encode replace unknown with ?
            if pVals[5] == 0:
                retVal = len(ascii) + 1
            else:
                uc.mem_write(pVals[4], pack(f'<{len(ascii)}s', ascii))
                retVal = len(ascii)
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WideCharToMultiByte", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetComputerNameA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameA([out] LPSTR lpBuffer,[in, out] LPDWORD nSize);
        pTypes = ['LPSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        computerName = emuSimVals.computer_name.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[1], pack('<I', len(computerName)))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetComputerNameW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameW([out] LPWSTR lpBuffer,[in, out] LPDWORD nSize);
        pTypes = ['LPWSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        computerName = emuSimVals.computer_name.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[1], pack('<I', len(computerName)))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetComputerNameExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameExA([in] COMPUTER_NAME_FORMAT NameType,[out] LPSTR  lpBuffer,[in, out] LPDWORD nSize);
        pTypes = ['COMPUTER_NAME_FORMAT', 'LPSTR', 'LPDWORD']
        pNames = ['NameType', 'lpBuffer', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        nameTypeReverseLookup = {0: 'ComputerNameNetBIOS', 1: 'ComputerNameDnsHostname', 2: 'ComputerNameDnsDomain',
                                 3: 'ComputerNameDnsFullyQualified', 4: 'ComputerNamePhysicalNetBIOS',
                                 5: 'ComputerNamePhysicalDnsHostname', 6: 'ComputerNamePhysicalDnsDomain',
                                 7: 'ComputerNamePhysicalDnsFullyQualified', 8: 'ComputerNameMax'}
        # Possibly Implement Different Formats
        pVals[0] = getLookUpVal(pVals[0], nameTypeReverseLookup)

        computerName = emuSimVals.computer_name.encode('ascii')
        uc.mem_write(pVals[1], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[2], pack('<I', len(computerName)))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetComputerNameExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameExW([in] COMPUTER_NAME_FORMAT NameType,[out] LPWSTR  lpBuffer,[in, out] LPDWORD nSize);
        pTypes = ['COMPUTER_NAME_FORMAT', 'LPWSTR', 'LPDWORD']
        pNames = ['NameType', 'lpBuffer', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        nameTypeReverseLookup = {0: 'ComputerNameNetBIOS', 1: 'ComputerNameDnsHostname', 2: 'ComputerNameDnsDomain',
                                 3: 'ComputerNameDnsFullyQualified', 4: 'ComputerNamePhysicalNetBIOS',
                                 5: 'ComputerNamePhysicalDnsHostname', 6: 'ComputerNamePhysicalDnsDomain',
                                 7: 'ComputerNamePhysicalDnsFullyQualified', 8: 'ComputerNameMax'}
        # Possibly Implement Different Formats
        pVals[0] = getLookUpVal(pVals[0], nameTypeReverseLookup)

        computerName = emuSimVals.computer_name.encode('utf-16')[2:]
        uc.mem_write(pVals[1], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[2], pack('<I', len(computerName)))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def gethostname(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # int gethostname([out] char *name,[in]  int  namelen);
        pTypes = ['char', 'int']
        pNames = ['*name', 'namelen']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        computerName = emuSimVals.computer_name.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(computerName) + 2}s', computerName))

        pVals[0] = read_string(uc, pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("gethostname", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetWindowsDirectoryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetWindowsDirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);
        pTypes = ['LPSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\Windows'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetWindowsDirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetWindowsDirectoryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetWindowsDirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);
        pTypes = ['LPWSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\Windows'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetWindowsDirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemWindowsDirectoryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWindowsDirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);
        pTypes = ['LPSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\Windows'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWindowsDirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemWindowsDirectoryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWindowsDirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);
        pTypes = ['LPWSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\Windows'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWindowsDirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetTempPathA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # DWORD GetTempPathA([in]  DWORD nBufferLength,[out] LPSTR lpBuffer);
        pTypes = ['DWORD', 'LPSTR', ]
        pNames = ['nBufferLength', 'lpBuffer', ]
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\TEMP\\'.encode('ascii')
        uc.mem_write(pVals[1], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempPathA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetTempPathW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # DWORD GetTempPathW([in]  DWORD nBufferLength,[out] LPWSTR lpBuffer);
        pTypes = ['DWORD', 'LPWSTR', ]
        pNames = ['nBufferLength', 'lpBuffer', ]
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\TEMP\\'.encode('utf-16')[2:]
        uc.mem_write(pVals[1], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempPathW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetTempFileNameA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetTempFileNameA([in]  LPCSTR lpPathName,[in]  LPCSTR lpPrefixString,[in]  UINT   uUnique,[out] LPSTR  lpTempFileName);
        pTypes = ['LPCSTR', 'LPCSTR', 'UINT', 'LPSTR']
        pNames = ['lpPathName', 'lpPrefixString', 'uUnique', 'lpTempFileName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        tempPath = read_string(uc, pVals[0])
        preFix = read_string(uc, pVals[1])

        if pVals[2] == 0x0:
            retVal = randint(0x0, 0xffff)
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{value}.TMP'
        else:
            retVal = pVals[2]
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{value}.TMP'

        pathEncoded = path.encode('ascii')
        uc.mem_write(pVals[3], pack(f'<{len(pathEncoded)}s', pathEncoded))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempFileNameA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetTempFileNameW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetTempFileNameW([in]  LPCWSTR lpPathName,[in]  LPCWSTR lpPrefixString,[in]  UINT   uUnique,[out] LPWSTR  lpTempFileName);
        pTypes = ['LPCWSTR', 'LPCWSTR', 'UINT', 'LPWSTR']
        pNames = ['lpPathName', 'lpPrefixString', 'uUnique', 'lpTempFileName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        tempPath = read_unicode(uc, pVals[0])
        preFix = read_unicode(uc, pVals[1])

        if pVals[2] == 0x0:
            retVal = randint(0x0, 0xffff)
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{value}.TMP'
        else:
            retVal = pVals[2]
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}{emuSimVals.temp_file_prefix}{value}.TMP'

        pathEncoded = path.encode('utf-16')[2:]

        uc.mem_write(pVals[3], pack(f'<{len(pathEncoded) + 2}s', pathEncoded))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempFileNameW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemWow64DirectoryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWow64DirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);
        pTypes = ['LPSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\Windows\SysWOW64'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWow64DirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemWow64DirectoryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWow64DirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);
        pTypes = ['LPWSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        path = 'C:\Windows\SysWOW64'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWow64DirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemTime(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # void GetSystemTime([out] LPSYSTEMTIME lpSystemTime);
        pTypes = ['LPSYSTEMTIME']
        pNames = ['lpSystemTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        if pVals[0] != 0x0:
            timeVal = get_SYSTEMTIME(uc, pVals[0], em)
            timeVal.setTime(True,emuSimVals.system_time_since_epoch)
            timeVal.writeToMemory(uc, pVals[0])

        pVals[0] = makeStructVals(uc, timeVal, pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal= 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemTime", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetLocalTime(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # void GetLocalTime([out] LPSYSTEMTIME lpSystemTime);
        pTypes = ['LPSYSTEMTIME']
        pNames = ['lpSystemTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if pVals[0] != 0x0:
            timeVal = get_SYSTEMTIME(uc, pVals[0], em)
            timeVal.setTime(False, emuSimVals.system_time_since_epoch)
            timeVal.writeToMemory(uc, pVals[0])

        pVals[0] = makeStructVals(uc, timeVal, pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal= 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetLocalTime", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def timeGetTime(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = emuSimVals.system_uptime_minutes * 60 * 1000
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("timeGetTime", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))
    
    def GetTickCount(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = emuSimVals.system_uptime_minutes * 60 * 1000
        if retVal > int(49.7 * 24 * 60 * 60 * 1000): # Max Value aprox 49.7 days
            retVal = int(49.7 * 24 * 60 * 60 * 1000)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTickCount", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetTickCount64(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = emuSimVals.system_uptime_minutes * 60 * 1000
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTickCount64", hex(callAddr), (retValStr), 'ULONGLONG', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def QueryPerformanceCounter(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LARGE_INTEGER *']
        pNames = ['lpPerformanceCount']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            pc = perf_counter_ns()
            li = LARGE_INTEGER(QuadPart=pc)
            li.writeToMemory(uc,pVals[0])
        except:
            pass

        pVals[0] = makeStructVals(uc,li,pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("QueryPerformanceCounter", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetUserNameA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetUserNameA([out] LPSTR lpBuffer,[in, out] LPDWORD pcbBuffer);
        pTypes = ['LPSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'pcbBuffer']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        username = emuSimVals.user_name.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[1], pack('<I', len(username)))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetUserNameW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetUserNameW([out] LPWSTR lpBuffer,[in, out] LPDWORD pcbBuffer);
        pTypes = ['LPWSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'pcbBuffer']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        username = emuSimVals.user_name.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[1], pack('<I', len(username)))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetUserNameExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOLEAN SEC_ENTRY GetUserNameExA([in] EXTENDED_NAME_FORMAT NameFormat,[out] LPSTR lpNameBuffer,[in, out] PULONG nSize);
        pTypes = ['EXTENDED_NAME_FORMAT', 'LPSTR', 'LPDWORD']
        pNames = ['NameFormat', 'lpBuffer', 'pcbBuffer']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        nameFormatReverseLookup = {0: 'NameUnknown', 1: 'NameFullyQualifiedDN', 2: 'NameSamCompatible',
                                   3: 'NameDisplay',
                                   6: 'NameUniqueId', 7: 'NameCanonical', 8: 'NameUserPrincipal', 9: 'NameCanonicalEx',
                                   10: 'NameServicePrincipal', 12: 'NameDnsDomain', 13: 'NameGivenName',
                                   14: 'NameSurname'}
        # Possibly Implement Different Formats
        username = emuSimVals.user_name.encode('ascii')
        uc.mem_write(pVals[1], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[2], pack('<I', len(username)))

        pVals[0] = getLookUpVal(pVals[0], nameFormatReverseLookup)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetUserNameExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOLEAN SEC_ENTRY GetUserNameExW([in] EXTENDED_NAME_FORMAT NameFormat,[out] LPWSTR lpNameBuffer,[in, out] PULONG nSize);
        pTypes = ['EXTENDED_NAME_FORMAT', 'LPWSTR', 'LPDWORD']
        pNames = ['NameFormat', 'lpBuffer', 'pcbBuffer']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        nameFormatReverseLookup = {0: 'NameUnknown', 1: 'NameFullyQualifiedDN', 2: 'NameSamCompatible',
                                   3: 'NameDisplay',
                                   6: 'NameUniqueId', 7: 'NameCanonical', 8: 'NameUserPrincipal', 9: 'NameCanonicalEx',
                                   10: 'NameServicePrincipal', 12: 'NameDnsDomain', 13: 'NameGivenName',
                                   14: 'NameSurname'}
        # Possibly Implement Different Formats
        username = emuSimVals.user_name.encode('utf-16')[2:]
        uc.mem_write(pVals[1], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[2], pack('<I', len(username)))

        pVals[0] = getLookUpVal(pVals[0], nameFormatReverseLookup)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def TerminateProcess(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'TerminateProcess': (2, ['HANDLE', 'UINT'], ['hProcess', 'uExitCode'], 'BOOL')
        pTypes = ['HANDLE', 'UINT']
        pNames = ['hProcess', 'uExitCode']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.ErrorCodes)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("TerminateProcess", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def Sleep(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'Sleep': (1, ['DWORD'], ['dwMilliseconds'], 'thunk void')
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['DWORD']
        pNames = ['dwMilliseconds']

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("Sleep", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetForegroundWindow(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.HWND, name='ForegroundWindow')

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetForegroundWindow", hex(callAddr), (retValStr), 'HWND', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))
    
    def GetDesktopWindow(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.HWND, name='DesktopWindow')

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetDesktopWindow", hex(callAddr), (retValStr), 'HWND', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def CloseHandle(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # BOOL CloseHandle( [in] HANDLE hObject);
        pTypes = ['HANDLE']
        pNames = ['hObject']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        if handle in HandlesDict:
            HandlesDict.pop(handle)

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CloseHandle", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetFileSizeEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'PLARGE_INTEGER']
        pNames = ['hFile', 'lpFileSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        randomPacking = 0xffffffff # For the try/pass uc.mem_write, uses a random value

        try:
            # uc.mem_write(pVals[1], pack(f'<{len(memory)}s', memory))
            uc.mem_write(pVals[1], pack('<Q', randomPacking))
        except:
            pass

        # expand write file size to pVals[1]
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetFileSizeEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetFileSize(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'LPDWORD']
        pNames = ['hFile', 'lpFileSizeHigh']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        # expand write file size to pVals[1]
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetFileSize", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    ### Has a structure of OSVERSIONINFOA, need help with.
    def GetVersionExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'GetVersionExA': (1, ['LPOSVERSIONINFOA'], ['lpVersionInformation'], 'BOOL')
        pTypes = ['LPOSVERSIONINFOA']
        pNames = ['lpVersionInformation']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetVersionExA", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetErrorMode(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'SetErrorMode': (1, ['UINT'], ['uMode'], 'UINT'),
        pTypes = ['UINT']
        pNames = ['uMode']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        SetErrorModeFormatReverseLookup = {0: '', 1: 'SEM_FAILCRITICALERRORS', 4: 'SEM_NOALIGNMENTFAULTEXCEPT',
                                           2: 'SEM_NOGPFAULTERRORBOX', 32768: 'SEM_NOOPENFILEERRORBOX'}
        pVals[0] = getLookUpVal(pVals[0], SetErrorModeFormatReverseLookup)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])        

        retVal = 0x0  # returns a the previous state of the error-mode bit flags
        retValStr = ''
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetErrorMode", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetEndOfFile(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'GetVersionExA': (1, ['LPOSVERSIONINFOA'], ['lpVersionInformation'], 'BOOL')
        pTypes = ['HANDLE']
        pNames = ['hFile']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetEndOfFile", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ResetEvent(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'GetVersionExA': (1, ['LPOSVERSIONINFOA'], ['lpVersionInformation'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes = ['HANDLE']
        pNames = ['hEvent']

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ResetEvent", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def WaitForSingleObjectEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'WaitForSingleObjectEx': (3, ['HANDLE', 'DWORD', 'BOOL'], ['hHandle', 'dwMilliseconds', 'bAlertable'], 'thunk DWORD')
        pTypes = ['HANDLE', 'DWORD', 'BOOL']
        pNames = ['hHandle', 'dwMilliseconds', 'bAlertable']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x00000000
        retValStr = 'WAIT_OBJECT_0'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("WaitForSingleObjectEx", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetModuleHandleA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCSTR'] 
        pNames = ['lpModuleName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Expand Possibly Make Function Similary to Load Library Research First

        name = read_string(uc, pVals[0])

        try:
            foundVal = allDllsDict[name]
            handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
            retVal = handle.value
        except:
            try:
                nameL = name.lower() + '.dll'
                foundVal = allDllsDict[nameL]
                handle = Handle(HandleType.HMODULE,data=name,handleValue=foundVal)
                retVal = handle.value
            except:
                print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                retVal = 0

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
       
        logged_calls= ("GetModuleHandleA", hex(callAddr), (retValStr), 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetModuleHandleW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # GetModuleHandleW': (1, ['LPCWSTR'], ['lpModuleName'], 'HMODULE'),
        pTypes = ['LPCWSTR']
        pNames = ['lpModuleName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Expand Possibly Make Function Similary to Load Library Research First
        name = read_string(uc, pVals[0])

        try:
            foundVal = allDllsDict[name]
            handle = Handle(HandleType.HMODULE,name=name,handleValue=foundVal)
            retVal = handle.value
        except:
            try:
                nameL = name.lower() + '.dll'
                foundVal = allDllsDict[nameL]
                handle = Handle(HandleType.HMODULE,data=name,handleValue=foundVal)
                retVal = handle.value
            except:
                print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                retVal = 0

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetModuleHandleW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetModuleFileNameA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HMODULE', 'LPSTR', 'DWORD']
        pNames = ['hModule', 'lpFilename', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Expand to Return filename in pVals[1]

        #string1 = read_string(uc, pVals[1])
        #try:
            #uc.mem_write(pVals[0], pack(f'<{pVals[2]}s', string1.encode("ascii")))
        #except:
            #pass

        #retVal = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetModuleFileNameA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetModuleFileNameExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'HMODULE', 'LPSTR', 'DWORD']
        pNames = ['hProcess', 'hModule', 'lpFilename', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Expand to Return filename in pVals[2]

        #string1 = read_string(uc, pVals[1])
        #try:
            #uc.mem_write(pVals[0], pack(f'<{pVals[2]}s', string1.encode("ascii")))
        #except:
            #pass

        #retVal = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetModuleFileNameExA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SleepEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['DWORD', 'BOOL']
        pNames = ['dwMilliseconds', 'bAlertable']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0x0
        retValStr = "SUCCESS - Specified Time Interval Expired"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SleepEx", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def TlsFree(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # ''TlsFree': (1, ['DWORD'], ['dwTlsIndex'], 'BOOL')
        pTypes = ['DWORD']
        pNames = ['dwTlsIndex']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("TlsFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FlsFree(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # ''TlsFree': (1, ['DWORD'], ['dwTlsIndex'], 'BOOL')
        pTypes = ['DWORD']
        pNames = ['dwFlsIndex']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("FlsFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GlobalFree(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'GlobalFree': (1, ['HGLOBAL'], ['hMem'], 'HGLOBAL')
        pTypes = ['HGLOBAL']
        pNames = ['hMem']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        retValStr = 'NULL'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("GlobalFree", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LocalFree(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # ''LocalFree': (1, ['HLOCAL'], ['hMem'], 'HLOCAL')
        pTypes = ['HLOCAL']
        pNames = ['hMem']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        retValStr = 'NULL'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("LocalFree", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FlushFileBuffers(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'FlushFileBuffers': (1, ['HANDLE'], ['hFile'], 'BOOL')
        pTypes = ['HANDLE']
        pNames = ['hFile']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FlushFileBuffers", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def IsDebuggerPresent(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        retValStr = 'False'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("IsDebuggerPresent", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CheckRemoteDebuggerPresent(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'PBOOL']
        pNames = ['hProcess', 'pbDebuggerPresent']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            uc.mem_write(pVals[1], pack('<?',0))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CheckRemoteDebuggerPresent", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetClipboardData(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['UINT', 'HANDLE'] 
        pNames = ['uFormat', 'hMem'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        # ClipBoard = auto() handle type at top
        
        FormatReverseLookUp = {2: 'CF_BITMAP', 8: 'CF_DIB', 17: 'CF_DIBV5', 5: 'CF_DIF', 130: 'CF_DSPBITMAP', 142: 'CF_DSPENHMETAFILE', 131: 'CF_DSPMETAFILEPICT', 129: 'CF_DSPTEXT', 14: 'CF_ENHMETAFILE', 768: 'CF_GDIOBJFIRST', 1023: 'CF_GDIOBJLAST', 15: 'CF_HDROP', 16: 'CF_LOCALE', 3: 'CF_METAFILEPICT', 7: 'CF_OEMTEXT', 128: 'CF_OWNERDISPLAY', 9: 'CF_PALETTE', 10: 'CF_PENDATA', 512: 'CF_PRIVATEFIRST', 767: 'CF_PRIVATELAST', 11: 'CF_RIFF', 4: 'CF_SYLK', 1: 'CF_TEXT', 6: 'CF_TIFF', 13: 'CF_UNICODETEXT', 12: 'CF_WAVE'}


        pVals[0] = getLookUpVal(pVals[0], FormatReverseLookUp)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip = [0])

        fakeData = emuSimVals.clipboard_data # Might Need Changed

        handle = Handle(HandleType.ClipBoard,data=fakeData)

        retVal =  handle.value # if success, return val is handle to data
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
    
        logged_calls= ("SetClipboardData", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetClipboardData(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['UINT'] 
        pNames = ['uFormat'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        # ClipBoard = auto() handle type at top
        FormatReverseLookUp = {2: 'CF_BITMAP', 8: 'CF_DIB', 17: 'CF_DIBV5', 5: 'CF_DIF', 130: 'CF_DSPBITMAP', 142: 'CF_DSPENHMETAFILE', 131: 'CF_DSPMETAFILEPICT', 129: 'CF_DSPTEXT', 14: 'CF_ENHMETAFILE', 768: 'CF_GDIOBJFIRST', 1023: 'CF_GDIOBJLAST', 15: 'CF_HDROP', 16: 'CF_LOCALE', 3: 'CF_METAFILEPICT', 7: 'CF_OEMTEXT', 128: 'CF_OWNERDISPLAY', 9: 'CF_PALETTE', 10: 'CF_PENDATA', 512: 'CF_PRIVATEFIRST', 767: 'CF_PRIVATELAST', 11: 'CF_RIFF', 4: 'CF_SYLK', 1: 'CF_TEXT', 6: 'CF_TIFF', 13: 'CF_UNICODETEXT', 12: 'CF_WAVE'}

        pVals[0] = getLookUpVal(pVals[0], FormatReverseLookUp)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])
        
        fakeData = emuSimVals.clipboard_data

        handle = Handle(HandleType.ClipBoard,data=fakeData)

        retVal =  handle.value 
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
    
        logged_calls= ("GetClipboardData", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateFile2(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'LPSCREATEFILE2_EXTENDED_PARAMETERS'] 
        pNames = ['lpFileName', 'dwDesiredAccess', 'dwShareMode', 'dwCreationDistribution', 'pCreateExParams'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        fileName = read_unicode(uc, pVals[0])
        handle = Handle(HandleType.CreateFile2, name=fileName)

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.File.DesiredAccess)
        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.File.ShareMode)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.File.CreationDistribution)
        pVals[4] = getLookUpVal(pVals[4], ReverseLookUps.File.FlagsAndAttribute)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip = [1, 2, 3, 4])

        retVal =  handle.value 
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
    
        logged_calls= ("CreateFile2", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcatA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPSTR', 'LPCSTR'] 
        pNames = ['lpString1', 'lpString2'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        str1 = read_string(uc, pVals[0])
        str2 = read_string(uc, pVals[1])

        try:
            finalStr = str1 + str2
            uc.mem_write(pVals[0],pack(f'<{len(finalStr)+1}s', finalStr.encode('ascii')))
        except:
            pass

        retVal = pVals[0]

        pVals[0] = str1
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcatA", hex(callAddr), (retValStr), 'LPSTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcatW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPWSTR', 'LPCWSTR'] 
        pNames = ['lpString1', 'lpString2'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        str1 = read_unicode(uc, pVals[0])
        str2 = read_unicode(uc, pVals[1])

        try:
            finalStr = str1 + str2
            uc.mem_write(pVals[0],pack(f'<{(len(finalStr)*2)+2}s', finalStr.encode('utf-16')))
        except:
            pass

        retVal = pVals[0]

        pVals[0] = str1
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcatW", hex(callAddr), (retValStr), 'LPWSTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcpynA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPSTR', 'LPCSTR', 'int'] 
        pNames = ['lpString1', 'lpString2', 'iMaxLength'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        string2 = read_string(uc, pVals[1])
        try:
            uc.mem_write(pVals[0], pack(f'<{pVals[2]}s', string2.encode("ascii")))
        except:
            pass

        retVal = pVals[0]

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcpynA", hex(callAddr), (retValStr), 'LPSTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcpynW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPWSTR', 'LPCWSTR', 'int'] 
        pNames = ['lpString1', 'lpString2', 'iMaxLength'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        string2 = read_unicode(uc, pVals[1])
        try:
            uc.mem_write(pVals[0], pack(f'<{pVals[2]*2}s', string2.encode("utf-16")[2:]))
        except:
            pass

        retVal = pVals[0]

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcpynW", hex(callAddr), (retValStr), 'LPWSTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcpyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPSTR', 'LPCSTR'] 
        pNames = ['lpString1', 'lpString2'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        
        string2 = read_string(uc, pVals[1])
        try:
            uc.mem_write(pVals[0], pack(f'<{len(string2)+1}s', string2.encode("ascii")))
        except:
            pass

        retVal = pVals[0]

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcpyA", hex(callAddr), (retValStr), 'LPSTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcpyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPWSTR', 'LPCWSTR'] 
        pNames = ['lpString1', 'lpString2'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        string2 = read_unicode(uc, pVals[1])
        try:
            uc.mem_write(pVals[0], pack(f'<{len(string2)*2+2}s', string2.encode("utf-16")[2:]))
        except:
            pass

        retVal = pVals[0]

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcpyW", hex(callAddr), (retValStr), 'LPWSTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrlenA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCSTR'] 
        pNames = ['lpString'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        if pVals[0] != '[NULL]':
            retVal = len(pVals[0])
        else:
            retVal = 0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrlenA", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrlenW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR'] 
        pNames = ['lpString'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        if pVals[0] != '[NULL]':
            retVal = len(pVals[0])
        else:
            retVal = 0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrlenW", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcmpA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'LPCSTR']
        pNames = ['lpString1', 'lpString2']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        string1 = read_string(uc, pVals[0])
        string2 = read_string(uc, pVals[1])
        if string1 == string2:  # Check if Same
            retVal = 0
        elif len(string1) <= len(string2):
            for i in range(len(string1)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break
        else:
            for i in range(len(string2)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("lstrcmpA", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcmpW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPCWSTR']
        pNames = ['lpString1', 'lpString2']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        string1 = read_unicode(uc, pVals[0])
        string2 = read_unicode(uc, pVals[1])
        if string1 == string2:  # Check if Same
            retVal = 0
        elif len(string1) <= len(string2):
            for i in range(len(string1)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break
        else:
            for i in range(len(string2)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("lstrcmpW", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcmpiA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCSTR', 'LPCSTR']
        pNames = ['lpString1', 'lpString2']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        string1 = read_string(uc, pVals[0]).lower()
        string2 = read_string(uc, pVals[1]).lower()
        if string1 == string2:  # Check if Same
            retVal = 0
        elif len(string1) <= len(string2):
            for i in range(len(string1)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break
        else:
            for i in range(len(string2)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("lstrcmpiA", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def lstrcmpiW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPCWSTR', 'LPCWSTR']
        pNames = ['lpString1', 'lpString2']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        string1 = read_unicode(uc, pVals[0]).lower()
        string2 = read_unicode(uc, pVals[1]).lower()
        if string1 == string2:  # Check if Same
            retVal = 0
        elif len(string1) <= len(string2):
            for i in range(len(string1)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break
        else:
            for i in range(len(string2)):  # Check Char by Char
                # print('Index:', i, 'S1:', string1[i], 'S2:', string2[i])
                if ord(string1[i]) < ord(string2[i]):
                    retVal = -1
                    break
                elif ord(string1[i]) > ord(string2[i]):
                    retVal = 1
                    break

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("lstrcmpiW", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MulDiv(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['int', 'int', 'int'] 
        pNames = ['nNumber', 'nNumerator', 'nDenominator'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            retVal = (pVals[0] * pVals[1]) // pVals[2]
            if retVal > 2147483647 or retVal < -2147483647: 
                # Max/Min Int Overflow
                retVal = -1
        except:
            retVal = -1

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("MulDiv", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CopyFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR', 'LPCWSTR', 'BOOL'] 
        pNames = ['lpExistingFileName', 'lpNewFileName', 'bFailIfExists'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CopyFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CopyFile2(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['PCWSTR', 'PCWSTR', 'COPYFILE2_EXTENDED_PARAMETERS'] 
        pNames = ['pwszExistingFileName', 'pwszNewFileName', '*pExtendedParameters'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        CopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK',
                                     1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING',
                                     4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE',
                                     268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

        pVals[2] = getLookUpVal(pVals[2], CopyFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retVal = 0x1
        retValStr = "S_OK"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CopyFile2", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def DeleteFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR'] 
        pNames = ['lpFileName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("DeleteFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def DeleteFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCSTR'] 
        pNames = ['lpFilename'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("DeleteFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetFileTime(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'FILETIME', 'FILETIME', 'FILETIME'] 
        pNames = ['hFile', '*lpCreationTime', '*lpLastAccessTime', '*lpLastWriteTime'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        creationTime = get_FILETIME(uc, pVals[1], em)
        accessTime = get_FILETIME(uc, pVals[2], em)
        writeTime = get_FILETIME(uc, pVals[3], em)

        pVals[1] = makeStructVals(uc, creationTime, pVals[1])
        pVals[2] = makeStructVals(uc, accessTime, pVals[2])
        pVals[3] = makeStructVals(uc, writeTime, pVals[3])

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip = [1,2,3])

        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SetFileTime", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetTimeZoneInformation(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPTIME_ZONE_INFORMATION'] 
        pNames = ['lpTimeZoneInformation'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        timeZone = get_TIME_ZONE_INFORMATION(uc, pVals[0], em)
        timeZone.DaylightName = 'ABCDEFGHIJKLMNOQRSTUVWXYZ01234'
        timeZone.StandardName = 'TestStandard'
        timeZone.DaylightDate.setTime(False, emuSimVals.system_time_since_epoch)
        timeZone.StandardDate.setTime(False, emuSimVals.system_time_since_epoch)
        timeZone.writeToMemory(uc, pVals[0])
        pVals[0] = makeStructVals(uc, timeZone, pVals[0])

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])
        
        retVal = 0x1
        retValStr = "TIME_ZONE_ID_STANDARD"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetTimeZoneInformation", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetStartupInfoW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPSTARTUPINFOW'] 
        pNames = ['lpStartupInfo'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        startupinfo = get_STARTUPINFOW(uc, pVals[0], em)
        uc.mem_write(startupinfo.lpDesktop, pack(f'<{len(emuSimVals.computer_name)*2+2}s',emuSimVals.computer_name.encode('utf-16')[2:]))
        startupinfo.writeToMemory(uc, pVals[0])
        pVals[0] = makeStructVals(uc, startupinfo, pVals[0])

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])
        
        retVal = 0x1
        retValStr = "STARTUPINFO"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetStartupInfoW", hex(callAddr), (retValStr), 'VOID', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegisterHotKey(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND', 'int', 'UINT', 'UINT'] 
        pNames = ['hWnd', 'id', 'fsModifiers', 'vk'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        fsModifiers_ReverseLookUp = {1: 'MOD_ALT', 2: 'MOD_CONTROL', 16384: 'MOD_NOREPEAT', 4: 'MOD_SHIFT', 8: 'MOD_WIN'}

        pVals[2] = getLookUpVal(pVals[2], fsModifiers_ReverseLookUp)
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[2])
        
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("RegisterHotKey", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenClipboard(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND'] 
        pNames = ['hWndNewOwner'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("OpenClipboard", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SendMessage(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND', 'UINT', 'WPARAM', 'LPARAM'] 
        pNames = ['hWnd', 'Msg', 'wParam', 'lParam'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.SendMessageA)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SendMessage", hex(callAddr), (retValStr), 'LRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SendMessageCallbackA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND', 'UINT', 'WPARAM', 'LPARAM', 'SENDASYNCPROC', 'ULONG_PTR'] 
        pNames = ['hWnd', 'Msg', 'wParam', 'lParam', 'lpResultCallBack', 'dwData'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.SendMessageA)
        try:
            uc.mem_write(pVals[0], pack('<I',handle.value))
        except:
            pass

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SendMessageCallbackA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SendMessageTimeoutA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND', 'UINT', 'WPARAM', 'LPARAM', 'UINT', 'UINT', 'PDWORD_PTR'] 
        pNames = ['hWnd', 'Msg', 'wParam', 'lParam', 'fuFlags', 'uTimeout', 'lpdwResult'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        fuFlags_ReverseLookUp = {2: 'SMTO_ABORTIFHUNG', 1: 'SMTO_BLOCK', 0: 'SMTO_NORMAL', 8: 'SMTO_NOTIMEOUTIFNOTHUNG', 32: 'SMTO_ERRORONEXIT'}

        #handle = Handle(HandleType.SendMessageA)
        handle = Handle(HandleType.HWND, name='DesktopWindow')
        try:
            uc.mem_write(pVals[0], pack('<I',handle.value))
        except:
            pass

        pVals[4] = getLookUpVal(pVals[4], fuFlags_ReverseLookUp)
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[4])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SendMessageTimeoutA", hex(callAddr), (retValStr), 'LRESULT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SendNotifyMessageA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND', 'UINT', 'WPARAM', 'LPARAM'] 
        pNames = ['hWnd', 'Msg', 'wParam', 'lParam'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.SendMessageA)
        try:
            uc.mem_write(pVals[0], pack('<I',handle.value))
        except:
            pass

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SendNotifyMessageA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def EnumDeviceDrivers(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPVOID', 'DWORD', 'LPDWORD'] 
        pNames = ['*lpImageBase', 'cb', 'lpcbNeeded'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("EnumDeviceDrivers", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def EnumProcesses(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['DWORD', 'DWORD', 'LPDWORD'] 
        pNames = ['*lpidProcess', 'cb', 'lpcbNeeded'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("EnumProcesses", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def EnumProcessModules(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'HMODULE', 'DWORD', 'LPDWORD'] 
        pNames = ['hProcess', '*lphModule', 'cb', 'lpcbNeeded'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("EnumProcessModules", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def EnumProcessModulesEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'HMODULE', 'DWORD', 'LPDWORD', 'DWORD'] 
        pNames = ['hProcess', '*lphModule', 'cb', 'lpcbNeeded', 'dwFilterFlag'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFilterFlag_ReverseLookUp = {1: 'LIST_MODULES_32BIT', 2: 'LIST_MODULES_64BIT', 3: 'LIST_MODULES_ALL', 0: 'LIST_MODULES_DEFAULT'}

        pVals[4] = getLookUpVal(pVals[4], dwFilterFlag_ReverseLookUp)
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[4])
        
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("EnumProcessModulesEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def IsProcessorFeaturePresent(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['DWORD'] 
        pNames = ['ProcessorFeature'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        ProcessorFeature_ReverseLookUp = {25: 'PF_ARM_64BIT_LOADSTORE_ATOMIC', 24: 'PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE', 26: 'PF_ARM_EXTERNAL_CACHE_AVAILABLE', 27: 'PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE', 18: 'PF_ARM_VFP_32_REGISTERS_AVAILABLE', 7: 'PF_3DNOW_INSTRUCTIONS_AVAILABLE', 16: 'PF_CHANNELS_ENABLED', 2:
 'PF_COMPARE_EXCHANGE_DOUBLE', 14: 'PF_COMPARE_EXCHANGE128', 15: 'PF_COMPARE64_EXCHANGE128', 23: 'PF_FASTFAIL_AVAILABLE', 1: 'PF_FLOATING_POINT_EMULATED', 0: 'PF_FLOATING_POINT_PRECISION_ERRATA', 3: 'PF_MMX_INSTRUCTIONS_AVAILABLE', 12: 'PF_NX_ENABLED', 9: 'PF_PAE_ENABLED', 8: 'PF_RDTSC_INSTRUCTION_AVAILABLE', 22: 'PF_RDWRFSGSBASE_AVAILABLE', 20: 'PF_SECOND_LEVEL_ADDRESS_TRANSLATION', 13: 'PF_SSE3_INSTRUCTIONS_AVAILABLE', 21: 'PF_VIRT_FIRMWARE_ENABLED', 6: 'PF_XMMI_INSTRUCTIONS_AVAILABLE', 10: 'PF_XMMI64_INSTRUCTIONS_AVAILABLE', 17: 'PF_XSAVE_ENABLED', 29: 'PF_ARM_V8_INSTRUCTIONS_AVAILABLE', 30: 'PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE', 31: 'PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE', 34: 'PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE'}

        pVals[0] = getLookUpVal(pVals[0], ProcessorFeature_ReverseLookUp)
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])
        
        retVal = 0x1
        retValStr = "SUPPORTED"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("IsProcessorFeaturePresent", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetFileAttributesW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['LPCWSTR']
        pNames= ['lpFileName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x88888888
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetFileAttributesW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def EnumDesktopWindows(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HDESK', 'WNDENUMPROC', 'LPARAM']
        pNames= ['hDesktop', 'lpfn', 'lParam']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("EnumDesktopWindows", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def EnumWindows(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['WNDENUMPROC', 'LPARAM']
        pNames= ['lpEnumFunc', 'lParam']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("EnumWindows", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetPropA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HWND', 'LPCSTR', 'HANDLE']
        pNames= ['hWnd', 'lpString', 'hData']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetPropA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptEncrypt(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HCRYPTKEY', 'HCRYPTHASH', 'BOOL', 'DWORD', 'BYTE', 'DWORD', 'DWORD']
        pNames= ['hKey', 'hHash', 'Final', 'dwFlags', '*pbData', '*pdwDataLen', 'dwBufLen']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CryptEncrypt", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptCreateHash(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HCRYPTPROV', 'ALG_ID', 'HCRYPTKEY', 'DWORD', 'HCRYPTHASH']
        pNames= ['hProv', 'Algid', 'hKey', 'dwFlags', '*phHash']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CryptCreateHash", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptHashData(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HCRYPTPROV', 'BYTE', 'DWORD', 'DWORD']
        pNames= ['hHash', '*pbData', 'dwDataLen', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CryptHashData", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptDeriveKey(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HCRYPTPROV', 'ALG_ID', 'HCRYPTHASH', 'DWORD', 'HCRYPTKEY']
        pNames= ['hProv', 'Algid', 'hBaseData', 'dwFlags', '*phKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CryptDeriveKey", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptGetHashParam(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HCRYPTHASH', 'DWORD', 'BYTE', 'DWORD', 'DWORD']
        pNames= ['hHash', 'dwParam', '*pbData', '*pdwDataLen', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CryptGetHashParam", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptSetKeyParam(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HCRYPTKEY', 'DWORD', 'BYTE', 'DWORD']
        pNames= ['hKey', 'dwParam', '*pbData', 'dwFlags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CryptSetKeyParam", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptDestroyKey(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HCRYPTKEY']
        pNames= ['hKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CryptDestroyKey", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FindFirstUrlCacheEntryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['LPCSTR', 'LPINTERNET_CACHE_ENTRY_INFOA', 'LPDWORD']
        pNames= ['lpszUrlSearchPattern', 'lpFirstCacheEntryInfo', 'lpcbCacheEntryInfo']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("FindFirstUrlCacheEntryA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def DuplicateToken(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['HANDLE', 'SECURITY_IMPERSONATION_LEVEL', 'PHANDLE']
        pNames= ['ExistingTokenHandle', 'ImpersonationLevel', 'DuplicateTokenHandle']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.DuplicateToken)

        try:
            uc.mem_write(pVals[2], pack('<I',handle.value))
        except:
            pass

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("DuplicateToken", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def WaitForMultipleObjects(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['DWORD', 'HANDLE', 'BOOL', 'DWORD']
        pNames= ['nCount', '*lpHandles', 'bWaitAll', 'dwMilliseconds']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("WaitForMultipleObjects", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def WaitForMultipleObjectsEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['DWORD', 'HANDLE', 'BOOL', 'DWORD', 'BOOL']
        pNames= ['nCount', '*lpHandles', 'bWaitAll', 'dwMilliseconds', 'bAlertable']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr= 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("WaitForMultipleObjectsEx", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetCurrentThreadId(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =[] 
        pNames = [] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 2000
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetCurrentThreadID", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetThreadId(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE'] 
        pNames = ['Thread'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetThreadID", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetProcessId(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE'] 
        pNames = ['Process'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x55555555
        retValStr = 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetProcessID", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetProcessIdOfThread(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE'] 
        pNames = ['Thread'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetProcessIdOfThread", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetThreadInformation(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'THREAD_INFORMATION_CLASS', 'LPVOID', 'DWORD'] 
        pNames = ['hThread', 'ThreadInformationClass', 'ThreadInformation', 'ThreadInformationSize'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = 'SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetThreadInformation", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetCurrentThread(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =[] 
        pNames = [] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        handle = Handle(HandleType.Thread,data=[])

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetCurrentThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetModuleBaseNameA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'HMODULE', 'LPSTR', 'DWORD'] 
        pNames = ['hProcess', 'hModule', 'lpBaseName', 'nSize'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        #handle = Handle(HandleType.GetModuleBaseNameA)

        if pVals[0] in HandlesDict:
            handle = HandlesDict[pVals[0]]
            if handle.type == HandleType.HMODULE:
                if handle.name != '':
                    uc.mem_write(pVals[0], pack(f'<{len(handle.name) + 1}s', handle.name.encode('ascii')))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("GetModuleBaseNameA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def SetTimer(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND', 'UINT_PTR', 'UINT', 'TIMERPROC'] 
        pNames = ['hWnd', 'nIDEvent', 'uElapse', 'lpTimerFunc'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "SUCCESS - New integer identified as timer"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SetTimer", hex(callAddr), (retValStr), 'UINT_PTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MoveFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCTSTR', 'LPCTSTR'] 
        pNames = ['lpExistingFileName', 'lpNewFileName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("MoveFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MoveFileW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR', 'LPCWSTR'] 
        pNames = ['lpExistingFileName', 'lpNewFileName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("MoveFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CopyFile(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCSTR', 'LPCSTR', 'BOOL'] 
        pNames = ['lpExistingFileName', 'lpNewFileName', 'bFailIfExists'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr = "SUCCESSFUL"
        uc.reg_write(UC_X86_REG_EAX, retVal)
        # "0x15e17a55": ["CopyFile", "kernel32.dll"],
        logged_calls= ("CopyFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ReadFile(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'LPVOID', 'DWORD', 'LPDWORD', 'LPOVERLAPPED'] 
        pNames = ['hFile', 'lpBuffer', 'nNumberOfBytesToRead', 'lpNumberOfBytesRead', 'lpOverlapped'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls= ("ReadFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetForegroundWindow(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND'] 
        pNames = ['hWnd'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr = "Window Successfully Brought to Foreground"
        uc.reg_write(UC_X86_REG_EAX, retVal)
       
        logged_calls= ("SetForegroundWindow", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetLastError(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # void SetLastError([in] DWORD dwErrCode);
        pTypes = ['DWORD']
        pNames = ['dwErrCode']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        global lastErrorCode

        lastErrorCode = pVals[0]

        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.ErrorCodes)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("SetLastError", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetLastErrorEx(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # void SetLastErrorEx([in] DWORD dwErrCode,[in] DWORD dwType);
        pTypes = ['DWORD', 'DWORD']
        pNames = ['dwErrCode', 'dwType']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        global lastErrorCode

        lastErrorCode = pVals[0]

        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.ErrorCodes)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retValStr = 'None'
        retVal = 0
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("SetLastErrorEx", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetLastError(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = []
        pNames = []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        global lastErrorCode

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = lastErrorCode
        retValStr = getLookUpVal(retVal, ReverseLookUps.ErrorCodes)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetLastError", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetFileType(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'GetFileType': (1, ['HANDLE'], ['hFile'], 'DWORD'
        # match the filetypes to the HandleType list
        pTypes = ['HANDLE']
        pNames = ['hFile']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if (pVals[0] in HandlesDict):
            fileTypeHandle = HandlesDict[pVals[0]]
            if (fileTypeHandle.type == HandleType.CreateFileW or fileTypeHandle.type == HandleType.CreateFileA or fileTypeHandle.type == HandleType.CreateFile2):
                retVal = 0x0001
                retValStr = 'FILE_TYPE_DISK'
            elif (fileTypeHandle.type == HandleType.FtpOpenFileA or fileTypeHandle.type == HandleType.FtpOpenFileW):
                retVal = 0x8000
                retValStr = 'FILE_TYPE_REMOTE'
            elif (fileTypeHandle.type == HandleType.charName):
                retVal = 0x0002
                retValStr = 'FILE_TYPE_CHAR'
            elif (fileTypeHandle.type == HandleType.pipeName):
                retVal = 0x0003
                retValStr = 'FILE_TYPE_PIPE'
            else:
                retVal = 0x0000
                retValStr = 'FILE_TYPE_UNKNOWN'
        else:
            retVal = 0x0000
            retValStr = 'FILE_TYPE_UNKNOWN'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetFileType", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GlobalLock(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'FlushFileBuffers': (1, ['HANDLE'], ['hFile'], 'BOOL')
        pTypes = ['HGLOBAL']
        pNames = ['hMem']
        pVals = makeArgVals(uc, em, esp, len(pTypes)) # Needs Reworked A little
        global availMem

        if (pVals[0] in HandlesDict):
            # return pointer
            handle = HandlesDict[pVals[0]]
            # retValStr = hex(retVal)
            allocMemoryVal = availMem
            uc.mem_map(availMem, 4096)
            availMem += 4096
            # print(handle.data)
            # retHandle = Handle(HandleType.HGLOBAL, allocMemoryVal, pVals[0])
            uc.mem_write(allocMemoryVal, pack(f'<{len(handle.data)}s', handle.data.encode('ascii')))
            retVal = allocMemoryVal
            retValStr = hex(retVal)
        else:
            # return pointer
            print('test03')
            allocMemoryVal = availMem
            uc.mem_map(availMem, 4096)
            availMem += 4096
            # retHandle = Handle(HandleType.HGLOBAL, allocMemoryVal, pVals[0])
            uc.mem_write(allocMemoryVal, pack(f'<{len()}'))
            retVal = allocMemoryVal
            retValStr = hex(retVal)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GlobalLock", hex(callAddr), (retValStr), 'LPVOID ', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GlobalAlloc(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # ''GlobalAlloc': (2, ['UINT', 'SIZE_T'], ['uFlags', 'dwBytes'], 'HGLOBAL')
        pTypes = ['UINT', 'SIZE_T']
        pNames = ['uFlags', 'dwBytes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        uFlags_ReverseLookUp = {66: 'GHND', 0: 'GMEM_FIXED', 2: 'GMEM_MOVEABLE', 64: 'GPTR'}
        global availMem

        if (pVals[0] == 0 or pVals[0] == 0x0040):
            # GMEM_FIXED
            # gptr
            try:
                retVal = availMem
                pVals[1] = ((pVals[1] // 4096) + 1) * 4096
                uc.mem_map(availMem, pVals[1])
                availMem += pVals[1]
                retValStr = hex(retVal)
            except:
                pass
        elif (pVals[0] == 0x0002 or pVals[0] == 0x0042):
            # GMEM_MOVEABLE
            # GHND
            try:
                allocMemoryVal = availMem
                pVals[1] = ((pVals[1] // 4096) + 1) * 4096
                uc.mem_map(availMem, pVals[1])
                availMem += pVals[1]
                retHandle = Handle(HandleType.HGLOBAL, data=allocMemoryVal)
                retVal = retHandle.value
                retValStr = hex(retVal)
            except:
                pass
        else:
            retVal = 0
            retValStr = 'NULL'

        pVals[0] = getLookUpVal(pVals[0], uFlags_ReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("GlobalAlloc", hex(callAddr), (retValStr), 'HGLOBAL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateDirectoryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'CreateDirectoryA': (2, ['LPCSTR', 'LPSECURITY_ATTRIBUTES'], ['lpPathName', 'lpSecurityAttributes'], 'thunk BOOL')
        pTypes= ['LPCSTR', 'LPSECURITY_ATTRIBUTES']
        pNames= ['lpPathName', 'lpSecurityAttributes']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CreateDirectoryA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateDirectoryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'CreateDirectoryA': (2, ['LPCSTR', 'LPSECURITY_ATTRIBUTES'], ['lpPathName', 'lpSecurityAttributes'], 'thunk BOOL')
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        pTypes= ['LPCWSTR', 'LPSECURITY_ATTRIBUTES']
        pNames= ['lpPathName', 'lpSecurityAttributes']

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CreateDirectoryW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RemoveDirectoryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
         #'RemoveDirectoryW': (1, ['LPCWSTR'], ['lpPathName'], 'thunk BOOL')
        pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 1)
        pTypes= ['LPCWSTR']
        pNames= ['lpPathName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("RemoveDirectoryW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RemoveDirectoryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #RemoveDirectoryA': (1, ['LPCSTR'], ['lpPathName'], 'thunk BOOL')
        pTypes= ['LPCSTR']
        pNames= ['lpPathName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("RemoveDirectoryA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ResumeThread(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'ResumeThread': (1, ['HANDLE'], ['hThread'], 'DWORD')
        pTypes= ['HANDLE']
        pNames= ['hThread']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("ResumeThread", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetThreadContext(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'ResumeThread': (1, ['HANDLE'], ['hThread'], 'DWORD')
        pTypes= ['HANDLE', 'LPCONTEXT']
        pNames=['hThread', 'lpContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        ### RETURN WEIRD

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetThreadContext", hex(callAddr), (retValStr), 'Bool', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def AllocConsole(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'AllocConsole': (0, [], [], 'BOOL')
        pTypes= []
        pNames=[]
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("AllocConsole", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def FreeLibrary(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        ##'FreeLibrary': (1, ['HMODULE'], ['hLibModule'], 'BOOL')
        pTypes= ['HMODULE']
        pNames= ['hLibModule']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("FreeLibrary", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetEnvironmentVariableA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'SetEnvironmentVariableA': (2, ['LPCSTR', 'LPCSTR'], ['lpName', 'lpValue'], 'BOOL')
        pTypes= ['LPCSTR', 'LPCSTR']
        pNames= ['lpName', 'lpValue']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetEnvironmentVariableA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SystemParametersInfoA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['UNINT', 'UNINT', 'PVOID', 'UINT']
        pNames= ['uiAction', 'uiParam', 'pvParam', 'fWinIni']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Might Need to Expand

        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.SystemParametersInfo.Action)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SystemParametersInfoA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SystemParametersInfoW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['UNINT', 'UNINT', 'PVOID', 'UINT']
        pNames= ['uiAction', 'uiParam', 'pvParam', 'fWinIni']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Might Need to Expand

        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.SystemParametersInfo.Action)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SystemParametersInfoW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    
    def OpenProcess(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'OpenProcess': (3, ['DWORD', 'BOOL', 'DWORD'], ['dwDesiredAccess', 'bInheritHandle', 'dwProcessId'], 'HANDLE')
        pTypes= ['DWORD', 'BOOL', 'DWORD']
        pNames= ['dwDesiredAccess', 'bInheritHandle', 'dwProcessId']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwDesiredAccess_ReverseLookUp = {65536: 'DELETE', 131072: 'READ_CONTROL', 1048576: 'SYNCHRONIZE', 262144: 'WRITE_DAC', 983040: 'STANDARD_RIGHTS_REQUIRED', 128:'PROCESS_CREATE_PROCESS', 2: 'PROCESS_CREATE_THREAD', 64:'PROCESS_DUP_HANDLE', 1024: 'PROCESS_QUERY_INFORMATION', 4096:'PROCESS_QUERY_LIMITED_INFORMATION', 512: 'PROCESS_SET_INFORMATION', 256: 'PROCESS_SET_QUOTA', 2048: 'PROCESS_SUSPEND_RESUME', 1: 'PROCESS_TERMINATE', 8: 'PROCESS_VM_OPERATION', 16: 'PROCESS_VM_READ', 32: 'PROCESS_VM_WRITE'}

        pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retVal = FakeProcess # Might Need Changed
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("OpenProcess", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))
    
    def CreateEventA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['LPSECURITY_ATTRIBUTES', 'BOOL', 'BOOL', 'LPCSTR']
        pNames= ['lpEventAttributes', 'bManualReset', 'bInitialState', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        if pVals[3] != '[NULL]':
            handle = Handle(HandleType.Event,name=pVals[3])
        else:
            handle = Handle(HandleType.Event)

        retVal = handle.value
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CreateEventA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateEventW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['LPSECURITY_ATTRIBUTES', 'BOOL', 'BOOL', 'LPCWSTR']
        pNames= ['lpEventAttributes', 'bManualReset', 'bInitialState', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        if pVals[3] != '[NULL]':
            handle = Handle(HandleType.Event,name=pVals[3])
        else:
            handle = Handle(HandleType.Event)

        retVal = handle.value
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CreateEventW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def CreateEventExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['LPSECURITY_ATTRIBUTES', 'LPCSTR', 'DWORD', 'DWORD']
        pNames= ['lpEventAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Event.Flags)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Event.DesiredAccess)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[2,3])

        if pVals[1] != '[NULL]':
            handle = Handle(HandleType.Event,name=pVals[1])
        else:
            handle = Handle(HandleType.Event)

        retVal = handle.value
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CreateEventExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateEventExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['LPSECURITY_ATTRIBUTES', 'LPCWSTR', 'DWORD', 'DWORD']
        pNames= ['lpEventAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.Event.Flags)
        pVals[3] = getLookUpVal(pVals[3], ReverseLookUps.Event.DesiredAccess)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[2,3])

        if pVals[1] != '[NULL]':
            handle = Handle(HandleType.Event,name=pVals[1])
        else:
            handle = Handle(HandleType.Event)

        retVal = handle.value
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CreateEventExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenEventA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['DWORD', 'BOOL', 'LPCSTR']
        pNames= ['dwDesiredAccess', 'bInheritHandle', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.Event.DesiredAccess)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retHandle = None
        for handle in HandlesDict.values():
            if handle.name == pVals[2]:
                retHandle = handle
                break

        if retHandle is None:
            retHandle = Handle(HandleType.Event,name=pVals[2])

        retVal = retHandle.value
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("OpenEventA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenEventW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['DWORD', 'BOOL', 'LPCWSTR']
        pNames= ['dwDesiredAccess', 'bInheritHandle', 'lpName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.Event.DesiredAccess)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retHandle = None
        for handle in HandlesDict.values():
            if handle.name == pVals[2]:
                retHandle = handle
                break

        if retHandle is None:
            retHandle = Handle(HandleType.Event,name=pVals[2])

        retVal = retHandle.value
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("OpenEventW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemTimeAsFileTime(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #GetSystemTimeAsFileTime': (1, ['LPFILETIME'], ['lpSystemTimeAsFileTime'], 'VOID')
        pTypes= ['LPFILETIME']
        pNames= ['lpSystemTimeAsFileTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        fileTime = get_FILETIME(uc, pVals[0], em)
        fileTime.genTime()
        fileTime.writeToMemory(uc, pVals[0])

        pVals[0] = makeStructVals(uc, fileTime, pVals[0])

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retVal = 0
        retValStr='NONE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetSystemTimeAsFileTime", hex(callAddr), (retValStr), 'VOID', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetFileTime(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetFileTime': (4, ['HANDLE', 'LPFILETIME', 'LPFILETIME', 'LPFILETIME'], ['hFile', 'lpCreationTime', 'lpLastAccessTime', 'lpLastWriteTime'], 'thunk BOOL')
        pTypes= ['HANDLE', 'LPFILETIME', 'LPFILETIME', 'LPFILETIME']
        pNames= ['hFile', 'lpCreationTime', 'lpLastAccessTime', 'lpLastWriteTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if pVals[1] != 0x0:
            fileTime = get_FILETIME(uc, pVals[1], em)
            fileTime.genTime()
            fileTime.writeToMemory(uc, pVals[1])
            pVals[1] = makeStructVals(uc, fileTime, pVals[1])
        else:
            pVals[3] = hex(pVals[3])

        if pVals[2] != 0x0:
            fileTime = get_FILETIME(uc, pVals[2], em)
            fileTime.genTime()
            fileTime.writeToMemory(uc, pVals[2])
            pVals[2] = makeStructVals(uc, fileTime, pVals[2])
        else:
            pVals[3] = hex(pVals[3])

        if pVals[3] != 0x0:
            fileTime = get_FILETIME(uc, pVals[3], em)
            fileTime.genTime()
            pVals[3] = makeStructVals(uc, fileTime, pVals[3])
        else:
            pVals[3] = hex(pVals[3])

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1,2,3])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetFileTime", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def recv(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'recv': (4, ['SOCKET', 'char *', 'int', 'int'], ['s', 'buf', 'len', 'flags'], 'int')
        pTypes= ['SOCKET', 'char *', 'int', 'int']
        pNames= ['s', 'buf', 'len', 'flags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        #return is len of bytes sent.
        #print(pVals[2])
        retVal = int(pVals[2],16)
        retValStr= hex(retVal)
        #print(retValStr)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("recv", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def send(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'send': (4, ['SOCKET', 'const char *', 'int', 'int'], ['s', 'buf', 'len', 'flags'], 'int')
        pTypes= ['SOCKET', 'const char *', 'int', 'int']
        pNames= ['s', 'buf', 'len', 'flags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        #return is len of bytes sent.
        #print(pVals[2])
        retVal = int(pVals[2],16)
        retValStr= hex(retVal)
        #print(retValStr)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("send", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def connect(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['SOCKET', 'const sockaddr *', 'int']
        pNames= ['s', 'name', 'namelen']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            sock_addr = uc.mem_read(pVals[1], pVals[2])

            sin_family, = unpack("<h", sock_addr[:2])

            if sin_family == 2:  # AF_INET
                port, host = unpack(">HI", sock_addr[2:8])
                pVals[1] = "%s:%d" % (bin_to_ipv4(host), port)
            elif sin_family == 6:  # AF_INET6
                # Add ipv6 later
                pVals[1] = hex(pVals[1])
        except:
            pVals[1] = hex(pVals[1])
            pass


        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])

        retVal = 0x0
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("connect", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def bind(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['SOCKET', 'const sockaddr *', 'int']
        pNames= ['s', 'name', 'namelen']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        try:
            sock_addr = uc.mem_read(pVals[1], pVals[2])

            sin_family, = unpack("<h", sock_addr[:2])

            if sin_family == 2:  # AF_INET
                port, host = unpack(">HI", sock_addr[2:8])
                pVals[1] = "%s:%d" % (bin_to_ipv4(host), port)
            elif sin_family == 6:  # AF_INET6
                # Add ipv6 later
                pVals[1] = hex(pVals[1])
        except:
            pVals[1] = hex(pVals[1])
            pass


        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])

        retVal = 0x0
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("bind", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def accept(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['SOCKET', 'sockaddr *', 'int *']
        pNames= ['s', 'addr', 'addrlen']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        # try:
        #     addrLength = getPointerVal(uc, pVals[1])
        #     pVals[2] = buildPtrString(pVals[2], addrLength)
        #     sock_addr = uc.mem_read(pVals[1], addrLength)

        #     sin_family, = unpack("<h", sock_addr[:2])

        #     if sin_family == 2:  # AF_INET
        #         port, host = unpack(">HI", sock_addr[2:8])
        #         pVals[1] = "%s:%d" % (bin_to_ipv4(host), port)
        #     elif sin_family == 6:  # AF_INET6
        #         # Add ipv6 later
        #         pVals[1] = hex(pVals[1])
        # except:
        #     pVals[1] = hex(pVals[1])
        #     pass


        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x0
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("accept", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemDirectoryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetSystemDirectoryA': (2, ['LPSTR', 'UINT'], ['lpBuffer', 'uSize'], 'UINT')
        pTypes= ['LPSTR', 'UINT']
        pNames= ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        systemDir = 'C:\Windows\System32'

        path = systemDir.encode('ascii')
        if (len(path)+2) <= pVals[1]:
            uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = len(systemDir)
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetSystemDirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetSystemDirectoryW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetSystemDirectoryW': (2, ['LPWSTR', 'UINT'], ['lpBuffer', 'uSize'], 'UINT')
        pTypes= ['LPWSTR', 'UINT']
        pNames= ['lpBuffer', 'uSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        systemDir = 'C:\Windows\System32'

        path = systemDir.encode('utf-16')[2:]
        if (len(path)+2) <= pVals[1]:
            uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = len(systemDir)
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetSystemDirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetFocus(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'SetFocus': (1, ['HWND'], ['hWnd'], 'HWND')
        pTypes= ['HWND']
        pNames= ['hWnd']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        #this should be updated to include the previous process.
        PreviousHandle = FakeProcess

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = PreviousHandle
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetFocus", hex(callAddr), (retValStr), 'HWND', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetWindowLongPtrA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'SetWindowLongPtrA': (3, ['HWND', 'INT', 'LONG_PTR'], ['hwnd', 'offset', 'newval'], 'LONG_PTR')
        pTypes= ['HWND', 'INT', 'LONG_PTR']
        pNames= ['hwnd', 'offset', 'newval']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        setWindowLongPtrA_ReverseLookUp = {-32: 'GWL_EXSTYLE', -6: 'GWLP_HINSTANCE', -18: 'GWLP_ID', -22: 'GWL_STYLE', -33: 'GWLP_USERDATA', -4: 'GWLP_WNDPROC'}
        pVals[1] = getLookUpVal(pVals[1], setWindowLongPtrA_ReverseLookUp)
        #this should be updated to include the previous value.
        previousValue = 123

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])

        retVal = previousValue
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetWindowLongPtrA", hex(callAddr), (retValStr), 'LONG_PTR', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetWindowLongA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'SetWindowLongA': (3, ['HWND', 'int', 'LONG'], ['hWnd', 'nIndex', 'dwNewLong'], 'LONG')
        pTypes= ['HWND', 'int', 'LONG']
        pNames= ['hWnd', 'nIndex', 'dwNewLong']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        setWindowLongPtrA_ReverseLookUp = {-32: 'GWL_EXSTYLE', -6: 'GWLP_HINSTANCE', -18: 'GWLP_ID', -22: 'GWL_STYLE', -33: 'GWLP_USERDATA', -4: 'GWLP_WNDPROC'}
        pVals[1] = getLookUpVal(pVals[1], setWindowLongPtrA_ReverseLookUp)
        #this should be updated to include the previous value.
        previousValue = 0x00004000

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])

        retVal = previousValue
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetWindowLongA", hex(callAddr), (retValStr), 'LONG', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetWindowLongW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'SetWindowLongW': (3, ['HWND', 'int', 'LONG'], ['hWnd', 'nIndex', 'dwNewLong'], 'LONG')
        pTypes= ['HWND', 'int', 'LONG']
        pNames= ['hWnd', 'nIndex', 'dwNewLong']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        setWindowLongPtrA_ReverseLookUp = {-32: 'GWL_EXSTYLE', -6: 'GWLP_HINSTANCE', -18: 'GWLP_ID', -22: 'GWL_STYLE', -33: 'GWLP_USERDATA', -4: 'GWLP_WNDPROC'}
        pVals[1] = getLookUpVal(pVals[1], setWindowLongPtrA_ReverseLookUp)
        #this should be updated to include the previous value.
        previousValue = 0x00004000

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])

        retVal = previousValue
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetWindowLongA", hex(callAddr), (retValStr), 'LONG', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def SetCurrentDirectoryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'SetCurrentDirectoryA': (1, ['LPCSTR'], ['lpPathName'], 'BOOL')
        pTypes= ['LPCTSTR']
        pNames= ['lpPathName']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        currentDirectory = pVals[0]
        #changes relative paths into absolute paths
        if(".." in pVals[0]):
            #have a workaround for now to convert to an absolute path
            currentDirectory = "C:\\"+ currentDirectory.replace('..','SHAREM_PATH')
        #print(currentDirectory)
        art.path_artifacts.append(currentDirectory)
        retVal = 0x1
        retValStr= 'True'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetCurrentDirectoryA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CountClipboardFormats(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'CountClipboardFormats': (0, [], [], 'INT')
        pTypes= []
        pNames= []
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        #need to somehow identify the different data formats in the clipboard
        #for now just is returning a non zero number to indicate success
        numberOfDatatypes = 1
        

        retVal = numberOfDatatypes
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CountClipboardFormats", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetKeyNameTextA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetKeyNameTextA': (3, ['LONG', 'LPSTR', 'INT'], ['lParam', 'lpBuffer', 'nSize'], 'INT')
        pTypes= ['LONG', 'LPSTR', 'INT']
        pNames= ['lParam', 'lpBuffer', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        writeAddress = pVals[1]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        scanCode = pVals[0]
        keyboardCode = ReverseLookUps.SCtoVK.get(int(scanCode,16),'0')
        keyName = ReverseLookUps.VirtualKey.get(keyboardCode,'0')
        #Currently returns a static key name for any key code passed in.
        
        #write to the lpBuffer
        keyName_bytes = bytes(keyName, 'utf-8')
        uc.mem_write(writeAddress, keyName_bytes)

        #show what was written to buffer
        #pVals[1] += " -> " + keyName

        retVal = len(keyName)
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetKeyNameTextA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetKeyNameTextW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetKeyNameTextW': (3, ['LONG', 'LPWSTR', 'INT'], ['lParam', 'lpBuffer', 'nSize'], 'INT')
        pTypes= ['LONG', 'LPWSTR', 'INT']
        pNames= ['lParam', 'lpBuffer', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        scanCode = pVals[0]
        keyboardCode = ReverseLookUps.SCtoVK.get(int(scanCode,16),'0')
        keyName = ReverseLookUps.VirtualKey.get(keyboardCode,'0')
        #Currently returns a static key name for any key code passed in.
        
        #write to the lpBuffer
        keyName_bytes = bytes(keyName, 'utf-8')
        uc.mem_write(writeAddress, keyName_bytes)

        retVal = len(keyName)
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetKeyNameTextW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetKeyState(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetKeyState': (1, ['int'], ['nVirtKey'], 'SHORT')
        pTypes= ['int']
        pNames= ['nVirtKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        keysVirtVal = pVals[0]
        #toggle Keys
        if(keysVirtVal == '0x14'):
            #capsLock
            retVal = 0x0001
        elif(keysVirtVal == '0x90'):
            #numLock
            retVal = 0x0001
        elif(keysVirtVal == '0x91'):
            #scrollLock
            retVal = 0x0001
        else:
            retVal = 0x1000

        #retVal = 
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetKeyState", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))
    
    def MapVirtualKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'MapVirtualKeyA': (2, ['UINT', 'UINT'], ['uCode', 'uMapType'], 'UINT')
        pTypes= ['UINT', 'UINT']
        pNames= ['uCode', 'uMapType']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        #get key from GeeksForGeeks, https://www.geeksforgeeks.org/python-get-key-from-value-in-dictionary/
        def get_key(val):
            for key, value in ReverseLookUps.VirtualKey.items():
                 if val == value:
                     return key
 
            return 0x999

        def checkRightCodeVK(keysVal):
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            if re.search('VK_R.+',charMapping):
                charMapping = list(charMapping)
                charMapping[3] = 'L'
                charMapping = ''.join(charMapping)
                return get_key(charMapping)

        def checkRightCodeSC(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            leftVK = checkRightCodeVK(result)
            return ReverseLookUps.VKtoSC.get(leftVK)

        def VKtoSCretVal(keysVal):
            result = ReverseLookUps.VKtoSC.get(keysVal,0)
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            keysVal = hex(keysVal)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal
            else:
                retVal = result
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal

        def SCtoVKretVal(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            charMapping = getLookUpVal(result,ReverseLookUps.VirtualKey)
            resultStr = hex(result)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr
            else:
                retVal = result
                retValStr= resultStr
                return retVal, retValStr

        mapType = pVals[1]
        keysVal = pVals[0]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])

        if(mapType == 0):
            #print('virtual -> scan | left code return')
            #need to check for any right codes and return the left only
            keysVal = checkRightCodeVK(keysVal)
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        elif(mapType == 1):
            #print('scan -> virtual | left code return')
            keysVal = checkRightCodeSC(keysVal)
            #need to check for any right codes and return the left only
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 2):
            #print('virtual -> unshifted char val in lowest order word')
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            retVal = keysVal
            retValStr = charMapping
        elif(mapType == 3):
            #print('scan -> virtual | left and right codes return')
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 4):
            #print('virtual -> scan | look at documentation')
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        else:
            retVal = 0x90
            retValStr= hex(retVal)

        #pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])
        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.MapKey_MapType_ReverseLookUp)
        uc.reg_write(UC_X86_REG_EAX, retVal)    

        logged_calls= ("MapVirtualKeyA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MapVirtualKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'MapVirtualKeyW': (2, ['UINT', 'UINT'], ['uCode', 'uMapType'], 'UINT')
        pTypes= ['UINT', 'UINT']
        pNames= ['uCode', 'uMapType']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        #get key from GeeksForGeeks, https://www.geeksforgeeks.org/python-get-key-from-value-in-dictionary/
        def get_key(val):
            for key, value in ReverseLookUps.VirtualKey.items():
                 if val == value:
                     return key
 
            return 0x999

        def checkRightCodeVK(keysVal):
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            if re.search('VK_R.+',charMapping):
                charMapping = list(charMapping)
                charMapping[3] = 'L'
                charMapping = ''.join(charMapping)
                return get_key(charMapping)

        def checkRightCodeSC(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            leftVK = checkRightCodeVK(result)
            return ReverseLookUps.VKtoSC.get(leftVK)

        def VKtoSCretVal(keysVal):
            result = ReverseLookUps.VKtoSC.get(keysVal,0)
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            keysVal = hex(keysVal)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal
            else:
                retVal = result
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal

        def SCtoVKretVal(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            charMapping = getLookUpVal(result,ReverseLookUps.VirtualKey)
            resultStr = hex(result)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr
            else:
                retVal = result
                retValStr= resultStr
                return retVal, retValStr

        mapType = pVals[1]
        keysVal = pVals[0]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])

        if(mapType == 0):
            #print('virtual -> scan | left code return')
            #need to check for any right codes and return the left only
            keysVal = checkRightCodeVK(keysVal)
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        elif(mapType == 1):
            #print('scan -> virtual | left code return')
            keysVal = checkRightCodeSC(keysVal)
            #need to check for any right codes and return the left only
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 2):
            #print('virtual -> unshifted char val in lowest order word')
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            retVal = keysVal
            retValStr = charMapping
        elif(mapType == 3):
            #print('scan -> virtual | left and right codes return')
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 4):
            #print('virtual -> scan | look at documentation')
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        else:
            retVal = 0x90
            retValStr= hex(retVal)

        #pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])
        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.MapKey_MapType_ReverseLookUp)
        uc.reg_write(UC_X86_REG_EAX, retVal)    

        logged_calls= ("MapVirtualKeyW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MapVirtualKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'MapVirtualKeyExA': (3, ['UINT', 'UINT', 'HKL'], ['uCode', 'uMapType', 'dwhkl'], 'UINT')
        pTypes= ['UINT', 'UINT', 'HKL']
        pNames= ['uCode', 'uMapType', 'dwhkl']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        #get key from GeeksForGeeks, https://www.geeksforgeeks.org/python-get-key-from-value-in-dictionary/
        def get_key(val):
            for key, value in ReverseLookUps.VirtualKey.items():
                 if val == value:
                     return key
 
            return 0x999

        def checkRightCodeVK(keysVal):
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            if re.search('VK_R.+',charMapping):
                charMapping = list(charMapping)
                charMapping[3] = 'L'
                charMapping = ''.join(charMapping)
                return get_key(charMapping)

        def checkRightCodeSC(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            leftVK = checkRightCodeVK(result)
            return ReverseLookUps.VKtoSC.get(leftVK)

        def VKtoSCretVal(keysVal):
            result = ReverseLookUps.VKtoSC.get(keysVal,0)
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            keysVal = hex(keysVal)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal
            else:
                retVal = result
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal

        def SCtoVKretVal(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            charMapping = getLookUpVal(result,ReverseLookUps.VirtualKey)
            resultStr = hex(result)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr
            else:
                retVal = result
                retValStr= resultStr
                return retVal, retValStr

        mapType = pVals[1]
        keysVal = pVals[0]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1,2])

        if(mapType == 0):
            #print('virtual -> scan | left code return')
            #need to check for any right codes and return the left only
            keysVal = checkRightCodeVK(keysVal)
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        elif(mapType == 1):
            #print('scan -> virtual | left code return')
            keysVal = checkRightCodeSC(keysVal)
            #need to check for any right codes and return the left only
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 2):
            #print('virtual -> unshifted char val in lowest order word')
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            retVal = keysVal
            retValStr = charMapping
        elif(mapType == 3):
            #print('scan -> virtual | left and right codes return')
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 4):
            #print('virtual -> scan | look at documentation')
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        else:
            retVal = 0x90
            retValStr= hex(retVal)

        #pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])
        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.MapKey_MapType_ReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.keyboardLanguages)
        uc.reg_write(UC_X86_REG_EAX, retVal)    

        logged_calls= ("MapVirtualKeyExA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def MapVirtualKeyExW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'MapVirtualKeyExW': (3, ['UINT', 'UINT', 'HKL'], ['uCode', 'uMapType', 'dwhkl'], 'UINT')
        pTypes= ['UINT', 'UINT', 'HKL']
        pNames= ['uCode', 'uMapType', 'dwhkl']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        #get key from GeeksForGeeks, https://www.geeksforgeeks.org/python-get-key-from-value-in-dictionary/
        def get_key(val):
            for key, value in ReverseLookUps.VirtualKey.items():
                 if val == value:
                     return key
 
            return 0x999

        def checkRightCodeVK(keysVal):
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            if re.search('VK_R.+',charMapping):
                charMapping = list(charMapping)
                charMapping[3] = 'L'
                charMapping = ''.join(charMapping)
                return get_key(charMapping)

        def checkRightCodeSC(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            leftVK = checkRightCodeVK(result)
            return ReverseLookUps.VKtoSC.get(leftVK)

        def VKtoSCretVal(keysVal):
            result = ReverseLookUps.VKtoSC.get(keysVal,0)
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            keysVal = hex(keysVal)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal
            else:
                retVal = result
                retValStr= hex(retVal)
                return retVal, retValStr, keysVal

        def SCtoVKretVal(keysVal):
            result = ReverseLookUps.SCtoVK.get(keysVal,0)
            charMapping = getLookUpVal(result,ReverseLookUps.VirtualKey)
            resultStr = hex(result)+" ("+charMapping+")"
            if(result == 0):
                retVal = 0x90
                retValStr= hex(retVal)
                return retVal, retValStr
            else:
                retVal = result
                retValStr= resultStr
                return retVal, retValStr

        mapType = pVals[1]
        keysVal = pVals[0]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1,2])

        if(mapType == 0):
            #print('virtual -> scan | left code return')
            #need to check for any right codes and return the left only
            keysVal = checkRightCodeVK(keysVal)
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        elif(mapType == 1):
            #print('scan -> virtual | left code return')
            keysVal = checkRightCodeSC(keysVal)
            #need to check for any right codes and return the left only
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 2):
            #print('virtual -> unshifted char val in lowest order word')
            charMapping = getLookUpVal(keysVal,ReverseLookUps.VirtualKey)
            retVal = keysVal
            retValStr = charMapping
        elif(mapType == 3):
            #print('scan -> virtual | left and right codes return')
            retVal,retValStr = SCtoVKretVal(keysVal)
        elif(mapType == 4):
            #print('virtual -> scan | look at documentation')
            retVal,retValStr, pVals[0] = VKtoSCretVal(keysVal)
        else:
            retVal = 0x90
            retValStr= hex(retVal)

        #pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])
        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.MapKey_MapType_ReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2], ReverseLookUps.keyboardLanguages)
        uc.reg_write(UC_X86_REG_EAX, retVal)    

        logged_calls= ("MapVirtualKeyExW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LoadKeyboardLayoutA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'LoadKeyboardLayoutA': (2, ['LPCSTR', 'UINT'], ['pwszKLID', 'Flags'], 'HKL')
        pTypes= ['LPCSTR', 'UINT']
        pNames= ['pwszKLID', 'Flags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])
        
        keyboardIdentifier = int(pVals[0],16)
        keyboardIdentifierStr = getLookUpVal(keyboardIdentifier, ReverseLookUps.keyboardLanguages)
        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.loadKeyboard_uFlags_ReverseLookUp)
        retVal = keyboardIdentifier
        retValStr= hex(keyboardIdentifier) + " (" +keyboardIdentifierStr + ")"
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("LoadKeyboardLayoutA", hex(callAddr), (retValStr), 'HKL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def LoadKeyboardLayoutW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'LoadKeyboardLayoutW': (2, ['LPCWSTR', 'UINT'], ['pwszKLID', 'Flags'], 'HKL')
        pTypes= ['LPCWSTR', 'UINT']
        pNames= ['pwszKLID', 'Flags']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[1])
        
        keyboardIdentifier = int(pVals[0],16)
        keyboardIdentifierStr = getLookUpVal(keyboardIdentifier, ReverseLookUps.keyboardLanguages)
        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.loadKeyboard_uFlags_ReverseLookUp)
        retVal = keyboardIdentifier
        retValStr= hex(keyboardIdentifier) + " (" +keyboardIdentifierStr + ")"
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("LoadKeyboardLayoutW", hex(callAddr), (retValStr), 'HKL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetKeyboardState(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetKeyboardState': (1, ['PBYTE'], ['lpKeyState'], 'BOOL')
        pTypes= ['PBYTE']
        pNames= ['lpKeyState']
        pVals = makeArgVals(uc, em, esp, len(pTypes))


        keysStatus = []
        for i in range(256):
            keysStatus.append(0)

        keysStatus = bytearray(keysStatus)
        #this shows that a key is pressed.
        keysStatus[65] = 0x80
        keysStatus = bytes(keysStatus)
        uc.mem_write(pVals[0], keysStatus)


        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        retVal = 1
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetKeyboardState", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetAsyncKeyState(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetAsyncKeyState': (1, ['int'], ['vKey'], 'SHORT')
        pTypes= ['int']
        pNames= ['vKey']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        virtualKey = pVals[0]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])
        virtualKey = getLookUpVal(virtualKey, ReverseLookUps.VirtualKey)
        pVals[0] += " ("+ virtualKey + ")"

        retVal = 128
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetAsyncKeyState", hex(callAddr), (retValStr), 'SHORT', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetDC(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'GetDC': (1, ['HWND'], ['hWnd'], 'HDC')
        pTypes= ['HWND']
        pNames= ['hWnd']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        print(1)
        #get the strucutre of the device, for now just creates a new one
        if pVals[0] != 0x0:
            disPlayVal = get_DISPLAY_DEVICE(uc, pVals[0], em)
            disPlayVal.writeToMemory(uc, pVals[0])
        else:
            #null grabs the entire screen's DC
            #creates a new handle for the address to write to, and will return that handle
            print(1.1)
            handle = Handle(HandleType.Process, name='screenDCHandle')
            print(1.2)
            #pVals[0] = handle
            print(1.3)
            disPlayVal = get_DISPLAY_DEVICE(uc, pVals[0], em)
            print(1.4)
            disPlayVal.writeToMemory(uc, pVals[0])
            print(1.5)
        print(2)
        pVals[0] = makeStructVals(uc, disPlayVal, pVals[0])
        print(3)
        
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])
        retVal = 1
        retValStr= hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetDC", hex(callAddr), (retValStr), 'HDC', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


class CustomWinSysCalls():

    def makeArgVals(self, uc: Uc, em, esp, numParams):
        args = [0] * numParams
        for i in range(len(args)):
            args[i] = self.getStackVal(uc, em, esp, i + 1)
        return args
    
    def getStackVal(self, uc: Uc, em, esp, loc):
        # x64 Windows syscall parameter order: r10, rdx, r8, r9, stack
        # r10 because rcx and r11 are used for syscall instruction
        if loc == 1 and em.arch == 64:
            arg = uc.reg_read(UC_X86_REG_R10)
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

    def NtCreateProcess(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 8)
        pTypes = ['PHANDLE', 'ACCESS_MASK', 'POBJECT_ATTRIBUTES', 'HANDLE', 'BOOLEAN', 'HANDLE', 'HANDLE', 'HANDLE']
        pNames = ['ProcessHandle', 'DesiredAccess', 'ObjectAttributes', 'ParentProcess', 'InheritObjectTable', 'SectionHandle', 'DebugPort', 'ExceptionPort']

        handle = Handle(HandleType.Process)

        try:
            uc.mem_write(pVals[0], pack('<I',handle.value))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 1
        retValStr = hex(retVal) 
        logged_calls = ["NtCreateProcess", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]
        return logged_calls

    def NtTerminateProcess(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'NTSTATUS']
        pNames = ['ProcessHandle', 'ExitStatus']

        if pVals[0] in HandlesDict:
            HandlesDict.pop(pVals[0])

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.NTSTATUS)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtTerminateProcess", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtAllocateVirtualMemory(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 6) 
        pTypes = ['HANDLE', 'PVOID', 'ULONG_PTR', 'PSIZE_T', 'ULONG', 'ULONG']
        pNames = ['ProcessHandle', '*BaseAddress', 'ZeroBits', 'RegionSize', 'AllocationType', 'Protect']
        
        global availMem

        # Get pointer values
        allocLoc = getPointerVal(uc, pVals[1])
        size = getPointerVal(uc, pVals[3])

        # Round up to next page (4096)
        size = ((size // 4096) + 1) * 4096

        retVal = 0
        try:
            uc.mem_map(allocLoc, size)
            uc.reg_write(UC_X86_REG_EAX, retVal)
        except Exception as e:
            # print("Error: ", e)
            # print(traceback.format_exc())
            try:
                allocLoc = availMem
                uc.mem_map(allocLoc, size)
                uc.mem_write(pVals[3], pack('<Q',size)) # Write Size
                availMem += size
                uc.reg_write(UC_X86_REG_EAX, retVal)
                uc.mem_write(pVals[1], pack("<Q", allocLoc)) # Write Allocation Location

            except Exception as e:
                print("Error: ", e)
                print(traceback.format_exc())
                print("NtAllocateVirtualMemory Function Failed")
                retVal = 0xbadd0000
                uc.reg_write(UC_X86_REG_EAX, retVal)

        pVals[4] = getLookUpVal(pVals[4], ReverseLookUps.Memmory)
        pVals[5] = getLookUpVal(pVals[5], ReverseLookUps.flProtect)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4,5])

        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtAllocateVirtualMemory", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtReadVirtualMemory(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 5)
        pTypes = ['HANDLE', 'PVOID', 'PVOID', 'ULONG', 'PULONG']
        pNames = ['ProcessHandle', 'BaseAddress', 'Buffer', 'NumberOfBytesToRead', 'NumberOfBytesReaded']

        baseAddress = getPointerVal(uc, pVals[1])
        buffer = getPointerVal(uc, pVals[2])

        try:
            memory = uc.mem_read(baseAddress, pVals[3])
            uc.mem_write(buffer, pack(f'<{len(memory)}s', memory))
            uc.mem_write(pVals[4], pack('<Q',len(memory)))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0
        uc.reg_write(UC_X86_REG_EAX, retVal)
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        logged_calls = ["NtReadVirtualMemory", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtWriteVirtualMemory(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 5)
        pTypes = ['HANDLE', 'PVOID', 'PVOID', 'ULONG', 'PULONG']
        pNames = ['ProcessHandle', 'BaseAddress', 'Buffer', 'NumberOfBytesToWrite', 'NumberOfBytesWritten']

        baseAddress = getPointerVal(uc, pVals[1])
        buffer = getPointerVal(uc, pVals[2])

        try:
            memory = uc.mem_read(buffer, pVals[3])
            uc.mem_write(baseAddress, pack(f'<{len(memory)}s', memory))
            uc.mem_write(pVals[4], pack('<Q',len(memory)))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
        
        retVal = 0
        uc.reg_write(UC_X86_REG_EAX, retVal)
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        logged_calls = ["NtWriteVirtualMemory", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtShutdownSystem(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 1)
        pTypes = ['SHUTDOWN_ACTION']
        pNames = ['Action']
        actionReversLookup = {0: 'ShutdownNoReboot', 1: 'ShutdownReboot', 2: 'ShutdownPowerOff'}

        pVals[0] = getLookUpVal(pVals[0], actionReversLookup)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])
        
        retVal = 0
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtShutdownSystem", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtCreateThread(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 8)
        pTypes = ['PHANDLE', 'ACCESS_MASK', 'POBJECT_ATTRIBUTES', 'HANDLE', 'PCLIENT_ID', 'PCONTEXT', 'PINITIAL_TEB', 'BOOLEAN']
        pNames = ['ThreadHandle', 'DesiredAccess', 'ObjectAttributes', 'ProcessHandle', 'ClientId', 'ThreadContext', 'InitialTeb', 'CreateSuspended']
        dwDesiredAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}

        handle = Handle(HandleType.Thread)

        try:
            uc.mem_write(pVals[0], pack('<I', handle.value))
            # uc.mem_write(pVals[4], PCLIENT_ID)
            # Maybe create PCLIENT_ID need to determing how to generate process and thread IDs
        except:
            pass

        pVals[1] = getLookUpVal(pVals[1], dwDesiredAccessReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])
        
        retVal = 0
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtCreateThread", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtCreateThreadEx(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 11)
        pTypes = ['PHANDLE', 'ACCESS_MASK', 'POBJECT_ATTRIBUTES', 'HANDLE', 'PVOID', 'PVOID', 'ULONG', 'ULONG', 'ULONG', 'ULONG', 'PVOID']
        pNames = ['ThreadHandle', 'DesiredAccess', 'ObjectAttributes', 'ProcessHandle', 'StartR__OUTine', 'Argument', 'CreateFlags', 'ZeroBits', 'StackSize', 'MaximumStackSize', 'AttributeList']
        dwDesiredAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
        dwCreateFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        handle = Handle(HandleType.Thread)

        try:
            uc.mem_write(pVals[0], pack('<I', handle.value))
            # uc.mem_write(pVals[4], PCLIENT_ID)
            # Maybe create PCLIENT_ID need to determing how to generate process and thread IDs
        except:
            pass

        pVals[1] = getLookUpVal(pVals[1], dwDesiredAccessReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], dwCreateFlagsReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,6])
        
        retVal = 0
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtCreateThreadEx", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtTerminateThread(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'NTSTATUS']
        pNames = ['ThreadHandle', 'ExitStatus']

        if pVals[0] in HandlesDict:
            HandlesDict.pop(pVals[0])

        pVals[1] = getLookUpVal(pVals[1], ReverseLookUps.NTSTATUS)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtTerminateThread", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtCreateNamedPipeFile(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 14)
        pTypes = ['PHANDLE', 'ACCESS_MASK', 'POBJECT_ATTRIBUTES', 'PIO_STATUS_BLOCK', 'ULONG', 'ULONG', 'ULONG', 'BOOLEAN', 'BOOLEAN', 'BOOLEAN', 'ULONG', 'ULONG', 'ULONG', 'PLARGE_INTEGER']
        pNames = ['NamedPipeFileHandle', 'DesiredAccess', 'ObjectAttributes', 'IoStatusBlock', 'ShareAccess', 'CreateDisposition', 'CreateOptions', 'WriteModeMessage', 'ReadModeMessage', 'NonBlocking', 'MaxInstances', 'InBufferSize', 'OutBufferSize', 'DefaultTimeOut']
        desiredAccessReverseLookUp = {0x0001: 'FILE_READ_DATA', 0x0002: 'FILE_WRITE_DATA', 0x0004: 'FILE_CREATE_PIPE_INSTANCE', 0x0080: 'FILE_READ_ATTRIBUTES', 0x0100: 'FILE_WRITE_ATTRIBUTES', 0x00100000: 'SYNCHRONIZE', 0x00200000: 'READ_CONTROL', 0x00080000: 'WRITE_OWNER', 0x00040000: 'WRITE_DAC', 0x01000000: 'ACCESS_SYSTEM_SECURITY'}
        shareAccessReverseLookUp = {0x1: 'FILE_SHARE_READ', 0x2: 'FILE_SHARE_WRITE', 0x4: 'FILE_SHARE_DELETE'}
        createDispositionReverseLookUp = {0x00000000: 'FILE_SUPERSEDE', 0x00000001: 'FILE_OPEN', 0x00000002: 'FILE_CREATE', 0x00000003: 'FILE_OPEN_IF', 0x00000004: 'FILE_OVERWRITE', 0x00000005: 'FILE_OVERWRITE_IF', 0x00000005: 'FILE_MAXIMUM_DISPOSITION'}
        createOptionsReverseLookup = {1: 'FILE_DIRECTORY_FILE', 2: 'FILE_WRITE_THROUGH', 4: 'FILE_SEQUENTIAL_ONLY', 8: 'FILE_NO_INTERMEDIATE_BUFFERING', 16: 'FILE_SYNCHRONOUS_IO_ALERT', 32: 'FILE_SYNCHRONOUS_IO_NONALERT', 64: 'FILE_NON_DIRECTORY_FILE', 128: 'FILE_CREATE_TREE_CONNECTION', 256: 'FILE_COMPLETE_IF_OPLOCKED', 512: 'FILE_NO_EA_KNOWLEDGE', 1024: 'FILE_OPEN_REMOTE_INSTANCE', 2048: 'FILE_RANDOM_ACCESS', 4096: 'FILE_DELETE_ON_CLOSE', 8192: 'FILE_OPEN_BY_FILE_ID', 16384: 'FILE_OPEN_FOR_BACKUP_INTENT', 32768: 'FILE_NO_COMPRESSION', 65536: 'FILE_OPEN_REQUIRING_OPLOCK', 1048576: 'FILE_RESERVE_OPFILTER', 2097152: 'FILE_OPEN_REPARSE_POINT', 4194304: 'FILE_OPEN_NO_RECALL', 8388608: 'FILE_OPEN_FOR_FREE_SPACE_QUERY', 16777215: 'FILE_VALID_OPTION_FLAGS', 50: 'FILE_VALID_MAILSLOT_OPTION_FLAGS', 54: 'FILE_VALID_SET_FLAGS'}
        maxInstancesReverseLookUp = {255: 'PIPE_UNLIMITED_INSTANCES'}
  
        try:
            # Possibly Parse ObjectAttributes Struct for Name
            handle = Handle(HandleType.ReadWritePipe)
            uc.mem_write(pVals[0], pack('<I', handle.value))
        except:
            pass

        pVals[1] = getLookUpVal(pVals[1], desiredAccessReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], shareAccessReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], createDispositionReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], createOptionsReverseLookup)
        pVals[10] = getLookUpVal(pVals[10], maxInstancesReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1,4,5,6,10])

        retVal = 0
        retValStr = getLookUpVal(retVal, ReverseLookUps.NTSTATUS)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtCreateNamedPipeFile", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls


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
        self.allocations: dict[int,HeapAllocation] = {}
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
            fmt = '<' + str(oldAllo.size) + 's'
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

class System_SnapShot:
    def __init__(self, fakeThreads: bool, fakeModules: bool):
        self.processOffset = 0
        self.threadOffset = 0
        self.moduleOffset = 0
        self.baseThreadID = 1000
        self.processDict = {4: PROCESSENTRY32(0, 10, 0, 0, 'System'),
                            2688: PROCESSENTRY32(2688, 16, 0, 4, 'explorer.exe'),
                            9172: PROCESSENTRY32(9172, 10, 2688, 10, 'calc.exe'),
                            8280: PROCESSENTRY32(8280, 50, 2688, 16, 'chrome.exe'),
                            11676: PROCESSENTRY32(11676, 78, 2688, 15, 'notepad.exe'),
                            8768: PROCESSENTRY32(8768, 20, 2688, 4, 'firefox.exe')}
        self.threadDict: dict[int, THREADENTRY32] = {}
        self.moduleList: list[MODULEENTRY32] = []
        if fakeThreads:
            self.fakeThreads()
        # if fakeModules: # Need To Fix Modules Thing
            # self.fakeModules()
        self.resetOffsets()

    def fakeThreads(self):
        for k, v in self.processDict.items():  # Create Fake Threads
            for i in range(v.cntThreads):
                self.threadDict.update(
                    {self.baseThreadID: THREADENTRY32(self.baseThreadID, v.th32ProcessID, v.pcPriClassBase)})
                self.baseThreadID += 1

    # def fakeModules(self):
    #     allDllsSizeDict = {'ntdll.dll': NTDLL_TOP - NTDLL_BASE, 'kernel32.dll': KERNEL32_TOP - KERNEL32_BASE,
    #                        'KernelBase.dll': KERNELBASE_TOP - KERNELBASE_BASE,
    #                        'advapi32.dll': ADVAPI32_TOP - ADVAPI32_BASE, 'comctl32.dll': COMCTL32_TOP - COMCTL32_BASE,
    #                        'comdlg32.dll': COMDLG32_TOP - COMDLG32_BASE, 'gdi32.dll': GDI32_TOP - GDI32_BASE,
    #                        'gdiplus.dll': GDIPLUS_TOP - GDIPLUS_BASE, 'imm32.dll': IMM32_TOP - IMM32_BASE,
    #                        'mscoree.dll': MSCOREE_TOP - MSCOREE_BASE, 'msvcrt.dll': MSVCRT_TOP - MSVCRT_BASE,
    #                        'netapi32.dll': NETAPI32_TOP - NETAPI32_BASE, 'ole32.dll': OLE32_TOP - OLE32_BASE,
    #                        'oleaut32.dll': OLEAUT32_TOP - OLEAUT32_BASE, 'shell32.dll': SHELL32_TOP - SHELL32_BASE,
    #                        'shlwapi.dll': SHLWAPI_TOP - SHLWAPI_BASE, 'urlmon.dll': URLMON_TOP - URLMON_BASE,
    #                        'user32.dll': USER32_TOP - USER32_BASE, 'wininet.dll': WININET_TOP - WININET_BASE,
    #                        'winmm.dll': WINMM_TOP - WINMM_BASE, 'ws2_32.dll': WS2_32_TOP - WS2_32_BASE,
    #                        'wsock32.dll': WSOCK32_TOP - WSOCK32_BASE, 'advpack.dll': ADVPACK_TOP - ADVPACK_BASE,
    #                        'bcrypt.dll': BCRYPT_TOP - BCRYPT_BASE, 'crypt32.dll': CRYPT32_TOP - CRYPT32_BASE,
    #                        'dnsapi.dll': DNSAPI_TOP - DNSAPI_BASE, 'mpr.dll': MPR_TOP - MPR_BASE,
    #                        'ncrypt.dll': NCRYPT_TOP - NCRYPT_BASE, 'netutils.dll': NETUTILS_TOP - NETUTILS_BASE,
    #                        'samcli.dll': SAMCLI_TOP - SAMCLI_BASE, 'secur32.dll': SECUR32_TOP - SECUR32_BASE,
    #                        'wkscli.dll': WKSCLI_TOP - WKSCLI_BASE, 'wtsapi32.dll': WTSAPI32_TOP - WTSAPI32_BASE}
    #     for k, v in self.processDict.items():
    #         moduleCount = randint(2, 16)  # Add Random Number of Modules
    #         modules = set()
    #         for i in range(moduleCount):
    #             selectedDLL = choice(list(allDllsDict))
    #             if selectedDLL not in modules:
    #                 modules.add(selectedDLL)
    #                 path = "C:\Windows\SysWOW64\\" + selectedDLL
    #                 self.moduleList.append(
    #                     MODULEENTRY32(v.th32ProcessID, allDllsDict[selectedDLL], allDllsSizeDict[selectedDLL],
    #                                          allDllsDict[selectedDLL], selectedDLL, path))

    def resetOffsets(self):
        try:
            self.processOffset = list(self.processDict.keys())[0]
            self.threadOffset = list(self.threadDict.keys())[0]
            self.moduleOffset = 0
        except:
            pass


class RegValueTypes(Enum):
    REG_BINARY = 3  # Binary data in any form.
    REG_DWORD = 4  # A 32-bit number.
    # REG_DWORD_LITTLE_ENDIAN = 4  # A 32-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_DWORD in the Windows header files.
    REG_DWORD_BIG_ENDIAN = 5  # A 32-bit number in big-endian format. Some UNIX systems support big-endian architectures.
    REG_EXPAND_SZ = 2  # A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%"). It will be a Unicode or ANSI string depending on whether you use the Unicode or ANSI functions. To expand the environment variable references, use the ExpandEnvironmentStrings function.
    REG_LINK = 6  # A null-terminated Unicode string that contains the target path of a symbolic link that was created by calling the RegCreateKeyEx function with REG_OPTION_CREATE_LINK.
    REG_MULTI_SZ = 7  # A sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: String1\0String2\0String3\0LastString\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string.
    REG_NONE = 0  # No defined value type.
    REG_QWORD = 11	# A 64-bit number.
    # REG_QWORD_LITTLE_ENDIAN = 11  # A 64-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_QWORD in the Windows header files.
    REG_SZ = 1  # A null-terminated string. This will be either a Unicode or an ANSI string, depending on whether you use the Unicode or ANSI functions.

class RegKey:
    PreDefinedKeys = {0x80000000: 'HKEY_CLASSES_ROOT',0x80000001: 'HKEY_CURRENT_USER',0x80000002: 'HKEY_LOCAL_MACHINE',0x80000003: 'HKEY_USERS',0x80000004: 'HKEY_PERFORMANCE_DATA',0x80000005: 'HKEY_CURRENT_CONFIG',0x80000006: 'HKEY_DYN_DATA'}
    nextHandleValue = 0x80000010 # Registry Uses Different Range of Handles
    nextRemoteHandleValues = 0x90000010 # Registry Start value for Remote Computer Handles
    securityAccessRights = {983103: 'KEY_ALL_ACCESS', 32: 'KEY_CREATE_LINK', 4: 'KEY_CREATE_SUB_KEY', 8: 'KEY_ENUMERATE_SUB_KEYS', 131097: 'KEY_READ', 16: 'KEY_NOTIFY', 1: 'KEY_QUERY_VALUE', 2: 'KEY_SET_VALUE', 512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY', 131078: 'KEY_WRITE'}

    def __init__(self, path: str, handle=0, remote: bool = False):
        pathSplit = path.split('\\')
        parentKeyPath = '\\'.join(pathSplit[:-1]) # Get Parent Key Path
        if len(pathSplit) > 2: # Create Parent Keys of Subkey
            newPath = ''
            for i in range(len(pathSplit)-1):
                if i == 0:
                    newPath += pathSplit[i]
                else:
                    newPath += '\\' + pathSplit[i]
                if newPath not in RegistryKeys:
                    RegKey(newPath,remote=remote)
        self.name = pathSplit[-1]
        self.path = path
        self.values: dict[str,KeyValue] = {}
        self.childKeys: dict[str,RegKey] = {}
        if handle == 0:
            if not remote:
                handle = RegKey.nextHandleValue
                RegKey.nextHandleValue += 8
            else:
                handle = RegKey.nextRemoteHandleValues
                RegKey.nextRemoteHandleValues += 8
        self.handle = Handle(HandleType.HKEY, handleValue=handle, name=self.path)
        RegistryKeys.update({self.path: self})
        self.parentKey = None
        if parentKeyPath != '':
            for key, val in RegistryKeys.items():
                if key == parentKeyPath:
                    self.parentKey = val
                    val.childKeys.update({self.name: self})            

    def createPreDefinedKeys():
        # Create Default Keys
        for key, val in RegKey.PreDefinedKeys.items():
            RegKey(path=val, handle=key)

    def deleteKey(self):
        if self.handle.value in HandlesDict: # Remove Handle
            HandlesDict.pop(self.handle.value)
        if self.path in RegistryKeys: # Delete Key
            # print(f'Key: {self.path} deleted')
            RegistryKeys.pop(self.path)

    def setValue(self, valueType: RegValueTypes, data, valueName = '(Default)'):
        val = KeyValue(valueType, data, valueName)
        self.values.update({val.name: val})

    def getValue(self, valueName: str = '(Default)'):
        if valueName in self.values:
            return self.values[valueName]
        else: # Return Value Not Set
            value = KeyValue(RegValueTypes.REG_SZ,emuSimVals.default_registry_value,valueName)
            return value

    def deleteValue(self, valueName: str = '(Default)'):
        if valueName in self.values:
            # print(f'Value: {self.values[valueName].name} deleted')
            return self.values.pop(valueName)

    def printInfo(self):
        print(f'Name: {self.name}')
        print(f'Path: {self.path}')
        print(f'Handle: {hex(self.handle.value)}')
        if isinstance(self.parentKey,RegKey):
            parentName = self.parentKey.name
        else:
            parentName = 'No Parent'
        print(f'Parent Key: {parentName}')
        print(f'Child Keys Count: {len(self.childKeys)}')
        if len(self.childKeys) > 0:
            for sKey, sVal in self.childKeys.items():
                print(f' >> {sKey}')
        print(f'Values Count: {len(self.values)}')
        if len(self.values) > 0:
            print ("{:<20} {:<20} {:<20}".format('Name','Type','Data'))
            for key, val in self.values.items():
                print ("{:<20} {:<20} {:<20}".format(val.name,val.type.name,val.dataAsStr))

    def printInfoAllKeys():
        print(f'Number of Registry Keys: {len(RegistryKeys)}')
        for rkey, rval in RegistryKeys.items():
            print(f'Name: {rval.name}')
            print(f'Path: {rval.path}')
            print(f'Handle: {hex(rval.handle.value)}')
            if isinstance(rval.parentKey,RegKey): 
                parentName = rval.parentKey.name
            else: 
                parentName = 'No Parent'
            print(f'Parent Key: {parentName}')
            print(f'Child Keys Count: {len(rval.childKeys)}')
            if len(rval.childKeys) > 0:
                for sKey, sVal in rval.childKeys.items():
                    print(f' >> {sKey}')
            print(f'Values Count: {len(rval.values)}')
            if len(rval.values) > 0:
                print ("{:<20} {:<20} {:<20}".format('Name','Type','Data'))
                for key, val in rval.values.items():
                    print ("{:<20} {:<20} {:<20}".format(val.name,val.type.name,val.dataAsStr))
            print('\n')
    
    def printTree():
        def printTreeRecursive(key: RegKey, level=0):
            if level == 0:
                print(key.name)
            else:
                print(('  ' * level) + '└─╴' + key.name)
            for sKey, sVal in key.childKeys.items():
                printTreeRecursive(sVal, level+1)

        print('Registry Tree')
        for key, value in RegKey.PreDefinedKeys.items():
            if value in RegistryKeys:
                rKey = RegistryKeys[value]
                printTreeRecursive(rKey)
        print('\n')
    
        
            
class KeyValue():
    def __init__(self, valueType: RegValueTypes, data, valueName: str):
        self.name = valueName
        self.type = valueType
        self.data = data
        if isinstance(data, str):
            self.dataAsStr = data
        elif isinstance(data, int):
            self.dataAsStr = hex(data)
        elif isinstance(data, bytearray):
            self.dataAsStr = data.hex()
        elif isinstance(data, list):
            self.dataAsStr = (' ').join(data)
        else:
            self.dataAsStr = str(data)

# Create Default Registry Keys
RegKey.createPreDefinedKeys()

def getStackVal(uc: Uc, em, esp, loc):
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


def makeArgVals(uc: Uc, em, esp, numParams):
    # print ("numParams", numParams)
    args = [0] * numParams
    for i in range(len(args)):
        args[i] = getStackVal(uc, em, esp, i + 1)
    return args

def stackCleanup(uc, em, esp, numParams):
    if em.arch == 32:
        bytes = numParams * 4
    else:
        bytes = numParams * 8
        bytes -= 32
        if bytes < 0:
            bytes = 0
    return bytes
    # uc.reg_write(UC_X86_REG_ESP, esp + bytes)

def findStringsParms(uc: Uc, pTypes, pVals, skip):
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

def SystemParametersInfoA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['UNINT', 'UNINT', 'PVOID', 'UINT']
        pNames= ['uiAction', 'uiParam', 'pvParam', 'fWinIni']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Might Need to Expand

        pVals[0] = getLookUpVal(pVals[0], ReverseLookUps.SystemParametersInfo.Action)

        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[0])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SystemParametersInfoA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

def CopyFileA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes= ['LCPSTR', 'LCPSTR', 'BOOL']
        pNames= ['lpExistingFileName', 'lpNewFileName', 'bFailIfExists']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # Might Need to Expand


        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip=[])

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CopyFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

