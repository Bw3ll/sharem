from enum import Enum, auto
from random import choice, randint
from unicorn.x86_const import *
from struct import pack, unpack
from ..helper.emuHelpers import Uc
from ..modules import allDllsDict
from .structures import makeStructVals, struct_FILETIME, struct_PROCESS_INFORMATION, struct_PROCESSENTRY32, struct_MODULEENTRY32, struct_SYSTEMTIME, struct_THREADENTRY32, struct_UNICODE_STRING
import traceback
from ..sharem_artifacts import *

art = Artifacts_emulation()


FakeProcess = 0xbadd0000
ProcessCreationReverseLookUp = {16777216: 'CREATE_BREAKAWAY_FROM_JOB', 67108864: 'CREATE_DEFAULT_ERROR_MODE',
                                16: 'CREATE_NEW_CONSOLE', 512: 'CREATE_NEW_PROCESS_GROUP',
                                134217728: 'CREATE_NO_WINDOW', 262144: 'CREATE_PROTECTED_PROCESS',
                                33554432: 'CREATE_PRESERVE_CODE_AUTHZ_LEVEL', 4194304: 'CREATE_SECURE_PROCESS',
                                2048: 'CREATE_SEPARATE_WOW_VDM', 4096: 'CREATE_SHARED_WOW_VDM', 4: 'CREATE_SUSPENDED',
                                1024: 'CREATE_UNICODE_ENVIRONMENT', 2: 'DEBUG_ONLY_THIS_PROCESS', 1: 'DEBUG_PROCESS',
                                8: 'DETACHED_PROCESS', 524288: 'EXTENDED_STARTUPINFO_PRESENT',
                                65536: 'INHERIT_PARENT_AFFINITY'}
MemLookUp = {'MEM_COMMIT | MEM_RESERVE': '0x3000', 'MEM_COMMIT': '0x1000', 'MEM_FREE': '0x10000',
             'MEM_RESERVE': '0x2000', 'MEM_IMAGE': '0x1000000', 'MEM_MAPPED': '0x40000', 'MEM_PRIVATE': '0x20000',
             'PAGE_EXECUTE': '0x10', 'PAGE_EXECUTE_READ': '0x20', 'PAGE_EXECUTE_READWRITE': '0x40',
             'PAGE_EXECUTE_WRITECOPY': '0x80', 'PAGE_NOACCESS': '0x01', 'PAGE_READONLY': '0x02',
             'PAGE_READWRITE': '0x04', 'PAGE_TARGETS_INVALID': '0x40000000', 'PAGE_TARGETS_NO_UPDATE': '0x40000000'}
MemReverseLookUp = {0x3000: 'MEM_COMMIT | MEM_RESERVE', 4096: 'MEM_COMMIT', 65536: 'MEM_FREE', 8192: 'MEM_RESERVE',
                    16777216: 'MEM_IMAGE', 262144: 'MEM_MAPPED', 131072: 'MEM_PRIVATE', 16: 'PAGE_EXECUTE',
                    32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                    1: 'PAGE_NOACCESS', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 1073741824: 'PAGE_TARGETS_NO_UPDATE'}
availMem = 0x25000000
lastErrorCode = 0x0
HeapsDict = {}  # Dictionary of All Heaps
HandlesDict = {}  # Dictionary of All Handles
RegistryKeys = {} # Dictionary of All Reg Keys

class HandleType(Enum):
    # Threads
    Thread = auto()
    # Process
    Process = auto()
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
    CreateFile2 = auto()
    CreateFileMappingA = auto()
    CreateFileMappingW = auto()
    CreateFileMappingNumaA = auto()
    CreateFileMappingNumaW = auto()
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
    # Module
    HMODULE = auto()
    # Desktop/Window
    HWND = auto()
    ClipBoard = auto()
    # Registry
    HKEY = auto()
    Transaction = auto()


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


class CustomWinAPIs():
    def GetProcAddress(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HMODULE', 'LPCSTR']
        pNames = ['hModule', 'lpProcName']
        
        name = read_string(uc, pVals[1])

        retVal = 0

        for api in export_dict:
            if export_dict[api][0] == name:
                retVal = int(api, 16)

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("GetProcAddress", hex(callAddr), hex(retVal), 'FARPROC', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LdrGetProcedureAddress(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        retVal = 0
        retValStr = 'STATUS_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("LdrGetProcedureAddress", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LoadLibraryA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['LPCTSTR']
        pNames = ['lpLibFileName']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)
        
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("LoadLibraryA", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LoadLibraryW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 1)
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
                print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                print(hex(eip), (len(name)))
                retVal = 0

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)
        
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("LoadLibraryW", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LoadLibraryExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCSTR', 'HANDLE', 'DWORD']
        pNames = ['lpLibFileName', 'hFile', 'dwFlags']
        dwFlagsReverseLookUp = {1: 'DONT_RESOLVE_DLL_REFERENCES', 16: 'LOAD_IGNORE_CODE_AUTHZ_LEVEL', 2: 'LOAD_LIBRARY_AS_DATAFILE', 64: 'LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE', 32: 'LOAD_LIBRARY_AS_IMAGE_RESOURCE', 512: 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR', 4096: 'LOAD_LIBRARY_SEARCH_DEFAULT_DIRS', 256: 'LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR', 2048: 'LOAD_LIBRARY_SEARCH_SYSTEM32', 1024: 'LOAD_LIBRARY_SEARCH_USER_DIRS', 8: 'LOAD_WITH_ALTERED_SEARCH_PATH', 128: 'LOAD_LIBRARY_REQUIRE_SIGNED_TARGET', 8192: 'LOAD_LIBRARY_SAFE_CURRENT_DIRS'}
        
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
                print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                print(hex(eip), (len(name)))
                retVal = 0

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("LoadLibraryExA", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LoadLibraryExW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCWSTR', 'HANDLE', 'DWORD']
        pNames = ['lpLibFileName', 'hFile', 'dwFlags']
        dwFlagsReverseLookUp = {1: 'DONT_RESOLVE_DLL_REFERENCES', 16: 'LOAD_IGNORE_CODE_AUTHZ_LEVEL', 2: 'LOAD_LIBRARY_AS_DATAFILE', 64: 'LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE', 32: 'LOAD_LIBRARY_AS_IMAGE_RESOURCE', 512: 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR', 4096: 'LOAD_LIBRARY_SEARCH_DEFAULT_DIRS', 256: 'LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR', 2048: 'LOAD_LIBRARY_SEARCH_SYSTEM32', 1024: 'LOAD_LIBRARY_SEARCH_USER_DIRS', 8: 'LOAD_WITH_ALTERED_SEARCH_PATH', 128: 'LOAD_LIBRARY_REQUIRE_SIGNED_TARGET', 8192: 'LOAD_LIBRARY_SAFE_CURRENT_DIRS'}

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
                print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                print(hex(eip), (len(name)))
                retVal = 0

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("LoadLibraryExW", hex(callAddr), retValStr, 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LdrLoadDll(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['PWCHAR', 'ULONG', 'PUNICODE_STRING', 'PHANDLE']
        pNames = ['PathToFile', 'Flags', 'ModuleFileName', 'ModuleHandle']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        flagsReverseLookUp = {1: 'DONT_RESOLVE_DLL_REFERENCES', 16: 'LOAD_IGNORE_CODE_AUTHZ_LEVEL', 2: 'LOAD_LIBRARY_AS_DATAFILE', 64: 'LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE', 32: 'LOAD_LIBRARY_AS_IMAGE_RESOURCE', 512: 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR', 4096: 'LOAD_LIBRARY_SEARCH_DEFAULT_DIRS', 256: 'LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR', 2048: 'LOAD_LIBRARY_SEARCH_SYSTEM32', 1024: 'LOAD_LIBRARY_SEARCH_USER_DIRS', 8: 'LOAD_WITH_ALTERED_SEARCH_PATH', 128: 'LOAD_LIBRARY_REQUIRE_SIGNED_TARGET', 8192: 'LOAD_LIBRARY_SAFE_CURRENT_DIRS'}

        unicode_string = struct_UNICODE_STRING(0, 0)
        unicode_string.readFromMemory(uc, pVals[2])
        name = read_unicode(uc, unicode_string.Buffer)

        try:
            moduleLoc = allDllsDict[name]
        except:
            try:
                nameL = name.lower()
                moduleLoc = allDllsDict[nameL]
            except:
                print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", name)
                moduleLoc = 0

        # uc.reg_write(UC_X86_REG_EAX, retVal)
        if moduleLoc != 0:
            handle = Handle(HandleType.HMODULE,name=name,handleValue=moduleLoc)
            uc.mem_write(pVals[3], pack("<I", handle.value))
        retVal = 0

        pVals[0] = read_unicode(uc, pVals[0])
        pVals[1] = getLookUpVal(pVals[1], flagsReverseLookUp)
        pVals[2] = makeStructVals(uc, unicode_string, pVals[2])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0,1,2])

        retValStr = getLookUpVal(retVal, CustomWinSysCalls.NTSTATUSReverseLookUp)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("LdrLoadDll", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def VirtualAlloc(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['LPVOID', 'SIZE_T', 'DWORD', 'DWORD']
        pNames = ['lpAddress', 'dwSize', 'flAllocationType', 'flProtect']
        flProtectReverseLookUp = {16: 'PAGE_EXECUTE', 32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 1: 'PAGE_NOACCESS', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 1073741824: 'PAGE_TARGETS_NO_UPDATE', 256: 'PAGE_GUARD', 512: 'PAGE_NOCACHE', 1024: 'PAGE_WRITECOMBINE'}
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

        pVals[2] = getLookUpVal(pVals[2], MemReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], flProtectReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualAlloc", hex(callAddr), hex(retVal), 'INT',pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualAllocEx(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'DWORD']
        pNames = ['hProcess', 'lpAddress', 'dwSize', 'flAllocationType', 'flProtect']
        flProtectReverseLookUp = {16: 'PAGE_EXECUTE', 32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 1: 'PAGE_NOACCESS', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 1073741824: 'PAGE_TARGETS_NO_UPDATE', 256: 'PAGE_GUARD', 512: 'PAGE_NOCACHE', 1024: 'PAGE_WRITECOMBINE'}
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

        pVals[3] = getLookUpVal(pVals[3], MemReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], flProtectReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("VirtualAllocEx", hex(callAddr), hex(retVal), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ExitProcess(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['UINT']
        pNames = ['uExitCode']

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0
        uc.reg_write(UC_X86_REG_EAX, retVal)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        logged_calls = ("ExitProcess", hex(callAddr), 'None', 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ["LPCSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD", "HANDLE"]
        pNames = ["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDistribution", "dwFlagsAndAttributes", "hTemplateFile"]
        dwDesiredAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
        dwShareModeReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE', 4: 'FILE_SHARE_DELETE'}
        dwCreationDistributionReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING', 3: 'OPEN_EXISTING', 5: 'TRUNCATE_EXISTING'}
        dwFlagsAndAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 16384: 'FILE_ATTRIBUTE_ENCRYPTED', 2: 'FILE_ATTRIBUTE_HIDDEN', 128: 'FILE_ATTRIBUTE_NORMAL', 4096: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY', 4: 'FILE_ATTRIBUTE_SYSTEM', 256: 'FILE_ATTRIBUTE_TEMPORARY', 33554432: 'FILE_FLAG_BACKUP_SEMANTICS', 67108864: 'FILE_FLAG_DELETE_ON_CLOSE', 536870912: 'FILE_FLAG_NO_BUFFERING', 1048576: 'FILE_FLAG_OPEN_NO_RECALL', 2097152: 'FILE_FLAG_OPEN_REPARSE_POINT', 1073741824: 'FILE_FLAG_OVERLAPPED', 16777216: 'FILE_FLAG_POSIX_SEMANTICS', 268435456: 'FILE_FLAG_RANDOM_ACCESS', 8388608: 'FILE_FLAG_SESSION_AWARE', 134217728: 'FILE_FLAG_SEQUENTIAL_SCAN', 2147483648: 'FILE_FLAG_WRITE_THROUGH'}
        
        handle = Handle(HandleType.CreateFileA)

        pVals[1] = getLookUpVal(pVals[1],dwDesiredAccessReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2],dwShareModeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4],dwCreationDistributionReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5],dwFlagsAndAttributesReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        stackCleanup(uc, em, esp, len(pTypes))
        cleanBytes = 0
        logged_calls = ("CreateFileA", hex(callAddr), retValStr, 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFileW(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateFileW([in] LPCWSTR lpFileName,[in] DWORD dwDesiredAccess,[in] DWORD dwShareMode,[in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,[in] DWORD dwCreationDisposition,[in] DWORD dwFlagsAndAttributes,[in, optional] HANDLE hTemplateFile);
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes=['LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'HANDLE']
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
        skip = [1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualProtect(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL VirtualProtect([in]  LPVOID lpAddress,[in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect)
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
        pNames = ['lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']

        pVals[2] = getLookUpVal(pVals[2],MemReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualProtect", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualProtectEx(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL VirtualProtectEx([in]  HANDLE hProcess, [in]  LPVOID lpAddress, [in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect);
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
        pNames = ['hProcess', 'lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']

        pVals[3] = getLookUpVal(pVals[3],MemReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualProtectEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualFree(self, uc, eip, esp, export_dict, callAddr, em):
        # 'VirtualFree': (3, ['LPVOID', 'SIZE_T', 'DWORD'], ['lpAddress', 'dwSize', 'dwFreeType'], 'BOOL'),
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPVOID', 'SIZE_T', 'DWORD']
        pNames = ['lpAddress', 'dwSize', 'dwFreeType']
        memReleaseReverseLookUp = {16384: 'MEM_DECOMMIT', 32768: 'MEM_RELEASE', 1: 'MEM_COALESCE_PLACEHOLDERS',
                                   2: 'MEM_PRESERVE_PLACEHOLDER',
                                   0x00004001: 'MEM_DECOMMIT | MEM_COALESCE_PLACEHOLDERS',
                                   0x00004002: 'MEM_DECOMMIT | MEM_PRESERVE_PLACEHOLDER',
                                   0x00008001: 'MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS',
                                   0x00008002: 'MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER'}
        
        pVals[2] = getLookUpVal(pVals[2],memReleaseReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualFree", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def WSASocketA(self, uc, eip, esp, export_dict, callAddr, em):
        # 'WSASocketA': (6, ['INT', 'INT', 'INT', 'LPWSAPROTOCOL_INFOA', 'GROUP', 'DWORD'], ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags'], 'SOCKET'),
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['int', 'int', 'int', 'LPWSAPROTOCOL_INFOA', 'GROUP', 'DWORD']
        pNames = ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags']
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
        
        # create strings for everything except ones in our skip
        skip = [0, 1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WSASocketA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def WSASocketW(self, uc, eip, esp, export_dict, callAddr, em):
        # 'WSASocketW': (6, ['INT', 'INT', 'INT', 'LPWSAPROTOCOL_INFOW', 'GROUP', 'DWORD'], ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags'], 'SOCKET'),
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['int', 'int', 'int', 'LPWSAPROTOCOL_INFOW', 'GROUP', 'DWORD']
        pNames = ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags']
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

        # create strings for everything except ones in our skip
        skip = [0, 1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WSASocketW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def socket(self, uc, eip, esp, export_dict, callAddr, em):
        # SOCKET WSAAPI socket([in] int af, [in] int type, [in] int protocol)
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['int', 'int', 'int']
        pNames = ['af', 'type', 'protocol']
        aFReverseLookUp = {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 16: 'AF_APPLETALK', 17: 'AF_NETBIOS',
                           23: 'AF_INET6', 26: 'AF_IRDA', 32: 'AF_BTH'}
        sockTypeReverseLookUp = {1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 4: 'SOCK_RDM', 5: 'SOCK_SEQPACKET'}
        sockProtocolReverseLookUp = {1: 'IPPROTO_ICMP', 2: 'IPPROTO_IGMP', 3: 'BTHPROTO_RFCOMM', 6: 'IPPROTO_TCP',
                                     17: 'IPPROTO_UDP', 58: 'IPPROTO_ICMPV6', 113: 'IPPROTO_RM'}

        pVals[0] = getLookUpVal(pVals[0],aFReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],sockTypeReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2],sockProtocolReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0, 1, 2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("socket", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def BroadcastSystemMessageA(self, uc, eip, esp, export_dict, callAddr, em):
        # long BroadcastSystemMessage([in] DWORD   flags, [in, out, optional] LPDWORD lpInfo,
        # [in] UINT Msg, [in]  WPARAM  wParam, [in]  LPARAM  lParam );
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['DWORD', 'LPDWORD', 'UINT', 'WPARAM', 'LPARAM']
        pNames = ['flags', 'lpInfo', 'Msg', 'wParam', 'lParam']
        flagsReverseLookUp = {0x00000080: 'BSF_ALLOWSFW', 0x00000004: 'BSF_FLUSHDISK', 0x00000020: 'BSF_FORCEIFHUNG',
                              0x00000002: 'BSF_IGNORECURRENTTASK', 0x00000008: 'BSF_NOHANG',
                              0x00000040: 'BSF_NOTIMEOUTIFNOTHUNG', 0x00000010: 'BSF_POSTMESSAGE',
                              0x00000001: 'BSF_QUERY', 0x00000100: 'BSF_SENDNOTIFYMESSAGE'}
        lpInfoReverseLookUp = {0x00000000: 'BSM_ALLCOMPONENTS', 0x00000010: 'BSM_ALLDESKTOPS',
                               0x00000008: 'BSM_APPLICATIONS'}

        pVals[0] = getLookUpVal(pVals[0],flagsReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],lpInfoReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0, 1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("BroadcastSystemMessageA", hex(callAddr), (retValStr), 'long', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def BroadcastSystemMessageW(self, uc, eip, esp, export_dict, callAddr, em):
        # long BroadcastSystemMessage([in] DWORD   flags, [in, out, optional] LPDWORD lpInfo,
        # [in] UINT Msg, [in]  WPARAM  wParam, [in]  LPARAM  lParam );
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['DWORD', 'LPDWORD', 'UINT', 'WPARAM', 'LPARAM']
        pNames = ['flags', 'lpInfo', 'Msg', 'wParam', 'lParam']
        flagsReverseLookUp = {0x00000080: 'BSF_ALLOWSFW', 0x00000004: 'BSF_FLUSHDISK', 0x00000020: 'BSF_FORCEIFHUNG',
                              0x00000002: 'BSF_IGNORECURRENTTASK', 0x00000008: 'BSF_NOHANG',
                              0x00000040: 'BSF_NOTIMEOUTIFNOTHUNG', 0x00000010: 'BSF_POSTMESSAGE',
                              0x00000001: 'BSF_QUERY', 0x00000100: 'BSF_SENDNOTIFYMESSAGE'}
        lpInfoReverseLookUp = {0x00000000: 'BSM_ALLCOMPONENTS', 0x00000010: 'BSM_ALLDESKTOPS',
                               0x00000008: 'BSM_APPLICATIONS'}

        pVals[0] = getLookUpVal(pVals[0],flagsReverseLookUp)
        pVals[1] = getLookUpVal(pVals[1],lpInfoReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0, 1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("BroadcastSystemMessageW", hex(callAddr), (retValStr), 'long', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateThread(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpThreadId']
        dwCreateFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        handle = Handle(HandleType.Thread)

        # Round up to next page (4096)
        pVals[1] = ((pVals[1] // 4096) + 1) * 4096

        pVals[4] = getLookUpVal(pVals[4],dwCreateFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateRemoteThread(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['hProcess', 'lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags',
                  'lpThreadId']
        dwCreationFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        handle = Handle(HandleType.Thread)

        # Round up to next page (4096)
        pVals[2] = ((pVals[2] // 4096) + 1) * 4096

        pVals[5] = getLookUpVal(pVals[5],dwCreationFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateRemoteThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes


    def CreateRemoteThreadEx(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPPROC_THREAD_ATTRIBUTE_LIST', 'LPDWORD']
        pNames = ['hProcess', 'lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpAttributeList', 'lpThreadId']
        dwCreationFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        handle = Handle(HandleType.Thread)

        # Round up to next page (4096)
        pVals[2] = ((pVals[2] // 4096) + 1) * 4096

        pVals[5] = getLookUpVal(pVals[5],dwCreationFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateRemoteThreadEx", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateServiceA(self, uc, eip, esp, export_dict, callAddr, em):
        # SC_HANDLE CreateServiceA([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
        pVals = makeArgVals(uc, em, esp, 13)
        pTypes=['SC_HANDLE', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'LPCSTR', 'LPDWORD', 'LPCSTR', 'LPCSTR', 'LPCSTR']
        pNames=['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType', 'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies', 'lpServiceStartName', 'lpPassword']
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

        # create strings for everything except ones in our skip
        skip = [3, 4, 5, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateServiceA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateServiceW(self, uc, eip, esp, export_dict, callAddr, em):
        # SC_HANDLE CreateServiceW([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
        pVals = makeArgVals(uc, em, esp, 13)
        pTypes=['SC_HANDLE', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR', 'LPCWSTR', 'LPDWORD', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR']
        pNames=['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType', 'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies', 'lpServiceStartName', 'lpPassword']
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

        #create strings for everything except ones in our skip
        skip = [3, 4, 5, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateServiceW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def OpenServiceA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['SC_HANDLE', 'LPCSTR', 'DWORD']
        pNames = ['hSCManager', 'lpServiceName', 'dwDesiredAccess']
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

    def OpenServiceW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['SC_HANDLE', 'LPCWSTR', 'DWORD']
        pNames = ['hSCManager', 'lpServiceName', 'dwDesiredAccess']
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

    def StartServiceA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['SC_HANDLE', 'DWORD', 'LPCSTR *']
        pNames = ['hService', 'dwNumServiceArgs', 'lpServiceArgVectors']

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("StartServiceA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def StartServiceW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['SC_HANDLE', 'DWORD', 'LPCWSTR *']
        pNames = ['hService', 'dwNumServiceArgs', 'lpServiceArgVectors']

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("StartServiceW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def ControlService(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['SC_HANDLE', 'DWORD', 'LPSERVICE_STATUS']
        pNames = ['hService', 'dwControl', 'lpServiceStatus']
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

    def ControlServiceExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['SC_HANDLE', 'DWORD', 'DWORD', 'PVOID']
        pNames = ['hService', 'dwControl', 'dwInfoLevel', 'pControlParams']
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

    def ControlServiceExW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['SC_HANDLE', 'DWORD', 'DWORD', 'PVOID']
        pNames = ['hService', 'dwControl', 'dwInfoLevel', 'pControlParams']
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

    def DeleteService(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['SC_HANDLE']
        pNames = ['hService']

        if pVals[0] in HandlesDict:
            HandlesDict.pop(pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("DeleteService", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CloseServiceHandle(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['SC_HANDLE']
        pNames = ['hSCObject']

        if pVals[0] in HandlesDict:
            HandlesDict.pop(pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CloseServiceHandle", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CryptDecrypt(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HCRYPTKEY', 'HCRYPTHASH', 'BOOL', 'DWORD', 'BYTE', 'DWORD']
        pNames = ['hKey', 'hHash', 'Final', 'dwFlags', 'pbData', 'pdwDataLen']

        dwFlagsReverseLookUp = {64: 'CRYPT_OAEP', 32: 'CRYPT_DECRYPT_RSA_NO_PADDING_CHECK'}

        pVals[3] = getLookUpVal(pVals[3],dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptDecrypt", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HeapCreate(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE HeapCreate([in] DWORD  flOptions,[in] SIZE_T dwInitialSize,[in] SIZE_T dwMaximumSize);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['DWORD', 'SIZE_T', 'SIZE_T']
        pNames = ['flOptions', 'dwInitialSize', 'dwMaximumSize']
        flOptionsReverseLookUp = {0x00040000: 'HEAP_CREATE_ENABLE_EXECUTE', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                  0x00000001: 'HEAP_NO_SERIALIZE'}

        heap = Heap(uc, 0, pVals[2])

        pVals[0] = getLookUpVal(pVals[0], flOptionsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = heap.handle
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapCreate", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HeapAlloc(self, uc, eip, esp, export_dict, callAddr, em):
        # DECLSPEC_ALLOCATOR LPVOID HeapAlloc([in] HANDLE hHeap, [in] DWORD  dwFlags, [in] SIZE_T dwBytes)
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HANDLE', 'DWORD', 'SIZE_T']
        pNames = ['hHeap', 'dwFlags', 'dwBytes']
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

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = allocation.address
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapAlloc", hex(callAddr), (retValStr), 'LPVOID', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HeapDestroy(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL HeapDestroy([in] HANDLE hHeap);
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HANDLE']
        pNames = ['hHeap']

        try:
            heap = HeapsDict[pVals[0]]
            heap.destroy(uc)
        except:
            pass

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapDestroy", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HeapFree(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL HeapFree([in] HANDLE hHeap,[in] DWORD dwFlags,[in] _Frees_ptr_opt_ LPVOID lpMem);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HANDLE', 'DWORD', '_Frees_ptr_opt_ LPVOID']
        pNames = ['hHeap', 'dwFlags', 'lpMem']
        dwFlagsReverseLookUp = {0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                0x00000001: 'HEAP_NO_SERIALIZE'}

        try:
            heap = HeapsDict[pVals[0]]
            heap.free(uc, pVals[2])
        except:
            pass

        pVals[1] = getLookUpVal(pVals[1], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HeapSize(self, uc, eip, esp, export_dict, callAddr, em):
        # SIZE_T HeapSize([in] HANDLE  hHeap,[in] DWORD   dwFlags,[in] LPCVOID lpMem);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HANDLE', 'DWORD', 'LPCVOID']
        pNames = ['hHeap', 'dwFlags', 'lpMem']
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

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapSize", hex(callAddr), (retValStr), 'SIZE_T', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HeapReAlloc(self, uc, eip, esp, export_dict, callAddr, em):
        # DECLSPEC_ALLOCATOR LPVOID HeapReAlloc([in] HANDLE hHeap,[in] DWORD dwFlags,[in] _Frees_ptr_opt_ LPVOID lpMem,[in] SIZE_T dwBytes);
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HANDLE', 'DWORD', '_Frees_ptr_opt_ LPVOID', 'SIZE_T']
        pNames = ['hHeap', 'dwFlags', 'lpMem', 'dwBytes']
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

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = allocation.address
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapReAlloc", hex(callAddr), (retValStr), 'LPVOID', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetProcessHeap(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE GetProcessHeap()
        pVals = makeArgVals(uc, em, esp, 0)
        pTypes = []
        pNames = []

        # Create new Heap
        heap = Heap(uc, 0, 4096)

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = heap.handle
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetProcessHeap", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetProcessHeaps(self, uc, eip, esp, export_dict, callAddr, em):
        # 'GetProcessHeaps': (2, ['DWORD', 'PHANDLE'], ['NumberOfHeaps', 'ProcessHeaps'], 'DWORD'),
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['DWORD', 'PHANDLE']
        pNames = ['NumberOfHeaps', 'ProcessHeaps']

        # Get Heaps from Heap Dict
        total = 0
        for heap in HeapsDict:
            uc.mem_write(pVals[1] + (total * 4), pack('<I', HeapsDict[heap].handle))
            total += 1
            if total == pVals[0]:  # Write up to NumberOfHeaps to Memory
                break

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = total
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetProcessHeaps", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateToolhelp32Snapshot(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['DWORD', 'DWORD']
        pNames = ['dwFlags', 'th32ProcessID']
        dwFlagsReverseLookUp = {2147483648: 'TH32CS_INHERIT', 15: 'TH32CS_SNAPALL', 1: 'TH32CS_SNAPHEAPLIST',
                                8: 'TH32CS_SNAPMODULE', 16: 'TH32CS_SNAPMODULE32', 2: 'TH32CS_SNAPPROCESS',
                                4: 'TH32CS_SNAPTHREAD', 15: 'TH32CS_SNAPALL'}

        SnapShot = System_SnapShot(True, True)
        handle = Handle(HandleType.CreateToolhelp32Snapshot, data=SnapShot)

        pVals[0] = getLookUpVal(pVals[0], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateToolhelp32Snapshot", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Process32First(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32First([in] HANDLE hSnapshot,[in, out] LPPROCESSENTRY32 lppe);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPPROCESSENTRY32']
        pNames = ['hSnapshot', 'lppe']

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

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Process32Next(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32Next([in]  HANDLE hSnapshot,[out] LPPROCESSENTRY32 lppe);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPPROCESSENTRY32']
        pNames = ['hSnapshot', 'lppe']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Process32FirstW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32FirstW([in] HANDLE hSnapshot,[in, out] LPPROCESSENTRY32W lppe);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPPROCESSENTRY32W']
        pNames = ['hSnapshot', 'lppe']

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

            # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32FirstW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Process32NextW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Process32NextW([in]  HANDLE hSnapshot,[out] LPPROCESSENTRY32W lppe);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPPROCESSENTRY32W']
        pNames = ['hSnapshot', 'lppe']

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

            # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Process32NextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Thread32First(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Thread32First([in] HANDLE hSnapshot,[in, out] LPTHREADENTRY32 lpte);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPTHREADENTRY32']
        pNames = ['hSnapshot', 'lpte']

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

            # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Thread32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Thread32Next(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Thread32Next([in] HANDLE hSnapshot,[out] LPTHREADENTRY32 lpte);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPTHREADENTRY32']
        pNames = ['hSnapshot', 'lpte']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Thread32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Module32First(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32First([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32 lpme);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPMODULEENTRY32']
        pNames = ['hSnapshot', 'lpme']

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

            # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32First", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Module32Next(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32Next([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32 lpme);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPMODULEENTRY32']
        pNames = ['hSnapshot', 'lpme']

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

            # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32Next", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Module32FirstW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32FirstW([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32W lpme);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPMODULEENTRY32']
        pNames = ['hSnapshot', 'lpme']

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

            # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32FirstW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Module32NextW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL Module32NextW([in] HANDLE hSnapshot,[in, out] LPMODULEENTRY32W lpme);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'LPMODULEENTRY32W']
        pNames = ['hSnapshot', 'lpme']

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

            # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Module32NextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Toolhelp32ReadProcessMemory2(self, uc, eip, esp, export_dict, callAddr, em): # Needs to be Redone 
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['DWORD', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T']
        pNames = ['th32ProcessID', 'lpBaseAddress', 'lpBuffer', 'cbRead', 'lpNumberOfBytesRead']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("Toolhelp32ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    # Memory Functions
    def WriteProcessMemory(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL WriteProcessMemory([in]  HANDLE  hProcess,[in]  LPVOID  lpBaseAddress,[in]  LPCVOID lpBuffer,[in]  SIZE_T  nSize,[out] SIZE_T  *lpNumberOfBytesWritten);
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HANDLE', 'LPVOID', 'LPCVOID', 'SIZE_T', 'SIZE_T']
        pNames = ['hProcess', 'lpBaseAddress', 'lpBuffer', 'nSize', '*lpNumberOfBytesWritten']

        try:
            buffer = uc.mem_read(pVals[2], pVals[3])
            fmt = '<' + str(pVals[3]) + 's'
            uc.mem_write(pVals[1], pack(fmt, buffer))
            uc.mem_write(pVals[4], pack('<I',pVals[3]))
        except:
            pass

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WriteProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def memcpy(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['void', 'const void', 'size_t']
        pNames = ['*dest', '*src', 'count']

        try:
            buffer = uc.mem_read(pVals[1], pVals[2])
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        retVal = pVals[0]

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memcpy", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def memcpy_s(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['void', 'size_t', 'const void', 'size_t']
        pNames = ['*dest', 'destSize', '*src', 'count']

        try:
            buffer = uc.mem_read(pVals[2], pVals[3])
            fmt = '<' + str(pVals[1]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memcpy_s", hex(callAddr), (retValStr), 'errno_t', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def memmove(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['void', 'const void', 'size_t']
        pNames = ['*dest', '*src', 'count']

        try:
            buffer = uc.mem_read(pVals[1], pVals[2])
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        retVal = pVals[0]

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memmove", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def memmove_s(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['void', 'size_t', 'const void', 'size_t']
        pNames = ['*dest', 'numberOfElements', '*src', 'count']

        try:
            buffer = uc.mem_read(pVals[2], pVals[3])
            fmt = '<' + str(pVals[1]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memmove_s", hex(callAddr), (retValStr), 'errno_t', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def memset(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['void', 'int', 'size_t']
        pNames = ['*dest', 'c', 'count']

        try:
            buffer = uc.mem_read(pVals[0], pVals[2])
            for i in range(pVals[2]):
                buffer[i] = pVals[1]
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        retVal = pVals[0]

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memset", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def memcmp(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['const void', 'const void', 'size_t']
        pNames = ['*buffer1', '*buffer2', 'count']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memcmp", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def memchr(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['const void', 'int', 'size_t']
        pNames = ['*buffer', 'c', 'count']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        if retVal == 0:
            retValStr = 'NULL'
        else:
            retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("memchr", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RtlMoveMemory(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['VOID UNALIGNED', 'VOID UNALIGNED', 'SIZE_T']
        pNames = ['*Destination', '*Source', 'Length']

        try:
            buffer = uc.mem_read(pVals[1], pVals[2])
            fmt = '<' + str(pVals[2]) + 's'
            uc.mem_write(pVals[0], pack(fmt, buffer))
        except:
            pass

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = ''

        logged_calls = ("RtlMoveMemory", hex(callAddr), (retValStr), 'VOID', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ReadProcessMemory(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL ReadProcessMemory([in]  HANDLE  hProcess,[in]  LPCVOID lpBaseAddress,[out] LPVOID  lpBuffer,[in]  SIZE_T  nSize,[out] SIZE_T  *lpNumberOfBytesRead);
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HANDLE', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T']
        pNames = ['hProcess', 'lpBaseAddress', 'lpBuffer', 'nSize', '*lpNumberOfBytesRead']

        try:
            buffer = uc.mem_read(pVals[1], pVals[3])
            fmt = '<' + str(pVals[3]) + 's'
            uc.mem_write(pVals[2], pack(fmt, buffer))
            if pVals[4] != 0x0:
                uc.mem_write(pVals[4], pack('<I', len(buffer)))
        except:
            pass

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateProcessA(self, uc, eip, esp, export_dict, callAddr, em):
        # print ("CreateProcessA2")
        """'CreateProcess': (10, ['LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION'], ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation'], 'BOOL'),"""

        # function to get values for parameters - count as specified at the end - returned as a list
        pVals = makeArgVals(uc, em, esp, 10)
        pTypes = ['LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID',
                  'LPCSTR',
                  'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
        pNames = ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles',
                  'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']

        pVals[5] = getLookUpVal(pVals[5], ProcessCreationReverseLookUp)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = struct_PROCESS_INFORMATION(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[9])

        pVals[9] = makeStructVals(uc, processInfo, pVals[9])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5,9])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 10)
        pTypes = ['LPCWSTR', 'LPWSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID',
                  'LPCWSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
        pNames = ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles',
                  'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']

        pVals[5] = getLookUpVal(pVals[5], ProcessCreationReverseLookUp)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = struct_PROCESS_INFORMATION(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[9])

        pVals[9] = makeStructVals(uc, processInfo, pVals[9])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[5,9])

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessInternalA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 12)
        pTypes = ['DWORD', 'LPCTSTR', 'LPTSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID',
                  'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION', 'DWORD']
        pNames = ['unknown1', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation', 'unknown2']

        pVals[6] = getLookUpVal(pVals[6], ProcessCreationReverseLookUp)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = struct_PROCESS_INFORMATION(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessInternalA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessInternalW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 12)
        pTypes = ['DWORD', 'LPCTWSTR', 'LPTWSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID', 'LPCSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION', 'DWORD']
        pNames = ['unknown1', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation', 'unknown2']

        pVals[6] = getLookUpVal(pVals[6], ProcessCreationReverseLookUp)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = struct_PROCESS_INFORMATION(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessInternalW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def CreateProcessAsUserA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 11)
        pTypes = ['HANDLE', 'LPCSTR', 'LPSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID',
                  'LPCSTR', 'LPSTARTUPINFOA', 'LPPROCESS_INFORMATION']
        pNames = ['hToken', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation']

        pVals[6] = getLookUpVal(pVals[6], ProcessCreationReverseLookUp)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = struct_PROCESS_INFORMATION(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessAsUserA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateProcessAsUserW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 11)
        pTypes = ['HANDLE', 'LPCWSTR', 'LPWSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD',
                  'LPVOID', 'LPCWSTR', 'LPSTARTUPINFOW', 'LPPROCESS_INFORMATION']
        pNames = ['hToken', 'lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes',
                  'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo',
                  'lpProcessInformation']

        pVals[6] = getLookUpVal(pVals[6], ProcessCreationReverseLookUp)

        hProcess = Handle(HandleType.Process)
        hThread = Handle(HandleType.Thread)
        processInfo = struct_PROCESS_INFORMATION(hProcess.value, hThread.value)
        processInfo.writeToMemory(uc, pVals[10])

        pVals[10] = makeStructVals(uc, processInfo, pVals[10])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[6,10])

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateProcessAsUserW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLDownloadToFileA(self, uc, eip, esp, export_dict, callAddr, em):
        # function to get values for parameters - count as specified at the end - returned as a list
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToFileA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLDownloadToCacheFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'LPTSTR', 'DWORD', 'DWORD', 'IBindStatusCallback']
        pNames = ['lpUnkCaller', 'szURL', 'szFileName', 'cchFileName', 'dwReserved', '*pBSC']

        skip = []  
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToCacheFileA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLDownloadToCacheFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'IBindStatusCallback']
        pNames = ['lpUnkCaller', 'szURL', 'szFileName', 'cchFileName', 'dwReserved', '*pBSC']

        skip = [] 
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToCacheFileW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLDownloadToFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToFileW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def WinExec(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPCSTR', 'UINT']
        pNames = ['lpCmdLine', 'uCmdShow']
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

    
        pVals[1] = getLookUpVal(pVals[1], cmdShowReverseLookUp)
    
        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        #get the commandline from the arguments
        winexec_args = (pVals[0])
        art.commandLine_HookApis.add(winexec_args)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WinExec", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ShellExecuteA(self, uc, eip, esp, export_dict, callAddr, em):
        # HINSTANCE ShellExecuteA([in, optional] HWND   hwnd, [in, optional] LPCSTR lpOperation,[in] LPCSTR lpFile,
        # [in, optional] LPCSTR lpParameters, [in, optional] LPCSTR lpDirectory, [in] INT    nShowCmd);
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'INT']
        pNames = ['hwnd', 'lpOperation', 'lpFile', 'lpParameters', 'lpDirectory', 'nShowCmd']
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

        pVals[5] = getLookUpVal(pVals[5], cmdShowReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ShellExecuteA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ShellExecuteW(self, uc, eip, esp, export_dict, callAddr, em):
        # HINSTANCE ShellExecuteW([in, optional] HWND   hwnd, [in, optional] LPCSTR lpOperation,[in] LPCSTR lpFile,
        # [in, optional] LPCSTR lpParameters, [in, optional] LPCSTR lpDirectory, [in] INT    nShowCmd);
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HWND', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'INT']
        pNames = ['hwnd', 'lpOperation', 'lpFile', 'lpParameters', 'lpDirectory', 'nShowCmd']
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

        pVals[5] = getLookUpVal(pVals[5], cmdShowReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ShellExecuteW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def system(self, uc, eip, esp, export_dict, callAddr, em):
        # int system(const char *command);
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['const char']
        pNames = ['*command']

        pVals[0] = read_string(uc, pVals[0])

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        system_args = (pVals[0])
        commandLine_HookApis.add(system_args)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("system", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def _wsystem(self, uc, eip, esp, export_dict, callAddr, em):
        # int _wsystem(const wchar_t *command);
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['const wchar_t']
        pNames = ['*command']

        pVals[0] = read_unicode(uc, pVals[0])

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        wsystem_args = (pVals[0])
        commandLine_HookApis.add(wsystem_args)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("_wsystem", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetOpenA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPCSTR', 'DWORD', 'LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpszAgent', 'dwAccessType', 'lpszProxy', 'lpszProxyBypass', 'dwFlags']

        dwAccessTypeReverseLookUp = {0: 'INTERNET_OPEN_TYPE_PRECONFIG', 1: 'INTERNET_OPEN_TYPE_DIRECT',
                                     3: 'INTERNET_OPEN_TYPE_PROXY', 4: 'INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY'}
        dwFlagsReverseLookUp = {268435456: 'INTERNET_FLAG_ASYNC', 16777216: 'INTERNET_FLAG_FROM_CACHE'}

        pVals[1] = getLookUpVal(pVals[1], dwAccessTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00626262
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetOpenW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPCWSTR', 'DWORD', 'LPCWSTR', 'LPCWSTR', 'DWORD']
        pNames = ['lpszAgent', 'dwAccessType', 'lpszProxy', 'lpszProxyBypass', 'dwFlags']

        dwAccessTypeReverseLookUp = {0: 'INTERNET_OPEN_TYPE_PRECONFIG', 1: 'INTERNET_OPEN_TYPE_DIRECT',
                                     3: 'INTERNET_OPEN_TYPE_PROXY', 4: 'INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY'}
        dwFlagsReverseLookUp = {268435456: 'INTERNET_FLAG_ASYNC', 16777216: 'INTERNET_FLAG_FROM_CACHE'}

        pVals[1] = getLookUpVal(pVals[1], dwAccessTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00737373
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetConnectA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['HINTERNET', 'LPCSTR', 'INTERNET_PORT', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszServerName', 'nServerPort', 'lpszUserName', 'lpszPassword', 'dwService', 'dwFlags',
                  'dwContext']

        nServerPortReverseLookUp = {0: 'INTERNET_INVALID_PORT_NUMBER', 33: 'INTERNET_DEFAULT_FTP_PORT',
                                    112: 'INTERNET_DEFAULT_GOPHER_PORT', 128: 'INTERNET_DEFAULT_HTTP_PORT',
                                    1091: 'INTERNET_DEFAULT_HTTPS_PORT', 4224: 'INTERNET_DEFAULT_SOCKS_PORT'}
        dwServiceReverseLookUp = {1: 'INTERNET_SERVICE_FTP', 2: 'INTERNET_SERVICE_GOPHER', 3: 'INTERNET_SERVICE_HTTP'}
        dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 134217728: 'INTERNET_FLAG_PASSIVE',
                                1: 'WININET_API_FLAG_ASYNC', 4: 'WININET_API_FLAG_SYNC'}

        pVals[2] = getLookUpVal(pVals[2], nServerPortReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], dwServiceReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 5, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00636363
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetConnectA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetConnectW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['HINTERNET', 'LPCWSTR', 'INTERNET_PORT', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszServerName', 'nServerPort', 'lpszUserName', 'lpszPassword', 'dwService', 'dwFlags',
                  'dwContext']

        nServerPortReverseLookUp = {0: 'INTERNET_INVALID_PORT_NUMBER', 33: 'INTERNET_DEFAULT_FTP_PORT',
                                    112: 'INTERNET_DEFAULT_GOPHER_PORT', 128: 'INTERNET_DEFAULT_HTTP_PORT',
                                    1091: 'INTERNET_DEFAULT_HTTPS_PORT', 4224: 'INTERNET_DEFAULT_SOCKS_PORT'}
        dwServiceReverseLookUp = {1: 'INTERNET_SERVICE_FTP', 2: 'INTERNET_SERVICE_GOPHER', 3: 'INTERNET_SERVICE_HTTP'}
        dwFlagsReverseLookUp = {536870912: 'INTERNET_FLAG_EXISTING_CONNECT', 134217728: 'INTERNET_FLAG_PASSIVE',
                                1: 'WININET_API_FLAG_ASYNC', 4: 'WININET_API_FLAG_SYNC'}

        pVals[2] = getLookUpVal(pVals[2], nServerPortReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], dwServiceReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 5, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00727272
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetConnectW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RegCreateKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 9)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'LPSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition']
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 9)
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'LPWSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition']
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
        pVals = makeArgVals(uc, em, esp, 3)
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

        logged_calls = ("RegCreateKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegCreateKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCWSTR', 'PHKEY']
        pNames = ['hkey', 'lpSubKey', 'phkResult']

        

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
        pVals = makeArgVals(uc, em, esp, 11)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'LPSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD','HANDLE','PVOID']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition','hTransaction','pExtendedParemeter']
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
        pVals = makeArgVals(uc, em, esp, 11)
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'LPWSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD','HANDLE','PVOID']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes','phkResult','lpdwDisposition','hTransaction','pExtendedParemeter']
        dwOptionsReverseLookUp = {4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK',
                                  0: 'REG_OPTION_NON_VOLATILE',
                                  1: 'REG_OPTION_VOLATILE'}
        lpdwDispostitionReverseLookUp = {1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}

        global registry_add_values

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
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult','hTransaction','pExtendedParemeter']

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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult','hTransaction','pExtendedParemeter']

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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
        pVals = makeArgVals(uc, em, esp, 3)
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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCWSTR', 'PHKEY']
        pNames = ['hkey', 'lpSubKey', 'phkResult']

        

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

    def RegDeleteKeyA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey']
        
        
        

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteKeyW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey']
        
        

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteKeyExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCSTR', 'REGSAM', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved']
        
        

        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteKeyExW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCWSTR', 'REGSAM', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved']

        


        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteKeyTransactedA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCSTR', 'REGSAM', 'DWORD', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved', 'hTransaction', 'pExtendedParameter']

        

        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteKeyTransactedW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCWSTR', 'REGSAM', 'DWORD', 'HANDLE', 'PVOID']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved', 'hTransaction', 'pExtendedParameter']

        

        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        pVals[2] = getLookUpVal(pVals[2], samDesiredReverseLookUp)

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteTreeA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey']
        
        

        keysToDelete = set()

        keyPath = ''
        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys:
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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
            print(keyPath)
            art.registry_delete_keys.add(keyPath)
            for rKey in keysToDelete:
                rKey.deleteKey()

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)


        logged_calls = ("RegDeleteTreeA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegDeleteTreeW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey']
        
        

        keysToDelete = set()

        keyPath = ''
        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys:
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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
            print(keyPath)
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
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPDWORD', 'PVOID', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValue', 'dwFlags', 'pdwType', 'pvData', 'pcbData']

        

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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
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
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPDWORD', 'PVOID', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValue', 'dwFlags', 'pdwType', 'pvData', 'pcbData']

        

        dwFlagsReverseLookUp = {65535: 'RRF_RT_ANY', 24: 'RRF_RT_DWORD', 72: 'RRF_RT_QWORD', 8: 'RRF_RT_REG_BINARY',16: 'RRF_RT_REG_DWORD', 4: 'RRF_RT_REG_EXPAND_SZ', 32: 'RRF_RT_REG_MULTI_SZ',1: 'RRF_RT_REG_NONE', 64: 'RRF_RT_REG_QWORD', 2: 'RRF_RT_REG_SZ',268435456: 'RRF_NOEXPAND',536870912: 'RRF_ZEROONFAILURE', 65536: 'RRF_SUBKEY_WOW6464KEY',131072: 'RRF_SUBKEY_WOW6432KEY'}

        lpSubKey = read_unicode(uc, pVals[1])
        lpValue = read_unicode(uc, pVals[2])

        keyPath = ''
        keyValue = None

        if lpSubKey == '[NULL]':
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
                        registry_key_address = foundKey
                        if lpValue == '[NULL]':

                            keyValue = foundKey.getValue()
                        else:
                            keyValue = foundKey.getValue(lpValue)

        if keyValue is not None:
            # info grab here 
            print(keyValue.name)
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
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCSTR', 'LPSTR', 'PLONG']
        pNames = ['hKey', 'lpSubKey', 'lpData', 'lpcbData']

        

        lpSubKey = read_string(uc, pVals[1])
        pVals[1] = lpSubKey

        keyPath = ''
        keyValue = None

        if lpSubKey == '[NULL]':
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
                        keyValue = foundKey.getValue()
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
                        keyValue = foundKey.getValue()
                    else:
                        rKey = RegKey(keyPath)
                        keyValue = rKey.getValue()

        if keyValue is not None:
            # info grab here 
            # registry_keys.add()
            # print(keyValue.name)
            #registry_values.add(())
            print(1)
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
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCWSTR', 'LPWSTR', 'PLONG']
        pNames = ['hKey', 'lpSubKey', 'lpData', 'lpcbData']

        

        lpSubKey = read_unicode(uc, pVals[1])
        pVals[1] = lpSubKey

        keyPath = ''
        keyValue = None

        if lpSubKey == '[NULL]':
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
                        keyValue = foundKey.getValue()
        else:
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Get Value
                        foundKey: RegKey = RegistryKeys[keyPath]
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
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCSTR', 'LPDWORD', 'LPDWORD', 'LPBYTE', 'LPDWORD']
        pNames = ['hKey', 'lpValueName', 'lpReserved', 'lpType', 'lpData', 'lpcbData']

        

        lpValue = read_string(uc, pVals[1])

        keyPath = ''
        keyValue = None
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCWSTR', 'LPDWORD', 'LPDWORD', 'LPBYTE', 'LPDWORD']
        pNames = ['hKey', 'lpValueName', 'lpReserved', 'lpType', 'lpData', 'lpcbData']

        

        lpValue = read_unicode(uc, pVals[1])

        keyPath = ''
        keyValue = None
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'LPCSTR', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'dwType', 'lpData', 'cbData']
        
        

        lpSubKey = read_string(uc, pVals[1])
        lpData = read_string(uc, pVals[3])

        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Set Value
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path
                    if rKey.path in RegistryKeys: # If Key Found Set Value
                        foundKey: RegKey = RegistryKeys[rKey.path]
                        foundKey.setValue(RegValueTypes(pVals[2]),lpData)
                        registry_key_address = foundKey
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
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'LPCWSTR', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'dwType', 'lpData', 'cbData']

        


        lpSubKey = read_unicode(uc, pVals[1])
        lpData = read_unicode(uc, pVals[3])
        
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Set Value
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    if rKey.path in RegistryKeys: # If Key Found Set Value
                        foundKey: RegKey = RegistryKeys[rKey.path]
                        foundKey.setValue(RegValueTypes(pVals[2]),lpData)
                        registry_key_address = foundKey
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
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'DWORD', 'BYTE *', 'DWORD']
        pNames = ['hKey', 'lpValueName', 'Reserved', 'dwType', 'lpData', 'cbData']

        

        valType = RegValueTypes(pVals[3])
        valName = read_string(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        if pVals[0] in HandlesDict: # Handle Not Found
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name] # Key Found
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
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'DWORD', 'BYTE *', 'DWORD']
        pNames = ['hKey', 'lpValueName', 'Reserved', 'dwType', 'lpData', 'cbData']

        

        valType = RegValueTypes(pVals[3])
        valName = read_unicode(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        if pVals[0] in HandlesDict: # Handle Not Found
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name] # Key Found
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
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPCVOID', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValueName', 'dwType', 'lpData', 'cbData']

        

        valType = RegValueTypes(pVals[3])
        valName = read_string(uc,pVals[2])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[2] = valName
        lpSubKey = read_string(uc,pVals[1])
    
        if lpSubKey == '[NULL]':
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict: # Handle Not Found
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys: # Key Found
                    rKey: RegKey = RegistryKeys[hKey.name] 
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
                hKey: Handle = HandlesDict[pVals[0]]
                keyPath = hKey.name + lpSubKey
                if keyPath in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name] # Key Found
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
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPCVOID', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValueName', 'dwType', 'lpData', 'cbData']

        

        valType = RegValueTypes(pVals[3])
        valName = read_unicode(uc,pVals[2])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[2] = valName
        lpSubKey = read_unicode(uc,pVals[1])
    
        if lpSubKey == '[NULL]':
            pVals[1] = lpSubKey
            if pVals[0] in HandlesDict: # Handle Not Found
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys: # Key Found
                    rKey: RegKey = RegistryKeys[hKey.name] 
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
                hKey: Handle = HandlesDict[pVals[0]]
                keyPath = hKey.name + lpSubKey
                if keyPath in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name] # Key Found
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

    def RegDeleteValueA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpValueName']
        
        

        valName = read_string(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        keyPath = ''
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteValueW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpValueName']
        
        

        valName = read_unicode(uc,pVals[1])
        if valName == '[NULL]':
            valName = '(Default)'
        pVals[1] = valName

        keyPath = ''
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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


    def RegDeleteKeyValueA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey', 'lpValueName']
        
        

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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegDeleteKeyValueW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey', 'lpValueName']
        
        


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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['REGSAM', 'PHKEY']
        pNames = ['access', 'retkey']

        pVals[0] = getLookUpVal(pVals[0], RegKey.securityAccessRights)

        try:
            uc.mem_write(pVals[1], pack('<I',0x80000001))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegOpenCurrentUser", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenUserClassesRoot(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HANDLE', 'DWORD', 'REGSAM', 'PHKEY']
        pNames = ['hToken', 'dwOptions', 'samDesired', 'phkResult']
       
        pVals[0] = getLookUpVal(pVals[2], RegKey.securityAccessRights)

        try:
            uc.mem_write(pVals[3], pack('<I',0x80000000))
        except:
            pass

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[2])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegOpenUserClassesRoot", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegOpenKeyExA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
            #'RegOpenKeyExA': (5, ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY'], ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult'], 'LSTATUS')
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'REGSAM', 'PHKEY']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult']

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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD', 'REGSAM', 'PHKEY']
        pNames = ['hKey', 'lpSubKey', 'ulOptions', 'samDesired', 'phkResult']

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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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

    def RegFlushKey(self, uc, eip, esp, export_dict, callAddr, em):
        #'RegFlushKey': (1, ['HKEY'], ['hKey'], 'LSTATUS')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HKEY']
        pNames = ['hKey']

        

        keyPath =''
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else: # RegKey Not Found Use handle Name Instead Might Not Be KeyPath
              keyPath = hKey.name 
        else:
            #print("figure out what to do in the case of key not in dict")
            keyPath = 'Error in retreving key'
             

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegFlushKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RegLoadKeyA(self, uc, eip, esp, export_dict, callAddr, em):
        #'RegLoadKeyA': (3, ['HKEY', 'LPCSTR', 'LPCSTR'], ['hKey', 'lpSubKey', 'lpFile'], 'LSTATUS')
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey', 'lpFile']

        
        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegLoadKeyW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey', 'lpFile']

        
        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegUnLoadKeyA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey']

        
        

        lpSubKey = read_string(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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

    def RegUnLoadKeyW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey']

        

        lpSubKey = read_unicode(uc, pVals[1])
        if lpSubKey != '[NULL]':
            if lpSubKey[0] != '\\':
                lpSubKey = '\\' + lpSubKey
            pVals[1] = lpSubKey

            keyPath = ''
            if pVals[0] in HandlesDict:
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
                    keyPath = rKey.path + lpSubKey
                    if keyPath in RegistryKeys: # If Key Found Return Handle
                        foundKey: RegKey = RegistryKeys[keyPath]
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
                hKey: Handle = HandlesDict[pVals[0]]
                if hKey.name in RegistryKeys:
                    rKey: RegKey = RegistryKeys[hKey.name]
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


    def RegCloseKey(self, uc, eip, esp, export_dict, callAddr, em):
        #'RegCloseKey': (1, ['HKEY'], ['hKey'], 'LSTATUS')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HKEY']
        pNames = ['hKey']

        

        keyPath =''
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
                keyPath = rKey.path
            else:
                keyPath = hKey.name
        else:
            #print("figure out what to do in the case of key not in dict")
            keyPath = 'Error in retreving key - closeKey'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(keyPath)

        logged_calls = ("RegCloseKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RegRenameKey(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKeyName', 'lpNewKeyName']

        

        # RegKey.printInfoAllKeys()
        keysToRename = set()
        keyPath = ''

        lpSubKey = read_unicode(uc, pVals[1])
        newKey = read_unicode(uc, pVals[2])

        if newKey != '[NULL]':
            if lpSubKey != '[NULL]':
                if lpSubKey[0] != '\\':
                    lpSubKey = '\\' + lpSubKey
                pVals[1] = lpSubKey

                oldKeyName = lpSubKey.split('\\')[-1] # Get Key Name

                if pVals[0] in HandlesDict:
                    hKey: Handle = HandlesDict[pVals[0]]
                    if hKey.name in RegistryKeys:
                        rKey: RegKey = RegistryKeys[hKey.name]
                        keyPath = rKey.path + lpSubKey
                        if keyPath in RegistryKeys:
                            fKey: RegKey = RegistryKeys[keyPath]
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
                    hKey: Handle = HandlesDict[pVals[0]]
                    if hKey.name in RegistryKeys:
                        rKey: RegKey = RegistryKeys[hKey.name]
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

        if len(keysToRename) > 0:
            for key in keysToRename:
                if isinstance(key,RegKey):
                    # print(key.name)
                    key.name = newKey
                    art.registry_add_keys(newKey)
                    key.path = key.path.replace(oldKeyName,newKey)
                    key.handle.name = key.path


        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)


        logged_calls = ("RegRenameKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RegOverridePredefKey(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HKEY', 'HKEY']
        pNames = ['hKey', 'hNewHKEY']

        

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
                    hKey: Handle = HandlesDict[pVals[1]]
                    if hKey.name in RegistryKeys:
                        rKey: RegKey = RegistryKeys[hKey.name]
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

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        art.registry_add_keys.add(preKeyPath)


        logged_calls = ("RegOverridePredefKey", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RegEnumKeyA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'RegEnumKeyA': (4, ['HKEY', 'DWORD', 'LPSTR', 'DWORD'], ['hKey', 'dwIndex', 'lpName', 'cchName'], 'LSTATUS')
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'DWORD', 'LPSTR', 'DWORD']
        pNames = ['hKey', 'dwIndex', 'lpName', 'cchName']

        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            keyPath = hKey.name
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.childKeys):
                    ChildKeysList = list(rKey.childKeys)
                    childKey = rKey.childKeys[ChildKeysList[pVals[1]]]
                    try:
                        uc.mem_write(pVals[2],pack(f'<{len(childKey.name)+1}s',childKey.name.encode('ascii')))
                    except:
                        pass
                    retVal = 0x0
                    retValStr = 'ERROR_SUCCESS'
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
        else: # Handle Not Found
            retVal = 18
            retValStr = 'ERROR_NO_MORE_FILES'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])
    
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegEnumKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegEnumKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'DWORD', 'LPWSTR', 'DWORD']
        pNames = ['hKey', 'dwIndex', 'lpName', 'cchName']

        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            keyPath = hKey.name
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
                if pVals[1] < len(rKey.childKeys):
                    ChildKeysList = list(rKey.childKeys)
                    childKey = rKey.childKeys[ChildKeysList[pVals[1]]]
                    try:
                        uc.mem_write(pVals[2],pack(f'<{(len(childKey.name)*2)+1}s',childKey.name.encode('utf-16')[2:]))
                    except:
                        pass
                    retVal = 0x0
                    retValStr = 'ERROR_SUCCESS'
                else:
                    retVal = 18
                    retValStr = 'ERROR_NO_MORE_FILES'
                    RegKey.printTree()
                    print(RegistryKeys)
                    print('\n')
                    print(HandlesDict)
        else: # Handle Not Found
            retVal = 18
            retValStr = 'ERROR_NO_MORE_FILES'

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegEnumKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def RegConnectRegistryA(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        #'RegConnectRegistryA': (3, ['LPCSTR', 'HKEY', 'PHKEY'], ['lpMachineName', 'hKey', 'phkResult'], 'LSTATUS')
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCSTR', 'HKEY', 'PHKEY']
        pNames = ['lpMachineName', 'hKey', 'phkResult']

        
        

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
                hKey: Handle = HandlesDict[pVals[1]]
                keyPath = hKey.name
                if hKey.name in RegistryKeys:
                    key: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCWSTR', 'HKEY', 'PHKEY']
        pNames = ['lpMachineName', 'hKey', 'phkResult']

        
        

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
                hKey: Handle = HandlesDict[pVals[1]]
                keyPath = hKey.name
                if hKey.name in RegistryKeys:
                    key: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD']
        pNames = ['hKey', 'lpFile', 'dwFlags']
        dwFlagsReverseLookUp = {0x00000008: 'REG_FORCE_RESTORE', 0x00000001: 'REG_WHOLE_HIVE_VOLATILE'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCWSTR', 'DWORD']
        pNames = ['hKey', 'lpFile', 'dwFlags']
        dwFlagsReverseLookUp = {0x00000008: 'REG_FORCE_RESTORE', 0x00000001: 'REG_WHOLE_HIVE_VOLATILE'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCSTR', 'const LPSECURITY_ATTRIBUTES']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes']

        
        
    
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HKEY', 'LPCWSTR', 'const LPSECURITY_ATTRIBUTES']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes']

        
        
    
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCSTR', 'const LPSECURITY_ATTRIBUTES', 'DWORD']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes', 'Flags']
        dwFlagsReversLookUp = {1: 'REG_STANDARD_FORMAT', 2: 'REG_LATEST_FORMAT', 4: 'REG_NO_COMPRESSION'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCWSTR', 'const LPSECURITY_ATTRIBUTES', 'DWORD']
        pNames = ['hKey', 'lpFile', 'lpSecurityAttributes', 'Flags']
        dwFlagsReversLookUp = {1: 'REG_STANDARD_FORMAT', 2: 'REG_LATEST_FORMAT', 4: 'REG_NO_COMPRESSION'}

        
        
    
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR', 'LPCSTR']
        pNames = ['hKey', 'lpSubKey', 'lpNewFile', 'lpOldFile']

        

        lpSubKey = read_string(uc,pVals[1])
        pVals[1] = lpSubKey

        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegReplaceKeyA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def RegReplaceKeyW(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR']
        pNames = ['hKey', 'lpSubKey', 'lpNewFile', 'lpOldFile']

        

        lpSubKey = read_unicode(uc,pVals[1])
        pVals[1] = lpSubKey
        
        if pVals[0] in HandlesDict:
            hKey: Handle = HandlesDict[pVals[0]]
            if hKey.name in RegistryKeys:
                rKey: RegKey = RegistryKeys[hKey.name]
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

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegReplaceKeyW", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))


    def SetWindowsHookExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['int', 'HOOKPROC', 'HINSTANCE', 'DWORD']
        pNames = ['idHook', 'lpfn', 'hmod', 'dwThreadId']

        idHookReverseLookUp = {4: 'WH_CALLWNDPROC', 18: 'WH_CALLWNDPROCRET', 5: 'WH_CBT', 9: 'WH_DEBUG',
                               17: 'WH_FOREGROUNDIDLE', 3: 'WH_GETMESSAGE', 1: 'WH_JOURNALPLAYBACK',
                               0: 'WH_JOURNALRECORD',
                               2: 'WH_KEYBOARD', 19: 'WH_KEYBOARD_LL', 7: 'WH_MOUSE', 20: 'WH_MOUSE_LL',
                               -1: 'WH_MSGFILTER',
                               16: 'WH_SHELL', 6: 'WH_SYSMSGFILTER'}

        pVals[0] = getLookUpVal(pVals[0], idHookReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00656565
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetWindowsHookExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetWindowsHookExW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['int', 'HOOKPROC', 'HINSTANCE', 'DWORD']
        pNames = ['idHook', 'lpfn', 'hmod', 'dwThreadId']

        idHookReverseLookUp = {4: 'WH_CALLWNDPROC', 18: 'WH_CALLWNDPROCRET', 5: 'WH_CBT', 9: 'WH_DEBUG',
                               17: 'WH_FOREGROUNDIDLE', 3: 'WH_GETMESSAGE', 1: 'WH_JOURNALPLAYBACK',
                               0: 'WH_JOURNALRECORD',
                               2: 'WH_KEYBOARD', 19: 'WH_KEYBOARD_LL', 7: 'WH_MOUSE', 20: 'WH_MOUSE_LL',
                               -1: 'WH_MSGFILTER',
                               16: 'WH_SHELL', 6: 'WH_SYSMSGFILTER'}

        pVals[0] = getLookUpVal(pVals[0], idHookReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00717171
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetWindowsHookExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def shutdown(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['SOCKET', 'int']
        pNames = ['s', 'how']

        howReverseLookUp = {0: 'SD_RECEIVE', 1: 'SD_SEND', 2: 'SD_BOTH'}

        pVals[1] = getLookUpVal(pVals[1], howReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("shutdown", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ReplaceFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPCSTR', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPVOID', 'LPVOID']
        pNames = ['lpReplacedFileName', 'lpReplacementFileName', 'lpBackupFileName', 'dwReplaceFlags', 'lpExclude',
                  'lpReserved']

        dwReplaceFlagsReverseLookUp = {1: 'REPLACEFILE_WRITE_THROUGH', 2: 'REPLACEFILE_IGNORE_MERGE_ERRORS',
                                       4: 'REPLACEFILE_IGNORE_ACL_ERRORS'}

        pVals[3] = getLookUpVal(pVals[3], dwReplaceFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReplaceFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ReplaceFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'LPVOID', 'LPVOID']
        pNames = ['lpReplacedFileName', 'lpReplacementFileName', 'lpBackupFileName', 'dwReplaceFlags', 'lpExclude',
                  'lpReserved']

        dwReplaceFlagsReverseLookUp = {1: 'REPLACEFILE_WRITE_THROUGH', 2: 'REPLACEFILE_IGNORE_MERGE_ERRORS',
                                       4: 'REPLACEFILE_IGNORE_ACL_ERRORS'}

        pVals[3] = getLookUpVal(pVals[3], dwReplaceFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReplaceFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ReadDirectoryChangesW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['HANDLE', 'LPVOID', 'DWORD', 'BOOL', 'DWORD', 'LPDWORD', 'LPOVERLAPPED',
                  'LPOVERLAPPED_COMPLETION_ROUTINE']
        pNames = ['hDirectory', 'lpBuffer', 'nBufferLength', 'bWatchSubtree', 'dwNotifyFilter', 'lpBytesReturned',
                  'lpOverlapped', 'lpCompletionRoutine']

        dwNotifyFilterReverseLookUp = {1: 'FILE_NOTIFY_CHANGE_FILE_NAME', 2: 'FILE_NOTIFY_CHANGE_DIR_NAME',
                                       4: 'FILE_NOTIFY_CHANGE_ATTRIBUTES', 8: 'FILE_NOTIFY_CHANGE_SIZE',
                                       16: 'FILE_NOTIFY_CHANGE_LAST_WRITE', 32: 'FILE_NOTIFY_CHANGE_LAST_ACCESS',
                                       64: 'FILE_NOTIFY_CHANGE_CREATION', 256: 'FILE_NOTIFY_CHANGE_SECURITY'}

        pVals[4] = getLookUpVal(pVals[4], dwNotifyFilterReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReadDirectoryChangesW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetCombineUrlA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPCSTR', 'LPCSTR', 'LPSTR', 'LPDWORD', 'DWORD']
        pNames = ['lpszBaseUrl', 'lpszRelativeUrl', 'lpszBuffer', 'lpdwBufferLength', 'dwFlags']

        dwFlagsReverseLookUp = {536870912: 'ICU_NO_ENCODE', 268435456: 'ICU_DECODE', 134217728: 'ICU_NO_META',
                                67108864: 'ICU_ENCODE_SPACES_ONLY', 33554432: 'ICU_BROWSER_MODE',
                                4096: 'ICU_ENCODE_PERCENT'}

        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetCombineUrlA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetCombineUrlW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPCWSTR', 'LPCWSTR', 'LPWSTR', 'LPDWORD', 'DWORD']
        pNames = ['lpszBaseUrl', 'lpszRelativeUrl', 'lpszBuffer', 'lpdwBufferLength', 'dwFlags']

        dwFlagsReverseLookUp = {536870912: 'ICU_NO_ENCODE', 268435456: 'ICU_DECODE', 134217728: 'ICU_NO_META',
                                67108864: 'ICU_ENCODE_SPACES_ONLY', 33554432: 'ICU_BROWSER_MODE',
                                4096: 'ICU_ENCODE_PERCENT'}

        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetCombineUrlW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ExitWindowsEx(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['UINT', 'DWORD']
        pNames = ['uFlags', 'dwReason']

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

        # create strings for everything except ones in our skip
        skip = [0, 1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ExitWindowsEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetFileAttributesA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPCSTR', 'DWORD']
        pNames = ['lpFileName', 'dwFileAttributes']

        dwFileAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 2: 'FILE_ATTRIBUTE_HIDDEN',
                                         128: 'FILE_ATTRIBUTE_NORMAL', 8192: 'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',
                                         4096: 'FILE_ATTRIBUTE_OFFLINE', 4: 'FILE_ATTRIBUTE_SYSTEM',
                                         256: 'FILE_ATTRIBUTE_TEMPORARY'}

        pVals[1] = getLookUpVal(pVals[1], dwFileAttributesReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetFileAttributesA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetFileAttributesW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPCWSTR', 'DWORD']
        pNames = ['lpFileName', 'dwFileAttributes']

        dwFileAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 2: 'FILE_ATTRIBUTE_HIDDEN',
                                         128: 'FILE_ATTRIBUTE_NORMAL', 8192: 'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',
                                         4096: 'FILE_ATTRIBUTE_OFFLINE', 4: 'FILE_ATTRIBUTE_SYSTEM',
                                         256: 'FILE_ATTRIBUTE_TEMPORARY'}

        pVals[1] = getLookUpVal(pVals[1], dwFileAttributesReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetFileAttributesW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFileMappingA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName']

        flProtectReverseLookUp = {2: 'PAGE_READONLY', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE',
                                  285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00676767
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFileMappingW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName']

        flProtectReverseLookUp = {2: 'PAGE_READONLY', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE',
                                  285212672: 'SEC_IMAGE_NO_EXECUTE', 2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00707070
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CryptAcquireContextA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HCRYPTPROV', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD']
        pNames = ['phProv', 'szContainer', 'szProvider', 'dwProvType', 'dwFlags']

        dwProvTypeReverseLookUp = {1: 'PROV_RSA_FULL', 2: 'PROV_RSA_SIG', 3: 'PROV_DSS', 4: 'PROV_FORTEZZA',
                                   5: 'PROV_MS_EXCHANGE', 6: 'PROV_SSL', 18: 'PROV_RSA_SCHANNEL', 19: 'PROV_DSS_DH',
                                   24: 'PROV_DH_SCHANNEL', 36: 'PROV_RSA_AES'}
        dwFlagsReverseLookUp = {4026531840: 'CRYPT_VERIFYCONTEXT', 8: 'CRYPT_NEWKEYSET', 16: 'CRYPT_DELETEKEYSET',
                                32: 'CRYPT_MACHINE_KEYSET', 64: 'CRYPT_SILENT', 128: 'CRYPT_DEFAULT_CONTAINER_OPTIONAL'}

        pVals[3] = getLookUpVal(pVals[3], dwProvTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptAcquireContextA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CryptAcquireContextW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HCRYPTPROV', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD']
        pNames = ['phProv', 'szContainer', 'szProvider', 'dwProvType', 'dwFlags']

        dwProvTypeReverseLookUp = {1: 'PROV_RSA_FULL', 2: 'PROV_RSA_SIG', 3: 'PROV_DSS', 4: 'PROV_FORTEZZA',
                                   5: 'PROV_MS_EXCHANGE', 6: 'PROV_SSL', 18: 'PROV_RSA_SCHANNEL', 19: 'PROV_DSS_DH',
                                   24: 'PROV_DH_SCHANNEL', 36: 'PROV_RSA_AES'}
        dwFlagsReverseLookUp = {4026531840: 'CRYPT_VERIFYCONTEXT', 8: 'CRYPT_NEWKEYSET', 16: 'CRYPT_DELETEKEYSET',
                                32: 'CRYPT_MACHINE_KEYSET', 64: 'CRYPT_SILENT', 128: 'CRYPT_DEFAULT_CONTAINER_OPTIONAL'}

        pVals[3] = getLookUpVal(pVals[3], dwProvTypeReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptAcquireContextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def OpenSCManagerA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']

        dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE',
                                        1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE',
                                        8: 'SC_MANAGER_LOCK',
                                        32: 'SC_MANAGER_MODIFY_BOOT_CONFIG', 16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

        handle = Handle(HandleType.SC_HANDLE)

        pVals[2] = getLookUpVal(pVals[2], dwDesiredAccessReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenSCManagerA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def OpenSCManagerW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCWSTR', 'LPCWSTR', 'DWORD']
        pNames = ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']

        dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE',
                                        1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE',
                                        8: 'SC_MANAGER_LOCK',
                                        32: 'SC_MANAGER_MODIFY_BOOT_CONFIG', 16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

        handle = Handle(HandleType.SC_HANDLE)

        pVals[2] = getLookUpVal(pVals[2], dwDesiredAccessReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenSCManagerW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FtpPutFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszLocalFile', 'lpszNewRemoteFile', 'dwFlags', 'dwContext']

        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpPutFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FtpPutFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszLocalFile', 'lpszNewRemoteFile', 'dwFlags', 'dwContext']

        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpPutFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetQueryOptionA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'lpdwBufferLength']

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

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetQueryOptionA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetQueryOptionW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'lpdwBufferLength']

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

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetQueryOptionW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetSetOptionA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'DWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'dwBufferLength']

        dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC',
                                 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY',
                                 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE',
                                 1: 'INTERNET_OPTION_CALLBACK', 84: 'INTERNET_OPTION_CALLBACK_FILTER',
                                 132: 'INTERNET_OPTION_CLIENT_CERT_CONTEXT', 104: 'INTERNET_OPTION_CODEPAGE',
                                 256: 'INTERNET_OPTION_CODEPAGE_PATH', 257: 'INTERNET_OPTION_CODEPAGE_EXTRA',
                                 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH', 4: 'INTERNET_OPTION_CONNECT_BACKOFF',
                                 3: 'INTERNET_OPTION_CONNECT_RETRIES', 85: 'INTERNET_OPTION_CONNECT_TIME',
                                 2: 'INTERNET_OPTION_CONNECT_TIMEOUT', 80: 'INTERNET_OPTION_CONNECTED_STATE',
                                 69: 'INTERNET_OPTION_CONTEXT_VALUE', 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT',
                                 5: 'INTERNET_OPTION_SEND_TIMEOUT', 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT',
                                 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT', 150: 'INTERNET_OPTION_DATAFILE_EXT',
                                 118: 'INTERNET_OPTION_DIGEST_AUTH_UNLOAD', 112: 'INTERNET_OPTION_DISABLE_AUTODIAL',
                                 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT',
                                 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL',
                                 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA',
                                 66: 'INTERNET_OPTION_END_BROWSER_SESSION', 98: 'INTERNET_OPTION_ERROR_MASK',
                                 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT',
                                 343: 'INTERNET_OPTION_HSTS', 101: 'INTERNET_OPTION_HTTP_DECODING',
                                 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED', 89: 'INTERNET_OPTION_HTTP_VERSION',
                                 120: 'INTERNET_OPTION_IDENTITY', 81: 'INTERNET_OPTION_IDLE_STATE',
                                 258: 'INTERNET_OPTION_IDN', 119: 'INTERNET_OPTION_IGNORE_OFFLINE',
                                 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT',
                                 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER',
                                 259: 'INTERNET_OPTION_MAX_CONNS_PER_PROXY',
                                 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER',
                                 38: 'INTERNET_OPTION_OFFLINE_MODE', 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS',
                                 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE', 41: 'INTERNET_OPTION_PASSWORD',
                                 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY',
                                 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD',
                                 149: 'INTERNET_OPTION_PROXY_SETTINGS_CHANGED', 67: 'INTERNET_OPTION_PROXY_USERNAME',
                                 18: 'INTERNET_OPTION_READ_BUFFER_SIZE', 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT',
                                 55: 'INTERNET_OPTION_REFRESH', 121: 'INTERNET_OPTION_REMOVE_IDENTITY',
                                 88: 'INTERNET_OPTION_REQUEST_PRIORITY', 96: 'INTERNET_OPTION_RESET_URLCACHE_SESSION',
                                 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 86: 'INTERNET_OPTION_SEND_THROUGHPUT',
                                 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT',
                                 57: 'INTERNET_OPTION_SETTINGS_CHANGED',
                                 260: 'INTERNET_OPTION_SUPPRESS_SERVER_AUTH', 65: 'INTERNET_OPTION_USER_AGENT',
                                 40: 'INTERNET_OPTION_USERNAME', 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

        pVals[1] = getLookUpVal(pVals[1], dwOptionReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetSetOptionA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetSetOptionW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'DWORD']
        pNames = ['hInternet', 'dwOption', 'lpBuffer', 'dwBufferLength']

        dwOptionReverseLookUp = {128: 'INTERNET_OPTION_ALTER_IDENTITY', 48: 'INTERNET_OPTION_ASYNC',
                                 21: 'INTERNET_OPTION_ASYNC_ID', 22: 'INTERNET_OPTION_ASYNC_PRIORITY',
                                 100: 'INTERNET_OPTION_BYPASS_EDITED_ENTRY', 39: 'INTERNET_OPTION_CACHE_STREAM_HANDLE',
                                 1: 'INTERNET_OPTION_CALLBACK', 84: 'INTERNET_OPTION_CALLBACK_FILTER',
                                 132: 'INTERNET_OPTION_CLIENT_CERT_CONTEXT', 104: 'INTERNET_OPTION_CODEPAGE',
                                 256: 'INTERNET_OPTION_CODEPAGE_PATH', 257: 'INTERNET_OPTION_CODEPAGE_EXTRA',
                                 327: 'INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH', 4: 'INTERNET_OPTION_CONNECT_BACKOFF',
                                 3: 'INTERNET_OPTION_CONNECT_RETRIES', 85: 'INTERNET_OPTION_CONNECT_TIME',
                                 2: 'INTERNET_OPTION_CONNECT_TIMEOUT', 80: 'INTERNET_OPTION_CONNECTED_STATE',
                                 69: 'INTERNET_OPTION_CONTEXT_VALUE', 6: 'INTERNET_OPTION_RECEIVE_TIMEOUT',
                                 5: 'INTERNET_OPTION_SEND_TIMEOUT', 8: 'INTERNET_OPTION_DATA_RECEIVE_TIMEOUT',
                                 7: 'INTERNET_OPTION_DATA_SEND_TIMEOUT', 150: 'INTERNET_OPTION_DATAFILE_EXT',
                                 118: 'INTERNET_OPTION_DIGEST_AUTH_UNLOAD', 112: 'INTERNET_OPTION_DISABLE_AUTODIAL',
                                 73: 'INTERNET_OPTION_DISCONNECTED_TIMEOUT',
                                 328: 'INTERNET_OPTION_ENABLE_HTTP_PROTOCOL',
                                 290: 'INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ', 341: 'INTERNET_OPTION_ENCODE_EXTRA',
                                 66: 'INTERNET_OPTION_END_BROWSER_SESSION', 98: 'INTERNET_OPTION_ERROR_MASK',
                                 345: 'INTERNET_OPTION_ENTERPRISE_CONTEXT', 99: 'INTERNET_OPTION_FROM_CACHE_TIMEOUT',
                                 343: 'INTERNET_OPTION_HSTS', 101: 'INTERNET_OPTION_HTTP_DECODING',
                                 329: 'INTERNET_OPTION_HTTP_PROTOCOL_USED', 89: 'INTERNET_OPTION_HTTP_VERSION',
                                 120: 'INTERNET_OPTION_IDENTITY', 81: 'INTERNET_OPTION_IDLE_STATE',
                                 258: 'INTERNET_OPTION_IDN', 119: 'INTERNET_OPTION_IGNORE_OFFLINE',
                                 34: 'INTERNET_OPTION_KEEP_CONNECTION', 17: 'INTERNET_OPTION_LISTEN_TIMEOUT',
                                 116: 'INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER',
                                 259: 'INTERNET_OPTION_MAX_CONNS_PER_PROXY',
                                 115: 'INTERNET_OPTION_MAX_CONNS_PER_SERVER',
                                 38: 'INTERNET_OPTION_OFFLINE_MODE', 82: 'INTERNET_OPTION_OFFLINE_SEMANTICS',
                                 374: 'INTERNET_OPTION_OPT_IN_WEAK_SIGNATURE', 41: 'INTERNET_OPTION_PASSWORD',
                                 117: 'INTERNET_OPTION_PER_CONNECTION_OPTION', 72: 'INTERNET_OPTION_POLICY',
                                 56: 'INTERNET_OPTION_PROXY', 68: 'INTERNET_OPTION_PROXY_PASSWORD',
                                 149: 'INTERNET_OPTION_PROXY_SETTINGS_CHANGED', 67: 'INTERNET_OPTION_PROXY_USERNAME',
                                 18: 'INTERNET_OPTION_READ_BUFFER_SIZE', 87: 'INTERNET_OPTION_RECEIVE_THROUGHPUT',
                                 55: 'INTERNET_OPTION_REFRESH', 121: 'INTERNET_OPTION_REMOVE_IDENTITY',
                                 88: 'INTERNET_OPTION_REQUEST_PRIORITY', 96: 'INTERNET_OPTION_RESET_URLCACHE_SESSION',
                                 83: 'INTERNET_OPTION_SECONDARY_CACHE_KEY', 86: 'INTERNET_OPTION_SEND_THROUGHPUT',
                                 261: 'INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT',
                                 57: 'INTERNET_OPTION_SETTINGS_CHANGED',
                                 260: 'INTERNET_OPTION_SUPPRESS_SERVER_AUTH', 65: 'INTERNET_OPTION_USER_AGENT',
                                 40: 'INTERNET_OPTION_USERNAME', 19: 'INTERNET_OPTION_WRITE_BUFFER_SIZE'}

        pVals[1] = getLookUpVal(pVals[1], dwOptionReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetSetOptionW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpOpenRequestA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszVerb', 'lpszObjectName', 'lpszVersion', 'lpszReferrer', 'lplpszAcceptTypes',
                  'dwFlags',
                  'dwContext']

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

        # create strings for everything except ones in our skip
        skip = [6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        if pVals[3] == '[NULL]':
            pVals[3] = 'HTTP/1.1'

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00747474
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpOpenRequestA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpOpenRequestW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszVerb', 'lpszObjectName', 'lpszVersion', 'lpszReferrer', 'lplpszAcceptTypes',
                  'dwFlags',
                  'dwContext']

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

        # create strings for everything except ones in our skip
        skip = [6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        if pVals[3] == '[NULL]':
            pVals[3] = 'HTTP/1.1'

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00757575
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpOpenRequestW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpAddRequestHeadersA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HINTERNET', 'LPCSTR', 'DWORD', 'DWORD']
        pNames = ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'dwModifiers']

        dwModifiersReverseLookUp = {536870912: 'HTTP_ADDREQ_FLAG_ADD', 268435456: 'HTTP_ADDREQ_FLAG_ADD_IF_NEW',
                                    1073741824: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA',
                                    16777216: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON',
                                    2147483648: 'HTTP_ADDREQ_FLAG_REPLACE'}

        pVals[3] = getLookUpVal(pVals[3], dwModifiersReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpAddRequestHeadersA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpSendRequestA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCSTR', 'DWORD', 'LPVOID', 'DWORD']
        pNames = ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'lpOptional', 'dwOptionalLength']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpSendRequestA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpSendRequestExA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPINTERNET_BUFFERSA', 'LPINTERNET_BUFFERSA', 'DWORD', 'DWORD_PTR']
        pNames = ['hRequest', 'lpBuffersIn', 'lpBuffersOut', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpSendRequestExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetCloseHandle(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET']
        pNames = ['hInternet']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetCloseHandle", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetReadFile(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['hFile', 'lpBuffer', 'dwNumberOfBytesToRead', 'lpdwNumberOfBytesToRead']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetReadFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetReadFileExA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPINTERNET_BUFFERSA', 'DWORD', 'DWORD_PTR']
        pNames = ['hFile', 'lpBuffersOut', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {1: 'IRF_ASYNC', 4: 'IRF_SYNC', 8: 'IRF_USE_CONTEXT', 0: 'IRF_NO_WAIT'}
        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)
        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetReadFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetReadFileExW(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPINTERNET_BUFFERSW', 'DWORD', 'DWORD_PTR']
        pNames = ['hFile', 'lpBuffersOut', 'dwFlags', 'dwContext']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        dwFlagsReverseLookUp = {1: 'IRF_ASYNC', 4: 'IRF_SYNC', 8: 'IRF_USE_CONTEXT', 0: 'IRF_NO_WAIT'}
        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)
        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetReadFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetWriteFile(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HINTERNET', 'LPCVOID', 'DWORD', 'LPDWORD']
        pNames = ['hFile', 'lpBuffer', 'dwNumberOfBytesToWrite', 'lpdwNumberOfBytesWritten']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetWriteFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLOpenBlockingStreamA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'LPSTREAM', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', '*ppStream', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenBlockingStreamA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLOpenBlockingStreamW(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'LPSTREAM', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', '*ppStream', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenBlockingStreamW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLOpenStreamA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenStreamA", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLOpenStreamW(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['LPUNKNOWN', 'LPCWSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'dwReserved', 'lpfnCB']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLOpenStreamW", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpAddRequestHeadersW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HINTERNET', 'LPCWSTR', 'DWORD', 'DWORD']
        pNames = ['hRequest', 'lpszHeaders', 'dwHeadersLength', 'dwModifiers']

        dwModifiersReverseLookUp = {536870912: 'HTTP_ADDREQ_FLAG_ADD', 268435456: 'HTTP_ADDREQ_FLAG_ADD_IF_NEW',
                                    1073741824: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA',
                                    16777216: 'HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON',
                                    2147483648: 'HTTP_ADDREQ_FLAG_REPLACE'}

        pVals[3] = getLookUpVal(pVals[3], dwModifiersReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpAddRequestHeadersW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpQueryInfoA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD', 'LPDWORD']
        pNames = ['hRequest', 'dwInfoLevel', 'lpBuffer', 'lpdwBufferLength', 'lpdwIndex']

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

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpQueryInfoA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HttpQueryInfoW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HINTERNET', 'DWORD', 'LPVOID', 'LPDWORD', 'LPDWORD']
        pNames = ['hRequest', 'dwInfoLevel', 'lpBuffer', 'lpdwBufferLength', 'lpdwIndex']

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

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HttpQueryInfoW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FtpGetFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'BOOL', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszRemoteFile', 'lpszNewFile', 'fFailIfExists', 'dwFlagsAndAttributes', 'dwFlags',
                  'dwContext']

        dwFlagsAndAttributesReverseLookUp = {50: 'FILE_ATTRIBUTE_ARCHIVE', 91012: 'FILE_ATTRIBUTE_ENCRYPTED',
                                             2: 'FILE_ATTRIBUTE_HIDDEN', 296: 'FILE_ATTRIBUTE_NORMAL',
                                             16534: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY',
                                             4: 'FILE_ATTRIBUTE_SYSTEM', 598: 'FILE_ATTRIBUTE_TEMPORARY'}
        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[4] = getLookUpVal(pVals[4], dwFlagsAndAttributesReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpGetFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FtpGetFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'BOOL', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszRemoteFile', 'lpszNewFile', 'fFailIfExists', 'dwFlagsAndAttributes', 'dwFlags',
                  'dwContext']

        dwFlagsAndAttributesReverseLookUp = {50: 'FILE_ATTRIBUTE_ARCHIVE', 91012: 'FILE_ATTRIBUTE_ENCRYPTED',
                                             2: 'FILE_ATTRIBUTE_HIDDEN', 296: 'FILE_ATTRIBUTE_NORMAL',
                                             16534: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY',
                                             4: 'FILE_ATTRIBUTE_SYSTEM', 598: 'FILE_ATTRIBUTE_TEMPORARY'}
        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[4] = getLookUpVal(pVals[4], dwFlagsAndAttributesReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpGetFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FtpOpenFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HINTERNET', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszFileName', 'dwAccess', 'dwFlags', 'dwContext']

        dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE'}
        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[2] = getLookUpVal(pVals[2], dwAccessReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00767676
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpOpenFileA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FtpOpenFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HINTERNET', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hConnect', 'lpszFileName', 'dwAccess', 'dwFlags', 'dwContext']

        dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE'}
        dwFlagsReverseLookUp = {0: 'FTP_TRANSFER_TYPE_UNKNOWN', 1: 'FTP_TRANSFER_TYPE_ASCII',
                                2: 'FTP_TRANSFER_TYPE_BINARY',
                                1024: 'INTERNET_FLAG_HYPERLINK', 16: 'INTERNET_FLAG_NEED_FILE',
                                2147483648: 'INTERNET_FLAG_RELOAD', 2048: 'INTERNET_FLAG_RESYNCHRONIZE'}

        pVals[2] = getLookUpVal(pVals[2], dwAccessReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00777777
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FtpOpenFileW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetOpenUrlA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HINTERNET', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszUrl', 'lpszHeaders', 'dwHeadersLength', 'dwFlags', 'dwContext']

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

        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00787878
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenUrlA", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetOpenUrlW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HINTERNET', 'LPCWSTR', 'LPCWSTR', 'DWORD', 'DWORD', 'DWORD_PTR']
        pNames = ['hInternet', 'lpszUrl', 'lpszHeaders', 'dwHeadersLength', 'dwFlags', 'dwContext']

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

        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00797979
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenUrlW", hex(callAddr), (retValStr), 'HINTERNET', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def MoveFileExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'dwFlags']

        dwFlagsReverseLookUp = {2: 'MOVEFILE_COPY_ALLOWED', 16: 'MOVEFILE_CREATE_HARDLINK',
                                4: 'MOVEFILE_DELAY_UNTIL_REBOOT', 32: 'MOVEFILE_FAIL_IF_NOT_TRACKABLE',
                                1: 'MOVEFILE_REPLACE_EXISTING', 8: 'MOVEFILE_WRITE_THROUGH'}

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("MoveFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def MoveFileExW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCWSTR', 'LPCWSTR', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'dwFlags']

        dwFlagsReverseLookUp = {2: 'MOVEFILE_COPY_ALLOWED', 16: 'MOVEFILE_CREATE_HARDLINK',
                                4: 'MOVEFILE_DELAY_UNTIL_REBOOT', 32: 'MOVEFILE_FAIL_IF_NOT_TRACKABLE',
                                1: 'MOVEFILE_REPLACE_EXISTING', 8: 'MOVEFILE_WRITE_THROUGH'}

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("MoveFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CopyFileExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPCSTR', 'LPCSTR', 'LPPROGRESS_ROUTINE', 'LPVOID', 'LPBOOL', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'lpProgressRoutine', 'lpData', 'pbCancel', 'dwCopyFlags']

        mdwCopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK',
                                     1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING',
                                     4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE',
                                     268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

        pVals[5] = getLookUpVal(pVals[5], mdwCopyFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CopyFileExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CopyFileExW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPCWSTR', 'LPCWSTR', 'LPPROGRESS_ROUTINE', 'LPVOID', 'LPBOOL', 'DWORD']
        pNames = ['lpExistingFileName', 'lpNewFileName', 'lpProgressRoutine', 'lpData', 'pbCancel', 'dwCopyFlags']

        mdwCopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK',
                                     1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING',
                                     4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE',
                                     268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

        pVals[5] = getLookUpVal(pVals[5], mdwCopyFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CopyFileExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def DuplicateHandle(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HANDLE', 'HANDLE', 'HANDLE', 'LPHANDLE', 'DWORD', 'BOOL', 'DWORD']
        pNames = ['hSourceProcessHandle', 'hSourceHandle', 'hTargetProcessHandle', 'lpTargetHandle', 'dwDesiredAccess',
                  'bInheritHandle', 'dwOptions']

        dwDesiredAccessReverseLookUp = {65536: 'DELETE', 131072: 'READ_CONTROL', 262144: 'WRITE_DAC',
                                        524288: 'WRITE_OWNER',
                                        1048576: 'SYNCHRONIZE', 983040: 'STANDARD_RIGHTS_REQUIRED',
                                        2031616: 'STANDARD_RIGHTS_ALL'}
        dwOptionsReverseLookUp = {1: 'DUPLICATE_CLOSE_SOURCE', 2: 'DUPLICATE_SAME_ACCESS'}

        pVals[4] = getLookUpVal(pVals[4], dwDesiredAccessReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], dwOptionsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [4, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("DuplicateHandle", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFileMappingNumaA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'DWORD']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName',
                  'nndPreferred']

        flProtectReverseLookUp = {32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE',
                                  2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}
        nndPreferredReverseLookUp = {4294967295: 'NUMA_NO_PREFERRED_NODE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], nndPreferredReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00808080
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingNumaA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFileMappingNumaW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCWSTR', 'DWORD']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName',
                  'nndPreferred']

        flProtectReverseLookUp = {32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE',
                                  2147483648: 'SEC_LARGE_PAGES',
                                  268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE', 1073741824: 'SEC_WRITECOMBINE'}
        nndPreferredReverseLookUp = {4294967295: 'NUMA_NO_PREFERRED_NODE'}

        pVals[2] = getLookUpVal(pVals[2], flProtectReverseLookUp)
        pVals[6] = getLookUpVal(pVals[6], nndPreferredReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00818181
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingNumaW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateMutexA(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexA([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in] BOOL bInitialOwner,[in, optional] LPCSTR lpName)
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'BOOL', 'LPCSTR']
        pNames = ['lpMutexAttributes', 'bInitialOwner', 'lpName']

        name = read_string(uc, pVals[2])
        handle = Handle(HandleType.Mutex, name = name)

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateMutexW(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexW([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in] BOOL bInitialOwner,[in, optional] LPCWSTR lpName)
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'BOOL', 'LPCWSTR']
        pNames = ['lpMutexAttributes', 'bInitialOwner', 'lpName']

        name = read_unicode(uc, pVals[2])
        handle = Handle(HandleType.Mutex, name = name)

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateMutexExA(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexExA([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in, optional] LPCSTR lpName,[in] DWORD dwFlags,[in] DWORD dwDesiredAccess);
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'LPCSTR', 'DWORD', 'DWORD']
        pNames = ['lpMutexAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
        dwFlagsReverseLookUp = {0x00000001: 'CREATE_MUTEX_INITIAL_OWNER'}
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG',
                                        0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE',
                                        0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG',
                                        0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP',
                                        0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE',
                                        0x20000: 'READ_CONTROL',
                                        0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}

        name = read_string(uc, pVals[1])
        handle = Handle(HandleType.Mutex, name = name)

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], dwDesiredAccessReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)
        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateMutexExW(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateMutexExW([in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,[in, optional] LPCWSTR lpName,[in] DWORD dwFlags,[in] DWORD dwDesiredAccess);
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'LPCWSTR', 'DWORD', 'DWORD']
        pNames = ['lpMutexAttributes', 'lpName', 'dwFlags', 'dwDesiredAccess']
        dwFlagsReverseLookUp = {0x00000001: 'CREATE_MUTEX_INITIAL_OWNER'}
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG',
                                        0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE',
                                        0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG',
                                        0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP',
                                        0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE',
                                        0x20000: 'READ_CONTROL',
                                        0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
        
        name = read_unicode(uc, pVals[1])
        handle = Handle(HandleType.Mutex, name = name)

        pVals[2] = getLookUpVal(pVals[2], dwFlagsReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], dwDesiredAccessReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2, 3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateMutexExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def OpenMutexA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['DWORD', 'BOOL', 'LPCSTR']
        pNames = ['dwDesiredAccess', 'bInheritHandle', 'lpName']
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG',
                                        0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE',
                                        0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG',
                                        0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP',
                                        0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE',
                                        0x20000: 'READ_CONTROL',
                                        0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
        
        name = read_string(uc, pVals[2])

        handle = None
        for key, val in HandlesDict.items():
            if val.type == HandleType.Mutex:
                if val.name == name:
                    handle = val
                    break

        if handle is None: # Create New Mutex if Not Found
            handle = Handle(HandleType.Mutex, name = name)

        pVals[0] = getLookUpVal(pVals[0], dwDesiredAccessReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenMutexA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def OpenMutexW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['DWORD', 'BOOL', 'LPCWSTR']
        pNames = ['dwDesiredAccess', 'bInheritHandle', 'lpName']
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG',
                                        0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE',
                                        0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG',
                                        0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP',
                                        0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE',
                                        0x20000: 'READ_CONTROL',
                                        0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}

        name = read_unicode(uc, pVals[2])

        handle = None
        for key, val in HandlesDict.items():
            if val.type == HandleType.Mutex:
                if val.name == name:
                    handle = val
                    break

        if handle is None: # Create New Mutex if Not Found
            handle = Handle(HandleType.Mutex,data=name)

        pVals[0] = getLookUpVal(pVals[0], dwDesiredAccessReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = handle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenMutexW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ReleaseMutex(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL ReleaseMutex([in] HANDLE hMutex);
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HANDLE']
        pNames = ['hMutex']

        # Remove Handle from HandlesDict
        if pVals[0] in HandlesDict:
            if HandlesDict[pVals[0]].type == HandleType.Mutex:
                HandlesDict.pop(pVals[0])

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReleaseMutex", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreatePipe(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['PHANDLE', 'PHANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD']
        pNames = ['hReadPipe', 'hWritePipe', 'lpPipeAttributes', 'nSize']

        # Create Handles
        readHandle = Handle(HandleType.ReadPipe)
        writeHandle = Handle(HandleType.WritePipe)

        # Write Handles to memory
        try:
            uc.mem_write(pVals[0], pack('<I', readHandle.value))
            uc.mem_write(pVals[1], pack('<I', writeHandle.value))
        except:
            pass

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreatePipe", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateNamedPipeA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['LPCSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES']
        pNames = ['lpName', 'dwOpenMode', 'dwPipeMode', 'nMaxInstances', 'nOutBufferSize', 'nInBufferSize',
                  'nDefaultTimeOut', 'lpSecurityAttributes']
        dwOpenModeReverseLookUp = {0x00000003: 'PIPE_ACCESS_DUPLEX', 0x00000001: 'PIPE_ACCESS_INBOUND',
                                   0x00000002: 'PIPE_ACCESS_OUTBOUND', 0x00040003: 'PIPE_ACCESS_DUPLEX | WRITE_DAC',
                                   0x00040001: 'PIPE_ACCESS_INBOUND | WRITE_DAC',
                                   0x00040002: 'PIPE_ACCESS_OUTBOUND | WRITE_DAC',
                                   0x01000003: 'PIPE_ACCESS_DUPLEX | ACCESS_SYSTEM_SECURITY',
                                   0x01000001: 'PIPE_ACCESS_INBOUND | ACCESS_SYSTEM_SECURITY',
                                   0x01000002: 'PIPE_ACCESS_OUTBOUND | ACCESS_SYSTEM_SECURITY',
                                   0x00080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE',
                                   0x00080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE',
                                   0x00080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE',
                                   0x000C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC',
                                   0x000C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC',
                                   0x000C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC',
                                   0x00080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_OWNER',
                                   0x00080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_OWNER',
                                   0x00080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_OWNER',
                                   0x01080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | ACCESS_SYSTEM_SECURITY',
                                   0x01080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | ACCESS_SYSTEM_SECURITY',
                                   0x01080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | ACCESS_SYSTEM_SECURITY',
                                   0x80000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH',
                                   0x80000001: 'PIPE_ACCESS_INBOUND| FILE_FLAG_WRITE_THROUGH',
                                   0x80000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH',
                                   0x80040003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x80040001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x80040002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x81000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x40000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED',
                                   0x40000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED',
                                   0x40000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED',
                                   0x40040003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x40040001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x40040002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x41000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x80080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH',
                                   0x80080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH',
                                   0x80080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH',
                                   0x800C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x800C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x800C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x80080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_OWNER',
                                   0x80080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_OWNER',
                                   0x80080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_OWNER',
                                   0x81080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x40080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED',
                                   0x40080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED',
                                   0x40080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED',
                                   0x400C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x400C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x400C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x40080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0x40080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0x40080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0x41080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC0000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0000001: 'PIPE_ACCESS_INBOUND| FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0040003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC0040001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC0040002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC1000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC0080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC00C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC00C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC00C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC0080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0xC0080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0xC0080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0xC1080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY'}
        dwPipeModeReverseLookUp = {
            0x00000000: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000001: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000002: 'PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000003: 'PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000004: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000005: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000006: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000007: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000008: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x00000009: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000A: 'PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000C: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000D: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000E: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000F: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS'}
        nMaxInstancesReverseLookUp = {255: 'PIPE_UNLIMITED_INSTANCES'}

        name = read_string(uc, pVals[0])

        if pVals[1] == 1:
            pipeHandle = Handle(HandleType.ReadPipe, data=name)
        elif pVals[1] == 2:
            pipeHandle = Handle(HandleType.WritePipe, data=name)
        else:
            pipeHandle = Handle(HandleType.ReadWritePipe, data=name)

        pVals[1] = getLookUpVal(pVals[1], dwOpenModeReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2], dwPipeModeReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], nMaxInstancesReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1, 2, 3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = pipeHandle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateNamedPipeA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateNamedPipeW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES']
        pNames = ['lpName', 'dwOpenMode', 'dwPipeMode', 'nMaxInstances', 'nOutBufferSize', 'nInBufferSize',
                  'nDefaultTimeOut', 'lpSecurityAttributes']
        dwOpenModeReverseLookUp = {0x00000003: 'PIPE_ACCESS_DUPLEX', 0x00000001: 'PIPE_ACCESS_INBOUND',
                                   0x00000002: 'PIPE_ACCESS_OUTBOUND', 0x00040003: 'PIPE_ACCESS_DUPLEX | WRITE_DAC',
                                   0x00040001: 'PIPE_ACCESS_INBOUND | WRITE_DAC',
                                   0x00040002: 'PIPE_ACCESS_OUTBOUND | WRITE_DAC',
                                   0x01000003: 'PIPE_ACCESS_DUPLEX | ACCESS_SYSTEM_SECURITY',
                                   0x01000001: 'PIPE_ACCESS_INBOUND | ACCESS_SYSTEM_SECURITY',
                                   0x01000002: 'PIPE_ACCESS_OUTBOUND | ACCESS_SYSTEM_SECURITY',
                                   0x00080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE',
                                   0x00080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE',
                                   0x00080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE',
                                   0x000C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC',
                                   0x000C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC',
                                   0x000C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC',
                                   0x00080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_OWNER',
                                   0x00080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_OWNER',
                                   0x00080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_OWNER',
                                   0x01080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | ACCESS_SYSTEM_SECURITY',
                                   0x01080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | ACCESS_SYSTEM_SECURITY',
                                   0x01080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | ACCESS_SYSTEM_SECURITY',
                                   0x80000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH',
                                   0x80000001: 'PIPE_ACCESS_INBOUND| FILE_FLAG_WRITE_THROUGH',
                                   0x80000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH',
                                   0x80040003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x80040001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x80040002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x81000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x40000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED',
                                   0x40000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED',
                                   0x40000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED',
                                   0x40040003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x40040001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x40040002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x41000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x80080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH',
                                   0x80080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH',
                                   0x80080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH',
                                   0x800C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x800C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x800C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_DAC',
                                   0x80080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_OWNER',
                                   0x80080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_OWNER',
                                   0x80080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | WRITE_OWNER',
                                   0x81080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x81080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | ACCESS_SYSTEM_SECURITY',
                                   0x40080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED',
                                   0x40080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED',
                                   0x40080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED',
                                   0x400C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x400C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x400C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0x40080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0x40080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0x40080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0x41080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0x41080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC0000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0000001: 'PIPE_ACCESS_INBOUND| FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0040003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC0040001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC0040002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC1000003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1000001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1000002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC0080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC0080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED',
                                   0xC00C0003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC00C0001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC00C0002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_DAC',
                                   0xC0080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0xC0080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0xC0080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | WRITE_OWNER',
                                   0xC1080003: 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1080001: 'PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY',
                                   0xC1080002: 'PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | ACCESS_SYSTEM_SECURITY'}
        dwPipeModeReverseLookUp = {
            0x00000000: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000001: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000002: 'PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000003: 'PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000004: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000005: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000006: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000007: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_ACCEPT_REMOTE_CLIENTS',
            0x00000008: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x00000009: 'PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000A: 'PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000C: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000D: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000E: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS',
            0x0000000F: 'PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS'}
        nMaxInstancesReverseLookUp = {255: 'PIPE_UNLIMITED_INSTANCES'}

        name = read_string(uc, pVals[0])

        if pVals[1] == 1:
            pipeHandle = Handle(HandleType.ReadPipe, data=name)
        elif pVals[1] == 2:
            pipeHandle = Handle(HandleType.WritePipe, data=name)
        else:
            pipeHandle = Handle(HandleType.ReadWritePipe, data=name)

        pVals[1] = getLookUpVal(pVals[1], dwOpenModeReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2], dwPipeModeReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3], nMaxInstancesReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1, 2, 3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = pipeHandle.value
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateNamedPipeW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def MultiByteToWideChar(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['UINT', 'DWORD', 'LPCSTR', 'int', 'LPWSTR', 'int']
        pNames = ['CodePage', 'dwFlags', 'lpMultiByteStr', 'cbMultiByte', 'lpWideCharStr', 'cchWideChar']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("MultiByteToWideChar", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def WideCharToMultiByte(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['UINT', 'DWORD', 'LPCWSTR', 'int', 'LPSTR', 'int', 'LPCSTR', 'LPBOOL']
        pNames = ['CodePage', 'dwFlags', 'lpWideCharStr', 'cchWideChar', 'lpMultiByteStr', 'cbMultiByte',
                  'lpDefaultChar',
                  'lpUsedDefaultChar']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("WideCharToMultiByte", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetComputerNameA(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameA([out] LPSTR lpBuffer,[in, out] LPDWORD nSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'nSize']

        computerName = 'Desktop-SHAREM'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[1], pack('<I', len(computerName)))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetComputerNameW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameW([out] LPWSTR lpBuffer,[in, out] LPDWORD nSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPWSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'nSize']

        computerName = 'Desktop-SHAREM'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[1], pack('<I', len(computerName)))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetComputerNameExA(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameExA([in] COMPUTER_NAME_FORMAT NameType,[out] LPSTR  lpBuffer,[in, out] LPDWORD nSize);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['COMPUTER_NAME_FORMAT', 'LPSTR', 'LPDWORD']
        pNames = ['NameType', 'lpBuffer', 'nSize']
        nameTypeReverseLookup = {0: 'ComputerNameNetBIOS', 1: 'ComputerNameDnsHostname', 2: 'ComputerNameDnsDomain',
                                 3: 'ComputerNameDnsFullyQualified', 4: 'ComputerNamePhysicalNetBIOS',
                                 5: 'ComputerNamePhysicalDnsHostname', 6: 'ComputerNamePhysicalDnsDomain',
                                 7: 'ComputerNamePhysicalDnsFullyQualified', 8: 'ComputerNameMax'}
        # Possibly Implement Different Formats
        pVals[0] = getLookUpVal(pVals[0], nameTypeReverseLookup)

        computerName = 'Desktop-SHAREM'.encode('ascii')
        uc.mem_write(pVals[1], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[2], pack('<I', len(computerName)))

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetComputerNameExW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetComputerNameExW([in] COMPUTER_NAME_FORMAT NameType,[out] LPWSTR  lpBuffer,[in, out] LPDWORD nSize);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['COMPUTER_NAME_FORMAT', 'LPWSTR', 'LPDWORD']
        pNames = ['NameType', 'lpBuffer', 'nSize']
        nameTypeReverseLookup = {0: 'ComputerNameNetBIOS', 1: 'ComputerNameDnsHostname', 2: 'ComputerNameDnsDomain',
                                 3: 'ComputerNameDnsFullyQualified', 4: 'ComputerNamePhysicalNetBIOS',
                                 5: 'ComputerNamePhysicalDnsHostname', 6: 'ComputerNamePhysicalDnsDomain',
                                 7: 'ComputerNamePhysicalDnsFullyQualified', 8: 'ComputerNameMax'}
        # Possibly Implement Different Formats
        pVals[0] = getLookUpVal(pVals[0], nameTypeReverseLookup)

        computerName = 'Desktop-SHAREM'.encode('utf-16')[2:]
        uc.mem_write(pVals[1], pack(f'<{len(computerName) + 2}s', computerName))
        uc.mem_write(pVals[2], pack('<I', len(computerName)))

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetComputerNameExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def gethostname(self, uc, eip, esp, export_dict, callAddr, em):
        # int gethostname([out] char *name,[in]  int  namelen);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['char', 'int']
        pNames = ['*name', 'namelen']

        computerName = 'Desktop-SHAREM'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(computerName) + 2}s', computerName))

        pVals[0] = read_string(uc, pVals[0])

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("gethostname", hex(callAddr), (retValStr), 'int', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetWindowsDirectoryA(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetWindowsDirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']

        path = 'C:\Windows'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetWindowsDirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetWindowsDirectoryW(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetWindowsDirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPWSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']

        path = 'C:\Windows'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetWindowsDirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetSystemWindowsDirectoryA(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWindowsDirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']

        path = 'C:\Windows'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWindowsDirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetSystemWindowsDirectoryW(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWindowsDirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPWSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']

        path = 'C:\Windows'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWindowsDirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetTempPathA(self, uc, eip, esp, export_dict, callAddr, em):
        # DWORD GetTempPathA([in]  DWORD nBufferLength,[out] LPSTR lpBuffer);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['DWORD', 'LPSTR', ]
        pNames = ['nBufferLength', 'lpBuffer', ]

        path = 'C:\TEMP\\'.encode('ascii')
        uc.mem_write(pVals[1], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempPathA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetTempPathW(self, uc, eip, esp, export_dict, callAddr, em):
        # DWORD GetTempPathW([in]  DWORD nBufferLength,[out] LPWSTR lpBuffer);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['DWORD', 'LPWSTR', ]
        pNames = ['nBufferLength', 'lpBuffer', ]

        path = 'C:\TEMP\\'.encode('utf-16')[2:]
        uc.mem_write(pVals[1], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempPathW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetTempFileNameA(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetTempFileNameA([in]  LPCSTR lpPathName,[in]  LPCSTR lpPrefixString,[in]  UINT   uUnique,[out] LPSTR  lpTempFileName);
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['LPCSTR', 'LPCSTR', 'UINT', 'LPSTR']
        pNames = ['lpPathName', 'lpPrefixString', 'uUnique', 'lpTempFileName']

        tempPath = read_string(uc, pVals[0])
        preFix = read_string(uc, pVals[1])

        if pVals[2] == 0x0:
            retVal = randint(0x0, 0xffff)
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}SHAREM{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}SHAREM{value}.TMP'
        else:
            retVal = pVals[2]
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}SHAREM{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}SHAREM{value}.TMP'

        pathEncoded = path.encode('ascii')
        uc.mem_write(pVals[3], pack(f'<{len(pathEncoded)}s', pathEncoded))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempFileNameA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetTempFileNameW(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetTempFileNameW([in]  LPCWSTR lpPathName,[in]  LPCWSTR lpPrefixString,[in]  UINT   uUnique,[out] LPWSTR  lpTempFileName);
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['LPCWSTR', 'LPCWSTR', 'UINT', 'LPWSTR']
        pNames = ['lpPathName', 'lpPrefixString', 'uUnique', 'lpTempFileName']

        tempPath = read_unicode(uc, pVals[0])
        preFix = read_unicode(uc, pVals[1])

        if pVals[2] == 0x0:
            retVal = randint(0x0, 0xffff)
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}SHAREM{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}SHAREM{value}.TMP'
        else:
            retVal = pVals[2]
            value = hex(retVal)[2:]
            while len(value) < 4:  # Pad to 4
                value = str(0) + value
            if preFix != '[NULL]':
                path = f'{tempPath}SHAREM{preFix[:3]}{value}.TMP'
            else:
                path = f'{tempPath}SHAREM{value}.TMP'

        pathEncoded = path.encode('utf-16')[2:]

        uc.mem_write(pVals[3], pack(f'<{len(pathEncoded) + 2}s', pathEncoded))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetTempFileNameW", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetSystemWow64DirectoryA(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWow64DirectoryA([out] LPSTR lpBuffer,[in]  UINT  uSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']

        path = 'C:\Windows\SysWOW64'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWow64DirectoryA", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetSystemWow64DirectoryW(self, uc, eip, esp, export_dict, callAddr, em):
        # UINT GetSystemWow64DirectoryW([out] LPWSTR lpBuffer,[in]  UINT  uSize);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPWSTR', 'UNINT']
        pNames = ['lpBuffer', 'uSize']

        path = 'C:\Windows\SysWOW64'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(path) + 2}s', path))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = len(path)
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemWow64DirectoryW", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetSystemTime(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # void GetSystemTime([out] LPSYSTEMTIME lpSystemTime);
        pTypes = ['LPSYSTEMTIME']
        pNames = ['lpSystemTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        if pVals[0] != 0x0:
            timeVal = struct_SYSTEMTIME(True)
            timeVal.writeToMemory(uc, pVals[0])

        pVals[0] = makeStructVals(uc, timeVal, pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal= 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetSystemTime", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetLocalTime(self, uc, eip, esp, export_dict, callAddr, em):
        # void GetLocalTime([out] LPSYSTEMTIME lpSystemTime);
        pTypes = ['LPSYSTEMTIME']
        pNames = ['lpSystemTime']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        if pVals[0] != 0x0:
            timeVal = struct_SYSTEMTIME(False)
            timeVal.writeToMemory(uc, pVals[0])

        pVals[0] = makeStructVals(uc, timeVal, pVals[0])

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[0])

        retVal= 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetLocalTime", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetUserNameA(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetUserNameA([out] LPSTR lpBuffer,[in, out] LPDWORD pcbBuffer);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'pcbBuffer']

        username = 'Administrator'.encode('ascii')
        uc.mem_write(pVals[0], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[1], pack('<I', len(username)))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetUserNameW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL GetUserNameW([out] LPWSTR lpBuffer,[in, out] LPDWORD pcbBuffer);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['LPWSTR', 'LPDWORD']
        pNames = ['lpBuffer', 'pcbBuffer']

        username = 'Administrator'.encode('utf-16')[2:]
        uc.mem_write(pVals[0], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[1], pack('<I', len(username)))

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetUserNameExA(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOLEAN SEC_ENTRY GetUserNameExA([in] EXTENDED_NAME_FORMAT NameFormat,[out] LPSTR lpNameBuffer,[in, out] PULONG nSize);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['EXTENDED_NAME_FORMAT', 'LPSTR', 'LPDWORD']
        pNames = ['NameFormat', 'lpBuffer', 'pcbBuffer']
        nameFormatReverseLookup = {0: 'NameUnknown', 1: 'NameFullyQualifiedDN', 2: 'NameSamCompatible',
                                   3: 'NameDisplay',
                                   6: 'NameUniqueId', 7: 'NameCanonical', 8: 'NameUserPrincipal', 9: 'NameCanonicalEx',
                                   10: 'NameServicePrincipal', 12: 'NameDnsDomain', 13: 'NameGivenName',
                                   14: 'NameSurname'}
        # Possibly Implement Different Formats
        username = 'Administrator'.encode('ascii')
        uc.mem_write(pVals[1], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[2], pack('<I', len(username)))

        pVals[0] = getLookUpVal(pVals[0], nameFormatReverseLookup)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameExA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetUserNameExW(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOLEAN SEC_ENTRY GetUserNameExW([in] EXTENDED_NAME_FORMAT NameFormat,[out] LPWSTR lpNameBuffer,[in, out] PULONG nSize);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['EXTENDED_NAME_FORMAT', 'LPWSTR', 'LPDWORD']
        pNames = ['NameFormat', 'lpBuffer', 'pcbBuffer']
        nameFormatReverseLookup = {0: 'NameUnknown', 1: 'NameFullyQualifiedDN', 2: 'NameSamCompatible',
                                   3: 'NameDisplay',
                                   6: 'NameUniqueId', 7: 'NameCanonical', 8: 'NameUserPrincipal', 9: 'NameCanonicalEx',
                                   10: 'NameServicePrincipal', 12: 'NameDnsDomain', 13: 'NameGivenName',
                                   14: 'NameSurname'}
        # Possibly Implement Different Formats
        username = 'Administrator'.encode('utf-16')[2:]
        uc.mem_write(pVals[1], pack(f'<{len(username) + 2}s', username))
        uc.mem_write(pVals[2], pack('<I', len(username)))

        pVals[0] = getLookUpVal(pVals[0], nameFormatReverseLookup)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetUserNameExW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def TerminateProcess(self, uc, eip, esp, export_dict, callAddr, em):
        # 'TerminateProcess': (2, ['HANDLE', 'UINT'], ['hProcess', 'uExitCode'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'UINT']
        pNames = ['hProcess', 'uExitCode']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("TerminateProcess", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Sleep(self, uc, eip, esp, export_dict, callAddr, em):
        # 'Sleep': (1, ['DWORD'], ['dwMilliseconds'], 'thunk void')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['DWORD']
        pNames = ['dwMilliseconds']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("Sleep", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetDesktopWindow(self, uc, eip, esp, export_dict, callAddr, em):
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

    def GetForegroundWindow(self, uc, eip, esp, export_dict, callAddr, em):
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
    
    def GetDesktopWindow(self, uc, eip, esp, export_dict, callAddr, em):
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


    def CloseHandle(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL CloseHandle( [in] HANDLE hObject);
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HANDLE']
        pNames = ['hObject']

        handle = pVals[0]

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[])

        if handle in HandlesDict:
            HandlesDict.pop(handle)

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CloseHandle", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    def GetFileSizeEx(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HANDLE', 'PLARGE_INTEGER']
        pNames = ['hFile', 'lpFileSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        #handle = Handle(HandleType.HWND, name='ForegroundWindow')

        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetFileSizeEx", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, stackCleanup(uc, em, esp, len(pTypes))

    ### Has a structure of OSVERSIONINFOA, need help with.
    def GetVersionExA(self, uc, eip, esp, export_dict, callAddr, em):
        # 'GetVersionExA': (1, ['LPOSVERSIONINFOA'], ['lpVersionInformation'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['LPOSVERSIONINFOA']
        pNames = ['lpVersionInformation']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetVersionExA", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetErrorMode(self, uc, eip, esp, export_dict, callAddr, em):
        # 'SetErrorMode': (1, ['UINT'], ['uMode'], 'UINT'),
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['UINT']
        pNames = ['uMode']
        SetErrorModeFormatReverseLookup = {0: '', 1: 'SEM_FAILCRITICALERRORS', 4: 'SEM_NOALIGNMENTFAULTEXCEPT',
                                           2: 'SEM_NOGPFAULTERRORBOX', 32768: 'SEM_NOOPENFILEERRORBOX'}
        pVals[0] = getLookUpVal(pVals[0], SetErrorModeFormatReverseLookup)
        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x0  # returns a the previous state of the error-mode bit flags
        retValStr = ''
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetErrorMode", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetEndOfFile(self, uc, eip, esp, export_dict, callAddr, em):
        # 'GetVersionExA': (1, ['LPOSVERSIONINFOA'], ['lpVersionInformation'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HANDLE']
        pNames = ['hFile']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetEndOfFile", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ResetEvent(self, uc, eip, esp, export_dict, callAddr, em):
        # 'GetVersionExA': (1, ['LPOSVERSIONINFOA'], ['lpVersionInformation'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HANDLE']
        pNames = ['hEvent']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ResetEvent", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def WaitForSingleObjectEx(self, uc, eip, esp, export_dict, callAddr, em):
        # 'WaitForSingleObjectEx': (3, ['HANDLE', 'DWORD', 'BOOL'], ['hHandle', 'dwMilliseconds', 'bAlertable'], 'thunk DWORD')
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HANDLE', 'DWORD', 'BOOL']
        pNames = ['hHandle', 'dwMilliseconds', 'bAlertable']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x00000000
        retValStr = 'WAIT_OBJECT_0'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("WaitForSingleObjectEx", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetModuleHandleA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCSTR'] 
        pNames = ['lpModuleName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x00808080
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
       
        logged_calls= ("GetModuleHandleA", hex(callAddr), (retValStr), 'HMODULE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetModuleHandleW(self, uc, eip, esp, export_dict, callAddr, em):
        # GetModuleHandleW': (1, ['LPCWSTR'], ['lpModuleName'], 'HMODULE'),
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCWSTR']
        pNames = ['lpModuleName']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x00808080
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetModuleHandleW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetModuleFileNameA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HMODULE', 'LPSTR', 'DWORD']
        pNames = ['hModule', 'lpFilename', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        #string1 = read_string(uc, pVals[1])
        #try:
            #uc.mem_write(pVals[0], pack(f'<{pVals[2]}s', string1.encode("ascii")))
        #except:
            #pass

        #retVal = pVals[0]

        skip = []  
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetModuleFileNameA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetModuleFileNameExA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes = ['HMODULE', 'LPSTR', 'DWORD']
        pNames = ['hModule', 'lpFilename', 'nSize']
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        #string1 = read_string(uc, pVals[1])
        #try:
            #uc.mem_write(pVals[0], pack(f'<{pVals[2]}s', string1.encode("ascii")))
        #except:
            #pass

        #retVal = pVals[0]

        skip = []  
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetModuleFileNameExA", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SleepEx(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['DWORD', 'BOOL']
        pNames = ['dwMilliseconds', 'bAlertable']

        skip = []  
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x0
        retValStr = "SUCCESS - Specified Time Interval Expired"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SleepEx", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def TlsFree(self, uc, eip, esp, export_dict, callAddr, em):
        # ''TlsFree': (1, ['DWORD'], ['dwTlsIndex'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['DWORD']
        pNames = ['dwTlsIndex']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("TlsFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FlsFree(self, uc, eip, esp, export_dict, callAddr, em):
        # ''TlsFree': (1, ['DWORD'], ['dwTlsIndex'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['DWORD']
        pNames = ['dwFlsIndex']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("FlsFree", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GlobalFree(self, uc, eip, esp, export_dict, callAddr, em):
        # 'GlobalFree': (1, ['HGLOBAL'], ['hMem'], 'HGLOBAL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HGLOBAL']
        pNames = ['hMem']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0
        retValStr = 'NULL'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("GlobalFree", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LocalFree(self, uc, eip, esp, export_dict, callAddr, em):
        # ''LocalFree': (1, ['HLOCAL'], ['hMem'], 'HLOCAL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HLOCAL']
        pNames = ['hMem']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0
        retValStr = 'NULL'
        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("LocalFree", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FlushFileBuffers(self, uc, eip, esp, export_dict, callAddr, em):
        # 'FlushFileBuffers': (1, ['HANDLE'], ['hFile'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HANDLE']
        pNames = ['hFile']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("FlushFileBuffers", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def IsDebuggerPresent(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 0)
        pTypes = []
        pNames = []

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        retVal = 0
        retValStr = 'False'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("IsDebuggerPresent", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

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

    def SetClipboardData(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['UINT', 'HANDLE'] 
        pNames = ['uFormat', 'hMem'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        # ClipBoard = auto() handle type at top
        FormatReverseLookUp = {2: 'CF_BITMAP', 8: 'CF_DIB', 17: 'CF_DIBV5', 5: 'CF_DIF', 130: 'CF_DSPBITMAP', 142: 'CF_DSPENHMETAFILE', 131: 'CF_DSPMETAFILEPICT', 129: 'CF_DSPTEXT', 14: 'CF_ENHMETAFILE', 768: 'CF_GDIOBJFIRST', 1023: 'CF_GDIOBJLAST', 15: 'CF_HDROP', 16: 'CF_LOCALE', 3: 'CF_METAFILEPICT', 7: 'CF_OEMTEXT', 128: 'CF_OWNERDISPLAY', 9: 'CF_PALETTE', 10: 'CF_PENDATA', 512: 'CF_PRIVATEFIRST', 767: 'CF_PRIVATELAST', 11: 'CF_RIFF', 4: 'CF_SYLK', 1: 'CF_TEXT', 6: 'CF_TIFF', 13: 'CF_UNICODETEXT', 12: 'CF_WAVE'}

        pVals[0] = getLookUpVal(pVals[0], FormatReverseLookUp)

        skip = [0]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        fakeData = 'https://sharem.com/login/#'

        handle = Handle(HandleType.Clipboard,data=fakeData)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal =  handle.value # if success, return val is handle to data
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
    
        logged_calls= ("SetClipboardData", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetClipboardData(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['UINT'] 
        pNames = ['uFormat'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        # ClipBoard = auto() handle type at top
        FormatReverseLookUp = {2: 'CF_BITMAP', 8: 'CF_DIB', 17: 'CF_DIBV5', 5: 'CF_DIF', 130: 'CF_DSPBITMAP', 142: 'CF_DSPENHMETAFILE', 131: 'CF_DSPMETAFILEPICT', 129: 'CF_DSPTEXT', 14: 'CF_ENHMETAFILE', 768: 'CF_GDIOBJFIRST', 1023: 'CF_GDIOBJLAST', 15: 'CF_HDROP', 16: 'CF_LOCALE', 3: 'CF_METAFILEPICT', 7: 'CF_OEMTEXT', 128: 'CF_OWNERDISPLAY', 9: 'CF_PALETTE', 10: 'CF_PENDATA', 512: 'CF_PRIVATEFIRST', 767: 'CF_PRIVATELAST', 11: 'CF_RIFF', 4: 'CF_SYLK', 1: 'CF_TEXT', 6: 'CF_TIFF', 13: 'CF_UNICODETEXT', 12: 'CF_WAVE'}

        pVals[0] = getLookUpVal(pVals[0], FormatReverseLookUp)

        skip = [0]
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)
        
        fakeData = 'https://sharem.com/login/#'

        handle = Handle(HandleType.ClipBoard,data=fakeData)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal =  handle.value 
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
    
        logged_calls= ("GetClipboardData", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFile2(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR', 'DWORD', 'DWORD', 'DWORD', 'LPSCREATEFILE2_EXTENDED_PARAMETERS'] 
        pNames = ['lpFileName', 'dwDesiredAccess', 'dwShareMode', 'dwCreationDistribution', 'pCreateExParams'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))
        
        
        dwDesiredAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
        dwShareModeReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE', 4: 'FILE_SHARE_DELETE'}
        dwCreationDistributionReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING', 3: 'OPEN_EXISTING', 5: 'TRUNCATE_EXISTING'}
        dwFlagsAndAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 16384: 'FILE_ATTRIBUTE_ENCRYPTED', 2: 'FILE_ATTRIBUTE_HIDDEN', 128: 'FILE_ATTRIBUTE_NORMAL', 4096: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY', 4: 'FILE_ATTRIBUTE_SYSTEM', 256: 'FILE_ATTRIBUTE_TEMPORARY', 33554432: 'FILE_FLAG_BACKUP_SEMANTICS', 67108864: 'FILE_FLAG_DELETE_ON_CLOSE', 536870912: 'FILE_FLAG_NO_BUFFERING', 1048576: 'FILE_FLAG_OPEN_NO_RECALL', 2097152: 'FILE_FLAG_OPEN_REPARSE_POINT', 1073741824: 'FILE_FLAG_OVERLAPPED', 16777216: 'FILE_FLAG_POSIX_SEMANTICS', 268435456: 'FILE_FLAG_RANDOM_ACCESS', 8388608: 'FILE_FLAG_SESSION_AWARE', 134217728: 'FILE_FLAG_SEQUENTIAL_SCAN', 2147483648: 'FILE_FLAG_WRITE_THROUGH'}
        
        fileName = read_unicode(uc, pVals[0])
        handle = Handle(HandleType.CreateFile2, name=fileName)

        pVals[1] = getLookUpVal(pVals[1],dwDesiredAccessReverseLookUp)
        pVals[2] = getLookUpVal(pVals[2],dwShareModeReverseLookUp)
        pVals[3] = getLookUpVal(pVals[3],dwCreationDistributionReverseLookUp)
        pVals[4] = getLookUpVal(pVals[4],dwFlagsAndAttributesReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [1, 2, 3, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal =  handle.value 
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)
    
        logged_calls= ("CreateFile2", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

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

    def lstrcpynA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPSTR', 'LPCSTR', 'int'] 
        pNames = ['lpString1', 'lpString2', 'iMaxLength'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        

        string2 = read_string(uc, pVals[1])
        try:
            uc.mem_write(pVals[0], pack(f'<{pVals[2]}s', string2.encode("ascii")))
        except:
            pass

        retVal = pVals[0]

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)


        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        #retVal =  # pointer to buffer
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcpynA", hex(callAddr), (retValStr), 'LPSTR', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def lstrcpynW(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPWSTR', 'LPCWSTR', 'int'] 
        pNames = ['lpString1', 'lpString2', 'iMaxLength'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        string2 = read_unicode(uc, pVals[1])
        try:
            uc.mem_write(pVals[0], pack(f'<{pVals[2]*2}s', string2.encode("utf-16")[2:]))
        except:
            pass

        retVal = pVals[0]

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)


        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        #retVal =  # pointer to buffer
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("lstrcpynW", hex(callAddr), (retValStr), 'LPWSTR', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CopyFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR', 'LPCWSTR', 'BOOL'] 
        pNames = ['lpExistingFileName', 'lpNewFileName', 'bFailIfExists'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CopyFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CopyFile2(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['PCWSTR', 'PCWSTR', 'COPYFILE2_EXTENDED_PARAMETERS'] 
        pNames = ['pwszExistingFileName', 'pwszNewFileName', '*pExtendedParameters'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        CopyFlagsReverseLookUp = {8: 'COPY_FILE_ALLOW_DECRYPTED_DESTINATION', 2048: 'COPY_FILE_COPY_SYMLINK',
                                     1: 'COPY_FILE_FAIL_IF_EXISTS', 4096: 'COPY_FILE_NO_BUFFERING',
                                     4: 'COPY_FILE_OPEN_SOURCE_FOR_WRITE', 2: 'COPY_FILE_RESTARTABLE',
                                     268435456: 'COPY_FILE_REQUEST_COMPRESSED_TRAFFIC'}

        pVals[2] = getLookUpVal(pVals[2], CopyFlagsReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "S_OK"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("CopyFile2", hex(callAddr), (retValStr), 'HRESULT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def DeleteFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR'] 
        pNames = ['lpFileName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("DeleteFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def DeleteFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCSTR'] 
        pNames = ['lpFilename'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("DeleteFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetFileTime(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'FILETIME', 'FILETIME', 'FILETIME'] 
        pNames = ['hFile', '*lpCreationTime', '*lpLastAccessTime', '*lpLastWriteTime'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "SUCCESS"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SetFileTime", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def OpenClipboard(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND'] 
        pNames = ['hWndNewOwner'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("OpenClipboard", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetTimer(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND', 'UINT_PTR', 'UINT', 'TIMERPROC'] 
        pNames = ['hWnd', 'nIDEvent', 'uElapse', 'lpTimerFunc'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "SUCCESS - New integer identified as timer"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("SetTimer", hex(callAddr), (retValStr), 'UINT_PTR', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def MoveFileA(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCTSTR', 'LPCTSTR'] 
        pNames = ['lpExistingFileName', 'lpNewFileName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("MoveFileA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def MoveFileW(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCWSTR', 'LPCWSTR'] 
        pNames = ['lpExistingFileName', 'lpNewFileName'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls= ("MoveFileW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CopyFile(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['LPCSTR', 'LPCSTR', 'BOOL'] 
        pNames = ['lpExistingFileName', 'lpNewFileName', 'bFailIfExists'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "SUCCESSFUL"
        uc.reg_write(UC_X86_REG_EAX, retVal)
        # "0x15e17a55": ["CopyFile", "kernel32.dll"],
        logged_calls= ("CopyFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ReadFile(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HANDLE', 'LPVOID', 'DWORD', 'LPDWORD', 'LPOVERLAPPED'] 
        pNames = ['hFile', 'lpBuffer', 'nNumberOfBytesToRead', 'lpNumberOfBytesRead', 'lpOverlapped'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "TRUE"
        uc.reg_write(UC_X86_REG_EAX, retVal)
        
        logged_calls= ("ReadFile", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetForegroundWindow(self, uc, eip, esp, export_dict, callAddr, em):
        pTypes =['HWND'] 
        pNames = ['hWnd'] 
        pVals = makeArgVals(uc, em, esp, len(pTypes))

        skip = []
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes = cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0x1
        retValStr = "Window Successfully Brought to Foreground"
        uc.reg_write(UC_X86_REG_EAX, retVal)
       
        logged_calls= ("SetForegroundWindow", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetLastError(self, uc, eip, esp, export_dict, callAddr, em):
        # void SetLastError([in] DWORD dwErrCode);
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['DWORD']
        pNames = ['dwErrCode']
        ErrorCodeReverseLookUp = {0: 'ERROR_SUCCESS', 1: 'ERROR_INVALID_FUNCTION', 2: 'ERROR_FILE_NOT_FOUND',
                                  3: 'ERROR_PATH_NOT_FOUND', 4: 'ERROR_TOO_MANY_OPEN_FILES', 5: 'ERROR_ACCESS_DENIED',
                                  6: 'ERROR_INVALID_HANDLE', 7: 'ERROR_ARENA_TRASHED', 8: 'ERROR_NOT_ENOUGH_MEMORY',
                                  9: 'ERROR_INVALID_BLOCK', 10: 'ERROR_BAD_ENVIRONMENT', 11: 'ERROR_BAD_FORMAT',
                                  12: 'ERROR_INVALID_ACCESS', 13: 'ERROR_INVALID_DATA', 14: 'ERROR_OUTOFMEMORY',
                                  15: 'ERROR_INVALID_DRIVE', 16: 'ERROR_CURRENT_DIRECTORY', 17: 'ERROR_NOT_SAME_DEVICE',
                                  18: 'ERROR_NO_MORE_FILES', 19: 'ERROR_WRITE_PROTECT', 20: 'ERROR_BAD_UNIT',
                                  21: 'ERROR_NOT_READY', 22: 'ERROR_BAD_COMMAND', 23: 'ERROR_CRC',
                                  24: 'ERROR_BAD_LENGTH',
                                  25: 'ERROR_SEEK', 26: 'ERROR_NOT_DOS_DISK', 27: 'ERROR_SECTOR_NOT_FOUND',
                                  28: 'ERROR_OUT_OF_PAPER', 29: 'ERROR_WRITE_FAULT', 30: 'ERROR_READ_FAULT',
                                  31: 'ERROR_GEN_FAILURE', 32: 'ERROR_SHARING_VIOLATION', 33: 'ERROR_LOCK_VIOLATION',
                                  34: 'ERROR_WRONG_DISK', 36: 'ERROR_SHARING_BUFFER_EXCEEDED', 38: 'ERROR_HANDLE_EOF',
                                  39: 'ERROR_HANDLE_DISK_FULL', 50: 'ERROR_NOT_SUPPORTED', 51: 'ERROR_REM_NOT_LIST',
                                  52: 'ERROR_DUP_NAME', 53: 'ERROR_BAD_NETPATH', 54: 'ERROR_NETWORK_BUSY',
                                  55: 'ERROR_DEV_NOT_EXIST', 56: 'ERROR_TOO_MANY_CMDS', 57: 'ERROR_ADAP_HDW_ERR',
                                  58: 'ERROR_BAD_NET_RESP', 59: 'ERROR_UNEXP_NET_ERR', 60: 'ERROR_BAD_REM_ADAP',
                                  61: 'ERROR_PRINTQ_FULL', 62: 'ERROR_NO_SPOOL_SPACE', 63: 'ERROR_PRINT_CANCELLED',
                                  64: 'ERROR_NETNAME_DELETED', 65: 'ERROR_NETWORK_ACCESS_DENIED',
                                  66: 'ERROR_BAD_DEV_TYPE',
                                  67: 'ERROR_BAD_NET_NAME', 68: 'ERROR_TOO_MANY_NAMES', 69: 'ERROR_TOO_MANY_SESS',
                                  70: 'ERROR_SHARING_PAUSED', 71: 'ERROR_REQ_NOT_ACCEP', 72: 'ERROR_REDIR_PAUSED',
                                  80: 'ERROR_FILE_EXISTS', 82: 'ERROR_CANNOT_MAKE', 83: 'ERROR_FAIL_I24',
                                  84: 'ERROR_OUT_OF_STRUCTURES', 85: 'ERROR_ALREADY_ASSIGNED',
                                  86: 'ERROR_INVALID_PASSWORD',
                                  87: 'ERROR_INVALID_PARAMETER', 88: 'ERROR_NET_WRITE_FAULT', 89: 'ERROR_NO_PROC_SLOTS',
                                  100: 'ERROR_TOO_MANY_SEMAPHORES', 101: 'ERROR_EXCL_SEM_ALREADY_OWNED',
                                  102: 'ERROR_SEM_IS_SET', 103: 'ERROR_TOO_MANY_SEM_REQUESTS',
                                  104: 'ERROR_INVALID_AT_INTERRUPT_TIME', 105: 'ERROR_SEM_OWNER_DIED',
                                  106: 'ERROR_SEM_USER_LIMIT', 107: 'ERROR_DISK_CHANGE', 108: 'ERROR_DRIVE_LOCKED',
                                  109: 'ERROR_BROKEN_PIPE', 110: 'ERROR_OPEN_FAILED', 111: 'ERROR_BUFFER_OVERFLOW',
                                  112: 'ERROR_DISK_FULL', 113: 'ERROR_NO_MORE_SEARCH_HANDLES',
                                  114: 'ERROR_INVALID_TARGET_HANDLE', 117: 'ERROR_INVALID_CATEGORY',
                                  118: 'ERROR_INVALID_VERIFY_SWITCH', 119: 'ERROR_BAD_DRIVER_LEVEL',
                                  120: 'ERROR_CALL_NOT_IMPLEMENTED', 121: 'ERROR_SEM_TIMEOUT',
                                  122: 'ERROR_INSUFFICIENT_BUFFER', 123: 'ERROR_INVALID_NAME',
                                  124: 'ERROR_INVALID_LEVEL',
                                  125: 'ERROR_NO_VOLUME_LABEL', 126: 'ERROR_MOD_NOT_FOUND', 127: 'ERROR_PROC_NOT_FOUND',
                                  128: 'ERROR_WAIT_NO_CHILDREN', 129: 'ERROR_CHILD_NOT_COMPLETE',
                                  130: 'ERROR_DIRECT_ACCESS_HANDLE', 131: 'ERROR_NEGATIVE_SEEK',
                                  132: 'ERROR_SEEK_ON_DEVICE', 133: 'ERROR_IS_JOIN_TARGET', 134: 'ERROR_IS_JOINED',
                                  135: 'ERROR_IS_SUBSTED', 136: 'ERROR_NOT_JOINED', 137: 'ERROR_NOT_SUBSTED',
                                  138: 'ERROR_JOIN_TO_JOIN', 139: 'ERROR_SUBST_TO_SUBST', 140: 'ERROR_JOIN_TO_SUBST',
                                  141: 'ERROR_SUBST_TO_JOIN', 142: 'ERROR_BUSY_DRIVE', 143: 'ERROR_SAME_DRIVE',
                                  144: 'ERROR_DIR_NOT_ROOT', 145: 'ERROR_DIR_NOT_EMPTY', 146: 'ERROR_IS_SUBST_PATH',
                                  147: 'ERROR_IS_JOIN_PATH', 148: 'ERROR_PATH_BUSY', 149: 'ERROR_IS_SUBST_TARGET',
                                  150: 'ERROR_SYSTEM_TRACE', 151: 'ERROR_INVALID_EVENT_COUNT',
                                  152: 'ERROR_TOO_MANY_MUXWAITERS', 153: 'ERROR_INVALID_LIST_FORMAT',
                                  154: 'ERROR_LABEL_TOO_LONG', 155: 'ERROR_TOO_MANY_TCBS', 156: 'ERROR_SIGNAL_REFUSED',
                                  157: 'ERROR_DISCARDED', 158: 'ERROR_NOT_LOCKED', 159: 'ERROR_BAD_THREADID_ADDR',
                                  160: 'ERROR_BAD_ARGUMENTS', 161: 'ERROR_BAD_PATHNAME', 162: 'ERROR_SIGNAL_PENDING',
                                  164: 'ERROR_MAX_THRDS_REACHED', 167: 'ERROR_LOCK_FAILED', 170: 'ERROR_BUSY',
                                  171: 'ERROR_DEVICE_SUPPORT_IN_PROGRESS', 173: 'ERROR_CANCEL_VIOLATION',
                                  174: 'ERROR_ATOMIC_LOCKS_NOT_SUPPORTED', 180: 'ERROR_INVALID_SEGMENT_NUMBER',
                                  182: 'ERROR_INVALID_ORDINAL', 183: 'ERROR_ALREADY_EXISTS',
                                  186: 'ERROR_INVALID_FLAG_NUMBER', 187: 'ERROR_SEM_NOT_FOUND',
                                  188: 'ERROR_INVALID_STARTING_CODESEG', 189: 'ERROR_INVALID_STACKSEG',
                                  190: 'ERROR_INVALID_MODULETYPE', 191: 'ERROR_INVALID_EXE_SIGNATURE',
                                  192: 'ERROR_EXE_MARKED_INVALID', 193: 'ERROR_BAD_EXE_FORMAT',
                                  194: 'ERROR_ITERATED_DATA_EXCEEDS_64k', 195: 'ERROR_INVALID_MINALLOCSIZE',
                                  196: 'ERROR_DYNLINK_FROM_INVALID_RING', 197: 'ERROR_IOPL_NOT_ENABLED',
                                  198: 'ERROR_INVALID_SEGDPL', 199: 'ERROR_AUTODATASEG_EXCEEDS_64k',
                                  200: 'ERROR_RING2SEG_MUST_BE_MOVABLE', 201: 'ERROR_RELOC_CHAIN_XEEDS_SEGLIM',
                                  202: 'ERROR_INFLOOP_IN_RELOC_CHAIN', 203: 'ERROR_ENVVAR_NOT_FOUND',
                                  205: 'ERROR_NO_SIGNAL_SENT', 206: 'ERROR_FILENAME_EXCED_RANGE',
                                  207: 'ERROR_RING2_STACK_IN_USE', 208: 'ERROR_META_EXPANSION_TOO_LONG',
                                  209: 'ERROR_INVALID_SIGNAL_NUMBER', 210: 'ERROR_THREAD_1_INACTIVE',
                                  212: 'ERROR_LOCKED',
                                  214: 'ERROR_TOO_MANY_MODULES', 215: 'ERROR_NESTING_NOT_ALLOWED',
                                  216: 'ERROR_EXE_MACHINE_TYPE_MISMATCH', 217: 'ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY',
                                  218: 'ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY', 220: 'ERROR_FILE_CHECKED_OUT',
                                  221: 'ERROR_CHECKOUT_REQUIRED', 222: 'ERROR_BAD_FILE_TYPE',
                                  223: 'ERROR_FILE_TOO_LARGE',
                                  224: 'ERROR_FORMS_AUTH_REQUIRED', 225: 'ERROR_VIRUS_INFECTED',
                                  226: 'ERROR_VIRUS_DELETED',
                                  229: 'ERROR_PIPE_LOCAL', 230: 'ERROR_BAD_PIPE', 231: 'ERROR_PIPE_BUSY',
                                  232: 'ERROR_NO_DATA', 233: 'ERROR_PIPE_NOT_CONNECTED', 234: 'ERROR_MORE_DATA',
                                  240: 'ERROR_VC_DISCONNECTED', 254: 'ERROR_INVALID_EA_NAME',
                                  255: 'ERROR_EA_LIST_INCONSISTENT', 258: 'WAIT_TIMEOUT', 259: 'ERROR_NO_MORE_ITEMS',
                                  266: 'ERROR_CANNOT_COPY', 267: 'ERROR_DIRECTORY', 275: 'ERROR_EAS_DIDNT_FIT',
                                  276: 'ERROR_EA_FILE_CORRUPT', 277: 'ERROR_EA_TABLE_FULL',
                                  278: 'ERROR_INVALID_EA_HANDLE',
                                  282: 'ERROR_EAS_NOT_SUPPORTED', 288: 'ERROR_NOT_OWNER', 298: 'ERROR_TOO_MANY_POSTS',
                                  299: 'ERROR_PARTIAL_COPY', 300: 'ERROR_OPLOCK_NOT_GRANTED',
                                  301: 'ERROR_INVALID_OPLOCK_PROTOCOL', 302: 'ERROR_DISK_TOO_FRAGMENTED',
                                  303: 'ERROR_DELETE_PENDING',
                                  304: 'ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING',
                                  305: 'ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME',
                                  306: 'ERROR_SECURITY_STREAM_IS_INCONSISTENT', 307: 'ERROR_INVALID_LOCK_RANGE',
                                  308: 'ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT',
                                  309: 'ERROR_NOTIFICATION_GUID_ALREADY_DEFINED',
                                  310: 'ERROR_INVALID_EXCEPTION_HANDLER', 311: 'ERROR_DUPLICATE_PRIVILEGES',
                                  312: 'ERROR_NO_RANGES_PROCESSED', 313: 'ERROR_NOT_ALLOWED_ON_SYSTEM_FILE',
                                  314: 'ERROR_DISK_RESOURCES_EXHAUSTED', 315: 'ERROR_INVALID_TOKEN',
                                  316: 'ERROR_DEVICE_FEATURE_NOT_SUPPORTED', 317: 'ERROR_MR_MID_NOT_FOUND',
                                  318: 'ERROR_SCOPE_NOT_FOUND', 319: 'ERROR_UNDEFINED_SCOPE', 320: 'ERROR_INVALID_CAP',
                                  321: 'ERROR_DEVICE_UNREACHABLE', 322: 'ERROR_DEVICE_NO_RESOURCES',
                                  323: 'ERROR_DATA_CHECKSUM_ERROR', 324: 'ERROR_INTERMIXED_KERNEL_EA_OPERATION',
                                  326: 'ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED', 327: 'ERROR_OFFSET_ALIGNMENT_VIOLATION',
                                  328: 'ERROR_INVALID_FIELD_IN_PARAMETER_LIST', 329: 'ERROR_OPERATION_IN_PROGRESS',
                                  330: 'ERROR_BAD_DEVICE_PATH', 331: 'ERROR_TOO_MANY_DESCRIPTORS',
                                  332: 'ERROR_SCRUB_DATA_DISABLED', 333: 'ERROR_NOT_REDUNDANT_STORAGE',
                                  334: 'ERROR_RESIDENT_FILE_NOT_SUPPORTED', 335: 'ERROR_COMPRESSED_FILE_NOT_SUPPORTED',
                                  336: 'ERROR_DIRECTORY_NOT_SUPPORTED', 337: 'ERROR_NOT_READ_FROM_COPY',
                                  350: 'ERROR_FAIL_NOACTION_REBOOT', 351: 'ERROR_FAIL_SHUTDOWN',
                                  352: 'ERROR_FAIL_RESTART',
                                  353: 'ERROR_MAX_SESSIONS_REACHED', 400: 'ERROR_THREAD_MODE_ALREADY_BACKGROUND',
                                  401: 'ERROR_THREAD_MODE_NOT_BACKGROUND', 402: 'ERROR_PROCESS_MODE_ALREADY_BACKGROUND',
                                  403: 'ERROR_PROCESS_MODE_NOT_BACKGROUND', 487: 'ERROR_INVALID_ADDRESS'}
        global lastErrorCode

        lastErrorCode = pVals[0]

        pVals[0] = getLookUpVal(pVals[0], ErrorCodeReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = 0
        retValStr = 'None'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("SetLastError", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetLastErrorEx(self, uc, eip, esp, export_dict, callAddr, em):
        # void SetLastErrorEx([in] DWORD dwErrCode,[in] DWORD dwType);
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['DWORD', 'DWORD']
        pNames = ['dwErrCode', 'dwType']
        ErrorCodeReverseLookUp = {0: 'ERROR_SUCCESS', 1: 'ERROR_INVALID_FUNCTION', 2: 'ERROR_FILE_NOT_FOUND',
                                  3: 'ERROR_PATH_NOT_FOUND', 4: 'ERROR_TOO_MANY_OPEN_FILES', 5: 'ERROR_ACCESS_DENIED',
                                  6: 'ERROR_INVALID_HANDLE', 7: 'ERROR_ARENA_TRASHED', 8: 'ERROR_NOT_ENOUGH_MEMORY',
                                  9: 'ERROR_INVALID_BLOCK', 10: 'ERROR_BAD_ENVIRONMENT', 11: 'ERROR_BAD_FORMAT',
                                  12: 'ERROR_INVALID_ACCESS', 13: 'ERROR_INVALID_DATA', 14: 'ERROR_OUTOFMEMORY',
                                  15: 'ERROR_INVALID_DRIVE', 16: 'ERROR_CURRENT_DIRECTORY', 17: 'ERROR_NOT_SAME_DEVICE',
                                  18: 'ERROR_NO_MORE_FILES', 19: 'ERROR_WRITE_PROTECT', 20: 'ERROR_BAD_UNIT',
                                  21: 'ERROR_NOT_READY', 22: 'ERROR_BAD_COMMAND', 23: 'ERROR_CRC',
                                  24: 'ERROR_BAD_LENGTH',
                                  25: 'ERROR_SEEK', 26: 'ERROR_NOT_DOS_DISK', 27: 'ERROR_SECTOR_NOT_FOUND',
                                  28: 'ERROR_OUT_OF_PAPER', 29: 'ERROR_WRITE_FAULT', 30: 'ERROR_READ_FAULT',
                                  31: 'ERROR_GEN_FAILURE', 32: 'ERROR_SHARING_VIOLATION', 33: 'ERROR_LOCK_VIOLATION',
                                  34: 'ERROR_WRONG_DISK', 36: 'ERROR_SHARING_BUFFER_EXCEEDED', 38: 'ERROR_HANDLE_EOF',
                                  39: 'ERROR_HANDLE_DISK_FULL', 50: 'ERROR_NOT_SUPPORTED', 51: 'ERROR_REM_NOT_LIST',
                                  52: 'ERROR_DUP_NAME', 53: 'ERROR_BAD_NETPATH', 54: 'ERROR_NETWORK_BUSY',
                                  55: 'ERROR_DEV_NOT_EXIST', 56: 'ERROR_TOO_MANY_CMDS', 57: 'ERROR_ADAP_HDW_ERR',
                                  58: 'ERROR_BAD_NET_RESP', 59: 'ERROR_UNEXP_NET_ERR', 60: 'ERROR_BAD_REM_ADAP',
                                  61: 'ERROR_PRINTQ_FULL', 62: 'ERROR_NO_SPOOL_SPACE', 63: 'ERROR_PRINT_CANCELLED',
                                  64: 'ERROR_NETNAME_DELETED', 65: 'ERROR_NETWORK_ACCESS_DENIED',
                                  66: 'ERROR_BAD_DEV_TYPE',
                                  67: 'ERROR_BAD_NET_NAME', 68: 'ERROR_TOO_MANY_NAMES', 69: 'ERROR_TOO_MANY_SESS',
                                  70: 'ERROR_SHARING_PAUSED', 71: 'ERROR_REQ_NOT_ACCEP', 72: 'ERROR_REDIR_PAUSED',
                                  80: 'ERROR_FILE_EXISTS', 82: 'ERROR_CANNOT_MAKE', 83: 'ERROR_FAIL_I24',
                                  84: 'ERROR_OUT_OF_STRUCTURES', 85: 'ERROR_ALREADY_ASSIGNED',
                                  86: 'ERROR_INVALID_PASSWORD',
                                  87: 'ERROR_INVALID_PARAMETER', 88: 'ERROR_NET_WRITE_FAULT', 89: 'ERROR_NO_PROC_SLOTS',
                                  100: 'ERROR_TOO_MANY_SEMAPHORES', 101: 'ERROR_EXCL_SEM_ALREADY_OWNED',
                                  102: 'ERROR_SEM_IS_SET', 103: 'ERROR_TOO_MANY_SEM_REQUESTS',
                                  104: 'ERROR_INVALID_AT_INTERRUPT_TIME', 105: 'ERROR_SEM_OWNER_DIED',
                                  106: 'ERROR_SEM_USER_LIMIT', 107: 'ERROR_DISK_CHANGE', 108: 'ERROR_DRIVE_LOCKED',
                                  109: 'ERROR_BROKEN_PIPE', 110: 'ERROR_OPEN_FAILED', 111: 'ERROR_BUFFER_OVERFLOW',
                                  112: 'ERROR_DISK_FULL', 113: 'ERROR_NO_MORE_SEARCH_HANDLES',
                                  114: 'ERROR_INVALID_TARGET_HANDLE', 117: 'ERROR_INVALID_CATEGORY',
                                  118: 'ERROR_INVALID_VERIFY_SWITCH', 119: 'ERROR_BAD_DRIVER_LEVEL',
                                  120: 'ERROR_CALL_NOT_IMPLEMENTED', 121: 'ERROR_SEM_TIMEOUT',
                                  122: 'ERROR_INSUFFICIENT_BUFFER', 123: 'ERROR_INVALID_NAME',
                                  124: 'ERROR_INVALID_LEVEL',
                                  125: 'ERROR_NO_VOLUME_LABEL', 126: 'ERROR_MOD_NOT_FOUND', 127: 'ERROR_PROC_NOT_FOUND',
                                  128: 'ERROR_WAIT_NO_CHILDREN', 129: 'ERROR_CHILD_NOT_COMPLETE',
                                  130: 'ERROR_DIRECT_ACCESS_HANDLE', 131: 'ERROR_NEGATIVE_SEEK',
                                  132: 'ERROR_SEEK_ON_DEVICE', 133: 'ERROR_IS_JOIN_TARGET', 134: 'ERROR_IS_JOINED',
                                  135: 'ERROR_IS_SUBSTED', 136: 'ERROR_NOT_JOINED', 137: 'ERROR_NOT_SUBSTED',
                                  138: 'ERROR_JOIN_TO_JOIN', 139: 'ERROR_SUBST_TO_SUBST', 140: 'ERROR_JOIN_TO_SUBST',
                                  141: 'ERROR_SUBST_TO_JOIN', 142: 'ERROR_BUSY_DRIVE', 143: 'ERROR_SAME_DRIVE',
                                  144: 'ERROR_DIR_NOT_ROOT', 145: 'ERROR_DIR_NOT_EMPTY', 146: 'ERROR_IS_SUBST_PATH',
                                  147: 'ERROR_IS_JOIN_PATH', 148: 'ERROR_PATH_BUSY', 149: 'ERROR_IS_SUBST_TARGET',
                                  150: 'ERROR_SYSTEM_TRACE', 151: 'ERROR_INVALID_EVENT_COUNT',
                                  152: 'ERROR_TOO_MANY_MUXWAITERS', 153: 'ERROR_INVALID_LIST_FORMAT',
                                  154: 'ERROR_LABEL_TOO_LONG', 155: 'ERROR_TOO_MANY_TCBS', 156: 'ERROR_SIGNAL_REFUSED',
                                  157: 'ERROR_DISCARDED', 158: 'ERROR_NOT_LOCKED', 159: 'ERROR_BAD_THREADID_ADDR',
                                  160: 'ERROR_BAD_ARGUMENTS', 161: 'ERROR_BAD_PATHNAME', 162: 'ERROR_SIGNAL_PENDING',
                                  164: 'ERROR_MAX_THRDS_REACHED', 167: 'ERROR_LOCK_FAILED', 170: 'ERROR_BUSY',
                                  171: 'ERROR_DEVICE_SUPPORT_IN_PROGRESS', 173: 'ERROR_CANCEL_VIOLATION',
                                  174: 'ERROR_ATOMIC_LOCKS_NOT_SUPPORTED', 180: 'ERROR_INVALID_SEGMENT_NUMBER',
                                  182: 'ERROR_INVALID_ORDINAL', 183: 'ERROR_ALREADY_EXISTS',
                                  186: 'ERROR_INVALID_FLAG_NUMBER', 187: 'ERROR_SEM_NOT_FOUND',
                                  188: 'ERROR_INVALID_STARTING_CODESEG', 189: 'ERROR_INVALID_STACKSEG',
                                  190: 'ERROR_INVALID_MODULETYPE', 191: 'ERROR_INVALID_EXE_SIGNATURE',
                                  192: 'ERROR_EXE_MARKED_INVALID', 193: 'ERROR_BAD_EXE_FORMAT',
                                  194: 'ERROR_ITERATED_DATA_EXCEEDS_64k', 195: 'ERROR_INVALID_MINALLOCSIZE',
                                  196: 'ERROR_DYNLINK_FROM_INVALID_RING', 197: 'ERROR_IOPL_NOT_ENABLED',
                                  198: 'ERROR_INVALID_SEGDPL', 199: 'ERROR_AUTODATASEG_EXCEEDS_64k',
                                  200: 'ERROR_RING2SEG_MUST_BE_MOVABLE', 201: 'ERROR_RELOC_CHAIN_XEEDS_SEGLIM',
                                  202: 'ERROR_INFLOOP_IN_RELOC_CHAIN', 203: 'ERROR_ENVVAR_NOT_FOUND',
                                  205: 'ERROR_NO_SIGNAL_SENT', 206: 'ERROR_FILENAME_EXCED_RANGE',
                                  207: 'ERROR_RING2_STACK_IN_USE', 208: 'ERROR_META_EXPANSION_TOO_LONG',
                                  209: 'ERROR_INVALID_SIGNAL_NUMBER', 210: 'ERROR_THREAD_1_INACTIVE',
                                  212: 'ERROR_LOCKED',
                                  214: 'ERROR_TOO_MANY_MODULES', 215: 'ERROR_NESTING_NOT_ALLOWED',
                                  216: 'ERROR_EXE_MACHINE_TYPE_MISMATCH', 217: 'ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY',
                                  218: 'ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY', 220: 'ERROR_FILE_CHECKED_OUT',
                                  221: 'ERROR_CHECKOUT_REQUIRED', 222: 'ERROR_BAD_FILE_TYPE',
                                  223: 'ERROR_FILE_TOO_LARGE',
                                  224: 'ERROR_FORMS_AUTH_REQUIRED', 225: 'ERROR_VIRUS_INFECTED',
                                  226: 'ERROR_VIRUS_DELETED',
                                  229: 'ERROR_PIPE_LOCAL', 230: 'ERROR_BAD_PIPE', 231: 'ERROR_PIPE_BUSY',
                                  232: 'ERROR_NO_DATA', 233: 'ERROR_PIPE_NOT_CONNECTED', 234: 'ERROR_MORE_DATA',
                                  240: 'ERROR_VC_DISCONNECTED', 254: 'ERROR_INVALID_EA_NAME',
                                  255: 'ERROR_EA_LIST_INCONSISTENT', 258: 'WAIT_TIMEOUT', 259: 'ERROR_NO_MORE_ITEMS',
                                  266: 'ERROR_CANNOT_COPY', 267: 'ERROR_DIRECTORY', 275: 'ERROR_EAS_DIDNT_FIT',
                                  276: 'ERROR_EA_FILE_CORRUPT', 277: 'ERROR_EA_TABLE_FULL',
                                  278: 'ERROR_INVALID_EA_HANDLE',
                                  282: 'ERROR_EAS_NOT_SUPPORTED', 288: 'ERROR_NOT_OWNER', 298: 'ERROR_TOO_MANY_POSTS',
                                  299: 'ERROR_PARTIAL_COPY', 300: 'ERROR_OPLOCK_NOT_GRANTED',
                                  301: 'ERROR_INVALID_OPLOCK_PROTOCOL', 302: 'ERROR_DISK_TOO_FRAGMENTED',
                                  303: 'ERROR_DELETE_PENDING',
                                  304: 'ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING',
                                  305: 'ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME',
                                  306: 'ERROR_SECURITY_STREAM_IS_INCONSISTENT', 307: 'ERROR_INVALID_LOCK_RANGE',
                                  308: 'ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT',
                                  309: 'ERROR_NOTIFICATION_GUID_ALREADY_DEFINED',
                                  310: 'ERROR_INVALID_EXCEPTION_HANDLER', 311: 'ERROR_DUPLICATE_PRIVILEGES',
                                  312: 'ERROR_NO_RANGES_PROCESSED', 313: 'ERROR_NOT_ALLOWED_ON_SYSTEM_FILE',
                                  314: 'ERROR_DISK_RESOURCES_EXHAUSTED', 315: 'ERROR_INVALID_TOKEN',
                                  316: 'ERROR_DEVICE_FEATURE_NOT_SUPPORTED', 317: 'ERROR_MR_MID_NOT_FOUND',
                                  318: 'ERROR_SCOPE_NOT_FOUND', 319: 'ERROR_UNDEFINED_SCOPE', 320: 'ERROR_INVALID_CAP',
                                  321: 'ERROR_DEVICE_UNREACHABLE', 322: 'ERROR_DEVICE_NO_RESOURCES',
                                  323: 'ERROR_DATA_CHECKSUM_ERROR', 324: 'ERROR_INTERMIXED_KERNEL_EA_OPERATION',
                                  326: 'ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED', 327: 'ERROR_OFFSET_ALIGNMENT_VIOLATION',
                                  328: 'ERROR_INVALID_FIELD_IN_PARAMETER_LIST', 329: 'ERROR_OPERATION_IN_PROGRESS',
                                  330: 'ERROR_BAD_DEVICE_PATH', 331: 'ERROR_TOO_MANY_DESCRIPTORS',
                                  332: 'ERROR_SCRUB_DATA_DISABLED', 333: 'ERROR_NOT_REDUNDANT_STORAGE',
                                  334: 'ERROR_RESIDENT_FILE_NOT_SUPPORTED', 335: 'ERROR_COMPRESSED_FILE_NOT_SUPPORTED',
                                  336: 'ERROR_DIRECTORY_NOT_SUPPORTED', 337: 'ERROR_NOT_READ_FROM_COPY',
                                  350: 'ERROR_FAIL_NOACTION_REBOOT', 351: 'ERROR_FAIL_SHUTDOWN',
                                  352: 'ERROR_FAIL_RESTART',
                                  353: 'ERROR_MAX_SESSIONS_REACHED', 400: 'ERROR_THREAD_MODE_ALREADY_BACKGROUND',
                                  401: 'ERROR_THREAD_MODE_NOT_BACKGROUND', 402: 'ERROR_PROCESS_MODE_ALREADY_BACKGROUND',
                                  403: 'ERROR_PROCESS_MODE_NOT_BACKGROUND', 487: 'ERROR_INVALID_ADDRESS'}
        global lastErrorCode

        lastErrorCode = pVals[0]

        pVals[0] = getLookUpVal(pVals[0], ErrorCodeReverseLookUp)

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retValStr = 'None'
        retVal = 0
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("SetLastErrorEx", hex(callAddr), (retValStr), 'void', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetLastError(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 0)
        pTypes = []
        pNames = []
        ErrorCodeReverseLookUp = {0: 'ERROR_SUCCESS', 1: 'ERROR_INVALID_FUNCTION', 2: 'ERROR_FILE_NOT_FOUND',
                                  3: 'ERROR_PATH_NOT_FOUND', 4: 'ERROR_TOO_MANY_OPEN_FILES', 5: 'ERROR_ACCESS_DENIED',
                                  6: 'ERROR_INVALID_HANDLE', 7: 'ERROR_ARENA_TRASHED', 8: 'ERROR_NOT_ENOUGH_MEMORY',
                                  9: 'ERROR_INVALID_BLOCK', 10: 'ERROR_BAD_ENVIRONMENT', 11: 'ERROR_BAD_FORMAT',
                                  12: 'ERROR_INVALID_ACCESS', 13: 'ERROR_INVALID_DATA', 14: 'ERROR_OUTOFMEMORY',
                                  15: 'ERROR_INVALID_DRIVE', 16: 'ERROR_CURRENT_DIRECTORY', 17: 'ERROR_NOT_SAME_DEVICE',
                                  18: 'ERROR_NO_MORE_FILES', 19: 'ERROR_WRITE_PROTECT', 20: 'ERROR_BAD_UNIT',
                                  21: 'ERROR_NOT_READY', 22: 'ERROR_BAD_COMMAND', 23: 'ERROR_CRC',
                                  24: 'ERROR_BAD_LENGTH',
                                  25: 'ERROR_SEEK', 26: 'ERROR_NOT_DOS_DISK', 27: 'ERROR_SECTOR_NOT_FOUND',
                                  28: 'ERROR_OUT_OF_PAPER', 29: 'ERROR_WRITE_FAULT', 30: 'ERROR_READ_FAULT',
                                  31: 'ERROR_GEN_FAILURE', 32: 'ERROR_SHARING_VIOLATION', 33: 'ERROR_LOCK_VIOLATION',
                                  34: 'ERROR_WRONG_DISK', 36: 'ERROR_SHARING_BUFFER_EXCEEDED', 38: 'ERROR_HANDLE_EOF',
                                  39: 'ERROR_HANDLE_DISK_FULL', 50: 'ERROR_NOT_SUPPORTED', 51: 'ERROR_REM_NOT_LIST',
                                  52: 'ERROR_DUP_NAME', 53: 'ERROR_BAD_NETPATH', 54: 'ERROR_NETWORK_BUSY',
                                  55: 'ERROR_DEV_NOT_EXIST', 56: 'ERROR_TOO_MANY_CMDS', 57: 'ERROR_ADAP_HDW_ERR',
                                  58: 'ERROR_BAD_NET_RESP', 59: 'ERROR_UNEXP_NET_ERR', 60: 'ERROR_BAD_REM_ADAP',
                                  61: 'ERROR_PRINTQ_FULL', 62: 'ERROR_NO_SPOOL_SPACE', 63: 'ERROR_PRINT_CANCELLED',
                                  64: 'ERROR_NETNAME_DELETED', 65: 'ERROR_NETWORK_ACCESS_DENIED',
                                  66: 'ERROR_BAD_DEV_TYPE',
                                  67: 'ERROR_BAD_NET_NAME', 68: 'ERROR_TOO_MANY_NAMES', 69: 'ERROR_TOO_MANY_SESS',
                                  70: 'ERROR_SHARING_PAUSED', 71: 'ERROR_REQ_NOT_ACCEP', 72: 'ERROR_REDIR_PAUSED',
                                  80: 'ERROR_FILE_EXISTS', 82: 'ERROR_CANNOT_MAKE', 83: 'ERROR_FAIL_I24',
                                  84: 'ERROR_OUT_OF_STRUCTURES', 85: 'ERROR_ALREADY_ASSIGNED',
                                  86: 'ERROR_INVALID_PASSWORD',
                                  87: 'ERROR_INVALID_PARAMETER', 88: 'ERROR_NET_WRITE_FAULT', 89: 'ERROR_NO_PROC_SLOTS',
                                  100: 'ERROR_TOO_MANY_SEMAPHORES', 101: 'ERROR_EXCL_SEM_ALREADY_OWNED',
                                  102: 'ERROR_SEM_IS_SET', 103: 'ERROR_TOO_MANY_SEM_REQUESTS',
                                  104: 'ERROR_INVALID_AT_INTERRUPT_TIME', 105: 'ERROR_SEM_OWNER_DIED',
                                  106: 'ERROR_SEM_USER_LIMIT', 107: 'ERROR_DISK_CHANGE', 108: 'ERROR_DRIVE_LOCKED',
                                  109: 'ERROR_BROKEN_PIPE', 110: 'ERROR_OPEN_FAILED', 111: 'ERROR_BUFFER_OVERFLOW',
                                  112: 'ERROR_DISK_FULL', 113: 'ERROR_NO_MORE_SEARCH_HANDLES',
                                  114: 'ERROR_INVALID_TARGET_HANDLE', 117: 'ERROR_INVALID_CATEGORY',
                                  118: 'ERROR_INVALID_VERIFY_SWITCH', 119: 'ERROR_BAD_DRIVER_LEVEL',
                                  120: 'ERROR_CALL_NOT_IMPLEMENTED', 121: 'ERROR_SEM_TIMEOUT',
                                  122: 'ERROR_INSUFFICIENT_BUFFER', 123: 'ERROR_INVALID_NAME',
                                  124: 'ERROR_INVALID_LEVEL',
                                  125: 'ERROR_NO_VOLUME_LABEL', 126: 'ERROR_MOD_NOT_FOUND', 127: 'ERROR_PROC_NOT_FOUND',
                                  128: 'ERROR_WAIT_NO_CHILDREN', 129: 'ERROR_CHILD_NOT_COMPLETE',
                                  130: 'ERROR_DIRECT_ACCESS_HANDLE', 131: 'ERROR_NEGATIVE_SEEK',
                                  132: 'ERROR_SEEK_ON_DEVICE', 133: 'ERROR_IS_JOIN_TARGET', 134: 'ERROR_IS_JOINED',
                                  135: 'ERROR_IS_SUBSTED', 136: 'ERROR_NOT_JOINED', 137: 'ERROR_NOT_SUBSTED',
                                  138: 'ERROR_JOIN_TO_JOIN', 139: 'ERROR_SUBST_TO_SUBST', 140: 'ERROR_JOIN_TO_SUBST',
                                  141: 'ERROR_SUBST_TO_JOIN', 142: 'ERROR_BUSY_DRIVE', 143: 'ERROR_SAME_DRIVE',
                                  144: 'ERROR_DIR_NOT_ROOT', 145: 'ERROR_DIR_NOT_EMPTY', 146: 'ERROR_IS_SUBST_PATH',
                                  147: 'ERROR_IS_JOIN_PATH', 148: 'ERROR_PATH_BUSY', 149: 'ERROR_IS_SUBST_TARGET',
                                  150: 'ERROR_SYSTEM_TRACE', 151: 'ERROR_INVALID_EVENT_COUNT',
                                  152: 'ERROR_TOO_MANY_MUXWAITERS', 153: 'ERROR_INVALID_LIST_FORMAT',
                                  154: 'ERROR_LABEL_TOO_LONG', 155: 'ERROR_TOO_MANY_TCBS', 156: 'ERROR_SIGNAL_REFUSED',
                                  157: 'ERROR_DISCARDED', 158: 'ERROR_NOT_LOCKED', 159: 'ERROR_BAD_THREADID_ADDR',
                                  160: 'ERROR_BAD_ARGUMENTS', 161: 'ERROR_BAD_PATHNAME', 162: 'ERROR_SIGNAL_PENDING',
                                  164: 'ERROR_MAX_THRDS_REACHED', 167: 'ERROR_LOCK_FAILED', 170: 'ERROR_BUSY',
                                  171: 'ERROR_DEVICE_SUPPORT_IN_PROGRESS', 173: 'ERROR_CANCEL_VIOLATION',
                                  174: 'ERROR_ATOMIC_LOCKS_NOT_SUPPORTED', 180: 'ERROR_INVALID_SEGMENT_NUMBER',
                                  182: 'ERROR_INVALID_ORDINAL', 183: 'ERROR_ALREADY_EXISTS',
                                  186: 'ERROR_INVALID_FLAG_NUMBER', 187: 'ERROR_SEM_NOT_FOUND',
                                  188: 'ERROR_INVALID_STARTING_CODESEG', 189: 'ERROR_INVALID_STACKSEG',
                                  190: 'ERROR_INVALID_MODULETYPE', 191: 'ERROR_INVALID_EXE_SIGNATURE',
                                  192: 'ERROR_EXE_MARKED_INVALID', 193: 'ERROR_BAD_EXE_FORMAT',
                                  194: 'ERROR_ITERATED_DATA_EXCEEDS_64k', 195: 'ERROR_INVALID_MINALLOCSIZE',
                                  196: 'ERROR_DYNLINK_FROM_INVALID_RING', 197: 'ERROR_IOPL_NOT_ENABLED',
                                  198: 'ERROR_INVALID_SEGDPL', 199: 'ERROR_AUTODATASEG_EXCEEDS_64k',
                                  200: 'ERROR_RING2SEG_MUST_BE_MOVABLE', 201: 'ERROR_RELOC_CHAIN_XEEDS_SEGLIM',
                                  202: 'ERROR_INFLOOP_IN_RELOC_CHAIN', 203: 'ERROR_ENVVAR_NOT_FOUND',
                                  205: 'ERROR_NO_SIGNAL_SENT', 206: 'ERROR_FILENAME_EXCED_RANGE',
                                  207: 'ERROR_RING2_STACK_IN_USE', 208: 'ERROR_META_EXPANSION_TOO_LONG',
                                  209: 'ERROR_INVALID_SIGNAL_NUMBER', 210: 'ERROR_THREAD_1_INACTIVE',
                                  212: 'ERROR_LOCKED',
                                  214: 'ERROR_TOO_MANY_MODULES', 215: 'ERROR_NESTING_NOT_ALLOWED',
                                  216: 'ERROR_EXE_MACHINE_TYPE_MISMATCH', 217: 'ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY',
                                  218: 'ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY', 220: 'ERROR_FILE_CHECKED_OUT',
                                  221: 'ERROR_CHECKOUT_REQUIRED', 222: 'ERROR_BAD_FILE_TYPE',
                                  223: 'ERROR_FILE_TOO_LARGE',
                                  224: 'ERROR_FORMS_AUTH_REQUIRED', 225: 'ERROR_VIRUS_INFECTED',
                                  226: 'ERROR_VIRUS_DELETED',
                                  229: 'ERROR_PIPE_LOCAL', 230: 'ERROR_BAD_PIPE', 231: 'ERROR_PIPE_BUSY',
                                  232: 'ERROR_NO_DATA', 233: 'ERROR_PIPE_NOT_CONNECTED', 234: 'ERROR_MORE_DATA',
                                  240: 'ERROR_VC_DISCONNECTED', 254: 'ERROR_INVALID_EA_NAME',
                                  255: 'ERROR_EA_LIST_INCONSISTENT', 258: 'WAIT_TIMEOUT', 259: 'ERROR_NO_MORE_ITEMS',
                                  266: 'ERROR_CANNOT_COPY', 267: 'ERROR_DIRECTORY', 275: 'ERROR_EAS_DIDNT_FIT',
                                  276: 'ERROR_EA_FILE_CORRUPT', 277: 'ERROR_EA_TABLE_FULL',
                                  278: 'ERROR_INVALID_EA_HANDLE',
                                  282: 'ERROR_EAS_NOT_SUPPORTED', 288: 'ERROR_NOT_OWNER', 298: 'ERROR_TOO_MANY_POSTS',
                                  299: 'ERROR_PARTIAL_COPY', 300: 'ERROR_OPLOCK_NOT_GRANTED',
                                  301: 'ERROR_INVALID_OPLOCK_PROTOCOL', 302: 'ERROR_DISK_TOO_FRAGMENTED',
                                  303: 'ERROR_DELETE_PENDING',
                                  304: 'ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING',
                                  305: 'ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME',
                                  306: 'ERROR_SECURITY_STREAM_IS_INCONSISTENT', 307: 'ERROR_INVALID_LOCK_RANGE',
                                  308: 'ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT',
                                  309: 'ERROR_NOTIFICATION_GUID_ALREADY_DEFINED',
                                  310: 'ERROR_INVALID_EXCEPTION_HANDLER', 311: 'ERROR_DUPLICATE_PRIVILEGES',
                                  312: 'ERROR_NO_RANGES_PROCESSED', 313: 'ERROR_NOT_ALLOWED_ON_SYSTEM_FILE',
                                  314: 'ERROR_DISK_RESOURCES_EXHAUSTED', 315: 'ERROR_INVALID_TOKEN',
                                  316: 'ERROR_DEVICE_FEATURE_NOT_SUPPORTED', 317: 'ERROR_MR_MID_NOT_FOUND',
                                  318: 'ERROR_SCOPE_NOT_FOUND', 319: 'ERROR_UNDEFINED_SCOPE', 320: 'ERROR_INVALID_CAP',
                                  321: 'ERROR_DEVICE_UNREACHABLE', 322: 'ERROR_DEVICE_NO_RESOURCES',
                                  323: 'ERROR_DATA_CHECKSUM_ERROR', 324: 'ERROR_INTERMIXED_KERNEL_EA_OPERATION',
                                  326: 'ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED', 327: 'ERROR_OFFSET_ALIGNMENT_VIOLATION',
                                  328: 'ERROR_INVALID_FIELD_IN_PARAMETER_LIST', 329: 'ERROR_OPERATION_IN_PROGRESS',
                                  330: 'ERROR_BAD_DEVICE_PATH', 331: 'ERROR_TOO_MANY_DESCRIPTORS',
                                  332: 'ERROR_SCRUB_DATA_DISABLED', 333: 'ERROR_NOT_REDUNDANT_STORAGE',
                                  334: 'ERROR_RESIDENT_FILE_NOT_SUPPORTED', 335: 'ERROR_COMPRESSED_FILE_NOT_SUPPORTED',
                                  336: 'ERROR_DIRECTORY_NOT_SUPPORTED', 337: 'ERROR_NOT_READ_FROM_COPY',
                                  350: 'ERROR_FAIL_NOACTION_REBOOT', 351: 'ERROR_FAIL_SHUTDOWN',
                                  352: 'ERROR_FAIL_RESTART',
                                  353: 'ERROR_MAX_SESSIONS_REACHED', 400: 'ERROR_THREAD_MODE_ALREADY_BACKGROUND',
                                  401: 'ERROR_THREAD_MODE_NOT_BACKGROUND', 402: 'ERROR_PROCESS_MODE_ALREADY_BACKGROUND',
                                  403: 'ERROR_PROCESS_MODE_NOT_BACKGROUND', 487: 'ERROR_INVALID_ADDRESS'}
        global lastErrorCode

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        retVal = lastErrorCode
        retValStr = getLookUpVal(retVal, ErrorCodeReverseLookUp)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GetlastError", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    # handle in handle dict
    def GetFileType(self, uc, eip, esp, export_dict, callAddr, em):
        # 'GetFileType': (1, ['HANDLE'], ['hFile'], 'DWORD'
        # match the filetypes to the HandleType list
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes = ['HANDLE']
        pNames = ['hFile']

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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("GetFileType", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GlobalLock(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        # 'FlushFileBuffers': (1, ['HANDLE'], ['hFile'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1) # Needs Reworked A little
        pTypes = ['HGLOBAL']
        pNames = ['hMem']
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

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("GlobalLock", hex(callAddr), (retValStr), 'LPVOID ', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GlobalAlloc(self, uc, eip, esp, export_dict, callAddr, em):
        # ''GlobalAlloc': (2, ['UINT', 'SIZE_T'], ['uFlags', 'dwBytes'], 'HGLOBAL')
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['UINT', 'SIZE_T']
        pNames = ['uFlags', 'dwBytes']
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
        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = stackCleanup(uc, em, esp, len(pTypes))

        uc.reg_write(UC_X86_REG_EAX,
                     retVal)  ## The return value can be of 4 differnt things, what do i do in this situation?

        logged_calls = ("GlobalAlloc", hex(callAddr), (retValStr), 'HGLOBAL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes
    def CreateDirectoryA(self, uc, eip, esp, export_dict, callAddr, em):
        #'CreateDirectoryA': (2, ['LPCSTR', 'LPSECURITY_ATTRIBUTES'], ['lpPathName', 'lpSecurityAttributes'], 'thunk BOOL')
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes= ['LPCSTR', 'LPSECURITY_ATTRIBUTES']
        pNames= ['lpPathName', 'lpSecurityAttributes']

        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CreateDirectoryA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateDirectoryW(self, uc, eip, esp, export_dict, callAddr, em):
        #'CreateDirectoryA': (2, ['LPCSTR', 'LPSECURITY_ATTRIBUTES'], ['lpPathName', 'lpSecurityAttributes'], 'thunk BOOL')
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes= ['LPCWSTR', 'LPSECURITY_ATTRIBUTES']
        pNames= ['lpPathName', 'lpSecurityAttributes']

        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CreateDirectoryW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RemoveDirectoryW(self, uc, eip, esp, export_dict, callAddr, em):
         #'RemoveDirectoryW': (1, ['LPCWSTR'], ['lpPathName'], 'thunk BOOL')
        pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 1)
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes= ['LPCWSTR']
        pNames= ['lpPathName']

        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("RemoveDirectoryW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes
    def RemoveDirectoryA(self, uc, eip, esp, export_dict, callAddr, em):
        #RemoveDirectoryA': (1, ['LPCSTR'], ['lpPathName'], 'thunk BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes= ['LPCSTR']
        pNames= ['lpPathName']

        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("RemoveDirectoryA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ResumeThread(self, uc, eip, esp, export_dict, callAddr, em):
        #'ResumeThread': (1, ['HANDLE'], ['hThread'], 'DWORD')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes= ['HANDLE']
        pNames= ['hThread']


        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x1
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("ResumeThread", hex(callAddr), (retValStr), 'DWORD', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetThreadContext(self, uc, eip, esp, export_dict, callAddr, em):
        #'ResumeThread': (1, ['HANDLE'], ['hThread'], 'DWORD')
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes= ['HANDLE', 'LPCONTEXT']
        pNames=['hThread', 'lpContext']

        ### RETURN WEIRD

        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetThreadContext", hex(callAddr), (retValStr), 'Bool', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def AllocConsole(self, uc, eip, esp, export_dict, callAddr, em):
        #'AllocConsole': (0, [], [], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 0)
        pTypes= []
        pNames=[]


        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("AllocConsole", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def FreeLibrary(self, uc, eip, esp, export_dict, callAddr, em):
        ##'FreeLibrary': (1, ['HMODULE'], ['hLibModule'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes= ['HMODULE']
        pNames= ['hLibModule']

        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("FreeLibrary", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetEnvironmentVariableA(self, uc, eip, esp, export_dict, callAddr, em):
        #'SetEnvironmentVariableA': (2, ['LPCSTR', 'LPCSTR'], ['lpName', 'lpValue'], 'BOOL')
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes= ['LPCSTR', 'LPCSTR']
        pNames= ['lpName', 'lpValue']

        #create strings for everything except ones in our skip
        skip=[]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("SetEnvironmentVariableA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes
    
    def OpenProcess(self, uc, eip, esp, export_dict, callAddr, em):
        #'OpenProcess': (3, ['DWORD', 'BOOL', 'DWORD'], ['dwDesiredAccess', 'bInheritHandle', 'dwProcessId'], 'HANDLE')
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes= ['DWORD', 'BOOL', 'DWORD']
        pNames= ['dwDesiredAccess', 'bInheritHandle', 'dwProcessId']

        dwDesiredAccess_ReverseLookUp = {65536: 'DELETE', 131072: 'READ_CONTROL', 1048576: 'SYNCHRONIZE', 262144: 'WRITE_DAC', 983040: 'STANDARD_RIGHTS_REQUIRED', 128:'PROCESS_CREATE_PROCESS', 2: 'PROCESS_CREATE_THREAD', 64:'PROCESS_DUP_HANDLE', 1024: 'PROCESS_QUERY_INFORMATION', 4096:'PROCESS_QUERY_LIMITED_INFORMATION', 512: 'PROCESS_SET_INFORMATION', 256: 'PROCESS_SET_QUOTA', 2048: 'PROCESS_SUSPEND_RESUME', 1: 'PROCESS_TERMINATE', 8: 'PROCESS_VM_OPERATION', 16: 'PROCESS_VM_READ', 32: 'PROCESS_VM_WRITE'}

        pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        #create strings for everything except ones in our skip
        skip=[0]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = FakeProcess
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("OpenProcess", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes
    
    def CreateEventA(self, uc, eip, esp, export_dict, callAddr, em):
        #'CreateEvent': (4, ['LPSECURITY_ATTRIBUTES', 'BOOL', 'BOOL', 'LPCTSTR'], ['lpEventAttributes', 'bManualReset', 'bInitialState', 'lpName'], 'HANDLE')
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes= ['LPSECURITY_ATTRIBUTES', 'BOOL', 'BOOL', 'LPCTSTR']
        pNames= ['lpEventAttributes', 'bManualReset', 'bInitialState', 'lpName']

        
        #pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        #create strings for everything except ones in our skip
        skip=[0]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x9090909
        retValStr=hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("CreateEventA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetSystemTimeAsFileTime(self, uc, eip, esp, export_dict, callAddr, em):
        #GetSystemTimeAsFileTime': (1, ['LPFILETIME'], ['lpSystemTimeAsFileTime'], 'VOID')
        pVals = makeArgVals(uc, em, esp, 1)
        pTypes= ['LPFILETIME']
        pNames= ['lpSystemTimeAsFileTime']

        fileTime = struct_FILETIME()
        fileTime.writeToMemory(uc, pVals[0])
        #fileTime.writeToMemory(uc, address)​
        #pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        #create strings for everything except ones in our skip
        skip=[0]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0
        retValStr='NONE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetSystemTimeAsFileTime", hex(callAddr), (retValStr), 'VOID', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def GetFileTime(self, uc, eip, esp, export_dict, callAddr, em):
        #'GetFileTime': (4, ['HANDLE', 'LPFILETIME', 'LPFILETIME', 'LPFILETIME'], ['hFile', 'lpCreationTime', 'lpLastAccessTime', 'lpLastWriteTime'], 'thunk BOOL')
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes= ['HANDLE', 'LPFILETIME', 'LPFILETIME', 'LPFILETIME']
        pNames= ['hFile', 'lpCreationTime', 'lpLastAccessTime', 'lpLastWriteTime']


        if pVals[1] != 0x0:
            fileTime = struct_FILETIME()
            fileTime.writeToMemory(uc, pVals[1])
        else:
            pass
        if pVals[2] != 0x0:
            fileTime = struct_FILETIME()
            fileTime.writeToMemory(uc, pVals[2])
        else:
            pass
        if pVals[3] != 0x0:
            fileTime = struct_FILETIME()
            fileTime.writeToMemory(uc, pVals[3])
        else:
            pass
        #pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        #create strings for everything except ones in our skip
        skip=[0]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = 0x1
        retValStr='TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetFileTime", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)

    def recv(self, uc, eip, esp, export_dict, callAddr, em):
        #'recv': (4, ['SOCKET', 'char *', 'int', 'int'], ['s', 'buf', 'len', 'flags'], 'int')
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes= ['SOCKET', 'char *', 'int', 'int']
        pNames= ['s', 'buf', 'len', 'flags']

        
        #pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        #create strings for everything except ones in our skip
        skip=[0]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        #return is len of bytes sent.
        #print(pVals[2])
        retVal = int(pVals[2],16)
        retValStr= hex(retVal)
        #print(retValStr)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("recv", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def send(self, uc, eip, esp, export_dict, callAddr, em):
        #'send': (4, ['SOCKET', 'const char *', 'int', 'int'], ['s', 'buf', 'len', 'flags'], 'int')
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes= ['SOCKET', 'const char *', 'int', 'int']
        pNames= ['s', 'buf', 'len', 'flags']

        
        #pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        #create strings for everything except ones in our skip
        skip=[0]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        #return is len of bytes sent.
        #print(pVals[2])
        retVal = int(pVals[2],16)
        retValStr= hex(retVal)
        #print(retValStr)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("send", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def connect(self, uc: Uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes= ['SOCKET', 'const sockaddr *', 'int']
        pNames= ['s', 'name', 'namelen']

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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes= ['SOCKET', 'const sockaddr *', 'int']
        pNames= ['s', 'name', 'namelen']

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
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes= ['SOCKET', 'sockaddr *', 'int *']
        pNames= ['s', 'addr', 'addrlen']


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

    def GetSystemDirectoryA (self, uc, eip, esp, export_dict, callAddr, em):
        #'GetSystemDirectoryA': (2, ['LPSTR', 'UINT'], ['lpBuffer', 'uSize'], 'UINT')
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes= ['LPSTR', 'UINT']
        pNames= ['lpBuffer', 'uSize']

        systemDir = 'C:\Windows\System32'

        
        #pVals[0] = getLookUpVal(pVals[0], dwDesiredAccess_ReverseLookUp)
        #create strings for everything except ones in our skip
        skip=[0]   # we need to skip this value (index) later-let's put it in skip
        pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

        cleanBytes=len(pTypes)*4

        retVal = len(systemDir)
        retValStr= str(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)     

        logged_calls= ("GetSystemDirectoryA ", hex(callAddr), (retValStr), 'UINT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes





class CustomWinSysCalls():
    NTSTATUSReverseLookUp = {0: 'STATUS_SUCCESS', 1: 'STATUS_WAIT_1', 2: 'STATUS_WAIT_2', 3: 'STATUS_WAIT_3', 63: 'STATUS_WAIT_63', 128: 'STATUS_ABANDONED_WAIT_0', 191: 'STATUS_ABANDONED_WAIT_63', 192: 'STATUS_USER_APC', 257: 'STATUS_ALERTED', 258: 'STATUS_TIMEOUT', 259: 'STATUS_PENDING', 260: 'STATUS_REPARSE', 261: 'STATUS_MORE_ENTRIES', 262: 'STATUS_NOT_ALL_ASSIGNED', 263: 'STATUS_SOME_NOT_MAPPED', 264: 'STATUS_OPLOCK_BREAK_IN_PROGRESS', 265: 'STATUS_VOLUME_MOUNTED', 266: 'STATUS_RXACT_COMMITTED', 267: 'STATUS_NOTIFY_CLEANUP', 268: 'STATUS_NOTIFY_ENUM_DIR', 269: 'STATUS_NO_QUOTAS_FOR_ACCOUNT', 270: 'STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED', 272: 'STATUS_PAGE_FAULT_TRANSITION', 273: 'STATUS_PAGE_FAULT_DEMAND_ZERO', 274: 'STATUS_PAGE_FAULT_COPY_ON_WRITE', 275: 'STATUS_PAGE_FAULT_GUARD_PAGE', 276: 'STATUS_PAGE_FAULT_PAGING_FILE', 277: 'STATUS_CACHE_PAGE_LOCKED', 278: 'STATUS_CRASH_DUMP', 279: 'STATUS_BUFFER_ALL_ZEROS',280: 'STATUS_REPARSE_OBJECT', 281: 'STATUS_RESOURCE_REQUIREMENTS_CHANGED', 288: 'STATUS_TRANSLATION_COMPLETE', 289: 'STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY', 290: 'STATUS_NOTHING_TO_TERMINATE', 291: 'STATUS_PROCESS_NOT_IN_JOB', 292: 'STATUS_PROCESS_IN_JOB', 293: 'STATUS_VOLSNAP_HIBERNATE_READY', 294: 'STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY', 295: 'STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED', 296: 'STATUS_INTERRUPT_STILL_CONNECTED', 297: 'STATUS_PROCESS_CLONED', 298: 'STATUS_FILE_LOCKED_WITH_ONLY_READERS', 299: 'STATUS_FILE_LOCKED_WITH_WRITERS', 514: 'STATUS_RESOURCEMANAGER_READ_ONLY', 871: 'STATUS_WAIT_FOR_OPLOCK', 65537: 'DBG_EXCEPTION_HANDLED', 65538: 'DBG_CONTINUE', 1835009: 'STATUS_FLT_IO_COMPLETE', 3221226599: 'STATUS_FILE_NOT_AVAILABLE', 3221226624: 'STATUS_SHARE_UNAVAILABLE', 3221227297: 'STATUS_CALLBACK_RETURNED_THREAD_AFFINITY', 1073741824: 'STATUS_OBJECT_NAME_EXISTS', 1073741825: 'STATUS_THREAD_WAS_SUSPENDED', 1073741826: 'STATUS_WORKING_SET_LIMIT_RANGE', 1073741827: 'STATUS_IMAGE_NOT_AT_BASE', 1073741828: 'STATUS_RXACT_STATE_CREATED', 1073741829: 'STATUS_SEGMENT_NOTIFICATION', 1073741830: 'STATUS_LOCAL_USER_SESSION_KEY', 1073741831: 'STATUS_BAD_CURRENT_DIRECTORY', 1073741832: 'STATUS_SERIAL_MORE_WRITES', 1073741833: 'STATUS_REGISTRY_RECOVERED', 1073741834: 'STATUS_FT_READ_RECOVERY_FROM_BACKUP', 1073741835: 'STATUS_FT_WRITE_RECOVERY', 1073741836: 'STATUS_SERIAL_COUNTER_TIMEOUT', 1073741837: 'STATUS_NULL_LM_PASSWORD', 1073741838: 'STATUS_IMAGE_MACHINE_TYPE_MISMATCH', 1073741839: 'STATUS_RECEIVE_PARTIAL', 1073741840: 'STATUS_RECEIVE_EXPEDITED', 1073741841: 'STATUS_RECEIVE_PARTIAL_EXPEDITED', 1073741842: 'STATUS_EVENT_DONE', 1073741843: 'STATUS_EVENT_PENDING', 1073741844: 'STATUS_CHECKING_FILE_SYSTEM', 1073741845: 'STATUS_FATAL_APP_EXIT', 1073741846: 'STATUS_PREDEFINED_HANDLE', 1073741847: 'STATUS_WAS_UNLOCKED', 1073741848: 'STATUS_SERVICE_NOTIFICATION', 1073741849: 'STATUS_WAS_LOCKED', 1073741850: 'STATUS_LOG_HARD_ERROR', 1073741851: 'STATUS_ALREADY_WIN32',1073741852: 'STATUS_WX86_UNSIMULATE', 1073741853: 'STATUS_WX86_CONTINUE', 1073741854: 'STATUS_WX86_SINGLE_STEP', 1073741855: 'STATUS_WX86_BREAKPOINT', 1073741856: 'STATUS_WX86_EXCEPTION_CONTINUE', 1073741857: 'STATUS_WX86_EXCEPTION_LASTCHANCE', 1073741858: 'STATUS_WX86_EXCEPTION_CHAIN', 1073741859: 'STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE', 1073741860: 'STATUS_NO_YIELD_PERFORMED', 1073741861: 'STATUS_TIMER_RESUME_IGNORED', 1073741862: 'STATUS_ARBITRATION_UNHANDLED', 1073741863: 'STATUS_CARDBUS_NOT_SUPPORTED', 1073741864: 'STATUS_WX86_CREATEWX86TIB', 1073741865: 'STATUS_MP_PROCESSOR_MISMATCH', 1073741866: 'STATUS_HIBERNATED', 1073741867: 'STATUS_RESUME_HIBERNATION', 1073741868: 'STATUS_FIRMWARE_UPDATED', 1073741869: 'STATUS_DRIVERS_LEAKING_LOCKED_PAGES', 1073741870: 'STATUS_MESSAGE_RETRIEVED', 1073741871: 'STATUS_SYSTEM_POWERSTATE_TRANSITION', 1073741872: 'STATUS_ALPC_CHECK_COMPLETION_LIST', 1073741873: 'STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION', 1073741874: 'STATUS_ACCESS_AUDIT_BY_POLICY', 1073741875: 'STATUS_ABANDON_HIBERFILE', 1073741876: 'STATUS_BIZRULES_NOT_ENABLED', 1073742484: 'STATUS_WAKE_SYSTEM', 1073742704: 'STATUS_DS_SHUTTING_DOWN', 1073807361: 'DBG_REPLY_LATER', 1073807362: 'DBG_UNABLE_TO_PROVIDE_HANDLE', 1073807363: 'DBG_TERMINATE_THREAD', 1073807364: 'DBG_TERMINATE_PROCESS', 1073807365: 'DBG_CONTROL_C', 1073807366: 'DBG_PRINTEXCEPTION_C', 1073807367: 'DBG_RIPEXCEPTION', 1073807368: 'DBG_CONTROL_BREAK', 1073807369: 'DBG_COMMAND_EXCEPTION', 1073872982: 'RPC_NT_UUID_LOCAL_ONLY', 1073873071: 'RPC_NT_SEND_INCOMPLETE', 1074397188: 'STATUS_CTX_CDM_CONNECT', 1074397189: 'STATUS_CTX_CDM_DISCONNECT', 1075118093: 'STATUS_SXS_RELEASE_ACTIVATION_CONTEXT', 1075380276: 'STATUS_RECOVERY_NOT_NEEDED', 1075380277: 'STATUS_RM_ALREADY_STARTED', 1075445772: 'STATUS_LOG_NO_RESTART', 1075511532: 'STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST', 1075707914: 'STATUS_GRAPHICS_PARTIAL_DATA_POPULATED', 1075708183: 'STATUS_GRAPHICS_DRIVER_MISMATCH', 1075708679: 'STATUS_GRAPHICS_MODE_NOT_PINNED', 1075708702: 'STATUS_GRAPHICS_NO_PREFERRED_MODE', 1075708747: 'STATUS_GRAPHICS_DATASET_IS_EMPTY', 1075708748: 'STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET', 1075708753: 'STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED', 1075708975: 'STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS', 1075708983: 'STATUS_GRAPHICS_LEADLINK_START_DEFERRED', 1075708985: 'STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY', 1075708986: 'STATUS_GRAPHICS_START_DEFERRED', 1076035585:'STATUS_NDIS_INDICATION_REQUIRED', 2147483649: 'STATUS_GUARD_PAGE_VIOLATION', 2147483650: 'STATUS_DATATYPE_MISALIGNMENT', 2147483651: 'STATUS_BREAKPOINT', 2147483652: 'STATUS_SINGLE_STEP', 2147483653: 'STATUS_BUFFER_OVERFLOW', 2147483654: 'STATUS_NO_MORE_FILES', 2147483655: 'STATUS_WAKE_SYSTEM_DEBUGGER', 2147483658: 'STATUS_HANDLES_CLOSED', 2147483659: 'STATUS_NO_INHERITANCE', 2147483660: 'STATUS_GUID_SUBSTITUTION_MADE', 2147483661: 'STATUS_PARTIAL_COPY', 2147483662: 'STATUS_DEVICE_PAPER_EMPTY', 2147483663: 'STATUS_DEVICE_POWERED_OFF', 2147483664: 'STATUS_DEVICE_OFF_LINE', 2147483665: 'STATUS_DEVICE_BUSY', 2147483666: 'STATUS_NO_MORE_EAS', 2147483667: 'STATUS_INVALID_EA_NAME', 2147483668: 'STATUS_EA_LIST_INCONSISTENT', 2147483669: 'STATUS_INVALID_EA_FLAG', 2147483670: 'STATUS_VERIFY_REQUIRED', 2147483671: 'STATUS_EXTRANEOUS_INFORMATION', 2147483672: 'STATUS_RXACT_COMMIT_NECESSARY', 2147483674: 'STATUS_NO_MORE_ENTRIES', 2147483675: 'STATUS_FILEMARK_DETECTED', 2147483676: 'STATUS_MEDIA_CHANGED', 2147483677: 'STATUS_BUS_RESET', 2147483678: 'STATUS_END_OF_MEDIA', 2147483679: 'STATUS_BEGINNING_OF_MEDIA', 2147483680: 'STATUS_MEDIA_CHECK', 2147483681: 'STATUS_SETMARK_DETECTED', 2147483682: 'STATUS_NO_DATA_DETECTED', 2147483683: 'STATUS_REDIRECTOR_HAS_OPEN_HANDLES', 2147483684: 'STATUS_SERVER_HAS_OPEN_HANDLES', 2147483685: 'STATUS_ALREADY_DISCONNECTED', 2147483686: 'STATUS_LONGJUMP', 2147483687: 'STATUS_CLEANER_CARTRIDGE_INSTALLED', 2147483688: 'STATUS_PLUGPLAY_QUERY_VETOED', 2147483689: 'STATUS_UNWIND_CONSOLIDATE', 2147483690: 'STATUS_REGISTRY_HIVE_RECOVERED', 2147483691: 'STATUS_DLL_MIGHT_BE_INSECURE', 2147483692: 'STATUS_DLL_MIGHT_BE_INCOMPATIBLE', 2147483693: 'STATUS_STOPPED_ON_SYMLINK', 2147484296: 'STATUS_DEVICE_REQUIRES_CLEANING', 2147484297: 'STATUS_DEVICE_DOOR_OPEN', 2147485699: 'STATUS_DATA_LOST_REPAIR', 2147549185: 'DBG_EXCEPTION_NOT_HANDLED', 2148728833: 'STATUS_CLUSTER_NODE_ALREADY_UP', 2148728834: 'STATUS_CLUSTER_NODE_ALREADY_DOWN', 2148728835: 'STATUS_CLUSTER_NETWORK_ALREADY_ONLINE', 2148728836: 'STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE', 2148728837: 'STATUS_CLUSTER_NODE_ALREADY_MEMBER', 2149122057: 'STATUS_COULD_NOT_RESIZE_LOG', 2149122089: 'STATUS_NO_TXF_METADATA', 2149122097: 'STATUS_CANT_RECOVER_WITH_HANDLE_OPEN', 2149122113: 'STATUS_TXF_METADATA_ALREADY_PRESENT', 2149122114: 'STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET', 2149253355: 'STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED', 2149318657: 'STATUS_FLT_BUFFER_TOO_SMALL', 2149646337: 'STATUS_FVE_PARTIAL_METADATA', 2149646338: 'STATUS_FVE_TRANSIENT_STATE', 3221225473: 'STATUS_UNSUCCESSFUL', 3221225474: 'STATUS_NOT_IMPLEMENTED', 3221225475: 'STATUS_INVALID_INFO_CLASS', 3221225476: 'STATUS_INFO_LENGTH_MISMATCH', 3221225477: 'STATUS_ACCESS_VIOLATION', 3221225478: 'STATUS_IN_PAGE_ERROR', 3221225479: 'STATUS_PAGEFILE_QUOTA', 3221225480: 'STATUS_INVALID_HANDLE', 3221225481: 'STATUS_BAD_INITIAL_STACK', 3221225482: 'STATUS_BAD_INITIAL_PC', 3221225483: 'STATUS_INVALID_CID', 3221225484: 'STATUS_TIMER_NOT_CANCELED', 3221225485: 'STATUS_INVALID_PARAMETER', 3221225486: 'STATUS_NO_SUCH_DEVICE', 3221225487: 'STATUS_NO_SUCH_FILE', 3221225488: 'STATUS_INVALID_DEVICE_REQUEST', 3221225489: 'STATUS_END_OF_FILE', 3221225490: 'STATUS_WRONG_VOLUME', 3221225491: 'STATUS_NO_MEDIA_IN_DEVICE', 3221225492: 'STATUS_UNRECOGNIZED_MEDIA', 3221225493: 'STATUS_NONEXISTENT_SECTOR', 3221225494: 'STATUS_MORE_PROCESSING_REQUIRED', 3221225495: 'STATUS_NO_MEMORY', 3221225496: 'STATUS_CONFLICTING_ADDRESSES', 3221225497: 'STATUS_NOT_MAPPED_VIEW', 3221225498: 'STATUS_UNABLE_TO_FREE_VM', 3221225499: 'STATUS_UNABLE_TO_DELETE_SECTION', 3221225500: 'STATUS_INVALID_SYSTEM_SERVICE', 3221225501: 'STATUS_ILLEGAL_INSTRUCTION', 3221225502: 'STATUS_INVALID_LOCK_SEQUENCE', 3221225503: 'STATUS_INVALID_VIEW_SIZE', 3221225504: 'STATUS_INVALID_FILE_FOR_SECTION', 3221225505:'STATUS_ALREADY_COMMITTED', 3221225506: 'STATUS_ACCESS_DENIED', 3221225507: 'STATUS_BUFFER_TOO_SMALL', 3221225508: 'STATUS_OBJECT_TYPE_MISMATCH', 3221225509: 'STATUS_NONCONTINUABLE_EXCEPTION', 3221225510: 'STATUS_INVALID_DISPOSITION', 3221225511: 'STATUS_UNWIND', 3221225512: 'STATUS_BAD_STACK', 3221225513:'STATUS_INVALID_UNWIND_TARGET', 3221225514: 'STATUS_NOT_LOCKED', 3221225515: 'STATUS_PARITY_ERROR', 3221225516: 'STATUS_UNABLE_TO_DECOMMIT_VM', 3221225517: 'STATUS_NOT_COMMITTED', 3221225518: 'STATUS_INVALID_PORT_ATTRIBUTES', 3221225519: 'STATUS_PORT_MESSAGE_TOO_LONG', 3221225520: 'STATUS_INVALID_PARAMETER_MIX', 3221225521: 'STATUS_INVALID_QUOTA_LOWER', 3221225522: 'STATUS_DISK_CORRUPT_ERROR', 3221225523: 'STATUS_OBJECT_NAME_INVALID', 3221225524: 'STATUS_OBJECT_NAME_NOT_FOUND', 3221225525: 'STATUS_OBJECT_NAME_COLLISION', 3221225527: 'STATUS_PORT_DISCONNECTED', 3221225528: 'STATUS_DEVICE_ALREADY_ATTACHED', 3221225529: 'STATUS_OBJECT_PATH_INVALID', 3221225530: 'STATUS_OBJECT_PATH_NOT_FOUND', 3221225531: 'STATUS_OBJECT_PATH_SYNTAX_BAD', 3221225532: 'STATUS_DATA_OVERRUN', 3221225533: 'STATUS_DATA_LATE_ERROR', 3221225534: 'STATUS_DATA_ERROR', 3221225535: 'STATUS_CRC_ERROR', 3221225536: 'STATUS_SECTION_TOO_BIG', 3221225537: 'STATUS_PORT_CONNECTION_REFUSED', 3221225538: 'STATUS_INVALID_PORT_HANDLE', 3221225539: 'STATUS_SHARING_VIOLATION', 3221225540: 'STATUS_QUOTA_EXCEEDED', 3221225541: 'STATUS_INVALID_PAGE_PROTECTION', 3221225542: 'STATUS_MUTANT_NOT_OWNED', 3221225543: 'STATUS_SEMAPHORE_LIMIT_EXCEEDED', 3221225544: 'STATUS_PORT_ALREADY_SET', 3221225545: 'STATUS_SECTION_NOT_IMAGE', 3221225546: 'STATUS_SUSPEND_COUNT_EXCEEDED', 3221225547: 'STATUS_THREAD_IS_TERMINATING', 3221225548: 'STATUS_BAD_WORKING_SET_LIMIT', 3221225549: 'STATUS_INCOMPATIBLE_FILE_MAP', 3221225550: 'STATUS_SECTION_PROTECTION', 3221225551: 'STATUS_EAS_NOT_SUPPORTED', 3221225552: 'STATUS_EA_TOO_LARGE', 3221225553: 'STATUS_NONEXISTENT_EA_ENTRY', 3221225554: 'STATUS_NO_EAS_ON_FILE', 3221225555: 'STATUS_EA_CORRUPT_ERROR', 3221225556: 'STATUS_FILE_LOCK_CONFLICT', 3221225557: 'STATUS_LOCK_NOT_GRANTED', 3221225558: 'STATUS_DELETE_PENDING', 3221225559: 'STATUS_CTL_FILE_NOT_SUPPORTED', 3221225560: 'STATUS_UNKNOWN_REVISION', 3221225561: 'STATUS_REVISION_MISMATCH', 3221225562: 'STATUS_INVALID_OWNER', 3221225563: 'STATUS_INVALID_PRIMARY_GROUP', 3221225564: 'STATUS_NO_IMPERSONATION_TOKEN', 3221225565: 'STATUS_CANT_DISABLE_MANDATORY', 3221225566: 'STATUS_NO_LOGON_SERVERS', 3221225567: 'STATUS_NO_SUCH_LOGON_SESSION', 3221225568: 'STATUS_NO_SUCH_PRIVILEGE', 3221225569: 'STATUS_PRIVILEGE_NOT_HELD', 3221225570: 'STATUS_INVALID_ACCOUNT_NAME', 3221225571: 'STATUS_USER_EXISTS', 3221225572: 'STATUS_NO_SUCH_USER', 3221225573: 'STATUS_GROUP_EXISTS', 3221225574: 'STATUS_NO_SUCH_GROUP', 3221225575: 'STATUS_MEMBER_IN_GROUP', 3221225576: 'STATUS_MEMBER_NOT_IN_GROUP', 3221225577: 'STATUS_LAST_ADMIN', 3221225578: 'STATUS_WRONG_PASSWORD', 3221225579: 'STATUS_ILL_FORMED_PASSWORD', 3221225580: 'STATUS_PASSWORD_RESTRICTION', 3221225581: 'STATUS_LOGON_FAILURE', 3221225582: 'STATUS_ACCOUNT_RESTRICTION', 3221225583: 'STATUS_INVALID_LOGON_HOURS', 3221225584: 'STATUS_INVALID_WORKSTATION', 3221225585: 'STATUS_PASSWORD_EXPIRED', 3221225586: 'STATUS_ACCOUNT_DISABLED', 3221225587: 'STATUS_NONE_MAPPED', 3221225588: 'STATUS_TOO_MANY_LUIDS_REQUESTED', 3221225589: 'STATUS_LUIDS_EXHAUSTED', 3221225590: 'STATUS_INVALID_SUB_AUTHORITY', 3221225591: 'STATUS_INVALID_ACL', 3221225592: 'STATUS_INVALID_SID', 3221225593: 'STATUS_INVALID_SECURITY_DESCR', 3221225594: 'STATUS_PROCEDURE_NOT_FOUND', 3221225595: 'STATUS_INVALID_IMAGE_FORMAT', 3221225596: 'STATUS_NO_TOKEN', 3221225597: 'STATUS_BAD_INHERITANCE_ACL', 3221225598: 'STATUS_RANGE_NOT_LOCKED', 3221225599: 'STATUS_DISK_FULL', 3221225600: 'STATUS_SERVER_DISABLED', 3221225601: 'STATUS_SERVER_NOT_DISABLED', 3221225602: 'STATUS_TOO_MANY_GUIDS_REQUESTED', 3221225603: 'STATUS_GUIDS_EXHAUSTED', 3221225604: 'STATUS_INVALID_ID_AUTHORITY', 3221225605: 'STATUS_AGENTS_EXHAUSTED', 3221225606: 'STATUS_INVALID_VOLUME_LABEL', 3221225607: 'STATUS_SECTION_NOT_EXTENDED', 3221225608: 'STATUS_NOT_MAPPED_DATA', 3221225609: 'STATUS_RESOURCE_DATA_NOT_FOUND', 3221225610: 'STATUS_RESOURCE_TYPE_NOT_FOUND', 3221225611: 'STATUS_RESOURCE_NAME_NOT_FOUND', 3221225612: 'STATUS_ARRAY_BOUNDS_EXCEEDED', 3221225613: 'STATUS_FLOAT_DENORMAL_OPERAND', 3221225614: 'STATUS_FLOAT_DIVIDE_BY_ZERO', 3221225615: 'STATUS_FLOAT_INEXACT_RESULT', 3221225616: 'STATUS_FLOAT_INVALID_OPERATION', 3221225617: 'STATUS_FLOAT_OVERFLOW', 3221225618: 'STATUS_FLOAT_STACK_CHECK', 3221225619: 'STATUS_FLOAT_UNDERFLOW', 3221225620: 'STATUS_INTEGER_DIVIDE_BY_ZERO', 3221225621: 'STATUS_INTEGER_OVERFLOW', 3221225622: 'STATUS_PRIVILEGED_INSTRUCTION', 3221225623: 'STATUS_TOO_MANY_PAGING_FILES', 3221225624: 'STATUS_FILE_INVALID', 3221225625: 'STATUS_ALLOTTED_SPACE_EXCEEDED', 3221225626: 'STATUS_INSUFFICIENT_RESOURCES', 3221225627: 'STATUS_DFS_EXIT_PATH_FOUND', 3221225628: 'STATUS_DEVICE_DATA_ERROR', 3221225629: 'STATUS_DEVICE_NOT_CONNECTED', 3221225631: 'STATUS_FREE_VM_NOT_AT_BASE', 3221225632: 'STATUS_MEMORY_NOT_ALLOCATED', 3221225633: 'STATUS_WORKING_SET_QUOTA', 3221225634: 'STATUS_MEDIA_WRITE_PROTECTED', 3221225635: 'STATUS_DEVICE_NOT_READY', 3221225636: 'STATUS_INVALID_GROUP_ATTRIBUTES', 3221225637: 'STATUS_BAD_IMPERSONATION_LEVEL', 3221225638: 'STATUS_CANT_OPEN_ANONYMOUS', 3221225639: 'STATUS_BAD_VALIDATION_CLASS', 3221225640: 'STATUS_BAD_TOKEN_TYPE', 3221225641: 'STATUS_BAD_MASTER_BOOT_RECORD', 3221225642: 'STATUS_INSTRUCTION_MISALIGNMENT', 3221225643: 'STATUS_INSTANCE_NOT_AVAILABLE', 3221225644: 'STATUS_PIPE_NOT_AVAILABLE', 3221225645: 'STATUS_INVALID_PIPE_STATE', 3221225646: 'STATUS_PIPE_BUSY', 3221225647: 'STATUS_ILLEGAL_FUNCTION', 3221225648: 'STATUS_PIPE_DISCONNECTED', 3221225649: 'STATUS_PIPE_CLOSING', 3221225650: 'STATUS_PIPE_CONNECTED', 3221225651: 'STATUS_PIPE_LISTENING', 3221225652: 'STATUS_INVALID_READ_MODE', 3221225653: 'STATUS_IO_TIMEOUT', 3221225654: 'STATUS_FILE_FORCED_CLOSED', 3221225655: 'STATUS_PROFILING_NOT_STARTED', 3221225656: 'STATUS_PROFILING_NOT_STOPPED', 3221225657: 'STATUS_COULD_NOT_INTERPRET', 3221225658: 'STATUS_FILE_IS_A_DIRECTORY', 3221225659: 'STATUS_NOT_SUPPORTED', 3221225660: 'STATUS_REMOTE_NOT_LISTENING', 3221225661: 'STATUS_DUPLICATE_NAME', 3221225662: 'STATUS_BAD_NETWORK_PATH', 3221225663: 'STATUS_NETWORK_BUSY', 3221225664: 'STATUS_DEVICE_DOES_NOT_EXIST', 3221225665: 'STATUS_TOO_MANY_COMMANDS', 3221225666: 'STATUS_ADAPTER_HARDWARE_ERROR', 3221225667: 'STATUS_INVALID_NETWORK_RESPONSE', 3221225668: 'STATUS_UNEXPECTED_NETWORK_ERROR', 3221225669: 'STATUS_BAD_REMOTE_ADAPTER', 3221225670: 'STATUS_PRINT_QUEUE_FULL', 3221225671: 'STATUS_NO_SPOOL_SPACE', 3221225672: 'STATUS_PRINT_CANCELLED', 3221225673: 'STATUS_NETWORK_NAME_DELETED', 3221225674: 'STATUS_NETWORK_ACCESS_DENIED', 3221225675: 'STATUS_BAD_DEVICE_TYPE', 3221225676: 'STATUS_BAD_NETWORK_NAME', 3221225677: 'STATUS_TOO_MANY_NAMES', 3221225678: 'STATUS_TOO_MANY_SESSIONS', 3221225679: 'STATUS_SHARING_PAUSED', 3221225680: 'STATUS_REQUEST_NOT_ACCEPTED', 3221225681: 'STATUS_REDIRECTOR_PAUSED', 3221225682: 'STATUS_NET_WRITE_FAULT', 3221225683: 'STATUS_PROFILING_AT_LIMIT', 3221225684: 'STATUS_NOT_SAME_DEVICE', 3221225685: 'STATUS_FILE_RENAMED', 3221225686: 'STATUS_VIRTUAL_CIRCUIT_CLOSED', 3221225687: 'STATUS_NO_SECURITY_ON_OBJECT', 3221225688: 'STATUS_CANT_WAIT', 3221225689: 'STATUS_PIPE_EMPTY', 3221225690: 'STATUS_CANT_ACCESS_DOMAIN_INFO', 3221225691: 'STATUS_CANT_TERMINATE_SELF', 3221225692: 'STATUS_INVALID_SERVER_STATE', 3221225693: 'STATUS_INVALID_DOMAIN_STATE', 3221225694: 'STATUS_INVALID_DOMAIN_ROLE', 3221225695: 'STATUS_NO_SUCH_DOMAIN', 3221225696: 'STATUS_DOMAIN_EXISTS', 3221225697: 'STATUS_DOMAIN_LIMIT_EXCEEDED', 3221225698: 'STATUS_OPLOCK_NOT_GRANTED', 3221225699: 'STATUS_INVALID_OPLOCK_PROTOCOL', 3221225700: 'STATUS_INTERNAL_DB_CORRUPTION', 3221225701: 'STATUS_INTERNAL_ERROR', 3221225702: 'STATUS_GENERIC_NOT_MAPPED', 3221225703: 'STATUS_BAD_DESCRIPTOR_FORMAT', 3221225704: 'STATUS_INVALID_USER_BUFFER', 3221225705: 'STATUS_UNEXPECTED_IO_ERROR', 3221225706: 'STATUS_UNEXPECTED_MM_CREATE_ERR', 3221225707: 'STATUS_UNEXPECTED_MM_MAP_ERROR', 3221225708: 'STATUS_UNEXPECTED_MM_EXTEND_ERR', 3221225709: 'STATUS_NOT_LOGON_PROCESS', 3221225710: 'STATUS_LOGON_SESSION_EXISTS', 3221225711: 'STATUS_INVALID_PARAMETER_1', 3221225712: 'STATUS_INVALID_PARAMETER_2', 3221225713: 'STATUS_INVALID_PARAMETER_3', 3221225714: 'STATUS_INVALID_PARAMETER_4', 3221225715: 'STATUS_INVALID_PARAMETER_5', 3221225716: 'STATUS_INVALID_PARAMETER_6', 3221225717: 'STATUS_INVALID_PARAMETER_7', 3221225718: 'STATUS_INVALID_PARAMETER_8', 3221225719: 'STATUS_INVALID_PARAMETER_9', 3221225720: 'STATUS_INVALID_PARAMETER_10', 3221225721: 'STATUS_INVALID_PARAMETER_11', 3221225722: 'STATUS_INVALID_PARAMETER_12', 3221225723: 'STATUS_REDIRECTOR_NOT_STARTED', 3221225724: 'STATUS_REDIRECTOR_STARTED', 3221225725: 'STATUS_STACK_OVERFLOW', 3221225726: 'STATUS_NO_SUCH_PACKAGE', 3221225727: 'STATUS_BAD_FUNCTION_TABLE', 3221225728: 'STATUS_VARIABLE_NOT_FOUND', 3221225729: 'STATUS_DIRECTORY_NOT_EMPTY', 3221225730: 'STATUS_FILE_CORRUPT_ERROR', 3221225731: 'STATUS_NOT_A_DIRECTORY', 3221225732: 'STATUS_BAD_LOGON_SESSION_STATE', 3221225733: 'STATUS_LOGON_SESSION_COLLISION', 3221225734: 'STATUS_NAME_TOO_LONG', 3221225735: 'STATUS_FILES_OPEN', 3221225736: 'STATUS_CONNECTION_IN_USE', 3221225737: 'STATUS_MESSAGE_NOT_FOUND', 3221225738: 'STATUS_PROCESS_IS_TERMINATING', 3221225739: 'STATUS_INVALID_LOGON_TYPE', 3221225740: 'STATUS_NO_GUID_TRANSLATION', 3221225741: 'STATUS_CANNOT_IMPERSONATE', 3221225742: 'STATUS_IMAGE_ALREADY_LOADED', 3221225751: 'STATUS_NO_LDT', 3221225752: 'STATUS_INVALID_LDT_SIZE', 3221225753: 'STATUS_INVALID_LDT_OFFSET', 3221225754: 'STATUS_INVALID_LDT_DESCRIPTOR', 3221225755: 'STATUS_INVALID_IMAGE_NE_FORMAT', 3221225756: 'STATUS_RXACT_INVALID_STATE', 3221225757: 'STATUS_RXACT_COMMIT_FAILURE', 3221225758: 'STATUS_MAPPED_FILE_SIZE_ZERO', 3221225759: 'STATUS_TOO_MANY_OPENED_FILES', 3221225760: 'STATUS_CANCELLED', 3221225761: 'STATUS_CANNOT_DELETE', 3221225762: 'STATUS_INVALID_COMPUTER_NAME', 3221225763: 'STATUS_FILE_DELETED', 3221225764: 'STATUS_SPECIAL_ACCOUNT', 3221225765: 'STATUS_SPECIAL_GROUP', 3221225766: 'STATUS_SPECIAL_USER', 3221225767: 'STATUS_MEMBERS_PRIMARY_GROUP', 3221225768: 'STATUS_FILE_CLOSED', 3221225769: 'STATUS_TOO_MANY_THREADS', 3221225770: 'STATUS_THREAD_NOT_IN_PROCESS', 3221225771: 'STATUS_TOKEN_ALREADY_IN_USE', 3221225772: 'STATUS_PAGEFILE_QUOTA_EXCEEDED', 3221225773: 'STATUS_COMMITMENT_LIMIT', 3221225774: 'STATUS_INVALID_IMAGE_LE_FORMAT', 3221225775: 'STATUS_INVALID_IMAGE_NOT_MZ', 3221225776: 'STATUS_INVALID_IMAGE_PROTECT', 3221225777: 'STATUS_INVALID_IMAGE_WIN_16', 3221225778: 'STATUS_LOGON_SERVER_CONFLICT', 3221225779: 'STATUS_TIME_DIFFERENCE_AT_DC', 3221225780: 'STATUS_SYNCHRONIZATION_REQUIRED', 3221225781: 'STATUS_DLL_NOT_FOUND', 3221225782: 'STATUS_OPEN_FAILED', 3221225783: 'STATUS_IO_PRIVILEGE_FAILED', 3221225784: 'STATUS_ORDINAL_NOT_FOUND', 3221225785: 'STATUS_ENTRYPOINT_NOT_FOUND', 3221225786: 'STATUS_CONTROL_C_EXIT', 3221225787: 'STATUS_LOCAL_DISCONNECT', 3221225788: 'STATUS_REMOTE_DISCONNECT', 3221225789: 'STATUS_REMOTE_RESOURCES', 3221225790: 'STATUS_LINK_FAILED', 3221225791: 'STATUS_LINK_TIMEOUT', 3221225792: 'STATUS_INVALID_CONNECTION', 3221225793: 'STATUS_INVALID_ADDRESS', 3221225794: 'STATUS_DLL_INIT_FAILED', 3221225795: 'STATUS_MISSING_SYSTEMFILE', 3221225796: 'STATUS_UNHANDLED_EXCEPTION', 3221225797: 'STATUS_APP_INIT_FAILURE', 3221225798: 'STATUS_PAGEFILE_CREATE_FAILED', 3221225799: 'STATUS_NO_PAGEFILE', 3221225800: 'STATUS_INVALID_LEVEL', 3221225801: 'STATUS_WRONG_PASSWORD_CORE', 3221225802: 'STATUS_ILLEGAL_FLOAT_CONTEXT', 3221225803: 'STATUS_PIPE_BROKEN', 3221225804: 'STATUS_REGISTRY_CORRUPT', 3221225805: 'STATUS_REGISTRY_IO_FAILED', 3221225806: 'STATUS_NO_EVENT_PAIR', 3221225807: 'STATUS_UNRECOGNIZED_VOLUME', 3221225808: 'STATUS_SERIAL_NO_DEVICE_INITED', 3221225809: 'STATUS_NO_SUCH_ALIAS', 3221225810: 'STATUS_MEMBER_NOT_IN_ALIAS', 3221225811: 'STATUS_MEMBER_IN_ALIAS', 3221225812: 'STATUS_ALIAS_EXISTS', 3221225813: 'STATUS_LOGON_NOT_GRANTED', 3221225814: 'STATUS_TOO_MANY_SECRETS', 3221225815: 'STATUS_SECRET_TOO_LONG', 3221225816: 'STATUS_INTERNAL_DB_ERROR', 3221225817: 'STATUS_FULLSCREEN_MODE', 3221225818: 'STATUS_TOO_MANY_CONTEXT_IDS', 3221225819: 'STATUS_LOGON_TYPE_NOT_GRANTED', 3221225820: 'STATUS_NOT_REGISTRY_FILE', 3221225821: 'STATUS_NT_CROSS_ENCRYPTION_REQUIRED', 3221225822: 'STATUS_DOMAIN_CTRLR_CONFIG_ERROR', 3221225823: 'STATUS_FT_MISSING_MEMBER', 3221225824: 'STATUS_ILL_FORMED_SERVICE_ENTRY', 3221225825: 'STATUS_ILLEGAL_CHARACTER', 3221225826: 'STATUS_UNMAPPABLE_CHARACTER', 3221225827: 'STATUS_UNDEFINED_CHARACTER', 3221225828: 'STATUS_FLOPPY_VOLUME', 3221225829: 'STATUS_FLOPPY_ID_MARK_NOT_FOUND', 3221225830: 'STATUS_FLOPPY_WRONG_CYLINDER', 3221225831: 'STATUS_FLOPPY_UNKNOWN_ERROR', 3221225832: 'STATUS_FLOPPY_BAD_REGISTERS', 3221225833: 'STATUS_DISK_RECALIBRATE_FAILED', 3221225834: 'STATUS_DISK_OPERATION_FAILED', 3221225835: 'STATUS_DISK_RESET_FAILED', 3221225836:'STATUS_SHARED_IRQ_BUSY', 3221225837: 'STATUS_FT_ORPHANING', 3221225838: 'STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT', 3221225842: 'STATUS_PARTITION_FAILURE', 3221225843: 'STATUS_INVALID_BLOCK_LENGTH', 3221225844: 'STATUS_DEVICE_NOT_PARTITIONED', 3221225845: 'STATUS_UNABLE_TO_LOCK_MEDIA', 3221225846: 'STATUS_UNABLE_TO_UNLOAD_MEDIA', 3221225847: 'STATUS_EOM_OVERFLOW', 3221225848: 'STATUS_NO_MEDIA', 3221225850: 'STATUS_NO_SUCH_MEMBER', 3221225851: 'STATUS_INVALID_MEMBER', 3221225852: 'STATUS_KEY_DELETED', 3221225853: 'STATUS_NO_LOG_SPACE', 3221225854: 'STATUS_TOO_MANY_SIDS', 3221225855: 'STATUS_LM_CROSS_ENCRYPTION_REQUIRED', 3221225856: 'STATUS_KEY_HAS_CHILDREN', 3221225857: 'STATUS_CHILD_MUST_BE_VOLATILE', 3221225858: 'STATUS_DEVICE_CONFIGURATION_ERROR', 3221225859: 'STATUS_DRIVER_INTERNAL_ERROR', 3221225860: 'STATUS_INVALID_DEVICE_STATE', 3221225861: 'STATUS_IO_DEVICE_ERROR', 3221225862: 'STATUS_DEVICE_PROTOCOL_ERROR', 3221225863: 'STATUS_BACKUP_CONTROLLER', 3221225864: 'STATUS_LOG_FILE_FULL', 3221225865: 'STATUS_TOO_LATE', 3221225866: 'STATUS_NO_TRUST_LSA_SECRET', 3221225867: 'STATUS_NO_TRUST_SAM_ACCOUNT', 3221225868: 'STATUS_TRUSTED_DOMAIN_FAILURE', 3221225869: 'STATUS_TRUSTED_RELATIONSHIP_FAILURE', 3221225870: 'STATUS_EVENTLOG_FILE_CORRUPT', 3221225871: 'STATUS_EVENTLOG_CANT_START', 3221225872: 'STATUS_TRUST_FAILURE', 3221225873: 'STATUS_MUTANT_LIMIT_EXCEEDED', 3221225874: 'STATUS_NETLOGON_NOT_STARTED', 3221225875: 'STATUS_ACCOUNT_EXPIRED', 3221225876: 'STATUS_POSSIBLE_DEADLOCK', 3221225877: 'STATUS_NETWORK_CREDENTIAL_CONFLICT', 3221225878: 'STATUS_REMOTE_SESSION_LIMIT', 3221225879: 'STATUS_EVENTLOG_FILE_CHANGED', 3221225880: 'STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT', 3221225881: 'STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT', 3221225882: 'STATUS_NOLOGON_SERVER_TRUST_ACCOUNT', 3221225883: 'STATUS_DOMAIN_TRUST_INCONSISTENT', 3221225884: 'STATUS_FS_DRIVER_REQUIRED', 3221225885: 'STATUS_IMAGE_ALREADY_LOADED_AS_DLL', 3221225886: 'STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING', 3221225887: 'STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME', 3221225888: 'STATUS_SECURITY_STREAM_IS_INCONSISTENT', 3221225889: 'STATUS_INVALID_LOCK_RANGE', 3221225890: 'STATUS_INVALID_ACE_CONDITION', 3221225891: 'STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT', 3221225892: 'STATUS_NOTIFICATION_GUID_ALREADY_DEFINED', 3221225985: 'STATUS_NETWORK_OPEN_RESTRICTION', 3221225986: 'STATUS_NO_USER_SESSION_KEY', 3221225987: 'STATUS_USER_SESSION_DELETED', 3221225988:'STATUS_RESOURCE_LANG_NOT_FOUND', 3221225989: 'STATUS_INSUFF_SERVER_RESOURCES', 3221225990: 'STATUS_INVALID_BUFFER_SIZE', 3221225991: 'STATUS_INVALID_ADDRESS_COMPONENT', 3221225992: 'STATUS_INVALID_ADDRESS_WILDCARD', 3221225993: 'STATUS_TOO_MANY_ADDRESSES', 3221225994: 'STATUS_ADDRESS_ALREADY_EXISTS', 3221225995: 'STATUS_ADDRESS_CLOSED', 3221225996: 'STATUS_CONNECTION_DISCONNECTED', 3221225997: 'STATUS_CONNECTION_RESET', 3221225998: 'STATUS_TOO_MANY_NODES',3221225999: 'STATUS_TRANSACTION_ABORTED', 3221226000: 'STATUS_TRANSACTION_TIMED_OUT', 3221226001: 'STATUS_TRANSACTION_NO_RELEASE', 3221226002: 'STATUS_TRANSACTION_NO_MATCH', 3221226003: 'STATUS_TRANSACTION_RESPONDED', 3221226004: 'STATUS_TRANSACTION_INVALID_ID', 3221226005: 'STATUS_TRANSACTION_INVALID_TYPE', 3221226006: 'STATUS_NOT_SERVER_SESSION', 3221226007: 'STATUS_NOT_CLIENT_SESSION', 3221226008: 'STATUS_CANNOT_LOAD_REGISTRY_FILE', 3221226009: 'STATUS_DEBUG_ATTACH_FAILED', 3221226010: 'STATUS_SYSTEM_PROCESS_TERMINATED', 3221226011: 'STATUS_DATA_NOT_ACCEPTED', 3221226012: 'STATUS_NO_BROWSER_SERVERS_FOUND', 3221226013: 'STATUS_VDM_HARD_ERROR', 3221226014: 'STATUS_DRIVER_CANCEL_TIMEOUT', 3221226015: 'STATUS_REPLY_MESSAGE_MISMATCH', 3221226016: 'STATUS_MAPPED_ALIGNMENT', 3221226017: 'STATUS_IMAGE_CHECKSUM_MISMATCH', 3221226018: 'STATUS_LOST_WRITEBEHIND_DATA', 3221226019: 'STATUS_CLIENT_SERVER_PARAMETERS_INVALID', 3221226020: 'STATUS_PASSWORD_MUST_CHANGE', 3221226021: 'STATUS_NOT_FOUND', 3221226022: 'STATUS_NOT_TINY_STREAM', 3221226023: 'STATUS_RECOVERY_FAILURE', 3221226024: 'STATUS_STACK_OVERFLOW_READ', 3221226025: 'STATUS_FAIL_CHECK', 3221226026: 'STATUS_DUPLICATE_OBJECTID', 3221226027: 'STATUS_OBJECTID_EXISTS', 3221226028: 'STATUS_CONVERT_TO_LARGE', 3221226029: 'STATUS_RETRY', 3221226030: 'STATUS_FOUND_OUT_OF_SCOPE', 3221226031: 'STATUS_ALLOCATE_BUCKET', 3221226032: 'STATUS_PROPSET_NOT_FOUND', 3221226033: 'STATUS_MARSHALL_OVERFLOW', 3221226034: 'STATUS_INVALID_VARIANT', 3221226035: 'STATUS_DOMAIN_CONTROLLER_NOT_FOUND', 3221226036: 'STATUS_ACCOUNT_LOCKED_OUT', 3221226037: 'STATUS_HANDLE_NOT_CLOSABLE', 3221226038: 'STATUS_CONNECTION_REFUSED', 3221226039: 'STATUS_GRACEFUL_DISCONNECT', 3221226040: 'STATUS_ADDRESS_ALREADY_ASSOCIATED', 3221226041: 'STATUS_ADDRESS_NOT_ASSOCIATED', 3221226042: 'STATUS_CONNECTION_INVALID',3221226043: 'STATUS_CONNECTION_ACTIVE', 3221226044: 'STATUS_NETWORK_UNREACHABLE', 3221226045: 'STATUS_HOST_UNREACHABLE', 3221226046: 'STATUS_PROTOCOL_UNREACHABLE', 3221226047: 'STATUS_PORT_UNREACHABLE', 3221226048: 'STATUS_REQUEST_ABORTED', 3221226049: 'STATUS_CONNECTION_ABORTED', 3221226050: 'STATUS_BAD_COMPRESSION_BUFFER', 3221226051: 'STATUS_USER_MAPPED_FILE', 3221226052: 'STATUS_AUDIT_FAILED', 3221226053: 'STATUS_TIMER_RESOLUTION_NOT_SET', 3221226054: 'STATUS_CONNECTION_COUNT_LIMIT', 3221226055: 'STATUS_LOGIN_TIME_RESTRICTION', 3221226056: 'STATUS_LOGIN_WKSTA_RESTRICTION', 3221226057: 'STATUS_IMAGE_MP_UP_MISMATCH', 3221226064: 'STATUS_INSUFFICIENT_LOGON_INFO', 3221226065: 'STATUS_BAD_DLL_ENTRYPOINT', 3221226066: 'STATUS_BAD_SERVICE_ENTRYPOINT', 3221226067: 'STATUS_LPC_REPLY_LOST', 3221226068: 'STATUS_IP_ADDRESS_CONFLICT1', 3221226069: 'STATUS_IP_ADDRESS_CONFLICT2', 3221226070: 'STATUS_REGISTRY_QUOTA_LIMIT', 3221226071: 'STATUS_PATH_NOT_COVERED', 3221226072: 'STATUS_NO_CALLBACK_ACTIVE', 3221226073: 'STATUS_LICENSE_QUOTA_EXCEEDED', 3221226074: 'STATUS_PWD_TOO_SHORT', 3221226075: 'STATUS_PWD_TOO_RECENT', 3221226076: 'STATUS_PWD_HISTORY_CONFLICT', 3221226078: 'STATUS_PLUGPLAY_NO_DEVICE', 3221226079: 'STATUS_UNSUPPORTED_COMPRESSION', 3221226080: 'STATUS_INVALID_HW_PROFILE', 3221226081: 'STATUS_INVALID_PLUGPLAY_DEVICE_PATH', 3221226082: 'STATUS_DRIVER_ORDINAL_NOT_FOUND', 3221226083: 'STATUS_DRIVER_ENTRYPOINT_NOT_FOUND', 3221226084: 'STATUS_RESOURCE_NOT_OWNED', 3221226085: 'STATUS_TOO_MANY_LINKS', 3221226086: 'STATUS_QUOTA_LIST_INCONSISTENT', 3221226087: 'STATUS_FILE_IS_OFFLINE', 3221226088: 'STATUS_EVALUATION_EXPIRATION', 3221226089: 'STATUS_ILLEGAL_DLL_RELOCATION', 3221226090: 'STATUS_LICENSE_VIOLATION', 3221226091: 'STATUS_DLL_INIT_FAILED_LOGOFF', 3221226092: 'STATUS_DRIVER_UNABLE_TO_LOAD', 3221226093: 'STATUS_DFS_UNAVAILABLE', 3221226094: 'STATUS_VOLUME_DISMOUNTED', 3221226095: 'STATUS_WX86_INTERNAL_ERROR', 3221226096: 'STATUS_WX86_FLOAT_STACK_CHECK', 3221226097: 'STATUS_VALIDATE_CONTINUE', 3221226098: 'STATUS_NO_MATCH', 3221226099: 'STATUS_NO_MORE_MATCHES', 3221226101: 'STATUS_NOT_A_REPARSE_POINT', 3221226102: 'STATUS_IO_REPARSE_TAG_INVALID', 3221226103: 'STATUS_IO_REPARSE_TAG_MISMATCH', 3221226104: 'STATUS_IO_REPARSE_DATA_INVALID', 3221226105: 'STATUS_IO_REPARSE_TAG_NOT_HANDLED', 3221226112: 'STATUS_REPARSE_POINT_NOT_RESOLVED', 3221226113: 'STATUS_DIRECTORY_IS_A_REPARSE_POINT', 3221226114: 'STATUS_RANGE_LIST_CONFLICT', 3221226115: 'STATUS_SOURCE_ELEMENT_EMPTY', 3221226116: 'STATUS_DESTINATION_ELEMENT_FULL', 3221226117: 'STATUS_ILLEGAL_ELEMENT_ADDRESS', 3221226118: 'STATUS_MAGAZINE_NOT_PRESENT', 3221226119: 'STATUS_REINITIALIZATION_NEEDED', 3221226122: 'STATUS_ENCRYPTION_FAILED', 3221226123: 'STATUS_DECRYPTION_FAILED', 3221226124: 'STATUS_RANGE_NOT_FOUND', 3221226125: 'STATUS_NO_RECOVERY_POLICY', 3221226126: 'STATUS_NO_EFS', 3221226127: 'STATUS_WRONG_EFS', 3221226128: 'STATUS_NO_USER_KEYS', 3221226129: 'STATUS_FILE_NOT_ENCRYPTED', 3221226130: 'STATUS_NOT_EXPORT_FORMAT', 3221226131: 'STATUS_FILE_ENCRYPTED', 3221226133: 'STATUS_WMI_GUID_NOT_FOUND', 3221226134: 'STATUS_WMI_INSTANCE_NOT_FOUND', 3221226135: 'STATUS_WMI_ITEMID_NOT_FOUND', 3221226136: 'STATUS_WMI_TRY_AGAIN', 3221226137: 'STATUS_SHARED_POLICY', 3221226138: 'STATUS_POLICY_OBJECT_NOT_FOUND', 3221226139: 'STATUS_POLICY_ONLY_IN_DS', 3221226140: 'STATUS_VOLUME_NOT_UPGRADED', 3221226141: 'STATUS_REMOTE_STORAGE_NOT_ACTIVE', 3221226142: 'STATUS_REMOTE_STORAGE_MEDIA_ERROR', 3221226143: 'STATUS_NO_TRACKING_SERVICE', 3221226144: 'STATUS_SERVER_SID_MISMATCH', 3221226145: 'STATUS_DS_NO_ATTRIBUTE_OR_VALUE', 3221226146: 'STATUS_DS_INVALID_ATTRIBUTE_SYNTAX', 3221226147: 'STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED', 3221226148: 'STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS', 3221226149: 'STATUS_DS_BUSY', 3221226150: 'STATUS_DS_UNAVAILABLE', 3221226151: 'STATUS_DS_NO_RIDS_ALLOCATED', 3221226152: 'STATUS_DS_NO_MORE_RIDS', 3221226153: 'STATUS_DS_INCORRECT_ROLE_OWNER', 3221226154: 'STATUS_DS_RIDMGR_INIT_ERROR', 3221226155: 'STATUS_DS_OBJ_CLASS_VIOLATION', 3221226156: 'STATUS_DS_CANT_ON_NON_LEAF', 3221226157: 'STATUS_DS_CANT_ON_RDN', 3221226158: 'STATUS_DS_CANT_MOD_OBJ_CLASS', 3221226159: 'STATUS_DS_CROSS_DOM_MOVE_FAILED', 3221226160: 'STATUS_DS_GC_NOT_AVAILABLE', 3221226161: 'STATUS_DIRECTORY_SERVICE_REQUIRED', 3221226162: 'STATUS_REPARSE_ATTRIBUTE_CONFLICT', 3221226163: 'STATUS_CANT_ENABLE_DENY_ONLY', 3221226164: 'STATUS_FLOAT_MULTIPLE_FAULTS', 3221226165: 'STATUS_FLOAT_MULTIPLE_TRAPS', 3221226166: 'STATUS_DEVICE_REMOVED', 3221226167: 'STATUS_JOURNAL_DELETE_IN_PROGRESS', 3221226168: 'STATUS_JOURNAL_NOT_ACTIVE', 3221226169: 'STATUS_NOINTERFACE', 3221226177: 'STATUS_DS_ADMIN_LIMIT_EXCEEDED', 3221226178: 'STATUS_DRIVER_FAILED_SLEEP', 3221226179: 'STATUS_MUTUAL_AUTHENTICATION_FAILED', 3221226180: 'STATUS_CORRUPT_SYSTEM_FILE', 3221226181: 'STATUS_DATATYPE_MISALIGNMENT_ERROR', 3221226182: 'STATUS_WMI_READ_ONLY', 3221226183: 'STATUS_WMI_SET_FAILURE', 3221226184: 'STATUS_COMMITMENT_MINIMUM', 3221226185: 'STATUS_REG_NAT_CONSUMPTION', 3221226186: 'STATUS_TRANSPORT_FULL', 3221226187: 'STATUS_DS_SAM_INIT_FAILURE', 3221226188: 'STATUS_ONLY_IF_CONNECTED', 3221226189: 'STATUS_DS_SENSITIVE_GROUP_VIOLATION', 3221226190: 'STATUS_PNP_RESTART_ENUMERATION', 3221226191: 'STATUS_JOURNAL_ENTRY_DELETED', 3221226192: 'STATUS_DS_CANT_MOD_PRIMARYGROUPID', 3221226193: 'STATUS_SYSTEM_IMAGE_BAD_SIGNATURE', 3221226194: 'STATUS_PNP_REBOOT_REQUIRED', 3221226195: 'STATUS_POWER_STATE_INVALID', 3221226196: 'STATUS_DS_INVALID_GROUP_TYPE', 3221226197: 'STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN', 3221226198: 'STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN', 3221226199: 'STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER', 3221226200: 'STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER', 3221226201: 'STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER', 3221226202: 'STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER', 3221226203: 'STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER', 3221226204: 'STATUS_DS_HAVE_PRIMARY_MEMBERS', 3221226205:'STATUS_WMI_NOT_SUPPORTED', 3221226206: 'STATUS_INSUFFICIENT_POWER', 3221226207: 'STATUS_SAM_NEED_BOOTKEY_PASSWORD', 3221226208: 'STATUS_SAM_NEED_BOOTKEY_FLOPPY', 3221226209: 'STATUS_DS_CANT_START', 3221226210: 'STATUS_DS_INIT_FAILURE', 3221226211: 'STATUS_SAM_INIT_FAILURE', 3221226212: 'STATUS_DS_GC_REQUIRED', 3221226213: 'STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY', 3221226214: 'STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS', 3221226215: 'STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED', 3221226217: 'STATUS_CURRENT_DOMAIN_NOT_ALLOWED', 3221226218: 'STATUS_CANNOT_MAKE', 3221226219: 'STATUS_SYSTEM_SHUTDOWN', 3221226220: 'STATUS_DS_INIT_FAILURE_CONSOLE', 3221226221: 'STATUS_DS_SAM_INIT_FAILURE_CONSOLE', 3221226222: 'STATUS_UNFINISHED_CONTEXT_DELETED', 3221226223: 'STATUS_NO_TGT_REPLY', 3221226224: 'STATUS_OBJECTID_NOT_FOUND', 3221226225: 'STATUS_NO_IP_ADDRESSES', 3221226226: 'STATUS_WRONG_CREDENTIAL_HANDLE', 3221226227: 'STATUS_CRYPTO_SYSTEM_INVALID', 3221226228: 'STATUS_MAX_REFERRALS_EXCEEDED', 3221226229: 'STATUS_MUST_BE_KDC', 3221226230: 'STATUS_STRONG_CRYPTO_NOT_SUPPORTED', 3221226231: 'STATUS_TOO_MANY_PRINCIPALS', 3221226232: 'STATUS_NO_PA_DATA', 3221226233: 'STATUS_PKINIT_NAME_MISMATCH', 3221226234: 'STATUS_SMARTCARD_LOGON_REQUIRED', 3221226235: 'STATUS_KDC_INVALID_REQUEST', 3221226236: 'STATUS_KDC_UNABLE_TO_REFER', 3221226237: 'STATUS_KDC_UNKNOWN_ETYPE', 3221226238: 'STATUS_SHUTDOWN_IN_PROGRESS', 3221226239: 'STATUS_SERVER_SHUTDOWN_IN_PROGRESS', 3221226240: 'STATUS_NOT_SUPPORTED_ON_SBS', 3221226241: 'STATUS_WMI_GUID_DISCONNECTED', 3221226242: 'STATUS_WMI_ALREADY_DISABLED', 3221226243: 'STATUS_WMI_ALREADY_ENABLED', 3221226244: 'STATUS_MFT_TOO_FRAGMENTED', 3221226245: 'STATUS_COPY_PROTECTION_FAILURE', 3221226246: 'STATUS_CSS_AUTHENTICATION_FAILURE', 3221226247: 'STATUS_CSS_KEY_NOT_PRESENT', 3221226248: 'STATUS_CSS_KEY_NOT_ESTABLISHED', 3221226249: 'STATUS_CSS_SCRAMBLED_SECTOR', 3221226250: 'STATUS_CSS_REGION_MISMATCH', 3221226251: 'STATUS_CSS_RESETS_EXHAUSTED', 3221226272: 'STATUS_PKINIT_FAILURE', 3221226273: 'STATUS_SMARTCARD_SUBSYSTEM_FAILURE', 3221226274: 'STATUS_NO_KERB_KEY', 3221226320: 'STATUS_HOST_DOWN', 3221226321: 'STATUS_UNSUPPORTED_PREAUTH', 3221226322: 'STATUS_EFS_ALG_BLOB_TOO_BIG', 3221226323: 'STATUS_PORT_NOT_SET', 3221226324: 'STATUS_DEBUGGER_INACTIVE', 3221226325: 'STATUS_DS_VERSION_CHECK_FAILURE', 3221226326: 'STATUS_AUDITING_DISABLED', 3221226327: 'STATUS_PRENT4_MACHINE_ACCOUNT', 3221226328: 'STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER', 3221226329: 'STATUS_INVALID_IMAGE_WIN_32', 3221226330: 'STATUS_INVALID_IMAGE_WIN_64', 3221226331: 'STATUS_BAD_BINDINGS', 3221226332: 'STATUS_NETWORK_SESSION_EXPIRED', 3221226333: 'STATUS_APPHELP_BLOCK', 3221226334: 'STATUS_ALL_SIDS_FILTERED', 3221226335: 'STATUS_NOT_SAFE_MODE_DRIVER', 3221226337: 'STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT', 3221226338: 'STATUS_ACCESS_DISABLED_BY_POLICY_PATH', 3221226339: 'STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER', 3221226340: 'STATUS_ACCESS_DISABLED_BY_POLICY_OTHER', 3221226341: 'STATUS_FAILED_DRIVER_ENTRY', 3221226342: 'STATUS_DEVICE_ENUMERATION_ERROR', 3221226344: 'STATUS_MOUNT_POINT_NOT_RESOLVED', 3221226345: 'STATUS_INVALID_DEVICE_OBJECT_PARAMETER', 3221226346: 'STATUS_MCA_OCCURED', 3221226347: 'STATUS_DRIVER_BLOCKED_CRITICAL', 3221226348: 'STATUS_DRIVER_BLOCKED', 3221226349: 'STATUS_DRIVER_DATABASE_ERROR', 3221226350: 'STATUS_SYSTEM_HIVE_TOO_LARGE', 3221226351: 'STATUS_INVALID_IMPORT_OF_NON_DLL', 3221226353: 'STATUS_NO_SECRETS', 3221226354: 'STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY', 3221226355: 'STATUS_FAILED_STACK_SWITCH', 3221226356: 'STATUS_HEAP_CORRUPTION', 3221226368: 'STATUS_SMARTCARD_WRONG_PIN', 3221226369: 'STATUS_SMARTCARD_CARD_BLOCKED', 3221226370: 'STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED', 3221226371: 'STATUS_SMARTCARD_NO_CARD', 3221226372: 'STATUS_SMARTCARD_NO_KEY_CONTAINER', 3221226373: 'STATUS_SMARTCARD_NO_CERTIFICATE', 3221226374: 'STATUS_SMARTCARD_NO_KEYSET', 3221226375: 'STATUS_SMARTCARD_IO_ERROR', 3221226376: 'STATUS_DOWNGRADE_DETECTED', 3221226377: 'STATUS_SMARTCARD_CERT_REVOKED', 3221226378: 'STATUS_ISSUING_CA_UNTRUSTED', 3221226379: 'STATUS_REVOCATION_OFFLINE_C', 3221226380: 'STATUS_PKINIT_CLIENT_FAILURE', 3221226381: 'STATUS_SMARTCARD_CERT_EXPIRED', 3221226382: 'STATUS_DRIVER_FAILED_PRIOR_UNLOAD', 3221226383: 'STATUS_SMARTCARD_SILENT_CONTEXT', 3221226497: 'STATUS_PER_USER_TRUST_QUOTA_EXCEEDED', 3221226498: 'STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED', 3221226499: 'STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED', 3221226500: 'STATUS_DS_NAME_NOT_UNIQUE', 3221226501: 'STATUS_DS_DUPLICATE_ID_FOUND', 3221226502: 'STATUS_DS_GROUP_CONVERSION_ERROR', 3221226503: 'STATUS_VOLSNAP_PREPARE_HIBERNATE', 3221226504: 'STATUS_USER2USER_REQUIRED', 3221226505: 'STATUS_STACK_BUFFER_OVERRUN', 3221226506: 'STATUS_NO_S4U_PROT_SUPPORT', 3221226507: 'STATUS_CROSSREALM_DELEGATION_FAILURE', 3221226508: 'STATUS_REVOCATION_OFFLINE_KDC', 3221226509: 'STATUS_ISSUING_CA_UNTRUSTED_KDC', 3221226510: 'STATUS_KDC_CERT_EXPIRED', 3221226511: 'STATUS_KDC_CERT_REVOKED', 3221226512: 'STATUS_PARAMETER_QUOTA_EXCEEDED', 3221226513: 'STATUS_HIBERNATION_FAILURE', 3221226514: 'STATUS_DELAY_LOAD_FAILED', 3221226515: 'STATUS_AUTHENTICATION_FIREWALL_FAILED', 3221226516: 'STATUS_VDM_DISALLOWED', 3221226517: 'STATUS_HUNG_DISPLAY_DRIVER_THREAD', 3221226518: 'STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE', 3221226519: 'STATUS_INVALID_CRUNTIME_PARAMETER', 3221226520: 'STATUS_NTLM_BLOCKED', 3221226521: 'STATUS_DS_SRC_SID_EXISTS_IN_FOREST', 3221226522: 'STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST', 3221226523: 'STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST', 3221226524: 'STATUS_INVALID_USER_PRINCIPAL_NAME', 3221226528: 'STATUS_ASSERTION_FAILURE', 3221226529: 'STATUS_VERIFIER_STOP', 3221226531: 'STATUS_CALLBACK_POP_STACK', 3221226532: 'STATUS_INCOMPATIBLE_DRIVER_BLOCKED', 3221226533: 'STATUS_HIVE_UNLOADED', 3221226534: 'STATUS_COMPRESSION_DISABLED', 3221226535: 'STATUS_FILE_SYSTEM_LIMITATION', 3221226536: 'STATUS_INVALID_IMAGE_HASH', 3221226537: 'STATUS_NOT_CAPABLE', 3221226538: 'STATUS_REQUEST_OUT_OF_SEQUENCE', 3221226539: 'STATUS_IMPLEMENTATION_LIMIT', 3221226540: 'STATUS_ELEVATION_REQUIRED', 3221226541: 'STATUS_NO_SECURITY_CONTEXT', 3221226542: 'STATUS_PKU2U_CERT_FAILURE', 3221226546: 'STATUS_BEYOND_VDL', 3221226547: 'STATUS_ENCOUNTERED_WRITE_IN_PROGRESS', 3221226548: 'STATUS_PTE_CHANGED', 3221226549: 'STATUS_PURGE_FAILED', 3221226560: 'STATUS_CRED_REQUIRES_CONFIRMATION', 3221226561: 'STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE', 3221226562: 'STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER', 3221226563: 'STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE', 3221226564: 'STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE', 3221226565: 'STATUS_CS_ENCRYPTION_FILE_NOT_CSE', 3221226566: 'STATUS_INVALID_LABEL', 3221226576: 'STATUS_DRIVER_PROCESS_TERMINATED', 3221226577: 'STATUS_AMBIGUOUS_SYSTEM_DEVICE', 3221226578: 'STATUS_SYSTEM_DEVICE_NOT_FOUND', 3221226579: 'STATUS_RESTART_BOOT_APPLICATION', 3221226580: 'STATUS_INSUFFICIENT_NVRAM_RESOURCES', 3221226592: 'STATUS_NO_RANGES_PROCESSED', 3221226595: 'STATUS_DEVICE_FEATURE_NOT_SUPPORTED', 3221226596: 'STATUS_DEVICE_UNREACHABLE', 3221226597: 'STATUS_INVALID_TOKEN', 3221226598: 'STATUS_SERVER_UNAVAILABLE', 3221226752: 'STATUS_INVALID_TASK_NAME', 3221226753: 'STATUS_INVALID_TASK_INDEX', 3221226754: 'STATUS_THREAD_ALREADY_IN_TASK', 3221226755: 'STATUS_CALLBACK_BYPASS', 3221227010: 'STATUS_FAIL_FAST_EXCEPTION', 3221227011: 'STATUS_IMAGE_CERT_REVOKED', 3221227264: 'STATUS_PORT_CLOSED', 3221227265: 'STATUS_MESSAGE_LOST', 3221227266: 'STATUS_INVALID_MESSAGE', 3221227267: 'STATUS_REQUEST_CANCELED', 3221227268: 'STATUS_RECURSIVE_DISPATCH', 3221227269: 'STATUS_LPC_RECEIVE_BUFFER_EXPECTED', 3221227270: 'STATUS_LPC_INVALID_CONNECTION_USAGE', 3221227271: 'STATUS_LPC_REQUESTS_NOT_ALLOWED', 3221227272: 'STATUS_RESOURCE_IN_USE', 3221227273: 'STATUS_HARDWARE_MEMORY_ERROR', 3221227274: 'STATUS_THREADPOOL_HANDLE_EXCEPTION', 3221227275: 'STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED', 3221227276: 'STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED', 3221227277: 'STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED', 3221227278: 'STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED', 3221227279: 'STATUS_THREADPOOL_RELEASED_DURING_OPERATION', 3221227280: 'STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING', 3221227281: 'STATUS_APC_RETURNED_WHILE_IMPERSONATING', 3221227282: 'STATUS_PROCESS_IS_PROTECTED', 3221227283: 'STATUS_MCA_EXCEPTION', 3221227284: 'STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE', 3221227285: 'STATUS_SYMLINK_CLASS_DISABLED', 3221227286: 'STATUS_INVALID_IDN_NORMALIZATION', 3221227287: 'STATUS_NO_UNICODE_TRANSLATION', 3221227288: 'STATUS_ALREADY_REGISTERED', 3221227289: 'STATUS_CONTEXT_MISMATCH', 3221227290: 'STATUS_PORT_ALREADY_HAS_COMPLETION_LIST', 3221227291: 'STATUS_CALLBACK_RETURNED_THREAD_PRIORITY', 3221227292: 'STATUS_INVALID_THREAD', 3221227293: 'STATUS_CALLBACK_RETURNED_TRANSACTION', 3221227294: 'STATUS_CALLBACK_RETURNED_LDR_LOCK', 3221227295: 'STATUS_CALLBACK_RETURNED_LANG', 3221227296: 'STATUS_CALLBACK_RETURNED_PRI_BACK', 3221227520: 'STATUS_DISK_REPAIR_DISABLED', 3221227521: 'STATUS_DS_DOMAIN_RENAME_IN_PROGRESS', 3221227522: 'STATUS_DISK_QUOTA_EXCEEDED', 3221227524: 'STATUS_CONTENT_BLOCKED', 3221227525: 'STATUS_BAD_CLUSTERS', 3221227526: 'STATUS_VOLUME_DIRTY', 3221227777: 'STATUS_FILE_CHECKED_OUT', 3221227778: 'STATUS_CHECKOUT_REQUIRED', 3221227779: 'STATUS_BAD_FILE_TYPE', 3221227780: 'STATUS_FILE_TOO_LARGE', 3221227781: 'STATUS_FORMS_AUTH_REQUIRED', 3221227782: 'STATUS_VIRUS_INFECTED', 3221227783: 'STATUS_VIRUS_DELETED', 3221227784: 'STATUS_BAD_MCFG_TABLE', 3221227785: 'STATUS_CANNOT_BREAK_OPLOCK', 3221264536: 'STATUS_WOW_ASSERTION', 3221266432: 'STATUS_INVALID_SIGNATURE', 3221266433: 'STATUS_HMAC_NOT_SUPPORTED', 3221266448: 'STATUS_IPSEC_QUEUE_OVERFLOW', 3221266449: 'STATUS_ND_QUEUE_OVERFLOW', 3221266450: 'STATUS_HOPLIMIT_EXCEEDED', 3221266451: 'STATUS_PROTOCOL_NOT_SUPPORTED', 3221266560: 'STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED', 3221266561: 'STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR', 3221266562: 'STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR', 3221266563: 'STATUS_XML_PARSE_ERROR', 3221266564: 'STATUS_XMLDSIG_ERROR', 3221266565: 'STATUS_WRONG_COMPARTMENT', 3221266566: 'STATUS_AUTHIP_FAILURE', 3221266567: 'STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS',3221266568: 'STATUS_DS_OID_NOT_FOUND', 3221266688: 'STATUS_HASH_NOT_SUPPORTED', 3221266689: 'STATUS_HASH_NOT_PRESENT', 3221267105: 'STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED', 3221267106: 'STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED', 3221267107: 'STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED', 3221267108: 'STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED', 3221291009: 'DBG_NO_STATE_CHANGE', 3221291010: 'DBG_APP_NOT_IDLE', 3221356545: 'RPC_NT_INVALID_STRING_BINDING', 3221356546: 'RPC_NT_WRONG_KIND_OF_BINDING', 3221356547: 'RPC_NT_INVALID_BINDING', 3221356548: 'RPC_NT_PROTSEQ_NOT_SUPPORTED', 3221356549: 'RPC_NT_INVALID_RPC_PROTSEQ', 3221356550: 'RPC_NT_INVALID_STRING_UUID', 3221356551: 'RPC_NT_INVALID_ENDPOINT_FORMAT', 3221356552: 'RPC_NT_INVALID_NET_ADDR', 3221356553: 'RPC_NT_NO_ENDPOINT_FOUND', 3221356554: 'RPC_NT_INVALID_TIMEOUT', 3221356555: 'RPC_NT_OBJECT_NOT_FOUND', 3221356556: 'RPC_NT_ALREADY_REGISTERED', 3221356557: 'RPC_NT_TYPE_ALREADY_REGISTERED', 3221356558: 'RPC_NT_ALREADY_LISTENING', 3221356559: 'RPC_NT_NO_PROTSEQS_REGISTERED', 3221356560: 'RPC_NT_NOT_LISTENING', 3221356561: 'RPC_NT_UNKNOWN_MGR_TYPE', 3221356562: 'RPC_NT_UNKNOWN_IF', 3221356563: 'RPC_NT_NO_BINDINGS', 3221356564: 'RPC_NT_NO_PROTSEQS', 3221356565: 'RPC_NT_CANT_CREATE_ENDPOINT', 3221356566: 'RPC_NT_OUT_OF_RESOURCES', 3221356567: 'RPC_NT_SERVER_UNAVAILABLE', 3221356568: 'RPC_NT_SERVER_TOO_BUSY', 3221356569: 'RPC_NT_INVALID_NETWORK_OPTIONS', 3221356570: 'RPC_NT_NO_CALL_ACTIVE', 3221356571: 'RPC_NT_CALL_FAILED', 3221356572: 'RPC_NT_CALL_FAILED_DNE', 3221356573: 'RPC_NT_PROTOCOL_ERROR', 3221356575: 'RPC_NT_UNSUPPORTED_TRANS_SYN', 3221356577: 'RPC_NT_UNSUPPORTED_TYPE', 3221356578: 'RPC_NT_INVALID_TAG', 3221356579: 'RPC_NT_INVALID_BOUND', 3221356580: 'RPC_NT_NO_ENTRY_NAME', 3221356581: 'RPC_NT_INVALID_NAME_SYNTAX', 3221356582: 'RPC_NT_UNSUPPORTED_NAME_SYNTAX', 3221356584: 'RPC_NT_UUID_NO_ADDRESS', 3221356585: 'RPC_NT_DUPLICATE_ENDPOINT', 3221356586: 'RPC_NT_UNKNOWN_AUTHN_TYPE', 3221356587: 'RPC_NT_MAX_CALLS_TOO_SMALL', 3221356588: 'RPC_NT_STRING_TOO_LONG', 3221356589: 'RPC_NT_PROTSEQ_NOT_FOUND', 3221356590: 'RPC_NT_PROCNUM_OUT_OF_RANGE', 3221356591: 'RPC_NT_BINDING_HAS_NO_AUTH', 3221356592: 'RPC_NT_UNKNOWN_AUTHN_SERVICE', 3221356593: 'RPC_NT_UNKNOWN_AUTHN_LEVEL', 3221356594: 'RPC_NT_INVALID_AUTH_IDENTITY', 3221356595: 'RPC_NT_UNKNOWN_AUTHZ_SERVICE', 3221356596: 'EPT_NT_INVALID_ENTRY', 3221356597: 'EPT_NT_CANT_PERFORM_OP', 3221356598: 'EPT_NT_NOT_REGISTERED', 3221356599: 'RPC_NT_NOTHING_TO_EXPORT', 3221356600: 'RPC_NT_INCOMPLETE_NAME', 3221356601: 'RPC_NT_INVALID_VERS_OPTION', 3221356602: 'RPC_NT_NO_MORE_MEMBERS', 3221356603: 'RPC_NT_NOT_ALL_OBJS_UNEXPORTED', 3221356604: 'RPC_NT_INTERFACE_NOT_FOUND', 3221356605: 'RPC_NT_ENTRY_ALREADY_EXISTS', 3221356606: 'RPC_NT_ENTRY_NOT_FOUND', 3221356607: 'RPC_NT_NAME_SERVICE_UNAVAILABLE', 3221356608: 'RPC_NT_INVALID_NAF_ID', 3221356609: 'RPC_NT_CANNOT_SUPPORT', 3221356610: 'RPC_NT_NO_CONTEXT_AVAILABLE', 3221356611: 'RPC_NT_INTERNAL_ERROR', 3221356612: 'RPC_NT_ZERO_DIVIDE', 3221356613: 'RPC_NT_ADDRESS_ERROR', 3221356614: 'RPC_NT_FP_DIV_ZERO', 3221356615: 'RPC_NT_FP_UNDERFLOW', 3221356616: 'RPC_NT_FP_OVERFLOW', 3221356617: 'RPC_NT_CALL_IN_PROGRESS', 3221356618: 'RPC_NT_NO_MORE_BINDINGS', 3221356619: 'RPC_NT_GROUP_MEMBER_NOT_FOUND', 3221356620: 'EPT_NT_CANT_CREATE', 3221356621: 'RPC_NT_INVALID_OBJECT', 3221356623: 'RPC_NT_NO_INTERFACES', 3221356624: 'RPC_NT_CALL_CANCELLED', 3221356625: 'RPC_NT_BINDING_INCOMPLETE', 3221356626: 'RPC_NT_COMM_FAILURE', 3221356627: 'RPC_NT_UNSUPPORTED_AUTHN_LEVEL', 3221356628: 'RPC_NT_NO_PRINC_NAME', 3221356629: 'RPC_NT_NOT_RPC_ERROR', 3221356631: 'RPC_NT_SEC_PKG_ERROR', 3221356632: 'RPC_NT_NOT_CANCELLED', 3221356642: 'RPC_NT_INVALID_ASYNC_HANDLE', 3221356643: 'RPC_NT_INVALID_ASYNC_CALL', 3221356644: 'RPC_NT_PROXY_ACCESS_DENIED', 3221422081: 'RPC_NT_NO_MORE_ENTRIES', 3221422082: 'RPC_NT_SS_CHAR_TRANS_OPEN_FAIL', 3221422083: 'RPC_NT_SS_CHAR_TRANS_SHORT_FILE', 3221422084: 'RPC_NT_SS_IN_NULL_CONTEXT', 3221422085: 'RPC_NT_SS_CONTEXT_MISMATCH', 3221422086: 'RPC_NT_SS_CONTEXT_DAMAGED', 3221422087: 'RPC_NT_SS_HANDLES_MISMATCH', 3221422088: 'RPC_NT_SS_CANNOT_GET_CALL_HANDLE', 3221422089: 'RPC_NT_NULL_REF_POINTER', 3221422090: 'RPC_NT_ENUM_VALUE_OUT_OF_RANGE', 3221422091: 'RPC_NT_BYTE_COUNT_TOO_SMALL', 3221422092: 'RPC_NT_BAD_STUB_DATA', 3221422169: 'RPC_NT_INVALID_ES_ACTION', 3221422170: 'RPC_NT_WRONG_ES_VERSION', 3221422171: 'RPC_NT_WRONG_STUB_VERSION', 3221422172: 'RPC_NT_INVALID_PIPE_OBJECT', 3221422173: 'RPC_NT_INVALID_PIPE_OPERATION', 3221422174: 'RPC_NT_WRONG_PIPE_VERSION', 3221422175: 'RPC_NT_PIPE_CLOSED', 3221422176: 'RPC_NT_PIPE_DISCIPLINE_ERROR', 3221422177: 'RPC_NT_PIPE_EMPTY', 3221487669: 'STATUS_PNP_BAD_MPS_TABLE', 3221487670: 'STATUS_PNP_TRANSLATION_FAILED', 3221487671: 'STATUS_PNP_IRQ_TRANSLATION_FAILED', 3221487672: 'STATUS_PNP_INVALID_ID', 3221487673: 'STATUS_IO_REISSUE_AS_CACHED', 3221880833: 'STATUS_CTX_WINSTATION_NAME_INVALID', 3221880834: 'STATUS_CTX_INVALID_PD', 3221880835: 'STATUS_CTX_PD_NOT_FOUND', 3221880838: 'STATUS_CTX_CLOSE_PENDING', 3221880839: 'STATUS_CTX_NO_OUTBUF', 3221880840: 'STATUS_CTX_MODEM_INF_NOT_FOUND', 3221880841: 'STATUS_CTX_INVALID_MODEMNAME', 3221880842: 'STATUS_CTX_RESPONSE_ERROR', 3221880843: 'STATUS_CTX_MODEM_RESPONSE_TIMEOUT', 3221880844: 'STATUS_CTX_MODEM_RESPONSE_NO_CARRIER', 3221880845: 'STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE', 3221880846: 'STATUS_CTX_MODEM_RESPONSE_BUSY', 3221880847: 'STATUS_CTX_MODEM_RESPONSE_VOICE', 3221880848: 'STATUS_CTX_TD_ERROR', 3221880850: 'STATUS_CTX_LICENSE_CLIENT_INVALID', 3221880851: 'STATUS_CTX_LICENSE_NOT_AVAILABLE', 3221880852: 'STATUS_CTX_LICENSE_EXPIRED', 3221880853: 'STATUS_CTX_WINSTATION_NOT_FOUND', 3221880854: 'STATUS_CTX_WINSTATION_NAME_COLLISION', 3221880855: 'STATUS_CTX_WINSTATION_BUSY', 3221880856: 'STATUS_CTX_BAD_VIDEO_MODE', 3221880866: 'STATUS_CTX_GRAPHICS_INVALID', 3221880868: 'STATUS_CTX_NOT_CONSOLE', 3221880870: 'STATUS_CTX_CLIENT_QUERY_TIMEOUT', 3221880871: 'STATUS_CTX_CONSOLE_DISCONNECT', 3221880872: 'STATUS_CTX_CONSOLE_CONNECT', 3221880874: 'STATUS_CTX_SHADOW_DENIED', 3221880875: 'STATUS_CTX_WINSTATION_ACCESS_DENIED', 3221880878: 'STATUS_CTX_INVALID_WD', 3221880879: 'STATUS_CTX_WD_NOT_FOUND', 3221880880: 'STATUS_CTX_SHADOW_INVALID', 3221880881: 'STATUS_CTX_SHADOW_DISABLED', 3221880882: 'STATUS_RDP_PROTOCOL_ERROR', 3221880883: 'STATUS_CTX_CLIENT_LICENSE_NOT_SET', 3221880884: 'STATUS_CTX_CLIENT_LICENSE_IN_USE', 3221880885: 'STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE', 3221880886: 'STATUS_CTX_SHADOW_NOT_RUNNING', 3221880887: 'STATUS_CTX_LOGON_DISABLED', 3221880888: 'STATUS_CTX_SECURITY_LAYER_ERROR', 3221880889: 'STATUS_TS_INCOMPATIBLE_SESSIONS', 3221946369: 'STATUS_MUI_FILE_NOT_FOUND', 3221946370: 'STATUS_MUI_INVALID_FILE', 3221946371: 'STATUS_MUI_INVALID_RC_CONFIG', 3221946372: 'STATUS_MUI_INVALID_LOCALE_NAME', 3221946373: 'STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME', 3221946374: 'STATUS_MUI_FILE_NOT_LOADED',3221946375: 'STATUS_RESOURCE_ENUM_USER_STOP', 3222470657: 'STATUS_CLUSTER_INVALID_NODE', 3222470658: 'STATUS_CLUSTER_NODE_EXISTS', 3222470659: 'STATUS_CLUSTER_JOIN_IN_PROGRESS', 3222470660: 'STATUS_CLUSTER_NODE_NOT_FOUND', 3222470661: 'STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND', 3222470662: 'STATUS_CLUSTER_NETWORK_EXISTS', 3222470663: 'STATUS_CLUSTER_NETWORK_NOT_FOUND', 3222470664: 'STATUS_CLUSTER_NETINTERFACE_EXISTS', 3222470665: 'STATUS_CLUSTER_NETINTERFACE_NOT_FOUND', 3222470666: 'STATUS_CLUSTER_INVALID_REQUEST', 3222470667: 'STATUS_CLUSTER_INVALID_NETWORK_PROVIDER', 3222470668: 'STATUS_CLUSTER_NODE_DOWN', 3222470669: 'STATUS_CLUSTER_NODE_UNREACHABLE', 3222470670: 'STATUS_CLUSTER_NODE_NOT_MEMBER', 3222470671: 'STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS', 3222470672: 'STATUS_CLUSTER_INVALID_NETWORK', 3222470673: 'STATUS_CLUSTER_NO_NET_ADAPTERS', 3222470674: 'STATUS_CLUSTER_NODE_UP', 3222470675: 'STATUS_CLUSTER_NODE_PAUSED', 3222470676: 'STATUS_CLUSTER_NODE_NOT_PAUSED', 3222470677: 'STATUS_CLUSTER_NO_SECURITY_CONTEXT', 3222470678: 'STATUS_CLUSTER_NETWORK_NOT_INTERNAL', 3222470679: 'STATUS_CLUSTER_POISONED', 3222536193: 'STATUS_ACPI_INVALID_OPCODE', 3222536194: 'STATUS_ACPI_STACK_OVERFLOW', 3222536195: 'STATUS_ACPI_ASSERT_FAILED', 3222536196: 'STATUS_ACPI_INVALID_INDEX', 3222536197: 'STATUS_ACPI_INVALID_ARGUMENT', 3222536198: 'STATUS_ACPI_FATAL', 3222536199: 'STATUS_ACPI_INVALID_SUPERNAME', 3222536200: 'STATUS_ACPI_INVALID_ARGTYPE', 3222536201: 'STATUS_ACPI_INVALID_OBJTYPE', 3222536202: 'STATUS_ACPI_INVALID_TARGETTYPE', 3222536203: 'STATUS_ACPI_INCORRECT_ARGUMENT_COUNT', 3222536204: 'STATUS_ACPI_ADDRESS_NOT_MAPPED', 3222536205: 'STATUS_ACPI_INVALID_EVENTTYPE', 3222536206: 'STATUS_ACPI_HANDLER_COLLISION', 3222536207: 'STATUS_ACPI_INVALID_DATA', 3222536208: 'STATUS_ACPI_INVALID_REGION', 3222536209: 'STATUS_ACPI_INVALID_ACCESS_SIZE', 3222536210: 'STATUS_ACPI_ACQUIRE_GLOBAL_LOCK', 3222536211: 'STATUS_ACPI_ALREADY_INITIALIZED', 3222536212: 'STATUS_ACPI_NOT_INITIALIZED', 3222536213: 'STATUS_ACPI_INVALID_MUTEX_LEVEL', 3222536214: 'STATUS_ACPI_MUTEX_NOT_OWNED', 3222536215: 'STATUS_ACPI_MUTEX_NOT_OWNER', 3222536216: 'STATUS_ACPI_RS_ACCESS', 3222536217: 'STATUS_ACPI_INVALID_TABLE', 3222536224: 'STATUS_ACPI_REG_HANDLER_FAILED', 3222536225: 'STATUS_ACPI_POWER_REQUEST_FAILED', 3222601729: 'STATUS_SXS_SECTION_NOT_FOUND', 3222601730: 'STATUS_SXS_CANT_GEN_ACTCTX', 3222601731: 'STATUS_SXS_INVALID_ACTCTXDATA_FORMAT', 3222601732: 'STATUS_SXS_ASSEMBLY_NOT_FOUND', 3222601733: 'STATUS_SXS_MANIFEST_FORMAT_ERROR', 3222601734: 'STATUS_SXS_MANIFEST_PARSE_ERROR', 3222601735: 'STATUS_SXS_ACTIVATION_CONTEXT_DISABLED', 3222601736: 'STATUS_SXS_KEY_NOT_FOUND', 3222601737: 'STATUS_SXS_VERSION_CONFLICT', 3222601738: 'STATUS_SXS_WRONG_SECTION_TYPE', 3222601739: 'STATUS_SXS_THREAD_QUERIES_DISABLED', 3222601740: 'STATUS_SXS_ASSEMBLY_MISSING', 3222601742: 'STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET', 3222601743: 'STATUS_SXS_EARLY_DEACTIVATION', 3222601744: 'STATUS_SXS_INVALID_DEACTIVATION', 3222601745: 'STATUS_SXS_MULTIPLE_DEACTIVATION', 3222601746: 'STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY', 3222601747: 'STATUS_SXS_PROCESS_TERMINATION_REQUESTED', 3222601748: 'STATUS_SXS_CORRUPT_ACTIVATION_STACK', 3222601749: 'STATUS_SXS_CORRUPTION', 3222601750: 'STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE', 3222601751: 'STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME', 3222601752: 'STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE', 3222601753: 'STATUS_SXS_IDENTITY_PARSE_ERROR', 3222601754: 'STATUS_SXS_COMPONENT_STORE_CORRUPT', 3222601755: 'STATUS_SXS_FILE_HASH_MISMATCH', 3222601756: 'STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT', 3222601757: 'STATUS_SXS_IDENTITIES_DIFFERENT', 3222601758: 'STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT', 3222601759: 'STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY', 3222601760: 'STATUS_ADVANCED_INSTALLER_FAILED', 3222601761: 'STATUS_XML_ENCODING_MISMATCH', 3222601762: 'STATUS_SXS_MANIFEST_TOO_BIG', 3222601763: 'STATUS_SXS_SETTING_NOT_REGISTERED', 3222601764: 'STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE', 3222601765: 'STATUS_SMI_PRIMITIVE_INSTALLER_FAILED', 3222601766: 'STATUS_GENERIC_COMMAND_FAILED', 3222601767: 'STATUS_SXS_FILE_HASH_MISSING', 3222863873: 'STATUS_TRANSACTIONAL_CONFLICT', 3222863874: 'STATUS_INVALID_TRANSACTION', 3222863875: 'STATUS_TRANSACTION_NOT_ACTIVE', 3222863876: 'STATUS_TM_INITIALIZATION_FAILED', 3222863877: 'STATUS_RM_NOT_ACTIVE', 3222863878: 'STATUS_RM_METADATA_CORRUPT', 3222863879: 'STATUS_TRANSACTION_NOT_JOINED', 3222863880: 'STATUS_DIRECTORY_NOT_RM', 3222863882: 'STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE', 3222863883: 'STATUS_LOG_RESIZE_INVALID_SIZE', 3222863884: 'STATUS_REMOTE_FILE_VERSION_MISMATCH', 3222863887: 'STATUS_CRM_PROTOCOL_ALREADY_EXISTS', 3222863888: 'STATUS_TRANSACTION_PROPAGATION_FAILED', 3222863889: 'STATUS_CRM_PROTOCOL_NOT_FOUND', 3222863890: 'STATUS_TRANSACTION_SUPERIOR_EXISTS', 3222863891: 'STATUS_TRANSACTION_REQUEST_NOT_VALID', 3222863892: 'STATUS_TRANSACTION_NOT_REQUESTED', 3222863893: 'STATUS_TRANSACTION_ALREADY_ABORTED', 3222863894: 'STATUS_TRANSACTION_ALREADY_COMMITTED', 3222863895: 'STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER', 3222863896: 'STATUS_CURRENT_TRANSACTION_NOT_VALID', 3222863897: 'STATUS_LOG_GROWTH_FAILED', 3222863905: 'STATUS_OBJECT_NO_LONGER_EXISTS', 3222863906: 'STATUS_STREAM_MINIVERSION_NOT_FOUND', 3222863907: 'STATUS_STREAM_MINIVERSION_NOT_VALID', 3222863908: 'STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION', 3222863909: 'STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT', 3222863910: 'STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS', 3222863912: 'STATUS_HANDLE_NO_LONGER_VALID', 3222863920: 'STATUS_LOG_CORRUPTION_DETECTED', 3222863922: 'STATUS_RM_DISCONNECTED', 3222863923: 'STATUS_ENLISTMENT_NOT_SUPERIOR', 3222863926: 'STATUS_FILE_IDENTITY_NOT_PERSISTENT', 3222863927: 'STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY', 3222863928: 'STATUS_CANT_CROSS_RM_BOUNDARY', 3222863929: 'STATUS_TXF_DIR_NOT_EMPTY', 3222863930: 'STATUS_INDOUBT_TRANSACTIONS_EXIST', 3222863931: 'STATUS_TM_VOLATILE', 3222863932: 'STATUS_ROLLBACK_TIMER_EXPIRED', 3222863933: 'STATUS_TXF_ATTRIBUTE_CORRUPT', 3222863934: 'STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION', 3222863935: 'STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED', 3222863936: 'STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE', 3222863939: 'STATUS_TRANSACTION_REQUIRED_PROMOTION', 3222863940: 'STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION', 3222863941: 'STATUS_TRANSACTIONS_NOT_FROZEN', 3222863942: 'STATUS_TRANSACTION_FREEZE_IN_PROGRESS', 3222863943: 'STATUS_NOT_SNAPSHOT_VOLUME', 3222863944: 'STATUS_NO_SAVEPOINT_WITH_OPEN_FILES', 3222863945: 'STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION', 3222863946: 'STATUS_TM_IDENTITY_MISMATCH', 3222863947: 'STATUS_FLOATED_SECTION', 3222863948: 'STATUS_CANNOT_ACCEPT_TRANSACTED_WORK', 3222863949: 'STATUS_CANNOT_ABORT_TRANSACTIONS', 3222863950: 'STATUS_TRANSACTION_NOT_FOUND', 3222863951: 'STATUS_RESOURCEMANAGER_NOT_FOUND', 3222863952: 'STATUS_ENLISTMENT_NOT_FOUND', 3222863953: 'STATUS_TRANSACTIONMANAGER_NOT_FOUND', 3222863954: 'STATUS_TRANSACTIONMANAGER_NOT_ONLINE', 3222863955: 'STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION', 3222863956: 'STATUS_TRANSACTION_NOT_ROOT', 3222863957: 'STATUS_TRANSACTION_OBJECT_EXPIRED', 3222863958: 'STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION', 3222863959: 'STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED', 3222863960: 'STATUS_TRANSACTION_RECORD_TOO_LONG', 3222863961: 'STATUS_NO_LINK_TRACKING_IN_TRANSACTION', 3222863962: 'STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION', 3222863963: 'STATUS_TRANSACTION_INTEGRITY_VIOLATED', 3222863968:'STATUS_EXPIRED_HANDLE', 3222863969: 'STATUS_TRANSACTION_NOT_ENLISTED', 3222929409: 'STATUS_LOG_SECTOR_INVALID', 3222929410: 'STATUS_LOG_SECTOR_PARITY_INVALID', 3222929411: 'STATUS_LOG_SECTOR_REMAPPED', 3222929412: 'STATUS_LOG_BLOCK_INCOMPLETE', 3222929413: 'STATUS_LOG_INVALID_RANGE', 3222929414: 'STATUS_LOG_BLOCKS_EXHAUSTED', 3222929415: 'STATUS_LOG_READ_CONTEXT_INVALID', 3222929416: 'STATUS_LOG_RESTART_INVALID', 3222929417: 'STATUS_LOG_BLOCK_VERSION', 3222929418: 'STATUS_LOG_BLOCK_INVALID', 3222929419: 'STATUS_LOG_READ_MODE_INVALID', 3222929421: 'STATUS_LOG_METADATA_CORRUPT', 3222929422: 'STATUS_LOG_METADATA_INVALID', 3222929423: 'STATUS_LOG_METADATA_INCONSISTENT', 3222929424: 'STATUS_LOG_RESERVATION_INVALID', 3222929425: 'STATUS_LOG_CANT_DELETE', 3222929426: 'STATUS_LOG_CONTAINER_LIMIT_EXCEEDED', 3222929427: 'STATUS_LOG_START_OF_LOG', 3222929428: 'STATUS_LOG_POLICY_ALREADY_INSTALLED', 3222929429: 'STATUS_LOG_POLICY_NOT_INSTALLED', 3222929430: 'STATUS_LOG_POLICY_INVALID', 3222929431: 'STATUS_LOG_POLICY_CONFLICT', 3222929432: 'STATUS_LOG_PINNED_ARCHIVE_TAIL', 3222929433: 'STATUS_LOG_RECORD_NONEXISTENT', 3222929434: 'STATUS_LOG_RECORDS_RESERVED_INVALID', 3222929435: 'STATUS_LOG_SPACE_RESERVED_INVALID', 3222929436: 'STATUS_LOG_TAIL_INVALID', 3222929437: 'STATUS_LOG_FULL', 3222929438: 'STATUS_LOG_MULTIPLEXED', 3222929439: 'STATUS_LOG_DEDICATED', 3222929440: 'STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS', 3222929441: 'STATUS_LOG_ARCHIVE_IN_PROGRESS', 3222929442: 'STATUS_LOG_EPHEMERAL', 3222929443: 'STATUS_LOG_NOT_ENOUGH_CONTAINERS', 3222929444: 'STATUS_LOG_CLIENT_ALREADY_REGISTERED', 3222929445: 'STATUS_LOG_CLIENT_NOT_REGISTERED', 3222929446: 'STATUS_LOG_FULL_HANDLER_IN_PROGRESS', 3222929447: 'STATUS_LOG_CONTAINER_READ_FAILED', 3222929448: 'STATUS_LOG_CONTAINER_WRITE_FAILED', 3222929449: 'STATUS_LOG_CONTAINER_OPEN_FAILED', 3222929450: 'STATUS_LOG_CONTAINER_STATE_INVALID', 3222929451: 'STATUS_LOG_STATE_INVALID', 3222929452: 'STATUS_LOG_PINNED', 3222929453: 'STATUS_LOG_METADATA_FLUSH_FAILED', 3222929454: 'STATUS_LOG_INCONSISTENT_SECURITY', 3222929455: 'STATUS_LOG_APPENDED_FLUSH_FAILED', 3222929456: 'STATUS_LOG_PINNED_RESERVATION', 3222995178: 'STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD', 3223060481: 'STATUS_FLT_NO_HANDLER_DEFINED', 3223060482: 'STATUS_FLT_CONTEXT_ALREADY_DEFINED', 3223060483: 'STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST', 3223060484: 'STATUS_FLT_DISALLOW_FAST_IO', 3223060485: 'STATUS_FLT_INVALID_NAME_REQUEST', 3223060486: 'STATUS_FLT_NOT_SAFE_TO_POST_OPERATION', 3223060487: 'STATUS_FLT_NOT_INITIALIZED', 3223060488: 'STATUS_FLT_FILTER_NOT_READY', 3223060489: 'STATUS_FLT_POST_OPERATION_CLEANUP', 3223060490: 'STATUS_FLT_INTERNAL_ERROR', 3223060491: 'STATUS_FLT_DELETING_OBJECT', 3223060492: 'STATUS_FLT_MUST_BE_NONPAGED_POOL', 3223060493: 'STATUS_FLT_DUPLICATE_ENTRY', 3223060494: 'STATUS_FLT_CBDQ_DISABLED', 3223060495: 'STATUS_FLT_DO_NOT_ATTACH', 3223060496: 'STATUS_FLT_DO_NOT_DETACH', 3223060497: 'STATUS_FLT_INSTANCE_ALTITUDE_COLLISION', 3223060498: 'STATUS_FLT_INSTANCE_NAME_COLLISION', 3223060499: 'STATUS_FLT_FILTER_NOT_FOUND', 3223060500: 'STATUS_FLT_VOLUME_NOT_FOUND', 3223060501: 'STATUS_FLT_INSTANCE_NOT_FOUND', 3223060502: 'STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND', 3223060503: 'STATUS_FLT_INVALID_CONTEXT_REGISTRATION', 3223060504: 'STATUS_FLT_NAME_CACHE_MISS', 3223060505: 'STATUS_FLT_NO_DEVICE_OBJECT', 3223060506: 'STATUS_FLT_VOLUME_ALREADY_MOUNTED', 3223060507: 'STATUS_FLT_ALREADY_ENLISTED', 3223060508: 'STATUS_FLT_CONTEXT_ALREADY_LINKED', 3223060512: 'STATUS_FLT_NO_WAITER_FOR_REPLY', 3223126017: 'STATUS_MONITOR_NO_DESCRIPTOR', 3223126018: 'STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT', 3223126019: 'STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM', 3223126020: 'STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK', 3223126021: 'STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED', 3223126022: 'STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK', 3223126023: 'STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK', 3223126024: 'STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA', 3223126025: 'STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK', 3223126026: 'STATUS_MONITOR_INVALID_MANUFACTURE_DATE', 3223191552: 'STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER', 3223191553: 'STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER', 3223191554: 'STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER', 3223191555: 'STATUS_GRAPHICS_ADAPTER_WAS_RESET', 3223191556: 'STATUS_GRAPHICS_INVALID_DRIVER_MODEL', 3223191557: 'STATUS_GRAPHICS_PRESENT_MODE_CHANGED', 3223191558: 'STATUS_GRAPHICS_PRESENT_OCCLUDED', 3223191559: 'STATUS_GRAPHICS_PRESENT_DENIED', 3223191560: 'STATUS_GRAPHICS_CANNOTCOLORCONVERT', 3223191563: 'STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED', 3223191564: 'STATUS_GRAPHICS_PRESENT_UNOCCLUDED', 3223191808: 'STATUS_GRAPHICS_NO_VIDEO_MEMORY', 3223191809: 'STATUS_GRAPHICS_CANT_LOCK_MEMORY', 3223191810: 'STATUS_GRAPHICS_ALLOCATION_BUSY', 3223191811: 'STATUS_GRAPHICS_TOO_MANY_REFERENCES', 3223191812: 'STATUS_GRAPHICS_TRY_AGAIN_LATER', 3223191813: 'STATUS_GRAPHICS_TRY_AGAIN_NOW', 3223191814: 'STATUS_GRAPHICS_ALLOCATION_INVALID', 3223191815: 'STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE', 3223191816: 'STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED', 3223191817: 'STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION', 3223191824: 'STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE', 3223191825: 'STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION', 3223191826: 'STATUS_GRAPHICS_ALLOCATION_CLOSED', 3223191827: 'STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE', 3223191828: 'STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE', 3223191829: 'STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE', 3223191830: 'STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST', 3223192064: 'STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE', 3223192320: 'STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY', 3223192321: 'STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED', 3223192322: 'STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED', 3223192323: 'STATUS_GRAPHICS_INVALID_VIDPN', 3223192324: 'STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE', 3223192325: 'STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET', 3223192326: 'STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED', 3223192328: 'STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET', 3223192329: 'STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET', 3223192330: 'STATUS_GRAPHICS_INVALID_FREQUENCY', 3223192331: 'STATUS_GRAPHICS_INVALID_ACTIVE_REGION', 3223192332: 'STATUS_GRAPHICS_INVALID_TOTAL_REGION', 3223192336: 'STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE', 3223192337: 'STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE', 3223192338: 'STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET', 3223192339: 'STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY', 3223192340: 'STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET', 3223192341: 'STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET', 3223192342: 'STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET',3223192343: 'STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET', 3223192344: 'STATUS_GRAPHICS_TARGET_ALREADY_IN_SET', 3223192345: 'STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH', 3223192346: 'STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY', 3223192347: 'STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET', 3223192348: 'STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE', 3223192349: 'STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET', 3223192351: 'STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET', 3223192352: 'STATUS_GRAPHICS_STALE_MODESET', 3223192353: 'STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET', 3223192354: 'STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE', 3223192355: 'STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN', 3223192356: 'STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE', 3223192357: 'STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION', 3223192358: 'STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES', 3223192359: 'STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY', 3223192360: 'STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE', 3223192361: 'STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET', 3223192362: 'STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET', 3223192363: 'STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR', 3223192364: 'STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET', 3223192365: 'STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET', 3223192366: 'STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE', 3223192367: 'STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE', 3223192368: 'STATUS_GRAPHICS_RESOURCES_NOT_RELATED', 3223192369: 'STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE', 3223192370: 'STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE', 3223192371: 'STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET', 3223192372: 'STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER', 3223192373: 'STATUS_GRAPHICS_NO_VIDPNMGR', 3223192374: 'STATUS_GRAPHICS_NO_ACTIVE_VIDPN', 3223192375: 'STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY', 3223192376: 'STATUS_GRAPHICS_MONITOR_NOT_CONNECTED', 3223192377: 'STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY', 3223192378: 'STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE', 3223192379: 'STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE', 3223192380: 'STATUS_GRAPHICS_INVALID_STRIDE', 3223192381: 'STATUS_GRAPHICS_INVALID_PIXELFORMAT', 3223192382: 'STATUS_GRAPHICS_INVALID_COLORBASIS', 3223192383: 'STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE', 3223192384: 'STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY', 3223192385: 'STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT', 3223192386: 'STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE', 3223192387: 'STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN', 3223192388: 'STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL', 3223192389: 'STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION', 3223192390: 'STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED', 3223192391: 'STATUS_GRAPHICS_INVALID_GAMMA_RAMP', 3223192392: 'STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED', 3223192393: 'STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED', 3223192394: 'STATUS_GRAPHICS_MODE_NOT_IN_MODESET', 3223192397: 'STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON', 3223192398: 'STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE', 3223192399: 'STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE', 3223192400: 'STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS', 3223192402: 'STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING', 3223192403: 'STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED', 3223192404: 'STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS', 3223192405: 'STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT', 3223192406: 'STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM', 3223192407: 'STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN', 3223192408: 'STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT',3223192409: 'STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED', 3223192410: 'STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION', 3223192411: 'STATUS_GRAPHICS_INVALID_CLIENT_TYPE', 3223192412: 'STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET', 3223192576: 'STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED', 3223192577: 'STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED', 3223192624: 'STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER', 3223192625: 'STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED', 3223192626: 'STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED', 3223192627: 'STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY', 3223192628: 'STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED', 3223192629: 'STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON', 3223192630: 'STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE', 3223192632: 'STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER', 3223192635: 'STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED', 3223192832: 'STATUS_GRAPHICS_OPM_NOT_SUPPORTED', 3223192833: 'STATUS_GRAPHICS_COPP_NOT_SUPPORTED', 3223192834: 'STATUS_GRAPHICS_UAB_NOT_SUPPORTED', 3223192835: 'STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS', 3223192836: 'STATUS_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL', 3223192837: 'STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST', 3223192838: 'STATUS_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME', 3223192839: 'STATUS_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP', 3223192840: 'STATUS_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED', 3223192842: 'STATUS_GRAPHICS_OPM_INVALID_POINTER', 3223192843: 'STATUS_GRAPHICS_OPM_INTERNAL_ERROR', 3223192844: 'STATUS_GRAPHICS_OPM_INVALID_HANDLE', 3223192845: 'STATUS_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE', 3223192846: 'STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH', 3223192847: 'STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED', 3223192848: 'STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED', 3223192849: 'STATUS_GRAPHICS_PVP_HFS_FAILED', 3223192850: 'STATUS_GRAPHICS_OPM_INVALID_SRM', 3223192851: 'STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP', 3223192852: 'STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP', 3223192853: 'STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA', 3223192854: 'STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET', 3223192855: 'STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH', 3223192856: 'STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE', 3223192858: 'STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS', 3223192859: 'STATUS_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS', 3223192860: 'STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS', 3223192861: 'STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST', 3223192862: 'STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR', 3223192863: 'STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS', 3223192864: 'STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED', 3223192865: 'STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST', 3223192960: 'STATUS_GRAPHICS_I2C_NOT_SUPPORTED', 3223192961: 'STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST', 3223192962: 'STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA', 3223192963: 'STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA', 3223192964: 'STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED', 3223192965: 'STATUS_GRAPHICS_DDCCI_INVALID_DATA', 3223192966: 'STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE', 3223192967: 'STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING', 3223192968: 'STATUS_GRAPHICS_MCA_INTERNAL_ERROR', 3223192969: 'STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND', 3223192970: 'STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH', 3223192971: 'STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM', 3223192972: 'STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE', 3223192973: 'STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS', 3223193056: 'STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED', 3223193057: 'STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME', 3223193058: 'STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP', 3223193059: 'STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED', 3223193060: 'STATUS_GRAPHICS_INVALID_POINTER', 3223193061: 'STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE', 3223193062: 'STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL', 3223193063: 'STATUS_GRAPHICS_INTERNAL_ERROR', 3223193064: 'STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS', 3223388160: 'STATUS_FVE_LOCKED_VOLUME', 3223388161: 'STATUS_FVE_NOT_ENCRYPTED', 3223388162: 'STATUS_FVE_BAD_INFORMATION', 3223388163: 'STATUS_FVE_TOO_SMALL', 3223388164: 'STATUS_FVE_FAILED_WRONG_FS', 3223388165: 'STATUS_FVE_FAILED_BAD_FS', 3223388166: 'STATUS_FVE_FS_NOT_EXTENDED', 3223388167: 'STATUS_FVE_FS_MOUNTED', 3223388168: 'STATUS_FVE_NO_LICENSE', 3223388169: 'STATUS_FVE_ACTION_NOT_ALLOWED', 3223388170: 'STATUS_FVE_BAD_DATA', 3223388171: 'STATUS_FVE_VOLUME_NOT_BOUND', 3223388172: 'STATUS_FVE_NOT_DATA_VOLUME', 3223388173: 'STATUS_FVE_CONV_READ_ERROR', 3223388174: 'STATUS_FVE_CONV_WRITE_ERROR', 3223388175: 'STATUS_FVE_OVERLAPPED_UPDATE', 3223388176: 'STATUS_FVE_FAILED_SECTOR_SIZE', 3223388177: 'STATUS_FVE_FAILED_AUTHENTICATION', 3223388178: 'STATUS_FVE_NOT_OS_VOLUME', 3223388179: 'STATUS_FVE_KEYFILE_NOT_FOUND', 3223388180: 'STATUS_FVE_KEYFILE_INVALID', 3223388181: 'STATUS_FVE_KEYFILE_NO_VMK', 3223388182: 'STATUS_FVE_TPM_DISABLED', 3223388183: 'STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO', 3223388184: 'STATUS_FVE_TPM_INVALID_PCR', 3223388185: 'STATUS_FVE_TPM_NO_VMK', 3223388186: 'STATUS_FVE_PIN_INVALID', 3223388187: 'STATUS_FVE_AUTH_INVALID_APPLICATION', 3223388188: 'STATUS_FVE_AUTH_INVALID_CONFIG', 3223388189: 'STATUS_FVE_DEBUGGER_ENABLED', 3223388190: 'STATUS_FVE_DRY_RUN_FAILED', 3223388191: 'STATUS_FVE_BAD_METADATA_POINTER', 3223388192: 'STATUS_FVE_OLD_METADATA_COPY', 3223388193: 'STATUS_FVE_REBOOT_REQUIRED', 3223388194: 'STATUS_FVE_RAW_ACCESS', 3223388195: 'STATUS_FVE_RAW_BLOCKED', 3223388198: 'STATUS_FVE_NO_FEATURE_LICENSE', 3223388199: 'STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED', 3223388200: 'STATUS_FVE_CONV_RECOVERY_FAILED', 3223388201: 'STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG', 3223388208: 'STATUS_FVE_VOLUME_TOO_SMALL', 3223453697: 'STATUS_FWP_CALLOUT_NOT_FOUND', 3223453698: 'STATUS_FWP_CONDITION_NOT_FOUND', 3223453699: 'STATUS_FWP_FILTER_NOT_FOUND', 3223453700: 'STATUS_FWP_LAYER_NOT_FOUND', 3223453701: 'STATUS_FWP_PROVIDER_NOT_FOUND', 3223453702: 'STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND', 3223453703: 'STATUS_FWP_SUBLAYER_NOT_FOUND', 3223453704: 'STATUS_FWP_NOT_FOUND', 3223453705: 'STATUS_FWP_ALREADY_EXISTS', 3223453706: 'STATUS_FWP_IN_USE', 3223453707: 'STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS', 3223453708: 'STATUS_FWP_WRONG_SESSION', 3223453709: 'STATUS_FWP_NO_TXN_IN_PROGRESS', 3223453710: 'STATUS_FWP_TXN_IN_PROGRESS', 3223453711: 'STATUS_FWP_TXN_ABORTED', 3223453712: 'STATUS_FWP_SESSION_ABORTED', 3223453713: 'STATUS_FWP_INCOMPATIBLE_TXN', 3223453714: 'STATUS_FWP_TIMEOUT', 3223453715: 'STATUS_FWP_NET_EVENTS_DISABLED', 3223453716: 'STATUS_FWP_INCOMPATIBLE_LAYER', 3223453717: 'STATUS_FWP_KM_CLIENTS_ONLY', 3223453718: 'STATUS_FWP_LIFETIME_MISMATCH', 3223453719: 'STATUS_FWP_BUILTIN_OBJECT', 3223453720: 'STATUS_FWP_TOO_MANY_CALLOUTS', 3223453721: 'STATUS_FWP_NOTIFICATION_DROPPED', 3223453722: 'STATUS_FWP_TRAFFIC_MISMATCH', 3223453723: 'STATUS_FWP_INCOMPATIBLE_SA_STATE', 3223453724: 'STATUS_FWP_NULL_POINTER', 3223453725: 'STATUS_FWP_INVALID_ENUMERATOR', 3223453726: 'STATUS_FWP_INVALID_FLAGS', 3223453727: 'STATUS_FWP_INVALID_NET_MASK', 3223453728: 'STATUS_FWP_INVALID_RANGE', 3223453729: 'STATUS_FWP_INVALID_INTERVAL', 3223453730: 'STATUS_FWP_ZERO_LENGTH_ARRAY',3223453731: 'STATUS_FWP_NULL_DISPLAY_NAME', 3223453732: 'STATUS_FWP_INVALID_ACTION_TYPE', 3223453733: 'STATUS_FWP_INVALID_WEIGHT', 3223453734: 'STATUS_FWP_MATCH_TYPE_MISMATCH', 3223453735: 'STATUS_FWP_TYPE_MISMATCH', 3223453736: 'STATUS_FWP_OUT_OF_BOUNDS', 3223453737: 'STATUS_FWP_RESERVED', 3223453738: 'STATUS_FWP_DUPLICATE_CONDITION', 3223453739: 'STATUS_FWP_DUPLICATE_KEYMOD', 3223453740: 'STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER', 3223453741: 'STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER', 3223453742: 'STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER', 3223453743: 'STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT',3223453744: 'STATUS_FWP_INCOMPATIBLE_AUTH_METHOD', 3223453745: 'STATUS_FWP_INCOMPATIBLE_DH_GROUP', 3223453746: 'STATUS_FWP_EM_NOT_SUPPORTED', 3223453747:'STATUS_FWP_NEVER_MATCH', 3223453748: 'STATUS_FWP_PROVIDER_CONTEXT_MISMATCH', 3223453749: 'STATUS_FWP_INVALID_PARAMETER', 3223453750: 'STATUS_FWP_TOO_MANY_SUBLAYERS', 3223453751: 'STATUS_FWP_CALLOUT_NOTIFICATION_FAILED', 3223453752: 'STATUS_FWP_INCOMPATIBLE_AUTH_CONFIG', 3223453753: 'STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG', 3223453756: 'STATUS_FWP_DUPLICATE_AUTH_METHOD', 3223453952: 'STATUS_FWP_TCPIP_NOT_READY', 3223453953: 'STATUS_FWP_INJECT_HANDLE_CLOSING', 3223453954: 'STATUS_FWP_INJECT_HANDLE_STALE', 3223453955: 'STATUS_FWP_CANNOT_PEND', 3223519234: 'STATUS_NDIS_CLOSING', 3223519236: 'STATUS_NDIS_BAD_VERSION', 3223519237: 'STATUS_NDIS_BAD_CHARACTERISTICS', 3223519238: 'STATUS_NDIS_ADAPTER_NOT_FOUND', 3223519239: 'STATUS_NDIS_OPEN_FAILED', 3223519240: 'STATUS_NDIS_DEVICE_FAILED', 3223519241: 'STATUS_NDIS_MULTICAST_FULL', 3223519242: 'STATUS_NDIS_MULTICAST_EXISTS', 3223519243: 'STATUS_NDIS_MULTICAST_NOT_FOUND', 3223519244: 'STATUS_NDIS_REQUEST_ABORTED', 3223519245: 'STATUS_NDIS_RESET_IN_PROGRESS', 3223519247: 'STATUS_NDIS_INVALID_PACKET', 3223519248: 'STATUS_NDIS_INVALID_DEVICE_REQUEST', 3223519249: 'STATUS_NDIS_ADAPTER_NOT_READY', 3223519252: 'STATUS_NDIS_INVALID_LENGTH', 3223519253: 'STATUS_NDIS_INVALID_DATA', 3223519254: 'STATUS_NDIS_BUFFER_TOO_SHORT', 3223519255: 'STATUS_NDIS_INVALID_OID', 3223519256: 'STATUS_NDIS_ADAPTER_REMOVED', 3223519257: 'STATUS_NDIS_UNSUPPORTED_MEDIA', 3223519258: 'STATUS_NDIS_GROUP_ADDRESS_IN_USE', 3223519259: 'STATUS_NDIS_FILE_NOT_FOUND', 3223519260: 'STATUS_NDIS_ERROR_READING_FILE',3223519261: 'STATUS_NDIS_ALREADY_MAPPED', 3223519262: 'STATUS_NDIS_RESOURCE_CONFLICT', 3223519263: 'STATUS_NDIS_MEDIA_DISCONNECTED', 3223519266: 'STATUS_NDIS_INVALID_ADDRESS', 3223519274: 'STATUS_NDIS_PAUSED', 3223519275: 'STATUS_NDIS_INTERFACE_NOT_FOUND', 3223519276: 'STATUS_NDIS_UNSUPPORTED_REVISION', 3223519277: 'STATUS_NDIS_INVALID_PORT', 3223519278: 'STATUS_NDIS_INVALID_PORT_STATE', 3223519279: 'STATUS_NDIS_LOW_POWER_STATE', 3223519419: 'STATUS_NDIS_NOT_SUPPORTED', 3223523343: 'STATUS_NDIS_OFFLOAD_POLICY', 3223523346: 'STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED', 3223523347: 'STATUS_NDIS_OFFLOAD_PATH_REJECTED', 3223527424: 'STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED', 3223527425: 'STATUS_NDIS_DOT11_MEDIA_IN_USE', 3223527426: 'STATUS_NDIS_DOT11_POWER_STATE_INVALID', 3223527427: 'STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL', 3223527428: 'STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL', 3224764417: 'STATUS_IPSEC_BAD_SPI', 3224764418: 'STATUS_IPSEC_SA_LIFETIME_EXPIRED', 3224764419: 'STATUS_IPSEC_WRONG_SA', 3224764420: 'STATUS_IPSEC_REPLAY_CHECK_FAILED', 3224764421: 'STATUS_IPSEC_INVALID_PACKET', 3224764422: 'STATUS_IPSEC_INTEGRITY_CHECK_FAILED', 3224764423: 'STATUS_IPSEC_CLEAR_TEXT_DROP', 3224764424: 'STATUS_IPSEC_AUTH_FIREWALL_DROP', 3224764425: 'STATUS_IPSEC_THROTTLE_DROP', 3224797184: 'STATUS_IPSEC_DOSP_BLOCK', 3224797185: 'STATUS_IPSEC_DOSP_RECEIVED_MULTICAST', 3224797186: 'STATUS_IPSEC_DOSP_INVALID_PACKET', 3224797187: 'STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED', 3224797188: 'STATUS_IPSEC_DOSP_MAX_ENTRIES', 3224797189: 'STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED', 3224797190: 'STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES', 3224895579: 'STATUS_VOLMGR_MIRROR_NOT_SUPPORTED', 3224895580: 'STATUS_VOLMGR_RAID5_NOT_SUPPORTED', 3225026580: 'STATUS_VIRTDISK_PROVIDER_NOT_FOUND', 3225026581: 'STATUS_VIRTDISK_NOT_VIRTUAL_DISK', 3225026582: 'STATUS_VHD_PARENT_VHD_ACCESS_DENIED', 3225026583: 'STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH', 3225026584: 'STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED', 3225026585: 'STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT'}

    def makeArgVals(self, uc, em, esp, numParams):
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

        pVals[1] = getLookUpVal(pVals[1], self.NTSTATUSReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtTerminateProcess", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtAllocateVirtualMemory(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 6) 
        pTypes = ['HANDLE', 'PVOID', 'ULONG_PTR', 'PSIZE_T', 'ULONG', 'ULONG']
        pNames = ['ProcessHandle', '*BaseAddress', 'ZeroBits', 'RegionSize', 'AllocationType', 'Protect']
        flProtectReverseLookUp = {16: 'PAGE_EXECUTE', 32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 1: 'PAGE_NOACCESS', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 1073741824: 'PAGE_TARGETS_NO_UPDATE', 256: 'PAGE_GUARD', 512: 'PAGE_NOCACHE', 1024: 'PAGE_WRITECOMBINE'}
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

        pVals[4] = getLookUpVal(pVals[4], MemReverseLookUp)
        pVals[5] = getLookUpVal(pVals[5], flProtectReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[4,5])

        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
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
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
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
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
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
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
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
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
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
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ["NtCreateThreadEx", hex(callAddr), retValStr, 'NTSTATUS', pVals, pTypes, pNames, False]

        return logged_calls

    def NtTerminateThread(self, uc: Uc, eip, esp, callAddr, em):
        pVals = self.makeArgVals(uc, em, esp, 2)
        pTypes = ['HANDLE', 'NTSTATUS']
        pNames = ['ThreadHandle', 'ExitStatus']

        if pVals[0] in HandlesDict:
            HandlesDict.pop(pVals[0])

        pVals[1] = getLookUpVal(pVals[1], self.NTSTATUSReverseLookUp)

        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip=[1])

        retVal = 0
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
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
        retValStr = getLookUpVal(retVal, self.NTSTATUSReverseLookUp)
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
        self.processDict = {4: struct_PROCESSENTRY32(0, 10, 0, 0, 'System'),
                            2688: struct_PROCESSENTRY32(2688, 16, 0, 4, 'explorer.exe'),
                            9172: struct_PROCESSENTRY32(9172, 10, 2688, 10, 'calc.exe'),
                            8280: struct_PROCESSENTRY32(8280, 50, 2688, 16, 'chrome.exe'),
                            11676: struct_PROCESSENTRY32(11676, 78, 2688, 15, 'notepad.exe'),
                            8768: struct_PROCESSENTRY32(8768, 20, 2688, 4, 'firefox.exe')}
        self.threadDict: dict[int, struct_THREADENTRY32] = {}
        self.moduleList: list[struct_MODULEENTRY32] = []
        if fakeThreads:
            self.fakeThreads()
        # if fakeModules: # Need To Fix Modules Thing
            # self.fakeModules()
        self.resetOffsets()

    def fakeThreads(self):
        for k, v in self.processDict.items():  # Create Fake Threads
            for i in range(v.cntThreads):
                self.threadDict.update(
                    {self.baseThreadID: struct_THREADENTRY32(self.baseThreadID, v.th32ProcessID, v.pcPriClassBase)})
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
    #                     struct_MODULEENTRY32(v.th32ProcessID, allDllsDict[selectedDLL], allDllsSizeDict[selectedDLL],
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
    # REG_DWORD_LITTLE_ENDIAN	= 4  # A 32-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_DWORD in the Windows header files.
    REG_DWORD_BIG_ENDIAN = 5  # A 32-bit number in big-endian format. Some UNIX systems support big-endian architectures.
    REG_EXPAND_SZ = 2  # A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%"). It will be a Unicode or ANSI string depending on whether you use the Unicode or ANSI functions. To expand the environment variable references, use the ExpandEnvironmentStrings function.
    REG_LINK = 6  # A null-terminated Unicode string that contains the target path of a symbolic link that was created by calling the RegCreateKeyEx function with REG_OPTION_CREATE_LINK.
    REG_MULTI_SZ = 7  # A sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: String1\0String2\0String3\0LastString\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string.
    REG_NONE = 0  # No defined value type.
    REG_QWORD = 11	# A 64-bit number.
    # REG_QWORD_LITTLE_ENDIAN	= 11  # A 64-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_QWORD in the Windows header files.
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
        self.parentKey = ''
        if parentKeyPath != '':
            for key, val in RegistryKeys.items():
                if key == parentKeyPath:
                    self.parentKey = val.name
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
            value = KeyValue(RegValueTypes.REG_SZ,data='(SHAREM Default Value)',valueName=valueName)
            return value

    def deleteValue(self, valueName: str = '(Default)'):
        if valueName in self.values:
            # print(f'Value: {self.values[valueName].name} deleted')
            return self.values.pop(valueName)

    def printInfo(self):
        print(f'Name: {self.name}')
        print(f'Path: {self.path}')
        print(f'Handle: {hex(self.handle.value)}')
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
        print('Registry Tree')
        for key, value in RegKey.PreDefinedKeys.items():
            if value in RegistryKeys:
                rKey: RegKey = RegistryKeys[value]
                rKey.printTreeRecursive()
        print('\n')
    
    def printTreeRecursive(self, level=0):
        if level == 0:
            print(self.name)
        else:
            print(('  ' * level) + '└─╴' + self.name)
        for sKey, sVal in self.childKeys.items():
            sVal.printTreeRecursive(level+1)
            
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

def getStackVal(uc, em, esp, loc):
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


def makeArgVals(uc, em, esp, numParams):
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

def findStringsParms(uc, pTypes, pVals, skip):
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

def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    if c == 0x0: ret = "[NULL]"  # Option for NULL String

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret

def read_unicode(uc, address):
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

def read_unicode_extended(uc, address): # Able to read more utf-16 chars
    ret = ""
    mem = uc.mem_read(address, 2)[::-1]
    read_bytes = 2

    unicodeString = str(hex(mem[0])) + str(hex(mem[1])[2::])
    unicodeInt = int(unicodeString, 0)

    if unicodeInt == 0x0000: ret="NULL" # Option for NULL String

    while unicodeInt != 0x0000:
        ret += chr(unicodeInt)
        mem = uc.mem_read(address + read_bytes, 2)[::-1]
        unicodeString = str(hex(mem[0])) + str(hex(mem[1])[2::])
        unicodeInt = int(unicodeString, 0)
        read_bytes += 2

    return ret

def buildPtrString(pointer, val):
    return hex(pointer) + " -> " + hex(val)

def getPointerVal(uc, pointer):
    val = uc.mem_read(pointer, 4)
    return unpack('<I', val)[0]

def getLookUpVal(search, dictionary: dict):
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