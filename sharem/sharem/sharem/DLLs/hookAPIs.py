from unicorn.x86_const import *
from struct import pack, unpack
from ..modules import allDllsDict
from ..helper.emuHelpers import *
import sys
import traceback

FakeProcess=0xbadd0000
ProcessCreationReverseLookUp = {16777216: 'CREATE_BREAKAWAY_FROM_JOB', 67108864: 'CREATE_DEFAULT_ERROR_MODE', 16: 'CREATE_NEW_CONSOLE', 512: 'CREATE_NEW_PROCESS_GROUP', 134217728: 'CREATE_NO_WINDOW', 262144: 'CREATE_PROTECTED_PROCESS', 33554432: 'CREATE_PRESERVE_CODE_AUTHZ_LEVEL', 4194304: 'CREATE_SECURE_PROCESS', 2048: 'CREATE_SEPARATE_WOW_VDM', 4096: 'CREATE_SHARED_WOW_VDM', 4: 'CREATE_SUSPENDED', 1024: 'CREATE_UNICODE_ENVIRONMENT', 2: 'DEBUG_ONLY_THIS_PROCESS', 1: 'DEBUG_PROCESS', 8: 'DETACHED_PROCESS', 524288: 'EXTENDED_STARTUPINFO_PRESENT', 65536: 'INHERIT_PARENT_AFFINITY'}
MemLookUp = {'MEM_COMMIT | MEM_RESERVE':'0x3000', 'MEM_COMMIT': '0x1000', 'MEM_FREE': '0x10000', 'MEM_RESERVE': '0x2000', 'MEM_IMAGE': '0x1000000', 'MEM_MAPPED': '0x40000', 'MEM_PRIVATE': '0x20000', 'PAGE_EXECUTE': '0x10', 'PAGE_EXECUTE_READ': '0x20', 'PAGE_EXECUTE_READWRITE': '0x40', 'PAGE_EXECUTE_WRITECOPY': '0x80', 'PAGE_NOACCESS': '0x01', 'PAGE_READONLY': '0x02', 'PAGE_READWRITE': '0x04', 'PAGE_TARGETS_INVALID': '0x40000000', 'PAGE_TARGETS_NO_UPDATE': '0x40000000'}
MemReverseLookUp = {0x3000:'MEM_COMMIT | MEM_RESERVE', 4096: 'MEM_COMMIT', 65536: 'MEM_FREE', 8192: 'MEM_RESERVE', 16777216: 'MEM_IMAGE', 262144: 'MEM_MAPPED', 131072: 'MEM_PRIVATE', 16: 'PAGE_EXECUTE', 32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 1: 'PAGE_NOACCESS', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 1073741824: 'PAGE_TARGETS_NO_UPDATE'}
availMem = 0x25000000

class CustomWinAPIs():
    def GetProcAddress(self, uc, eip, esp, export_dict, callAddr, em):
        arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        arg1 = unpack('<I', arg1)[0]
        arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 4)
        arg2 = unpack('<I', arg2)[0]
        arg2 = read_string(uc, arg2)

        retVal = 0

        for api in export_dict:
            if export_dict[api][0] == arg2:
                retVal = int(api, 16)

        # print("Using custom API function...")

        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = (
        "GetProcAddress", hex(callAddr), hex(retVal), 'FARPROC', [hex(arg1), arg2], ['HMODULE', 'LPCSTR'],
        ['hModule', 'lpProcName'], False)

        cleanBytes = 8

        return logged_calls, cleanBytes

    def GetProcedureAddress(self, uc, eip, esp, export_dict, callAddr, em):
        arg1 = uc.mem_read(esp + 4, 4)
        arg2 = uc.mem_read(esp + 8, 4)
        arg2 = unpack('<I', arg2)[0]
        arg2 = read_string(uc, arg2)
        arg3 = uc.mem_read(esp + 12, 4)
        arg4 = uc.mem_read(esp + 16, 4)

        retVal = 0

        for api in export_dict:
            if export_dict[api][0] == arg2:
                retVal = int(api, 16)

        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = (
        "LdrGetProcedureAddress", hex(callAddr), hex(retVal), 'FARPROC', [hex(arg1), arg2], ['HMODULE', 'LPCSTR'],
        ['hModule', 'lpProcName'], False)

        cleanBytes = 8

        return logged_calls, cleanBytes

    def LoadLibraryA(self, uc, eip, esp, export_dict, callAddr, em):
        arg1 = uc.mem_read(esp + 4, 4)
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
                arg1L = arg1.lower()
                retVal = allDllsDict[arg1L]
            except:
                print("\tError: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
                print(hex(eip), (len(arg1)))
                retVal = 0

        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = (
        "LoadLibraryA", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1], ['LPCTSTR'], ['lpLibFileName'], False)

        cleanBytes = 4
        return logged_calls, cleanBytes

    def LoadLibraryW(self, uc, eip, esp, export_dict, callAddr, em):
        # print("Using custom function...")
        arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        arg1 = unpack('<I', arg1)[0]
        arg1 = read_string(uc, arg1)

        # Return base address of passed library
        try:
            retVal = allDllsDict[arg1]
        except:
            print("Error: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
            retVal = 0

        uc.reg_write(UC_X86_REG_EAX, retVal)
        # ("FuncName", hex(callAddr), hex(retVal), 'returnType', [paramValues], [paramTypes], [paramNames], False)
        logged_calls = (
        "LoadLibraryW", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1], ['LPCTSTR'], ['lpLibFileName'], False)

        cleanBytes = 4
        return logged_calls, cleanBytes

    def LoadLibraryExW(self, uc, eip, esp, export_dict, callAddr, em):
        # print("Using custom function...")
        arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        arg1 = unpack('<I', arg1)[0]
        arg1 = read_string(uc, arg1)
        arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 4)
        arg3 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 12, 4)

        # Return base address of passed library
        try:
            retVal = allDllsDict[arg1]
        except:
            print("Error: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
            retVal = 0

        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = (
        "LoadLibraryExW", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1, arg2, arg3], ['LPCTSTR', 'HANDLE', 'DWORD'],
        ['lpLibFileName', 'hFile', 'dwFlags'], False)

        cleanBytes = 12
        return logged_calls, cleanBytes

    def HeapCreate2(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE HeapCreate([in] DWORD  flOptions,[in] SIZE_T dwInitialSize,[in] SIZE_T dwMaximumSize);
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['DWORD', 'SIZE_T', 'SIZE_T']
        pNames = ['flOptions', 'dwInitialSize', 'dwMaximumSize']
        flOptionsReverseLookUp = {0x00040000: 'HEAP_CREATE_ENABLE_EXECUTE', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                  0x00000001: 'HEAP_NO_SERIALIZE'}

        # Round up to next page (4096)
        pVals[1] = ((pVals[1] // 4096) + 1) * 4096
        pVals[2] = ((pVals[2] // 4096) + 1) * 4096

        search = pVals[0]
        if search in flOptionsReverseLookUp:
            pVals[0] = flOptionsReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = FakeProcess  # Figure out how to return HANDLE
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapCreate", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def HeapAlloc2(self, uc, eip, esp, export_dict, callAddr, em):
        # DECLSPEC_ALLOCATOR LPVOID HeapAlloc([in] HANDLE hHeap, [in] DWORD  dwFlags, [in] SIZE_T dwBytes)
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['HANDLE', 'DWORD', 'SIZE_T']
        pNames = ['hHeap', 'dwFlags', 'dwBytes']
        dwFlagsReverseLookUp = {0x00000008: 'HEAP_ZERO_MEMORY', 0x00000004: 'HEAP_GENERATE_EXCEPTIONS',
                                0x00000001: 'HEAP_NO_SERIALIZE'}

        search = pVals[1]
        if search in dwFlagsReverseLookUp:
            pVals[1] = dwFlagsReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x20  # Return pointer to allocated memory block
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("HeapAlloc", hex(callAddr), (retValStr), 'PTR', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualAlloc(self, uc, eip, esp, export_dict, callAddr, em):
        global availMem

        lpAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        lpAddress = unpack('<I', lpAddress)[0]
        dwSize = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 4)
        dwSize = unpack('<I', dwSize)[0]
        flAllocationType = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 12, 4)
        flAllocationType = unpack('<I', flAllocationType)[0]
        flProtect = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 16, 4)
        flProtect = unpack('<I', flProtect)[0]

        # Round up to next page (4096)
        dwSize = ((dwSize // 4096) + 1) * 4096

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
            flAllocationType = MemReverseLookUp[flAllocationType]
        else:
            flAllocationType = hex(flAllocationType)

        if flProtect in MemReverseLookUp:
            flProtect = MemReverseLookUp[flProtect]
        else:
            flProtect = hex(flProtect)

        logged_calls = ("VirtualAlloc", hex(callAddr), hex(retVal), 'INT',
                        [hex(lpAddress), hex(dwSize), (flAllocationType), (flProtect)],
                        ['LPVOID', 'SIZE_T', 'DWORD', 'DWORD'],
                        ['lpAddress', 'dwSize', 'flAllocationType', 'flProtect'], False)
        cleanBytes = 16

        return logged_calls, cleanBytes

    def ExitProcess(self, uc, eip, esp, export_dict, callAddr, em):
        # print("Using custom function...")
        uExitCode = uc.mem_read(esp + 4, 4)
        uExitCode = unpack('<I', uExitCode)[0]

        cleanBytes = 4
        logged_calls = ("ExitProcess", hex(callAddr), 'None', '', [uExitCode], ['UINT'], ['uExitCode'], False)
        return logged_calls, cleanBytes

    def CreateFileA(self, uc, eip, esp, export_dict, callAddr, em):
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
        lpFileName = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        lpFileName = unpack('<I', lpFileName)[0]
        lpFileName = read_string(uc, lpFileName)

        dwDesiredAccess = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 4)
        dwDesiredAccess = unpack('<I', dwDesiredAccess)[0]
        dwShareMode = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 12, 4)
        dwShareMode = unpack('<I', dwShareMode)[0]
        lpSecurityAttributes = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 16, 4)
        lpSecurityAttributes = unpack('<I', lpSecurityAttributes)[0]
        dwCreationDistribution = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 20, 4)
        dwCreationDistribution = unpack('<I', dwCreationDistribution)[0]
        dwFlagsAndAttributes = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 24, 4)
        dwFlagsAndAttributes = unpack('<I', dwFlagsAndAttributes)[0]
        hTemplateFile = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 28, 4)
        hTemplateFile = unpack('<I', hTemplateFile)[0]

        retVal = FakeProcess
        uc.reg_write(UC_X86_REG_EAX, retVal)

        createDispoReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING', 3: 'OPEN_EXISTING'}
        dwShareReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE'}
        dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE',
                                 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
        if dwCreationDistribution in createDispoReverseLookUp:
            dwCreationDistribution = createDispoReverseLookUp[dwCreationDistribution]
        else:
            dwCreationDistribution = hex(dwCreationDistribution)
        if dwShareMode in dwShareReverseLookUp:
            dwShareMode = dwShareReverseLookUp[dwShareMode]
        else:
            dwShareMode = hex(dwShareMode)
        if dwDesiredAccess in dwAccessReverseLookUp:
            dwDesiredAccess = dwAccessReverseLookUp[dwDesiredAccess]
        else:
            dwDesiredAccess = hex(dwDesiredAccess)
        cleanBytes = 28
        logged_calls = ("CreateFileA", hex(callAddr), hex(retVal), 'HANDLE',
                        [hex(lpFileName), dwDesiredAccess, dwShareMode, hex(lpSecurityAttributes),
                         dwCreationDistribution, hex(dwFlagsAndAttributes), hex(hTemplateFile)],
                        ["LPCSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD", "HANDLE"],
                        ["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes",
                         "dwCreationDistribution", "dwFlagsAndAttributes", "hTemplateFile"], False)

        return logged_calls, cleanBytes

    def CreateFileW(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateFileW([in] LPCWSTR lpFileName,[in] DWORD dwDesiredAccess,[in] DWORD dwShareMode,[in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,[in] DWORD dwCreationDisposition,[in] DWORD dwFlagsAndAttributes,[in, optional] HANDLE hTemplateFile);
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['LPCWSTR', 'lpFileName', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'HANDLE']
        pNames = ["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDistribution",
                  "dwFlagsAndAttributes", "hTemplateFile"]
        dwDesiredAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE',
                                        536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL',
                                        0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
        dwShareModeReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE',
                                    4: 'FILE_SHARE_DELETE'}
        dwCreationDistributionReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING',
                                               3: 'OPEN_EXISTING', 5: 'TRUNCATE_EXISTING'}
        dwFlagsAndAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 16384: 'FILE_ATTRIBUTE_ENCRYPTED',
                                             2: 'FILE_ATTRIBUTE_HIDDEN', 128: 'FILE_ATTRIBUTE_NORMAL',
                                             4096: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY',
                                             4: 'FILE_ATTRIBUTE_SYSTEM', 256: 'FILE_ATTRIBUTE_TEMPORARY',
                                             33554432: 'FILE_FLAG_BACKUP_SEMANTICS',
                                             67108864: 'FILE_FLAG_DELETE_ON_CLOSE', 536870912: 'FILE_FLAG_NO_BUFFERING',
                                             1048576: 'FILE_FLAG_OPEN_NO_RECALL',
                                             2097152: 'FILE_FLAG_OPEN_REPARSE_POINT',
                                             1073741824: 'FILE_FLAG_OVERLAPPED', 16777216: 'FILE_FLAG_POSIX_SEMANTICS',
                                             268435456: 'FILE_FLAG_RANDOM_ACCESS', 8388608: 'FILE_FLAG_SESSION_AWARE',
                                             134217728: 'FILE_FLAG_SEQUENTIAL_SCAN',
                                             2147483648: 'FILE_FLAG_WRITE_THROUGH'}

        search = pVals[1]
        if search in dwDesiredAccessReverseLookUp:
            pVals[1] = dwDesiredAccessReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])
        search = pVals[2]
        if search in dwShareModeReverseLookUp:
            pVals[2] = dwShareModeReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])
        search = pVals[4]
        if search in dwCreationDistributionReverseLookUp:
            pVals[4] = dwCreationDistributionReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        search = pVals[5]
        if search in dwFlagsAndAttributesReverseLookUp:
            pVals[5] = dwFlagsAndAttributesReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])

        # create strings for everything except ones in our skip
        skip = [1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = FakeProcess
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ExitProcess(self, uc, eip, esp, export_dict, callAddr, em):
        # print("Using custom function...")
        uExitCode = uc.mem_read(esp + 4, 4)
        uExitCode = unpack('<I', uExitCode)[0]

        cleanBytes = 4
        logged_calls = ("ExitProcess", hex(callAddr), 'None', '', [uExitCode], ['UINT'], ['uExitCode'], False)
        return logged_calls, cleanBytes

    def CreateFileA(self, uc, eip, esp, export_dict, callAddr, em):
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
        lpFileName = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        lpFileName = unpack('<I', lpFileName)[0]
        lpFileName = read_string(uc, lpFileName)

        dwDesiredAccess = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 4)
        dwDesiredAccess = unpack('<I', dwDesiredAccess)[0]
        dwShareMode = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 12, 4)
        dwShareMode = unpack('<I', dwShareMode)[0]
        lpSecurityAttributes = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 16, 4)
        lpSecurityAttributes = unpack('<I', lpSecurityAttributes)[0]
        dwCreationDistribution = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 20, 4)
        dwCreationDistribution = unpack('<I', dwCreationDistribution)[0]
        dwFlagsAndAttributes = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 24, 4)
        dwFlagsAndAttributes = unpack('<I', dwFlagsAndAttributes)[0]
        hTemplateFile = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 28, 4)
        hTemplateFile = unpack('<I', hTemplateFile)[0]

        retVal = FakeProcess
        uc.reg_write(UC_X86_REG_EAX, retVal)

        createDispoReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING', 3: 'OPEN_EXISTING'}
        dwShareReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE'}
        dwAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE', 536870912: 'GENERIC_EXECUTE',
                                 268435456: 'GENERIC_ALL', 0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
        if dwCreationDistribution in createDispoReverseLookUp:
            dwCreationDistribution = createDispoReverseLookUp[dwCreationDistribution]
        else:
            dwCreationDistribution = hex(dwCreationDistribution)
        if dwShareMode in dwShareReverseLookUp:
            dwShareMode = dwShareReverseLookUp[dwShareMode]
        else:
            dwShareMode = hex(dwShareMode)
        if dwDesiredAccess in dwAccessReverseLookUp:
            dwDesiredAccess = dwAccessReverseLookUp[dwDesiredAccess]
        else:
            dwDesiredAccess = hex(dwDesiredAccess)
        cleanBytes = 28
        logged_calls = ("CreateFileA", hex(callAddr), hex(retVal), 'HANDLE',
                        [hex(lpFileName), dwDesiredAccess, dwShareMode, hex(lpSecurityAttributes),
                         dwCreationDistribution, hex(dwFlagsAndAttributes), hex(hTemplateFile)],
                        ["LPCSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD", "HANDLE"],
                        ["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes",
                         "dwCreationDistribution", "dwFlagsAndAttributes", "hTemplateFile"], False)

        return logged_calls, cleanBytes

    def CreateFileW(self, uc, eip, esp, export_dict, callAddr, em):
        # HANDLE CreateFileW([in] LPCWSTR lpFileName,[in] DWORD dwDesiredAccess,[in] DWORD dwShareMode,[in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,[in] DWORD dwCreationDisposition,[in] DWORD dwFlagsAndAttributes,[in, optional] HANDLE hTemplateFile);
        pVals = makeArgVals(uc, em, esp, 8)
        pTypes = ['LPCWSTR', 'lpFileName', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'HANDLE']
        pNames = ["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDistribution",
                  "dwFlagsAndAttributes", "hTemplateFile"]
        dwDesiredAccessReverseLookUp = {2147483648: 'GENERIC_READ', 1073741824: 'GENERIC_WRITE',
                                        536870912: 'GENERIC_EXECUTE', 268435456: 'GENERIC_ALL',
                                        0xC0000000: 'GENERIC_READ | GENERIC_WRITE'}
        dwShareModeReverseLookUp = {0: 'FILE_NO_OPEN', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE',
                                    4: 'FILE_SHARE_DELETE'}
        dwCreationDistributionReverseLookUp = {2: 'CREATE_ALWAYS', 1: 'CREATE_NEW', 4: 'TRUNCATE_EXISTING',
                                               3: 'OPEN_EXISTING', 5: 'TRUNCATE_EXISTING'}
        dwFlagsAndAttributesReverseLookUp = {32: 'FILE_ATTRIBUTE_ARCHIVE', 16384: 'FILE_ATTRIBUTE_ENCRYPTED',
                                             2: 'FILE_ATTRIBUTE_HIDDEN', 128: 'FILE_ATTRIBUTE_NORMAL',
                                             4096: 'FILE_ATTRIBUTE_OFFLINE', 1: 'FILE_ATTRIBUTE_READONLY',
                                             4: 'FILE_ATTRIBUTE_SYSTEM', 256: 'FILE_ATTRIBUTE_TEMPORARY',
                                             33554432: 'FILE_FLAG_BACKUP_SEMANTICS',
                                             67108864: 'FILE_FLAG_DELETE_ON_CLOSE', 536870912: 'FILE_FLAG_NO_BUFFERING',
                                             1048576: 'FILE_FLAG_OPEN_NO_RECALL',
                                             2097152: 'FILE_FLAG_OPEN_REPARSE_POINT',
                                             1073741824: 'FILE_FLAG_OVERLAPPED', 16777216: 'FILE_FLAG_POSIX_SEMANTICS',
                                             268435456: 'FILE_FLAG_RANDOM_ACCESS', 8388608: 'FILE_FLAG_SESSION_AWARE',
                                             134217728: 'FILE_FLAG_SEQUENTIAL_SCAN',
                                             2147483648: 'FILE_FLAG_WRITE_THROUGH'}

        search = pVals[1]
        if search in dwDesiredAccessReverseLookUp:
            pVals[1] = dwDesiredAccessReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])
        search = pVals[2]
        if search in dwShareModeReverseLookUp:
            pVals[2] = dwShareModeReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])
        search = pVals[4]
        if search in dwCreationDistributionReverseLookUp:
            pVals[4] = dwCreationDistributionReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        search = pVals[5]
        if search in dwFlagsAndAttributesReverseLookUp:
            pVals[5] = dwFlagsAndAttributesReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])

        # create strings for everything except ones in our skip
        skip = [1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = FakeProcess
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateProcessA(self, uc, eip, esp, export_dict, callAddr, em):
        # print ("CreateProcessA2")
        """'CreateProcess': (10, ['LPCTSTR', 'LPTSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCTSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION'], ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation'], 'BOOL'),"""

        # function to get values for parameters - count as specified at the end - returned as a list
        pVals = makeArgVals(uc, em, esp, 10)
        pTypes = ['LPCTSTR', 'LPTSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID',
                  'LPCTSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
        pNames = ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles',
                  'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']

        # searching a dictionary for string to replace hex with
        search = pVals[5]
        if search in ProcessCreationReverseLookUp:
            pVals[5] = ProcessCreationReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = 40
        retVal = 32
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ProcessCreateA", hex(callAddr), hex(retVal), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def URLDownloadToFileA(self, uc, eip, esp, export_dict, callAddr, em):
        # function to get values for parameters - count as specified at the end - returned as a list
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPUNKNOWN', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
        pNames = ['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']

        # create strings for everything except ones in our skip
        skip = []  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x0
        retValStr = 'S_OK'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("URLDownloadToFileA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def WinExec(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)

        pTypes = ['LPCSTR', 'UINT']
        pNames = ['lpCmdLine', 'uCmdShow']
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

        search = pVals[1]
        if search in cmdShowReverseLookUp:
            pVals[1] = cmdShowReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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
        search = pVals[5]
        if search in cmdShowReverseLookUp:
            pVals[5] = cmdShowReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ShellExecuteA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ShellExecuteW(self, uc, eip, esp, export_dict, callAddr, em):
        # HINSTANCE ShellExecuteW([in, optional] HWND   hwnd, [in, optional] LPCSTR lpOperation,[in] LPCSTR lpFile,
        # [in, optional] LPCSTR lpParameters, [in, optional] LPCSTR lpDirectory, [in] INT    nShowCmd);
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'INT']
        pNames = ['hwnd', 'lpOperation', 'lpFile', 'lpParameters', 'lpDirectory', 'nShowCmd']
        cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE',
                                4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE',
                                8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}
        search = pVals[5]
        if search in cmdShowReverseLookUp:
            pVals[5] = cmdShowReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ShellExecuteW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualProtect(self, uc, eip, esp, export_dict, callAddr, em):
        # BOOL VirtualProtect([in]  LPVOID lpAddress,[in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect)
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
        pNames = ['lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']

        search = pVals[2]
        if search in MemReverseLookUp:
            pVals[2] = MemReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("VirtualProtect", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualProtectEx(self, uc, eip, esp, export_dict, callAddr, em):
        # Need to Finish Testing when VirtualAllocEx is Commited
        # BOOL VirtualProtectEx([in]  HANDLE hProcess, [in]  LPVOID lpAddress, [in]  SIZE_T dwSize, [in]  DWORD  flNewProtect, [out] PDWORD lpflOldProtect);
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'PDWORD']
        pNames = ['hProcess', 'lpAddress', 'dwSize', 'flNewProtect', 'lpflOldProtect']

        search = pVals[3]
        if search in MemReverseLookUp:
            pVals[3] = MemReverseLookUp[search]
        else:
            pVals[3] = hex(pVals[3])

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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
        search = pVals[2]

        if search in memReleaseReverseLookUp:
            pVals[2] = memReleaseReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[0]
        if search in aFReverseLookUp:
            pVals[0] = aFReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])
        search = pVals[1]
        if search in sockTypeReverseLookUp:
            pVals[1] = sockTypeReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])
        search = pVals[2]
        if search in sockProtocolReverseLookUp:
            pVals[2] = sockProtocolReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])
        search = pVals[5]
        if search in dwFlagsReverseLookUp:
            pVals[5] = dwFlagsReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])
        search = pVals[5]

        if search in groupReverseLookUp:
            pVals[4] = groupReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        # create strings for everything except ones in our skip
        skip = [0, 1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[0]
        if search in aFReverseLookUp:
            pVals[0] = aFReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])
        search = pVals[1]
        if search in sockTypeReverseLookUp:
            pVals[1] = sockTypeReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])
        search = pVals[2]
        if search in sockProtocolReverseLookUp:
            pVals[2] = sockProtocolReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])
        search = pVals[5]
        if search in groupReverseLookUp:
            pVals[4] = groupReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        if search in dwFlagsReverseLookUp:
            pVals[5] = dwFlagsReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])
        search = pVals[4]

        # create strings for everything except ones in our skip
        skip = [0, 1, 2, 4, 5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[0]
        if search in aFReverseLookUp:
            pVals[0] = aFReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])
        search = pVals[1]
        if search in sockTypeReverseLookUp:
            pVals[1] = sockTypeReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])
        search = pVals[2]
        if search in sockProtocolReverseLookUp:
            pVals[2] = sockProtocolReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])

        # create strings for everything except ones in our skip
        skip = [0, 1, 2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[0]
        if search in flagsReverseLookUp:
            pVals[0] = flagsReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])
        search = pVals[1]
        if search in lpInfoReverseLookUp:
            pVals[1] = lpInfoReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])
        search = pVals[2]

        # create strings for everything except ones in our skip
        skip = [0, 1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[0]
        if search in flagsReverseLookUp:
            pVals[0] = flagsReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])
        search = pVals[1]
        if search in lpInfoReverseLookUp:
            pVals[1] = lpInfoReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])
        search = pVals[2]

        # create strings for everything except ones in our skip
        skip = [0, 1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("BroadcastSystemMessageW", hex(callAddr), (retValStr), 'long', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def LdrLoadDll(self, uc, eip, esp, export_dict, callAddr, em):
        print("Doing manual function")
        arg1 = uc.mem_read(esp + 4, 4)
        arg1 = unpack('<I', arg1)[0]
        arg1 = read_string(uc, arg1)

        arg2 = uc.mem_read(esp + 8, 4)
        arg2 = hex(unpack('<I', arg2)[0])

        arg3 = uc.mem_read(esp + 12, 4)
        arg3 = unpack('<I', arg3)[0]
        arg3 = uc.mem_read(arg3 + 4, 4)
        arg3 = unpack('<I', arg3)[0]
        arg3 = read_unicode(uc, arg3)

        arg4 = uc.mem_read(esp + 16, 4)
        arg4 = unpack('<I', arg4)[0]

        # Return base address of passed library
        try:
            retVal = allDllsDict[arg1]
        except:
            try:
                arg3 = arg3.lower()
                retVal = allDllsDict[arg3]
            except:
                print("\tError: The shellcode tried to load a DLL that isn't handled by this tool: ", arg1)
                print(hex(eip), (len(arg1)))
                retVal = 0

        # uc.reg_write(UC_X86_REG_EAX, retVal)
        uc.mem_write(arg4, pack("<Q", retVal))

        check = uc.mem_read(arg4, 4)
        check = unpack('<I', arg4)[0]
        print("Check: ", check)

        logged_calls = ("LdrLoadDll", hex(callAddr), hex(retVal), 'ModuleHandle', [arg1, arg2, arg3, arg4],
                        ['PWCHAR', 'ULONG', 'PUNICODE_STRING', 'PHANDLE'],
                        ['PathToFile', 'Flags', 'ModuleFileName', 'ModuleHandle'], False)

        cleanBytes = 16
        return logged_calls, cleanBytes

    def CreateThread(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpThreadId']
        dwCreateFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        search = pVals[4]
        if search in dwCreateFlagsReverseLookUp:
            pVals[4] = dwCreateFlagsReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00616161  # Implement handle later
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateServiceA(self, uc, eip, esp, export_dict, callAddr, em):
        # SC_HANDLE CreateServiceA([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
        pVals = makeArgVals(uc, em, esp, 13)
        pTypes = ['SC_HANDLE', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'LPCSTR', 'LPDWORD',
                  'LPCSTR', 'LPCSTR', 'LPCSTR']
        pNames = ['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType',
                  'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies',
                  'lpServiceStartName', 'lpPassword']
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG',
                                        0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE',
                                        0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG',
                                        0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP',
                                        0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE',
                                        0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
        dwServiceTypeReverseLookUp = {0x00000004: 'SERVICE_ADAPTER', 0x00000002: 'SERVICE_FILE_SYSTEM_DRIVER',
                                      0x00000001: 'SERVICE_KERNEL_DRIVER', 0x00000008: 'SERVICE_RECOGNIZER_DRIVER',
                                      0x00000010: 'SERVICE_WIN32_OWN_PROCESS',
                                      0x00000020: 'SERVICE_WIN32_SHARE_PROCESS',
                                      0x00000100: 'SERVICE_INTERACTIVE_PROCESS'}
        dwStartTypeReverseLookUp = {0x00000002: 'SERVICE_AUTO_START', 0x00000000: 'SERVICE_BOOT_START',
                                    0x00000003: 'SERVICE_DEMAND_START', 0x00000004: 'SERVICE_DISABLED',
                                    0x00000001: 'SERVICE_SYSTEM_START'}
        dwErrorControlReverseLookUp = {0x00000003: 'SERVICE_ERROR_CRITICAL', 0x00000000: 'SERVICE_ERROR_IGNORE',
                                       0x00000001: 'SERVICE_ERROR_NORMAL', 0x00000002: 'SERVICE_ERROR_SEVERE'}

        search = pVals[3]
        if search in dwDesiredAccessReverseLookUp:
            pVals[3] = dwDesiredAccessReverseLookUp[search]
        else:
            pVals[3] = hex(pVals[3])
        search = pVals[4]
        if search in dwServiceTypeReverseLookUp:
            pVals[4] = dwServiceTypeReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        search = pVals[5]
        if search in dwStartTypeReverseLookUp:
            pVals[5] = dwStartTypeReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])
        search = pVals[6]
        if search in dwErrorControlReverseLookUp:
            pVals[6] = dwErrorControlReverseLookUp[search]
        else:
            pVals[6] = hex(pVals[6])

        # create strings for everything except ones in our skip
        skip = [3, 4, 5, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = FakeProcess  # Return HANDLE to service
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateServiceA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateServiceW(self, uc, eip, esp, export_dict, callAddr, em):
        # SC_HANDLE CreateServiceW([in]SC_HANDLE hSCManager,[in] LPCSTR lpServiceName,[in, optional]  LPCSTR lpDisplayName,[in] DWORD dwDesiredAccess,[in] DWORD dwServiceType,[in] DWORD dwStartType,[in] DWORD dwErrorControl,[in, optional]  LPCSTR    lpBinaryPathName,[in, optional]  LPCSTR    lpLoadOrderGroup,[out, optional] LPDWORD lpdwTagId,[in, optional]  LPCSTR lpDependencies,[in, optional]  LPCSTR lpServiceStartName,[in, optional] LPCSTR lpPassword);
        pVals = makeArgVals(uc, em, esp, 13)
        pTypes = ['SC_HANDLE', 'LPCSTR', 'LPCSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR', 'LPCSTR', 'LPDWORD',
                  'LPCSTR', 'LPCSTR', 'LPCSTR']
        pNames = ['hSCManager', 'lpServiceName', 'lpDisplayName', 'dwDesiredAccess', 'dwServiceType', 'dwStartType',
                  'dwErrorControl', 'lpBinaryPathName', 'lpLoadOrderGroup', 'lpdwTagId', 'lpDependencies',
                  'lpServiceStartName', 'lpPassword']
        dwDesiredAccessReverseLookUp = {0xf01ff: 'SERVICE_ALL_ACCESS', 0x0002: 'SERVICE_CHANGE_CONFIG',
                                        0x0008: 'SERVICE_ENUMERATE_DEPENDENTS', 0x0080: 'SERVICE_INTERROGATE',
                                        0x0040: 'SERVICE_PAUSE_COUNTINUE', 0x0001: 'SERVICE_QUERY_CONFIG',
                                        0x0004: 'SERVICE_QUERY_STATUS', 0X0010: 'SERVICE_START', 0x0020: 'SERVICE_STOP',
                                        0x0100: 'SERVICE_USER_DEFINED_CONTROL', 0x10000: 'DELETE',
                                        0x20000: 'READ_CONTROL', 0x40000: 'WRITE_DAC', 0x80000: 'WRITE_OWNER'}
        dwServiceTypeReverseLookUp = {0x00000004: 'SERVICE_ADAPTER', 0x00000002: 'SERVICE_FILE_SYSTEM_DRIVER',
                                      0x00000001: 'SERVICE_KERNEL_DRIVER', 0x00000008: 'SERVICE_RECOGNIZER_DRIVER',
                                      0x00000010: 'SERVICE_WIN32_OWN_PROCESS',
                                      0x00000020: 'SERVICE_WIN32_SHARE_PROCESS',
                                      0x00000100: 'SERVICE_INTERACTIVE_PROCESS'}
        dwStartTypeReverseLookUp = {0x00000002: 'SERVICE_AUTO_START', 0x00000000: 'SERVICE_BOOT_START',
                                    0x00000003: 'SERVICE_DEMAND_START', 0x00000004: 'SERVICE_DISABLED',
                                    0x00000001: 'SERVICE_SYSTEM_START'}
        dwErrorControlReverseLookUp = {0x00000003: 'SERVICE_ERROR_CRITICAL', 0x00000000: 'SERVICE_ERROR_IGNORE',
                                       0x00000001: 'SERVICE_ERROR_NORMAL', 0x00000002: 'SERVICE_ERROR_SEVERE'}

        search = pVals[3]
        if search in dwDesiredAccessReverseLookUp:
            pVals[3] = dwDesiredAccessReverseLookUp[search]
        else:
            pVals[3] = hex(pVals[3])
        search = pVals[4]
        if search in dwServiceTypeReverseLookUp:
            pVals[4] = dwServiceTypeReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        search = pVals[5]
        if search in dwStartTypeReverseLookUp:
            pVals[5] = dwStartTypeReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])
        search = pVals[6]
        if search in dwErrorControlReverseLookUp:
            pVals[6] = dwErrorControlReverseLookUp[search]
        else:
            pVals[6] = hex(pVals[6])

        # create strings for everything except ones in our skip
        skip = [3, 4, 5, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = FakeProcess  # Return HANDLE to service
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateServiceW", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetOpenA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPCSTR', 'DWORD', 'LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpszAgent', 'dwAccessType', 'lpszProxy', 'lpszProxyBypass', 'dwFlags']

        dwAccessTypeReverseLookUp = {0: 'INTERNET_OPEN_TYPE_PRECONFIG', 1: 'INTERNET_OPEN_TYPE_DIRECT',
                                     3: 'INTERNET_OPEN_TYPE_PROXY', 4: 'INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY'}
        dwFlagsReverseLookUp = {268435456: 'INTERNET_FLAG_ASYNC', 16777216: 'INTERNET_FLAG_FROM_CACHE'}

        search = pVals[1]
        if search in dwAccessTypeReverseLookUp:
            pVals[1] = dwAccessTypeReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])

        search = pVals[4]
        if search in dwFlagsReverseLookUp:
            pVals[4] = dwFlagsReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])

        # create strings for everything except ones in our skip
        skip = [1, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00626262
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetOpenA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
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
        dwFlagsReverseLookUp = {134217728: 'INTERNET_FLAG_PASSIVE'}

        search = pVals[2]
        if search in nServerPortReverseLookUp:
            pVals[2] = nServerPortReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])
        search = pVals[5]
        if search in dwServiceReverseLookUp:
            pVals[5] = dwServiceReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])
        search = pVals[6]
        if search in dwFlagsReverseLookUp:
            pVals[6] = dwFlagsReverseLookUp[search]
        else:
            pVals[6] = hex(pVals[6])
        # create strings for everything except ones in our skip
        skip = [2, 5, 6]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00636363
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("InternetConnectA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateRemoteThread(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
        pNames = ['hProcess', 'lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags',
                  'lpThreadId']

        dwCreationFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

        search = pVals[5]
        if search in dwCreationFlagsReverseLookUp:
            pVals[5] = dwCreationFlagsReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])

        # create strings for everything except ones in our skip
        skip = [5]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00646464
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateRemoteThread", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def VirtualAllocEx(self, uc, eip, esp, export_dict, callAddr, em):
        global availMem

        hProcess = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4)
        hProcess = unpack('<I', hProcess)[0]
        lpAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 4)
        lpAddress = unpack('<I', lpAddress)[0]
        dwSize = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 12, 4)
        dwSize = unpack('<I', dwSize)[0]
        flAllocationType = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 16, 4)
        flAllocationType = unpack('<I', flAllocationType)[0]
        flProtect = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 20, 4)
        flProtect = unpack('<I', flProtect)[0]

        # Round up to next page (4096)
        dwSize = ((dwSize // 4096) + 1) * 4096

        retVal = 0
        try:
            uc.mem_map(lpAddress, dwSize)
            retVal = lpAddress
            uc.reg_write(UC_X86_REG_EAX, retVal)
        except:
            try:
                allocLoc = availMem
                uc.mem_map(allocLoc, dwSize)
                availMem += dwSize + 20
                uc.reg_write(UC_X86_REG_EAX, allocLoc)
                retVal = allocLoc
            except:
                success = False
                retVal = 0xbaddd000
                uc.reg_write(UC_X86_REG_EAX, retVal)

        if flAllocationType in MemReverseLookUp:
            flAllocationType = MemReverseLookUp[flAllocationType]
        else:
            flAllocationType = hex(flAllocationType)

        if flProtect in MemReverseLookUp:
            flProtect = MemReverseLookUp[flProtect]
        else:
            flProtect = hex(flProtect)

        logged_calls = ("VirtualAllocEx", hex(callAddr), hex(retVal), 'INT',
                        [hex(hProcess), hex(lpAddress), hex(dwSize), (flAllocationType), (flProtect)],
                        ['HANDLE', 'LPVOID', 'SIZE_T', 'DWORD', 'DWORD'],
                        ['hProcess', 'lpAddress', 'dwSize', 'flAllocationType', 'flProtect'], False)
        cleanBytes = 20

        return logged_calls, cleanBytes

    def RegCreateKeyExA2(self, uc, eip, esp, export_dict, callAddr, em):
        # LSTATUS RegCreateKeyExA([in] HKEY hKey,[in] LPCSTR lpSubKey,DWORD Reserved,[in, optional]  LPSTR lpClass,[in] DWORD dwOptions,[in] REGSAM samDesired,[in, optional] const LPSECURITY_ATTRIBUTES lpSecurityAttributes,[out] PHKEY phkResult,[out, optional] LPDWORD lpdwDisposition);
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCSTR', 'DWORD', 'LPSTR', 'DWORD', 'REGSAM', 'LPSECURITY_ATTRIBUTES', 'PHKEY', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'Reserved', 'lpClass', 'dwOptions', 'samDesired', 'lpSecurityAttributes',
                  'phkResult', 'lpdwDisposition']
        dwOptionsReverseLookUp = {4: 'REG_OPTION_BACKUP_RESTORE', 2: 'REG_OPTION_CREATE_LINK',
                                  0: 'REG_OPTION_NON_VOLATILE', 1: 'REG_OPTION_VOLATILE'}
        lpdwDispostitionReverseLookUp = {1: 'REG_CREATED_NEW_KEY', 2: 'REG_OPENED_EXISTING_KEY'}
        samDesiredReverseLookUp = {983103: 'KEY_ALL_ACCESS', 32: 'KEY_CREATE_LINK', 4: 'KEY_CREATE_SUB_KEY',
                                   8: 'KEY_ENUMERATE_SUB_KEYS', 131097: 'KEY_READ', 16: 'KEY_NOTIFY',
                                   1: 'KEY_QUERY_VALUE', 2: 'KEY_SET_VALUE', 512: 'KEY_WOW64_32KEY',
                                   256: 'KEY_WOW64_64KEY', 131078: 'KEY_WRITE'}

        search = pVals[4]
        if search in dwOptionsReverseLookUp:
            pVals[4] = dwOptionsReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        search = pVals[5]
        if search in dwOptionsReverseLookUp:
            pVals[5] = dwOptionsReverseLookUp[search]
        else:
            pVals[5] = hex(pVals[5])
        search = pVals[8]
        if search in dwOptionsReverseLookUp:
            pVals[8] = dwOptionsReverseLookUp[search]
        else:
            pVals[8] = hex(pVals[8])

        # create strings for everything except ones in our skip
        skip = [4, 5, 8]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x1
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegCreateKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RegDeleteKeyExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['HKEY', 'LPCSTR', 'REGSAM', 'DWORD']
        pNames = ['hKey', 'lpSubKey', 'samDesired', 'Reserved']

        samDesiredReverseLookUp = {512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY'}

        search = pVals[2]
        if search in samDesiredReverseLookUp:
            pVals[2] = samDesiredReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegDeleteKeyExA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def RegGetValueA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 7)
        pTypes = ['HKEY', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPDWORD', 'PVOID', 'LPDWORD']
        pNames = ['hKey', 'lpSubKey', 'lpValue', 'dwFlags', 'pdwType', 'pvData', 'pcbData']

        dwFlagsReverseLookUp = {65535: 'RRF_RT_ANY', 24: 'RRF_RT_DWORD', 72: 'RRF_RT_QWORD', 8: 'RRF_RT_REG_BINARY',
                                16: 'RRF_RT_REG_DWORD', 4: 'RRF_RT_REG_EXPAND_SZ', 32: 'RRF_RT_REG_MULTI_SZ',
                                1: 'RRF_RT_REG_NONE', 64: 'RRF_RT_REG_QWORD', 2: 'RRF_RT_REG_SZ',
                                268435456: 'RRF_NOEXPAND', 536870912: 'RRF_ZEROONFAILURE',
                                65536: 'RRF_SUBKEY_WOW6464KEY', 131072: 'RRF_SUBKEY_WOW6432KEY'}

        search = pVals[3]
        if search in dwFlagsReverseLookUp:
            pVals[3] = dwFlagsReverseLookUp[search]
        else:
            pVals[3] = hex(pVals[3])

        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x0
        retValStr = 'ERROR_SUCCESS'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("RegGetValueA", hex(callAddr), (retValStr), 'LSTATUS', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CryptDecrypt(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HCRYPTKEY', 'HCRYPTHASH', 'BOOL', 'DWORD', 'BYTE', 'DWORD']
        pNames = ['hKey', 'hHash', 'Final', 'dwFlags', 'pbData', 'pdwDataLen']

        dwFlagsReverseLookUp = {64: 'CRYPT_OAEP', 32: 'CRYPT_DECRYPT_RSA_NO_PADDING_CHECK'}

        search = pVals[3]
        if search in dwFlagsReverseLookUp:
            pVals[3] = dwFlagsReverseLookUp[search]
        else:
            pVals[3] = hex(pVals[3])
        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptDecrypt", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def SetWindowsHookExA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 4)
        pTypes = ['int', 'HOOKPROC', 'HINSTANCE', 'DWORD']
        pNames = ['idHook', 'lpfn', 'hmod', 'dwThreadId']

        idHookReverseLookUp = {4: 'WH_CALLWNDPROC', 18: 'WH_CALLWNDPROCRET', 5: 'WH_CBT', 9: 'WH_DEBUG',
                               17: 'WH_FOREGROUNDIDLE', 3: 'WH_GETMESSAGE', 1: 'WH_JOURNALPLAYBACK',
                               0: 'WH_JOURNALRECORD', 2: 'WH_KEYBOARD', 19: 'WH_KEYBOARD_LL', 7: 'WH_MOUSE',
                               20: 'WH_MOUSE_LL', -1: 'WH_MSGFILTER', 16: 'WH_SHELL', 6: 'WH_SYSMSGFILTER'}

        search = pVals[0]
        if search in idHookReverseLookUp:
            pVals[0] = idHookReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00656565
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetWindowsHookExA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateToolhelp32Snapshot(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['DWORD', 'DWORD']
        pNames = ['dwFlags', 'th32ProcessID']

        dwFlagsReverseLookUp = {2147483648: 'TH32CS_INHERIT', 15: 'TH32CS_SNAPALL', 1: 'TH32CS_SNAPHEAPLIST',
                                8: 'TH32CS_SNAPMODULE', 16: 'TH32CS_SNAPMODULE32', 2: 'TH32CS_SNAPPROCESS',
                                4: 'TH32CS_SNAPTHREAD'}

        search = pVals[0]
        if search in dwFlagsReverseLookUp:
            pVals[0] = dwFlagsReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])

        # create strings for everything except ones in our skip
        skip = [0]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00666666
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateToolhelp32Snapshot", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def shutdown(self, uc, eip, esp, export_dict, callAddr, em):
        # 'WSASocketA': (6, ['INT', 'INT', 'INT', 'LPWSAPROTOCOL_INFOA', 'GROUP', 'DWORD'], ['af', 'type', 'protocol', 'lpProtocolInfo', 'g', 'dwFlags'], 'SOCKET'),
        pVals = makeArgVals(uc, em, esp, 2)
        pTypes = ['SOCKET', 'int']
        pNames = ['s', 'how']

        howReverseLookUp = {0: 'SD_RECEIVE', 1: 'SD_SEND', 2: 'SD_BOTH'}

        search = pVals[1]
        if search in howReverseLookUp:
            pVals[1] = howReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[3]
        if search in dwReplaceFlagsReverseLookUp:
            pVals[3] = dwReplaceFlagsReverseLookUp[search]
        else:
            pVals[3] = hex(pVals[3])
        # create strings for everything except ones in our skip
        skip = [3]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReplaceFileA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
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

        search = pVals[4]
        if search in dwNotifyFilterReverseLookUp:
            pVals[4] = dwNotifyFilterReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])

        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x20
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ReadDirectoryChangesW", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def InternetCombineUrlW(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 5)
        pTypes = ['LPCWSTR', 'LPCWSTR', 'LPWSTR', 'LPDWORD', 'DWORD']
        pNames = ['lpszBaseUrl', 'lpszRelativeUrl', 'lpszBuffer', 'lpdwBufferLength', 'dwFlags']

        dwFlagsReverseLookUp = {536870912: 'ICU_NO_ENCODE', 268435456: 'ICU_DECODE', 134217728: 'ICU_NO_META',
                                67108864: 'ICU_ENCODE_SPACES_ONLY', 33554432: 'ICU_BROWSER_MODE',
                                4096: 'ICU_ENCODE_PERCENT'}

        search = pVals[4]
        if search in dwFlagsReverseLookUp:
            pVals[4] = dwFlagsReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        # create strings for everything except ones in our skip
        skip = [4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[0]
        if search in uFlagsReverseLookUp:
            pVals[0] = uFlagsReverseLookUp[search]
        else:
            pVals[0] = hex(pVals[0])
        search = pVals[1]
        if search in dwReasonReverseLookUp:
            pVals[1] = dwReasonReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])

        # create strings for everything except ones in our skip
        skip = [0, 1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
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

        search = pVals[1]
        if search in dwFileAttributesReverseLookUp:
            pVals[1] = dwFileAttributesReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("SetFileAttributesA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def ControlService(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['SC_HANDLE', 'DWORD', 'LPSERVICE_STATUS']
        pNames = ['hService', 'dwControl', 'lpServiceStatus']

        dwControlReverseLookUp = {3: 'SERVICE_CONTROL_CONTINUE', 4: 'SERVICE_CONTROL_INTERROGATE',
                                  7: 'SERVICE_CONTROL_NETBINDADD', 10: 'SERVICE_CONTROL_NETBINDDISABLE',
                                  9: 'SERVICE_CONTROL_NETBINDENABLE', 8: 'SERVICE_CONTROL_NETBINDREMOVE',
                                  6: 'SERVICE_CONTROL_PARAMCHANGE', 2: 'SERVICE_CONTROL_PAUSE',
                                  1: 'SERVICE_CONTROL_STOP'}

        search = pVals[1]
        if search in dwControlReverseLookUp:
            pVals[1] = dwControlReverseLookUp[search]
        else:
            pVals[1] = hex(pVals[1])

        # create strings for everything except ones in our skip
        skip = [1]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("ControlService", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def CreateFileMappingA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 6)
        pTypes = ['HANDLE', 'LPSECURITY_ATTRIBUTES', 'DWORD', 'DWORD', 'DWORD', 'LPCSTR']
        pNames = ['hFile', 'lpFileMappingAttributes', 'flProtect', 'dwMaximumSizeHigh', 'dwMaximumSizeLow', 'lpName']

        flProtectReverseLookUp = {2: 'PAGE_READONLY', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY',
                                  4: 'PAGE_READWRITE', 8: 'PAGE_WRITECOPY', 134217728: 'SEC_COMMIT',
                                  16777216: 'SEC_IMAGE', 285212672: 'SEC_IMAGE_NO_EXECUTE',
                                  2147483648: 'SEC_LARGE_PAGES', 268435456: 'SEC_NOCACHE', 67108864: 'SEC_RESERVE',
                                  1073741824: 'SEC_WRITECOMBINE'}

        search = pVals[2]
        if search in flProtectReverseLookUp:
            pVals[2] = flProtectReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00676767
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CreateFileMappingA", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
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

        search = pVals[3]
        if search in dwProvTypeReverseLookUp:
            pVals[3] = dwProvTypeReverseLookUp[search]
        else:
            pVals[3] = hex(pVals[3])

        search = pVals[4]
        if search in dwFlagsReverseLookUp:
            pVals[4] = dwFlagsReverseLookUp[search]
        else:
            pVals[4] = hex(pVals[4])
        # create strings for everything except ones in our skip
        skip = [3, 4]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("CryptAcquireContextA", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes

    def Toolhelp32ReadProcessMemory(self, uc, eip, esp, export_dict, callAddr, em):
        global availMem

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
                availMem += cbRead + 20
                lpBuffer = allocLoc
            except:
                success = False
                retAddr = 0xbadd0000

        retVal = 0x1
        retValStr = 'TRUE'
        uc.reg_write(UC_X86_REG_EAX, retVal)
        logged_calls = ("Toolhelp32ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL',
                        [(th32ProcessID), hex(lpBaseAddress), hex(lpBuffer), hex(cbRead), hex(lpNumberOfBytesRead)],
                        ['DWORD', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T'],
                        ['th32ProcessID', 'lpBaseAddress', 'lpBuffer', 'cbRead', 'lpNumberOfBytesRead'], False)
        cleanBytes = 20

        return logged_calls, cleanBytes

    def OpenSCManagerA(self, uc, eip, esp, export_dict, callAddr, em):
        pVals = makeArgVals(uc, em, esp, 3)
        pTypes = ['LPCSTR', 'LPCSTR', 'DWORD']
        pNames = ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']

        dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE',
                                        1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE',
                                        8: 'SC_MANAGER_LOCK', 32: 'SC_MANAGER_MODIFY_BOOT_CONFIG',
                                        16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

        search = pVals[2]
        if search in dwDesiredAccessReverseLookUp:
            pVals[2] = dwDesiredAccessReverseLookUp[search]
        else:
            pVals[2] = hex(pVals[2])

        # create strings for everything except ones in our skip
        skip = [2]  # we need to skip this value (index) later-let's put it in skip
        pTypes, pVals = findStringsParms(uc, pTypes, pVals, skip)

        cleanBytes = len(pTypes) * 4
        retVal = 0x00686868
        retValStr = hex(retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)

        logged_calls = ("OpenSCManagerA", hex(callAddr), (retValStr), 'SC_HANDLE', pVals, pTypes, pNames, False)
        return logged_calls, cleanBytes


class CustomWinSysCalls():
    def NtTerminateProcess(self, uc, eip, esp, callAddr):
        handle = uc.mem_read(esp + 4, 4)
        handle = unpack('<I', handle)[0]
        ntstatus = uc.mem_read(esp + 8, 4)
        ntstatus = unpack('<I', ntstatus)[0]

        retVal = 1

        logged_calls = (
        "NtTerminateProcess", hex(callAddr), hex(retVal), 'INT', [hex(handle), hex(ntstatus)], ['HANDLE', 'NTSTATUS'],
        ['ProcessHandle', 'ExitStatus'], False)
        return logged_calls

    def NtAllocateVirtualMemory(self, uc, eip, esp, callAddr):
        global availMem
        global address_range

        processHandle = uc.mem_read(esp + 4, 4)
        processHandle = unpack('<I', processHandle)[0]
        baseAddress = uc.mem_read(esp + 8, 4)
        baseAddress = unpack('<I', baseAddress)[0]
        zeroBits = uc.mem_read(esp + 12, 4)
        zeroBits = unpack('<I', zeroBits)[0]
        regionSize = uc.mem_read(esp + 16, 4)
        regionSize = unpack('<I', regionSize)[0]
        allocationType = uc.mem_read(esp + 20, 4)
        allocationType = unpack('<I', allocationType)[0]
        protect = uc.mem_read(esp + 24, 4)
        protect = unpack('<I', protect)[0]

        # Get pointer values
        allocLoc = getPointerVal(uc, baseAddress)
        size = getPointerVal(uc, regionSize)

        size = ((size // 4096) + 1) * 4096

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

                availMem += (regionSize + 20)
                uc.reg_write(UC_X86_REG_EAX, retVal)
                uc.mem_write(baseAddress, pack("<Q", allocLoc))

                tmp = uc.mem_read(baseAddress, 4)
                tmp = unpack('<I', tmp)[0]
            except Exception as e:
                print("Error: ", e)
                print(traceback.format_exc())
                print("VirtualAlloc Function Failed")
                success = False
                retVal = 0xbadd0000
                uc.reg_write(UC_X86_REG_EAX, retVal)

        if allocationType in MemReverseLookUp:
            flAllocationType = MemReverseLookUp[allocationType]
        else:
            flAllocationType = hex(allocationType)

        if protect in MemReverseLookUp:
            flProtect = MemReverseLookUp[protect]
        else:
            flProtect = hex(protect)

        baseAddress = buildPtrString(baseAddress, allocLoc)
        regionSize = buildPtrString(regionSize, size)

        logged_calls = ("NtAllocateVirtualMemory", hex(callAddr), hex(retVal), 'INT',
                        [hex(processHandle), baseAddress, hex(zeroBits), regionSize, hex(allocationType), hex(protect)],
                        ['HANDLE', 'PVOID', 'ULONG_PTR', 'PSIZE_T', 'ULONG', 'ULONG'],
                        ['ProcessHandle', '*BaseAddress', 'ZeroBits', '*RegionSize', 'AllocationType', 'Protect'],
                        False)

        return logged_calls

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
            arg = uc.mem_read(esp + (8 * loc), 8)
            arg = unpack('<q', arg)[0]
        else:
            arg = uc.mem_read(esp + (4 * loc), 4)
            arg = unpack('<I', arg)[0]

    return arg

def makeArgVals(uc, em , esp, numParams):
    args = [0] * numParams
    for i in range(len(args)):
        args[i] = getStackVal(uc, em, esp, i+1)

    return args

def findStringsParms(uc, pTypes,pVals, skip):
    i=0
    for each in pTypes:
        if i not in skip:
            if "STR" in pTypes[i]: #finding ones with string
                try:
                    # print ("looking", i, pTypes[i], pVals[i])
                    pVals[i] = read_string(uc, pVals[i])
                    # print (pVals[i],"*")
                except:
                    # print ("pass", i)
                    pass
            else:
                pVals[i] = hex(pVals[i])

        i+=1
    return pTypes, pVals

def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret