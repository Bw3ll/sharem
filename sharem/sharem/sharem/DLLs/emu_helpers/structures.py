from ctypes import LittleEndianStructure, sizeof
from struct import pack, unpack
from time import gmtime, localtime, time_ns
from sharem.sharem.DLLs.emu_helpers.reverseLookUps import ReverseLookUps
from sharem.sharem.DLLs.emu_helpers.sim_values import emuSimVals

from sharem.sharem.helper.ctypesUnion import LittleEndianUnion
from sharem.sharem.helper.emu import EMU
from sharem.sharem.helper.structHelpers import BOOL, BYTE, DWORD, DWORD_PTR_32BIT, DWORD_PTR_64BIT, HANDLE_32BIT, HANDLE_64BIT, HINSTANCE_32BIT, HINSTANCE_64BIT, HKEY_32BIT, HKEY_64BIT, HMENU_32BIT, HMENU_64BIT, HWND_32BIT, HWND_64BIT, INT, LONG, LONGLONG, LPBYTE_32BIT, LPBYTE_64BIT, LPCSTR_32BIT, LPCSTR_64BIT, LPCWSTR_32BIT, LPCWSTR_64BIT, LPSTR_32BIT, LPSTR_64BIT, LPVOID_32BIT, LPVOID_64BIT, LPWSTR_32BIT, LPWSTR_64BIT, MAX_PATH, PCHAR_32BIT, PCHAR_64BIT, POINTER_32BIT, POINTER_64BIT, PVOID_32BIT, PVOID_64BIT, PWSTR_32BIT, PWSTR_64BIT, SIZE_T_32BIT, SIZE_T_64BIT, UCHAR, ULONG, ULONG64, ULONG_PTR_32BIT, ULONG_PTR_64BIT, ULONGLONG, USHORT, WCHAR, WORD, CHAR, StructFieldsFromTypeHints, UnionFieldsFromTypeHints

from ...helper.emuHelpers import Uc


# Struct PROCESS_INFORMATION
# Alias Names: _PROCESS_INFORMATION
# Alias Pointer Names: *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION

def get_PROCESS_INFORMATION(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return PROCESS_INFORMATION.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(PROCESS_INFORMATION.ARCH32)))
    else:
        return PROCESS_INFORMATION.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(PROCESS_INFORMATION.ARCH64)))

# Struct Aliases:
# get__PROCESS_INFORMATION = get_PROCESS_INFORMATION

# Struct Pointers:
PPROCESS_INFORMATION_32BIT = POINTER_32BIT
PPROCESS_INFORMATION_64BIT = POINTER_64BIT
LPPROCESS_INFORMATION_32BIT = POINTER_32BIT
LPPROCESS_INFORMATION_64BIT = POINTER_64BIT

class PROCESS_INFORMATION:
    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        hProcess: HANDLE_32BIT
        hThread: HANDLE_32BIT
        dwProcessId: DWORD
        dwThreadId: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

        def setValues(self, hProcess: int, hThread: int, pID: int = 0, tID: int = 0):
            self.hProcess = hProcess
            self.hThread = hThread
            if pID != 0:
                self.dwProcessId = pID
            else:
                self.dwProcessId = emuSimVals.getNextPID()
            if tID != 0:
                self.dwThreadId = tID
            else:
                self.dwThreadId = emuSimVals.getNextTID()

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        hProcess: HANDLE_64BIT
        hThread: HANDLE_64BIT
        dwProcessId: DWORD
        dwThreadId: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

        def setValues(self, hProcess: int, hThread: int, pID: int = 0, tID: int = 0):
            self.hProcess = hProcess
            self.hThread = hThread
            if pID != 0:
                self.dwProcessId = pID
            else:
                self.dwProcessId = emuSimVals.getNextPID()
            if tID != 0:
                self.dwThreadId = tID
            else:
                self.dwThreadId = emuSimVals.getNextTID()


# class PROCESSENTRY32: # Needs Redone
#     # Backs both PROCESSENTRY32 and PROCESSENTRY32W
#     types = ['DWORD','DWORD','DWORD','ULONG_PTR','DWORD','DWORD','DWORD','LONG','DWORD','CHAR'] 
#     names = ['dwSize','cntUsage','th32ProcessID','th32DefaultHeapID','th32ModuleID','cntThreads','th32ParentProcessID','pcPriClassBase','dwFlags','szExeFile']

#     def __init__(self, processID, threadCount, parent_pID, baseThreadPriority, exeFile: str):
#         self.dwSizeA = 296 # Ascii Size
#         self.dwSizeW = 556 # Unicode Size
#         self.cntUsage = 0 # No Longer Used
#         self.th32ProcessID = processID
#         self.th32DefaultHeapID = 0 # No Longer Used
#         self.th32ModuleID = 0 # No Longer Used
#         self.cntThreads= threadCount
#         self.th32ParentProcessID = parent_pID
#         self.pcPriClassBase = baseThreadPriority
#         self.dwFlags = 0 # No Longer Used
#         self.szExeFile = exeFile

#     def writeToMemoryA(self, uc: Uc, address):
#         packedStruct = pack('<IIILIIIlI260s', self.dwSizeA, self.cntUsage, self.th32ProcessID, self.th32DefaultHeapID, self.th32ModuleID, self.cntThreads, self.th32ParentProcessID, self.pcPriClassBase, self.dwFlags, self.szExeFile.encode('ascii'))
#         uc.mem_write(address, packedStruct)

#     def readFromMemoryA(self, uc: Uc, address):
#         data = uc.mem_read(address, self.dwSizeA)
#         unpackedStruct = unpack('<IIILIIIlI260s', data)
#         self.dwSizeA = unpackedStruct[0]
#         self.cntUsage = unpackedStruct[1]
#         self.th32ProcessID = unpackedStruct[2]
#         self.th32DefaultHeapID = unpackedStruct[3]
#         self.th32ModuleID = unpackedStruct[4]
#         self.cntThreads = unpackedStruct[5]
#         self.th32ParentProcessID = unpackedStruct[6]
#         self.pcPriClassBase = unpackedStruct[7]
#         self.dwFlags = unpackedStruct[8]
#         self.szExeFile = unpackedStruct[9].decode()

#     def writeToMemoryW(self, uc: Uc, address):
#         packedStruct = pack('<IIILIIIlI520s', self.dwSizeW, self.cntUsage, self.th32ProcessID, self.th32DefaultHeapID, self.th32ModuleID, self.cntThreads, self.th32ParentProcessID, self.pcPriClassBase, self.dwFlags,self.szExeFile.encode('utf-16')[2:])
#         uc.mem_write(address, packedStruct)

#     def readFromMemoryW(self, uc: Uc, address):
#         data = uc.mem_read(address, self.dwSizeW)
#         unpackedStruct = unpack('<IIILIIIlI520s', data)
#         self.dwSizeW = unpackedStruct[0]
#         self.cntUsage = unpackedStruct[1]
#         self.th32ProcessID = unpackedStruct[2]
#         self.th32DefaultHeapID = unpackedStruct[3]
#         self.th32ModuleID = unpackedStruct[4]
#         self.cntThreads = unpackedStruct[5]
#         self.th32ParentProcessID = unpackedStruct[6]
#         self.pcPriClassBase = unpackedStruct[7]
#         self.dwFlags = unpackedStruct[8]
#         self.szExeFile = unpackedStruct[9].decode()

# Needs Redone More
# Struct PROCESSENTRY32
# Alias Names: tagPROCESSENTRY32
# Alias Pointer Names: 

def get_PROCESSENTRY32(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return PROCESSENTRY32.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32.ARCH32)))
    else:
        return PROCESSENTRY32.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32.ARCH64)))

# Struct Aliases:
# get_tagPROCESSENTRY32 = get_PROCESSENTRY32

class PROCESSENTRY32:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'CHAR']
        lookUps = {}

        # Struct Members
        dwSize: DWORD
        cntUsage: DWORD
        th32ProcessID: DWORD
        th32DefaultHeapID: ULONG_PTR_32BIT
        th32ModuleID: DWORD
        cntThreads: DWORD
        th32ParentProcessID: DWORD
        pcPriClassBase: LONG
        dwFlags: DWORD
        szExeFile: CHAR * MAX_PATH

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'CHAR']
        lookUps = {}

        # Struct Members
        dwSize: DWORD
        cntUsage: DWORD
        th32ProcessID: DWORD
        th32DefaultHeapID: ULONG_PTR_64BIT
        th32ModuleID: DWORD
        cntThreads: DWORD
        th32ParentProcessID: DWORD
        pcPriClassBase: LONG
        dwFlags: DWORD
        szExeFile: CHAR * MAX_PATH

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct PROCESSENTRY32W
# Alias Names: tagPROCESSENTRY32W
# Alias Pointer Names: 

def get_PROCESSENTRY32W(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return PROCESSENTRY32W.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32W.ARCH32)))
    else:
        return PROCESSENTRY32W.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32W.ARCH64)))

# Struct Aliases:
# get_tagPROCESSENTRY32W = get_PROCESSENTRY32W

class PROCESSENTRY32W:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'WCHAR']
        lookUps = {}

        # Struct Members
        dwSize: DWORD
        cntUsage: DWORD
        th32ProcessID: DWORD
        th32DefaultHeapID: ULONG_PTR_32BIT
        th32ModuleID: DWORD
        cntThreads: DWORD
        th32ParentProcessID: DWORD
        pcPriClassBase: LONG
        dwFlags: DWORD
        szExeFile: WCHAR * MAX_PATH

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'WCHAR']
        lookUps = {}

        # Struct Members
        dwSize: DWORD
        cntUsage: DWORD
        th32ProcessID: DWORD
        th32DefaultHeapID: ULONG_PTR_64BIT
        th32ModuleID: DWORD
        cntThreads: DWORD
        th32ParentProcessID: DWORD
        pcPriClassBase: LONG
        dwFlags: DWORD
        szExeFile: WCHAR * MAX_PATH

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

class THREADENTRY32: # Needs Redone
    types = ['DWORD','DWORD','DWORD','DWORD','DWORD','DWORD','LONG','LONG','DWORD']
    names = ['dwSize','cntUsage','th32ThreadID','th32OwnerProcessID','tpBasePri','tpDeltaPri','dwFlags']
    
    def __init__(self, ThreadID, OwnerProcessID, tpBasePri):
        self.dwSize = 28
        self.cntUsage = 0 # No Longer Used
        self.th32ThreadID = ThreadID
        self.th32OwnerProcessID = OwnerProcessID
        if tpBasePri < 0 or tpBasePri > 31: # Value 0 to 31
            tpBasePri = 16 # Set to Middle Priority
        self.tpBasePri = tpBasePri
        self.tpDeltaPri = 0 # No Longer Used
        self.dwFlags = 0 # No Longer Used

    def writeToMemory(self, uc: Uc, address):
        packedStruct = pack('<IIIIllI', self.dwSize, self.cntUsage, self.th32ThreadID, self.th32OwnerProcessID, self.tpBasePri, self.tpDeltaPri, self.dwFlags)
        uc.mem_write(address, packedStruct)

    def readFromMemory(self, uc: Uc, address):
        data = uc.mem_read(address, self.dwSize)
        unpackedStruct = unpack('<IIIIllI', data)
        self.dwSize = unpackedStruct[0]
        self.cntUsage = unpackedStruct[1]
        self.th32ThreadID = unpackedStruct[2]
        self.th32OwnerProcessID = unpackedStruct[3]
        self.tpBasePri = unpackedStruct[4]
        self.tpDeltaPri = unpackedStruct[5]
        self.dwFlags = unpackedStruct[6]

class MODULEENTRY32: # Needs Redone
    # Backs both MODULEENTRY32 and MODULEENTRY32W
    types = ['DWORD','DWORD','DWORD','DWORD','DWORD','BYTE','DWORD','HMODULE','char','char']
    names = ['dwSize','th32ModuleID','th32ProcessID','GlblcntUsage','ProccntUsage','*modBaseAddr','modBaseSize','hModule','szModule','szExePath']

    def __init__(self, th32ProcessID, modBaseAddr, modBaseSize, hModule, szModule: str, szExePath: str):
        self.dwSizeA = 548 # Ascii Size
        self.dwSizeW = 1064 # unicode Size
        self.th32ModuleID = 1 # No Longer Used
        self.th32ProcessID = th32ProcessID
        self.GlblcntUsage = 0xFFFF
        self.ProccntUsage = 0xFFFF
        self.modBaseAddr = modBaseAddr
        self.modBaseSize = modBaseSize
        self.hModule = hModule
        self.szModule = szModule
        self.szExePath = szExePath

    def writeToMemoryA(self, uc: Uc, address):
        packedStruct = pack('<IIIIIIII256s260s', self.dwSizeA, self.th32ModuleID, self.th32ProcessID, self.GlblcntUsage, self.ProccntUsage, self.modBaseAddr, self.modBaseSize, self.hModule, self.szModule.encode('ascii'), self.szExePath.encode('ascii'))
        uc.mem_write(address, packedStruct)

    def readFromMemoryA(self, uc: Uc, address):
        data = uc.mem_read(address, self.dwSizeA)
        unpackedStruct = unpack('<IIIIIIII256s260s', data)
        self.dwSizeA = unpackedStruct[0]
        self.th32ModuleID = unpackedStruct[1]
        self.th32ProcessID = unpackedStruct[2]
        self.GlblcntUsage = unpackedStruct[3]
        self.ProccntUsage = unpackedStruct[4]
        self.modBaseAddr = unpackedStruct[5]
        self.modBaseSize = unpackedStruct[6]
        self.hModule = unpackedStruct[7]
        self.szModule = unpackedStruct[8].decode()
        self.szExePath = unpackedStruct[9].decode()

    def writeToMemoryW(self, uc: Uc, address):
        packedStruct = pack('<IIIIIIII512s520s', self.dwSizeW, self.th32ModuleID, self.th32ProcessID, self.GlblcntUsage, self.ProccntUsage, self.modBaseAddr, self.modBaseSize, self.hModule, self.szModule.encode('utf-16')[2:], self.szExePath.encode('utf-16')[2:])
        uc.mem_write(address, packedStruct)

    def readFromMemoryW(self, uc: Uc, address):
        data = uc.mem_read(address, self.dwSizeW)
        unpackedStruct = unpack('<IIIIIIII512s520s', data)
        self.dwSizeW = unpackedStruct[0]
        self.th32ModuleID = unpackedStruct[1]
        self.th32ProcessID = unpackedStruct[2]
        self.GlblcntUsage = unpackedStruct[3]
        self.ProccntUsage = unpackedStruct[4]
        self.modBaseAddr = unpackedStruct[5]
        self.modBaseSize = unpackedStruct[6]
        self.hModule = unpackedStruct[7]
        self.szModule = unpackedStruct[8].decode()
        self.szExePath = unpackedStruct[9].decode()

# Struct SYSTEMTIME
# Alias Names: _SYSTEMTIME
# Alias Pointer Names: *PSYSTEMTIME, *LPSYSTEMTIME

def get_SYSTEMTIME(uc: Uc, address: int, em: EMU):
    return SYSTEMTIME.from_buffer_copy(uc.mem_read(address, sizeof(SYSTEMTIME)))

# Struct Aliases:
# get__SYSTEMTIME = get_SYSTEMTIME

# Struct Pointers:
PSYSTEMTIME_32BIT = POINTER_32BIT
PSYSTEMTIME_64BIT = POINTER_64BIT
LPSYSTEMTIME_32BIT = POINTER_32BIT
LPSYSTEMTIME_64BIT = POINTER_64BIT

class SYSTEMTIME(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD']
    lookUps = {}

    # Struct Members
    wYear: WORD
    wMonth: WORD
    wDayOfWeek: WORD
    wDay: WORD
    wHour: WORD
    wMinute: WORD
    wSecond: WORD
    wMilliseconds: WORD

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

    def setTime(self, utc: bool, customTime= 0):
        if utc:
            if customTime == 0:
                timeVal = gmtime()
            else:
                timeVal = gmtime(customTime)
        else:
            if customTime == 0:
                timeVal = localtime()
            else:
                timeVal = localtime(customTime)

        self.wYear = timeVal.tm_year
        self.wMonth = timeVal.tm_mon
        dayOfWeek = timeVal.tm_wday + 1 # Convert Monday 0 to Sunday 0
        if dayOfWeek == 7: dayOfWeek = 0
        self.wDayOfWeek = dayOfWeek
        self.wDay = timeVal.tm_mday
        self.wHour = timeVal.tm_hour
        self.wMinute = timeVal.tm_min
        self.wSecond = timeVal.tm_sec
        self.wMilliseconds = 0
    

# Struct SYSTEM_INFO
# Alias Names: _SYSTEM_INFO
# Alias Pointer Names: *LPSYSTEM_INFO

def get_SYSTEM_INFO(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return SYSTEM_INFO.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(SYSTEM_INFO.ARCH32)))
    else:
        return SYSTEM_INFO.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(SYSTEM_INFO.ARCH64)))

# Struct Aliases:
# get__SYSTEM_INFO = get_SYSTEM_INFO

# Struct Pointers:
LPSYSTEM_INFO_32BIT = POINTER_32BIT
LPSYSTEM_INFO_64BIT = POINTER_64BIT

class SYSTEM_INFO_Helpers:
    class DummyStruct(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['WORD', 'WORD']
        lookUps = {0: ReverseLookUps.Processor}
        
        # Struct Members
        wProcessorArchitecture: WORD
        wReserved: WORD

class SYSTEM_INFO:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['struct','DWORD','LPVOID','LPVOID','DWORD_PTR','DWORD','DWORD','DWORD','WORD','WORD']
        lookUps = {6: ReverseLookUps.ProcessorType}

        # Struct Members
        DUMMYSTRUCTNAME: SYSTEM_INFO_Helpers.DummyStruct
        dwPageSize: DWORD
        lpMinimumApplicationAddress: LPVOID_32BIT
        lpMaximumApplicationAddress: LPVOID_32BIT
        dwActiveProcessorMask: DWORD_PTR_32BIT
        dwNumberOfProcessors: DWORD
        dwProcessorType: DWORD
        dwAllocationGranularity: DWORD
        wProcessorLevel: WORD
        wProcessorRevision: WORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['struct','DWORD','LPVOID','LPVOID','DWORD_PTR','DWORD','DWORD','DWORD','WORD','WORD']
        lookUps = {6: ReverseLookUps.ProcessorType}

        # Struct Members
        DUMMYSTRUCTNAME: SYSTEM_INFO_Helpers.DummyStruct
        dwPageSize: DWORD
        lpMinimumApplicationAddress: LPVOID_64BIT
        lpMaximumApplicationAddress: LPVOID_64BIT
        dwActiveProcessorMask: DWORD_PTR_64BIT
        dwNumberOfProcessors: DWORD
        dwProcessorType: DWORD
        dwAllocationGranularity: DWORD
        wProcessorLevel: WORD
        wProcessorRevision: WORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


# Struct LIST_ENTRY
# Alias Names: _LIST_ENTRY
# Alias Pointer Names: *PLIST_ENTRY, PRLIST_ENTRY

def get_LIST_ENTRY(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return LIST_ENTRY.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(LIST_ENTRY.ARCH32)))
    else:
        return LIST_ENTRY.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(LIST_ENTRY.ARCH64)))

# Struct Aliases:
# get__LIST_ENTRY = get_LIST_ENTRY

# Struct Pointers:
PLIST_ENTRY_32BIT = POINTER_32BIT
PLIST_ENTRY_64BIT = POINTER_64BIT
PRLIST_ENTRY_32BIT = POINTER_32BIT
PRLIST_ENTRY_64BIT = POINTER_64BIT

class LIST_ENTRY:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['PLIST_ENTRY', 'PLIST_ENTRY']
        
        # Struct Members
        Flink: PLIST_ENTRY_32BIT
        Blink: PLIST_ENTRY_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['PLIST_ENTRY', 'PLIST_ENTRY']
        
        # Struct Members
        Flink: PLIST_ENTRY_64BIT
        Blink: PLIST_ENTRY_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct SINGLE_LIST_ENTRY
# Alias Names: _SINGLE_LIST_ENTRY
# Alias Pointer Names: *PSINGLE_LIST_ENTRY

def get_SINGLE_LIST_ENTRY(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return SINGLE_LIST_ENTRY.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(SINGLE_LIST_ENTRY.ARCH32)))
    else:
        return SINGLE_LIST_ENTRY.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(SINGLE_LIST_ENTRY.ARCH64)))

# Struct Aliases:
# get__SINGLE_LIST_ENTRY = get_SINGLE_LIST_ENTRY

# Struct Pointers:
PSINGLE_LIST_ENTRY_32BIT = POINTER_32BIT
PSINGLE_LIST_ENTRY_64BIT = POINTER_64BIT

class SINGLE_LIST_ENTRY:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['PSINGLE_LIST_ENTRY']
        lookUps = {}

        # Struct Members
        Next: PSINGLE_LIST_ENTRY_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['PSINGLE_LIST_ENTRY']
        lookUps = {}

        # Struct Members
        Next: PSINGLE_LIST_ENTRY_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct FILETIME
# Alias Names: _FILETIME
# Alias Pointer Names: PFILETIME, LPFILETIME

def get_FILETIME(uc: Uc, address: int, em: EMU):
    return FILETIME.from_buffer_copy(uc.mem_read(address, sizeof(FILETIME)))

# Struct Aliases:
# get__FILETIME = get_FILETIME

# Struct Pointers:
PFILETIME_32BIT = POINTER_32BIT
PFILETIME_64BIT = POINTER_64BIT
LPFILETIME_32BIT = POINTER_32BIT
LPFILETIME_64BIT = POINTER_64BIT

class FILETIME(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'DWORD']
    lookUps = {}

    # Struct Members
    dwLowDateTime: DWORD
    dwHighDateTime: DWORD

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

    def genTime(self):
        # time is in epoch 100 nanoseconds split into low and high
        timeEpoch = time_ns()
        highEndData = timeEpoch >> 32
        lowEndData = timeEpoch & 0xffffffff
        self.dwLowDateTime = lowEndData
        self.dwHighDateTime = highEndData

# Struct UNICODE_STRING
# Alias Names: _UNICODE_STRING
# Alias Pointer Names: PUNICODE_STRING

def get_UNICODE_STRING(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return UNICODE_STRING.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(UNICODE_STRING.ARCH32)))
    else:
        return UNICODE_STRING.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(UNICODE_STRING.ARCH64)))

# Struct Aliases:
# get__UNICODE_STRING = get_UNICODE_STRING

# Struct Pointers:
PUNICODE_STRING_32BIT = POINTER_32BIT
PUNICODE_STRING_64BIT = POINTER_64BIT

class UNICODE_STRING:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['USHORT', 'USHORT', 'PWSTR']
        lookUps = {}

        # Struct Members
        Length: USHORT
        MaximumLength: USHORT
        Buffer: PWSTR_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['USHORT', 'USHORT', 'PWSTR']
        lookUps = {}

        # Struct Members
        Length: USHORT
        MaximumLength: USHORT
        Buffer: PWSTR_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct STRING
# Alias Names: _STRING
# Alias Pointer Names:

def get_STRING(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return STRING.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(STRING.ARCH32)))
    else:
        return STRING.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(STRING.ARCH64)))

# Struct Aliases:
# get__STRING = get_STRING

class STRING:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['USHORT', 'USHORT', 'PCHAR']
        lookUps = {}

        # Struct Members
        Length: USHORT
        MaximumLength: USHORT
        Buffer: PCHAR_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['USHORT', 'USHORT', 'PCHAR']
        lookUps = {}

        # Struct Members
        Length: USHORT
        MaximumLength: USHORT
        Buffer: PCHAR_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct TIME_ZONE_INFORMATION
# Alias Names: _TIME_ZONE_INFORMATION
# Alias Pointer Names: *PTIME_ZONE_INFORMATION, *LPTIME_ZONE_INFORMATION

def get_TIME_ZONE_INFORMATION(uc: Uc, address: int, em: EMU):
    return TIME_ZONE_INFORMATION.from_buffer_copy(uc.mem_read(address, sizeof(TIME_ZONE_INFORMATION)))

# Struct Aliases:
# get__TIME_ZONE_INFORMATION = get_TIME_ZONE_INFORMATION

# Struct Pointers:
PTIME_ZONE_INFORMATION_32BIT = POINTER_32BIT
PTIME_ZONE_INFORMATION_64BIT = POINTER_64BIT
LPTIME_ZONE_INFORMATION_32BIT = POINTER_32BIT
LPTIME_ZONE_INFORMATION_64BIT = POINTER_64BIT

class TIME_ZONE_INFORMATION(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['LONG', 'WCHAR', 'SYSTEMTIME', 'LONG', 'WCHAR', 'SYSTEMTIME', 'LONG']
    lookUps = {}

    # Struct Members
    Bias: LONG
    StandardName: WCHAR * 32
    StandardDate: SYSTEMTIME
    StandardBias: LONG
    DaylightName: WCHAR * 32
    DaylightDate: SYSTEMTIME
    DaylightBias: LONG

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct REG_TZI_FORMAT
# Alias Names: _REG_TZI_FORMAT
# Alias Pointer Names:

def get_REG_TZI_FORMAT(uc: Uc, address: int, em: EMU):
    return REG_TZI_FORMAT.from_buffer_copy(uc.mem_read(address, sizeof(REG_TZI_FORMAT)))

# Struct Aliases:
# get__REG_TZI_FORMAT = get_REG_TZI_FORMAT

class REG_TZI_FORMAT(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['LONG', 'LONG', 'LONG', 'SYSTEMTIME', 'SYSTEMTIME']
    lookUps = {}
    
    # Struct Members
    Bias: LONG
    StandardBias: LONG
    DaylightBias: LONG
    StandardDate: SYSTEMTIME
    DaylightDate: SYSTEMTIME

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct STARTUPINFOA
# Alias Names:
# Alias Pointer Names: *LPSTARTUPINFOA

def get_STARTUPINFOA(uc: Uc, address: int, em: EMU):
        if em.arch == 32:
            return STARTUPINFOA.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(STARTUPINFOA.ARCH32)))
        else:
            return STARTUPINFOA.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(STARTUPINFOA.ARCH64)))

# Struct Pointers:
LPSTARTUPINFOA_32BIT = POINTER_32BIT
LPSTARTUPINFOA_64BIT = POINTER_64BIT

class STARTUPINFOA:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        lookUps = {11: ReverseLookUps.StartupInfo.flags}

        # Struct Members
        cb: DWORD
        lpReserved: LPSTR_32BIT
        lpDesktop: LPSTR_32BIT
        lpTitle: LPSTR_32BIT
        dwX: DWORD
        dwY: DWORD
        dwXSize: DWORD
        dwYSize: DWORD
        dwXCountChars: DWORD
        dwYCountChars: DWORD
        dwFillAttribute: DWORD
        dwFlags: DWORD
        wShowWindow: WORD
        hStdInput: HANDLE_32BIT
        hStdOutput: HANDLE_32BIT
        hStdError: HANDLE_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        lookUps = {11: ReverseLookUps.StartupInfo.flags}

        # Struct Members
        cb: DWORD
        lpReserved: LPSTR_64BIT
        lpDesktop: LPSTR_64BIT
        lpTitle: LPSTR_64BIT
        dwX: DWORD
        dwY: DWORD
        dwXSize: DWORD
        dwYSize: DWORD
        dwXCountChars: DWORD
        dwYCountChars: DWORD
        dwFillAttribute: DWORD
        dwFlags: DWORD
        wShowWindow: WORD
        hStdInput: HANDLE_64BIT
        hStdOutput: HANDLE_64BIT
        hStdError: HANDLE_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct STARTUPINFOW
# Alias Names: _STARTUPINFOW
# Alias Pointer Names: *LPSTARTUPINFOW

def get_STARTUPINFOW(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return STARTUPINFOW.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(STARTUPINFOW.ARCH32)))
    else:
        return STARTUPINFOW.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(STARTUPINFOW.ARCH64)))

# Struct Aliases:
# get__STARTUPINFOW = get_STARTUPINFOW

# Struct Pointers:
LPSTARTUPINFOW_32BIT = POINTER_32BIT
LPSTARTUPINFOW_64BIT = POINTER_64BIT

class STARTUPINFOW:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        lookUps = {11: ReverseLookUps.StartupInfo.flags}

        # Struct Members
        cb: DWORD
        lpReserved: LPWSTR_32BIT
        lpDesktop: LPWSTR_32BIT
        lpTitle: LPWSTR_32BIT
        dwX: DWORD
        dwY: DWORD
        dwXSize: DWORD
        dwYSize: DWORD
        dwXCountChars: DWORD
        dwYCountChars: DWORD
        dwFillAttribute: DWORD
        dwFlags: DWORD
        wShowWindow: WORD
        hStdInput: HANDLE_32BIT
        hStdOutput: HANDLE_32BIT
        hStdError: HANDLE_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        lookUps = {11: ReverseLookUps.StartupInfo.flags}

        # Struct Members
        cb: DWORD
        lpReserved: LPWSTR_64BIT
        lpDesktop: LPWSTR_64BIT
        lpTitle: LPWSTR_64BIT
        dwX: DWORD
        dwY: DWORD
        dwXSize: DWORD
        dwYSize: DWORD
        dwXCountChars: DWORD
        dwYCountChars: DWORD
        dwFillAttribute: DWORD
        dwFlags: DWORD
        wShowWindow: WORD
        hStdInput: HANDLE_64BIT
        hStdOutput: HANDLE_64BIT
        hStdError: HANDLE_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


# Struct OBJECT_ATTRIBUTES
# Alias Names: _OBJECT_ATTRIBUTES
# Alias Pointer Names: POBJECT_ATTRIBUTES

def get_OBJECT_ATTRIBUTES(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return OBJECT_ATTRIBUTES.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(OBJECT_ATTRIBUTES.ARCH32)))
    else:
        return OBJECT_ATTRIBUTES.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(OBJECT_ATTRIBUTES.ARCH64)))

# Struct Aliases:
# get__OBJECT_ATTRIBUTES = get_OBJECT_ATTRIBUTES

# Struct Pointers:
POBJECT_ATTRIBUTES_32BIT = POINTER_32BIT
POBJECT_ATTRIBUTES_64BIT = POINTER_64BIT

class OBJECT_ATTRIBUTES:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['ULONG', 'HANDLE', 'PUNICODE_STRING', 'ULONG', 'PVOID', 'PVOID']
        lookUps = {3: ReverseLookUps.ObjectAttributes.Attributes}

        # Struct Members
        Length: ULONG
        RootDirectory: HANDLE_32BIT
        ObjectName: PUNICODE_STRING_32BIT
        Attributes: ULONG
        SecurityDescriptor: PVOID_32BIT
        SecurityQualityOfService: PVOID_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['ULONG', 'HANDLE', 'PUNICODE_STRING', 'ULONG', 'PVOID', 'PVOID']
        lookUps = {3: ReverseLookUps.ObjectAttributes.Attributes}

        # Struct Members
        Length: ULONG
        RootDirectory: HANDLE_64BIT
        ObjectName: PUNICODE_STRING_64BIT
        Attributes: ULONG
        SecurityDescriptor: PVOID_64BIT
        SecurityQualityOfService: PVOID_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


def get_LARGE_INTEGER(uc: Uc, address: int, em: EMU):
    return LARGE_INTEGER.from_buffer_copy(uc.mem_read(address, sizeof(LARGE_INTEGER)))

# Struct Aliases:
# get__LARGE_INTEGER = get_LARGE_INTEGER

# Struct Pointers:
PLARGE_INTEGER_32BIT = POINTER_32BIT
PLARGE_INTEGER_64BIT = POINTER_64BIT

class LARGE_INTEGER_Helpers:
    class u(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD','LONG']
        lookUps = {}

        # Struct Members
        LowPart: DWORD
        HighPart: LONG

class LARGE_INTEGER(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
    types = ['struct','LONGLONG']
    lookUps = {}

    # Struct Members
    u: LARGE_INTEGER_Helpers.u
    QuadPart: LONGLONG

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

def get_ULARGE_INTEGER(uc: Uc, address: int, em: EMU):
    return LARGE_INTEGER.from_buffer_copy(uc.mem_read(address, sizeof(ULARGE_INTEGER)))

# Struct Aliases:
# get__ULARGE_INTEGER = get_ULARGE_INTEGER

# Struct Pointers:
PULARGE_INTEGER_32BIT = POINTER_32BIT
PULARGE_INTEGER_64BIT = POINTER_64BIT

class ULARGE_INTEGER_Helpers:
    class u(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD','DWORD']
        lookUps = {}

        # Struct Members
        LowPart: DWORD
        HighPart: DWORD

class ULARGE_INTEGER(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
    types = ['struct','ULONGLONG']
    lookUps = {}

    # Struct Members
    u: ULARGE_INTEGER_Helpers.u
    QuadPart: ULONGLONG

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct GUID
# Alias Names: _GUID
# Alias Pointer Names:

def get_GUID(uc: Uc, address: int, em: EMU):
    return GUID.from_buffer_copy(uc.mem_read(address, sizeof(GUID)))

# Struct Aliases:
# get__GUID = get_GUID

class GUID(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['ULONG', 'USHORT', 'USHORT', 'UCHAR']
    lookUps = {}

    # Struct Members
    Data1: ULONG
    Data2: USHORT
    Data3: USHORT
    Data4: UCHAR * 8

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct SECURITY_ATTRIBUTES
# Alias Names: _SECURITY_ATTRIBUTES
# Alias Pointer Names: *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES

def get_SECURITY_ATTRIBUTES(uc: Uc, address: int, em: EMU):
        if em.arch == 32:
            return SECURITY_ATTRIBUTES.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(SECURITY_ATTRIBUTES.ARCH32)))
        else:
            return SECURITY_ATTRIBUTES.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(SECURITY_ATTRIBUTES.ARCH64)))

# Struct Aliases:
# get__SECURITY_ATTRIBUTES = get_SECURITY_ATTRIBUTES

# Struct Pointers:
PSECURITY_ATTRIBUTES_32BIT = POINTER_32BIT
PSECURITY_ATTRIBUTES_64BIT = POINTER_64BIT
LPSECURITY_ATTRIBUTES_32BIT = POINTER_32BIT
LPSECURITY_ATTRIBUTES_64BIT = POINTER_64BIT

class SECURITY_ATTRIBUTES:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPVOID', 'BOOL']
        lookUps = {}

        # Struct Members
        nLength: DWORD
        lpSecurityDescriptor: LPVOID_32BIT
        bInheritHandle: BOOL

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPVOID', 'BOOL']
        lookUps = {}

        # Struct Members
        nLength: DWORD
        lpSecurityDescriptor: LPVOID_64BIT
        bInheritHandle: BOOL

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct value_entA
# Alias Names: VALENTA
# Alias Pointer Names: *PVALENTA

def get_value_entA(uc: Uc, address: int, em: EMU):
        if em.arch == 32:
            return value_entA.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(value_entA.ARCH32)))
        else:
            return value_entA.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(value_entA.ARCH64)))

# Struct Aliases:
get_VALENTA = get_value_entA

# Struct Pointers:
PVALENTA_32BIT = POINTER_32BIT
PVALENTA_64BIT = POINTER_64BIT

class value_entA:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['LPSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        lookUps = {}

        # Struct Members
        ve_valuename: LPSTR_32BIT
        ve_valuelen: DWORD
        ve_valueptr: DWORD_PTR_32BIT
        ve_type: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['LPSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        lookUps = {}

        # Struct Members
        ve_valuename: LPSTR_64BIT
        ve_valuelen: DWORD
        ve_valueptr: DWORD_PTR_64BIT
        ve_type: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct value_entW
# Alias Names: VALENTW
# Alias Pointer Names: *PVALENTW

def get_value_entW(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return value_entW.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(value_entW.ARCH32)))
    else:
        return value_entW.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(value_entW.ARCH64)))

# Struct Aliases:
get_VALENTW = get_value_entW

# Struct Pointers:
PVALENTW_32BIT = POINTER_32BIT
PVALENTW_64BIT = POINTER_64BIT

class value_entW:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['LPWSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        lookUps = {}

        # Struct Members
        ve_valuename: LPWSTR_32BIT
        ve_valuelen: DWORD
        ve_valueptr: DWORD_PTR_32BIT
        ve_type: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['LPWSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        lookUps = {}

        # Struct Members
        ve_valuename: LPWSTR_64BIT
        ve_valuelen: DWORD
        ve_valueptr: DWORD_PTR_64BIT
        ve_type: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct DISPLAY_DEVICEA
# Alias Names: _DISPLAY_DEVICEA
# Alias Pointer Names:  *PDISPLAY_DEVICEA, *LPDISPLAY_DEVICEA;

def get_DISPLAY_DEVICEA(uc: Uc, address: int, em: EMU):
    return DISPLAY_DEVICEA.from_buffer_copy(uc.mem_read(address, sizeof(DISPLAY_DEVICEA)))

# Struct Aliases:
# get__DISPLAY_DEVICEA = get_DISPLAY_DEVICEA

# Struct Pointers:
PDISPLAY_32BIT = POINTER_32BIT
PDISPLAY_64BIT = POINTER_64BIT
LPDISPLAY_32BIT = POINTER_32BIT
LPDISPLAY_64BIT = POINTER_64BIT

class DISPLAY_DEVICEA(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD','CHAR','CHAR','DWORD','CHAR','CHAR']
    lookUps = {}

    # Struct Members
    cb: DWORD
    DeviceName: CHAR * 32
    DeviceString: CHAR * 128
    StateFlags: DWORD
    DeviceID: CHAR * 128
    DeviceKey: CHAR * 128

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

    def screenDC(self):
        self.cb = sizeof(self)
        self.DeviceName = '\\\\.\\DISPLAY1\\Monitor0'
        self.DeviceString = 'GENEREIC PNP MONITOR'
        self.StateFlags = 0x1
        #self.DeviceID = not used
        #self.DeviceKey = reserved

# Struct DISPLAY_DEVICEW
# Alias Names: _DISPLAY_DEVICEW
# Alias Pointer Names: PDISPLAY_DEVICEW, LPDISPLAY_DEVICEW

def get_DISPLAY_DEVICEW(uc: Uc, address: int, em: EMU):
    return DISPLAY_DEVICEW.from_buffer_copy(uc.mem_read(address, sizeof(DISPLAY_DEVICEW)))

# Struct Aliases:
# get__DISPLAY_DEVICEW = get_DISPLAY_DEVICEW

# Struct Pointers:
PDISPLAY_DEVICEW_32BIT = POINTER_32BIT
PDISPLAY_DEVICEW_64BIT = POINTER_64BIT
LPDISPLAY_DEVICEW_32BIT = POINTER_32BIT
LPDISPLAY_DEVICEW_64BIT = POINTER_64BIT

class DISPLAY_DEVICEW(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'WCHAR', 'WCHAR', 'DWORD', 'WCHAR', 'WCHAR']
    lookUps = {}

    # Struct Members
    cb: DWORD
    DeviceName: WCHAR * 32
    DeviceString: WCHAR * 128
    StateFlags: DWORD
    DeviceID: WCHAR * 128
    DeviceKey: WCHAR * 128

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

    def screenDC(self):
        self.cb = sizeof(self)
        self.DeviceName = '\\\\.\\DISPLAY1\\Monitor0'
        self.DeviceString = 'GENEREIC PNP MONITOR'
        self.StateFlags = 0x1
        #self.DeviceID = not used
        #self.DeviceKey = reserved


## Struct VIDEOPARAMETERS 
## Alias Names: _VIDEOPARAMETERS
## Alias Pointer Names: *PVIDEOPARAMETERS

#def get_VIDEOPARAMETERS(uc: Uc, address: int, em: EMU):
#    return VIDEOPARAMETERS.from_buffer_copy(uc.mem_read(address, sizeof(VIDEOPARAMETERS)))

## Struct Aliases:
## get__VIDEOPARAMETERS = get_VIDEOPARAMETERS

## Struct Pointers:
#PVIDEOPARAMETERS_32BIT = POINTER_32BIT
#PVIDEOPARAMETERS_64BIT = POINTER_64BIT

#class VIDEOPARAMETERS (LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
#    types = ['GUID','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','UCHAR']
#    names = ['guid','dwOffset','dwCommand','dwFlags','dwMode','dwTVStandard','dwAvailableModes','dwAvailableTVStandard','dwFlickerFilter','dwOverScanX','dwOverScanY','dwMaxUnscaledX','dwMaxUnscaledY','dwPositionX','dwPositionY','dwBrightness','dwContrast','dwCPType','dwCPCommand','dwCPStandard','dwCPKey','bCP_APSTriggerBits','bOEMCopyProtection']
#    __slots__ = ('guid','dwOffset','dwCommand','dwFlags','dwMode','dwTVStandard','dwAvailableModes','dwAvailableTVStandard','dwFlickerFilter','dwOverScanX','dwOverScanY','dwMaxUnscaledX','dwMaxUnscaledY','dwPositionX','dwPositionY','dwBrightness','dwContrast','dwCPType','dwCPCommand','dwCPStandard','dwCPKey','bCP_APSTriggerBits','bOEMCopyProtection')
#    _fields_ = [('guid', GUID ),('dwOffset', ULONG),('dwCommand', ULONG),('dwFlags', ULONG),('dwMode', ULONG),('dwTVStandard', ULONG),('dwAvailableModes', ULONG),('dwAvailableTVStandard', ULONG),('dwFlickerFilter', ULONG),('dwOverScanX', ULONG),('dwOverScanY', ULONG),('dwMaxUnscaledX', ULONG),('dwMaxUnscaledY', ULONG),('dwPositionX', ULONG),('dwPositionY', ULONG),('dwBrightness', ULONG),('dwContrast', ULONG),('dwCPType', ULONG),('dwCPCommand', ULONG),('dwCPStandard', ULONG),('dwCPKey', ULONG),('bCP_APSTriggerBits', ULONG),('bOEMCopyProtection', UCHAR*256)]

#    def writeToMemory(self, uc: Uc, address: int):
#        uc.mem_write(address, bytes(self))


# Struct _SHELLEXECUTEINFOA
# Alias Names: SHELLEXECUTEINFOA
# Alias Pointer Names: *LPSHELLEXECUTEINFOA

def get_SHELLEXECUTEINFOA(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return SHELLEXECUTEINFOA.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(SHELLEXECUTEINFOA.ARCH32)))
    else:
        return SHELLEXECUTEINFOA.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(SHELLEXECUTEINFOA.ARCH64)))

# Struct Aliases:
# get__SHELLEXECUTEINFOA = get_SHELLEXECUTEINFOA

# Struct Pointers:
LPSHELLEXECUTEINFOA_32BIT = POINTER_32BIT
LPSHELLEXECUTEINFOA_64BIT = POINTER_64BIT

class SHELLEXECUTEINFOA_Helpers:
    # Sub Structures/Unions
    class Union_32BIT(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE']
        lookUps = {}

        # Struct Members
        hIcon: HANDLE_32BIT
        hMonitor: HANDLE_32BIT

    class Union_64BIT(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE']
        lookUps = {}

        # Struct Members
        hIcon: HANDLE_64BIT
        hMonitor: HANDLE_64BIT

class SHELLEXECUTEINFOA:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'int', 'HINSTANCE', 'void', 'LPCSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        # Struct Members
        cbSize: DWORD
        fMask: ULONG
        hwnd: HWND_32BIT
        lpVerb: LPCSTR_32BIT
        lpFile: LPCSTR_32BIT
        lpParameters: LPCSTR_32BIT
        lpDirectory: LPCSTR_32BIT
        nShow: INT
        hInstApp: HINSTANCE_32BIT
        lpIDList: PVOID_32BIT
        lpClass: LPCSTR_32BIT
        hkeyClass: HKEY_32BIT
        dwHotKey: DWORD
        DUMMYUNIONNAME: SHELLEXECUTEINFOA_Helpers.Union_32BIT
        hProcess: HANDLE_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'int', 'HINSTANCE', 'void', 'LPCSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        # Struct Members
        cbSize: DWORD
        fMask: ULONG
        hwnd: HWND_64BIT
        lpVerb: LPCSTR_64BIT
        lpFile: LPCSTR_64BIT
        lpParameters: LPCSTR_64BIT
        lpDirectory: LPCSTR_64BIT
        nShow: INT
        hInstApp: HINSTANCE_64BIT
        lpIDList: PVOID_64BIT
        lpClass: LPCSTR_64BIT
        hkeyClass: HKEY_64BIT
        dwHotKey: DWORD
        DUMMYUNIONNAME: SHELLEXECUTEINFOA_Helpers.Union_64BIT
        hProcess: HANDLE_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct _SHELLEXECUTEINFOW
# Alias Names: SHELLEXECUTEINFOW
# Alias Pointer Names: *LPSHELLEXECUTEINFOW

def get_SHELLEXECUTEINFOW(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return SHELLEXECUTEINFOW.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(SHELLEXECUTEINFOW.ARCH32)))
    else:
        return SHELLEXECUTEINFOW.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(SHELLEXECUTEINFOW.ARCH64)))

# Struct Aliases:
# get__SHELLEXECUTEINFOW = get_SHELLEXECUTEINFOW

# Struct Pointers:
LPSHELLEXECUTEINFOW_32BIT = POINTER_32BIT
LPSHELLEXECUTEINFOW_64BIT = POINTER_64BIT

class SHELLEXECUTEINFOW_Helpers:
    # Sub Structures/Unions
    class Union_32BIT(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE']
        lookUps = {}

        # Union Members
        hIcon: HANDLE_32BIT
        hMonitor: HANDLE_32BIT

    class Union_64BIT(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE']
        lookUps = {}

        # Union Members
        hIcon: HANDLE_64BIT
        hMonitor: HANDLE_64BIT

class SHELLEXECUTEINFOW:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'int', 'HINSTANCE', 'void', 'LPCWSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        # Struct Members
        cbSize: DWORD
        fMask: ULONG
        hwnd: HWND_32BIT
        lpVerb: LPCWSTR_32BIT
        lpFile: LPCWSTR_32BIT
        lpParameters: LPCWSTR_32BIT
        lpDirectory: LPCWSTR_32BIT
        nShow: INT
        hInstApp: HINSTANCE_32BIT
        lpIDList: PVOID_32BIT
        lpClass: LPCWSTR_32BIT
        hkeyClass: HKEY_32BIT
        dwHotKey: DWORD
        DUMMYUNIONNAME: SHELLEXECUTEINFOW_Helpers.Union_32BIT
        hProcess: HANDLE_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'int', 'HINSTANCE', 'void', 'LPCWSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        # Struct Members
        cbSize: DWORD
        fMask: ULONG
        hwnd: HWND_64BIT
        lpVerb: LPCWSTR_64BIT
        lpFile: LPCWSTR_64BIT
        lpParameters: LPCWSTR_64BIT
        lpDirectory: LPCWSTR_64BIT
        nShow: INT
        hInstApp: HINSTANCE_64BIT
        lpIDList: PVOID_64BIT
        lpClass: LPCWSTR_64BIT
        hkeyClass: HKEY_64BIT
        dwHotKey: DWORD
        DUMMYUNIONNAME: SHELLEXECUTEINFOW_Helpers.Union_64BIT
        hProcess: HANDLE_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct WSAPROTOCOLCHAIN
# Alias Names: _WSAPROTOCOLCHAIN
# Alias Pointer Names: LPWSAPROTOCOLCHAIN

def get_WSAPROTOCOLCHAIN(uc: Uc, address: int, em: EMU):
    return WSAPROTOCOLCHAIN.from_buffer_copy(uc.mem_read(address, sizeof(WSAPROTOCOLCHAIN)))

# Struct Aliases:
# get__WSAPROTOCOLCHAIN = get_WSAPROTOCOLCHAIN

# Struct Pointers:
LPWSAPROTOCOLCHAIN_32BIT = POINTER_32BIT
LPWSAPROTOCOLCHAIN_64BIT = POINTER_64BIT

class WSAPROTOCOLCHAIN(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['int', 'DWORD']
    lookUps = {}

    # Struct Members
    ChainLen: INT
    ChainEntries: DWORD * 7

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct WSAPROTOCOL_INFOA
# Alias Names: _WSAPROTOCOL_INFOA
# Alias Pointer Names: LPWSAPROTOCOL_INFOA

def get_WSAPROTOCOL_INFOA(uc: Uc, address: int, em: EMU):
    return WSAPROTOCOL_INFOA.from_buffer_copy(uc.mem_read(address, sizeof(WSAPROTOCOL_INFOA)))

# Struct Aliases:
# get__WSAPROTOCOL_INFOA = get_WSAPROTOCOL_INFOA

# Struct Pointers:
LPWSAPROTOCOL_INFOA_32BIT = POINTER_32BIT
LPWSAPROTOCOL_INFOA_64BIT = POINTER_64BIT

class WSAPROTOCOL_INFOA(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'GUID', 'DWORD', 'WSAPROTOCOLCHAIN', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'DWORD', 'DWORD', 'CHAR']
    lookUps = {0: ReverseLookUps.Socket.ServiceFlags, 9: ReverseLookUps.Socket.Af, 12: ReverseLookUps.Socket.Type, 13: ReverseLookUps.Socket.Protocol, 15: ReverseLookUps.Socket.NetworkByteOrder, 16: ReverseLookUps.Socket.SecurityScheme}

    # Struct Members
    dwServiceFlags1: DWORD
    dwServiceFlags2: DWORD
    dwServiceFlags3: DWORD
    dwServiceFlags4: DWORD
    dwProviderFlags: DWORD
    ProviderId: GUID
    dwCatalogEntryId: DWORD
    ProtocolChain: WSAPROTOCOLCHAIN
    iVersion: INT
    iAddressFamily: INT
    iMaxSockAddr: INT
    iMinSockAddr: INT
    iSocketType: INT
    iProtocol: INT
    iProtocolMaxOffset: INT
    iNetworkByteOrder: INT
    iSecurityScheme: INT
    dwMessageSize: DWORD
    dwProviderReserved: DWORD
    szProtocol: CHAR*256

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct WSAPROTOCOL_INFOW
# Alias Names: _WSAPROTOCOL_INFOW
# Alias Pointer Names: LPWSAPROTOCOL_INFOW

def get_WSAPROTOCOL_INFOW(uc: Uc, address: int, em: EMU):
    return WSAPROTOCOL_INFOW.from_buffer_copy(uc.mem_read(address, sizeof(WSAPROTOCOL_INFOW)))

# Struct Aliases:
# get__WSAPROTOCOL_INFOW = get_WSAPROTOCOL_INFOW

# Struct Pointers:
LPWSAPROTOCOL_INFOW_32BIT = POINTER_32BIT
LPWSAPROTOCOL_INFOW_64BIT = POINTER_64BIT

class WSAPROTOCOL_INFOW(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'GUID', 'DWORD', 'WSAPROTOCOLCHAIN', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'DWORD', 'DWORD', 'WCHAR']
    lookUps = {0: ReverseLookUps.Socket.ServiceFlags, 9: ReverseLookUps.Socket.Af, 12: ReverseLookUps.Socket.Type, 13: ReverseLookUps.Socket.Protocol, 15: ReverseLookUps.Socket.NetworkByteOrder, 16: ReverseLookUps.Socket.SecurityScheme}

    # Struct Members
    dwServiceFlags1: DWORD
    dwServiceFlags2: DWORD
    dwServiceFlags3: DWORD
    dwServiceFlags4: DWORD
    dwProviderFlags: DWORD
    ProviderId: GUID
    dwCatalogEntryId: DWORD
    ProtocolChain: WSAPROTOCOLCHAIN
    iVersion: INT
    iAddressFamily: INT
    iMaxSockAddr: INT
    iMinSockAddr: INT
    iSocketType: INT
    iProtocol: INT
    iProtocolMaxOffset: INT
    iNetworkByteOrder: INT
    iSecurityScheme: INT
    dwMessageSize: DWORD
    dwProviderReserved: DWORD
    szProtocol: WCHAR*256

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct OVERLAPPED 
# Alias Names: _OVERLAPPED
# Alias Pointer Names: LPWSAPROTOCOL_INFOW

# def get_OVERLAPPED(uc: Uc, address: int, em: EMU):
    # return OVERLAPPED.from_buffer_copy(uc.mem_read(address, sizeof(OVERLAPPED)))

# Struct Aliases:
# get__OVERLAPPED = get_OVERLAPPED

# Struct Pointers:
# LPWSAPROTOCOL_INFOW_32BIT = POINTER_32BIT
# LPWSAPROTOCOL_INFOW_64BIT = POINTER_64BIT
# class OVERLAPPED_Helpers:
#     #sub structures
#     class dummyStruct(LittleEndianUnion):
#         types = ['DWORD', 'DWORD']
#         __slots__ = ('Offset', 'OffsetHigh')
#         lookUps = {}
#         _fields_ = [('Offset',DWORD),('OffsetHigh',DWORD)]
#     class dummyUnion(LittleEndianUnion):
#         types = ['union', 'PVOID']
#         __slots__ = ('DUMMYSTRUCTNAME', 'Pointer')
#         lookUps = {}
#         _fields_ = [('DUMMYSTRUCTNAME',OVERLAPPED_Helpers.dummyStruct),('Pointer',PVOID)]

# class OVERLAPPED(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
#     types = ['ULONG_PTR', 'ULONG_PTR', 'union', 'HANDLE']
#     __slots__ = ('Internal','InternalHigh','DUMMYUNIONNAME','hEvent')
#     lookUps = {}
#     _fields_ = [('Internal',ULONG_PTR),('InternalHigh',ULONG_PTR),(DUMMYUNIONNAME,OVERLAPPED_Helpers.dummyUnion),('hEvent',HANDLE)]

#     def writeToMemory(self, uc: Uc, address: int):
#         uc.mem_write(address, bytes(self))

# Struct WIN32_FIND_DATAA 
# Alias Names: _WIN32_FIND_DATAA
# Alias Pointer Names: WIN32_FIND_DATAA

def get_WIN32_FIND_DATAA(uc: Uc, address: int, em: EMU):
    return WIN32_FIND_DATAA.from_buffer_copy(uc.mem_read(address, sizeof(WIN32_FIND_DATAA)))

# Struct Aliases:
# get__OVERLAPPED = get_OVERLAPPED

# Struct Pointers:
# LPWSAPROTOCOL_INFOW_32BIT = POINTER_32BIT
# LPWSAPROTOCOL_INFOW_64BIT = POINTER_64BIT

class WIN32_FIND_DATAA(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD','FILETIME','FILETIME','FILETIME','DWORD','DWORD','DWORD','DWORD','WCHAR','WCHAR','DWORD','DWORD','WORD']
    lookUps = {}
    #dwFileAttributes -> ReverseLookup from the files class
    #create some file time structures for the next three
    #Highword/lowword file size, if need help getting high low look @ filetime as filetime where it split the time into high and low
    #cFileName = fileName, get this from the handle/filesystem
    #Alt file name 1 period, no spaces, 1-8 characters in length followed by extension[1-3 length]
    
    # Struct Members
    dwFileAttributes: DWORD
    ftCreationTime: FILETIME
    ftLastAccessTime: FILETIME
    ftLastWriteTime: FILETIME
    nFileSizeHigh: DWORD
    nFileSizeLow: DWORD
    dwReserved0: DWORD
    dwReserved1: DWORD
    cFileName: CHAR * MAX_PATH
    cAlternateFileName: CHAR * 14
    # dwFileType: DWORD # Obsolete Member that would be used on MacOS
    # dwCreatorType: DWORD # Obsolete Member that would be used on MacOS
    # wFinderFlags: WORD # Obsolete Member that would be used on MacOS

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

    # def fileReturn(self,timeB1,timeB2,timeb3,filesize,filename,altFileName):
    #     self.dwFileAttributes = 0x80 #normal
    #     self.ftCreationTime = get_FILETIME(uc,buffer1,em)
    #     self.ftLastAccessTime = get_FILETIME(uc,buffer2,em)
    #     self.ftLastWriteTime = get_FILETIME(uc,buffer3,em)
    #     self.nFileSizeHigh = filesize >> 32
    #     self.nFileSizeLow = filesize & 0xffffffff
    #     self.cFileName = filename
    #     self.cAlternateFileName = altFileName

# Struct WIN32_FIND_DATAW
# Alias Names: _WIN32_FIND_DATAW
# Alias Pointer Names: *PWIN32_FIND_DATAW, *LPWIN32_FIND_DATAW

def get_WIN32_FIND_DATAW(uc: Uc, address: int, em: EMU):
    return WIN32_FIND_DATAW.from_buffer_copy(uc.mem_read(address, sizeof(WIN32_FIND_DATAW)))

# Struct Aliases:
# get__WIN32_FIND_DATAW = get_WIN32_FIND_DATAW

# Struct Pointers:
PWIN32_FIND_DATAW_32BIT = POINTER_32BIT
PWIN32_FIND_DATAW_64BIT = POINTER_64BIT
LPWIN32_FIND_DATAW_32BIT = POINTER_32BIT
LPWIN32_FIND_DATAW_64BIT = POINTER_64BIT

class WIN32_FIND_DATAW(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'FILETIME', 'FILETIME', 'FILETIME', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WCHAR', 'WCHAR', 'DWORD', 'DWORD','WORD']
    lookUps = {}

    # Struct Members
    dwFileAttributes: DWORD
    ftCreationTime: FILETIME
    ftLastAccessTime: FILETIME
    ftLastWriteTime: FILETIME
    nFileSizeHigh: DWORD
    nFileSizeLow: DWORD
    dwReserved0: DWORD
    dwReserved1: DWORD
    cFileName: WCHAR * MAX_PATH
    cAlternateFileName: WCHAR * 14
    # dwFileType: DWORD # Obsolete Member that would be used on MacOS
    # dwCreatorType: DWORD # Obsolete Member that would be used on MacOS
    # wFinderFlags: WORD # Obsolete Member that would be used on MacOS

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct NETRESOURCEA
# Alias Names: _NETRESOURCEA
# Alias Pointer Names: LPNETRESOURCEA

def get_NETRESOURCEA(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return NETRESOURCEA.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(NETRESOURCEA.ARCH32)))
    else:
        return NETRESOURCEA.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(NETRESOURCEA.ARCH64)))

# Struct Aliases:
# get__NETRESOURCEA = get_NETRESOURCEA

# Struct Pointers:
LPNETRESOURCEA_32BIT = POINTER_32BIT
LPNETRESOURCEA_64BIT = POINTER_64BIT

class NETRESOURCEA:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'LPSTR']
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        # Struct Members
        dwScope: DWORD
        dwType: DWORD
        dwDisplayType: DWORD
        dwUsage: DWORD
        lpLocalName: LPSTR_32BIT
        lpRemoteName: LPSTR_32BIT
        lpComment: LPSTR_32BIT
        lpProvider: LPSTR_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'LPSTR']
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        # Struct Members
        dwScope: DWORD
        dwType: DWORD
        dwDisplayType: DWORD
        dwUsage: DWORD
        lpLocalName: LPSTR_64BIT
        lpRemoteName: LPSTR_64BIT
        lpComment: LPSTR_64BIT
        lpProvider: LPSTR_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct NETRESOURCEW
# Alias Names: _NETRESOURCEW
# Alias Pointer Names: LPNETRESOURCEW

def get_NETRESOURCEW(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return NETRESOURCEW.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(NETRESOURCEW.ARCH32)))
    else:
        return NETRESOURCEW.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(NETRESOURCEW.ARCH64)))

# Struct Aliases:
# get__NETRESOURCEW = get_NETRESOURCEW

# Struct Pointers:
LPNETRESOURCEW_32BIT = POINTER_32BIT
LPNETRESOURCEW_64BIT = POINTER_64BIT

class NETRESOURCEW:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'LPWSTR']
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        # Struct Members
        dwScope: DWORD
        dwType: DWORD
        dwDisplayType: DWORD
        dwUsage: DWORD
        lpLocalName: LPWSTR_32BIT
        lpRemoteName: LPWSTR_32BIT
        lpComment: LPWSTR_32BIT
        lpProvider: LPWSTR_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'LPWSTR']
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        # Struct Members
        dwScope: DWORD
        dwType: DWORD
        dwDisplayType: DWORD
        dwUsage: DWORD
        lpLocalName: LPWSTR_64BIT
        lpRemoteName: LPWSTR_64BIT
        lpComment: LPWSTR_64BIT
        lpProvider: LPWSTR_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


# Struct OSVERSIONINFOA
# Alias Names: _OSVERSIONINFOA
# Alias Pointer Names: POSVERSIONINFOA, LPOSVERSIONINFOA

def get_OSVERSIONINFOA(uc: Uc, address: int, em: EMU):
    return OSVERSIONINFOA.from_buffer_copy(uc.mem_read(address, sizeof(OSVERSIONINFOA)))

# Struct Aliases:
# get__OSVERSIONINFOA = get_OSVERSIONINFOA

# Struct Pointers:
POSVERSIONINFOA_32BIT = POINTER_32BIT
POSVERSIONINFOA_64BIT = POINTER_64BIT
LPOSVERSIONINFOA_32BIT = POINTER_32BIT
LPOSVERSIONINFOA_64BIT = POINTER_64BIT

class OSVERSIONINFOA(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'CHAR']
    lookUps = {}

    # Struct Members
    dwOSVersionInfoSize: DWORD
    dwMajorVersion: DWORD
    dwMinorVersion: DWORD
    dwBuildNumber: DWORD
    dwPlatformId: DWORD
    szCSDVersion: CHAR * 128

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct OSVERSIONINFOW
# Alias Names: _OSVERSIONINFOW, RTL_OSVERSIONINFOW
# Alias Pointer Names: POSVERSIONINFOW, LPOSVERSIONINFOW, PRTL_OSVERSIONINFOW

def get_OSVERSIONINFOW(uc: Uc, address: int, em: EMU):
    return OSVERSIONINFOW.from_buffer_copy(uc.mem_read(address, sizeof(OSVERSIONINFOW)))

# Struct Aliases:
# get__OSVERSIONINFOW = get_OSVERSIONINFOW
# get_RTL_OSVERSIONINFOW = get_OSVERSIONINFOW

# Struct Pointers:
POSVERSIONINFOW_32BIT = POINTER_32BIT
POSVERSIONINFOW_64BIT = POINTER_64BIT
LPOSVERSIONINFOW_32BIT = POINTER_32BIT
LPOSVERSIONINFOW_64BIT = POINTER_64BIT
PRTL_OSVERSIONINFOW_32BIT = POINTER_32BIT
PRTL_OSVERSIONINFOW_64BIT = POINTER_64BIT

class OSVERSIONINFOW(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WCHAR']
    lookUps = {}

    # Struct Members
    dwOSVersionInfoSize: DWORD
    dwMajorVersion: DWORD
    dwMinorVersion: DWORD
    dwBuildNumber: DWORD
    dwPlatformId: DWORD
    szCSDVersion: WCHAR * 128

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct OSVERSIONINFOEXA
# Alias Names: _OSVERSIONINFOEXA
# Alias Pointer Names: POSVERSIONINFOEXA, LPOSVERSIONINFOEXA

def get_OSVERSIONINFOEXA(uc: Uc, address: int, em: EMU):
    return OSVERSIONINFOEXA.from_buffer_copy(uc.mem_read(address, sizeof(OSVERSIONINFOEXA)))

# Struct Aliases:
# get__OSVERSIONINFOEXA = get_OSVERSIONINFOEXA

# Struct Pointers:
POSVERSIONINFOEXA_32BIT = POINTER_32BIT
POSVERSIONINFOEXA_64BIT = POINTER_64BIT
LPOSVERSIONINFOEXA_32BIT = POINTER_32BIT
LPOSVERSIONINFOEXA_64BIT = POINTER_64BIT

class OSVERSIONINFOEXA(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'CHAR', 'WORD', 'WORD', 'WORD', 'BYTE', 'BYTE']
    lookUps = {}

    # Struct Members
    dwOSVersionInfoSize: DWORD
    dwMajorVersion: DWORD
    dwMinorVersion: DWORD
    dwBuildNumber: DWORD
    dwPlatformId: DWORD
    szCSDVersion: CHAR * 128
    wServicePackMajor: WORD
    wServicePackMinor: WORD
    wSuiteMask: WORD
    wProductType: BYTE
    wReserved: BYTE

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct OSVERSIONINFOEXW
# Alias Names: _OSVERSIONINFOEXW, RTL_OSVERSIONINFOEXW
# Alias Pointer Names: POSVERSIONINFOEXW, LPOSVERSIONINFOEXW, PRTL_OSVERSIONINFOEXW

def get_OSVERSIONINFOEXW(uc: Uc, address: int, em: EMU):
    return OSVERSIONINFOEXW.from_buffer_copy(uc.mem_read(address, sizeof(OSVERSIONINFOEXW)))

# Struct Aliases:
# get__OSVERSIONINFOEXW = get_OSVERSIONINFOEXW
# get_RTL_OSVERSIONINFOEXW = get_OSVERSIONINFOEXW

# Struct Pointers:
POSVERSIONINFOEXW_32BIT = POINTER_32BIT
POSVERSIONINFOEXW_64BIT = POINTER_64BIT
LPOSVERSIONINFOEXW_32BIT = POINTER_32BIT
LPOSVERSIONINFOEXW_64BIT = POINTER_64BIT
PRTL_OSVERSIONINFOEXW_32BIT = POINTER_32BIT
PRTL_OSVERSIONINFOEXW_64BIT = POINTER_64BIT

class OSVERSIONINFOEXW(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WCHAR', 'WORD', 'WORD', 'WORD', 'BYTE', 'BYTE']
    lookUps = {}

    # Struct Members
    dwOSVersionInfoSize: DWORD
    dwMajorVersion: DWORD
    dwMinorVersion: DWORD
    dwBuildNumber: DWORD
    dwPlatformId: DWORD
    szCSDVersion: WCHAR * 128
    wServicePackMajor: WORD
    wServicePackMinor: WORD
    wSuiteMask: WORD
    wProductType: BYTE
    wReserved: BYTE

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct CREATEFILE2_EXTENDED_PARAMETERS
# Alias Names: _CREATEFILE2_EXTENDED_PARAMETERS
# Alias Pointer Names: PCREATEFILE2_EXTENDED_PARAMETERS, LPCREATEFILE2_EXTENDED_PARAMETERS

def get_CREATEFILE2_EXTENDED_PARAMETERS(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return CREATEFILE2_EXTENDED_PARAMETERS.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(CREATEFILE2_EXTENDED_PARAMETERS.ARCH32)))
    else:
        return CREATEFILE2_EXTENDED_PARAMETERS.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(CREATEFILE2_EXTENDED_PARAMETERS.ARCH64)))

# Struct Aliases:
# get__CREATEFILE2_EXTENDED_PARAMETERS = get_CREATEFILE2_EXTENDED_PARAMETERS

# Struct Pointers:
PCREATEFILE2_EXTENDED_PARAMETERS_32BIT = POINTER_32BIT
PCREATEFILE2_EXTENDED_PARAMETERS_64BIT = POINTER_64BIT
LPCREATEFILE2_EXTENDED_PARAMETERS_32BIT = POINTER_32BIT
LPCREATEFILE2_EXTENDED_PARAMETERS_64BIT = POINTER_64BIT

class CREATEFILE2_EXTENDED_PARAMETERS:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES', 'HANDLE']
        lookUps = {} # need lookups

        # Struct Members
        dwSize: DWORD
        dwFileAttributes: DWORD
        dwFileFlags: DWORD
        dwSecurityQosFlags: DWORD
        lpSecurityAttributes: LPSECURITY_ATTRIBUTES_32BIT
        hTemplateFile: HANDLE_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSECURITY_ATTRIBUTES', 'HANDLE']
        lookUps = {} # need lookups

        # Struct Members
        dwSize: DWORD
        dwFileAttributes: DWORD
        dwFileFlags: DWORD
        dwSecurityQosFlags: DWORD
        lpSecurityAttributes: LPSECURITY_ATTRIBUTES_64BIT
        hTemplateFile: HANDLE_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Pointer Param for COPYFILE2_EXTENDED_PARAMETERS
PCOPYFILE2_PROGRESS_ROUTINE_32BIT = POINTER_32BIT
PCOPYFILE2_PROGRESS_ROUTINE_64BIT = POINTER_64BIT

# Struct COPYFILE2_EXTENDED_PARAMETERS
# Alias Names: _COPYFILE2_EXTENDED_PARAMETERS
# Alias Pointer Names:

def get_COPYFILE2_EXTENDED_PARAMETERS(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return COPYFILE2_EXTENDED_PARAMETERS.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(COPYFILE2_EXTENDED_PARAMETERS.ARCH32)))
    else:
        return COPYFILE2_EXTENDED_PARAMETERS.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(COPYFILE2_EXTENDED_PARAMETERS.ARCH64)))

# Struct Aliases:
# get__COPYFILE2_EXTENDED_PARAMETERS = get_COPYFILE2_EXTENDED_PARAMETERS

class COPYFILE2_EXTENDED_PARAMETERS:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'BOOL', 'PCOPYFILE2_PROGRESS_ROUTINE', 'PVOID']
        lookUps = {} # Need Lookups

        # Struct Members
        dwSize: DWORD
        dwCopyFlags: DWORD
        pfCancel: BOOL
        pProgressRoutine: PCOPYFILE2_PROGRESS_ROUTINE_32BIT
        pvCallbackContext: PVOID_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'DWORD', 'BOOL', 'PCOPYFILE2_PROGRESS_ROUTINE', 'PVOID']
        lookUps = {} # Need Lookups

        # Struct Members
        dwSize: DWORD
        dwCopyFlags: DWORD
        pfCancel: BOOL
        pProgressRoutine: PCOPYFILE2_PROGRESS_ROUTINE_64BIT
        pvCallbackContext: PVOID_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct INTERNET_BUFFERSA
# Alias Names: _INTERNET_BUFFERSA
# Alias Pointer Names: LPINTERNET_BUFFERSA

def get_INTERNET_BUFFERSA(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return INTERNET_BUFFERSA.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_BUFFERSA.ARCH32)))
    else:
        return INTERNET_BUFFERSA.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_BUFFERSA.ARCH64)))

# Struct Aliases:
# get__INTERNET_BUFFERSA = get_INTERNET_BUFFERSA

# Struct Pointers:
LPINTERNET_BUFFERSA_32BIT = POINTER_32BIT
LPINTERNET_BUFFERSA_64BIT = POINTER_64BIT

class INTERNET_BUFFERSA:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPINTERNET_BUFFERSA', 'LPCSTR', 'DWORD', 'DWORD', 'LPVOID', 'DWORD', 'DWORD', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        dwStructSize: DWORD
        Next: LPINTERNET_BUFFERSA_32BIT
        lpcszHeader: LPCSTR_32BIT
        dwHeadersLength: DWORD
        dwHeadersTotal: DWORD
        lpvBuffer: LPVOID_32BIT
        dwBufferLength: DWORD
        dwBufferTotal: DWORD
        dwOffsetLow: DWORD
        dwOffsetHigh: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPINTERNET_BUFFERSA', 'LPCSTR', 'DWORD', 'DWORD', 'LPVOID', 'DWORD', 'DWORD', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        dwStructSize: DWORD
        Next: LPINTERNET_BUFFERSA_64BIT
        lpcszHeader: LPCSTR_64BIT
        dwHeadersLength: DWORD
        dwHeadersTotal: DWORD
        lpvBuffer: LPVOID_64BIT
        dwBufferLength: DWORD
        dwBufferTotal: DWORD
        dwOffsetLow: DWORD
        dwOffsetHigh: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct INTERNET_BUFFERSW
# Alias Names: _INTERNET_BUFFERSW
# Alias Pointer Names: LPINTERNET_BUFFERSW

def get_INTERNET_BUFFERSW(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return INTERNET_BUFFERSW.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_BUFFERSW.ARCH32)))
    else:
        return INTERNET_BUFFERSW.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_BUFFERSW.ARCH64)))

# Struct Aliases:
# get__INTERNET_BUFFERSW = get_INTERNET_BUFFERSW

# Struct Pointers:
LPINTERNET_BUFFERSW_32BIT = POINTER_32BIT
LPINTERNET_BUFFERSW_64BIT = POINTER_64BIT

class INTERNET_BUFFERSW:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPINTERNET_BUFFERSW', 'LPCWSTR', 'DWORD', 'DWORD', 'LPVOID', 'DWORD', 'DWORD', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        dwStructSize: DWORD
        Next: LPINTERNET_BUFFERSW_32BIT
        lpcszHeader: LPCWSTR_32BIT
        dwHeadersLength: DWORD
        dwHeadersTotal: DWORD
        lpvBuffer: LPVOID_32BIT
        dwBufferLength: DWORD
        dwBufferTotal: DWORD
        dwOffsetLow: DWORD
        dwOffsetHigh: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPINTERNET_BUFFERSW', 'LPCWSTR', 'DWORD', 'DWORD', 'LPVOID', 'DWORD', 'DWORD', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        dwStructSize: DWORD
        Next: LPINTERNET_BUFFERSW_64BIT
        lpcszHeader: LPCWSTR_64BIT
        dwHeadersLength: DWORD
        dwHeadersTotal: DWORD
        lpvBuffer: LPVOID_64BIT
        dwBufferLength: DWORD
        dwBufferTotal: DWORD
        dwOffsetLow: DWORD
        dwOffsetHigh: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct MEMORY_PRIORITY_INFORMATION
# Alias Names: _MEMORY_PRIORITY_INFORMATION
# Alias Pointer Names: PMEMORY_PRIORITY_INFORMATION

def get_MEMORY_PRIORITY_INFORMATION(uc: Uc, address: int, em: EMU):
    return MEMORY_PRIORITY_INFORMATION.from_buffer_copy(uc.mem_read(address, sizeof(MEMORY_PRIORITY_INFORMATION)))

# Struct Aliases:
# get__MEMORY_PRIORITY_INFORMATION = get_MEMORY_PRIORITY_INFORMATION

# Struct Pointers:
PMEMORY_PRIORITY_INFORMATION_32BIT = POINTER_32BIT
PMEMORY_PRIORITY_INFORMATION_64BIT = POINTER_64BIT

class MEMORY_PRIORITY_INFORMATION(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['ULONG']
    lookUps = {0: ReverseLookUps.Thread.MEMORY_PRIORITY}

    # Struct Members
    MemoryPriority: ULONG

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct LUID
# Alias Names: _LUID
# Alias Pointer Names: PLUID

def get_LUID(uc: Uc, address: int, em: EMU):
    return LUID.from_buffer_copy(uc.mem_read(address, sizeof(LUID)))

# Struct Aliases:
# get__LUID = get_LUID

# Struct Pointers:
PLUID_32BIT = POINTER_32BIT
PLUID_64BIT = POINTER_64BIT

class LUID(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'LONG']
    lookUps = {}

    # Struct Members
    LowPart: DWORD
    HighPart: LONG

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct LUID_AND_ATTRIBUTES
# Alias Names: _LUID_AND_ATTRIBUTES
# Alias Pointer Names: PLUID_AND_ATTRIBUTES

def get_LUID_AND_ATTRIBUTES(uc: Uc, address: int, em: EMU):
    return LUID_AND_ATTRIBUTES.from_buffer_copy(uc.mem_read(address, sizeof(LUID_AND_ATTRIBUTES)))

# Struct Aliases:
# get__LUID_AND_ATTRIBUTES = get_LUID_AND_ATTRIBUTES

# Struct Pointers:
PLUID_AND_ATTRIBUTES_32BIT = POINTER_32BIT
PLUID_AND_ATTRIBUTES_64BIT = POINTER_64BIT

class LUID_AND_ATTRIBUTES(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['LUID', 'DWORD']
    lookUps = {}

    # Struct Members
    Luid: LUID
    Attributes: DWORD

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct TOKEN_PRIVILEGES
# Alias Names: _TOKEN_PRIVILEGES
# Alias Pointer Names: PTOKEN_PRIVILEGES

def get_TOKEN_PRIVILEGES(uc: Uc, address: int, em: EMU):
    return TOKEN_PRIVILEGES.from_buffer_copy(uc.mem_read(address, sizeof(TOKEN_PRIVILEGES)))

# Struct Aliases:
# get__TOKEN_PRIVILEGES = get_TOKEN_PRIVILEGES

# Struct Pointers:
PTOKEN_PRIVILEGES_32BIT = POINTER_32BIT
PTOKEN_PRIVILEGES_64BIT = POINTER_64BIT

class TOKEN_PRIVILEGES(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'LUID_AND_ATTRIBUTES']
    lookUps = {}

    ANYSIZE_ARRAY = 1 # Need to look into how to create this

    # Struct Members
    PrivilegeCount: DWORD
    Privileges: LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct INTERNET_CACHE_ENTRY_INFOA
# Alias Names: _INTERNET_CACHE_ENTRY_INFOA
# Alias Pointer Names: LPINTERNET_CACHE_ENTRY_INFOA

def get_INTERNET_BUFFERSW(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return INTERNET_BUFFERSW.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_BUFFERSW.ARCH32)))
    else:
        return INTERNET_BUFFERSW.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_BUFFERSW.ARCH64)))

# Struct Aliases:
# get__INTERNET_CACHE_ENTRY_INFOA = get_INTERNET_CACHE_ENTRY_INFOA

# Struct Pointers:
LPINTERNET_CACHE_ENTRY_INFOA_32BIT = POINTER_32BIT
LPINTERNET_CACHE_ENTRY_INFOA_64BIT = POINTER_64BIT

class INTERNET_CACHE_ENTRY_INFOA_Helpers:
    class union(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        type = ['DWORD', 'DWORD']
        lookUps = {}

        dwReserved: DWORD
        dwExemptDelta: DWORD

class INTERNET_CACHE_ENTRY_INFOA:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'FILETIME', 'FILETIME', 'FILETIME', 'FILETIME', 'LPSTR', 'DWORD', 'LPSTR', 'union']
        lookUps = {}

        # Struct Members
        dwStructSize: DWORD
        lpszSourceUrlName: LPSTR_32BIT
        lpszLocalFileName: LPSTR_32BIT
        CacheEntryType: DWORD
        dwUseCount: DWORD
        dwHitRate: DWORD
        dwSizeLow: DWORD
        dwSizeHigh: DWORD
        LastModifiedTime: FILETIME
        ExpireTime: FILETIME
        LastAccessTime: FILETIME
        LastSyncTime: FILETIME
        lpHeaderInfo: LPSTR_32BIT
        dwHeaderInfoSize: DWORD
        lpszFileExtension: LPSTR_32BIT
        DUMMYUNIONNAME:  INTERNET_CACHE_ENTRY_INFOA_Helpers.union

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


# Struct IO_STATUS_BLOCK
# Alias Names: 
# Alias Pointer Names: 

def get_IO_STATUS_BLOCK(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return IO_STATUS_BLOCK.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(IO_STATUS_BLOCK.ARCH32)))
    else:
        return IO_STATUS_BLOCK.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(IO_STATUS_BLOCK.ARCH64)))

# Struct Aliases:
# get__INTERNET_BUFFERSA = get_INTERNET_BUFFERSA

# Struct Pointers:
PIO_STATUS_BLOCK_32BIT = POINTER_32BIT
PIO_STATUS_BLOCK_64BIT = POINTER_64BIT

class IO_STATUS_BLOCK_Helpers:
    # Sub Structures/Unions
    class Union_32BIT(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['NTSTATUS', 'PVOID']
        lookUps = {}

        # Union Members
        Status: LONG
        Pointer: PVOID_32BIT

    class Union_64BIT(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['NTSTATUS', 'PVOID']
        lookUps = {}

        # Union Members
        Status: LONG
        Pointer: PVOID_64BIT

class IO_STATUS_BLOCK:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['union', 'ULONG_PTR']
        lookUps = {}

        # Struct Members
        DUMMYUNIONNAME: IO_STATUS_BLOCK_Helpers.Union_32BIT
        Information: ULONG_PTR_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['union', 'ULONG_PTR']
        lookUps = {}

        # Struct Members
        DUMMYUNIONNAME: IO_STATUS_BLOCK_Helpers.Union_64BIT
        Information: ULONG_PTR_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct INTERNET_CACHE_ENTRY_INFOW
# Alias Names: _INTERNET_CACHE_ENTRY_INFOW
# Alias Pointer Names: LPINTERNET_CACHE_ENTRY_INFOW

def get_INTERNET_CACHE_ENTRY_INFOW(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return INTERNET_CACHE_ENTRY_INFOW.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_CACHE_ENTRY_INFOW.ARCH32)))

    else:
        return INTERNET_CACHE_ENTRY_INFOW.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(INTERNET_CACHE_ENTRY_INFOW.ARCH64)))


# Struct Aliases:
# get__INTERNET_CACHE_ENTRY_INFOW = get_INTERNET_CACHE_ENTRY_INFOW

# Struct Pointers:
LPINTERNET_CACHE_ENTRY_INFOW_32BIT = POINTER_32BIT
LPINTERNET_CACHE_ENTRY_INFOW_64BIT = POINTER_64BIT

class INTERNET_CACHE_ENTRY_INFOW_Helpers:
    class union(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['DWORD', 'DWORD']
        lookUps = {}

        # Union Members
        dwReserved: DWORD
        dwExemptDelta: DWORD

class INTERNET_CACHE_ENTRY_INFOW:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'FILETIME', 'FILETIME', 'FILETIME', 'FILETIME', 'LPWSTR', 'DWORD', 'LPWSTR', 'union']
        lookUps = {}

        # Struct Members
        # Struct Members
        dwStructSize: DWORD
        lpszSourceUrlName: LPWSTR_32BIT
        lpszLocalFileName: LPWSTR_32BIT
        CacheEntryType: DWORD
        dwUseCount: DWORD
        dwHitRate: DWORD
        dwSizeLow: DWORD
        dwSizeHigh: DWORD
        LastModifiedTime: FILETIME
        ExpireTime: FILETIME
        LastAccessTime: FILETIME
        LastSyncTime: FILETIME
        lpHeaderInfo: LPWSTR_32BIT
        dwHeaderInfoSize: DWORD
        lpszFileExtension: LPWSTR_32BIT
        union1: INTERNET_CACHE_ENTRY_INFOW_Helpers.union

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'FILETIME', 'FILETIME', 'FILETIME', 'FILETIME', 'LPWSTR', 'DWORD', 'LPWSTR', 'union']
        lookUps = {}

        # Struct Members
        # Struct Members
        dwStructSize: DWORD
        lpszSourceUrlName: LPWSTR_64BIT
        lpszLocalFileName: LPWSTR_64BIT
        CacheEntryType: DWORD
        dwUseCount: DWORD
        dwHitRate: DWORD
        dwSizeLow: DWORD
        dwSizeHigh: DWORD
        LastModifiedTime: FILETIME
        ExpireTime: FILETIME
        LastAccessTime: FILETIME
        LastSyncTime: FILETIME
        lpHeaderInfo: LPWSTR_64BIT
        dwHeaderInfoSize: DWORD
        lpszFileExtension: LPWSTR_64BIT
        DUMMYUNIONNAME: INTERNET_CACHE_ENTRY_INFOW_Helpers.union

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct CLIENT_ID
# Alias Names: _CLIENT_ID
# Alias Pointer Names: PCLIENT_ID 

def get_CLIENT_ID(uc: Uc, address: int, em: EMU):
    if em.arch == 32:
        return CLIENT_ID.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(CLIENT_ID.ARCH32)))

    else:
        return CLIENT_ID.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(CLIENT_ID.ARCH64)))

# Struct Aliases:
# get__LUID = get_LUID

# Struct Pointers:
PCLIENT_ID_32BIT = POINTER_32BIT
PCLIENT_ID_64BIT = POINTER_64BIT

class CLIENT_ID(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE']
        lookUps = {}

        # Struct Members
        UniqueProcess: HANDLE_32BIT
        UniqueThread: HANDLE_32BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['HANDLE', 'HANDLE']
        lookUps = {}

        # Struct Members
        UniqueProcess: HANDLE_64BIT
        UniqueThread: HANDLE_64BIT

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))    

# Struct MIB_IPNETROW
# Alias Names: _MIB_IPNETROW
# Alias Pointer Names: PMIB_IPNETROW

def get_MIB_IPNETROW(uc: Uc, address: int, em: EMU):
    return MIB_IPNETROW.from_buffer_copy(uc.mem_read(address, sizeof(MIB_IPNETROW)))

# Struct Aliases:
# get__MIB_IPNETROW_LH = get_MIB_IPNETROW_LH

# Struct Pointers:
PMIB_IPNETROW_32BIT = POINTER_32BIT
PMIB_IPNETROW_64BIT = POINTER_64BIT

class MIB_IPNETROW_Helpers:
    class union(LittleEndianUnion, metaclass=UnionFieldsFromTypeHints):
        types = ['DWORD', 'MIB_IPNET_TYPE']
        lookUps = {0: ReverseLookUps.IPNET.TYPE, 1: ReverseLookUps.IPNET.TYPE}

        dwType: DWORD
        Type: DWORD

class MIB_IPNETROW(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['IF_INDEX', 'DWORD', 'UCHAR', 'DWORD', 'union']
    lookUps = {}

    MAXLEN_PHYSADDR = 8

    # Struct Members
    dwIndex: DWORD
    dwPhysAddrLen: DWORD
    bPhysAddr: UCHAR * MAXLEN_PHYSADDR
    dwAddr: DWORD
    DUMMYUNION: MIB_IPNETROW_Helpers.union

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct MIB_IPNETTABLE
# Alias Names: _MIB_IPNETTABLE
# Alias Pointer Names: PMIB_IPNETTABLE

def get_MIB_IPNETTABLE(uc: Uc, address: int, em: EMU):
    return MIB_IPNETTABLE.from_buffer_copy(uc.mem_read(address, sizeof(MIB_IPNETTABLE)))

# Struct Aliases:
# get__MIB_IPNETTABLE = get_MIB_IPNETTABLE

# Struct Pointers:
PMIB_IPNETTABLE_32BIT = POINTER_32BIT
PMIB_IPNETTABLE_64BIT = POINTER_64BIT

class MIB_IPNETTABLE(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['DWORD', 'MIB_IPNETROW']
    lookUps = {}

    ANY_SIZE = 1

    # Struct Members
    dwNumEntries: DWORD
    table: MIB_IPNETROW * ANY_SIZE

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct APP_MEMORY_INFORMATION
# Alias Names: _APP_MEMORY_INFORMATION
# Alias Pointer Names: PAPP_MEMORY_INFORMATION

def get_APP_MEMORY_INFORMATION(uc: Uc, address: int, em: EMU):
    return APP_MEMORY_INFORMATION.from_buffer_copy(uc.mem_read(address, sizeof(APP_MEMORY_INFORMATION)))

# Struct Aliases:
# get__APP_MEMORY_INFORMATION = get_APP_MEMORY_INFORMATION

# Struct Pointers:
PAPP_MEMORY_INFORMATION_32BIT = POINTER_32BIT
PAPP_MEMORY_INFORMATION_64BIT = POINTER_64BIT

class APP_MEMORY_INFORMATION(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
    types = ['ULONG64', 'ULONG64', 'ULONG64', 'ULONG64']
    lookUps = {}

    # Struct Members
    AvailableCommit: ULONG64
    PrivateCommitUsage: ULONG64
    PeakPrivateCommitUsage: ULONG64
    TotalCommitUsage: ULONG64

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct MEMORY_BASIC_INFORMATION
# Alias Names: _MEMORY_BASIC_INFORMATION
# Alias Pointer Names: PMEMORY_BASIC_INFORMATION

def get_MEMORY_BASIC_INFORMATION(uc: Uc, address: int, em):
    if em.arch == 32:
        return MEMORY_BASIC_INFORMATION.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(MEMORY_BASIC_INFORMATION.ARCH32)))
    else:
        return MEMORY_BASIC_INFORMATION.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(MEMORY_BASIC_INFORMATION.ARCH64)))

# Struct Aliases:
# get__MEMORY_BASIC_INFORMATION = get_MEMORY_BASIC_INFORMATION

# Struct Pointers:
PMEMORY_BASIC_INFORMATION_32BIT = POINTER_32BIT
PMEMORY_BASIC_INFORMATION_64BIT = POINTER_64BIT

class MEMORY_BASIC_INFORMATION:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['PVOID', 'PVOID', 'DWORD', 'WORD', 'SIZE_T', 'DWORD', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        BaseAddress: PVOID_32BIT
        AllocationBase: PVOID_32BIT
        AllocationProtect: DWORD
        PartitionId: WORD
        RegionSize: SIZE_T_32BIT
        State: DWORD
        Protect: DWORD
        Type: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['PVOID', 'PVOID', 'DWORD', 'WORD', 'SIZE_T', 'DWORD', 'DWORD', 'DWORD']
        lookUps = {}

        # Struct Members
        BaseAddress: PVOID_64BIT
        AllocationBase: PVOID_64BIT
        AllocationProtect: DWORD
        PartitionId: WORD
        RegionSize: SIZE_T_64BIT
        State: DWORD
        Protect: DWORD
        Type: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


# Struct CREATESTRUCTA
# Alias Names: CREATESTRUCTA
# Alias Pointer Names: LPCREATESTRUCTA

def get_CREATESTRUCTA(uc: Uc, address: int, em):
    if em.arch == 32:
        return CREATESTRUCTA.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(CREATESTRUCTA.ARCH32)))
    else:
        return CREATESTRUCTA.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(CREATESTRUCTA.ARCH64)))

# Struct Aliases:
# get_CREATESTRUCTA = get_tagCREATESTRUCTA

# Struct Pointers:
LPCREATESTRUCTA_32BIT = POINTER_32BIT
LPCREATESTRUCTA_64BIT = POINTER_64BIT

class CREATESTRUCTA:

    class ARCH32(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['LPVOID', 'HINSTANCE', 'HMENU', 'HWND', 'int', 'int', 'int', 'int', 'LONG', 'LPCSTR', 'LPCSTR', 'DWORD']
        lookUps = {}

        # Struct Members
        lpCreateParams: LPVOID_32BIT
        hInstance: HINSTANCE_32BIT
        hMenu: HMENU_32BIT
        hwndParent: HWND_32BIT
        cy: INT
        cx: INT
        y: INT
        x: INT
        style: LONG
        lpszName: LPCSTR_32BIT
        lpszClass: LPCSTR_32BIT
        dwExStyle: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure, metaclass=StructFieldsFromTypeHints):
        types = ['LPVOID', 'HINSTANCE', 'HMENU', 'HWND', 'int', 'int', 'int', 'int', 'LONG', 'LPCSTR', 'LPCSTR', 'DWORD']
        lookUps = {}

        # Struct Members
        lpCreateParams: LPVOID_64BIT
        hInstance: HINSTANCE_64BIT
        hMenu: HMENU_64BIT
        hwndParent: HWND_64BIT
        cy: INT
        cx: INT
        y: INT
        x: INT
        style: LONG
        lpszName: LPCSTR_64BIT
        lpszClass: LPCSTR_64BIT
        dwExStyle: DWORD

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))
