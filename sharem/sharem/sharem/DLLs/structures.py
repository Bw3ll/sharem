from ctypes import LittleEndianStructure, sizeof
from enum import Enum
from struct import pack, unpack
from time import gmtime, localtime, time_ns
from sharem.sharem.DLLs.reverseLookUps import ReverseLookUps

from sharem.sharem.helper.ctypesUnion import LittleEndianUnion
from sharem.sharem.helper.structHelpers import BOOL, DWORD, DWORD_PTR_32BIT, DWORD_PTR_64BIT, HANDLE_32BIT, HANDLE_64BIT, HINSTANCE_32BIT, HINSTANCE_64BIT, HKEY_32BIT, HKEY_64BIT, HWND_32BIT, HWND_64BIT, INT, LONG, LONGLONG, LPBYTE_32BIT, LPBYTE_64BIT, LPCSTR_32BIT, LPCSTR_64BIT, LPCWSTR_32BIT, LPCWSTR_64BIT, LPSTR_32BIT, LPSTR_64BIT, LPVOID_32BIT, LPVOID_64BIT, LPWSTR_32BIT, LPWSTR_64BIT, MAX_PATH, PCHAR_32BIT, PCHAR_64BIT, POINTER_32BIT, POINTER_64BIT, PVOID_32BIT, PVOID_64BIT, PWSTR_32BIT, PWSTR_64BIT, UCHAR, ULONG, ULONG_PTR_32BIT, ULONG_PTR_64BIT, ULONGLONG, USHORT, WCHAR, WORD, CHAR

from ..helper.emuHelpers import Uc


# Struct PROCESS_INFORMATION
# Alias Names: _PROCESS_INFORMATION
# Alias Pointer Names: *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION

def get_PROCESS_INFORMATION(uc: Uc, address: int, em):
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
    nextProcessID = 10000
    nextThreadID = 20000

    class ARCH32(LittleEndianStructure):
        types = ['HANDLE', 'HANDLE', 'DWORD', 'DWORD']
        __slots__ = ('hProcess', 'hThread', 'dwProcessId', 'dwThreadId')
        lookUps = {}
        _fields_ = [('hProcess',HANDLE_32BIT),('hThread',HANDLE_32BIT),('dwProcessId',DWORD),('dwThreadId',DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

        def setValues(self, hProcess: int, hThread: int, pID: int = 0, tID: int = 0):
            self.hProcess = hProcess
            self.hThread = hThread
            if pID != 0:
                self.dwProcessId = pID
            else:
                self.dwProcessId = PROCESS_INFORMATION.nextProcessID
                PROCESS_INFORMATION.nextProcessID += 1
            if tID != 0:
                self.dwThreadId = tID
            else:
                self.dwThreadId = PROCESS_INFORMATION.nextThreadID
                PROCESS_INFORMATION.nextThreadID += 1

    class ARCH64(LittleEndianStructure):
        types = ['HANDLE', 'HANDLE', 'DWORD', 'DWORD']
        __slots__ = ('hProcess', 'hThread', 'dwProcessId', 'dwThreadId')
        lookUps = {}

        _fields_ = [('hProcess',HANDLE_64BIT),('hThread',HANDLE_64BIT),('dwProcessId',DWORD),('dwThreadId',DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

        def setValues(self, hProcess: int, hThread: int, pID: int = 0, tID: int = 0):
            self.hProcess = hProcess
            self.hThread = hThread
            if pID != 0:
                self.dwProcessId = pID
            else:
                self.dwProcessId = PROCESS_INFORMATION.nextProcessID
                PROCESS_INFORMATION.nextProcessID += 1
            if tID != 0:
                self.dwThreadId = tID
            else:
                self.dwThreadId = PROCESS_INFORMATION.nextThreadID
                PROCESS_INFORMATION.nextThreadID += 1


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

def get_PROCESSENTRY32(uc: Uc, address: int, em):
    if em.arch == 32:
        return PROCESSENTRY32.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32.ARCH32)))
    else:
        return PROCESSENTRY32.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32.ARCH64)))

# Struct Aliases:
# get_tagPROCESSENTRY32 = get_PROCESSENTRY32

class PROCESSENTRY32:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'CHAR']
        __slots__ = ('dwSize', 'cntUsage', 'th32ProcessID', 'th32DefaultHeapID', 'th32ModuleID', 'cntThreads', 'th32ParentProcessID', 'pcPriClassBase', 'dwFlags', 'szExeFile')
        lookUps = {}

        _fields_ = [('dwSize',DWORD),('cntUsage',DWORD),('th32ProcessID',DWORD),('th32DefaultHeapID',ULONG_PTR_32BIT),('th32ModuleID',DWORD),('cntThreads',DWORD),('th32ParentProcessID',DWORD),('pcPriClassBase',LONG),('dwFlags',DWORD),('szExeFile',CHAR * MAX_PATH)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'CHAR']
        __slots__ = ('dwSize', 'cntUsage', 'th32ProcessID', 'th32DefaultHeapID', 'th32ModuleID', 'cntThreads', 'th32ParentProcessID', 'pcPriClassBase', 'dwFlags', 'szExeFile')
        lookUps = {}

        _fields_ = [('dwSize',DWORD),('cntUsage',DWORD),('th32ProcessID',DWORD),('th32DefaultHeapID',ULONG_PTR_64BIT),('th32ModuleID',DWORD),('cntThreads',DWORD),('th32ParentProcessID',DWORD),('pcPriClassBase',LONG),('dwFlags',DWORD),('szExeFile',CHAR * MAX_PATH)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct PROCESSENTRY32W
# Alias Names: tagPROCESSENTRY32W
# Alias Pointer Names: 

def get_PROCESSENTRY32W(uc: Uc, address: int, em):
    if em.arch == 32:
        return PROCESSENTRY32W.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32W.ARCH32)))
    else:
        return PROCESSENTRY32W.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(PROCESSENTRY32W.ARCH64)))

# Struct Aliases:
# get_tagPROCESSENTRY32W = get_PROCESSENTRY32W

class PROCESSENTRY32W:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'WCHAR']
        __slots__ = ('dwSize', 'cntUsage', 'th32ProcessID', 'th32DefaultHeapID', 'th32ModuleID', 'cntThreads', 'th32ParentProcessID', 'pcPriClassBase', 'dwFlags', 'szExeFile')
        lookUps = {}

        _fields_ = [('dwSize',DWORD),('cntUsage',DWORD),('th32ProcessID',DWORD),('th32DefaultHeapID',ULONG_PTR_32BIT),('th32ModuleID',DWORD),('cntThreads',DWORD),('th32ParentProcessID',DWORD),('pcPriClassBase',LONG),('dwFlags',DWORD),('szExeFile',WCHAR * MAX_PATH)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'ULONG_PTR', 'DWORD', 'DWORD', 'DWORD', 'LONG', 'DWORD', 'WCHAR']
        __slots__ = ('dwSize', 'cntUsage', 'th32ProcessID', 'th32DefaultHeapID', 'th32ModuleID', 'cntThreads', 'th32ParentProcessID', 'pcPriClassBase', 'dwFlags', 'szExeFile')
        lookUps = {}

        _fields_ = [('dwSize',DWORD),('cntUsage',DWORD),('th32ProcessID',DWORD),('th32DefaultHeapID',ULONG_PTR_64BIT),('th32ModuleID',DWORD),('cntThreads',DWORD),('th32ParentProcessID',DWORD),('pcPriClassBase',LONG),('dwFlags',DWORD),('szExeFile',WCHAR * MAX_PATH)]

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

def get_SYSTEMTIME(uc: Uc, address: int, em):
    return SYSTEMTIME.from_buffer_copy(uc.mem_read(address, sizeof(SYSTEMTIME)))

# Struct Aliases:
# get__SYSTEMTIME = get_SYSTEMTIME

# Struct Pointers:
PSYSTEMTIME_32BIT = POINTER_32BIT
PSYSTEMTIME_64BIT = POINTER_64BIT
LPSYSTEMTIME_32BIT = POINTER_32BIT
LPSYSTEMTIME_64BIT = POINTER_64BIT

class SYSTEMTIME(LittleEndianStructure):
    types = ['WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD']
    __slots__ = ('wYear', 'wMonth', 'wDayOfWeek', 'wDay', 'wHour', 'wMinute', 'wSecond', 'wMilliseconds')
    lookUps = {}

    _fields_ = [('wYear',WORD),('wMonth',WORD),('wDayOfWeek',WORD),('wDay',WORD),('wHour',WORD),('wMinute',WORD),('wSecond',WORD),('wMilliseconds',WORD)]

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

def get_SYSTEM_INFO(uc: Uc, address: int, em):
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
    class DummyStruct(LittleEndianStructure):
        types = ['WORD', 'WORD']
        __slots__ = ('wProcessorArchitecture','wReserved')
        lookUps = {0: ReverseLookUps.Processor}
        
        _fields_ = [('wProcessorArchitecture',WORD),('wReserved', WORD)]

class SYSTEM_INFO:

    class ARCH32(LittleEndianStructure):
        types = ['struct','DWORD','LPVOID','LPVOID','DWORD_PTR','DWORD','DWORD','DWORD','WORD','WORD']
        __slots__ = ('DUMMYSTRUCTNAME','dwPageSize','lpMinimumApplicationAddress','lpMaximumApplicationAddress','dwActiveProcessorMask','dwNumberOfProcessors','dwProcessorType','dwAllocationGranularity','wProcessorLevel','wProcessorRevision')
        lookUps = {6: ReverseLookUps.ProcessorType}

        _fields_ = [('DUMMYSTRUCTNAME',SYSTEM_INFO_Helpers.DummyStruct),('dwPageSize',DWORD),('lpMinimumApplicationAddress',LPVOID_32BIT),('lpMaximumApplicationAddress',LPVOID_32BIT),('dwActiveProcessorMask',DWORD_PTR_32BIT),('dwNumberOfProcessors',DWORD),('dwProcessorType',DWORD),('dwAllocationGranularity',DWORD),('wProcessorLevel',WORD),('wProcessorRevision',WORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['struct','DWORD','LPVOID','LPVOID','DWORD_PTR','DWORD','DWORD','DWORD','WORD','WORD']
        __slots__ = ('DUMMYSTRUCTNAME','dwPageSize','lpMinimumApplicationAddress','lpMaximumApplicationAddress','dwActiveProcessorMask','dwNumberOfProcessors','dwProcessorType','dwAllocationGranularity','wProcessorLevel','wProcessorRevision')
        lookUps = {6: ReverseLookUps.ProcessorType}

        _fields_ = [('DUMMYSTRUCTNAME',SYSTEM_INFO_Helpers.DummyStruct),('dwPageSize',DWORD),('lpMinimumApplicationAddress',LPVOID_64BIT),('lpMaximumApplicationAddress',LPVOID_64BIT),('dwActiveProcessorMask',DWORD_PTR_64BIT),('dwNumberOfProcessors',DWORD),('dwProcessorType',DWORD),('dwAllocationGranularity',DWORD),('wProcessorLevel',WORD),('wProcessorRevision',WORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct LIST_ENTRY
# Alias Names: _LIST_ENTRY
# Alias Pointer Names: *PLIST_ENTRY, PRLIST_ENTRY

def get_LIST_ENTRY(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['PLIST_ENTRY', 'PLIST_ENTRY']
        __slots__ = ('Flink', 'Blink')
        _fields_ = [('Flink',PLIST_ENTRY_32BIT),('Blink',PLIST_ENTRY_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['PLIST_ENTRY', 'PLIST_ENTRY']
        __slots__ = ('Flink', 'Blink')
        _fields_ = [('Flink',PLIST_ENTRY_64BIT),('Blink',PLIST_ENTRY_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct SINGLE_LIST_ENTRY
# Alias Names: _SINGLE_LIST_ENTRY
# Alias Pointer Names: *PSINGLE_LIST_ENTRY

def get_SINGLE_LIST_ENTRY(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['PSINGLE_LIST_ENTRY']
        __slots__ = ('Next')
        lookUps = {}

        _fields_ = [('Next',PSINGLE_LIST_ENTRY_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['PSINGLE_LIST_ENTRY']
        __slots__ = ('Next')
        lookUps = {}

        _fields_ = [('Next',PSINGLE_LIST_ENTRY_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct FILETIME
# Alias Names: _FILETIME
# Alias Pointer Names: PFILETIME, LPFILETIME

def get_FILETIME(uc: Uc, address: int, em):
    return FILETIME.from_buffer_copy(uc.mem_read(address, sizeof(FILETIME)))

# Struct Aliases:
# get__FILETIME = get_FILETIME

# Struct Pointers:
PFILETIME_32BIT = POINTER_32BIT
PFILETIME_64BIT = POINTER_64BIT
LPFILETIME_32BIT = POINTER_32BIT
LPFILETIME_64BIT = POINTER_64BIT

class FILETIME(LittleEndianStructure):
    types = ['DWORD', 'DWORD']
    __slots__ = ('dwLowDateTime', 'dwHighDateTime')
    lookUps = {}

    _fields_ = [('dwLowDateTime',DWORD),('dwHighDateTime',DWORD)]

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

def get_UNICODE_STRING(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['USHORT', 'USHORT', 'PWSTR']
        __slots__ = ('Length', 'MaximumLength', 'Buffer')
        lookUps = {}

        _fields_ = [('Length',USHORT),('MaximumLength',USHORT),('Buffer',PWSTR_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['USHORT', 'USHORT', 'PWSTR']
        __slots__ = ('Length', 'MaximumLength', 'Buffer')
        lookUps = {}

        _fields_ = [('Length',USHORT),('MaximumLength',USHORT),('Buffer',PWSTR_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct STRING
# Alias Names: _STRING
# Alias Pointer Names:

def get_STRING(uc: Uc, address: int, em):
    if em.arch == 32:
        return STRING.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(STRING.ARCH32)))
    else:
        return STRING.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(STRING.ARCH64)))

# Struct Aliases:
# get__STRING = get_STRING

class STRING:

    class ARCH32(LittleEndianStructure):
        types = ['USHORT', 'USHORT', 'PCHAR']
        __slots__ = ('Length', 'MaximumLength', 'Buffer')
        lookUps = {}

        _fields_ = [('Length',USHORT),('MaximumLength',USHORT),('Buffer',PCHAR_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['USHORT', 'USHORT', 'PCHAR']
        __slots__ = ('Length', 'MaximumLength', 'Buffer')
        lookUps = {}

        _fields_ = [('Length',USHORT),('MaximumLength',USHORT),('Buffer',PCHAR_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct TIME_ZONE_INFORMATION
# Alias Names: _TIME_ZONE_INFORMATION
# Alias Pointer Names: *PTIME_ZONE_INFORMATION, *LPTIME_ZONE_INFORMATION

def get_TIME_ZONE_INFORMATION(uc: Uc, address: int, em):
    return TIME_ZONE_INFORMATION.from_buffer_copy(uc.mem_read(address, sizeof(TIME_ZONE_INFORMATION)))

# Struct Aliases:
# get__TIME_ZONE_INFORMATION = get_TIME_ZONE_INFORMATION

# Struct Pointers:
PTIME_ZONE_INFORMATION_32BIT = POINTER_32BIT
PTIME_ZONE_INFORMATION_64BIT = POINTER_64BIT
LPTIME_ZONE_INFORMATION_32BIT = POINTER_32BIT
LPTIME_ZONE_INFORMATION_64BIT = POINTER_64BIT

class TIME_ZONE_INFORMATION(LittleEndianStructure):
    types = ['LONG', 'WCHAR', 'SYSTEMTIME', 'LONG', 'WCHAR', 'SYSTEMTIME', 'LONG']
    __slots__ = ('Bias', 'StandardName', 'StandardDate', 'StandardBias', 'DaylightName', 'DaylightDate', 'DaylightBias')
    lookUps = {}

    _fields_ = [('Bias',LONG),('StandardName',WCHAR * 32),('StandardDate',SYSTEMTIME),('StandardBias',LONG),('DaylightName',WCHAR * 32),('DaylightDate',SYSTEMTIME),('DaylightBias',LONG)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct REG_TZI_FORMAT
# Alias Names: _REG_TZI_FORMAT
# Alias Pointer Names:

def get_REG_TZI_FORMAT(uc: Uc, address: int, em):
    return REG_TZI_FORMAT.from_buffer_copy(uc.mem_read(address, sizeof(REG_TZI_FORMAT)))

# Struct Aliases:
# get__REG_TZI_FORMAT = get_REG_TZI_FORMAT

class REG_TZI_FORMAT(LittleEndianStructure):
    types = ['LONG', 'LONG', 'LONG', 'SYSTEMTIME', 'SYSTEMTIME']
    __slots__ = ('Bias', 'StandardBias', 'DaylightBias', 'StandardDate', 'DaylightDate')
    lookUps = {}
    
    _fields_ = [('Bias',LONG),('StandardBias',LONG),('DaylightBias',LONG),('StandardDate',SYSTEMTIME),('DaylightDate',SYSTEMTIME)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct STARTUPINFOA
# Alias Names:
# Alias Pointer Names: *LPSTARTUPINFOA

def get_STARTUPINFOA(uc: Uc, address: int, em):
        if em.arch == 32:
            return STARTUPINFOA.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(STARTUPINFOA.ARCH32)))
        else:
            return STARTUPINFOA.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(STARTUPINFOA.ARCH64)))

# Struct Pointers:
LPSTARTUPINFOA_32BIT = POINTER_32BIT
LPSTARTUPINFOA_64BIT = POINTER_64BIT

class STARTUPINFOA:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        __slots__ = ('cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        lookUps = {}

        _fields_ = [('cb',DWORD),('lpReserved',LPSTR_32BIT),('lpDesktop',LPSTR_32BIT),('lpTitle',LPSTR_32BIT),('dwX',DWORD),('dwY',DWORD),('dwXSize',DWORD),('dwYSize',DWORD),('dwXCountChars',DWORD),('dwYCountChars',DWORD),('dwFillAttribute',DWORD),('dwFlags',DWORD),('wShowWindow',WORD),('cbReserved2',WORD),('lpReserved2',LPBYTE_32BIT),('hStdInput',HANDLE_32BIT),('hStdOutput',HANDLE_32BIT),('hStdError',HANDLE_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        __slots__ = ('cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        lookUps = {}

        _fields_ = [('cb',DWORD),('lpReserved',LPSTR_64BIT),('lpDesktop',LPSTR_64BIT),('lpTitle',LPSTR_64BIT),('dwX',DWORD),('dwY',DWORD),('dwXSize',DWORD),('dwYSize',DWORD),('dwXCountChars',DWORD),('dwYCountChars',DWORD),('dwFillAttribute',DWORD),('dwFlags',DWORD),('wShowWindow',WORD),('cbReserved2',WORD),('lpReserved2',LPBYTE_64BIT),('hStdInput',HANDLE_64BIT),('hStdOutput',HANDLE_64BIT),('hStdError',HANDLE_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct STARTUPINFOW
# Alias Names: _STARTUPINFOW
# Alias Pointer Names: *LPSTARTUPINFOW

def get_STARTUPINFOW(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        __slots__ = ('cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        lookUps = {}

        _fields_ = [('cb',DWORD),('lpReserved',LPWSTR_32BIT),('lpDesktop',LPWSTR_32BIT),('lpTitle',LPWSTR_32BIT),('dwX',DWORD),('dwY',DWORD),('dwXSize',DWORD),('dwYSize',DWORD),('dwXCountChars',DWORD),('dwYCountChars',DWORD),('dwFillAttribute',DWORD),('dwFlags',DWORD),('wShowWindow',WORD),('cbReserved2',WORD),('lpReserved2',LPBYTE_32BIT),('hStdInput',HANDLE_32BIT),('hStdOutput',HANDLE_32BIT),('hStdError',HANDLE_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        __slots__ = ('cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        lookUps = {}

        _fields_ = [('cb',DWORD),('lpReserved',LPWSTR_64BIT),('lpDesktop',LPWSTR_64BIT),('lpTitle',LPWSTR_64BIT),('dwX',DWORD),('dwY',DWORD),('dwXSize',DWORD),('dwYSize',DWORD),('dwXCountChars',DWORD),('dwYCountChars',DWORD),('dwFillAttribute',DWORD),('dwFlags',DWORD),('wShowWindow',WORD),('cbReserved2',WORD),('lpReserved2',LPBYTE_64BIT),('hStdInput',HANDLE_64BIT),('hStdOutput',HANDLE_64BIT),('hStdError',HANDLE_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


# Struct OBJECT_ATTRIBUTES
# Alias Names: _OBJECT_ATTRIBUTES
# Alias Pointer Names: POBJECT_ATTRIBUTES

def get_OBJECT_ATTRIBUTES(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['ULONG', 'HANDLE', 'PUNICODE_STRING', 'ULONG', 'PVOID', 'PVOID']
        __slots__ = ('Length', 'RootDirectory', 'ObjectName', 'Attributes', 'SecurityDescriptor', 'SecurityQualityOfService')
        lookUps = {}

        _fields_ = [('Length',ULONG),('RootDirectory',HANDLE_32BIT),('ObjectName',PUNICODE_STRING_32BIT),('Attributes',ULONG),('SecurityDescriptor',PVOID_32BIT),('SecurityQualityOfService',PVOID_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['ULONG', 'HANDLE', 'PUNICODE_STRING', 'ULONG', 'PVOID', 'PVOID']
        __slots__ = ('Length', 'RootDirectory', 'ObjectName', 'Attributes', 'SecurityDescriptor', 'SecurityQualityOfService')
        lookUps = {}

        _fields_ = [('Length',ULONG),('RootDirectory',HANDLE_64BIT),('ObjectName',PUNICODE_STRING_64BIT),('Attributes',ULONG),('SecurityDescriptor',PVOID_64BIT),('SecurityQualityOfService',PVOID_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))


def get_LARGE_INTEGER(uc: Uc, address: int, em):
    return LARGE_INTEGER.from_buffer_copy(uc.mem_read(address, sizeof(LARGE_INTEGER)))

# Struct Aliases:
# get__LARGE_INTEGER = get_LARGE_INTEGER

# Struct Pointers:
PLARGE_INTEGER_32BIT = POINTER_32BIT
PLARGE_INTEGER_64BIT = POINTER_64BIT

class LARGE_INTEGER_Helpers:
    class u(LittleEndianStructure):
        types = ['DWORD','LONG']
        __slots__ = ('LowPart', 'HighPart')
        lookUps = {}

        _fields_ = [('LowPart',DWORD),('HighPart',LONG)]

class LARGE_INTEGER(LittleEndianUnion):
    types = ['struct','LONGLONG']
    __slots__ = ('u','QuadPart')
    lookUps = {}

    _fields_ = [('u',LARGE_INTEGER_Helpers.u),('QuadPart', LONGLONG)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

def get_ULARGE_INTEGER(uc: Uc, address: int, em):
    return LARGE_INTEGER.from_buffer_copy(uc.mem_read(address, sizeof(ULARGE_INTEGER)))

# Struct Aliases:
# get__ULARGE_INTEGER = get_ULARGE_INTEGER

# Struct Pointers:
PULARGE_INTEGER_32BIT = POINTER_32BIT
PULARGE_INTEGER_64BIT = POINTER_64BIT

class ULARGE_INTEGER_Helpers:
    class u(LittleEndianStructure):
        types = ['DWORD','DWORD']
        __slots__ = ('LowPart', 'HighPart')
        lookUps = {}

        _fields_ = [('LowPart',DWORD),('HighPart',DWORD)]

class ULARGE_INTEGER(LittleEndianUnion):
    types = ['struct','ULONGLONG']
    __slots__ = ('u','QuadPart')
    lookUps = {}

    _fields_ = [('u',ULARGE_INTEGER_Helpers.u),('QuadPart', ULONGLONG)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct GUID
# Alias Names: _GUID
# Alias Pointer Names:

def get_GUID(uc: Uc, address: int, em):
    return GUID.from_buffer_copy(uc.mem_read(address, sizeof(GUID)))

# Struct Aliases:
# get__GUID = get_GUID

class GUID(LittleEndianStructure):
    types = ['ULONG', 'USHORT', 'USHORT', 'UCHAR']
    __slots__ = ('Data1', 'Data2', 'Data3', 'Data4')
    lookUps = {}

    _fields_ = [('Data1',ULONG),('Data2',USHORT),('Data3',USHORT),('Data4',UCHAR*8)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct SECURITY_ATTRIBUTES
# Alias Names: _SECURITY_ATTRIBUTES
# Alias Pointer Names: *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES

def get_SECURITY_ATTRIBUTES(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'LPVOID', 'BOOL']
        __slots__ = ('nLength', 'lpSecurityDescriptor', 'bInheritHandle')
        lookUps = {}

        _fields_ = [('nLength',DWORD),('lpSecurityDescriptor',LPVOID_32BIT),('bInheritHandle',BOOL)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'LPVOID', 'BOOL']
        __slots__ = ('nLength', 'lpSecurityDescriptor', 'bInheritHandle')
        lookUps = {}

        _fields_ = [('nLength',DWORD),('lpSecurityDescriptor',LPVOID_64BIT),('bInheritHandle',BOOL)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct value_entA
# Alias Names: VALENTA
# Alias Pointer Names: *PVALENTA

def get_value_entA(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['LPSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        __slots__ = ('ve_valuename', 've_valuelen', 've_valueptr', 've_type')
        lookUps = {}

        _fields_ = [('ve_valuename',LPSTR_32BIT),('ve_valuelen',DWORD),('ve_valueptr',DWORD_PTR_32BIT),('ve_type',DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['LPSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        __slots__ = ('ve_valuename', 've_valuelen', 've_valueptr', 've_type')
        lookUps = {}

        _fields_ = [('ve_valuename',LPSTR_64BIT),('ve_valuelen',DWORD),('ve_valueptr',DWORD_PTR_64BIT),('ve_type',DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct value_entW
# Alias Names: VALENTW
# Alias Pointer Names: *PVALENTW

def get_value_entW(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['LPWSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        __slots__ = ('ve_valuename', 've_valuelen', 've_valueptr', 've_type')
        lookUps = {}

        _fields_ = [('ve_valuename',LPWSTR_32BIT),('ve_valuelen',DWORD),('ve_valueptr',DWORD_PTR_32BIT),('ve_type',DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['LPWSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        __slots__ = ('ve_valuename', 've_valuelen', 've_valueptr', 've_type')
        lookUps = {}

        _fields_ = [('ve_valuename',LPWSTR_64BIT),('ve_valuelen',DWORD),('ve_valueptr',DWORD_PTR_64BIT),('ve_type',DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct DISPLAY_DEVICEA
# Alias Names: _DISPLAY_DEVICEA
# Alias Pointer Names:  *PDISPLAY_DEVICEA, *LPDISPLAY_DEVICEA;

def get_DISPLAY_DEVICEA(uc: Uc, address: int, em):
    return DISPLAY_DEVICEA.from_buffer_copy(uc.mem_read(address, sizeof(DISPLAY_DEVICEA)))

# Struct Aliases:
# get__DISPLAY_DEVICEA = get_DISPLAY_DEVICEA

# Struct Pointers:
PDISPLAY_32BIT = POINTER_32BIT
PDISPLAY_64BIT = POINTER_64BIT
LPDISPLAY_32BIT = POINTER_32BIT
LPDISPLAY_64BIT = POINTER_64BIT

class DISPLAY_DEVICEA (LittleEndianStructure):
    types = ['DWORD','CHAR','CHAR','DWORD','CHAR','CHAR']
    __slots__ = ('cb','DeviceName','DeviceString','StateFlags','DeviceID','DeviceKey')
    lookUps = {}

    _fields_ = [('cb', DWORD ),('DeviceName', WCHAR * 32 ),('DeviceString', WCHAR * 128 ),('StateFlags', DWORD ),('DeviceID', CHAR * 128 ),('DeviceKey', CHAR * 128 )]

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

#def get_VIDEOPARAMETERS(uc: Uc, address: int, em):
#    return VIDEOPARAMETERS.from_buffer_copy(uc.mem_read(address, sizeof(VIDEOPARAMETERS)))

## Struct Aliases:
## get__VIDEOPARAMETERS = get_VIDEOPARAMETERS

## Struct Pointers:
#PVIDEOPARAMETERS_32BIT = POINTER_32BIT
#PVIDEOPARAMETERS_64BIT = POINTER_64BIT

#class VIDEOPARAMETERS (LittleEndianStructure):
#    types = ['GUID','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','ULONG','UCHAR']
#    names = ['guid','dwOffset','dwCommand','dwFlags','dwMode','dwTVStandard','dwAvailableModes','dwAvailableTVStandard','dwFlickerFilter','dwOverScanX','dwOverScanY','dwMaxUnscaledX','dwMaxUnscaledY','dwPositionX','dwPositionY','dwBrightness','dwContrast','dwCPType','dwCPCommand','dwCPStandard','dwCPKey','bCP_APSTriggerBits','bOEMCopyProtection']
#    __slots__ = ('guid','dwOffset','dwCommand','dwFlags','dwMode','dwTVStandard','dwAvailableModes','dwAvailableTVStandard','dwFlickerFilter','dwOverScanX','dwOverScanY','dwMaxUnscaledX','dwMaxUnscaledY','dwPositionX','dwPositionY','dwBrightness','dwContrast','dwCPType','dwCPCommand','dwCPStandard','dwCPKey','bCP_APSTriggerBits','bOEMCopyProtection')
#    _fields_ = [('guid', GUID ),('dwOffset', ULONG),('dwCommand', ULONG),('dwFlags', ULONG),('dwMode', ULONG),('dwTVStandard', ULONG),('dwAvailableModes', ULONG),('dwAvailableTVStandard', ULONG),('dwFlickerFilter', ULONG),('dwOverScanX', ULONG),('dwOverScanY', ULONG),('dwMaxUnscaledX', ULONG),('dwMaxUnscaledY', ULONG),('dwPositionX', ULONG),('dwPositionY', ULONG),('dwBrightness', ULONG),('dwContrast', ULONG),('dwCPType', ULONG),('dwCPCommand', ULONG),('dwCPStandard', ULONG),('dwCPKey', ULONG),('bCP_APSTriggerBits', ULONG),('bOEMCopyProtection', UCHAR*256)]

#    def writeToMemory(self, uc: Uc, address: int):
#        uc.mem_write(address, bytes(self))


# Struct _SHELLEXECUTEINFOA
# Alias Names: SHELLEXECUTEINFOA
# Alias Pointer Names: *LPSHELLEXECUTEINFOA

def get_SHELLEXECUTEINFOA(uc: Uc, address: int, em):
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
    class Union_32BIT(LittleEndianUnion):
        types = ['HANDLE', 'HANDLE']
        __slots__ = ('hIcon', 'hMonitor')
        lookUps = {}

        _fields_ = [('hIcon',HANDLE_32BIT),('hMonitor',HANDLE_32BIT)]

    class Union_64BIT(LittleEndianUnion):
        types = ['HANDLE', 'HANDLE']
        __slots__ = ('hIcon', 'hMonitor')
        lookUps = {}

        _fields_ = [('hIcon',HANDLE_64BIT),('hMonitor',HANDLE_64BIT)]

class SHELLEXECUTEINFOA:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'int', 'HINSTANCE', 'void', 'LPCSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        __slots__ = ('cbSize', 'fMask', 'hwnd', 'lpVerb','lpFile','lpParameters','lpDirectory','nShow','hInstApp','lpIDList','lpClass','hkeyClass','dwHotKey','DUMMYUNIONNAME','hProcess')
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        _fields_ = [('cbSize',DWORD),('fMask',ULONG),('hwnd',HWND_32BIT),('lpVerb',LPCSTR_32BIT),('lpFile',LPCSTR_32BIT),('lpParameters',LPCSTR_32BIT),('lpDirectory',LPCSTR_32BIT),('nShow',INT),('hInstApp',HINSTANCE_32BIT), ('lpIDList',PVOID_32BIT),('lpClass',LPCSTR_32BIT),('hkeyClass',HKEY_32BIT),('dwHotKey',DWORD),('DUMMYUNIONNAME',SHELLEXECUTEINFOA_Helpers.Union_32BIT),('hProcess',HANDLE_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'LPCSTR', 'int', 'HINSTANCE', 'void', 'LPCSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        __slots__ = ('cbSize', 'fMask', 'hwnd', 'lpVerb','lpFile','lpParameters','lpDirectory','nShow','hInstApp','lpIDList','lpClass','hkeyClass','dwHotKey','DUMMYUNIONNAME','hProcess')
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        _fields_ = [('cbSize',DWORD),('fMask',ULONG),('hwnd',HWND_64BIT),('lpVerb',LPCSTR_64BIT),('lpFile',LPCSTR_64BIT),('lpParameters',LPCSTR_64BIT),('lpDirectory',LPCSTR_64BIT),('nShow',INT),('hInstApp',HINSTANCE_64BIT), ('lpIDList',PVOID_64BIT),('lpClass',LPCSTR_64BIT),('hkeyClass',HKEY_64BIT),('dwHotKey',DWORD),('DUMMYUNIONNAME',SHELLEXECUTEINFOA_Helpers.Union_64BIT),('hProcess',HANDLE_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct _SHELLEXECUTEINFOW
# Alias Names: SHELLEXECUTEINFOW
# Alias Pointer Names: *LPSHELLEXECUTEINFOW

def get_SHELLEXECUTEINFOW(uc: Uc, address: int, em):
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
    class Union_32BIT(LittleEndianUnion):
        types = ['HANDLE', 'HANDLE']
        __slots__ = ('hIcon', 'hMonitor')
        lookUps = {}

        _fields_ = [('hIcon',HANDLE_32BIT),('hMonitor',HANDLE_32BIT)]

    class Union_64BIT(LittleEndianUnion):
        types = ['HANDLE', 'HANDLE']
        __slots__ = ('hIcon', 'hMonitor')
        lookUps = {}

        _fields_ = [('hIcon',HANDLE_64BIT),('hMonitor',HANDLE_64BIT)]

class SHELLEXECUTEINFOW:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'int', 'HINSTANCE', 'void', 'LPCWSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        __slots__ = ('cbSize', 'fMask', 'hwnd', 'lpVerb','lpFile','lpParameters','lpDirectory','nShow','hInstApp','lpIDList','lpClass','hkeyClass','dwHotKey','DUMMYUNIONNAME','hProcess')
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        _fields_ = [('cbSize',DWORD),('fMask',ULONG),('hwnd',HWND_32BIT),('lpVerb',LPCWSTR_32BIT),('lpFile',LPCWSTR_32BIT),('lpParameters',LPCWSTR_32BIT),('lpDirectory',LPCWSTR_32BIT),('nShow',INT),('hInstApp',HINSTANCE_32BIT), ('lpIDList',PVOID_32BIT),('lpClass',LPCWSTR_32BIT),('hkeyClass',HKEY_32BIT),('dwHotKey',DWORD),('DUMMYUNIONNAME',SHELLEXECUTEINFOW_Helpers.Union_32BIT),('hProcess',HANDLE_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'ULONG', 'HWND', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'LPCWSTR', 'int', 'HINSTANCE', 'void', 'LPCWSTR', 'HKEY', 'DWORD', 'union', 'HANDLE']
        __slots__ = ('cbSize', 'fMask', 'hwnd', 'lpVerb','lpFile','lpParameters','lpDirectory','nShow','hInstApp','lpIDList','lpClass','hkeyClass','dwHotKey','DUMMYUNIONNAME','hProcess')
        lookUps = {1: ReverseLookUps.ShellExecute.Mask, 7: ReverseLookUps.ShellExecute.cmdShow}

        _fields_ = [('cbSize',DWORD),('fMask',ULONG),('hwnd',HWND_64BIT),('lpVerb',LPCWSTR_64BIT),('lpFile',LPCWSTR_64BIT),('lpParameters',LPCWSTR_64BIT),('lpDirectory',LPCWSTR_64BIT),('nShow',INT),('hInstApp',HINSTANCE_64BIT), ('lpIDList',PVOID_64BIT),('lpClass',LPCWSTR_64BIT),('hkeyClass',HKEY_64BIT),('dwHotKey',DWORD),('DUMMYUNIONNAME',SHELLEXECUTEINFOW_Helpers.Union_64BIT),('hProcess',HANDLE_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct WSAPROTOCOLCHAIN
# Alias Names: _WSAPROTOCOLCHAIN
# Alias Pointer Names: LPWSAPROTOCOLCHAIN

def get_WSAPROTOCOLCHAIN(uc: Uc, address: int, em):
    return WSAPROTOCOLCHAIN.from_buffer_copy(uc.mem_read(address, sizeof(WSAPROTOCOLCHAIN)))

# Struct Aliases:
# get__WSAPROTOCOLCHAIN = get_WSAPROTOCOLCHAIN

# Struct Pointers:
LPWSAPROTOCOLCHAIN_32BIT = POINTER_32BIT
LPWSAPROTOCOLCHAIN_64BIT = POINTER_64BIT

class WSAPROTOCOLCHAIN(LittleEndianStructure):
    types = ['int', 'DWORD']
    __slots__ = ('ChainLen', 'ChainEntries')
    lookUps = {}

    _fields_ = [('ChainLen',INT),('ChainEntries',DWORD * 7)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct WSAPROTOCOL_INFOA
# Alias Names: _WSAPROTOCOL_INFOA
# Alias Pointer Names: LPWSAPROTOCOL_INFOA

def get_WSAPROTOCOL_INFOA(uc: Uc, address: int, em):
    return WSAPROTOCOL_INFOA.from_buffer_copy(uc.mem_read(address, sizeof(WSAPROTOCOL_INFOA)))

# Struct Aliases:
# get__WSAPROTOCOL_INFOA = get_WSAPROTOCOL_INFOA

# Struct Pointers:
LPWSAPROTOCOL_INFOA_32BIT = POINTER_32BIT
LPWSAPROTOCOL_INFOA_64BIT = POINTER_64BIT

class WSAPROTOCOL_INFOA(LittleEndianStructure):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'GUID', 'DWORD', 'WSAPROTOCOLCHAIN', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'DWORD', 'DWORD', 'CHAR']
    __slots__ = ('dwServiceFlags1', 'dwServiceFlags2', 'dwServiceFlags3', 'dwServiceFlags4', 'dwProviderFlags', 'ProviderId', 'dwCatalogEntryId', 'ProtocolChain', 'iVersion', 'iAddressFamily', 'iMaxSockAddr', 'iMinSockAddr', 'iSocketType', 'iProtocol', 'iProtocolMaxOffset', 'iNetworkByteOrder', 'iSecurityScheme', 'dwMessageSize', 'dwProviderReserved', 'szProtocol')
    lookUps = {0: ReverseLookUps.Socket.ServiceFlags, 9: ReverseLookUps.Socket.Af, 12: ReverseLookUps.Socket.Type, 13: ReverseLookUps.Socket.Protocol, 15: ReverseLookUps.Socket.NetworkByteOrder, 16: ReverseLookUps.Socket.SecurityScheme}

    _fields_ = [('dwServiceFlags1',DWORD),('dwServiceFlags2',DWORD),('dwServiceFlags3',DWORD),('dwServiceFlags4',DWORD),('dwProviderFlags',DWORD),('ProviderId',GUID),('dwCatalogEntryId',DWORD),('ProtocolChain',WSAPROTOCOLCHAIN),('iVersion',INT),('iAddressFamily',INT),('iMaxSockAddr',INT),('iMinSockAddr',INT),('iSocketType',INT),('iProtocol',INT),('iProtocolMaxOffset',INT),('iNetworkByteOrder',INT),('iSecurityScheme',INT),('dwMessageSize',DWORD),('dwProviderReserved',DWORD),('szProtocol',CHAR*256)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

# Struct WSAPROTOCOL_INFOW
# Alias Names: _WSAPROTOCOL_INFOW
# Alias Pointer Names: LPWSAPROTOCOL_INFOW

def get_WSAPROTOCOL_INFOW(uc: Uc, address: int, em):
    return WSAPROTOCOL_INFOW.from_buffer_copy(uc.mem_read(address, sizeof(WSAPROTOCOL_INFOW)))

# Struct Aliases:
# get__WSAPROTOCOL_INFOW = get_WSAPROTOCOL_INFOW

# Struct Pointers:
LPWSAPROTOCOL_INFOW_32BIT = POINTER_32BIT
LPWSAPROTOCOL_INFOW_64BIT = POINTER_64BIT

class WSAPROTOCOL_INFOW(LittleEndianStructure):
    types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'GUID', 'DWORD', 'WSAPROTOCOLCHAIN', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'DWORD', 'DWORD', 'WCHAR']
    __slots__ = ('dwServiceFlags1', 'dwServiceFlags2', 'dwServiceFlags3', 'dwServiceFlags4', 'dwProviderFlags', 'ProviderId', 'dwCatalogEntryId', 'ProtocolChain', 'iVersion', 'iAddressFamily', 'iMaxSockAddr', 'iMinSockAddr', 'iSocketType', 'iProtocol', 'iProtocolMaxOffset', 'iNetworkByteOrder', 'iSecurityScheme', 'dwMessageSize', 'dwProviderReserved', 'szProtocol')
    lookUps = {0: ReverseLookUps.Socket.ServiceFlags, 9: ReverseLookUps.Socket.Af, 12: ReverseLookUps.Socket.Type, 13: ReverseLookUps.Socket.Protocol, 15: ReverseLookUps.Socket.NetworkByteOrder, 16: ReverseLookUps.Socket.SecurityScheme}

    _fields_ = [('dwServiceFlags1',DWORD),('dwServiceFlags2',DWORD),('dwServiceFlags3',DWORD),('dwServiceFlags4',DWORD),('dwProviderFlags',DWORD),('ProviderId',GUID),('dwCatalogEntryId',DWORD),('ProtocolChain',WSAPROTOCOLCHAIN),('iVersion',INT),('iAddressFamily',INT),('iMaxSockAddr',INT),('iMinSockAddr',INT),('iSocketType',INT),('iProtocol',INT),('iProtocolMaxOffset',INT),('iNetworkByteOrder',INT),('iSecurityScheme',INT),('dwMessageSize',DWORD),('dwProviderReserved',DWORD),('szProtocol',WCHAR*256)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct NETRESOURCEA
# Alias Names: _NETRESOURCEA
# Alias Pointer Names: LPNETRESOURCEA

def get_NETRESOURCEA(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'LPSTR']
        __slots__ = ('dwScope', 'dwType', 'dwDisplayType', 'dwUsage', 'lpLocalName', 'lpRemoteName', 'lpComment', 'lpProvider')
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        _fields_ = [('dwScope',DWORD),('dwType',DWORD),('dwDisplayType',DWORD),('dwUsage',DWORD),('lpLocalName',LPSTR_32BIT),('lpRemoteName',LPSTR_32BIT),('lpComment',LPSTR_32BIT),('lpProvider',LPSTR_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'LPSTR']
        __slots__ = ('dwScope', 'dwType', 'dwDisplayType', 'dwUsage', 'lpLocalName', 'lpRemoteName', 'lpComment', 'lpProvider')
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        _fields_ = [('dwScope',DWORD),('dwType',DWORD),('dwDisplayType',DWORD),('dwUsage',DWORD),('lpLocalName',LPSTR_64BIT),('lpRemoteName',LPSTR_64BIT),('lpComment',LPSTR_64BIT),('lpProvider',LPSTR_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct NETRESOURCEW
# Alias Names: _NETRESOURCEW
# Alias Pointer Names: LPNETRESOURCEW

def get_NETRESOURCEW(uc: Uc, address: int, em):
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

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'LPWSTR']
        __slots__ = ('dwScope', 'dwType', 'dwDisplayType', 'dwUsage', 'lpLocalName', 'lpRemoteName', 'lpComment', 'lpProvider')
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        _fields_ = [('dwScope',DWORD),('dwType',DWORD),('dwDisplayType',DWORD),('dwUsage',DWORD),('lpLocalName',LPWSTR_32BIT),('lpRemoteName',LPWSTR_32BIT),('lpComment',LPWSTR_32BIT),('lpProvider',LPWSTR_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'DWORD', 'DWORD', 'DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'LPWSTR']
        __slots__ = ('dwScope', 'dwType', 'dwDisplayType', 'dwUsage', 'lpLocalName', 'lpRemoteName', 'lpComment', 'lpProvider')
        lookUps = {0: ReverseLookUps.Net.Scope, 1: ReverseLookUps.Net.Type, 2: ReverseLookUps.Net.Display, 3: ReverseLookUps.Net.Usage}

        _fields_ = [('dwScope',DWORD),('dwType',DWORD),('dwDisplayType',DWORD),('dwUsage',DWORD),('lpLocalName',LPWSTR_64BIT),('lpRemoteName',LPWSTR_64BIT),('lpComment',LPWSTR_64BIT),('lpProvider',LPWSTR_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))
