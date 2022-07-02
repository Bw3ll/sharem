from ctypes import LittleEndianStructure, sizeof
from enum import Enum
from struct import pack, unpack
from time import time_ns

from sharem.sharem.helper.ctypesUnion import LittleEndianUnion
from sharem.sharem.helper.structHelpers import BOOL, DWORD, DWORD_PTR, HANDLE_32BIT, HANDLE_64BIT, LONG, LONGLONG, LPBYTE_32BIT, LPBYTE_64BIT, LPSTR_32BIT, LPSTR_64BIT, LPVOID_32BIT, LPVOID_64BIT, LPWSTR_32BIT, LPWSTR_64BIT, PWSTR_32BIT, PWSTR_64BIT, ULONGLONG, USHORT, WCHAR, WORD

from ..helper.emuHelpers import Uc

class PROCESS_INFORMATION: # Needs Redone
    # Backs PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION
    types = ['HANDLE','HANDLE','DWORD','DWORD']
    names = ['hProcess','hThread','dwProcessId','dwThreadId']

    nextProcessID = 10000
    nextThreadID = 20000

    def __init__(self, hProcess: int, hThread: int, pID: int = 0, tID: int = 0):
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

    def writeToMemory(self, uc: Uc, address: int):
        packedStruct = pack('<IIII', self.hProcess, self.hThread, self.dwProcessId, self.dwThreadId)
        uc.mem_write(address, packedStruct)

    def readFromMemory(self, uc: Uc, address: int):
        data = uc.mem_read(address, 16)
        unpackedStruct = unpack('<IIII', data)
        self.hProcess = unpackedStruct[0]
        self.hThread = unpackedStruct[1]
        self.dwProcessId = unpackedStruct[2]
        self.dwThreadId = unpackedStruct[3]


class PROCESSENTRY32: # Needs Redone
    # Backs both PROCESSENTRY32 and PROCESSENTRY32W
    types = ['DWORD','DWORD','DWORD','ULONG_PTR','DWORD','DWORD','DWORD','LONG','DWORD','CHAR'] 
    names = ['dwSize','cntUsage','th32ProcessID','th32DefaultHeapID','th32ModuleID','cntThreads','th32ParentProcessID','pcPriClassBase','dwFlags','szExeFile']

    def __init__(self, processID, threadCount, parent_pID, baseThreadPriority, exeFile: str):
        self.dwSizeA = 296 # Ascii Size
        self.dwSizeW = 556 # Unicode Size
        self.cntUsage = 0 # No Longer Used
        self.th32ProcessID = processID
        self.th32DefaultHeapID = 0 # No Longer Used
        self.th32ModuleID = 0 # No Longer Used
        self.cntThreads= threadCount
        self.th32ParentProcessID = parent_pID
        self.pcPriClassBase = baseThreadPriority
        self.dwFlags = 0 # No Longer Used
        self.szExeFile = exeFile

    def writeToMemoryA(self, uc: Uc, address):
        packedStruct = pack('<IIILIIIlI260s', self.dwSizeA, self.cntUsage, self.th32ProcessID, self.th32DefaultHeapID, self.th32ModuleID, self.cntThreads, self.th32ParentProcessID, self.pcPriClassBase, self.dwFlags, self.szExeFile.encode('ascii'))
        uc.mem_write(address, packedStruct)

    def readFromMemoryA(self, uc: Uc, address):
        data = uc.mem_read(address, self.dwSizeA)
        unpackedStruct = unpack('<IIILIIIlI260s', data)
        self.dwSizeA = unpackedStruct[0]
        self.cntUsage = unpackedStruct[1]
        self.th32ProcessID = unpackedStruct[2]
        self.th32DefaultHeapID = unpackedStruct[3]
        self.th32ModuleID = unpackedStruct[4]
        self.cntThreads = unpackedStruct[5]
        self.th32ParentProcessID = unpackedStruct[6]
        self.pcPriClassBase = unpackedStruct[7]
        self.dwFlags = unpackedStruct[8]
        self.szExeFile = unpackedStruct[9].decode()

    def writeToMemoryW(self, uc: Uc, address):
        packedStruct = pack('<IIILIIIlI520s', self.dwSizeW, self.cntUsage, self.th32ProcessID, self.th32DefaultHeapID, self.th32ModuleID, self.cntThreads, self.th32ParentProcessID, self.pcPriClassBase, self.dwFlags,self.szExeFile.encode('utf-16')[2:])
        uc.mem_write(address, packedStruct)

    def readFromMemoryW(self, uc: Uc, address):
        data = uc.mem_read(address, self.dwSizeW)
        unpackedStruct = unpack('<IIILIIIlI520s', data)
        self.dwSizeW = unpackedStruct[0]
        self.cntUsage = unpackedStruct[1]
        self.th32ProcessID = unpackedStruct[2]
        self.th32DefaultHeapID = unpackedStruct[3]
        self.th32ModuleID = unpackedStruct[4]
        self.cntThreads = unpackedStruct[5]
        self.th32ParentProcessID = unpackedStruct[6]
        self.pcPriClassBase = unpackedStruct[7]
        self.dwFlags = unpackedStruct[8]
        self.szExeFile = unpackedStruct[9].decode()

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

# class SYSTEMTIME:
#     # Backs SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME
#     types = ['WORD','WORD','WORD','WORD','WORD','WORD','WORD','WORD']
#     names = ['wYear','wMonth','wDayOfWeek','wDay','wHour','wMinute','wSecond','wMilliseconds']

#     def __init__(self, utc: bool, customTime= 0):
#         if utc:
#             if customTime == 0:
#                 timeVal = gmtime()
#             else:
#                 timeVal = gmtime(customTime)
#         else:
#             if customTime == 0:
#                 timeVal = localtime()
#             else:
#                 timeVal = localtime(customTime)

#         self.wYear = timeVal.tm_year
#         self.wMonth = timeVal.tm_mon
#         dayOfWeek = timeVal.tm_wday + 1 # Convert Monday 0 to Sunday 0
#         if dayOfWeek == 7: dayOfWeek = 0
#         self.wDayOfWeek = dayOfWeek
#         self.wDay = timeVal.tm_mday
#         self.wHour = timeVal.tm_hour
#         self.wMinute = timeVal.tm_min
#         self.wSecond = timeVal.tm_sec
#         self.wMilliseconds = 0

#     def writeToMemory(self, uc: Uc, address):
#         packedStruct = pack('<HHHHHHHH', self.wYear, self.wMonth, self.wDayOfWeek, self.wDay, self.wHour, self.wMinute, self.wSecond, self.wMilliseconds)
#         uc.mem_write(address, packedStruct)

#     def readFromMemory(self, uc: Uc, address):
#         data = uc.mem_read(address, 16)
#         unpackedStruct = unpack('<HHHHHHHH', data)
#         self.wYear = unpackedStruct[0]
#         self.wMonth = unpackedStruct[1]
#         self.wDayOfWeek = unpackedStruct[2]
#         self.wDay = unpackedStruct[3]
#         self.wHour = unpackedStruct[4]
#         self.wMinute = unpackedStruct[5]
#         self.wSecond = unpackedStruct[6]
#         self.wMilliseconds = unpackedStruct[7]

# Struct SYSTEMTIME
# Alias Names: _SYSTEMTIME
# Alias Pointer Names: *PSYSTEMTIME, *LPSYSTEMTIME

def get_SYSTEMTIME(uc: Uc, address: int, em):
    return SYSTEMTIME.from_buffer_copy(uc.mem_read(address, sizeof(SYSTEMTIME)))

# Struct Aliases:
get__SYSTEMTIME = get_SYSTEMTIME

class SYSTEMTIME(LittleEndianStructure):
    types = ['WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD']
    names = ['wYear', 'wMonth', 'wDayOfWeek', 'wDay', 'wHour', 'wMinute', 'wSecond', 'wMilliseconds']
    __slots__ = ('types', 'names', 'wYear', 'wMonth', 'wDayOfWeek', 'wDay', 'wHour', 'wMinute', 'wSecond', 'wMilliseconds')
    _fields_ = [("wYear",WORD),("wMonth",WORD),("wDayOfWeek",WORD),("wDay",WORD),("wHour",WORD),("wMinute",WORD),("wSecond",WORD),("wMilliseconds",WORD)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

class SYSTEM_INFO: # Needs Redone
    # Backs SYSTEM_INFO, *LPSYSTEM_INFO
    def __init__(self, PA: 'SYSTEM_INFO.Processor', numProcessors: int):
        self.wProcessorArchitecture = PA
        self.wReserved = 0
        self.dwPageSize = 4096 # 4 KB
        self.lpMinimumApplicationAddress = 0x25000000 # Ask someone
        self.lpMaximumApplicationAddress = 0
        self.dwPageSizedwActiveProcessorMask = 0 # Check
        self.dwNumberOfProcessors = numProcessors
        self.dwProcessorType = 0
        self.dwAllocationGranularity = 0 # check
        self.wProcessorLevel = 0 # check
        self.wProcessorRevision = 0 # check

    def writeToMemory(self, uc: Uc, address):
        packedStruct = pack('<HHHHHHHH', self.wYear, self.wMonth, self.wDayOfWeek, self.wDay, self.wHour, self.wMinute, self.wSecond, self.wMilliseconds)
        uc.mem_write(address, packedStruct)

    def readFromMemory(self, uc: Uc, address):
        data = uc.mem_read(address, 16)
        unpackedStruct = unpack('<HHHHHHHH', data)
        self.wYear = unpackedStruct[0]
        self.wMonth = unpackedStruct[1]
        self.wDayOfWeek = unpackedStruct[2]
        self.wDay = unpackedStruct[3]
        self.wHour = unpackedStruct[4]
        self.wMinute = unpackedStruct[5]
        self.wSecond = unpackedStruct[6]
        self.wMilliseconds = unpackedStruct[7]

    class Processor(Enum):
        PROCESSOR_ARCHITECTURE_AMD64 = 9 # x64
        PROCESSOR_ARCHITECTURE_ARM = 5 # Arm 32
        PROCESSOR_ARCHITECTURE_ARM64 = 12 # Arm64/Aarch64
        PROCESSOR_ARCHITECTURE_IA64 = 6
        PROCESSOR_ARCHITECTURE_INTEL = 0 # x86
        PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff

class FILETIME: # Needs Redone
    types = ['DWORD','DWORD']
    names = ['dwLowDateTime','dwHighDateTime']

    def __init__(self):
        # time is in epoch 100 nanoseconds split into low and high
            timeEpoch = time_ns()
            #print("a0")
            ##timeEpoch = hex(timeEpoch)
            #print(timeEpoch)
            #print(hex(timeEpoch))
            #print("a1")
            #split into low and high end
            #test64Bit = 0xbbbbccccddddffff
            #print(hex(test64Bit))
            #testUpper = test64Bit >> 32
            #testLower = test64Bit & 0xffffffff
            #print(testUpper)
            #print(hex(testUpper))
            #print(testLower)
            #print(hex(testLower))

            highEndData = timeEpoch >> 32
            lowEndData = timeEpoch & 0xffffffff

            #print("high create")
            #print(highEndData)
            #print(hex(highEndData))
            #print("low create")
            #print(lowEndData)
            #print(hex(lowEndData))
            self.dwLowDateTime = lowEndData
            self.dwHighDateTime = highEndData

    def writeToMemory(self, uc: Uc, address):
        #print("memWrite entry filetime")
        ##print(address)
        #print("low")
        #print(self.dwLowDateTime)
        #print("high")
        #print(self.dwHighDateTime)
        packedStruct = pack('<II', self.dwLowDateTime, self.dwHighDateTime)
        #print("a1")
        uc.mem_write(address, packedStruct)
        #print("end memwrite")

    def readFromMemory(self, uc: Uc, address):
        #print("read from Filetime")
        data = uc.mem_read(address, 8) # Size of two dwords
        unPacked = unpack('<II', data)
        self.dwLowDateTime = unPacked[0]         
        self.dwHighDateTime = unPacked[1]

def get_UNICODE_STRING(uc: Uc, address: int, em):
    if em.arch == 32:
        return UNICODE_STRING.ARCH32.from_buffer_copy(uc.mem_read(address, sizeof(UNICODE_STRING.ARCH32)))
    else:
        return UNICODE_STRING.ARCH64.from_buffer_copy(uc.mem_read(address, sizeof(UNICODE_STRING.ARCH64)))

class UNICODE_STRING:

    class ARCH32(LittleEndianStructure):
        types = ['USHORT', 'USHORT', 'PWSTR']
        names = ['Length', 'MaximumLength', 'Buffer']
        __slots__ = ('types', 'names', 'Length', 'MaximumLength', 'Buffer')
        _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", PWSTR_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            print(sizeof(UNICODE_STRING.ARCH32))
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['USHORT', 'USHORT', 'PWSTR']
        names = ['Length', 'MaximumLength', 'Buffer']
        __slots__ = ('types', 'names', 'Length', 'MaximumLength', 'Buffer')
        _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", PWSTR_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

# Struct TIME_ZONE_INFORMATION
# Alias Names: _TIME_ZONE_INFORMATION
# Alias Pointer Names: *PTIME_ZONE_INFORMATION, *LPTIME_ZONE_INFORMATION

def get_TIME_ZONE_INFORMATION(uc: Uc, address: int, em):
    return TIME_ZONE_INFORMATION.from_buffer_copy(uc.mem_read(address, sizeof(TIME_ZONE_INFORMATION)))

# Struct Aliases:
get__TIME_ZONE_INFORMATION = get_TIME_ZONE_INFORMATION

class TIME_ZONE_INFORMATION(LittleEndianStructure):
    types = ['LONG', 'WCHAR', 'SYSTEMTIME', 'LONG', 'WCHAR', 'SYSTEMTIME', 'LONG']
    names = ['Bias', 'StandardName', 'StandardDate', 'StandardBias', 'DaylightName', 'DaylightDate', 'DaylightBias']
    __slots__ = ('types', 'names', 'Bias', 'StandardName', 'StandardDate', 'StandardBias', 'DaylightName', 'DaylightDate', 'DaylightBias')
    _fields_ = [("Bias",LONG),("StandardName",WCHAR * 32),("StandardDate",SYSTEMTIME),("StandardBias",LONG),("DaylightName",WCHAR * 32),("DaylightDate",SYSTEMTIME),("DaylightBias",LONG)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))


# Struct REG_TZI_FORMAT
# Alias Names: _REG_TZI_FORMAT
# Alias Pointer Names:

def get_REG_TZI_FORMAT(uc: Uc, address: int, em):
    return REG_TZI_FORMAT.from_buffer_copy(uc.mem_read(address, sizeof(REG_TZI_FORMAT)))

# Struct Aliases:
get__REG_TZI_FORMAT = get_REG_TZI_FORMAT

class REG_TZI_FORMAT(LittleEndianStructure):
    types = ['LONG', 'LONG', 'LONG', 'SYSTEMTIME', 'SYSTEMTIME']
    names = ['Bias', 'StandardBias', 'DaylightBias', 'StandardDate', 'DaylightDate']
    __slots__ = ('types', 'names', 'Bias', 'StandardBias', 'DaylightBias', 'StandardDate', 'DaylightDate')
    _fields_ = [("Bias",LONG),("StandardBias",LONG),("DaylightBias",LONG),("StandardDate",SYSTEMTIME),("DaylightDate",SYSTEMTIME)]

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

class STARTUPINFOA:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        names = ['cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError']
        __slots__ = ('types', 'names', 'cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        _fields_ = [("cb",DWORD),("lpReserved",LPSTR_32BIT),("lpDesktop",LPSTR_32BIT),("lpTitle",LPSTR_32BIT),("dwX",DWORD),("dwY",DWORD),("dwXSize",DWORD),("dwYSize",DWORD),("dwXCountChars",DWORD),("dwYCountChars",DWORD),("dwFillAttribute",DWORD),("dwFlags",DWORD),("wShowWindow",WORD),("cbReserved2",WORD),("lpReserved2",LPBYTE_32BIT),("hStdInput",HANDLE_32BIT),("hStdOutput",HANDLE_32BIT),("hStdError",HANDLE_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        names = ['cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError']
        __slots__ = ('types', 'names', 'cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        _fields_ = [("cb",DWORD),("lpReserved",LPSTR_64BIT),("lpDesktop",LPSTR_64BIT),("lpTitle",LPSTR_64BIT),("dwX",DWORD),("dwY",DWORD),("dwXSize",DWORD),("dwYSize",DWORD),("dwXCountChars",DWORD),("dwYCountChars",DWORD),("dwFillAttribute",DWORD),("dwFlags",DWORD),("wShowWindow",WORD),("cbReserved2",WORD),("lpReserved2",LPBYTE_64BIT),("hStdInput",HANDLE_64BIT),("hStdOutput",HANDLE_64BIT),("hStdError",HANDLE_64BIT)]

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
get__STARTUPINFOW = get_STARTUPINFOW

class STARTUPINFOW:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        names = ['cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError']
        __slots__ = ('types', 'names', 'cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        _fields_ = [("cb",DWORD),("lpReserved",LPWSTR_32BIT),("lpDesktop",LPWSTR_32BIT),("lpTitle",LPWSTR_32BIT),("dwX",DWORD),("dwY",DWORD),("dwXSize",DWORD),("dwYSize",DWORD),("dwXCountChars",DWORD),("dwYCountChars",DWORD),("dwFillAttribute",DWORD),("dwFlags",DWORD),("wShowWindow",WORD),("cbReserved2",WORD),("lpReserved2",LPBYTE_32BIT),("hStdInput",HANDLE_32BIT),("hStdOutput",HANDLE_32BIT),("hStdError",HANDLE_32BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'LPWSTR', 'LPWSTR', 'LPWSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        names = ['cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError']
        __slots__ = ('types', 'names', 'cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError')
        _fields_ = [("cb",DWORD),("lpReserved",LPWSTR_64BIT),("lpDesktop",LPWSTR_64BIT),("lpTitle",LPWSTR_64BIT),("dwX",DWORD),("dwY",DWORD),("dwXSize",DWORD),("dwYSize",DWORD),("dwXCountChars",DWORD),("dwYCountChars",DWORD),("dwFillAttribute",DWORD),("dwFlags",DWORD),("wShowWindow",WORD),("cbReserved2",WORD),("lpReserved2",LPBYTE_64BIT),("hStdInput",HANDLE_64BIT),("hStdOutput",HANDLE_64BIT),("hStdError",HANDLE_64BIT)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))



# class OBJECT_ATTRIBUTES: # To Be Finished Later 
#     def __init__(self):
#         self.Length = calcsize('<LIILII')
#         self.RootDirectory
#         self.ObjectName
#         self.Attributes
#         self.SecurityDescriptor
#         self.SecurityQualityOfService


def get_LARGE_INTEGER(uc: Uc, address: int, em):
    return LARGE_INTEGER.from_buffer_copy(uc.mem_read(address, sizeof(LARGE_INTEGER)))

class LARGE_INTEGER(LittleEndianStructure):
    types = ["LONGLONG"]
    names = ["QuadPart"]
    __slots__ = ("types", "names", "QuadPart")
    _fields_ = [("QuadPart", LONGLONG)]

    def writeToMemory(self, uc: Uc, address: int):
        uc.mem_write(address, bytes(self))

def get_ULARGE_INTEGER(uc: Uc, address: int, em):
    return LARGE_INTEGER.from_buffer_copy(uc.mem_read(address, sizeof(ULARGE_INTEGER)))

class ULARGE_INTEGER(LittleEndianStructure):
    types = ["LONGLONG"]
    names = ["QuadPart"]
    __slots__ = ("types", "names", "QuadPart")
    _fields_ = [("QuadPart", ULONGLONG)]

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
get__SECURITY_ATTRIBUTES = get_SECURITY_ATTRIBUTES

class SECURITY_ATTRIBUTES:

    class ARCH32(LittleEndianStructure):
        types = ['DWORD', 'LPVOID', 'BOOL']
        names = ['nLength', 'lpSecurityDescriptor', 'bInheritHandle']
        __slots__ = ("types", "names", 'nLength', 'lpSecurityDescriptor', 'bInheritHandle')
        _fields_ = [("nLength",DWORD),("lpSecurityDescriptor",LPVOID_32BIT),("bInheritHandle",BOOL)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['DWORD', 'LPVOID', 'BOOL']
        names = ['nLength', 'lpSecurityDescriptor', 'bInheritHandle']
        __slots__ = ("types", "names", 'nLength', 'lpSecurityDescriptor', 'bInheritHandle')
        _fields_ = [("nLength",DWORD),("lpSecurityDescriptor",LPVOID_64BIT),("bInheritHandle",BOOL)]

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

class value_entA:

    class ARCH32(LittleEndianStructure):
        types = ['LPSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        names = ['ve_valuename', 've_valuelen', 've_valueptr', 've_type']
        __slots__ = ('types', 'names', 've_valuename', 've_valuelen', 've_valueptr', 've_type')
        _fields_ = [("ve_valuename",LPSTR_32BIT),("ve_valuelen",DWORD),("ve_valueptr",DWORD_PTR),("ve_type",DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['LPSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        names = ['ve_valuename', 've_valuelen', 've_valueptr', 've_type']
        __slots__ = ('types', 'names', 've_valuename', 've_valuelen', 've_valueptr', 've_type')
        _fields_ = [("ve_valuename",LPSTR_64BIT),("ve_valuelen",DWORD),("ve_valueptr",DWORD_PTR),("ve_type",DWORD)]

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

class value_entW:

    class ARCH32(LittleEndianStructure):
        types = ['LPWSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        names = ['ve_valuename', 've_valuelen', 've_valueptr', 've_type']
        __slots__ = ('types', 'names', 've_valuename', 've_valuelen', 've_valueptr', 've_type')
        _fields_ = [("ve_valuename",LPWSTR_32BIT),("ve_valuelen",DWORD),("ve_valueptr",DWORD_PTR),("ve_type",DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))

    class ARCH64(LittleEndianStructure):
        types = ['LPWSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        names = ['ve_valuename', 've_valuelen', 've_valueptr', 've_type']
        __slots__ = ('types', 'names', 've_valuename', 've_valuelen', 've_valueptr', 've_type')
        _fields_ = [("ve_valuename",LPWSTR_64BIT),("ve_valuelen",DWORD),("ve_valueptr",DWORD_PTR),("ve_type",DWORD)]

        def writeToMemory(self, uc: Uc, address: int):
            uc.mem_write(address, bytes(self))
