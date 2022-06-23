from enum import Enum
from struct import pack, unpack
from time import gmtime, localtime,time_ns, localtime
from ..helper.emuHelpers import Uc

# Helpers
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

def buildPtrString(pointer, val):
    return hex(pointer) + " -> " + hex(val)

def getPointerVal(uc: Uc, pointer: int):
    val = uc.mem_read(pointer, 4)
    return unpack('<I', val)[0]

def makeStructVals(uc: Uc, struct: 'Structure', address: int,unicode: bool = False):
    pTypes = struct.types
    pNames = struct.names
    pVals = []
    for name in pNames:
        try:
            value = getattr(struct, name)
        except:
            # Some Struct Implementations are both Unicode and Ascii 
            # So some attributes have A or W Suffix.
            if not unicode: 
                name = name + 'A'
                value = getattr(struct, name) 
            else:
                name = name + 'W'
                value = getattr(struct, name)
        pVals.append(value)

    for i in range(len(pTypes)):
        if "STR" in pTypes[i]:  # finding ones with string
            try:
                if "WSTR" in pTypes[i]:
                    pVals[i] = read_unicode(uc, pVals[i])
                else:
                    pVals[i] = read_string(uc, pVals[i])
            except:
                pass
        elif pTypes[i][0] == 'P': # Pointer Builder
            try:
                pointerVal = getPointerVal(uc, pVals[i])
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
            try:
                pVals[i] = hex(pVals[i])
            except:
                pVals[i] = str(pVals[i])
                # If fail then Param is Probably String and Just Display value

    # zipped = tuple(zip(pTypes, pNames, pVals))
    
    return (pTypes, pNames, pVals, hex(address))

class Structure:
    types: 'list[str]' = []
    names: 'list[str]' = []

    class PROCESS_INFORMATION:
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
                self.dwProcessId = Structure.PROCESS_INFORMATION.nextProcessID
                Structure.PROCESS_INFORMATION.nextProcessID += 1
            if tID != 0:
                self.dwThreadId = tID
            else:
                self.dwThreadId = Structure.PROCESS_INFORMATION.nextThreadID
                Structure.PROCESS_INFORMATION.nextThreadID += 1

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


    class PROCESSENTRY32:
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

    class THREADENTRY32:
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

    class MODULEENTRY32:
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

    class SYSTEMTIME:
        # Backs SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME
        types = ['WORD','WORD','WORD','WORD','WORD','WORD','WORD','WORD']
        names = ['wYear','wMonth','wDayOfWeek','wDay','wHour','wMinute','wSecond','wMilliseconds']

        def __init__(self, utc: bool, customTime= 0):
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

    class SYSTEM_INFO:
        # Backs SYSTEM_INFO, *LPSYSTEM_INFO
        def __init__(self, PA: 'Structure.SYSTEM_INFO.Processor', numProcessors: int):
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

    class FILETIME:
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

    class UNICODE_STRING:
        # UNICODE_STRING, *PUNICODE_STRING
        types = ['USHORT', 'USHORT', 'PWSTR',]
        names = ['Length', 'MaximumLength', 'Buffer']

        def __init__(self, length: int, PWSTR: int):
            self.Length = length
            self.MaximumLength = length
            self.Buffer = PWSTR

        def writeToMemory(self, uc: Uc, address):
            packedStruct = pack(f'<HHI', self.Length, self.MaximumLength, self.Buffer)
            uc.mem_write(address, packedStruct)

        def readFromMemory(self, uc: Uc, address):
            data = uc.mem_read(address, 8)
            unpackedStruct = unpack('<HHI', data)
            self.Length = unpackedStruct[0]
            self.MaximumLength = unpackedStruct[1]
            self.Buffer = unpackedStruct[2]

    class TIME_ZONE_INFORMATION:
        # UNICODE_STRING, *PUNICODE_STRING
        types = ['LONG', 'WCHAR', 'SYSTEMTIME', 'LONG', 'WCHAR', 'SYSTEMTIME', 'LONG']
        names = ['Bias', 'StandardName', 'StandardDate', 'StandardBias', 'DaylightName', 'DaylightDate', 'DaylightBias']

        def __init__(self):
            self.Bias = 0
            self.StandardName = "UTC"
            self.StandardDate = 0
            self.StandardBias = 0
            self.DaylightName = "UTC"
            self.DaylightDate = 0
            self.DaylightBias = 0

        def writeToMemory(self, uc: Uc, address):
            packedStruct = pack('<l64sIl64sIl', self.Bias, self.StandardName.encode('UTF-16')[2:], self.StandardDate, self.StandardBias, self.DaylightName.encode('UTF-16')[2:], self.DaylightDate, self.DaylightBias)
            uc.mem_write(address, packedStruct)

        def readFromMemory(self, uc: Uc, address):
            data = uc.mem_read(address, 8)
            unpackedStruct = unpack('<l64sIl64sIl', data)
            self.Bias = unpackedStruct[0]
            self.StandardName = unpackedStruct[1].decode()
            self.StandardDate = unpackedStruct[2]
            self.StandardBias = unpackedStruct[3]
            self.DaylightName = unpackedStruct[4].decode()
            self.DaylightDate = unpackedStruct[5]
            self.DaylightBias = unpackedStruct[6]

    class STARTUPINFOA:
        # UNICODE_STRING, *PUNICODE_STRING
        types = ['DWORD', 'LPSTR', 'LPSTR', 'LPSTR', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'LPBYTE', 'HANDLE', 'HANDLE', 'HANDLE']
        names = ['cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY', 'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2', 'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError']

        def __init__(self):
            self.cb = 0
            self.lpReserved = 0
            self.lpDesktop = "DESKTOP-NAME"
            self.lpTitle = 0
            self.dwX = 0
            self.dwY = 0
            self.dwXSize = 0
            self.dwYSize = 0
            self.dwXCountChars = 0
            self.dwYCountChars = 0
            self.dwFillAttribute = 0
            self.dwFlags = 0
            self.wShowWindow = 0
            self.cbReserved2 = 0
            self.lpReserved2 = 0
            self.hStdInput = 0
            self.hStdOutput = 0
            self.hStdError = 0

        def writeToMemory(self, uc: Uc, address):
            packedStruct = pack('<l64sIl64sIl', self.cb, self.lpReserved, self.lpDesktop, self.lpTitle, self.dwX, self.dwY, self.dwXSize, self.dwYSize, self.dwXCountChars, self.dwYCountChars, self.dwFillAttribute, self.dwFlags, self.wShowWindow, self.cbReserved2, self.lpReserved2, self.hStdInput, self.hStdOutput, self.hStdError)
            uc.mem_write(address, packedStruct)

        def readFromMemory(self, uc: Uc, address):
            data = uc.mem_read(address, 19)
            unpackedStruct = unpack('<l64sIl64sIl', data)

            self.cb = unpackedStruct[0]
            self.lpReserved = unpackedStruct[1]
            self.lpDesktop = unpackedStruct[2]
            self.lpTitle = unpackedStruct[3]
            self.dwX = unpackedStruct[4]
            self.dwY = unpackedStruct[5]
            self.dwXSize = unpackedStruct[6]
            self.dwYSize = unpackedStruct[7]
            self.dwXCountChars = unpackedStruct[8]
            self.dwYCountChars = unpackedStruct[9]
            self.dwFillAttribute = unpackedStruct[10]
            self.dwFlags = unpackedStruct[11]
            self.wShowWindow = unpackedStruct[12]
            self.cbReserved2 = unpackedStruct[13]
            self.lpReserved2 = unpackedStruct[14]
            self.hStdInput = unpackedStruct[15]
            self.hStdOutput = unpackedStruct[16]
            self.hStdError = unpackedStruct[17]

    

    # class OBJECT_ATTRIBUTES: # To Be Finished Later 
    #     def __init__(self):
    #         self.Length = calcsize('<LIILII')
    #         self.RootDirectory
    #         self.ObjectName
    #         self.Attributes
    #         self.SecurityDescriptor
    #         self.SecurityQualityOfService

    class VALENTA:
        types = ['LPSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        names = ['ve_valuename', 've_valuele', 've_valueptr', 've_type']

        def __init__(self, nameAddress: int, valueLength: int, valueAddress: int, type: int):
            self.ve_valuename = nameAddress
            self.ve_valuelen = valueLength
            self.ve_valueptr = valueAddress
            self.ve_type = type

        def writeToMemory(self, uc: Uc, address: int):
            packedStruct = pack(f'<IIII', self.ve_valuename, self.ve_valuelen, self.ve_valueptr, self.ve_type,)
            uc.mem_write(address, packedStruct)

        def readFromMemory(self, uc: Uc, address: int):
            data = uc.mem_read(address, 16)
            unpackedStruct = unpack('<IIII', data)
            self.ve_valuename = unpackedStruct[0]
            self.ve_valuelen = unpackedStruct[1]
            self.ve_valueptr = unpackedStruct[2]
            self.ve_type = unpackedStruct[3]

    class VALENTW:
        types = ['LPWSTR', 'DWORD', 'DWORD_PTR', 'DWORD']
        names = ['ve_valuename', 've_valuele', 've_valueptr', 've_type']

        def __init__(self, nameAddress: int, valueLength: int, valueAddress: int, type: int):
            self.ve_valuename = nameAddress
            self.ve_valuelen = valueLength
            self.ve_valueptr = valueAddress
            self.ve_type = type

        def writeToMemory(self, uc: Uc, address: int):
            packedStruct = pack(f'<IIII', self.ve_valuename, self.ve_valuelen, self.ve_valueptr, self.ve_type,)
            uc.mem_write(address, packedStruct)

        def readFromMemory(self, uc: Uc, address: int):
            data = uc.mem_read(address, 16)
            unpackedStruct = unpack('<IIII', data)
            self.ve_valuename = unpackedStruct[0]
            self.ve_valuelen = unpackedStruct[1]
            self.ve_valueptr = unpackedStruct[2]
            self.ve_type = unpackedStruct[3]