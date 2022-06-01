from enum import Enum
from struct import calcsize, pack, unpack
from time import gmtime, localtime,time_ns, localtime
from ..helper.emuHelpers import Uc

class struct_PROCESSENTRY32:
    # Backs both PROCESSENTRY32 and PROCESSENTRY32W
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

class struct_THREADENTRY32:
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

class struct_MODULEENTRY32:
    # Backs both MODULEENTRY32 and MODULEENTRY32W
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

class struct_SYSTEMTIME:
    # Backs SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME
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

class Processor(Enum):
    PROCESSOR_ARCHITECTURE_AMD64 = 9 # x64
    PROCESSOR_ARCHITECTURE_ARM = 5 # Arm 32
    PROCESSOR_ARCHITECTURE_ARM64 = 12 # Arm64/Aarch64
    PROCESSOR_ARCHITECTURE_IA64 = 6
    PROCESSOR_ARCHITECTURE_INTEL = 0 # x86
    PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff

class struct_SYSTEM_INFO:
    # Backs SYSTEM_INFO, *LPSYSTEM_INFO
    def __init__(self, PA: Processor, numProcessors: int):
        self.wProcessorArchitecture = PA
        self.wReserved = 0
        self.dwPageSize = 4096 #KB
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

class struct_FILETIME:
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
    def writeToMemory(self, uc, address):
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
   
    def readFromMemory(self, uc, address):
        #print("read from Filetime")
        data = uc.mem_read(address, 8) # Size of two dwords
        unPacked = unpack('<II', data)
        self.dwLowDateTime = unPacked[0]         
        self.dwHighDateTime = unPacked[1]

class struct_UNICODE_STRING:
    # UNICODE_STRING, *PUNICODE_STRING
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

# class struct_OBJECT_ATTRIBUTES: # To Be Finished Later 
#     def __init__(self):
#         self.Length = calcsize('<LIILII')
#         self.RootDirectory
#         self.ObjectName
#         self.Attributes
#         self.SecurityDescriptor
#         self.SecurityQualityOfService
        