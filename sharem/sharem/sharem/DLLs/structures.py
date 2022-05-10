from struct import calcsize, pack, unpack
from ..helper.emuHelpers import Uc

class struct_PROCESSENTRY32:
    # Backs both PROCESSENTRY32 and PROCESSENTRY32W
    def __init__(self, processID, threadCount, parent_pID, baseThreadPriority, exeFile):
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
        packedStruct = pack('<IIILIIIlI260s', self.dwSizeA, self.cntUsage, self.th32ProcessID, self.th32DefaultHeapID, self.th32ModuleID, self.cntThreads, self.th32ParentProcessID, self.pcPriClassBase, self.dwFlags, bytes(self.szExeFile, 'ascii'))
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
        packedStruct = pack('<IIILIIIlI520s', self.dwSizeW, self.cntUsage, self.th32ProcessID, self.th32DefaultHeapID, self.th32ModuleID, self.cntThreads, self.th32ParentProcessID, self.pcPriClassBase, self.dwFlags, bytes(self.szExeFile, 'utf-8'))
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
    def __init__(self, th32ProcessID, modBaseAddr, modBaseSize, hModule, szModule, szExePath):
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
        packedStruct = pack('<IIIIIIII256s260s', self.dwSizeA, self.th32ModuleID, self.th32ProcessID, self.GlblcntUsage, self.ProccntUsage, self.modBaseAddr, self.modBaseSize, self.hModule, bytes(self.szModule, 'ascii'), bytes(self.szExePath, 'ascii'))
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
        packedStruct = pack('<IIIIIIII512s520s', self.dwSizeW, self.th32ModuleID, self.th32ProcessID, self.GlblcntUsage, self.ProccntUsage, self.modBaseAddr, self.modBaseSize, self.hModule, bytes(self.szModule, 'utf-8'), bytes(self.szExePath, 'utf-8'))
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