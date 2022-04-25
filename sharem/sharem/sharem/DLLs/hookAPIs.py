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
HeapsDict = {} # Dictionary of All Heaps 

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


# Make sure WinExec returns 32, then add it to created process log
def hook_WinExec(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)
    arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    arg2 = unpack('<I', arg2)[0]
    retVal = 32

    try:
        bruh = giveRegs(uc)
    except Exception as e:
        print(e)
        print("WOWWWWWWW")

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("WinExec", hex(callAddr), hex(retVal), 'UINT', [arg1, hex(arg2)], ['lpCmdLine', 'uCmdShow'], ['lpCmdLine', 'uCmdShow'], False)
    cleanBytes = 8

    print("Bruh2")

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

def hook_LoadLibraryExW(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)
    arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    arg3 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)

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
    print("Doing manual function")
    arg1 = uc.mem_read(esp+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)

    arg2 = uc.mem_read(esp+8, 4)
    arg2 = hex(unpack('<I', arg2)[0])

    arg3 = uc.mem_read(esp+12, 4)
    arg3 = unpack('<I', arg3)[0]
    arg3 = uc.mem_read(arg3+4, 4)
    arg3 = unpack('<I', arg3)[0]
    arg3 = read_unicode(uc, arg3)

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
    print("Check: ", check)

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

    search= pVals[0]
    if search in flOptionsReverseLookUp:
        pVals[0]=flOptionsReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])

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

    search = pVals[1]
    if search in dwFlagsReverseLookUp:
        pVals[1]=dwFlagsReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

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

    search = pVals[1]
    if search in dwFlagsReverseLookUp:
        pVals[1]=dwFlagsReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

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

    search = pVals[1]
    if search in dwFlagsReverseLookUp:
        pVals[1]=dwFlagsReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

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

    search = pVals[1]
    if search in dwFlagsReverseLookUp:
        pVals[1]=dwFlagsReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

    #create strings for everything except ones in our skip
    skip=[1]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=allocation.address
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HeapReAlloc", hex(callAddr), (retValStr), 'LPVOID', pVals, pTypes, pNames, False)
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
        except:
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
    
    search= pVals[1]
    if search in dwDesiredAccessReverseLookUp:
        pVals[1]=dwDesiredAccessReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    search= pVals[2]
    if search in dwShareModeReverseLookUp:
        pVals[2]=dwShareModeReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    search= pVals[4]
    if search in dwCreationDistributionReverseLookUp:
        pVals[4]=dwCreationDistributionReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    search= pVals[5]
    if search in dwFlagsAndAttributesReverseLookUp:
        pVals[5]=dwFlagsAndAttributesReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])

    # create strings for everything except ones in our skip
    skip=[1,2,4,5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=FakeProcess
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateFileW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

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

def hook_CreateProcessA(uc, eip, esp, export_dict, callAddr):
    # print ("hook_CreateProcessA2")
    """'CreateProcess': (10, ['LPCTSTR', 'LPTSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCTSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION'], ['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation'], 'BOOL'),"""

    # function to get values for parameters - count as specified at the end - returned as a list
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 10)
    pTypes=['LPCTSTR', 'LPTSTR', 'LPSECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES', 'BOOL', 'DWORD', 'LPVOID', 'LPCTSTR', 'LPSTARTUPINFO', 'LPPROCESS_INFORMATION']
    pNames=['lpApplicationName', 'lpCommandLine', 'lpProcessAttributes', 'lpThreadAttributes', 'bInheritHandles', 'dwCreationFlags', 'lpEnvironment', 'lpCurrentDirectory', 'lpStartupInfo', 'lpProcessInformation']

    #searching a dictionary for string to replace hex with
    search= pVals[5]
    if search in ProcessCreationReverseLookUp:
        pVals[5]=ProcessCreationReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])

    #create strings for everything except ones in our skip
    skip=[5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=40
    retVal=32
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("ProcessCreateA", hex(callAddr), hex(retVal), 'INT', pVals, pTypes, pNames, False)
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

    logged_calls= ("URLDownloadToFileA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_WinExec(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['LPCSTR', 'UINT']
    pNames=['lpCmdLine', 'uCmdShow']
    cmdShowReverseLookUp = {0: 'SW_HIDE', 1: 'SW_NORMAL', 2: 'SW_SHOWMINIMIZED', 3: 'SW_MAXIMIZE', 4: 'SW_SHOWNOACTIVATE', 5: 'SW_SHOW', 6: 'SW_MINIMIZE', 7: 'SW_SHOWMINNOACTIVE', 8: 'SW_SHOWNA', 9: 'SW_RESTORE', 16: 'SW_SHOWDEFAULT', 17: 'SW_FORCEMINIMIZE'}

    search= pVals[1]
    if search in cmdShowReverseLookUp:
        pVals[1]=cmdShowReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

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
    search= pVals[5]
    if search in cmdShowReverseLookUp:
        pVals[5]=cmdShowReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])

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
    search= pVals[5]
    if search in cmdShowReverseLookUp:
        pVals[5]=cmdShowReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])

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

    search= pVals[2]
    if search in MemReverseLookUp:
        pVals[2]=MemReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])

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

    search= pVals[3]
    if search in MemReverseLookUp:
        pVals[3]=MemReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])

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
    search= pVals[2]

    if search in memReleaseReverseLookUp:
        pVals[2]=memReleaseReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])

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

    search= pVals[0]
    if search in aFReverseLookUp:
        pVals[0]=aFReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])
    search= pVals[1]
    if search in sockTypeReverseLookUp:
        pVals[1]=sockTypeReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    search= pVals[2]
    if search in sockProtocolReverseLookUp:
        pVals[2]=sockProtocolReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    search= pVals[5]
    if search in dwFlagsReverseLookUp:
        pVals[5]=dwFlagsReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[5]

    if search in groupReverseLookUp:
        pVals[4]=groupReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
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
    

    search= pVals[0]
    if search in aFReverseLookUp:
        pVals[0]=aFReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])
    search= pVals[1]
    if search in sockTypeReverseLookUp:
        pVals[1]=sockTypeReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    search= pVals[2]
    if search in sockProtocolReverseLookUp:
        pVals[2]=sockProtocolReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    search= pVals[5]
    if search in groupReverseLookUp:
        pVals[4]=groupReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    if search in dwFlagsReverseLookUp:
        pVals[5]=dwFlagsReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[4]
    
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

    search= pVals[0]
    if search in aFReverseLookUp:
        pVals[0]=aFReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])
    search= pVals[1]
    if search in sockTypeReverseLookUp:
        pVals[1]=sockTypeReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    search= pVals[2]
    if search in sockProtocolReverseLookUp:
        pVals[2]=sockProtocolReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    
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

    search= pVals[0]
    if search in flagsReverseLookUp:
        pVals[0]=flagsReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])
    search= pVals[1]
    if search in lpInfoReverseLookUp:
        pVals[1]=lpInfoReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    search= pVals[2]
    
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

    search= pVals[0]
    if search in flagsReverseLookUp:
        pVals[0]=flagsReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])
    search= pVals[1]
    if search in lpInfoReverseLookUp:
        pVals[1]=lpInfoReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    search= pVals[2]
    
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


def hook_CreateThread(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 6)
    pTypes=['LPSECURITY_ATTRIBUTES', 'SIZE_T', 'LPTHREAD_START_ROUTINE', 'LPVOID', 'DWORD', 'LPDWORD']
    pNames= ['lpThreadAttributes', 'dwStackSize', 'lpStartAddress', 'lpParameter', 'dwCreationFlags', 'lpThreadId']
    dwCreateFlagsReverseLookUp = {4: 'CREATE_SUSPENDED', 65536: 'STACK_SIZE_PARAM_IS_A_RESERVATION'}

    search= pVals[4]
    if search in dwCreateFlagsReverseLookUp:
        pVals[4]=dwCreateFlagsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
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

    search= pVals[3]
    if search in dwDesiredAccessReverseLookUp:
        pVals[3]=dwDesiredAccessReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
    search= pVals[4]
    if search in dwServiceTypeReverseLookUp:
        pVals[4]=dwServiceTypeReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    search= pVals[5]
    if search in dwStartTypeReverseLookUp:
        pVals[5]=dwStartTypeReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[6]
    if search in dwErrorControlReverseLookUp:
        pVals[6]=dwErrorControlReverseLookUp[search]
    else:
        pVals[6]=hex(pVals[6])

    #create strings for everything except ones in our skip
    skip=[3,4,5,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=FakeProcess # Return HANDLE to service
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

    search= pVals[3]
    if search in dwDesiredAccessReverseLookUp:
        pVals[3]=dwDesiredAccessReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
    search= pVals[4]
    if search in dwServiceTypeReverseLookUp:
        pVals[4]=dwServiceTypeReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    search= pVals[5]
    if search in dwStartTypeReverseLookUp:
        pVals[5]=dwStartTypeReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[6]
    if search in dwErrorControlReverseLookUp:
        pVals[6]=dwErrorControlReverseLookUp[search]
    else:
        pVals[6]=hex(pVals[6])

    #create strings for everything except ones in our skip
    skip=[3,4,5,6]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=FakeProcess # Return HANDLE to service
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

    search= pVals[1]
    if search in dwAccessTypeReverseLookUp:
        pVals[1]=dwAccessTypeReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

    search= pVals[4]
    if search in dwFlagsReverseLookUp:
        pVals[4]=dwFlagsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    
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

    search= pVals[1]
    if search in dwAccessTypeReverseLookUp:
        pVals[1]=dwAccessTypeReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

    search= pVals[4]
    if search in dwFlagsReverseLookUp:
        pVals[4]=dwFlagsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    
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
    
    search= pVals[2]
    if search in nServerPortReverseLookUp:
        pVals[2]=nServerPortReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    search= pVals[5]
    if search in dwServiceReverseLookUp:
        pVals[5]=dwServiceReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[6]
    if search in dwFlagsReverseLookUp:
        pVals[6]=dwFlagsReverseLookUp[search]
    else:
        pVals[6]=hex(pVals[6])
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

    search= pVals[2]
    if search in nServerPortReverseLookUp:
        pVals[2]=nServerPortReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    search= pVals[5]
    if search in dwServiceReverseLookUp:
        pVals[5]=dwServiceReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[6]
    if search in dwFlagsReverseLookUp:
        pVals[6]=dwFlagsReverseLookUp[search]
    else:
        pVals[6]=hex(pVals[6])
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

    search= pVals[5]
    if search in dwCreationFlagsReverseLookUp:
        pVals[5]=dwCreationFlagsReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    
        
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

    search= pVals[4]
    if search in dwOptionsReverseLookUp:
        pVals[4]=dwOptionsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    search= pVals[5]
    if search in samDesiredReverseLookUp:
        pVals[5]=samDesiredReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[8]
    if search in lpdwDispostitionReverseLookUp:
        pVals[8]=lpdwDispostitionReverseLookUp[search]
    else:
        pVals[8]=hex(pVals[8])

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

    search= pVals[4]
    if search in dwOptionsReverseLookUp:
        pVals[4]=dwOptionsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    search= pVals[5]
    if search in samDesiredReverseLookUp:
        pVals[5]=samDesiredReverseLookUp[search]
    else:
        pVals[5]=hex(pVals[5])
    search= pVals[8]
    if search in lpdwDispostitionReverseLookUp:
        pVals[8]=lpdwDispostitionReverseLookUp[search]
    else:
        pVals[8]=hex(pVals[8])

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

    search= pVals[2]
    if search in samDesiredReverseLookUp:
        pVals[2]=samDesiredReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    
        
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

    search= pVals[2]
    if search in samDesiredReverseLookUp:
        pVals[2]=samDesiredReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    
        
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

    search= pVals[3]
    if search in dwFlagsReverseLookUp:
        pVals[3]=dwFlagsReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
    
        
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

    search= pVals[3]
    if search in dwFlagsReverseLookUp:
        pVals[3]=dwFlagsReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
    
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

    search= pVals[3]
    if search in dwFlagsReverseLookUp:
        pVals[3]=dwFlagsReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
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

    search= pVals[0]
    if search in idHookReverseLookUp:
        pVals[0]=idHookReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])

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

    search= pVals[0]
    if search in idHookReverseLookUp:
        pVals[0]=idHookReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00717171
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("SetWindowsHookExW", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_CreateToolhelp32Snapshot(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['DWORD', 'DWORD']
    pNames= ['dwFlags', 'th32ProcessID']

    dwFlagsReverseLookUp = {2147483648: 'TH32CS_INHERIT', 15: 'TH32CS_SNAPALL', 1: 'TH32CS_SNAPHEAPLIST', 8: 'TH32CS_SNAPMODULE', 16: 'TH32CS_SNAPMODULE32', 2: 'TH32CS_SNAPPROCESS', 4: 'TH32CS_SNAPTHREAD'}

    search= pVals[0]
    if search in dwFlagsReverseLookUp:
        pVals[0]=dwFlagsReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])

    #create strings for everything except ones in our skip
    skip=[0]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x00666666
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CreateToolhelp32Snapshot", hex(callAddr), (retValStr), 'HANDLE', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_shutdown(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 2)
    pTypes=['SOCKET', 'int']
    pNames= ['s', 'how']

    howReverseLookUp = {0: 'SD_RECEIVE', 1: 'SD_SEND', 2: 'SD_BOTH'}

    search= pVals[1]
    if search in howReverseLookUp:
        pVals[1]=howReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])

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

    search= pVals[3]
    if search in dwReplaceFlagsReverseLookUp:
        pVals[3]=dwReplaceFlagsReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
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

    search= pVals[3]
    if search in dwReplaceFlagsReverseLookUp:
        pVals[3]=dwReplaceFlagsReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
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

    search= pVals[4]
    if search in dwNotifyFilterReverseLookUp:
        pVals[4]=dwNotifyFilterReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])

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

    search= pVals[4]
    if search in dwFlagsReverseLookUp:
        pVals[4]=dwFlagsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
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

    search= pVals[4]
    if search in dwFlagsReverseLookUp:
        pVals[4]=dwFlagsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
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

    search= pVals[0]
    if search in uFlagsReverseLookUp:
        pVals[0]=uFlagsReverseLookUp[search]
    else:
        pVals[0]=hex(pVals[0])
    search= pVals[1]
    if search in dwReasonReverseLookUp:
        pVals[1]=dwReasonReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[1]
    if search in dwFileAttributesReverseLookUp:
        pVals[1]=dwFileAttributesReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[1]
    if search in dwFileAttributesReverseLookUp:
        pVals[1]=dwFileAttributesReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[1]
    if search in dwControlReverseLookUp:
        pVals[1]=dwControlReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[2]
    if search in flProtectReverseLookUp:
        pVals[2]=flProtectReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    
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

    search= pVals[2]
    if search in flProtectReverseLookUp:
        pVals[2]=flProtectReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    
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

    search= pVals[3]
    if search in dwProvTypeReverseLookUp:
        pVals[3]=dwProvTypeReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])

    search= pVals[4]
    if search in dwFlagsReverseLookUp:
        pVals[4]=dwFlagsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
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

    search= pVals[3]
    if search in dwProvTypeReverseLookUp:
        pVals[3]=dwProvTypeReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])

    search= pVals[4]
    if search in dwFlagsReverseLookUp:
        pVals[4]=dwFlagsReverseLookUp[search]
    else:
        pVals[4]=hex(pVals[4])
    #create strings for everything except ones in our skip
    skip=[3,4]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("CryptAcquireContextW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

def hook_Toolhelp32ReadProcessMemory(uc, eip, esp, export_dict, callAddr):
    global availMem

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

    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("Toolhelp32ReadProcessMemory", hex(callAddr), (retValStr), 'BOOL', [(th32ProcessID), hex(lpBaseAddress), hex(lpBuffer), hex(cbRead), hex(lpNumberOfBytesRead)], ['DWORD', 'LPCVOID', 'LPVOID', 'SIZE_T', 'SIZE_T'], ['th32ProcessID', 'lpBaseAddress', 'lpBuffer', 'cbRead', 'lpNumberOfBytesRead'], False)
    cleanBytes = 20

    return logged_calls, cleanBytes

def hook_OpenSCManagerA(uc, eip, esp, export_dict, callAddr):
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 3)
    pTypes=['LPCSTR', 'LPCSTR', 'DWORD']
    pNames= ['lpMachineName', 'lpDatabaseName', 'dwDesiredAccess']

    dwDesiredAccessReverseLookUp = {983103: 'SC_MANAGER_ALL_ACCESS', 2: 'SC_MANAGER_CREATE_SERVICE', 1: 'SC_MANAGER_CONNECT', 4: 'SC_MANAGER_ENUMERATE_SERVICE', 8: 'SC_MANAGER_LOCK', 32: 'SC_MANAGER_MODIFY_BOOT_CONFIG', 16: 'SC_MANAGER_QUERY_LOCK_STATUS'}

    search= pVals[2]
    if search in dwDesiredAccessReverseLookUp:
        pVals[2]=dwDesiredAccessReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    
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

    search= pVals[2]
    if search in dwDesiredAccessReverseLookUp:
        pVals[2]=dwDesiredAccessReverseLookUp[search]
    else:
        pVals[2]=hex(pVals[2])
    
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

    search= pVals[3]
    if search in dwFlagsReverseLookUp:
        pVals[3]=dwFlagsReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
    
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

    search= pVals[3]
    if search in dwFlagsReverseLookUp:
        pVals[3]=dwFlagsReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])
    
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

    search= pVals[1]
    if search in dwOptionReverseLookUp:
        pVals[1]=dwOptionReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[1]
    if search in dwOptionReverseLookUp:
        pVals[1]=dwOptionReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[1]
    if search in dwOptionReverseLookUp:
        pVals[1]=dwOptionReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[1]
    if search in dwOptionReverseLookUp:
        pVals[1]=dwOptionReverseLookUp[search]
    else:
        pVals[1]=hex(pVals[1])
    
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

    search= pVals[6]
    if search in dwFlagsReverseLookUp:
        pVals[6]=dwFlagsReverseLookUp[search]
    else:
        pVals[6]=hex(pVals[6])

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

    search= pVals[6]
    if search in dwFlagsReverseLookUp:
        pVals[6]=dwFlagsReverseLookUp[search]
    else:
        pVals[6]=hex(pVals[6])

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

    search= pVals[3]
    if search in dwModifiersReverseLookUp:
        pVals[3]=dwModifiersReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])

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

    search= pVals[3]
    if search in dwModifiersReverseLookUp:
        pVals[3]=dwModifiersReverseLookUp[search]
    else:
        pVals[3]=hex(pVals[3])

    #create strings for everything except ones in our skip
    skip=[3]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)

    cleanBytes=len(pTypes)*4
    retVal=0x1
    retValStr='TRUE'
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("HttpAddRequestHeadersW", hex(callAddr), (retValStr), 'BOOL', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes