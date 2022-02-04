from unicorn.x86_const import *
from struct import pack, unpack
from modules import allDllsDict
import sys

rsLookUp={'S_OK': 0x00000000, 'E_ABORT': 0x80004004, 'E_ACCESSDENIED':  0x80070005, 'E_FAIL': 0x80004005, 'E_HANDLE': 0x80070006, 'E_INVALIDARG': 0x80070057, 'E_NOINTERFACE': 0x80004002, 'E_NOTIMPL': 0x80004001, 'E_OUTOFMEMORY': 0x8007000E, 'E_POINTER': 0x80004003, 'E_UNEXPECTED': 0x8000FFFF}

rsReverseLookUp={0x00000000:'S_OK', 0x80004001:'E_NOTIMPL', 0x80004002:'E_NOINTERFACE', 0x80004003:'E_POINTER', 0x80004004:'E_ABORT', 0x80004005:'E_FAIL', 0x8000FFFF:'E_UNEXPECTED', 0x80070005:'E_ACCESSDENIED', 0x80070006:'E_HANDLE', 0x8007000E:'E_OUTOFMEMORY', 0x80070057:'E_INVALIDARG'}
MemLookUp = {'MEM_COMMIT | MEM_RESERVE':'0x3000', 'MEM_COMMIT': '0x1000', 'MEM_FREE': '0x10000', 'MEM_RESERVE': '0x2000', 'MEM_IMAGE': '0x1000000', 'MEM_MAPPED': '0x40000', 'MEM_PRIVATE': '0x20000', 'PAGE_EXECUTE': '0x10', 'PAGE_EXECUTE_READ': '0x20', 'PAGE_EXECUTE_READWRITE': '0x40', 'PAGE_EXECUTE_WRITECOPY': '0x80', 'PAGE_NOACCESS': '0x01', 'PAGE_READONLY': '0x02', 'PAGE_READWRITE': '0x04', 'PAGE_TARGETS_INVALID': '0x40000000', 'PAGE_TARGETS_NO_UPDATE': '0x40000000'}
MemReverseLookUp = {0x3000:'MEM_COMMIT | MEM_RESERVE', 4096: 'MEM_COMMIT', 65536: 'MEM_FREE', 8192: 'MEM_RESERVE', 16777216: 'MEM_IMAGE', 262144: 'MEM_MAPPED', 131072: 'MEM_PRIVATE', 16: 'PAGE_EXECUTE', 32: 'PAGE_EXECUTE_READ', 64: 'PAGE_EXECUTE_READWRITE', 128: 'PAGE_EXECUTE_WRITECOPY', 1: 'PAGE_NOACCESS', 2: 'PAGE_READONLY', 4: 'PAGE_READWRITE', 1073741824: 'PAGE_TARGETS_NO_UPDATE'}


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

# Make sure WinExec returns 32, then add it to created process log
def hook_WinExec(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)
    arg2 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    arg2 = unpack('<I', arg2)[0]
    retVal = 32

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("WinExec", hex(callAddr), hex(retVal), 'UINT', [arg1, hex(arg2)], ['lpCmdLine', 'uCmdShow'], ['lpCmdLine', 'uCmdShow'], False)
    cleanBytes = 8

    return logged_calls, cleanBytes

def hook_LoadLibraryA(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function... LoadLibraryA")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)

    # Return base address of passed library
    try:
        retVal = allDllsDict[arg1]
    except:
        try:
            arg1L=arg1.lower()
            retVal=allDllsDict[arg1L]
        except:
            print("\tError: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
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
        print("Error: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
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
        print("Error: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
        retVal = 0

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("LoadLibraryExW", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1, arg2, arg3], ['LPCTSTR', 'HANDLE', 'DWORD'], ['lpLibFileName', 'hFile', 'dwFlags'], False)

    cleanBytes = 12
    return logged_calls, cleanBytes

def hook_VirtualAlloc(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    lpAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    lpAddress = unpack('<I', lpAddress)[0]
    dwSize = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    dwSize = unpack('<I', dwSize)[0]
    flAllocationType = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    flAllocationType = unpack('<I', flAllocationType)[0]
    flProtect = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    flProtect = unpack('<I', flProtect)[0]

    success = True

    if lpAddress==0:
        lpAddress=0x90050000  # bramwell added--still not working for 0  # maybe because not on main emu page?
    try:
        uc.mem_map(lpAddress, dwSize)
        # if flProtect == 0x2:
        #     uc.mem_map(lpAddress, dwSize, UC_PROT_READ)
        # elif flProtect == 0x4:
        # 	uc.mem_map(lpAddress, dwSize, UC_PROT_READ|UC_PROT_WRITE)
        # elif flProtect == 0x10:
        #     uc.mem_map(lpAddress, dwSize, UC_PROT_EXEC)
        # elif flProtect == 0x20:
        #     uc.mem_map(lpAddress, dwSize, UC_PROT_READ|UC_PROT_EXEC)
        # elif flProtect == 0x40:
        #     uc.mem_map(0x80000000, 0x2000)
        #     print("hi")
        # else:
        # 	success = False
    except:
            success = False

    if success == True:
        retVal = lpAddress
        uc.reg_write(UC_X86_REG_EAX, retVal)
    else:
        retVal = 0
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
    uExitCode = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    uExitCode = unpack('<I', uExitCode)[0]

    cleanBytes = 4
    logged_calls = ("ExitProcess", hex(callAddr), 'None', '', [uExitCode], ['UINT'],  ['uExitCode'], False)
    return logged_calls, cleanBytes

def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret