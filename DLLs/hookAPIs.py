from unicorn.x86_const import *
from struct import pack, unpack
import sys

dlls = {'ndtll.dll': 0x44100000, 'kernel32.dll': 0x44253138, 'advapi32.dll': 0x44364138, 'comctl32.dll': 0x44403138, 'comdlg32.dll': 0x44486538, 'gdi32.dll': 0x444feb38, 'imm32.dll': 0x4455bf38, 'mscoree.dll': 0x44589f38, 'msvcrt.dll': 0x445d4688, 'netapi.dll': 0x4467e888, 'ole32.dll': 0x4468e288, 'oleaut32.dll': 0x447ec088, 'shell32.dll': 0x4487c488, 'shlwapi.dll': 0x454c6a88, 'urlmon.dll': 0x4551de88, 'user32.dll': 0x45664c88, 'wininet.dll': 0x45741488, 'winmm.dll': 0x45b72488, 'ws2_32.dll': 0x45ba3688, 'wsock32.dll': 0x45bd7888}

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

    print("Using custom API function...")

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
    logged_calls = ("WinExec", hex(callAddr), hex(retVal), 'UINT', [arg1, hex(arg2)], ['lpCmdLine', 'uCmdShow'], ['lpCmdLine', 'uCmdShow'])
    cleanBytes = 8

    return logged_calls, cleanBytes

def hook_LoadLibraryA(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function... LoadLibraryA")
    arg1 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    arg1 = unpack('<I', arg1)[0]
    arg1 = read_string(uc, arg1)

    # Return base address of passed library
    try:
        retVal = dlls[arg1]
    except:
        print("Error: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
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
        retVal = dlls[arg1]
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
        retVal = dlls[arg1]
    except:
        print("Error: The shellcode tried to lode a DLL that isn't handled by this tool: ", arg1)
        retVal = 0

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("LoadLibraryExW", hex(callAddr), hex(retVal), 'HINSTANCE', [arg1, arg2, arg3], ['LPCTSTR', 'HANDLE', 'DWORD'], ['lpLibFileName', 'hFile', 'dwFlags'], False)

    cleanBytes = 12
    return logged_calls, cleanBytes

def hook_VirtualAlloc(uc, eip, esp, export_dict, callAddr):
    print("Using custom function...")
    lpAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    lpAddress = unpack('<I', lpAddress)[0]
    dwSize = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    dwSize = unpack('<I', dwSize)[0]
    flAllocationType = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    flAllocationType = unpack('<I', flAllocationType)[0]
    flProtect = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    flProtect = unpack('<I', flProtect)[0]

    success = True

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

    logged_calls = ("VirtualAlloc", hex(callAddr), hex(retVal), 'LPVOID', [lpAddress, dwSize, flAllocationType, flProtect], ['LPVOID', 'SIZE_T', 'DWORD', 'DWORD'], ['lpAddress', 'dwSize', 'flAllocationType', 'flProtect'], False)
    cleanBytes = 16

    return logged_calls, cleanBytes

def hook_ExitProcess(uc, eip, esp, export_dict, callAddr):
    # print("Using custom function...")
    uExitCode = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    uExitCode = unpack('<I', uExitCode)[0]

    cleanBytes = 4
    logged_calls = ("ExitProcess", hex(callAddr), None, None, [uExitCode], ['UINT'],  ['uExitCode'], False)
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