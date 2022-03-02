from unicorn.x86_const import *
from struct import pack, unpack
from ..modules import allDllsDict
from ..helper.emuHelpers import *
import sys
FakeProcess=0xbadd0000

ProcessCreationReverseLookUp = {16777216: 'CREATE_BREAKAWAY_FROM_JOB', 67108864: 'CREATE_DEFAULT_ERROR_MODE', 16: 'CREATE_NEW_CONSOLE', 512: 'CREATE_NEW_PROCESS_GROUP', 134217728: 'CREATE_NO_WINDOW', 262144: 'CREATE_PROTECTED_PROCESS', 33554432: 'CREATE_PRESERVE_CODE_AUTHZ_LEVEL', 4194304: 'CREATE_SECURE_PROCESS', 2048: 'CREATE_SEPARATE_WOW_VDM', 4096: 'CREATE_SHARED_WOW_VDM', 4: 'CREATE_SUSPENDED', 1024: 'CREATE_UNICODE_ENVIRONMENT', 2: 'DEBUG_ONLY_THIS_PROCESS', 1: 'DEBUG_PROCESS', 8: 'DETACHED_PROCESS', 524288: 'EXTENDED_STARTUPINFO_PRESENT', 65536: 'INHERIT_PARENT_AFFINITY'}


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

    uc.reg_write(UC_X86_REG_EAX, retVal)
    logged_calls = ("WinExec", hex(callAddr), hex(retVal), 'UINT', [arg1, hex(arg2)], ['lpCmdLine', 'uCmdShow'], ['lpCmdLine', 'uCmdShow'], False)
    cleanBytes = 8

    return logged_calls, cleanBytes

def hook_LoadLibraryA(uc, eip, esp, export_dict, callAddr):
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


def hook_VirtualAlloc(uc, eip, esp, export_dict, callAddr):
    lpAddress = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+4, 4)
    lpAddress = unpack('<I', lpAddress)[0]
    dwSize = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+8, 4)
    dwSize = unpack('<I', dwSize)[0]
    flAllocationType = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+12, 4)
    flAllocationType = unpack('<I', flAllocationType)[0]
    flProtect = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+16, 4)
    flProtect = unpack('<I', flProtect)[0]

    if lpAddress==0:
        lpAddress=0x90050000  # bramwell added--still not working for 0  # maybe because not on main emu page?
    try:
        uc.mem_map(lpAddress, dwSize)
        retVal = lpAddress
        uc.reg_write(UC_X86_REG_EAX, retVal)
    except:
        print ("VirtualAlloc Function Failed")
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
    print ("hook_CreateFileA")
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
    arg11 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+36, 4)
    arg11 = unpack('<I', arg11)[0]
    arg12 = uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+40, 4)
    arg12 = unpack('<I', arg12)[0]
    
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
        return [arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12 ]

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
    print("hook_URLDownloadToFileA")
    # 'URLDownloadToFileA': (5, ['LPUNKNOWN', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK'], ['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB'], 'HRESULT')
    # function to get values for parameters - count as specified at the end - returned as a list
    pVals = makeArgVals(uc, eip, esp, export_dict, callAddr, 5)
    pTypes=['LPUNKNOWN', 'LPCSTR', 'LPCSTR', 'DWORD', 'LPBINDSTATUSCALLBACK']
    pNames=['pCaller', 'szURL', 'szFileName', 'dwReserved', 'lpfnCB']
    # search= pVals[5]
    # if search in ProcessCreationReverseLookUp:
    #     pVals[5]=ProcessCreationReverseLookUp[search]
    # else:
    #     pVals[5]=hex(pVals[5])

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
    # (2, ['LPCSTR', 'UINT'], ['lpCmdLine', 'uCmdShow'], 'UINT')
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
    skip=[0,1,2,4, 5]   # we need to skip this value (index) later-let's put it in skip
    pTypes,pVals= findStringsParms(uc, pTypes,pVals, skip)
    
    cleanBytes=len(pTypes)*4
    retVal=0x20
    retValStr=hex(retVal)
    uc.reg_write(UC_X86_REG_EAX, retVal)

    logged_calls= ("WSASocketA", hex(callAddr), (retValStr), 'INT', pVals, pTypes, pNames, False)
    return logged_calls, cleanBytes

# SysCalls
def hook_NtTerminateProcess(uc, eip, esp, callAddr):
    handle = uc.mem_read(esp+4, 4)
    handle = unpack('<I', handle)[0]
    ntstatus = uc.mem_read(esp+8, 4)
    ntstatus = unpack('<I', ntstatus)[0]

    cleanBytes = 8
    retVal = 1

    # FINISH THIS LATER
    logged_calls = ("NtTerminateProcess", hex(callAddr), hex(retVal), 'INT', [hex(handle), hex(ntstatus)], ['HANDLE', 'NTSTATUS'], ['ProcessHandle', 'ExitStatus'], False)
    return logged_calls, cleanBytes