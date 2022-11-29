from struct import pack, unpack
import ctypes
import os
import pefile
from pathlib import Path
import json
from .helper.moduleHelpers import *
import platform
from sharem.sharem.helper.variable import Variables

platformType = platform.uname()[0]

class winReleases():        
    def __init__(self):
        self.win10ReverseLookupHex={"4A64": "21H2", "4A65": "22H2", "4A63": "21H1", "4A62": "20H2", "4A61": "2004", "47BB": "1909", "47BA": "1903", "4563": "1809", "42EE": "1803", "3FAB": "1709", "3AD7": "1703", "3839": "1607", "295A": "1511", "2800": "1507"}
        

        self.win7LookupHex={"SP0":"1DB0", "SP1":"1DB1"}
        self.win11LookupHex={"21H2":"55F0", "22H2":"585D"}
        self.win10LookupHex={"21H2":"4A64", "22H2":"4A65", "21H1":"4A63", "20H2":"4A62", "2004":"4A61", "1909":"47BB", "1903":"47BA", "1809":"4563", "1803":"42EE", "1709":"3FAB", "1703":"3AD7", "1607":"3839", "1511":"295A", "1507":"2800"}
        self.windowsOSMajor={"Windows 11":10,"Windows 10":10,"Windows Server 2022":10,"Windows Server 2019":10,"Windows Server 2016":10,"Windows 8.1":6,"Windows Server 2012 R2":6,"Windows 8":6,"Windows Server 2012":6,"Windows 7":6,"Windows Server 2008 R2":6,"Windows Server 2008":6,"Windows Vista":6,"Windows Server 2003 R2":5,"Windows Server 2003":5,"Windows XP 64-Bit Edition":5,"Windows XP":5,"Windows 2000":5}
        self.windowsOSMinor={"Windows 11":0, "Windows 10":0, "Windows Server 2022":0, "Windows Server 2019":0, "Windows Server 2016":0, "Windows 8.1":3, "Windows Server 2012 R2":3, "Windows 8":2, "Windows Server 2012":2, "Windows 7":1, "Windows Server 2008 R2":1, "Windows Server 2008":0, "Windows Vista":0, "Windows Server 2003 R2":2, "Windows Server 2003":2, "Windows XP 64-Bit Edition":2, "Windows XP":1, "Windows 2000":0}

if platformType == "Windows":
    # https://code.activestate.com/recipes/578035-disable-file-system-redirector/
    class disable_file_system_redirection:
        _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
        def __enter__(self):
            self.old_value = ctypes.c_long()
            self.success = self._disable(ctypes.byref(self.old_value))
        def __exit__(self, type, value, traceback):
            if self.success:
                self._revert(self.old_value)

# PROCESS_BASE = 0x14000000
# PEB_ADDR = 0x11017000
# TIB_ADDR = 0x00000000
# CONST_ADDR = 0x20000000
# FAST_ADDR = 0x5000
# LDR_ADDR = 0x11020000
# LDR_PROG_ADDR = 0x11021000

allDlls=["ntdll", "kernel32", "KernelBase", "advapi32",  "comctl32",  "comdlg32",  "gdi32", "gdiplus", "imm32",  "mscoree",  "msvcrt",  "netapi32",  "ole32",  "oleaut32",  "shell32",  "shlwapi",  "urlmon",  "user32",  "wininet",  "winmm",  "ws2_32",  "wsock32", "advpack", "bcrypt", "crypt32", "dnsapi", "mpr", "ncrypt", "netutils", "samcli", "secur32", "wkscli", "wtsapi32"]
allDllsDict = {}

class Win32Addresses:
    def __init__(self):
        self.process_base = 0x14000000
        self.peb_addr = 0x11017000
        self.tib_addr = 0x00000000
        self.const_addr = 0x20000000
        self.fast_addr = 0x5000
        self.ldr_addr = 0x11020000
        self.ldr_prog_addr = 0x11021000

class Win64Addresses:
    def __init__(self):
        self.process_base = 0x14000000
        self.peb_addr = 0x1101c000
        self.tib_addr = 0x00000000
        self.const_addr = 0x20000000
        self.fast_addr = 0x5000
        self.ldr_addr = 0x11028000
        self.ldr_prog_addr = 0x11031000

# This struct can have up to 0x58 total bytes depending on Windows version
class PEB_LDR_DATA32():
    def __init__(self, addr, length, initialized, sshandle):
        self.Addr = addr
        self.Length = length
        self.Initialized = initialized
        self.Sshandle = sshandle
        self.ILO_entry = addr + 0xc
        self.IMO_entry = addr + 0x14
        self.IIO_entry = addr + 0x1c
    def allocate(self, mu, ilo_flink, ilo_blink, imo_flink, imo_blink, iio_flink, iio_blink):
        mu.mem_write(self.Addr, pack("<I", self.Length))
        mu.mem_write(self.Addr+0x4, pack("<I", self.Initialized))
        mu.mem_write(self.Addr+0x8, pack("<I", self.Sshandle))
        mu.mem_write(self.Addr+0xc, pack("<I", ilo_flink) + pack("<I", ilo_blink))
        mu.mem_write(self.Addr+0x14, pack("<I", imo_flink) + pack("<I", imo_blink))
        mu.mem_write(self.Addr+0x1c, pack("<I", iio_flink) + pack("<I", iio_blink))

class LDR_Module32():
    def __init__(self, mu, wa, addr, dll_base, entry_point, reserved, full_dll_name, base_dll_name):
        self.Addr = addr
        self.ILO_entry = addr
        self.IMO_entry = addr + 0x8
        self.IIO_entry = addr + 0x10
        self.DLL_Base = dll_base
        self.Entry_Point = entry_point
        self.Reserved = reserved

        full_dll_name = full_dll_name.encode("utf-16-le") + b"\x00"
        mu.mem_write(wa.const_addr, full_dll_name)
        self.Full_Dll_Name = wa.const_addr
        wa.const_addr += len(full_dll_name)

        base_dll_name = base_dll_name.encode("utf-16-le") + b"\x00"
        mu.mem_write(wa.const_addr, base_dll_name)
        self.Base_Dll_Name = wa.const_addr
        wa.const_addr += len(base_dll_name)

    def allocate(self, mu, ilo_flink, ilo_blink, imo_flink, imo_blink, iio_flink, iio_blink):
        mu.mem_write(self.Addr, pack("<I", ilo_flink) + pack("<I", ilo_blink))
        mu.mem_write(self.Addr+0x8, pack("<I", imo_flink) + pack("<I", imo_blink))
        mu.mem_write(self.Addr+0x10, pack("<I", iio_flink) + pack("<I", iio_blink))
        mu.mem_write(self.Addr+0x18, pack("<I", self.DLL_Base))
        mu.mem_write(self.Addr+0x1c, pack("<I", self.Entry_Point))

        mu.mem_write(self.Addr+0x24, pack("<I", 0x007e007c))
        mu.mem_write(self.Addr+0x28, pack("<I", self.Full_Dll_Name))
        mu.mem_write(self.Addr+0x2c, pack("<I", 0x001c001a))
        mu.mem_write(self.Addr+0x30, pack("<I", self.Base_Dll_Name))

class PEB_LDR_DATA64():
    def __init__(self, addr, length, initialized, sshandle):
        self.Addr = addr
        self.Length = length
        self.Initialized = initialized
        self.Sshandle = sshandle
        self.ILO_entry = addr + 0x10
        self.IMO_entry = addr + 0x20
        self.IIO_entry = addr + 0x30
    def allocate(self, mu, ilo_flink, ilo_blink, imo_flink, imo_blink, iio_flink, iio_blink):
        mu.mem_write(self.Addr, pack("<Q", self.Length))
        mu.mem_write(self.Addr+0x4, pack("<Q", self.Initialized))
        mu.mem_write(self.Addr+0x8, pack("<Q", self.Sshandle))
        mu.mem_write(self.Addr+0x10, pack("<Q", ilo_flink) + pack("<Q", ilo_blink))
        mu.mem_write(self.Addr+0x20, pack("<Q", imo_flink) + pack("<Q", imo_blink))
        mu.mem_write(self.Addr+0x30, pack("<Q", iio_flink) + pack("<Q", iio_blink))

class LDR_Module64():
    def __init__(self, mu, wa, addr, dll_base, entry_point, reserved, full_dll_name, base_dll_name):
        self.Addr = addr
        self.ILO_entry = addr
        self.IMO_entry = addr + 0x10
        self.IIO_entry = addr + 0x20
        self.DLL_Base = dll_base
        self.Entry_Point = entry_point
        self.Reserved = reserved

        full_dll_name = full_dll_name.encode("utf-16-le") + b"\x00"
        mu.mem_write(wa.const_addr, full_dll_name)
        self.Full_Dll_Name = wa.const_addr
        wa.const_addr += len(full_dll_name)

        base_dll_name = base_dll_name.encode("utf-16-le") + b"\x00"
        mu.mem_write(wa.const_addr, base_dll_name)
        self.Base_Dll_Name = wa.const_addr
        wa.const_addr += len(base_dll_name)
    def allocate(self, mu, ilo_flink, ilo_blink, imo_flink, imo_blink, iio_flink, iio_blink):
        mu.mem_write(self.Addr, pack("<Q", ilo_flink) + pack("<Q", ilo_blink))
        mu.mem_write(self.Addr+0x10, pack("<Q", imo_flink) + pack("<Q", imo_blink))
        mu.mem_write(self.Addr+0x20, pack("<Q", iio_flink) + pack("<Q", iio_blink))
        mu.mem_write(self.Addr+0x30, pack("<Q", self.DLL_Base))
        mu.mem_write(self.Addr+0x38, pack("<Q", self.Entry_Point))
        mu.mem_write(self.Addr+0x48, pack("<Q", 0x0000007e0000007c))
        mu.mem_write(self.Addr+0x50, pack("<Q", self.Full_Dll_Name))
        mu.mem_write(self.Addr+0x58, pack("<Q", 0x0000001c0000001a))
        mu.mem_write(self.Addr+0x58, pack("<Q", self.Base_Dll_Name))

def giveOsMajorMinorVersions():
    osMajor=0
    osMinor=0
    osBuild=0
    try:
        osMajor=builds.windowsOSMajor[em.winVersion]
        osMinor=builds.windowsOSMinor[em.winVersion]
    except:
        pass

    # Do not have data on older OS builds - not looking to support those - this only matters for syscall emulation using ShellWasp technique.
    
    if em.winVersion =="Windows 11":  
        osBuild=builds.win11LookupHex[em.winSP]
        print ("windows 11", osMajor, osMinor, osBuild)
    elif em.winVersion=="Windows 10":
        osBuild=builds.win10LookupHex[em.winSP]
        # print ("windows 10", osMajor, osMinor, osBuild)        
    elif em.winVersion=="Windows 7":
        osBuild=builds.win7LookupHex[em.winSP]
        # print ("windows 7", osMajor, osMinor, osBuild)
    return osMajor, osMinor, osBuild        
        
    
def allocateWinStructs32(mu, mods):
    wa = Win32Addresses()

    # Put location of PEB at FS:30 and FS:18
    mu.mem_write(wa.tib_addr+0x30, pack("<Q", wa.peb_addr))
    mu.mem_write(wa.tib_addr+0x18, pack("<Q", wa.peb_addr))
    # Fastcall at FS:c0
    mu.mem_write(wa.tib_addr+0xC0, pack("<Q", wa.fast_addr))
    mu.mem_write((wa.peb_addr-10), b'\x4a\x41\x43\x4f\x42\x41\x41\x41\x41\x42')
    mu.mem_write(wa.fast_addr, b'\xC3')


    # Create PEB data structure. Put pointer to ldr at offset 0xC
    mu.mem_write(wa.peb_addr + 0xc, pack("<Q", wa.ldr_addr))
    
    # Create PEB_LDR_DATA structure
    peb_ldr = PEB_LDR_DATA32(wa.ldr_addr, 0x24, 0x00000000, 0x00000000)

    # Put location of OSmajorversion (0xa4), OSMinorVersion(0xa8), OSBuild(0xac)
    # print ("special", em.winVersion, em.winSP)
    osMajor, osMinor, osBuild =giveOsMajorMinorVersions()
    mu.mem_write(wa.peb_addr + 0xa4, pack("<Q", int(osMajor)))
    mu.mem_write(wa.peb_addr + 0xa8, pack("<Q", int(osMinor)))
    try:
        mu.mem_write(wa.peb_addr + 0xac, pack("<Q", int(osBuild,16)))
    except:
        mu.mem_write(wa.peb_addr + 0xac, pack("<Q", int(osBuild)))

    dlls_obj = []

    # Create ldr module for the running process
    dlls_obj.append(LDR_Module32(mu, wa, wa.ldr_prog_addr, wa.process_base, wa.process_base, 0x00000000, "C:\\shellcode.exe", "shellcode.exe"))

    ldr_track = 0x11021300
    # Create ldr module for the rest
    for dll in mods:
        mods[dll].ldrAddr = ldr_track
        dlls_obj.append(LDR_Module32(mu, wa, mods[dll].ldrAddr, mods[dll].base, mods[dll].base, 0x00000000, mods[dll].d32, mods[dll].name))
        ldr_track += 0x300

    peb_ldr.allocate(mu, dlls_obj[0].ILO_entry, dlls_obj[-1].ILO_entry, dlls_obj[0].IMO_entry, dlls_obj[-1].IMO_entry, dlls_obj[1].IIO_entry, dlls_obj[-1].IIO_entry)

    # Allocate first 5 LDR records (ntdll, kernel32, kernelbase)
    dlls_obj[0].allocate(mu, dlls_obj[1].ILO_entry, dlls_obj[-1].ILO_entry, dlls_obj[1].IMO_entry, dlls_obj[-1].IMO_entry, 0x0, 0x0)
    dlls_obj[1].allocate(mu, dlls_obj[2].ILO_entry, dlls_obj[0].ILO_entry, dlls_obj[2].IMO_entry, dlls_obj[0].IMO_entry, dlls_obj[3].IIO_entry, dlls_obj[-1].IIO_entry)
    dlls_obj[2].allocate(mu, dlls_obj[3].ILO_entry, dlls_obj[1].ILO_entry, dlls_obj[3].IMO_entry, dlls_obj[1].IMO_entry, dlls_obj[4].IIO_entry, dlls_obj[3].IIO_entry)
    dlls_obj[3].allocate(mu, dlls_obj[4].ILO_entry, dlls_obj[2].ILO_entry, dlls_obj[4].IMO_entry, dlls_obj[2].IMO_entry, dlls_obj[2].IIO_entry, dlls_obj[1].IIO_entry)
    dlls_obj[4].allocate(mu, dlls_obj[5].ILO_entry, dlls_obj[3].ILO_entry, dlls_obj[5].IMO_entry, dlls_obj[3].IMO_entry, dlls_obj[5].IIO_entry, dlls_obj[2].IIO_entry)


    # Allocate the rest of the LDR records
    for i in range(5, len(dlls_obj)):
        currentDLL = dlls_obj[i]
        prevDLL = dlls_obj[i-1]

        if i == len(dlls_obj) - 1:
            currentDLL.allocate(mu, dlls_obj[0].ILO_entry, prevDLL.ILO_entry, dlls_obj[0].IMO_entry, prevDLL.IMO_entry, dlls_obj[1].IIO_entry, prevDLL.IIO_entry)
        else:
            nextDLL = dlls_obj[i+1]
            currentDLL.allocate(mu, nextDLL.ILO_entry, prevDLL.ILO_entry, nextDLL.IMO_entry, prevDLL.IMO_entry, nextDLL.IIO_entry, prevDLL.IIO_entry)

def allocateWinStructs64(mu, mods):
    wa = Win64Addresses()

    # Put location of PEB at GS:60
    mu.mem_write(wa.tib_addr+0x60, pack("<i", wa.peb_addr))

    # Create PEB data structure. Put pointer to ldr at offset 0x18
    mu.mem_write(wa.peb_addr, b'\x00'*0x18 + pack("<Q", wa.ldr_addr))

    # Create PEB_LDR_DATA structure
    peb_ldr = PEB_LDR_DATA64(wa.ldr_addr, 0x24, 0x00000000, 0x00000000)


    # Put location of OSmajorversion (0xa4), OSMinorVersion(0xa8), OSBuild(0xac)
    # print ("special", em.winVersion, em.winSP)
    osMajor, osMinor, osBuild =giveOsMajorMinorVersions()
    mu.mem_write(wa.peb_addr + 0x118, pack("<Q", int(osMajor)))
    mu.mem_write(wa.peb_addr + 0x11c, pack("<Q", int(osMinor)))
    try:
        mu.mem_write(wa.peb_addr + 0x120, pack("<Q", int(osBuild,16)))
    except:
        mu.mem_write(wa.peb_addr + 0x120, pack("<Q", int(osBuild)))



    dlls_obj = []

    dlls_obj.append(LDR_Module64(mu, wa, wa.ldr_prog_addr, wa.process_base, wa.process_base, 0x00000000, "C:\\shellcode.exe", "shellcode.exe"))

    ldr_track = 0x11071300
    # Create ldr module for the rest
    for dll in mods:
        mods[dll].ldrAddr = ldr_track
        dlls_obj.append(LDR_Module64(mu, wa, mods[dll].ldrAddr, mods[dll].base, mods[dll].base, 0x00000000, mods[dll].d64, mods[dll].name))
        ldr_track += 0x300

    peb_ldr.allocate(mu, dlls_obj[0].ILO_entry, dlls_obj[-1].ILO_entry, dlls_obj[0].IMO_entry, dlls_obj[-1].IMO_entry, dlls_obj[1].IIO_entry, dlls_obj[-1].IIO_entry)

    # Allocate first 5 LDR records (ntdll, kernel32, kernelbase)
    dlls_obj[0].allocate(mu, dlls_obj[1].ILO_entry, dlls_obj[-1].ILO_entry, dlls_obj[1].IMO_entry, dlls_obj[-1].IMO_entry, 0x0, 0x0)
    dlls_obj[1].allocate(mu, dlls_obj[2].ILO_entry, dlls_obj[0].ILO_entry, dlls_obj[2].IMO_entry, dlls_obj[0].IMO_entry, dlls_obj[3].IIO_entry, dlls_obj[-1].IIO_entry)
    dlls_obj[2].allocate(mu, dlls_obj[3].ILO_entry, dlls_obj[1].ILO_entry, dlls_obj[3].IMO_entry, dlls_obj[1].IMO_entry, dlls_obj[4].IIO_entry, dlls_obj[3].IIO_entry)
    dlls_obj[3].allocate(mu, dlls_obj[4].ILO_entry, dlls_obj[2].ILO_entry, dlls_obj[4].IMO_entry, dlls_obj[2].IMO_entry, dlls_obj[2].IIO_entry, dlls_obj[1].IIO_entry)
    dlls_obj[4].allocate(mu, dlls_obj[5].ILO_entry, dlls_obj[3].ILO_entry, dlls_obj[5].IMO_entry, dlls_obj[3].IMO_entry, dlls_obj[5].IIO_entry, dlls_obj[2].IIO_entry)

    # Allocate the rest of the LDR records
    for i in range(5, len(dlls_obj)):
        currentDLL = dlls_obj[i]
        prevDLL = dlls_obj[i-1]

        if i == len(dlls_obj) - 1:
            currentDLL.allocate(mu, dlls_obj[0].ILO_entry, prevDLL.ILO_entry, dlls_obj[0].IMO_entry, prevDLL.IMO_entry, dlls_obj[1].IIO_entry, prevDLL.IIO_entry)
        else:
            nextDLL = dlls_obj[i+1]
            currentDLL.allocate(mu, nextDLL.ILO_entry, prevDLL.ILO_entry, nextDLL.IMO_entry, prevDLL.IMO_entry, nextDLL.IIO_entry, prevDLL.IIO_entry)

class WinDLL:
    def __init__(self, dllName, d32, d64):
        self.id=dllName
        self.name = dllName + '.dll'
        self.base = 0x0
        self.d32 = d32
        self.d64 = d64
        self.ldrAddr = 0x11021300

def iter_and_dump_dlls(mu, em, export_dict, source_path, save_path, mods):
    global MOD_LOW

    base = 0x14100000
    runOnce = False

    for dll_name in mods:
        dll_file = dll_name + '.dll'

        allDllsDict[dll_file] = base
        mods[dll_name].base = base
        if platformType == "Windows":
            with disable_file_system_redirection():
                if os.path.exists(source_path+dll_file) == False:
                    continue

        if os.path.exists(save_path+dll_file):
            rawDll = readRaw(save_path + dll_file)

        # Inflate dlls so PE offsets are correct
        elif platformType == "Windows":
            if not runOnce:
                print("Warning: DLLs must be parsed and inflated from a Windows OS.\n\tThis may take several minutes to generate the initial emulation files.\n\tThis initial step must be completed only once from a Windows machine.\n\tThe emulation will not work without these.")
                runOnce = True

            dllPath = source_path + dll_file
            rawDll, padding = padDLL(dllPath, dll_file, save_path)

            with disable_file_system_redirection():
                pe = pefile.PE(source_path+dll_file)
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    export_dict[hex(base + exp.address)] = (exp.name.decode(), dll_file)
                except:
                    export_dict[hex(base + exp.address)] = ("unknown_function", dll_file)
        else:
            continue

        # Dump the dll into emulation memory
        mu.mem_write(base, rawDll)
        base += len(rawDll) + 20

    mod_high_val = base

    return export_dict, mods, mod_high_val


def padDLL(dllPath, dllName, expandedDLLsPath):
    with disable_file_system_redirection():
        pe = pefile.PE(dllPath)

    virtualAddress = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
    i = 0
    padding = 0
    while True:
        try:
            section = pe.sections[i]

            pointerToRaw = section.PointerToRawData
            sectionVA = section.VirtualAddress
            sizeOfRawData = section.SizeOfRawData

            if (virtualAddress >= sectionVA and virtualAddress < (sectionVA + sizeOfRawData)):
                padding = virtualAddress - (virtualAddress - sectionVA + pointerToRaw)
                break
        except:
            break

        i += 1

    # Replace e_lfanew value
    elfanew = pe.DOS_HEADER.e_lfanew
    pe.DOS_HEADER.e_lfanew = elfanew + padding

    tmpPath = expandedDLLsPath + dllName
    pe.write(tmpPath)

    # Add padding to dll, then save it.
    out = readRaw(tmpPath)
    final = insertIntoBytes(out, 0x40, padding, 0x00)
    newBin = open(tmpPath, "wb")
    newBin.write(final)
    newBin.close()

    rawDll = readRaw(tmpPath)

    return rawDll, padding


def saveDLLAddsToFile(foundDLLAddrs, export_dict):
    # Create foundDllAddresses.txt if it doesn't already exist
    if not os.path.exists(foundDLLAddrs):
        Path(foundDLLAddrs).touch()
        with open(foundDLLAddrs, 'a') as out:
            json.dump(export_dict, out)

    # Make sure no duplicates get in if there's already content in the file
    else:
        with open(foundDLLAddrs, 'r') as f:
            currentData = json.load(f)

        with open(foundDLLAddrs, 'a') as out:
            for apiAddr, apiInfo in export_dict.items():
                if apiAddr not in currentData.keys():
                    newRecord = {}
                    newRecord[apiAddr] = apiInfo
                    json.dump(newRecord, out)

def initMods(uc, em, export_dict, source_path, save_path):
    mods_list = ["ntdll", "kernel32", "KernelBase", "advapi32", "comctl32", "comdlg32", "gdi32", "gdiplus", "imm32",
               "mscoree", "msvcrt", "netapi32", "ole32", "oleaut32", "shell32", "shlwapi", "urlmon", "user32",
               "wininet", "winmm", "ws2_32", "wsock32", "advpack", "bcrypt", "crypt32", "dnsapi", "mpr", "ncrypt",
               "netutils", "samcli", "secur32", "wkscli", "wtsapi32"]
    path32 = 'C:\\Windows\\SysWOW64\\'
    path64 = 'C:\\Windows\\System32\\'
    mods = {}

    for dll_name in mods_list:
        mods[dll_name] = WinDLL(dll_name, path32+dll_name, path64+dll_name)

    export_dict, mods, mod_high_val = iter_and_dump_dlls(uc, em, export_dict, source_path, save_path, mods)

    return mods, export_dict, mod_high_val

builds=winReleases()
vars = Variables()
em = vars.emu