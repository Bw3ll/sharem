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


if platformType == "Windows":
    expandedDLLsPath32 = os.path.join(os.path.dirname(__file__), "DLLs\\x86\\")
    expandedDLLsPath64 = os.path.join(os.path.dirname(__file__), "DLLs\\x64\\")
else:
    expandedDLLsPath32 = os.path.join(os.path.dirname(__file__), "DLLs/x86/")
    expandedDLLsPath64 = os.path.join(os.path.dirname(__file__), "DLLs/x64/")


allDlls = ["ntdll", "kernel32", "KernelBase", "advapi32", "comctl32", "comdlg32", "gdi32", "gdiplus", "imm32",
               "mscoree", "msvcrt", "netapi32", "ole32", "oleaut32", "shell32", "shlwapi", "urlmon", "user32",
               "wininet", "winmm", "ws2_32", "wsock32", "advpack", "bcrypt", "crypt32", "dnsapi", "mpr", "ncrypt",
               "netutils", "samcli", "secur32", "wkscli", "wtsapi32", "cabinet","cfgmgr32","clfsw32","combase","dhcpsapi","gdiplus","httpapi","imm32","iphlpapi","iscsidsc","mprapi","msi","msvcrxx","odbc32","pdh","powrprof","rasapi32","rpcrt4","shell32","usp10","virtdisk","websocket","winbio","winhttp","winspool","wlanapi","wldap32","dbghelp","winspool","pdh","clfsw32","powrprof","mprapi","winbio","authz","cryptnet","psapi","sechost"]
allDllsDict = {}

class Win32Addresses:
    def __init__(self):
        self.process_base = 0x14000000
        self.peb_addr = 0x11017000
        self.tib_addr = 0x00000000
        self.const_addr = 0x22000000
        self.fast_addr = 0x5000
        self.ldr_addr = 0x11020000
        self.ldr_prog_addr = 0x11021000

class Win64Addresses:
    def __init__(self):
        self.process_base = 0x14000000
        self.peb_addr = 0x1101c000
        self.tib_addr = 0x00000000
        self.const_addr = 0x22000000
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

        full_dll_name = full_dll_name.encode("utf-16-le") + b"\x00\x00"
        mu.mem_write(wa.const_addr, full_dll_name)
        self.Full_Dll_Name = wa.const_addr
        wa.const_addr += len(full_dll_name)

        base_dll_name = base_dll_name.encode("utf-16-le") + b"\x00\x00"
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

        full_dll_name = full_dll_name.encode("utf-16-le") + b"\x00\x00"
        mu.mem_write(wa.const_addr, full_dll_name)
        self.Full_Dll_Name = wa.const_addr
        wa.const_addr += len(full_dll_name)

        base_dll_name = base_dll_name.encode("utf-16-le") + b"\x00\x00"
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
        # print ("windows 11", osMajor, osMinor, osBuild)
    elif em.winVersion=="Windows 10":
        osBuild=builds.win10LookupHex[em.winSP]
        # print ("windows 10", osMajor, osMinor, osBuild)        
    elif em.winVersion=="Windows 7":
        osBuild=builds.win7LookupHex[em.winSP]
        # print ("windows 7", osMajor, osMinor, osBuild)
    return osMajor, osMinor, osBuild        
        

ldr_track = 0x11021300
wa=None
dlls_obj=None
def appendNewDllToLdr32_2(mu, mods):
    global ldr_track, dlls_obj, wa

    prevDLL = dlls_obj[-1]
    for dll in mods:
        mods[dll].ldrAddr = ldr_track
        curLDR=ldr_track
        currentDLL = LDR_Module32(mu, wa, mods[dll].ldrAddr, mods[dll].base, mods[dll].base, 0x00000000, mods[dll].d32, mods[dll].name)
        ldr_track += 0x300


    # Fix old tail forward links so they now point to the new DLL
    mu.mem_write(prevDLL.ILO_entry + 0x0, pack("<I", currentDLL.ILO_entry))
    mu.mem_write(prevDLL.IMO_entry + 0x0, pack("<I", currentDLL.IMO_entry))
    mu.mem_write(prevDLL.IIO_entry + 0x0, pack("<I", currentDLL.IIO_entry))

    # Fix the "first" node backward links so they now point back to the new tail
    # ILO / IMO wrap to dlls_obj[0]
    # IIO wraps to dlls_obj[1] in your current layout
    mu.mem_write(dlls_obj[0].ILO_entry + 0x4, pack("<I", currentDLL.ILO_entry))
    mu.mem_write(dlls_obj[0].IMO_entry + 0x4, pack("<I", currentDLL.IMO_entry))
    mu.mem_write(dlls_obj[1].IIO_entry + 0x4, pack("<I", currentDLL.IIO_entry))

    # Fix PEB_LDR_DATA list-head Blink values so the loader head sees the new tail
    mu.mem_write(wa.ldr_addr + 0x10, pack("<I", currentDLL.ILO_entry))
    mu.mem_write(wa.ldr_addr + 0x18, pack("<I", currentDLL.IMO_entry))
    mu.mem_write(wa.ldr_addr + 0x20, pack("<I", currentDLL.IIO_entry))

    # Build the new DLL's own links
    currentDLL.allocate(
        mu,
        dlls_obj[0].ILO_entry, prevDLL.ILO_entry,
        dlls_obj[0].IMO_entry, prevDLL.IMO_entry,
        dlls_obj[1].IIO_entry, prevDLL.IIO_entry
    )

    dlls_obj.append(currentDLL)
    # confirmSuccess(mu,curLDR)
    # print (mods[dll].name)
    # print ("leaving appendNewDllToLdr32_2")
    # dumpAndVerifyPebLdr32(mu)


def confirmSuccess(mu,ldrAddr):
    dllBase = unpack("<I", mu.mem_read(ldrAddr + 0x18, 4))[0]
    mz = mu.mem_read(dllBase, 2)

    # DllBase
    dllBase = unpack("<I", mu.mem_read(ldrAddr + 0x18, 4))[0]

    # First 16 bytes at image base
    hdr = mu.mem_read(dllBase, 16)

    # FullDllName UNICODE_STRING at +0x24
    fullLen, fullMax, fullBuf = unpack("<HHI", mu.mem_read(ldrAddr + 0x24, 8))
    if fullLen:
        fullName = mu.mem_read(fullBuf, fullLen).decode("utf-16-le", errors="replace")
    else:
        fullName = ""

    # BaseDllName UNICODE_STRING at +0x2C
    baseLen, baseMax, baseBuf = unpack("<HHI", mu.mem_read(ldrAddr + 0x2C, 8))
    if baseLen:
        baseName = mu.mem_read(baseBuf, baseLen).decode("utf-16-le", errors="replace")
    else:
        baseName = ""

    print("LDR Addr      = 0x%08X" % ldrAddr)
    print("DllBase       = 0x%08X" % dllBase)
    print("Header bytes  = %s" % " ".join("%02X" % b for b in hdr))
    print("BaseDllName   = %s" % baseName)
    print("FullDllName   = %s" % fullName)

    test=b"MZ"
    if hdr[:2] == test:
        print("MZ OK")
    else:
        print("MZ BAD")
    print("LDR Addr   = 0x%08X" % ldrAddr)
    print("DllBase    = 0x%08X" % dllBase)
    print("MZ bytes   = %s" % hdr[:2].hex())

    iloFlink, iloBlink = unpack("<II", mu.mem_read(ldrAddr + 0x0, 8))
    imoFlink, imoBlink = unpack("<II", mu.mem_read(ldrAddr + 0x8, 8))
    iioFlink, iioBlink = unpack("<II", mu.mem_read(ldrAddr + 0x10, 8))

    print("LDR @ 0x%08X" % ldrAddr)

    print("ILO_entry @ 0x%08X" % (ldrAddr + 0x0))
    print("\tFlink = 0x%08X" % iloFlink)
    print("\tBlink = 0x%08X" % iloBlink)

    print("IMO_entry @ 0x%08X" % (ldrAddr + 0x8))
    print("\tFlink = 0x%08X" % imoFlink)
    print("\tBlink = 0x%08X" % imoBlink)

    print("IIO_entry @ 0x%08X" % (ldrAddr + 0x10))
    print("\tFlink = 0x%08X" % iioFlink)
    print("\tBlink = 0x%08X" % iioBlink)

def allocateWinStructs32(mu, mods):
    global ldr_track, dlls_obj, wa

    wa = Win32Addresses()
    dlls_obj = []

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


    # Create ldr module for the running process
    dlls_obj.append(LDR_Module32(mu, wa, wa.ldr_prog_addr, wa.process_base, wa.process_base, 0x00000000, "C:\\shellcode.exe", "shellcode.exe"))

    
    # print ("mods",len(mods))
    # print (mods)
    
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

    # t=0
    # for x in (dlls_obj):
    #     print (t, x)
    #     t+=1
    # Allocate the rest of the LDR records
    t=0
    for i in range(5, len(dlls_obj)):
        currentDLL = dlls_obj[i]
        prevDLL = dlls_obj[i-1]
        # print (t,"currentDLL", currentDLL)
        # print ("\tprevDLL",prevDLL)
        if i == len(dlls_obj) - 1:
            currentDLL.allocate(mu, dlls_obj[0].ILO_entry, prevDLL.ILO_entry, dlls_obj[0].IMO_entry, prevDLL.IMO_entry, dlls_obj[1].IIO_entry, prevDLL.IIO_entry)
        else:
            nextDLL = dlls_obj[i+1]
            currentDLL.allocate(mu, nextDLL.ILO_entry, prevDLL.ILO_entry, nextDLL.IMO_entry, prevDLL.IMO_entry, nextDLL.IIO_entry, prevDLL.IIO_entry)
        t+=1

    # dumpAndVerifyPebLdr32(mu)
    # exit()
    # print ("leaving allocateWinStructs32")


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



def readPtr32(mu, addr):
    return unpack("<I", mu.mem_read(addr, 4))[0]


def readWideString32(mu, addr, maxChars=260):
    buf = bytearray()

    for i in range(maxChars):
        ch = mu.mem_read(addr + (i * 2), 2)
        if ch == b"\x00\x00":
            break
        buf += ch

    return buf.decode("utf-16-le", errors="replace")


def dumpAndVerifyPebLdr32(mu):
    global wa, dlls_obj

    allOk = True
    status = {
        "ILO": True,
        "IMO": True,
        "IIO": True,
        "IIO_PREFIX": True,
    }
    if len(dlls_obj) < 2:
        raise Exception("dlls_obj is not initialized correctly")

    print("")
    print("===== PEB_LDR_DATA32 VERIFY =====")
    print("wa.peb_addr =", hex(wa.peb_addr))
    print("wa.ldr_addr =", hex(wa.ldr_addr))
    print("dll count   =", len(dlls_obj))
    print("")

    listSpecs = [
        ("ILO", 0x0C, 0x10, "ILO_entry", 0),
        ("IMO", 0x14, 0x18, "IMO_entry", 0),
        ("IIO", 0x1C, 0x20, "IIO_entry", 1),
    ]

    for listName, headFlinkOff, headBlinkOff, entryAttr, startIndex in listSpecs:
        print("========================================")
        print("VERIFYING", listName)
        print("========================================")

        headFlinkAddr = wa.ldr_addr + headFlinkOff
        headBlinkAddr = wa.ldr_addr + headBlinkOff

        headFlink = readPtr32(mu, headFlinkAddr)
        headBlink = readPtr32(mu, headBlinkAddr)

        entryToObj = {}
        for mod in dlls_obj:
            entryToObj[getattr(mod, entryAttr)] = mod

        print("")
        print(listName, "HEAD")
        print("\tFlink ptr @", hex(headFlinkAddr), "=", hex(headFlink))
        print("\tBlink ptr @", hex(headBlinkAddr), "=", hex(headBlink))

        if listName != "IIO":
            order = dlls_obj[startIndex:]

            expectedHeadFlink = getattr(order[0], entryAttr)
            expectedHeadBlink = getattr(order[-1], entryAttr)

            print("\tExpected Flink =", hex(expectedHeadFlink), "(", readWideString32(mu, order[0].Base_Dll_Name), ")")
            print("\tExpected Blink =", hex(expectedHeadBlink), "(", readWideString32(mu, order[-1].Base_Dll_Name), ")")

            if headFlink != expectedHeadFlink:
                print("\tBAD HEAD FLINK")
                allOk = False
            else:
                print("\tHEAD FLINK OK")

            if headBlink != expectedHeadBlink:
                print("\tBAD HEAD BLINK")
                allOk = False
            else:
                print("\tHEAD BLINK OK")

            print("")
            print(listName, "ENTRIES")

            for i in range(len(order)):
                currentDLL = order[i]

                if i == 0:
                    prevDLL = order[-1]
                else:
                    prevDLL = order[i-1]

                if i == len(order) - 1:
                    nextDLL = order[0]
                else:
                    nextDLL = order[i+1]

                entryAddr = getattr(currentDLL, entryAttr)

                actualFlink = readPtr32(mu, entryAddr + 0x0)
                actualBlink = readPtr32(mu, entryAddr + 0x4)

                expectedFlink = getattr(nextDLL, entryAttr)
                expectedBlink = getattr(prevDLL, entryAttr)

                fullName = readWideString32(mu, currentDLL.Full_Dll_Name)
                baseName = readWideString32(mu, currentDLL.Base_Dll_Name)

                print("")
                print("\tmodule          =", baseName)
                print("\tfull name       =", fullName)
                print("\tAddr            =", hex(currentDLL.Addr))
                print("\tentry           =", hex(entryAddr))
                print("\tactualFlink     =", hex(actualFlink))
                print("\tactualBlink     =", hex(actualBlink))
                print("\texpectFlink     =", hex(expectedFlink), "(", readWideString32(mu, nextDLL.Base_Dll_Name), ")")
                print("\texpectBlink     =", hex(expectedBlink), "(", readWideString32(mu, prevDLL.Base_Dll_Name), ")")

                entryOk = True

                if actualFlink != expectedFlink:
                    print("\tBAD FLINK")
                    entryOk = False
                    allOk = False

                if actualBlink != expectedBlink:
                    print("\tBAD BLINK")
                    entryOk = False
                    allOk = False

                flinkBack = readPtr32(mu, actualFlink + 0x4)
                blinkForward = readPtr32(mu, actualBlink + 0x0)

                print("\tflink->blink    =", hex(flinkBack))
                print("\tblink->flink    =", hex(blinkForward))

                if flinkBack != entryAddr:
                    print("\tBAD FLINK BACK-LINK")
                    entryOk = False
                    allOk = False

                if blinkForward != entryAddr:
                    print("\tBAD BLINK FORWARD-LINK")
                    entryOk = False
                    allOk = False

                if entryOk:
                    print("\tOK")

            print("")
            print(listName, "FORWARD WALK")

            walkPtr = headFlink
            seen = set()

            for i in range(len(order)):
                if walkPtr in seen:
                    print("\tBAD WALK: looped early at", hex(walkPtr), "after", i, "steps")
                    allOk = False
                    break

                seen.add(walkPtr)

                if walkPtr not in entryToObj:
                    print("\tBAD WALK: pointer", hex(walkPtr), "does not map to a known module entry")
                    allOk = False
                    break

                mod = entryToObj[walkPtr]
                expectedMod = order[i]

                print("\tstep", i, "ptr", hex(walkPtr), "->", readWideString32(mu, mod.Base_Dll_Name))

                if mod != expectedMod:
                    print("\tBAD WALK ORDER: expected", readWideString32(mu, expectedMod.Base_Dll_Name), "got", readWideString32(mu, mod.Base_Dll_Name))
                    allOk = False

                walkPtr = readPtr32(mu, walkPtr + 0x0)

            if walkPtr != headFlink:
                print("\tBAD WALK TERMINATION: expected return to", hex(headFlink), "got", hex(walkPtr))
                allOk = False
            else:
                print("\tWALK TERMINATION OK")

        else:
            # IIO: only the first 3 positions are treated as fixed in this model:
            # ntdll -> KernelBase -> kernel32
            expectedFirst = dlls_obj[1].IIO_entry
            expectedSecond = dlls_obj[3].IIO_entry
            expectedThird = dlls_obj[2].IIO_entry
            expectedCount = len(dlls_obj) - 1

            print("\tExpected Flink =", hex(expectedFirst), "(", readWideString32(mu, dlls_obj[1].Base_Dll_Name), ")")
            print("\tExpected Blink = dynamic tail from actual IIO walk")

            if headFlink != expectedFirst:
                print("\tBAD HEAD FLINK")
                allOk = False
            else:
                print("\tHEAD FLINK OK")

            print("")
            print(listName, "FORWARD WALK")

            walkPtrs = []
            walkPtr = headFlink
            seen = set()

            for i in range(expectedCount):
                if walkPtr in seen:
                    print("\tBAD WALK: looped early at", hex(walkPtr), "after", i, "steps")
                    allOk = False
                    break

                seen.add(walkPtr)
                walkPtrs.append(walkPtr)

                if walkPtr not in entryToObj:
                    print("\tBAD WALK: pointer", hex(walkPtr), "does not map to a known module entry")
                    allOk = False
                    break

                mod = entryToObj[walkPtr]
                print("\tstep", i, "ptr", hex(walkPtr), "->", readWideString32(mu, mod.Base_Dll_Name))

                walkPtr = readPtr32(mu, walkPtr + 0x0)

            if len(walkPtrs) == expectedCount:
                if walkPtr != headFlink:
                    print("\tBAD WALK TERMINATION: expected return to", hex(headFlink), "got", hex(walkPtr))
                    allOk = False
                else:
                    print("\tWALK TERMINATION OK")

                if headBlink != walkPtrs[-1]:
                    print("\tBAD HEAD BLINK: expected dynamic tail", hex(walkPtrs[-1]), "got", hex(headBlink))
                    allOk = False
                else:
                    print("\tHEAD BLINK OK")

                if walkPtrs[0] != expectedFirst:
                    print("\tBAD IIO FIRST ENTRY")
                    allOk = False

                if walkPtrs[1] != expectedSecond:
                    print("\tBAD IIO SECOND ENTRY: expected", readWideString32(mu, dlls_obj[3].Base_Dll_Name))
                    allOk = False

                if walkPtrs[2] != expectedThird:
                    print("\tBAD IIO THIRD ENTRY: expected", readWideString32(mu, dlls_obj[2].Base_Dll_Name))
                    allOk = False

            print("")
            print(listName, "ENTRIES")

            for entryAddr in walkPtrs:
                currentDLL = entryToObj[entryAddr]

                actualFlink = readPtr32(mu, entryAddr + 0x0)
                actualBlink = readPtr32(mu, entryAddr + 0x4)
                flinkBack = readPtr32(mu, actualFlink + 0x4)
                blinkForward = readPtr32(mu, actualBlink + 0x0)

                fullName = readWideString32(mu, currentDLL.Full_Dll_Name)
                baseName = readWideString32(mu, currentDLL.Base_Dll_Name)

                print("")
                print("\tmodule          =", baseName)
                print("\tfull name       =", fullName)
                print("\tAddr            =", hex(currentDLL.Addr))
                print("\tentry           =", hex(entryAddr))
                print("\tactualFlink     =", hex(actualFlink))
                print("\tactualBlink     =", hex(actualBlink))
                print("\tflink->blink    =", hex(flinkBack))
                print("\tblink->flink    =", hex(blinkForward))

                entryOk = True

                if flinkBack != entryAddr:
                    print("\tBAD FLINK BACK-LINK")
                    entryOk = False
                    allOk = False

                if blinkForward != entryAddr:
                    print("\tBAD BLINK FORWARD-LINK")
                    entryOk = False
                    allOk = False

                if entryOk:
                    print("\tOK")

            # Explicitly verify the fixed first-3 IIO relationships
            ntdllIio = dlls_obj[1].IIO_entry
            kernelBaseIio = dlls_obj[3].IIO_entry
            kernel32Iio = dlls_obj[2].IIO_entry

            ntdllFlink = readPtr32(mu, ntdllIio + 0x0)
            kernelBaseBlink = readPtr32(mu, kernelBaseIio + 0x4)
            kernelBaseFlink = readPtr32(mu, kernelBaseIio + 0x0)
            kernel32Blink = readPtr32(mu, kernel32Iio + 0x4)

            print("")
            print("IIO FIXED PREFIX CHECKS")

            if ntdllFlink != kernelBaseIio:
                print("\tBAD: ntdll IIO flink does not point to KernelBase")
                allOk = False
            else:
                print("\tntdll -> KernelBase OK")

            if kernelBaseBlink != ntdllIio:
                print("\tBAD: KernelBase IIO blink does not point to ntdll")
                allOk = False
            else:
                print("\tKernelBase <- ntdll OK")

            if kernelBaseFlink != kernel32Iio:
                print("\tBAD: KernelBase IIO flink does not point to kernel32")
                allOk = False
            else:
                print("\tKernelBase -> kernel32 OK")

            if kernel32Blink != kernelBaseIio:
                print("\tBAD: kernel32 IIO blink does not point to KernelBase")
                allOk = False
            else:
                print("\tkernel32 <- KernelBase OK")

        print("")
        print("allOk",allOk)

def addNew(uc, em, export_dict, source_path, save_path,newDll):  #//InitMods for single
    global allDlls
    path32 = 'C:\\Windows\\SysWOW64\\'
    path64 = 'C:\\Windows\\System32\\'
    mods = {}     ###  Can keep the list (mult. file format) even though this is for a single one, for ease of reusing old code
    not_found = []

    allDlls.append(newDll)

    with disable_file_system_redirection():                       
        if os.path.exists(source_path + newDll + ".dll"):
            mods[newDll] = WinDLL(newDll, path32 + newDll, path64 + newDll)
        elif os.path.exists(source_path + newDll):
            if newDll.lower().endswith(".dll"):
                newDll = newDll[:-4]
            mods[newDll] = WinDLL(newDll, path32 + newDll, path64 + newDll)
        else:
            not_found.append(newDll)

    for n in not_found:
        allDlls.remove(n)


####need to work on this part now!!!!
    export_dict, mods, mod_high_val, newBase = iter_and_dump_single_dll(uc, em, export_dict, source_path, save_path, mods)
    # print ("we are done2", hex(newBase))

    return mods, export_dict, mod_high_val,newBase


def iter_and_dump_single_dll (mu, em, export_dict, source_path, save_path, mods):
    global MOD_LOW, baseGlobal
    ###  Can keep the list (mult. file format) even though this is for a single one, for ease of reusing old code
    for dll_name in mods:
        dll_file = dll_name + '.dll'


        allDllsDict[dll_file] = baseGlobal
        mods[dll_name].base = baseGlobal
        newBase=baseGlobal
        if platformType == "Windows":
            with disable_file_system_redirection():
                if os.path.exists(source_path+dll_file) == False:
                    continue

        if os.path.exists(save_path+dll_file) and 2==23:  ###SKIP THIS FOR NOW
            rawDll = readRaw(save_path + dll_file)

        # Inflate dlls so PE offsets are correct
        elif platformType == "Windows":
            # if not runOnce:
            print("Warning: DLL must be parsed and inflated from a Windows OS.\n\tThis may take a moment to parse "+dll_name+" .")
            # runOnce = True

            dllPath = source_path + dll_file
            rawDll, padding = padDLL(dllPath, dll_file, save_path)

            with disable_file_system_redirection():
                # pe = pefile.PE(source_path+dll_file)
                pe = pefile.PE(source_path+dll_file, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    # print("exp",exp)
                    export_dict[hex(baseGlobal + exp.address)] = (exp.name.decode(), dll_file)
                except:
                    export_dict[hex(baseGlobal + exp.address)] = ("unknown_function", dll_file)
        else:
            newBase=0
            continue

        # Dump the dll into emulation memory
        mu.mem_write(baseGlobal, rawDll)
        baseGlobal += len(rawDll) + 20

    mod_high_val = baseGlobal
    # print ("we are done1", hex(newBase))
    return export_dict, mods, mod_high_val,newBase


baseGlobal = 0x14100000
def iter_and_dump_dlls(mu, em, export_dict, source_path, save_path, mods):
    global MOD_LOW, baseGlobal

    baseGlobal = 0x14100000
    runOnce = False

    for dll_name in mods:
        dll_file = dll_name + '.dll'

        allDllsDict[dll_file] = baseGlobal
        mods[dll_name].base = baseGlobal
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
                # pe = pefile.PE(source_path+dll_file)
                pe = pefile.PE(source_path+dll_file, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    export_dict[hex(baseGlobal + exp.address)] = (exp.name.decode(), dll_file)
                except:
                    export_dict[hex(baseGlobal + exp.address)] = ("unknown_function", dll_file)
        else:
            continue

        # Dump the dll into emulation memory
        mu.mem_write(baseGlobal, rawDll)
        baseGlobal += len(rawDll) + 20

    mod_high_val = baseGlobal
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
        with open(foundDLLAddrs, 'w') as out:
            json.dump(export_dict, out)

    # Make sure no duplicates get in if there's already content in the file
    else:
        with open(foundDLLAddrs, 'r') as f:
            currentData = json.load(f)

        if len(currentData) == 0 or True:  #### the one below does NOT work correctly
            # print ("currentData==0")
            with open(foundDLLAddrs, 'w') as out:
                json.dump(export_dict, out)

        # else:
        #     with open(foundDLLAddrs, 'a') as out:
        #         for apiAddr, apiInfo in export_dict.items():
        #             if apiAddr not in currentData.keys():
        #                 print ("apiAddr", apiInfo)
        #                 newRecord = {}
        #                 newRecord[apiAddr] = apiInfo
        #                 json.dump(newRecord, out)

def initMods(uc, em, export_dict, source_path, save_path):
    # print ("export_dict size2", len(export_dict))

    global allDlls
    allDlls = ["ntdll", "kernel32", "KernelBase", "advapi32", "comctl32", "comdlg32", "gdi32", "gdiplus", "imm32",
               "mscoree", "msvcrt", "netapi32", "ole32", "oleaut32", "shell32", "shlwapi", "urlmon", "user32",
               "wininet", "winmm", "ws2_32", "wsock32", "advpack", "bcrypt", "crypt32", "dnsapi", "mpr", "ncrypt",
               "netutils", "samcli", "secur32", "wkscli", "wtsapi32", "cabinet","cfgmgr32","clfsw32","combase","dhcpsapi","gdiplus","httpapi","imm32","iphlpapi","iscsidsc","mprapi","msi","msvcrxx","odbc32","pdh","powrprof","rasapi32","rpcrt4","shell32","usp10","virtdisk","websocket","winbio","winhttp","winspool","wlanapi","wldap32","dbghelp","winspool","pdh","clfsw32","powrprof","mprapi","winbio","authz","cryptnet","psapi","sechost"]
    path32 = 'C:\\Windows\\SysWOW64\\'
    path64 = 'C:\\Windows\\System32\\'
    mods = {}
    not_found = []

    for dll_name in allDlls:
            with disable_file_system_redirection():
                if os.path.exists(source_path + dll_name + ".dll"):
                    mods[dll_name] = WinDLL(dll_name, path32+dll_name, path64+dll_name)
                else:
                    not_found.append(dll_name)

    for n in not_found:
        allDlls.remove(n)

    export_dict, mods, mod_high_val = iter_and_dump_dlls(uc, em, export_dict, source_path, save_path, mods)

    return mods, export_dict, mod_high_val

builds=winReleases()
vars = Variables()
em = vars.emu