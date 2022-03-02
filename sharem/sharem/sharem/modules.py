from struct import pack, unpack

ENTRY_ADDR = 0x1000
PEB_ADDR = 0x11017000
SEGMENT_ADDR = 0x11010000
SEGMENT_SIZE = 0x4000
TIB_ADDR = 0x00000000
TIB_SIZE = 0x100
PEB_LIMIT = 0x208
CONST_ADDR = 0x20000000

LDR_ADDR = 0x11020000
LDR_PROG_ADDR = 0x11021000
LDR_NTDLL_ADDR = 0x11021300
LDR_KERNEL32_ADDR = 0x11021600
LDR_ADVAPI32_ADDR = 0x11021900
LDR_COMCTL32_ADDR = 0x11021C00
LDR_COMDLG32_ADDR = 0x11022000
LDR_GDI32_ADDR = 0x11022300
LDR_GDIPLUS_ADDR = 0x11022600
LDR_IMM32_ADDR = 0x11022900
LDR_MSCOREE_ADDR = 0x11022C00
LDR_MSVCRT_ADDR = 0x11023000
LDR_NETAPI32_ADDR = 0x11023300
LDR_OLE32_ADDR = 0x11023600
LDR_OLEAUT32_ADDR = 0x11023900
LDR_SHELL32_ADDR = 0x11024C00
LDR_SHLWAPI_ADDR = 0x11025000
LDR_URLMON_ADDR = 0x11025300
LDR_USER32_ADDR = 0x11025600
LDR_WININET_ADDR = 0x11025900
LDR_WINMM_ADDR = 0x11025C00
LDR_WS2_32_ADDR = 0x11026000
LDR_WSOCK32_ADDR = 0x11026300
LDR_ADVPACK_ADDR=0x11026600
LDR_BCRYPT_ADDR=0x11026900
LDR_CRYPT32_ADDR=0x11026C00
LDR_DNSAPI_ADDR=0x11027000
LDR_MPR_ADDR=0x11027300
LDR_NCRYPT_ADDR=0x11027600
LDR_NETUTILS_ADDR=0x11027900
LDR_SAMCLI_ADDR=0x11027C00
LDR_SECUR32_ADDR=0x11028000
LDR_WKSCLI_ADDR=0x11028300
LDR_WTSAPI32_ADDR=0x11028600

PROCESS_BASE = 0x14000000
NTDLL_BASE = 0x14100000
NTDLL_TOP = 0x14252538
KERNEL32_BASE = 0x14252538
KERNEL32_TOP = 0x14372538
ADVAPI32_BASE = 0x14372538
ADVAPI32_TOP = 0x1441f938
COMCTL32_BASE = 0x1441f938
COMCTL32_TOP = 0x144b1138
COMDLG32_BASE = 0x144b1138
COMDLG32_TOP = 0x14537b38
GDI32_BASE = 0x14537b38
GDI32_TOP = 0x14594338
GDIPLUS_BASE = 0x14594338
GDIPLUS_TOP = 0x151ecd38
IMM32_BASE = 0x151ecd38
IMM32_TOP = 0x1521a138
MSCOREE_BASE = 0x1521a138
MSCOREE_TOP = 0x15272c88
MSVCRT_BASE = 0x15272c88
MSVCRT_TOP = 0x1532b688
NETAPI32_BASE = 0x1532b688
NETAPI32_TOP = 0x15349688
OLE32_BASE = 0x15349688
OLE32_TOP = 0x154b5888
OLEAUT32_BASE = 0x154b5888
OLEAUT32_TOP = 0x15554088
SHELL32_BASE = 0x15554088
SHELL32_TOP = 0x161aca88
SHLWAPI_BASE = 0x161aca88
SHLWAPI_TOP = 0x16212288
URLMON_BASE = 0x16212288
URLMON_TOP = 0x16367488
USER32_BASE = 0x16367488
USER32_TOP = 0x16443088
WININET_BASE = 0x16443088
WININET_TOP = 0x16882488
WINMM_BASE = 0x16882488
WINMM_TOP = 0x168c1a88
WS2_32_BASE = 0x168c1a88
WS2_32_TOP = 0x16904088
WSOCK32_BASE = 0x16904088
WSOCK32_TOP = 0x16917c88
ADVPACK_BASE = 0x16917c88
ADVPACK_TOP = 0x16946a88
BCRYPT_BASE = 0x16946a88
BCRYPT_TOP = 0x1696ae88
CRYPT32_BASE = 0x1696ae88
CRYPT32_TOP = 0x16a9a488
DNSAPI_BASE = 0x16a9a488
DNSAPI_TOP = 0x16aec288
MPR_BASE = 0x16aec288
MPR_TOP = 0x16b0bc88
NCRYPT_BASE = 0x16b0bc88
NCRYPT_TOP = 0x16b52488
NETUTILS_BASE = 0x16b52488
NETUTILS_TOP = 0x16b67c88
SAMCLI_BASE = 0x16b67c88
SAMCLI_TOP = 0x16b84488
SECUR32_BASE = 0x16b84488
SECUR32_TOP = 0x16b99a88
WKSCLI_BASE = 0x16b99a88
WKSCLI_TOP = 0x16bb5288
WTSAPI32_BASE = 0x16bb5288
WTSAPI32_TOP = 0x16bcf088


path32 = 'C:\\Windows\\SysWOW64\\'
path64 = 'C:\\Windows\\System32\\'
expandedDLLsPath32="expandedDLLsPath"
expandedDLLsPath64="expandedDLLsPath"
mods = {}

allDlls=["ntdll", "kernel32",  "advapi32",  "comctl32",  "comdlg32",  "gdi32", "gdiplus", "imm32",  "mscoree",  "msvcrt",  "netapi32",  "ole32",  "oleaut32",  "shell32",  "shlwapi",  "urlmon",  "user32",  "wininet",  "winmm",  "ws2_32",  "wsock32", "advpack", "bcrypt", "crypt32", "dnsapi", "mpr", "ncrypt", "netutils", "samcli", "secur32", "wkscli", "wtsapi32"]
allDllsDict = {'ntdll.dll': NTDLL_BASE, 'kernel32.dll': KERNEL32_BASE, 'advapi32.dll': ADVAPI32_BASE, 'comctl32.dll': COMCTL32_BASE, 'comdlg32.dll': COMDLG32_BASE, 'gdi32.dll': GDI32_BASE, 'gdiplus.dll': GDIPLUS_BASE, 'imm32.dll': IMM32_BASE, 'mscoree.dll': MSCOREE_BASE, 'msvcrt.dll': MSVCRT_BASE, 'netapi32.dll': NETAPI32_BASE, 'ole32.dll': OLE32_BASE, 'oleaut32.dll': OLEAUT32_BASE, 'shell32.dll': SHELL32_BASE, 'shlwapi.dll': SHLWAPI_BASE, 'urlmon.dll': URLMON_BASE, 'user32.dll': USER32_BASE, 'wininet.dll': WININET_BASE, 'winmm.dll': WINMM_BASE, 'ws2_32.dll': WS2_32_BASE, 'wsock32.dll': WSOCK32_BASE, 'advpack.dll':ADVPACK_BASE, 'bcrypt.dll':BCRYPT_BASE, 'crypt32.dll':CRYPT32_BASE, 'dnsapi.dll':DNSAPI_BASE, 'mpr.dll':MPR_BASE, 'ncrypt.dll':NCRYPT_BASE, 'netutils.dll':NETUTILS_BASE, 'samcli.dll':SAMCLI_BASE, 'secur32.dll':SECUR32_BASE, 'wkscli.dll':WKSCLI_BASE, 'wtsapi32.dll':WTSAPI32_BASE}
ldrDict = {'ntdll.dll': LDR_NTDLL_ADDR, 'kernel32.dll': LDR_KERNEL32_ADDR, 'advapi32.dll': LDR_ADVAPI32_ADDR, 'comctl32.dll': LDR_COMCTL32_ADDR, 'comdlg32.dll': LDR_COMDLG32_ADDR, 'gdi32.dll': LDR_GDI32_ADDR, 'gdiplus.dll': LDR_GDIPLUS_ADDR, 'imm32.dll': LDR_IMM32_ADDR, 'mscoree.dll': LDR_MSCOREE_ADDR, 'msvcrt.dll': LDR_MSVCRT_ADDR, 'netapi32.dll': LDR_NETAPI32_ADDR, 'ole32.dll': LDR_OLE32_ADDR, 'oleaut32.dll': LDR_OLEAUT32_ADDR, 'shell32.dll': LDR_SHELL32_ADDR, 'shlwapi.dll': LDR_SHLWAPI_ADDR, 'urlmon.dll': LDR_URLMON_ADDR, 'user32.dll': LDR_USER32_ADDR, 'wininet.dll': LDR_WININET_ADDR, 'winmm.dll': LDR_WINMM_ADDR, 'ws2_32.dll': LDR_WS2_32_ADDR, 'wsock32.dll': LDR_WSOCK32_ADDR, 'advpack.dll':LDR_ADVPACK_ADDR, 'bcrypt.dll':LDR_BCRYPT_ADDR, 'crypt32.dll':LDR_CRYPT32_ADDR, 'dnsapi.dll':LDR_DNSAPI_ADDR, 'mpr.dll':LDR_MPR_ADDR, 'ncrypt.dll':LDR_NCRYPT_ADDR, 'netutils.dll':LDR_NETUTILS_ADDR, 'samcli.dll':LDR_SAMCLI_ADDR, 'secur32.dll':LDR_SECUR32_ADDR, 'wkscli.dll':LDR_WKSCLI_ADDR, 'wtsapi32.dll':LDR_WTSAPI32_ADDR}


advpack="advpack"
bcrypt="bcrypt"
crypt32="crypt32"
dnsapi="dnsapi"
mpr="mpr"
ncrypt="ncrypt"
netutils="netutils"
samcli="samcli"
secur32="secur32"
wkscli="wkscli"
wtsapi32="wtsapi32"

allDlls2=["advpack", "bcrypt", "crypt32", "dnsapi", "mpr", "ncrypt", "netutils", "samcli", "secur32", "wkscli", "wtsapi32"]

allDllsDict2={'advpack.dll':ADVPACK_BASE, 'bcrypt.dll':BCRYPT_BASE, 'crypt32.dll':CRYPT32_BASE, 'dnsapi.dll':DNSAPI_BASE, 'mpr.dll':MPR_BASE, 'ncrypt.dll':NCRYPT_BASE, 'netutils.dll':NETUTILS_BASE, 'samcli.dll':SAMCLI_BASE, 'secur32.dll':SECUR32_BASE, 'wkscli.dll':WKSCLI_BASE, 'wtsapi32.dll':WTSAPI32_BASE}

ldrDict2={'advpack.dll':LDR_ADVPACK_ADDR, 'bcrypt.dll':LDR_BCRYPT_ADDR, 'crypt32.dll':LDR_CRYPT32_ADDR, 'dnsapi.dll':LDR_DNSAPI_ADDR, 'mpr.dll':LDR_MPR_ADDR, 'ncrypt.dll':LDR_NCRYPT_ADDR, 'netutils.dll':LDR_NETUTILS_ADDR, 'samcli.dll':LDR_SAMCLI_ADDR, 'secur32.dll':LDR_SECUR32_ADDR, 'wkscli.dll':LDR_WKSCLI_ADDR, 'wtsapi32.dll':LDR_WTSAPI32_ADDR}

ntdll="ntdll"
kernel32="kernel32"
advapi32="advapi32"
comctl32="comctl32"
comdlg32="comdlg32"
gdiplus="gdiplus"
gdi32="gdi32"
imm32="imm32"
mscoree="mscoree"
msvcrt="msvcrt"
netapi32="netapi32"
ole32="ole32"
oleaut32="oleaut32"
shell32="shell32"
shlwapi="shlwapi"
urlmon="urlmon"
user32="user32"
wininet="wininet"
winmm="winmm"
ws2_32="ws2_32"
wsock32="wsock32"

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
        mu.mem_write(self.Addr, pack("<Q", self.Length))
        mu.mem_write(self.Addr+0x4, pack("<Q", self.Initialized))
        mu.mem_write(self.Addr+0x8, pack("<Q", self.Sshandle))
        mu.mem_write(self.Addr+0xc, pack("<Q", ilo_flink) + pack("<Q", ilo_blink))
        mu.mem_write(self.Addr+0x14, pack("<Q", imo_flink) + pack("<Q", imo_blink))
        mu.mem_write(self.Addr+0x1c, pack("<Q", iio_flink) + pack("<Q", iio_blink))

class LDR_Module32():
    def __init__(self, mu, addr, dll_base, entry_point, reserved, full_dll_name, base_dll_name):
        self.Addr = addr
        self.ILO_entry = addr
        self.IMO_entry = addr + 0x8
        self.IIO_entry = addr + 0x10
        self.DLL_Base = dll_base
        self.Entry_Point = entry_point
        self.Reserved = reserved

        global CONST_ADDR
        full_dll_name = full_dll_name.encode("utf-16-le") + b"\x00"
        mu.mem_write(CONST_ADDR, full_dll_name)
        self.Full_Dll_Name = CONST_ADDR
        CONST_ADDR += len(full_dll_name)

        base_dll_name = base_dll_name.encode("utf-16-le") + b"\x00"
        mu.mem_write(CONST_ADDR, base_dll_name)
        self.Base_Dll_Name = CONST_ADDR
        CONST_ADDR += len(base_dll_name)

    def allocate(self, mu, ilo_flink, ilo_blink, imo_flink, imo_blink, iio_flink, iio_blink):
        mu.mem_write(self.Addr, pack("<Q", ilo_flink) + pack("<Q", ilo_blink))
        mu.mem_write(self.Addr+0x8, pack("<Q", imo_flink) + pack("<Q", imo_blink))
        mu.mem_write(self.Addr+0x10, pack("<Q", iio_flink) + pack("<Q", iio_blink))
        mu.mem_write(self.Addr+0x18, pack("<Q", self.DLL_Base))
        mu.mem_write(self.Addr+0x1c, pack("<Q", self.Entry_Point))

        mu.mem_write(self.Addr+0x24, pack("<Q", 0x007e007c))
        mu.mem_write(self.Addr+0x28, pack("<Q", self.Full_Dll_Name))
        mu.mem_write(self.Addr+0x2c, pack("<Q", 0x001c001a))
        mu.mem_write(self.Addr+0x30, pack("<Q", self.Base_Dll_Name))


        pointer = unpack("<I", mu.mem_read(self.Addr+0x30, 4))[0]

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
    def __init__(self, addr, dll_base, entry_point, reserved, full_dll_name, base_dll_name):
        self.Addr = addr
        self.ILO_entry = addr
        self.IMO_entry = addr + 0x10
        self.IIO_entry = addr + 0x20
        self.DLL_Base = dll_base
        self.Entry_Point = entry_point
        self.Reserved = reserved
        self.Full_Dll_Name = full_dll_name
        self.Base_Dll_Name = base_dll_name
    def allocate(self, mu, ilo_flink, ilo_blink, imo_flink, imo_blink, iio_flink, iio_blink):
        mu.mem_write(self.Addr, pack("<Q", ilo_flink) + pack("<Q", ilo_blink))
        mu.mem_write(self.Addr+0x10, pack("<Q", imo_flink) + pack("<Q", imo_blink))
        mu.mem_write(self.Addr+0x20, pack("<Q", iio_flink) + pack("<Q", iio_blink))
        mu.mem_write(self.Addr+0x30, pack("<Q", self.DLL_Base))
        mu.mem_write(self.Addr+0x40, pack("<Q", self.Entry_Point))
        mu.mem_write(self.Addr+0x50, pack("<Q", self.Reserved))
        mu.mem_write(self.Addr+0x60, pack("<Q", self.Full_Dll_Name))
        mu.mem_write(self.Addr+0x70, pack("<Q", self.Base_Dll_Name))

def allocateWinStructs32(mu):
    # Put location of PEB at FS:30
    mu.mem_write((PEB_ADDR-10), b'\x4a\x41\x43\x4f\x42\x41\x41\x41\x41\x42')

    mu.mem_write(TIB_ADDR, b'\x00\x00\x00' + b'\x90'*0x2d + pack("<Q", PEB_ADDR))

    # Create PEB data structure. Put pointer to ldr at offset 0xC
    mu.mem_write(PEB_ADDR, b'\x90'*0xc + pack("<Q", LDR_ADDR) + b'\x90'*0x1fc)

    # Create PEB_LDR_DATA structure
    peb_ldr = PEB_LDR_DATA32(LDR_ADDR, 0x24, 0x00000000, 0x00000000)

    dlls_obj = [0]*(len(allDlls)+1)

    # Create ldr modules for the rest of the DLLs
    dlls_obj[0] = LDR_Module32(mu, LDR_PROG_ADDR, PROCESS_BASE, PROCESS_BASE, 0x00000000, "C:\\shellcode.exe", "shellcode.exe")

    i = 1
    for dll in allDlls:
        dlls_obj[i] = LDR_Module32(mu, mods[dll].ldrAddr, mods[dll].base, mods[dll].base, 0x00000000, mods[dll].d32, mods[dll].name)
        i += 1

    peb_ldr.allocate(mu, dlls_obj[0].ILO_entry, dlls_obj[-1].ILO_entry, dlls_obj[0].IMO_entry, dlls_obj[-1].IMO_entry, dlls_obj[1].IIO_entry, dlls_obj[-1].IIO_entry)

    # Allocate the record in memory for program, ntdll, and kernel32
    for i in range(0, len(dlls_obj)):
        currentDLL = dlls_obj[i]

        if i == 0:
            nextDLL = dlls_obj[i+1]
            currentDLL.allocate(mu, nextDLL.ILO_entry, dlls_obj[-1].ILO_entry, nextDLL.IMO_entry, dlls_obj[-1].IMO_entry, nextDLL.IIO_entry, dlls_obj[-1].IIO_entry)
        elif i == len(dlls_obj) - 1:
            prevDLL = dlls_obj[i-1]
            currentDLL.allocate(mu, dlls_obj[0].ILO_entry, prevDLL.ILO_entry, dlls_obj[0].IMO_entry, prevDLL.IMO_entry, dlls_obj[1].IIO_entry, prevDLL.IIO_entry)
        else:
            nextDLL = dlls_obj[i+1]
            prevDLL = dlls_obj[i-1]
            currentDLL.allocate(mu, nextDLL.ILO_entry, prevDLL.ILO_entry, nextDLL.IMO_entry, prevDLL.IMO_entry, nextDLL.IIO_entry, prevDLL.IIO_entry)

def allocateWinStructs64(mu):
    mu.reg_write(UC_X86_REG_FS_BASE, TIB_ADDR)

    # Put location of PEB at GS:60
    mu.mem_write(TIB_ADDR, b'\x00'*0x60 + pack("<Q", PEB_ADDR))

    # Create PEB data structure. Put pointer to ldr at offset 0x18
    mu.mem_write(PEB_ADDR, b'\x00'*0x18 + pack("<Q", LDR_ADDR) + b'\x00'*0x1fc)

    # Create PEB_LDR_DATA structure
    peb_ldr = PEB_LDR_DATA64(LDR_ADDR, 0x24, 0x00000000, 0x00000000)
    process = LDR_Module64(LDR_PROG_ADDR, PROCESS_BASE, PROCESS_BASE, 0x00000000, 0x00000000, 0x00000000)
    ntdll = LDR_Module64(LDR_NTDLL_ADDR, NTDLL_BASE, NTDLL_BASE, 0x00000000, 0x00000000, 0x00000000)
    kernel32 = LDR_Module64(LDR_KERNEL32_ADDR, KERNEL32_BASE, KERNEL32_BASE, 0x00000000, 0x00000000, 0x00000000)

    peb_ldr.allocate(mu, process.ILO_entry, kernel32.ILO_entry, process.IMO_entry, kernel32.IMO_entry, ntdll.IIO_entry, kernel32.IIO_entry)
    process.allocate(mu, ntdll.ILO_entry, peb_ldr.ILO_entry, ntdll.IMO_entry, peb_ldr.IMO_entry, 0x00000000, 0x00000000)
    ntdll.allocate(mu, kernel32.ILO_entry, process.ILO_entry, kernel32.IMO_entry, process.IMO_entry, kernel32.IIO_entry, peb_ldr.IIO_entry)
    kernel32.allocate(mu, peb_ldr.ILO_entry, ntdll.ILO_entry, peb_ldr.IMO_entry, ntdll.IMO_entry, peb_ldr.IIO_entry, ntdll.IIO_entry)

    # initialize stack
    mu.reg_write(UC_X86_REG_ESP, STACK_ADDR)
    mu.reg_write(UC_X86_REG_EBP, STACK_ADDR)

class WinDLL:
    def __init__(self, dllName, base, d32, d64, dExpanded32, dExpanded64, ldrAddr):
        self.id=dllName[:-3]
        self.name = dllName
        self.base = base
        self.d32 = d32
        self.d64 = d64
        self.dExpanded32=dExpanded32
        self.dExpanded64=dExpanded64
        self.ldrAddr = ldrAddr
    def setBase(self, base):
        self.base = base
    def setd32(self, d32):
        self.d32 = d32
    def setd64(self, d64):
        self.d64 = d64
    def setdExpanded32(self, dExpanded32):
        self.dExpanded32 = dExpanded32
    def setdExpanded64(self, dExpanded64):
        self.dExpanded64 = dExpanded64

def initMods():
    for dllName, base in allDllsDict.items():
        mods[dllName[:-4]]= WinDLL(dllName, base, path32+dllName, path64+dllName, expandedDLLsPath32, expandedDLLsPath64, ldrDict[dllName])

initMods()