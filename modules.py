LDR_ADDR = 0x41020000
LDR_PROG_ADDR = 0x41021000
LDR_NTDLL_ADDR = 0x41021300
LDR_KERNEL32_ADDR = 0x41021600
LDR_ADVAPI32_ADDR = 0x41021900
LDR_COMCTL32_ADDR = 0x41021C00
LDR_COMDLG32_ADDR = 0x41022000
LDR_GDI32_ADDR = 0x41022300
LDR_IMM32_ADDR = 0x41022600
LDR_MSCOREE_ADDR = 0x41022900
LDR_MSVCRT_ADDR = 0x41022C00
LDR_NETAPI32_ADDR = 0x41023000
LDR_OLE32_ADDR = 0x41023300
LDR_OLEAUT32_ADDR = 0x41023600
LDR_SHELL32_ADDR = 0x41023900
LDR_SHLWAPI_ADDR = 0x41023C00
LDR_URLMON_ADDR = 0x41024000
LDR_USER32_ADDR = 0x41024300
LDR_WININET_ADDR = 0x41024600
LDR_WINMM_ADDR = 0x41024900
LDR_WS2_32_ADDR = 0x41024C00
LDR_WSOCK32_ADDR = 0x41025000

PROCESS_BASE = 0x44000000
NTDLL_BASE = 0x44100000
NTDLL_TOP = 0x44253138
KERNEL32_BASE = 0x44253138
KERNEL32_TOP = 0x44364138
ADVAPI32_BASE = 0x44364138
ADVAPI32_TOP = 0x44403138
COMCTL32_BASE = 0x44403138
COMCTL32_TOP = 0x44486538
COMDLG32_BASE = 0x44486538
COMDLG32_TOP = 0x444feb38
GDI32_BASE = 0x444feb38
GDI32_TOP = 0x4455bf38
IMM32_BASE = 0x4455bf38
IMM32_TOP = 0x44589f38
MSCOREE_BASE = 0x44589f38
MSCOREE_TOP = 0x445d4688
MSVCRT_BASE = 0x445d4688
MSVCRT_TOP = 0x4467e888
NETAPI32_BASE = 0x4467e888
NETAPI32_TOP = 0x4468e288
OLE32_BASE = 0x4468e288
OLE32_TOP = 0x447ec088
OLEAUT32_BASE = 0x447ec088
OLEAUT32_TOP = 0x4487c488
SHELL32_BASE = 0x4487c488
SHELL32_TOP = 0x454c6a88
SHLWAPI_BASE = 0x454c6a88
SHLWAPI_TOP = 0x4551de88
URLMON_BASE = 0x4551de88
URLMON_TOP = 0x45664c88
USER32_BASE = 0x45664c88
USER32_TOP = 0x45741488
WININET_BASE = 0x45741488
WININET_TOP = 0x45b72488
WINMM_BASE = 0x45b72488
WINMM_TOP = 0x45ba3688
WS2_32_BASE = 0x45ba3688
WS2_32_TOP = 0x45b8d688
WSOCK32_BASE = 0x45bd7888
WSOCK32_TOP = 0x45bdc088

path32 = 'C:\\Windows\\SysWOW64\\'
path64 = 'C:\\Windows\\System32\\'
expandedDLLsPath32="expandedDLLsPath"
expandedDLLsPath64="expandedDLLsPath"
mods = {}

allDlls=["ntdll", "kernel32",  "advapi32",  "comctl32",  "comdlg32",  "gdi32",  "imm32",  "mscoree",  "msvcrt",  "netapi32",  "ole32",  "oleaut32",  "shell32",  "shlwapi",  "urlmon",  "user32",  "wininet",  "winmm",  "ws2_32",  "wsock32"]
allDllsDict = {'ntdll.dll': NTDLL_BASE, 'kernel32.dll': KERNEL32_BASE, 'advapi32.dll': ADVAPI32_BASE, 'comctl32.dll': COMCTL32_BASE, 'comdlg32.dll': COMDLG32_BASE, 'gdi32.dll': GDI32_BASE, 'imm32.dll': IMM32_BASE, 'mscoree.dll': MSCOREE_BASE, 'msvcrt.dll': MSVCRT_BASE, 'netapi32.dll': NETAPI32_BASE, 'ole32.dll': OLE32_BASE, 'oleaut32.dll': OLEAUT32_BASE, 'shell32.dll': SHELL32_BASE, 'shlwapi.dll': SHLWAPI_BASE, 'urlmon.dll': URLMON_BASE, 'user32.dll': USER32_BASE, 'wininet.dll': WININET_BASE, 'winmm.dll': WINMM_BASE, 'ws2_32.dll': WS2_32_BASE, 'wsock32.dll': WSOCK32_BASE}
ldrDict = {'ntdll.dll': LDR_NTDLL_ADDR, 'kernel32.dll': LDR_KERNEL32_ADDR, 'advapi32.dll': LDR_ADVAPI32_ADDR, 'comctl32.dll': LDR_COMCTL32_ADDR, 'comdlg32.dll': LDR_COMDLG32_ADDR, 'gdi32.dll': LDR_GDI32_ADDR, 'imm32.dll': LDR_IMM32_ADDR, 'mscoree.dll': LDR_MSCOREE_ADDR, 'msvcrt.dll': LDR_MSVCRT_ADDR, 'netapi32.dll': LDR_NETAPI32_ADDR, 'ole32.dll': LDR_OLE32_ADDR, 'oleaut32.dll': LDR_OLEAUT32_ADDR, 'shell32.dll': LDR_SHELL32_ADDR, 'shlwapi.dll': LDR_SHLWAPI_ADDR, 'urlmon.dll': LDR_URLMON_ADDR, 'user32.dll': LDR_USER32_ADDR, 'wininet.dll': LDR_WININET_ADDR, 'winmm.dll': LDR_WINMM_ADDR, 'ws2_32.dll': LDR_WS2_32_ADDR, 'wsock32.dll': LDR_WSOCK32_ADDR}

ntdll="ntdll"
kernel32="kernel32"
advapi32="advapi32"
comctl32="comctl32"
comdlg32="comdlg32"
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