NTDLL_BASE = 0x12345678
KERNEL32_BASE = 0x12345678
ADVAPI32_BASE = 0x12345678
COMCTL32_BASE = 0x12345678
COMDLG32_BASE = 0x12345678
GDI32_BASE = 0x12345678
IMM32_BASE = 0x12345678
MSCOREE_BASE = 0x12345678
MSVCRT_BASE = 0x12345678
NETAPI32_BASE = 0x12345678
OLE32_BASE = 0x12345678
OLEAUT32_BASE = 0x12345678
SHELL32_BASE = 0x12345678
SHLWAPI_BASE = 0x12345678
URLMON_BASE = 0x12345678
USER32_BASE = 0x12345678
WININET_BASE = 0x12345678
WINMM_BASE = 0x12345678
WS2_32_BASE = 0x12345678
WSOCK32_BASE = 0x12345678


allDlls=["ntdll", "kernel32",  "advapi32",  "comctl32",  "comdlg32",  "gdi32",  "imm32",  "mscoree",  "msvcrt",  "netapi32",  "ole32",  "oleaut32",  "shell32",  "shlwapi",  "urlmon",  "user32",  "wininet",  "winmm",  "ws2_32",  "wsock32"]

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

path32 = 'C:\\Windows\\SysWOW64\\'
path64 = 'C:\\Windows\\System32\\'
expandedDLLsPath32="expandedDLLsPath"
expandedDLLsPath64="expandedDLLsPath"
mod = {}


dlls = {'ntdll.dll': NTDLL_BASE, 'kernel32.dll': KERNEL32_BASE, 'advapi32.dll': ADVAPI32_BASE, 'comctl32.dll': COMCTL32_BASE, 'comdlg32.dll': COMDLG32_BASE, 'gdi32.dll': GDI32_BASE, 'imm32.dll': IMM32_BASE, 'mscoree.dll': MSCOREE_BASE, 'msvcrt.dll': MSVCRT_BASE, 'netapi32.dll': NETAPI32_BASE, 'ole32.dll': OLE32_BASE, 'oleaut32.dll': OLEAUT32_BASE, 'shell32.dll': SHELL32_BASE, 'shlwapi.dll': SHLWAPI_BASE, 'urlmon.dll': URLMON_BASE, 'user32.dll': USER32_BASE, 'wininet.dll': WININET_BASE, 'winmm.dll': WINMM_BASE, 'ws2_32.dll': WS2_32_BASE, 'wsock32.dll': WSOCK32_BASE}

     
class WinDLL:
	def __init__(self, dllName, base, d32, d64, dExpanded32, dExpanded64, ldr=None):
		"""Initializes the data."""
		self.id=dllName[:-3]
		self.name = dllName
		self.base =base
		self.d32 =d32  #SysWOW64
		self.d64=d64	#System32
		self.dExpanded32=dExpanded32   #SysWOW64 expanded
		self.dExpanded64=dExpanded64  #System32 expanded
		self.LDR = ldr

	def setBase(self, base):
		self.base=base
	def setd32(self, d32):
		self.d32=d32
	def setd64(self, d64):
		self.d64=d64
	def setdExpanded32(self, dExpanded32):
		self.dExpanded32=dExpanded32
	def setdExpanded64(self, dExpanded64):
		self.dExpanded64=dExpanded64
	def setSetLDR(self, ldr):
		self.ldr =ldr
 

def initMods():
	for dllName, base in dlls.items():
	    # dll=readRaw(path+dllName)
	    # print ("init", dllName[:-4])
	    mod[dllName[:-4]]= WinDLL(dllName, base, path32, path64, expandedDLLsPath32, expandedDLLsPath64)

initMods()

test=2
if test == 1:
	print ("\n\noutputs")
	print (mod[ntdll].name)
	print (mod[ntdll].base)
	print (mod[ntdll].d32)
	print (mod[ntdll].d64)
	print (mod[ntdll].dExpanded32)
	print (mod[ntdll].dExpanded64)

	mod[ntdll].setBase(400)
	mod[ntdll].setd32("d32")
	mod[ntdll].setd32("d64")
	mod[ntdll].setdExpanded32("test")
	mod[ntdll].setdExpanded64("test2")

	print (mod[ntdll].name)
	print (mod[ntdll].base)
	print (mod[ntdll].d32)
	print (mod[ntdll].d64)
	print (mod[ntdll].dExpanded32)
	print (mod[ntdll].dExpanded64)

	for each in mod:
		print (mod[each].name)
		print (mod[each].base)
