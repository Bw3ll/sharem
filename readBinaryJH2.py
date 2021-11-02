import pefile
def readRaw(appName):
	f = open(appName, "rb")
	myBinary = f.read()
	f.close()
	return myBinary

ntdll="C:\\Windows\\SysWOW64\\ntdll.dll"
kernel32="C:\\Windows\\SysWOW64\\kernel32.dll"
kernelbase="C:\\Windows\\SysWOW64\\kernelbase.dll"
advapi32="C:\\Windows\\SysWOW64\\advapi32.dll"
shell32="C:\\Windows\\SysWOW64\\shell32.dll"
# x="C:\\Windows\\SysWOW64\\x.dll"
ole32="C:\\Windows\\SysWOW64\\ole32.dll"
ws2_32="C:\\Windows\\SysWOW64\\ws2_32.dll"
user32="C:\\Windows\\SysWOW64\\user32.dll"
gdi32="C:\\Windows\\SysWOW64\\gdi32.dll"
netapi32="C:\\Windows\\SysWOW64\\netapi32.dll"
winmm="C:\\Windows\\SysWOW64\\winmm.dll"
wininet="C:\\Windows\\SysWOW64\\wininet.dll"
imm32="C:\\Windows\\SysWOW64\\imm32.dll"
msvcrt="C:\\Windows\\SysWOW64\\msvcrt.dll"

myNtdll=readRaw(ntdll)
myKernel32=readRaw(kernel32)
myKernelbase=readRaw(kernelbase)
myAdvapi32=readRaw(advapi32)
myShell32=readRaw(shell32)
myOle32=readRaw(ole32)
myWs2_32=readRaw(ws2_32)
# x=readRaw(x)
myUser32=readRaw(user32)
myGdi32=readRaw(gdi32)
myNetapi32=readRaw(netapi32)
myWinmm=readRaw(winmm)
myWininet=readRaw(wininet)
myImm32=readRaw(imm32)
myMsvcrt=readRaw(msvcrt)

print (len(myNtdll))
print (len(myKernel32))
print (len(myKernelbase))
print (len(myAdvapi32))
print (len(myShell32))
print (len(myOle32))
# print (len(x))
print (len(myWs2_32))
print (len(myUser32))
print (len(myGdi32))
print (len(myNetapi32))
print (len(myWinmm))
print (len(myWininet))
print (len(myImm32))
print (len(myMsvcrt))

print (type(myMsvcrt))


my_dict = {}

pe = pefile.PE(ntdll)
# for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
# 	try:
# 	 	# print (hex(exp.address), exp.name.decode())
# 	 	my_dict[hex(exp.address)]=exp.name.decode()
# 	 	print ("success")
# 	except:
# 	 	# print (hex(exp.address), "None", exp.name)
# 	 	my_dict[hex(exp.address)]="None"
a="ok"
b="doh"
c="me"
my_dict[a] = b
print (my_dict)

my_dict[c]="new"
print (my_dict)
my_dict[0xdeadc0de]="dfsd"
print (my_dict)

print ("answer")
print (my_dict["ok"])