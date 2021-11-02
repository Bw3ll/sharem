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



my_dict = {}
my_dict2={}

pe = pefile.PE(ntdll)
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	try:
	 	# print (hex(exp.address), exp.name.decode())
	 	my_dict[int(exp.address)]=exp.name.decode()
	except:
	 	# print (hex(exp.address), "None", exp.name)
	 	my_dict[int(exp.address)]="None"
a="ok"
b="doh"
c="me"
my_dict[a] = b
# print (my_dict)

my_dict[c]="new"
# print (my_dict)
my_dict[0xdeadc0de]="dfsd"
# print (my_dict)
# 

# 0xd5810
print ("answer")
print (my_dict[884538])

image=0x0040000  #Kernel32  
kernel32Image=0x0040000  #Kernel32  
ntdllImage=0x0050000  #Kernel32  


# put dll imagebase into dict - avoid conflicts
my_dict[0x0040000+666]="winApi"

my_dict2["winApi"]="we got it", 5, ("handle", "bool", "dword", "dword", "dword"), (2,3), 2,3

print (my_dict2)

ans2 = my_dict2["winApi"]

message = ans2[0]
numPara= ans2[1]
params = ans2[2]
param1 = params[0]

print ("\n\n")
print (message)
print (numPara)
print (params)
print (param1)
print ("\n")

print(my_dict[image+666])
ans=my_dict[image+666]

ans=33

t=0
for x in range (2000):
	try:
		print(my_dict2[ans])

		x,y,z = my_dict2[ans]
		if z =="memory":
			#allocate memory
			pass

	except:
		# print ("opps")
		t+=1
		pass
print (t)